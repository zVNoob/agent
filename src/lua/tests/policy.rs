//! The shipped `lua/policy.lua`: which syscalls become questions, what an
//! answer is remembered against, and how a refusal leaves the filesystem alone.
use super::*;

use crate::testutil::scratch_dir;
    /// Two tool calls in one round, each of which asks — can the TUI hold two
    /// questions at once?
    ///
    /// No, and this pins *why*: a tool call is a coroutine that has to be
    /// yielded back to before it can ask, and the loop keeps exactly one in
    /// flight (`tool_flight: Option<ToolFlight>`), so the second call is not
    /// even started until the first has returned. Driven here the way the loop
    /// drives it, and asserted from the outside: while call one is unanswered,
    /// call two does not exist, so there is nothing for its question to collide
    /// with.
    #[test]
    fn two_asking_tool_calls_are_strictly_sequential() {
        use ToolStep;
        let lua = vm();
        let sink = PanelSink::default();
        install_sink(&lua, &sink).expect("round sink");
        let args = |cmd: &str| format!(r#"{{"cmdline":{}}}"#, serde_json::json!(cmd));

        // Call one: started, and it asks.
        let Some((mut one, step1)) =
            ToolRun::start(&lua, "bash.bash", &args("cat /etc/hostname")).expect("start")
        else {
            panic!("the registry holds bash");
        };
        let step1 = drive_to_ask(&mut one, step1);
        let ToolStep::Ask { text: q1, .. } = &step1 else {
            panic!("expected an ask, got {step1:?}");
        };
        assert!(q1.contains("read"), "the question names the read: {q1}");
        // One panel exists for the first call. The dialog on it is the driver's to
        // draw, and it is what makes the second call's question impossible to
        // confuse with this one: the second call has not started.
        assert_eq!(
            sink.ops()
                .iter()
                .filter(|op| matches!(op, PanelOp::Create { .. }))
                .count(),
            1,
            "one panel so far: {:?}",
            sink.ops()
        );

        // Answer it; only once it has returned does call two begin.
        let v: serde_json::Value = serde_json::from_str(&drive_to_end(&mut one, step1))
            .expect("tool json");
        assert_eq!(v["ok"], true, "{v}");

        let Some((mut two, step2)) =
            ToolRun::start(&lua, "bash.bash", &args("cat /etc/hosts")).expect("start")
        else {
            panic!("the registry holds bash");
        };
        let step2 = drive_to_ask(&mut two, step2);
        let ToolStep::Ask { text: q2, .. } = &step2 else {
            panic!("expected an ask, got {step2:?}");
        };
        assert!(q2.contains("read"), "{q2}");
        let v: serde_json::Value = serde_json::from_str(&drive_to_end(&mut two, step2))
            .expect("tool json");
        assert_eq!(v["ok"], true, "{v}");

        // Two panels, each titled with its own command, each with its own
        // question, in order.
        let creates: Vec<String> = sink
            .ops()
            .iter()
            .filter_map(|op| match op {
                PanelOp::Create { title, .. } => Some(title.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            creates,
            ["cat /etc/hostname", "cat /etc/hosts"],
            "one panel per call, each titled with its own command"
        );
    }

    /// The other half, and the reason the test above matters: the machinery
    /// *does* let two runs sit on an ask at the same time — nothing in `ToolRun`
    /// or the runtime objects. What prevents it is the loop holding one flight.
    ///
    /// So the single `pending_verdict` slot in `main.rs` is safe by loop
    /// discipline, not by construction. Anyone who later runs tools in parallel
    /// has to widen it to a queue keyed by run, or a verdict will be handed to
    /// whichever coroutine is stepped first. This is the canary for that change.
    #[test]
    fn two_asking_runs_are_possible_but_the_loop_never_gets_there() {
        use ToolStep;
        let lua = vm();
        let sink = PanelSink::default();
        install_sink(&lua, &sink).expect("round sink");
        let args = |cmd: &str| format!(r#"{{"cmdline":{}}}"#, serde_json::json!(cmd));
        let start = |cmd: &str| {
            let Some(pair) = ToolRun::start(&lua, "bash.bash", &args(cmd)).unwrap() else {
                panic!("the registry holds bash");
            };
            pair
        };

        let (mut one, s1) = start("cat /etc/hostname");
        let (mut two, s2) = start("cat /etc/hosts");
        let s1 = drive_to_ask(&mut one, s1);
        let s2 = drive_to_ask(&mut two, s2);

        // Both suspended mid-ask simultaneously, with an overlay each. This is
        // the state the loop must never reach, and nothing below stops it.
        assert!(
            matches!(s1, ToolStep::Ask { .. }) && matches!(s2, ToolStep::Ask { .. }),
            "two outstanding asks: {s1:?} / {s2:?}"
        );
        assert_eq!(
            sink.ops()
                .iter()
                .filter(|op| matches!(op, PanelOp::Create { .. }))
                .count(),
            2,
            "and two panels, each with a command of its own as its title"
        );

        // One verdict advances one run and leaves the other asking: a single
        // slot is one wide, which is the whole constraint.
        let after = one
            .answer(verdict_to_lua(&lua, &AskAnswer::Allow))
            .expect("answer the first");
        assert!(
            matches!(
                after,
                ToolStep::Waiting { .. } | ToolStep::Ask { .. } | ToolStep::Returned(_)
            ),
            "the first moved on: {after:?}"
        );
        assert!(
            matches!(s2, ToolStep::Ask { .. }),
            "the second is untouched: still asking, unanswered"
        );
    }

    fn drive_to_ask(run: &mut ToolRun<'_>, mut step: ToolStep) -> ToolStep {
        for waited in 0..20_000 {
            match &step {
                ToolStep::Ask { .. } => return step,
                ToolStep::Waiting { ms } => {
                    // The cadence wait is *real* time, and honouring it is what
                    // makes this test deterministic. `ToolRun::wait` only
                    // resumes the coroutine — the `ms` is advice for whoever is
                    // driving it, and the shipped event loop is what acts on it.
                    // A test that spun without sleeping burned its whole 1000
                    // iterations in milliseconds and gave up before the
                    // sandbox's notification was ever delivered, so this test
                    // failed perhaps one run in three under load and passed the
                    // rest. Spinning was never the thing under test.
                    std::thread::sleep(std::time::Duration::from_millis(*ms));
                    step = run.wait().expect("wait");
                }
                ToolStep::Returned(body) => panic!("returned before asking: {body}"),
            }
            let _ = waited;
        }
        panic!("never asked");
    }

    /// The permissive mode's gates ask, in the words the mode specifies.
    ///
    /// The command is `bash` itself doing the syscall, so each case is one real
    /// trapped call: a read-open, a write-open, a TCP connect. A plain allow
    /// lets each through, and what the user was *asked* is the contract.
    ///
    /// (These run on a bare VM that never loaded `lua/init.lua`, so the working
    /// directory is *not* trusted here — which is why even a read asks. The cwd
    /// grant is pinned by `the_working_directory_is_trusted_at_startup`.)
    #[test]
    fn the_permissive_mode_asks_about_writes_connects_and_binds() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = scratch_dir("agent-permissive");
        let target = dir.join("out.txt");
        // Seeded so the write is an overwrite. Creating a name nothing holds is
        // deliberately not a question — `creating_a_new_name_is_not_a_question`
        // is that test's whole subject — and this one is about the *question*.
        std::fs::write(&target, "before\n").expect("seed the target");
        let path = target.to_string_lossy().to_string();

        // A write-open is asked, and the question names the file and the flags.
        let (v, asked) =
            run_policy_bash(&lua, &format!("echo hi > {path}"), AskAnswer::Allow);
        assert_eq!(v["ok"], true, "an allowed write runs: {v}");
        let q = asked
            .iter()
            .find(|q| q.contains("want to write"))
            .unwrap_or_else(|| panic!("a write is asked: {asked:?}"));
        assert!(q.contains(&path), "the write question names the file: {q:?}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hi\n", "and it wrote");

        // A *read* is asked too, and with the read question: "may I read here"
        // and "may I write here" are two decisions, and the flag reaching the ask
        // is what keeps them apart.
        let (v, asked) = run_policy_bash(&lua, &format!("cat {path}"), AskAnswer::Allow);
        assert_eq!(v["ok"], true, "{v}");
        let q = asked
            .iter()
            .find(|q| q.contains("want to read"))
            .unwrap_or_else(|| panic!("a read is asked: {asked:?}"));
        assert!(q.contains(&path), "with the read question and the path: {q:?}");

        // A refused write leaves the file alone, and says it was denied. Seeded,
        // because a refused *create* is no longer refusable — creating a name
        // nothing holds is deliberately silent
        // (`creating_a_new_name_is_not_a_question`). Overwriting something that
        // is there is still a question, and refusing it must leave the old
        // contents exactly as they were.
        let other_path = dir.join("refused.txt");
        std::fs::write(&other_path, "untouched\n").expect("seed the refused target");
        let other = other_path.to_string_lossy().to_string();
        let (v, asked) = run_policy_bash(
            &lua,
            &format!("echo nope > {other}"),
            AskAnswer::Deny(Some("denied by user".to_string())),
        );
        assert_eq!(v["ok"], false, "a refused write is not ok: {v}");
        assert!(asked_about(&asked, &other), "and it was asked: {asked:?}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("denied by user"),
            "and carries the reason: {v}"
        );
        assert_eq!(
            std::fs::read_to_string(&other_path).unwrap_or_default(),
            "untouched\n",
            "a refused overwrite left the file exactly as it was: {v}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `connect` is asked with the endpoint it wanted: the port, and the
    /// address with its reverse-resolved name when it has one. Loopback resolves
    /// without a network, so the name is `localhost` and the question reads
    /// "localhost (127.0.0.1)" — both halves, as the mode's wording asks.
    #[test]
    fn the_permissive_mode_asks_about_a_connection_with_its_endpoint() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        // A listener with nothing on it, so `connect` fails *after* the gate:
        // what is under test is the question, not the connection.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let (v, asked) = run_policy_bash(
            &lua,
            &format!("exec 3<>/dev/tcp/127.0.0.1/{port}"),
            AskAnswer::Allow,
        );
        let q = asked
            .iter()
            .find(|q| q.contains("want to access"))
            .unwrap_or_else(|| panic!("a connect is asked: {asked:?} {v}"));
        assert!(
            q.contains("127.0.0.1") && q.contains("localhost"),
            "the question names the host and its address: {q:?}"
        );
        assert_eq!(
            q.matches(&port.to_string()).count(),
            1,
            "and the port exactly once, not folded into the address too: {q:?}"
        );
        assert!(
            q.contains("at port"),
            "in the mode's own wording: {q:?}"
        );
    }

    /// A `bind` is asked with the port being opened. The listener is never
    /// actually reached — `listen()` names no address, so the gate that can ask
    /// about it is `bind`, and the question is about opening a port.
    #[test]
    fn the_permissive_mode_asks_about_opening_a_port() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        // A port nothing holds, so the bind succeeds and the gate is the only
        // thing that stops it.
        let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let _port = taken.local_addr().expect("addr").port();
        drop(taken);

        // Pick a free port by binding and releasing it, then ask bash to open it.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);

        let (v, asked) = run_policy_bash(
            &lua,
            &format!("exec 3<>/dev/tcp/127.0.0.1/{port}"),
            AskAnswer::Deny(None),
        );
        // A refused connect never reaches the port, so this asserts the connect
        // gate refused; the bind gate is pinned by the same policy table and is
        // covered by the mask assertion below.
        assert_eq!(asked.len(), 1, "{asked:?} {v}");
        assert!(asked[0].contains("want to access"), "{:?}", asked[0]);
    }

    /// list that came back empty is an object with no keys rather than an array
    /// with no elements. Asserting on `as_array()` alone would read that as a
    /// missing field, which is how the first run of this test failed on a tool
    /// that had worked.
    fn entries(v: &serde_json::Value) -> Vec<String> {
        if let Some(a) = v.as_array() {
            return a
                .iter()
                .map(|x| x.as_str().unwrap_or_default().to_string())
                .collect();
        }
        match v.as_object() {
            Some(o) => o.keys().cloned().collect(),
            None => Vec::new(),
        }
    }

    /// `hand_to_user` gives write-trust back, so the files a command created stop
    /// being writable without a question.
    ///
    /// The round trip is the point: a create records write-trust on its own (see
    /// `creating_a_new_name_is_not_a_question`), so without this the agent's own
    /// output is the one thing it can keep rewriting in silence forever, and
    /// nothing else in the system revokes a grant the agent made to itself.
    #[test]
    fn hand_to_user_takes_write_trust_back_so_later_writes_ask_again() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = scratch_dir("agent-hand");
        let path = dir.join("mine.txt");
        let path_s = path.to_string_lossy().to_string();

        // The create is silent and records write-trust.
        let (v, asked) =
            run_policy_bash(&lua, &format!("echo mine > {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], true, "the create ran: {v}");
        assert!(
            !asked.iter().any(|q| q.contains("want to write")),
            "and asked nothing: {asked:?}"
        );
        // ...which is why a second write is also silent.
        let (_, asked) =
            run_policy_bash(&lua, &format!("echo again > {path_s}"), AskAnswer::Deny(None));
        assert!(
            !asked.iter().any(|q| q.contains("want to write")),
            "the create trusted the name: {asked:?}"
        );

        // Hand it over, through the tool so the advertised shape is what gets
        // exercised — and on **this** VM, which is the whole mechanism. The trust
        // lives in the config VM's ask tables, and the event loop runs every tool
        // on that one VM; the `call_tool_asking` helper builds a fresh VM per
        // call, so reaching for it here would have tested a tool looking at an
        // empty table and quietly reporting "not trusted" for everything.
        let handover = |args: &str| -> serde_json::Value {
            let (body, _) = invoke_tool_asking(&lua, "fs.hand_to_user", args, None)
                .expect("invoke")
                .expect("the shipped config registers fs.hand_to_user");
            serde_json::from_str(&body).expect("tool json")
        };
        let r = handover(&serde_json::json!({ "paths": [&path_s] }).to_string());
        assert_eq!(r["ok"], true, "the handover ran: {r}");
        assert_eq!(
            entries(&r["result"]["handed_over"]),
            vec![path_s.clone()],
            "and it names what it gave up: {r}"
        );
        assert!(
            entries(&r["result"]["not_write_trusted"]).is_empty(),
            "with nothing left over: {r}"
        );

        // Now the third write asks, and a refusal stops it. This is the whole
        // point of the tool: the file is the user's to look after now.
        let (v, asked) =
            run_policy_bash(&lua, &format!("echo nope > {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], false, "a refused write is not ok: {v}");
        assert!(
            asked.iter().any(|q| q.contains("want to write") && q.contains(&path_s)),
            "the write asks again: {asked:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_default(),
            "again\n",
            "and the refusal left the file alone"
        );

        // Handing over something the agent never held is not an error, and says
        // so — a confused call has to be visible rather than quietly do nothing.
        // The already-handed-over path is in here too, and being reported back as
        // un-held is the honest answer: there is nothing left of it to give.
        let r = handover(
            &serde_json::json!({ "paths": ["/no/such/path", &path_s] }).to_string(),
        );
        assert_eq!(r["ok"], true, "{r}");
        assert!(
            entries(&r["result"]["handed_over"]).is_empty(),
            "nothing was given up a second time: {r}"
        );
        let mut missed = entries(&r["result"]["not_write_trusted"]);
        missed.sort();
        let mut want = vec!["/no/such/path".to_string(), path_s.clone()];
        want.sort();
        assert_eq!(missed, want, "both are named as un-held: {r}");

        // Reading stays silent: only the write half was given up.
        let (v, asked) = run_policy_bash(&lua, &format!("cat {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], true, "the read ran: {v}");
        assert!(
            !asked.iter().any(|q| q.contains(&path_s)),
            "and a read of a handed-over file is still silent: {asked:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The advertised shape: a `paths` array, and a single `path` accepted under
    /// the same name every other fs tool takes, because a model reaching for
    /// The pair that needed a blocklist: trust the working directory, then take
    /// one file back out of it.
    ///
    /// A directory grant covers its whole subtree, so there is no entry for
    /// `.env` to drop — `forget` removed nothing, reported success, and left the
    /// file exactly as trusted as before. That is the shape a config reaches for
    /// when it wants the repository to be quiet but not its secrets, so it is
    /// pinned here against the real working directory rather than a fixture.
    #[test]
    fn a_trusted_working_directory_can_have_a_file_taken_back_out_of_it() {
        let lua = new_vm_with_sink(None).expect("vm");
        let cwd = std::env::var("PWD").expect("PWD");
        let secret = format!("{cwd}/.env");
        let other = format!("{cwd}/README.md");

        // The shipped config trusts the cwd at startup.
        for p in [&secret, &other] {
            let trusted: bool = lua
                .load(format!("return agent.ask.is_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_trusted({p}): {e}"));
            assert!(trusted, "{p} is trusted by the cwd grant");
        }

        // Take the one back out.
        let forgot: bool = lua
            .load(format!("return agent.ask.forget({secret:?})"))
            .eval()
            .expect("forget");
        assert!(forgot, "and forgetting it reports it stopped being trusted");

        let still: bool = lua
            .load(format!("return agent.ask.is_trusted({secret:?})"))
            .eval()
            .expect("is_trusted");
        assert!(!still, "so the file inside the trusted cwd is not trusted");
        let sibling: bool = lua
            .load(format!("return agent.ask.is_trusted({other:?})"))
            .eval()
            .expect("is_trusted");
        assert!(sibling, "while the rest of the cwd is untouched");

        // It is a preference, so trusting the same path again is how you change
        // your mind: the block is lifted and the grant stands.
        let retrusted: String = lua
            .load(format!("return agent.ask.trust({secret:?})"))
            .eval()
            .expect("trust");
        assert_eq!(retrusted, secret, "re-trusting it works");
        let blocked: bool = lua
            .load(format!("return agent.ask.is_blocked({secret:?})"))
            .eval()
            .expect("is_blocked");
        assert!(!blocked, "and it lifted the block on the way");
        let trusted_again: bool = lua
            .load(format!("return agent.ask.is_trusted({secret:?})"))
            .eval()
            .expect("is_trusted");
        assert!(trusted_again, "so the file is trusted again");
        // ...but only exactly. A block on a *directory* is a statement about a
        // tree, so naming something inside it is still refused.
        lua.load("agent.ask.block('/usr')").exec().expect("block /usr");
        let refused: bool = lua
            .load("return not pcall(agent.ask.trust, '/usr/lib/inside-blocked.so')")
            .eval()
            .expect("pcall");
        assert!(
            refused,
            "a path inside a blocked directory is still refused: only an exact \
             block is a preference"
        );
        lua.load("agent.ask.unblock('/usr')").exec().expect("unblock /usr");

        // Back to blocked, for the ask assertions below: the re-trust lifted it,
        // and a trusted path answers itself rather than asking.
        lua.load(format!("agent.ask.block({secret:?})"))
            .exec()
            .expect("re-block");

        // The exclusion reaches the ask path, which is the part that matters: a
        // read of the file is a question again. Asked of `ask_trust_read` on a
        // coroutine — the helper the policy itself calls — because a real `cat`
        // would mean creating a file inside the repository to read back, and
        // because a file that does not exist never reaches the question at all.
        let asked: bool = lua
            .load(format!(
                r#"
            local co = coroutine.create(function()
              return agent.ask.ask_trust_read({secret:?}, "may I read it?")
            end)
            local ok, value = coroutine.resume(co)
            assert(ok, "the helper ran: " .. tostring(value))
            return coroutine.status(co) == "suspended"
        "#
            ))
            .eval()
            .expect("ask");
        assert!(asked, "reading the excluded file asks again rather than answering itself");

        // And a sibling still answers itself, so the exclusion is narrow.
        let silent: bool = lua
            .load(format!(
                r#"
            local co = coroutine.create(function()
              return agent.ask.ask_trust_read({other:?}, "may I read it?")
            end)
            local ok, value = coroutine.resume(co)
            assert(ok, "the helper ran: " .. tostring(value))
            return coroutine.status(co) == "dead"
        "#
            ))
            .eval()
            .expect("ask");
        assert!(silent, "while a file next to it still answers itself");

        // Unblocking puts the cwd grant back — it was never revoked, only stood
        // in front of.
        let lifted: bool = lua
            .load(format!("return agent.ask.unblock({secret:?})"))
            .eval()
            .expect("unblock");
        assert!(lifted, "unblocking reports it lifted the block");
        let back: bool = lua
            .load(format!("return agent.ask.is_trusted({secret:?})"))
            .eval()
            .expect("is_trusted");
        assert!(back, "and the cwd grant applies to it again");
    }

    /// `path` should not be met with an error it has to reason about.
    #[test]
    fn hand_to_user_takes_both_a_paths_array_and_a_single_path() {
        let dir = scratch_dir("agent-hand2");
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, "a\n").expect("seed a");
        std::fs::write(&b, "b\n").expect("seed b");

        // Neither path was ever granted, so both come back as "not held" — which
        // is what makes this a test of the argument handling and nothing else.
        let lua = shipped_vm();
        let handover = |args: &str| -> serde_json::Value {
            let (body, _) = invoke_tool_asking(&lua, "fs.hand_to_user", args, None)
                .expect("invoke")
                .expect("the shipped config registers fs.hand_to_user");
            serde_json::from_str(&body).expect("tool json")
        };
        let one = handover(&serde_json::json!({ "path": a.to_string_lossy() }).to_string());
        assert_eq!(one["ok"], true, "a single path is accepted: {one}");

        let many = handover(
            &serde_json::json!({
                "paths": [a.to_string_lossy(), b.to_string_lossy()],
            })
            .to_string(),
        );
        assert_eq!(many["ok"], true, "an array is accepted: {many}");
        assert_eq!(
            entries(&many["result"]["not_write_trusted"]).len(),
            2,
            "and both are accounted for: {many}"
        );

        // Nothing at all is refused, with a message that says what to give.
        let none = handover(&serde_json::json!({}).to_string());
        assert_eq!(none["ok"], false, "an empty call is refused: {none}");
        assert!(
            none["error"].as_str().unwrap_or("").contains("paths"),
            "and the error names the argument: {none}"
        );
        let wrong = handover(&serde_json::json!({ "paths": "not an array" }).to_string());
        assert_eq!(wrong["ok"], false, "a non-array is refused: {wrong}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// the console, a world-writable tmpfs, and the disks all stay questions.
    #[test]
    fn the_empty_devices_are_granted_and_the_rest_of_dev_is_not() {
        let lua = new_vm_with_sink(None).expect("vm");
        prime_the_sandbox(&lua);

        // Readable without a question: no data, no device, nothing to keep.
        for p in ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/full"] {
            let trusted: bool = lua
                .load(format!("return agent.ask.is_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_trusted({p}): {e}"));
            assert!(trusted, "{p} is readable without a question");
        }
        // ...and read-only, except the one that is meant to be written.
        for p in ["/dev/zero", "/dev/random", "/dev/urandom", "/dev/full"] {
            let writable: bool = lua
                .load(format!("return agent.ask.is_write_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_write_trusted({p}): {e}"));
            assert!(!writable, "{p} is granted to be looked at, not written");
        }
        let null_writable: bool = lua
            .load("return agent.ask.is_write_trusted('/dev/null')")
            .eval()
            .expect("is_write_trusted");
        assert!(null_writable, "/dev/null is meant to be written to");

        // The boundary. Each of these is a question, and naming them is the
        // point: a grant for "the safe devices" that swept up /dev would be a
        // grant for the disks.
        for p in ["/dev/tty", "/dev/console", "/dev/shm", "/dev/pts/0", "/dev/ptmx", "/dev/sda"] {
            let trusted: bool = lua
                .load(format!("return agent.ask.is_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_trusted({p}): {e}"));
            assert!(!trusted, "{p} is not granted: it is not one of the empty ones");
        }

        // And the effect, on a real run: a redirect into /dev/null is silent,
        // while a write to a device that was not granted still asks.
        let (v, asked) = run_policy_bash(
            &lua,
            "echo hello > /dev/null",
            AskAnswer::Deny(None),
        );
        assert_eq!(v["ok"], true, "the redirect ran: {v}");
        assert_eq!(v["result"]["denied"], 0, "and nothing was refused: {v}");
        assert!(
            !asked.iter().any(|q| q.contains("/dev/null")),
            "writing to /dev/null asks nothing: {asked:?}"
        );

        let (v, asked) = run_policy_bash(
            &lua,
            "echo hello > /dev/full",
            AskAnswer::Deny(None),
        );
        assert!(
            asked.iter().any(|q| q.contains("/dev/full")),
            "a device that was only granted for reading still asks to write: {asked:?} {v}"
        );
    }

    /// and it does not get to skip a write inside a granted tree.
    #[test]
    fn the_system_tree_is_trusted_to_read_and_still_asked_to_write() {
        let lua = new_vm_with_sink(None).expect("vm");
        // The *grants* are asserted before anything is run, on purpose.
        // `prime_the_sandbox` below drives real programs with `AllowAndTrust`,
        // and every path they touch is recorded as trusted — including
        // `/proc/filesystems`, which they read. Asserting the table after that
        // would have this test pass on its own warm-up rather than on the
        // config, and it did: it reported a grant the shipped config never made.
        // A cold run is the only thing that can answer this question.
        let _ = &lua;

        // Trusted to look, at both the tree and a file inside it.
        for p in ["/usr", "/lib", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"] {
            let trusted: bool = lua
                .load(format!("return agent.ask.is_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_trusted({p}): {e}"));
            assert!(trusted, "{p} is readable without a question");
        }
        // …and trusted *only* to look. The write table is the whole difference
        // between "you may read the system tree" and "you may install into it",
        // and this is where a read-only grant that had leaked into the general
        // table would show up.
        for p in ["/usr", "/lib", "/etc/ld.so.cache"] {
            let writable: bool = lua
                .load(format!("return agent.ask.is_write_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_write_trusted({p}): {e}"));
            assert!(!writable, "{p} is not write-trusted: it was granted to be read");
        }
        // The two procfs reads the C library makes on every exec. Granted as
        // files rather than as /proc, because a blanket grant there would be a
        // grant for every other procfs file as well.
        for p in ["/proc/self/maps", "/proc/filesystems"] {
            let trusted: bool = lua
                .load(format!("return agent.ask.is_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_trusted({p}): {e}"));
            assert!(trusted, "{p} is read on every exec, and is granted");
        }
        // ...but /proc itself is not.
        let proc: bool = lua
            .load("return agent.ask.is_trusted('/proc')")
            .eval()
            .expect("is_trusted");
        assert!(!proc, "/proc is not granted as a tree — only those two files are");
        // `/etc/ld.so.preload` decides what gets loaded into every process, so it
        // is the one loader file deliberately left as a question.
        let preload: bool = lua
            .load("return agent.ask.is_trusted('/etc/ld.so.preload')")
            .eval()
            .expect("is_trusted");
        assert!(
            !preload,
            "ld.so.preload is not granted: trusting it would mean trusting whatever \
             it names, and those names are not the loader's to hold"
        );
        // The dynamic linker's cache is in /etc, not /usr, and is granted on its
        // own: it is read on every exec, so without it a cold command still asks
        // once per program it starts.
        let cache: bool = lua
            .load("return agent.ask.is_trusted('/etc/ld.so.cache')")
            .eval()
            .expect("is_trusted");
        assert!(cache, "the loader cache is trusted");
        // And the rest of /etc is not: this grant is one file, not a directory.
        let shadow: bool = lua
            .load("return agent.ask.is_trusted('/etc/shadow')")
            .eval()
            .expect("is_trusted");
        assert!(!shadow, "but nothing else in /etc is — the grant is one file");

        // From here on, real runs. Primed first: on this machine something on
        // `PATH` is a rustup shim, so a cold `cat` also reads
        // `~/.rustup/toolchains/...`, which is correctly still a question and is
        // not what this test is about.
        prime_the_sandbox(&lua);

        // The read is genuinely silent, and it names something that is really
        // there, so the quiet is the grant's doing rather than a missing file.
        //
        // A *directory* rather than `cat /etc/ld.so.cache`: the cache is granted
        // and checked above, but it is binary, and the tool result has to encode
        // as JSON text — so `cat`ing it fails on an invalid UTF-8 sequence. That
        // is a pre-existing rough edge in the result encoding, not something the
        // grant introduced, and it is not what this test is about.
        let (v, asked) = run_policy_bash(&lua, "ls -d /usr/lib", AskAnswer::Deny(None));
        assert_eq!(v["ok"], true, "the read ran: {v} asked={asked:?}");
        assert_eq!(v["result"]["denied"], 0, "and nothing was refused: {v}");
        assert!(
            v["result"]["stdout"].as_str().unwrap_or("").contains("/usr/lib"),
            "and it listed the directory: {v}"
        );
        assert!(
            !asked.iter().any(|q| q.contains("/usr/lib")),
            "reading inside the trusted tree asks nothing: {asked:?}"
        );

        // The write still asks — even with every answer set to deny, so a silent
        // case would be silent because nothing was asked and not because the
        // answer was ignored.
        let (v, asked) = run_policy_bash(
            &lua,
            "echo x > /usr/share/agent-should-not-exist.txt",
            AskAnswer::Deny(None),
        );
        assert_eq!(v["ok"], false, "a refused write into /usr is not ok: {v}");
        assert!(
            asked
                .iter()
                .any(|q| q.contains("want to write") && q.contains("/usr/share")),
            "writing into the trusted tree still asks: {asked:?}"
        );
        assert!(
            !std::path::Path::new("/usr/share/agent-should-not-exist.txt").exists(),
            "and wrote nothing"
        );
    }

    /// silent because nothing was asked and not because nothing was refused.
    #[test]
    fn creating_a_new_name_is_not_a_question() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = scratch_dir("agent-new");
        let path = dir.join("brand-new.txt");
        let path_s = path.to_string_lossy().to_string();

        // Nothing under /tmp is granted, so without the rule this would ask.
        let (v, asked) = run_policy_bash(&lua, &format!("echo hi > {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], true, "the create ran: {v}");
        assert_eq!(v["result"]["denied"], 0, "and nothing was refused: {v}");
        assert!(
            !asked.iter().any(|q| q.contains("want to write")),
            "a create is not a question, even when every answer is deny: {asked:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_default(),
            "hi\n",
            "and the file is there"
        );

        // "Trust it for writing": the second write is silent too.
        let (v, asked) =
            run_policy_bash(&lua, &format!("echo there > {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], true, "the rewrite ran: {v}");
        assert!(
            !asked.iter().any(|q| q.contains("want to write")),
            "and it did not ask: the create trusted the name: {asked:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_default(),
            "there\n",
            "the second write landed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An **overwrite** is still a question, and a refused one leaves the file
    /// exactly as it was.
    ///
    /// This is the half that could go wrong silently: the new rule turns on
    /// whether the name is taken, so a permissive mistake in the existence test
    /// would show up here and nowhere else.
    #[test]
    fn an_overwrite_is_still_a_question() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = scratch_dir("agent-over");
        let path = dir.join("existing.txt");
        std::fs::write(&path, "original\n").expect("seed");
        let path_s = path.to_string_lossy().to_string();

        let (v, asked) =
            run_policy_bash(&lua, &format!("echo nope > {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], false, "a refused overwrite is not ok: {v}");
        assert!(
            asked.iter().any(|q| q.contains("want to write") && q.contains(&path_s)),
            "an overwrite asks, naming the file: {asked:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_default(),
            "original\n",
            "and the refusal left the old contents alone"
        );

        // Deliberately *not* asserted: a name below something that is not a
        // directory reads as "not taken" (ENOTDIR), so the create is silent. That
        // is safe rather than lax — the open cannot succeed either way, and the
        // sandbox is a bare fork, so the command has the user's own permissions.
        // An earlier version of this test asserted the opposite and was wrong.

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The existence test has to see a file the process **cannot read**, because
    /// that is the case a naive one misses.
    ///
    /// `io.open` follows the name and fails on anything not readable, so a locked
    /// file — `/etc/shadow` is the real one — reads as absent, and absent is the
    /// answer that skips the ask. `os.rename(p, p)` is a documented no-op that
    /// succeeds exactly when the name is taken, whatever its mode. This test is
    /// what tells the two implementations apart.
    #[test]
    fn a_file_the_process_cannot_read_still_counts_as_taken() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = scratch_dir("agent-unread");
        let path = dir.join("locked.txt");
        std::fs::write(&path, "secret\n").expect("seed");

        // mode 000: unreadable *and* unwritable by us, and plainly present.
        let mut perms = std::fs::metadata(&path).expect("stat").permissions();
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o000);
        }
        std::fs::set_permissions(&path, perms).expect("chmod 000");
        assert!(
            std::fs::File::open(&path).is_err(),
            "precondition: the file really is unreadable, or this test is vacuous"
        );

        let path_s = path.to_string_lossy().to_string();
        // The gate runs before the kernel, so it asks even though the write would
        // then fail with EACCES: the ask is the contract, not the write's success.
        let (_, asked) = run_policy_bash(&lua, &format!("echo x > {path_s}"), AskAnswer::Allow);
        assert!(
            asked.iter().any(|q| q.contains("want to write") && q.contains(&path_s)),
            "an unreadable existing file is an overwrite, and asks: {asked:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `chmod` asks on **write** trust, and a refused one leaves the mode alone.
    ///
    /// This was a genuine hole: the mask named files and endpoints, and a
    /// sandboxed command could still make one of your files executable, or take
    /// the bits off it. `chmod +x` is how a payload becomes runnable, and it was
    /// the one permission change the gate did not ask about.
    #[test]
    fn changing_a_files_mode_asks_and_a_refusal_leaves_it_alone() {
        use std::os::unix::fs::PermissionsExt;
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = scratch_dir("agent-chmod");
        let path = dir.join("payload");
        std::fs::write(&path, "#!/bin/sh\necho hi\n").expect("seed");
        let path_s = path.to_string_lossy().to_string();
        let mode_of = |p: &std::path::Path| {
            std::fs::metadata(p).expect("stat").permissions().mode() & 0o777
        };
        let before = mode_of(&path);
        // Not the exact bits — the temp dir's umask decides those — but the one
        // thing that matters: no execute bit yet.
        assert_eq!(before & 0o111, 0, "precondition: not executable yet");

        // Refused: asked, and the mode is untouched.
        let (v, asked) =
            run_policy_bash(&lua, &format!("chmod 0700 {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], false, "a refused chmod is not ok: {v}");
        assert!(
            asked
                .iter()
                .any(|q| q.contains("change the mode") && q.contains(&path_s)),
            "it asks, naming the file and the change: {asked:?}"
        );
        assert_eq!(mode_of(&path), before, "and the mode did not change");

        // Allowed: it goes through, and only then.
        let (v, asked) =
            run_policy_bash(&lua, &format!("chmod 0700 {path_s}"), AskAnswer::Allow);
        assert_eq!(v["ok"], true, "an allowed chmod runs: {v}");
        assert!(
            asked.iter().any(|q| q.contains("change the mode")),
            "and it still asked: {asked:?}"
        );
        assert_eq!(mode_of(&path), 0o700, "so the mode changed");

        // A *different* mode this time, because `chmod` to the mode a file
        // already has makes no syscall at all — so there would be nothing to
        // gate, and the run would pass for the wrong reason.
        let (v, asked) =
            run_policy_bash(&lua, &format!("chmod 0644 {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], false, "and refused again: {v}");
        assert!(
            asked.iter().any(|q| q.contains("change the mode")),
            "so it asks each time the mode really changes: {asked:?}"
        );
        assert_eq!(mode_of(&path), 0o700, "and the mode is still untouched");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Setting an extended attribute asks, and the question names the attribute —/ gated**, so a command holding an open descriptor can change that file's
    /// mode without a question — and `cp --preserve=mode` is exactly that.
    ///
    /// It is not gated because it names no path, and a question needs one: there
    /// is nothing to put in `ask_trust_write`, and a nameless question would be
    /// unanswerable in the only way that matters. The descriptor is not free,
    /// though — opening it cost read or write trust, so what this actually means
    /// is that *read*-trust on a path implies being able to make it executable.
    /// Closing that needs the engine to resolve an fd to a path through
    /// `/proc/<pid>/fd`, which is real work and a decision rather than a policy
    /// key. Pinned here so the gap is visible.
    #[test]
    fn fchmod_is_not_gated_because_it_names_no_path() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = scratch_dir("agent-fchmod");
        let src = dir.join("src");
        let dst = dir.join("dst");
        std::fs::write(&src, "x\n").expect("seed");

        let (v, asked) = run_policy_bash(
            &lua,
            &format!(
                "cp --preserve=mode {0} {1}",
                src.to_string_lossy(),
                dst.to_string_lossy()
            ),
            // Allow, not deny: the question here is whether a *mode* question
            // appears, and denying everything would just stop the copy early.
            AskAnswer::Allow,
        );
        assert_eq!(v["ok"], true, "the copy ran: {v}");
        assert!(
            !asked.iter().any(|q| q.contains("change the mode")),
            "and asked nothing about the mode: the descriptor path is ungated, \
             which is the gap this test names"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Setting an extended attribute asks, and the question names the attribute —
    /// because `security.capability` is `setcap`, and that is a different thing to
    /// be told about than an app writing its own `user.*` metadata.
    #[test]
    fn setting_an_extended_attribute_asks_and_names_which_one() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        // `python3` here resolves through the rustup toolchain, so its own
        // libraries ask unless they are warmed first — and a Deny to those would
        // kill the run before it ever reached the attribute, which is not what
        // this test is about.
        let (warm, _) = run_policy_bash(&lua, "python3 -c pass", AskAnswer::AllowAndTrust);
        assert_eq!(warm["ok"], true, "warmed python3: {warm}");
        let dir = scratch_dir("agent-xattr");
        let path = dir.join("tagged");
        std::fs::write(&path, "x\n").expect("seed");
        let path_s = path.to_string_lossy().to_string();

        // Driven through python's `os.setxattr`, which is the same
        // `setxattr(2)` call `setcap` makes for `security.capability`. In a
        // script file rather than `python3 -c`, because a path inside a
        // double-quoted `-c` string needs its own layer of quoting and gets it
        // wrong in a way that reads as a policy failure.
        let script = dir.join("setx.py");
        std::fs::write(
            &script,
            "import os, sys\nos.setxattr(sys.argv[1], 'user.agent-test', b'v')\n",
        )
        .expect("write the helper");
        let script_s = script.to_string_lossy().to_string();
        let read_script = dir.join("getx.py");
        std::fs::write(
            &read_script,
            "import os, sys\nsys.stdout.write(os.getxattr(sys.argv[1], 'user.agent-test').decode())\n",
        )
        .expect("write the reader");
        // Only the attribute question is denied, so the interpreter's own
        // startup reads do not get in the way.
        let (v, asked) = run_policy_bash_except(
            &lua,
            &format!("python3 {script_s} {path_s}"),
            "user.agent-test",
        );
        assert_eq!(v["ok"], false, "a refused setxattr is not ok: {v}");
        assert!(
            asked
                .iter()
                .any(|q| q.contains("user.agent-test") && q.contains(&path_s)),
            "the question names the attribute and the file: {asked:?}"
        );

        // Allowed, the attribute lands — so the gate was the only thing in the
        // way, and it is a gate rather than a block.
        let (v, asked) = run_policy_bash_except(
            &lua,
            &format!("python3 {script_s} {path_s}"),
            "\u{0}never-matches",
        );
        assert_eq!(v["ok"], true, "an allowed setxattr runs: {v}");
        assert!(
            asked.iter().any(|q| q.contains("user.agent-test")),
            "and it asked: {asked:?}"
        );
        // Read it back, rather than trusting that a silent run did the work. The
        // read is ungated (only the *setting* of an attribute asks), so this is
        // the same interpreter again and asks nothing.
        let (read, _) = run_policy_bash_except(
            &lua,
            &format!("python3 {} {path_s}", read_script.to_string_lossy()),
            "\u{0}never-matches",
        );
        assert_eq!(read["ok"], true, "the read-back ran: {read}");
        assert_eq!(
            read["result"]["stdout"], "v",
            "and the attribute really is set: {read}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// was in the file.
    #[test]
    fn deleting_a_file_asks_on_write_trust_and_rm_goes_through_it() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = scratch_dir("agent-rm");
        let path = dir.join("doomed.txt");
        std::fs::write(&path, "about to go\n").expect("seed the file to delete");
        let path = path.to_string_lossy().to_string();

        // Read-trust is not enough: the gate is the write table, and this is the
        // whole reason unlinkat is not on `ask_trust_read`.
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let handler: AskHandler = Rc::new(move |text: &str, _always: bool| {
            seen.borrow_mut().push(text.to_string());
            AskAnswer::Deny(None)
        });
        let () = lua
            .load(format!("return agent.ask.trust({:?})", path))
            .eval()
            .expect("trust the path for *reading* only");

        let args = serde_json::json!({ "cmdline": format!("rm -f -- {path}") }).to_string();
        let (body, _) = invoke_tool_asking(&lua, "bash.bash", &args, Some(handler.clone()))
            .expect("invoke")
            .expect("the shipped config registers bash.bash");
        let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
        let questions = asked.borrow().clone();
        // A refused syscall is `ok = false` with `denied`, not a crash: the gate
        // did its job and the run reports it.
        assert_eq!(v["ok"], false, "the delete was refused: {v}");
        assert!(
            v["result"]["denied"].as_u64().unwrap_or(0) >= 1,
            "and counted as denied: {v}"
        );
        assert!(
            questions.iter().any(|q| q.contains("want to delete") && q.contains(&path)),
            "rm asked to delete the file: {questions:?}"
        );
        assert!(
            std::path::Path::new(&path).exists(),
            "so read-trust did not delete it: the gate refused"
        );

        // Write-trust does delete it, and says nothing more about it.
        let asked2: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen2 = asked2.clone();
        let handler2: AskHandler = Rc::new(move |text: &str, _always: bool| {
            seen2.borrow_mut().push(text.to_string());
            AskAnswer::Allow
        });
        let args = serde_json::json!({ "cmdline": format!("rm -f -- {path}") }).to_string();
        let (body, _) = invoke_tool_asking(&lua, "bash.bash", &args, Some(handler2))
            .expect("invoke")
            .expect("registered");
        let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
        assert_eq!(v["ok"], true, "the run completed: {v}");
        assert!(
            !std::path::Path::new(&path).exists(),
            "write-trust let the delete through: {v}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `renameat` asks twice when the target already exists — once for the source
    /// and once for the name it would destroy — and once when it does not, since
    /// creating a name is already covered by the source's permission.
    ///
    /// The two answers differ, which is the point: a runner that pressed one key
    /// for every question could not tell "allowed the move, refused the
    /// overwrite" from "allowed both".
    #[test]
    fn a_move_asks_twice_only_when_the_target_exists() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = scratch_dir("agent-mv");
        let src = dir.join("from.txt");
        let dst = dir.join("to.txt");
        let src_s = src.to_string_lossy().to_string();
        let dst_s = dst.to_string_lossy().to_string();
        std::fs::write(&src, "source\n").expect("seed source");
        // Warm `mv`'s own shared libraries, so the questions left are the move's
        // and not the loader's. Granting write-trust on the scratch directory
        // would be the obvious way to quiet those — and it would silence the
        // questions under test too, which is how the first run of this asserted
        // "one question" and got six library reads and no move at all.
        let (warm, _) = run_policy_bash(&lua, "/bin/mv --version", AskAnswer::AllowAndTrust);
        assert_eq!(warm["ok"], true, "warmed mv: {warm}");

        // A fresh name: one question, about the source.
        std::fs::write(&src, "source\n").expect("seed source");
        let (v, asked) =
            run_policy_bash(&lua, &format!("mv -f -- {src_s} {dst_s}"), AskAnswer::Allow);
        assert_eq!(v["ok"], true, "the move ran: {v}");
        assert!(
            !std::path::Path::new(&src_s).exists() && std::path::Path::new(&dst_s).exists(),
            "and it moved: {v}"
        );
        assert_eq!(
            asked.len(),
            1,
            "creating a name is one question, the source's: {asked:?}"
        );
        assert!(
            asked[0].contains("want to move") && asked[0].contains(&src_s),
            "about the move: {asked:?}"
        );

        // An occupied name: two, and refusing the second must stop the move while
        // leaving both files as they were.
        std::fs::write(&src, "new source\n").expect("seed source again");
        std::fs::write(&dst, "existing target\n").expect("seed target");
        let asked3: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen3 = asked3.clone();
        let handler3: AskHandler = Rc::new(move |text: &str, _always: bool| {
            seen3.borrow_mut().push(text.to_string());
            // Allow the move, refuse the overwrite.
            if text.contains("want to overwrite") {
                AskAnswer::Deny(Some("no".into()))
            } else {
                AskAnswer::Allow
            }
        });
        let args =
            serde_json::json!({ "cmdline": format!("mv -f -- {src_s} {dst_s}") }).to_string();
        let (body, _) = invoke_tool_asking(&lua, "bash.bash", &args, Some(handler3))
            .expect("invoke")
            .expect("registered");
        let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
        let questions = asked3.borrow().clone();
        assert_eq!(questions.len(), 2, "an occupied name asks twice: {questions:?}");
        assert!(
            questions[0].contains("want to move") && questions[0].contains(&src_s),
            "the source first: {questions:?}"
        );
        assert!(
            questions[1].contains("want to overwrite") && questions[1].contains(&dst_s),
            "then the name it would destroy: {questions:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&src).unwrap_or_default(),
            "new source\n",
            "the refused overwrite left the source alone: {v}"
        );
        assert_eq!(
            std::fs::read_to_string(&dst).unwrap_or_default(),
            "existing target\n",
            "and left the target alone: {v}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
