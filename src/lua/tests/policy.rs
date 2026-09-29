//! The shipped `lua/policy.lua`: which syscalls become questions, what an
//! answer is remembered against, and how a refusal leaves the filesystem alone.
use super::*;

use crate::testutil::scratch_dir;

/// Grant read trust on a path, the way `lua/init.lua` grants the working
/// directory, so a test can set up "trusted directory, untrusted file".
fn trust_path(lua: &mlua::Lua, path: &std::path::Path) {
    lua.load(format!(
        "require('ask').trust({:?})",
        path.to_string_lossy()
    ))
    .exec()
    .expect("trust");
}

/// The hard-link bypass, closed.
///
/// This is the sharpest of the three gaps because it is not a gap in the
/// *read* gate, it is a way around it:
///
/// ```sh
/// ln /etc/passwd ./notes   # a hard link, inside the trusted cwd
/// cat ./notes              # resolved to ./notes, which is trusted
/// ```
///
/// A hard link has no target for the resolver to chase — unlike a symlink,
/// which `resolve_path` follows and reports as the file it points *at* — so
/// the read looks like a read of a file in the working directory, and the
/// working directory is trusted. The secret arrives with no question.
///
/// Driven through the real shell under the real policy with a really-trusted
/// directory, because the trusted directory is the whole mechanism: a
/// synthetic syscall table would not exercise the path resolution that makes
/// this interesting.
#[test]
fn a_hard_link_out_of_a_trusted_directory_asks() {
    let lua = shipped_vm();
    prime_the_sandbox(&lua);
    let dir = scratch_dir("agent-hardlink");
    // A file the agent is *not* trusted for, standing in for a secret.
    let outside = dir.join("outside-secret.txt");
    std::fs::write(&outside, "hunter2\n").expect("seed");
    // A directory it *is* trusted for, which is where the link will land.
    let inside = dir.join("inside");
    std::fs::create_dir_all(&inside).expect("inside");
    trust_path(&lua, &inside);
    let link = inside.join("notes");
    let link_s = link.to_string_lossy().to_string();

    // Refused. The link is a name inside a trusted directory pointing at a
    // file outside it, and it is asked rather than created quietly.
    let (v, asked) = run_policy_bash(
        &lua,
        &format!("ln {} {link_s}", outside.to_string_lossy()),
        AskAnswer::Deny(Some("not that".into())),
    );
    assert_eq!(v["ok"], false, "the link was refused: {v}");
    assert!(!link.exists(), "and it was not created: {link_s}");
    assert!(
        asked
            .iter()
            .any(|q| q.contains("hard-link") && q.contains(&link_s)),
        "and the question named the new name: {asked:?}"
    );

    // Allowed — and then the read it was for. The point of the gate is that
    // the read is a question too, not that links are banned for ever.
    let (v, _) = run_policy_bash(
        &lua,
        &format!("ln {} {link_s}", outside.to_string_lossy()),
        AskAnswer::AllowAndTrust,
    );
    assert_eq!(v["ok"], true, "allowed this time: {v}");
    assert!(link.exists(), "so the link exists: {link_s}");

    // …and now reading it is silent, and that is *correct* rather than a leak:
    // the answer above was an "always" on writing this name, and `trust_write`
    // records the general grant too, so the user has vouched for this path.
    //
    // The protection is at the point of creation, and the first half is what
    // proves it — a link that was not answered cannot exist, so there is no name
    // in the trusted directory for a later read to follow. The *other* order is
    // the hole this closes: a hard link into a trusted directory that already
    // existed — made by something outside the sandbox — makes a secret readable
    // with no question at all, and no amount of gating `openat` can see it,
    // because the path says nothing about what the name points at. A hard link
    // has no target for the resolver to chase, which is the whole problem.
    let (v, asked) = run_policy_bash(
        &lua,
        &format!("cat {link_s}"),
        AskAnswer::Deny(Some("no".into())),
    );
    assert_eq!(v["ok"], true, "the read ran: {v}");
    assert!(
        !asked.iter().any(|q| q.contains("read")),
        "and asked nothing — the name was granted above, and the grant is for the \
         name rather than for the inode behind it. {asked:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `symlinkat` gets its own test because the two are *not* the same case, and
/// treating them as one would be wrong in a way that only shows up later.
///
/// A symlink is chased by the resolver, so a read through one already reports
/// the file it points at and asks about that. What a symlink adds is the power
/// to make the *next* call mean somewhere else: a dangling target resolves to
/// itself, so `ln -s /elsewhere/x ./y` followed by a create through `./y` is a
/// write to `/elsewhere/x` wearing a trusted name. So the gate is on the name
/// being created — and the silent-create rule must not apply to it, which is
/// the same asymmetry `linkat` needs and for a different reason.
#[test]
fn a_symlink_out_of_a_trusted_directory_asks() {
    let lua = shipped_vm();
    prime_the_sandbox(&lua);
    let dir = scratch_dir("agent-symlink");
    let inside = dir.join("inside");
    std::fs::create_dir_all(&inside).expect("inside");
    trust_path(&lua, &inside);
    let link = inside.join("escape");
    let link_s = link.to_string_lossy().to_string();
    // A target that does not exist, which is the case that matters: a
    // dangling symlink resolves to itself, so the *next* write through it
    // lands outside the trusted directory under a trusted name.
    let target = dir.join("outside/does-not-exist-yet");

    let (v, asked) = run_policy_bash(
        &lua,
        &format!("ln -s {} {link_s}", target.to_string_lossy()),
        AskAnswer::Deny(Some("no".into())),
    );
    assert_eq!(v["ok"], false, "the symlink was refused: {v}");
    assert!(
        std::fs::symlink_metadata(&link).is_err(),
        "and not created: {link_s}"
    );
    assert!(
        asked
            .iter()
            .any(|q| q.contains("symlink") && q.contains(&link_s)),
        "and the question named the new name: {asked:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `fchmod` names no path — it names a descriptor — and that used to be
/// recorded as a reason it could not be gated at all, with the consequence
/// that read-trust on a file implied being able to make that file
/// executable. The engine now reads the descriptor back through
/// `/proc/<pid>/fd/<n>`, so the question names the real file.
///
/// Driven through the real shell, because a synthetic syscall table cannot
/// fake an `/proc` read: the path in the question *is* what the engine looked
/// up, and faking it would test the fake.
#[test]
fn fchmod_asks_about_the_file_its_descriptor_names() {
    let lua = shipped_vm();
    prime_the_sandbox(&lua);
    let dir = scratch_dir("agent-fchmod-gated");
    let target = dir.join("not-trusted.txt");
    std::fs::write(&target, "x\n").expect("seed");
    let target_s = target.to_string_lossy().to_string();

    // `cp --preserve=mode` chmods the *destination* by descriptor, through
    // `fchmod`, having opened it. Refused, and the question names the file.
    // `cp --preserve=mode` reads its share of the system tree on the way — libc,
    // libacl — before it ever reaches the mode, so a handler that denies
    // everything stops it long before the interesting syscall. Deny only the
    // mode question and let the rest through.
    let (v, asked) = run_policy_bash_except(
        &lua,
        &format!("cp --preserve=mode /dev/null {target_s}"),
        "change the mode of",
    );
    assert!(
        asked
            .iter()
            .any(|q| q.contains("change the mode of") && q.contains(&target_s)),
        "fchmod now asks, naming the file the descriptor points at: {asked:?}"
    );
    // …and the file is not made executable, which is the thing being closed.
    let mode = std::fs::metadata(&target)
        .map(|m| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o777
            }
            #[cfg(not(unix))]
            {
                0
            }
        })
        .expect("cp made the file before trying to chmod it");
    // The proof is the *difference*, not an absolute. `/dev/null` is `0o666`, and
    // `cp --preserve=mode` would have made the copy that. It is not that: the
    // file carries the mode `open(2)` gave it at creation, filtered by umask, and
    // the `fchmod` that would have made it `0o666` was refused. That is the gap
    // closed — read-trust on a file no longer implies being able to change its
    // mode, which is the whole of what `fchmod` can do.
    assert_ne!(
        mode, 0o666,
        "the mode was NOT copied from the source: --preserve=mode would have made \
         it 0o666 like /dev/null, and it is {mode:#o} (from {v})"
    );
    assert_eq!(
        mode & !0o666 & 0o7777,
        0,
        "and no bit outside the create-time mode was set: {mode:#o}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

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
    let v: serde_json::Value =
        serde_json::from_str(&drive_to_end(&mut one, step1)).expect("tool json");
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
    let v: serde_json::Value =
        serde_json::from_str(&drive_to_end(&mut two, step2)).expect("tool json");
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
    let (v, asked) = run_policy_bash(&lua, &format!("echo hi > {path}"), AskAnswer::Allow);
    assert_eq!(v["ok"], true, "an allowed write runs: {v}");
    let q = asked
        .iter()
        .find(|q| q.contains("want to write"))
        .unwrap_or_else(|| panic!("a write is asked: {asked:?}"));
    assert!(
        q.contains(&path),
        "the write question names the file: {q:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "hi\n",
        "and it wrote"
    );

    // A *read* is asked too, and with the read question: "may I read here"
    // and "may I write here" are two decisions, and the flag reaching the ask
    // is what keeps them apart.
    let (v, asked) = run_policy_bash(&lua, &format!("cat {path}"), AskAnswer::Allow);
    assert_eq!(v["ok"], true, "{v}");
    let q = asked
        .iter()
        .find(|q| q.contains("want to read"))
        .unwrap_or_else(|| panic!("a read is asked: {asked:?}"));
    assert!(
        q.contains(&path),
        "with the read question and the path: {q:?}"
    );

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
    // Matched on the subject: the command line quoted in every question is
    // `echo nope > <other>`, so a bare substring match would be satisfied by
    // the asker's own command line and would pass even if nothing had asked.
    assert!(
        asked_subject(&asked, "write", &other),
        "and it was asked: {asked:?}"
    );
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
    // The port is printed once by the question itself and never folded into
    // the address beside it. Measured on the part before the asker is
    // appended, because the command line legitimately contains the same
    // `/dev/tcp/127.0.0.1/<port>` — that is the point of quoting it.
    let question = q.split(" (pid ").next().expect("non-empty");
    assert_eq!(
        question.matches(&port.to_string()).count(),
        1,
        "and the port exactly once in the question, not folded into the \
             address too: {q:?}"
    );
    // The asker is named. Not decoration: `connect` is asked about a host,
    // and every gate that reached the same host would ask the same question
    // — so without the asker there is nothing on screen to tell an `ssh` from
    // the build the user started.
    assert!(
        q.contains(" (pid ") && q.contains(" [bash -c exec 3<>"),
        "and names the asking process and its command line: {q:?}"
    );
    assert!(q.contains("at port"), "in the mode's own wording: {q:?}");
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

/// The names an MCP result listed, from a value that may be a list or an
/// object: a list that came back empty is an object with no keys rather than
/// an array with no elements. Asserting on `as_array()` alone would read
/// that as a missing field, which is how the first run of this test failed
/// on a tool that had worked.
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
    let (v, asked) = run_policy_bash(
        &lua,
        &format!("echo mine > {path_s}"),
        AskAnswer::Deny(None),
    );
    assert_eq!(v["ok"], true, "the create ran: {v}");
    assert!(
        !asked.iter().any(|q| q.contains("want to write")),
        "and asked nothing: {asked:?}"
    );
    // ...which is why a second write is also silent.
    let (_, asked) = run_policy_bash(
        &lua,
        &format!("echo again > {path_s}"),
        AskAnswer::Deny(None),
    );
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
    let (v, asked) = run_policy_bash(
        &lua,
        &format!("echo nope > {path_s}"),
        AskAnswer::Deny(None),
    );
    assert_eq!(v["ok"], false, "a refused write is not ok: {v}");
    assert!(
        asked
            .iter()
            .any(|q| q.contains("want to write") && q.contains(&path_s)),
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
    let r = handover(&serde_json::json!({ "paths": ["/no/such/path", &path_s] }).to_string());
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
    lua.load("agent.ask.block('/usr')")
        .exec()
        .expect("block /usr");
    let refused: bool = lua
        .load("return not pcall(agent.ask.trust, '/usr/lib/inside-blocked.so')")
        .eval()
        .expect("pcall");
    assert!(
        refused,
        "a path inside a blocked directory is still refused: only an exact \
             block is a preference"
    );
    lua.load("agent.ask.unblock('/usr')")
        .exec()
        .expect("unblock /usr");

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
    assert!(
        asked,
        "reading the excluded file asks again rather than answering itself"
    );

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
    for p in [
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/dev/full",
    ] {
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
    for p in [
        "/dev/tty",
        "/dev/console",
        "/dev/shm",
        "/dev/pts/0",
        "/dev/ptmx",
        "/dev/sda",
    ] {
        let trusted: bool = lua
            .load(format!("return agent.ask.is_trusted({p:?})"))
            .eval()
            .unwrap_or_else(|e| panic!("is_trusted({p}): {e}"));
        assert!(
            !trusted,
            "{p} is not granted: it is not one of the empty ones"
        );
    }

    // And the effect, on a real run: a redirect into /dev/null is silent,
    // while a write to a device that was not granted still asks.
    let (v, asked) = run_policy_bash(&lua, "echo hello > /dev/null", AskAnswer::Deny(None));
    assert_eq!(v["ok"], true, "the redirect ran: {v}");
    assert_eq!(v["result"]["denied"], 0, "and nothing was refused: {v}");
    assert!(
        !asked.iter().any(|q| q.contains("/dev/null")),
        "writing to /dev/null asks nothing: {asked:?}"
    );

    let (v, asked) = run_policy_bash(&lua, "echo hello > /dev/full", AskAnswer::Deny(None));
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
    for p in [
        "/usr",
        "/lib",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/libc.so.6",
    ] {
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
        assert!(
            !writable,
            "{p} is not write-trusted: it was granted to be read"
        );
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
    assert!(
        !proc,
        "/proc is not granted as a tree — only those two files are"
    );
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
    assert!(
        !shadow,
        "but nothing else in /etc is — the grant is one file"
    );

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
        v["result"]["stdout"]
            .as_str()
            .unwrap_or("")
            .contains("/usr/lib"),
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
    let (v, asked) = run_policy_bash(
        &lua,
        &format!("echo there > {path_s}"),
        AskAnswer::Deny(None),
    );
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

    let (v, asked) = run_policy_bash(
        &lua,
        &format!("echo nope > {path_s}"),
        AskAnswer::Deny(None),
    );
    assert_eq!(v["ok"], false, "a refused overwrite is not ok: {v}");
    assert!(
        asked
            .iter()
            .any(|q| q.contains("want to write") && q.contains(&path_s)),
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
        asked
            .iter()
            .any(|q| q.contains("want to write") && q.contains(&path_s)),
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
    let mode_of =
        |p: &std::path::Path| std::fs::metadata(p).expect("stat").permissions().mode() & 0o777;
    let before = mode_of(&path);
    // Not the exact bits — the temp dir's umask decides those — but the one
    // thing that matters: no execute bit yet.
    assert_eq!(before & 0o111, 0, "precondition: not executable yet");

    // Refused: asked, and the mode is untouched.
    let (v, asked) = run_policy_bash(&lua, &format!("chmod 0700 {path_s}"), AskAnswer::Deny(None));
    assert_eq!(v["ok"], false, "a refused chmod is not ok: {v}");
    assert!(
        asked
            .iter()
            .any(|q| q.contains("change the mode") && q.contains(&path_s)),
        "it asks, naming the file and the change: {asked:?}"
    );
    assert_eq!(mode_of(&path), before, "and the mode did not change");

    // Allowed: it goes through, and only then.
    let (v, asked) = run_policy_bash(&lua, &format!("chmod 0700 {path_s}"), AskAnswer::Allow);
    assert_eq!(v["ok"], true, "an allowed chmod runs: {v}");
    assert!(
        asked.iter().any(|q| q.contains("change the mode")),
        "and it still asked: {asked:?}"
    );
    assert_eq!(mode_of(&path), 0o700, "so the mode changed");

    // A *different* mode this time, because `chmod` to the mode a file
    // already has makes no syscall at all — so there would be nothing to
    // gate, and the run would pass for the wrong reason.
    let (v, asked) = run_policy_bash(&lua, &format!("chmod 0644 {path_s}"), AskAnswer::Deny(None));
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
        questions
            .iter()
            .any(|q| q.contains("want to delete") && q.contains(&path)),
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
    let (v, asked) = run_policy_bash(&lua, &format!("mv -f -- {src_s} {dst_s}"), AskAnswer::Allow);
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
    let args = serde_json::json!({ "cmdline": format!("mv -f -- {src_s} {dst_s}") }).to_string();
    let (body, _) = invoke_tool_asking(&lua, "bash.bash", &args, Some(handler3))
        .expect("invoke")
        .expect("registered");
    let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
    let questions = asked3.borrow().clone();
    assert_eq!(
        questions.len(),
        2,
        "an occupied name asks twice: {questions:?}"
    );
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

/// Drive one gate of the shipped policy the way `agent.bash` drives it — in
/// a coroutine, with no panel — and hand back the question it raised
/// together with what the callback returned once `verdict` reached it.
///
/// `run` is the run being driven, and it is how a test says "and now a
/// different command": the helper keeps one policy table per run in the VM's
/// globals, built by `require("policy").new()`, which is exactly what
/// `bash_tool.lua` does once per call. A different run is a different table,
/// so anything a gate remembered in the first one is unreachable from the
/// second — which is the property under test, arranged rather than simulated.
///
/// This is also the only way to reach a gate for a syscall nothing in the
/// suite provokes: `io_uring_*` needs a program that speaks the ring protocol,
/// and there is no compiler here to build one. What that skips is the seccomp
/// interception step, which [`MASK`] and the engine's own filter tests already
/// cover. What it keeps is the part this change adds — the wording, the third
/// answer, and whether a second call goes quiet.
///
/// `paths` are `(slot, text)` pairs, 1-based as `syscall_into_table` writes
/// them: `sys.str` is sparse and keyed by number, which JSON objects cannot
/// express, so they are carried as a list and re-keyed here. The table is
/// always built, empty or not, because the engine always sets one.
fn ask_through_gate(
    lua: &mlua::Lua,
    run: i64,
    gate: &str,
    sys: &serde_json::Value,
    paths: &[(usize, &str)],
    verdict: &str,
) -> (Option<mlua::Table>, mlua::Value) {
    ask_through_gate_with_addr(lua, run, gate, sys, paths, &[], verdict)
}

/// [`ask_through_gate`], plus a decoded endpoint for the address gates.
///
/// `sys.addr` is passed as a JSON *string* and built in Lua for the same
/// reason `sys.str` is: both are keyed by argument slot, and a JSON object
/// has string keys, so `sc.addr` and `sc.paths` — which both read numeric
/// keys — would see nothing.
fn ask_through_gate_with_addr(
    lua: &mlua::Lua,
    run: i64,
    gate: &str,
    sys: &serde_json::Value,
    paths: &[(usize, &str)],
    addrs: &[(usize, &str)],
    verdict: &str,
) -> (Option<mlua::Table>, mlua::Value) {
    // The syscall table arrives as JSON text and is decoded by the same
    // bridge primitive the Lua side decodes MCP replies with, rather than
    // being spliced into the chunk: a JSON object is not a Lua table, and
    // writing it out by hand here would be a second, drifting copy of the
    // shape `src/lua/sandbox.rs` builds.
    let str = serde_json::to_string(&paths.to_vec()).expect("path list");
    let addr = serde_json::to_string(&addrs.to_vec()).expect("addr list");
    lua.load(
        r#"
        local gate_name, run, sys_json, str_json, addr_json, verdict_src = ...
        -- One policy table per run, kept here rather than reloaded each call so
        -- that two calls in the same run really do share it. `new()` is what
        -- `bash_tool.lua` calls; the registry is only standing in for the fact
        -- that a real run holds its table for its whole length.
        local runs = _G.__test_policy_runs or {}
        _G.__test_policy_runs = runs
        local policy = runs[run]
        if policy == nil then
          policy = require("policy").new()
          runs[run] = policy
        end
        local gate = policy[gate_name]
        assert(type(gate) == "function",
               "the shipped policy has no gate named " .. tostring(gate_name))
        local sys = agent.api.json_decode(sys_json)
        sys.str = sys.str or {}
        for _, entry in ipairs(agent.api.json_decode(str_json)) do
          sys.str[entry[1]] = entry[2]
        end
        sys.addr = sys.addr or {}
        for _, entry in ipairs(agent.api.json_decode(addr_json)) do
          sys.addr[entry[1]] = agent.api.json_decode(entry[2])
        end
        -- `verdict_src` is Lua source, so that a call site can say what the user
        -- pressed — `true`, `agent.deny("…")`, or an allow-and-remember table —
        -- in the same words the policy docs use rather than by hand-building it.
        local verdict = load("return " .. verdict_src)()
        local co = coroutine.create(function() return gate(sys) end)
        local ok, q = coroutine.resume(co)
        assert(ok, tostring(q))
        -- A gate that answers itself never yields, and the coroutine simply
        -- finishes with `true`. That is not a failure mode of the helper: it is
        -- the thing a granted capability looks like from out here, and the one
        -- way to tell it from a question that was asked and allowed. So the
        -- yield and the return are both reported, and which one happened is the
        -- caller's business to assert.
        if coroutine.status(co) == "dead" then
          -- Two legitimate ways to finish without asking: it answered itself
          -- (`true` — a gate remembering a grant it was given), or it *declined*,
          -- which is what a gate that cannot describe the call does rather than
          -- waving it through. Asserting that a gate must always ask would be
          -- asserting the opposite of what a policy is for.
          assert(q == true or type(q) == "table",
                 "a gate that neither asked nor declined returned " .. tostring(q))
          return nil, q
        end
        assert(type(q) == "table",
               "the gate asked, and the question was: " .. tostring(q))
        local done, ret = coroutine.resume(co, verdict)
        assert(done, tostring(ret))
        return q, ret
    "#,
    )
    .call::<(Option<mlua::Table>, mlua::Value)>((gate, run, sys.to_string(), str, addr, verdict))
    .expect("gate ran")
}

/// The syscall table the engine would have built for a ring: a descriptor,
/// and no path anywhere in it. The command line is the ordinary
/// server-worker shape, which is the point — the question has to be
/// answerable when the asker is a thread with no argument list.
fn ring_call(name: &str) -> serde_json::Value {
    json!({
        "name": name,
        "pid": 4242,
        "args": [3, 1, 1, 0, 0, 0],
        "cmdline": "nginx: worker process",
    })
}

/// A *different process's* call in the same run: a different pid, same
/// syscall, same everything else. The grant is one closure belonging to one
/// gate, not to one process, so it has to reach every worker in the tree —
/// which is also how the flood would return if the memory were anywhere near
/// a pid.
fn worker_call(gate: &str) -> serde_json::Value {
    json!({
        "name": gate,
        "pid": 4311,
        "args": [3, 1, 1, 0, 0, 0],
        "cmdline": "nginx: worker process",
    })
}

/// An `io_uring` ring is the one gate here added because of what it
/// *defeats* rather than what it allows: `IORING_OP_OPENAT` is a
/// submission-queue opcode rather than a syscall, so a program that speaks
/// the ring can open, unlink and rename files without `openat`, `unlinkat`
/// or `renameat` ever being called. Three things follow, and they are three
/// separate claims:
///
///  - all three entry points are gated, because gating `setup` alone would
///    be undone by `enter` and gating `enter` alone by `register`;
///  - each names no path, so the path tables cannot answer one of these by
///    themselves — a grant about a file must not answer a question about a
///    capability;
///  - each says what allowing it *means*, because "yes" here is not
///    permission to do one thing — it is permission to do everything the
///    rest of this policy asks about, silently, for as long as the ring
///    lives. A user who read only the first clause would not know that.
#[test]
fn an_io_uring_ring_is_asked_about_exactly_what_it_defeats() {
    let lua = shipped_vm();
    prime_the_sandbox(&lua);

    for gate in ["io_uring_setup", "io_uring_enter", "io_uring_register"] {
        let (q, ret) = ask_through_gate(&lua, 11, gate, &ring_call(gate), &[], "true");
        let q = q.expect("the gate asked");
        let description: String = q.get("description").expect("a description");

        assert!(
            description.contains(&format!("{gate} (pid 4242) requests")),
            "{gate} names itself and who is asking: {description}"
        );
        assert!(
            description.contains("without asking about it"),
            "{gate} says what a yes actually grants, because it is not one \
                 thing: {description}"
        );
        assert!(
            description.contains("nginx: worker process"),
            "{gate} names the tracee, which for a ring worker is the only \
                 thing that identifies it: {description}"
        );
        assert_eq!(
            q.get::<String>("always").expect("an always field"),
            "lways this run",
            "{gate} names the third answer by its own scope. `lways` would be a \
                 promise the grant cannot keep: the memory is keyed on the sandbox \
                 run, so the next command asks again"
        );
        assert!(
            q.get::<mlua::Function>("remember").is_ok(),
            "{gate} brings its own memory: there is no path table that could \
                 hold a capability, so it hands `ask` the function to call"
        );
        assert_eq!(
            q.get::<Option<String>>("path").expect("a path field"),
            None,
            "{gate} names no path, so the trust tables cannot answer it \
                 before the user does"
        );
        assert!(
            matches!(ret, mlua::Value::Boolean(true)),
            "{gate} allowed on a plain yes: {ret:?}"
        );
    }
}

/// Accepting the risk stops the *flood* without widening anything. The
/// grant lives for one command — the same command, every worker in its tree,
/// however many times — and dies with it.
///
/// Asserted against behaviour rather than read off a flag, because the two
/// designs this could have been look identical from the outside if the test
/// only looked at the field:
///
///  - a plain `yes` asks again. One operation, like every other gate.
///  - an "always" answers itself for the rest of the run, and across the
///    tree — a different pid, the same grant.
///  - it stops there. A *different run* — which here means a different policy
///    table, exactly as `bash_tool.lua` builds one per call — asks again.
///    This is the half that matters, and the one a table shared between runs
///    would fail.
///  - and one grant silences one gate, never two.
#[test]
fn accepting_a_capability_stops_the_flood_for_that_run_only() {
    let lua = shipped_vm();
    prime_the_sandbox(&lua);

    // A plain `yes` is one operation.
    let (q, ret) = ask_through_gate(&lua, 21, "bpf", &ring_call("bpf"), &[], "true");
    let asked = q.expect("a plain yes is still a question");
    assert_eq!(
        asked.get::<String>("description").expect("description"),
        "bpf (pid 4242) requests to load a program into the kernel \
             [nginx: worker process]",
        "and it is about the capability itself, which is the whole of what a \
             capability gate can name"
    );
    assert!(
        matches!(ret, mlua::Value::Boolean(true)),
        "allowed: {ret:?}"
    );
    let (q, _) = ask_through_gate(&lua, 21, "bpf", &ring_call("bpf"), &[], "true");
    assert_eq!(
        q.expect("a plain yes is still a question")
            .get::<String>("description")
            .expect("description"),
        asked.get::<String>("description").expect("description"),
        "a plain yes asks again — the same question, so the second asking is \
             a decision and not a difference in the syscall"
    );

    // "Always" answers itself for the rest of the run, and across the tree.
    let (_, granted) = ask_through_gate(&lua, 21, "bpf", &ring_call("bpf"), &[], TRUST);
    assert!(
        matches!(granted, mlua::Value::Boolean(true)),
        "the grant is an allow: {granted:?}"
    );
    assert_through_gate_allows_silently(&lua, 21, "bpf", &ring_call("bpf"));
    assert_through_gate_allows_silently(&lua, 21, "bpf", &worker_call("bpf"));

    // …and stops there. Run 22 is a different command, and a different table.
    assert_through_gate_asks(&lua, 22, "bpf", &ring_call("bpf"));

    // …and one grant silences one gate, not every gate.
    assert_through_gate_asks(&lua, 21, "userfaultfd", &ring_call("userfaultfd"));

    // …and it wrote nothing into the tables that *do* outlive a run. A
    // capability is not a file or a host, and a trust entry that outlived the
    // run would be a grant the user never scoped.
    assert_eq!(
        trusted_entry_count(&lua),
        trusted_entry_count(&lua),
        "the path tables are as they were: a capability has no path to record"
    );
}

/// The scoping claim, stated as the property it is: the memory is not *scoped*
/// to a run, it is unreachable from any other run. Proved by handing the same
/// gate name to two policy tables built the way two commands build them, and
/// by showing that the second knows nothing about the first's grant — with no
/// run id, no pid, and no table in between for the two to share.
///
/// This is the test the previous design could not have had. It keyed grants on
/// a sandbox id and was safe only because the id was a never-reused counter;
/// had it been a pid, a recycled pid would have inherited a stale grant and
/// this test — the shape of the bug — would have passed, because both halves
/// would have looked correct. Here there is no key to recycle.
#[test]
fn a_grant_is_unreachable_from_the_next_run_rather_than_scoped_to_it() {
    let lua = shipped_vm();
    prime_the_sandbox(&lua);

    // The same gate, two policy tables, one grant in the first. Built here
    // rather than through the helper so the two tables are visibly distinct
    // objects with nothing but the module between them.
    lua.load(
        r#"
        local runs = _G.__test_policy_runs or {}
        _G.__test_policy_runs = runs
        runs.first = require("policy").new()
        runs.second = require("policy").new()
        assert(runs.first ~= runs.second, "two constructions, two tables")
    "#,
    )
    .exec()
    .expect("two policies");

    // Grant in the first.
    let (_, granted) = ask_through_gate(&lua, 100, "bpf", &ring_call("bpf"), &[], TRUST);
    assert!(matches!(granted, mlua::Value::Boolean(true)));
    assert_through_gate_allows_silently(&lua, 100, "bpf", &ring_call("bpf"));

    // The second has not heard of it. Not "asked again because the scope
    // ended" — asked again because there is nothing there to read.
    assert_through_gate_asks(&lua, 101, "bpf", &ring_call("bpf"));

    // And the first is untouched by the second having asked: a question is
    // not a grant.
    assert_through_gate_allows_silently(&lua, 100, "bpf", &ring_call("bpf"));

    // Denying in a fresh run records nothing anywhere, either — there is
    // nowhere for it to be recorded.
    let (q, denied) = ask_through_gate(
        &lua,
        102,
        "bpf",
        &ring_call("bpf"),
        &[],
        r#"agent.deny("not this time")"#,
    );
    assert!(q.is_some(), "a fresh run asks, and can be refused");
    assert!(
        !matches!(denied, mlua::Value::Boolean(true)),
        "and the refusal is a refusal: {denied:?}"
    );
    assert_through_gate_asks(&lua, 102, "bpf", &ring_call("bpf"));
}

/// The verdict "allow, and remember it" — the one `AskAnswer::AllowAndTrust`
/// becomes (`verdict_to_lua` in `src/lua/config.rs`). Spelled out here so
/// the two ends of the protocol cannot drift: a test that granted with a
/// different shape would silently test nothing.
const TRUST: &str = r#"{ __agent_verdict = "allow", trust = true }"#;

fn assert_through_gate_allows_silently(
    lua: &mlua::Lua,
    run: i64,
    gate: &str,
    sys: &serde_json::Value,
) {
    let (q, ret) = ask_through_gate(lua, run, gate, sys, &[], "true");
    assert!(
        q.is_none(),
        "{gate} should not have asked in run {run}, but raised: {:?}",
        q.and_then(|q| q.get::<String>("description").ok())
    );
    assert!(
        matches!(ret, mlua::Value::Boolean(true)),
        "{gate} allowed: {ret:?}"
    );
}

/// The gate raised a question with a description naming `gate`.
fn assert_through_gate_asks(lua: &mlua::Lua, run: i64, gate: &str, sys: &serde_json::Value) {
    let (q, _) = ask_through_gate(lua, run, gate, sys, &[], "true");
    let description: String = q
        .expect("the gate asked")
        .get("description")
        .expect("a description");
    assert!(
        description.starts_with(&format!("{gate} (pid ")),
        "{gate} should have asked in run {run}: {description}"
    );
}

/// How many entries the path trust tables hold — the measure of "did this
/// answer get remembered". Counted before and after rather than pinned to a
/// number, because the shipped config's pre-grants are a different decision
/// from this one and are not what is under test here.
fn trusted_entry_count(lua: &mlua::Lua) -> usize {
    lua.load(
        r#"
        local ask = require("ask")
        local n = 0
        for _ in pairs(ask.trusted_paths()) do n = n + 1 end
        for _ in pairs(ask.trusted_write_paths()) do n = n + 1 end
        return n
    "#,
    )
    .eval()
    .expect("trust tables")
}

/// Refusing a capability is a real refusal: the gate returns the denial
/// object rather than a `true` the engine would read as a verdict to
/// continue on. A gate that could only allow would be a gate that had been
/// renamed.
#[test]
fn a_refused_capability_denies_rather_than_allowing() {
    let lua = shipped_vm();
    prime_the_sandbox(&lua);

    let (_, ret) = ask_through_gate(
        &lua,
        31,
        "open_by_handle_at",
        &json!({ "name": "open_by_handle_at", "pid": 99, "args": [3, 4, 0, 0, 0, 0] }),
        &[],
        r#"agent.deny("no handles here")"#,
    );
    let denial: mlua::Table = match ret {
        mlua::Value::Table(t) => t,
        other => panic!("a refusal is a denial table, got {other:?}"),
    };
    assert_eq!(
        denial.get::<String>("__agent_verdict").expect("a verdict"),
        "deny",
        "and it carries the reason the panel shows"
    );
}

/// The handle pair is deliberately asymmetric, and the reason is worth
/// pinning rather than leaving to a reader: a `file_handle` carries no path
/// back, so remembering that a path may be *read* cannot answer a question
/// about spending one.
///
/// Proven the hard way, by handing `open_by_handle_at` a trusted path in its
/// `str` table — something the engine does not do, and exactly what would
/// happen if someone "fixed" `open_by_handle_at_names_no_path_and_its_partner_names_one`
/// by adding the syscall to `CSTRING_ARGS`. `ask.ask` short-circuits to
/// `true` on a trusted path, so without `ask_capability` dropping the field
/// the gate would answer itself from a grant the user made about a *file*,
/// and the whole capability boundary would quietly become a path one.
#[test]
fn trusting_a_path_does_not_silence_opening_a_handle() {
    let lua = shipped_vm();
    prime_the_sandbox(&lua);
    let dir = scratch_dir("agent-handle-trust");
    std::fs::write(dir.join("secret"), "x\n").expect("seed");
    let path = dir.join("secret").to_string_lossy().to_string();
    lua.load(format!("require('ask').trust({path:?})"))
        .exec()
        .expect("trust the path outright");

    let named = json!({
        "name": "name_to_handle_at", "pid": 7, "args": [-100, 0, 0, 0, 0, 0],
    });
    let asked = json!({
        "name": "open_by_handle_at", "pid": 7, "args": [3, 4, 0, 0, 0, 0],
    });

    let (q, _) = ask_through_gate(
        &lua,
        7,
        "open_by_handle_at",
        &asked,
        &[(4, path.as_str())],
        "true",
    );
    assert_eq!(
        q.expect("the gate asked")
            .get::<Option<String>>("path")
            .expect("a path field"),
        None,
        "the gate dropped the path, so the trust table cannot answer it: the \
             grant above was about reading a file, and this is about an opaque \
             handle that might not be one"
    );
    // A *different* path for the partner, one nothing trusts — a trusted
    // path would (correctly) answer itself before any question, which is the
    // behaviour above rather than a contrast to it.
    let other = dir.join("elsewhere").to_string_lossy().to_string();
    let (part, _) = ask_through_gate(
        &lua,
        7,
        "name_to_handle_at",
        &named,
        &[(2, other.as_str())],
        "true",
    );
    assert_eq!(
        part.expect("the gate asked")
            .get::<Option<String>>("path")
            .expect("a path field"),
        Some(other),
        "…while its partner does keep the path, which is what makes it a \
             read-trust question instead of a capability one"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Every gate this file ships names who is asking, and this checks that for
/// all of them rather than for the one a given test happened to exercise.
///
/// The reason to want the whole list: the asker is appended by hand at each
/// question, so a new gate — or a new branch on an existing one — is silent
/// until someone notices. That is the same failure as a stale count in a
/// comment, and it is caught here by construction rather than by review.
///
/// Driven through the same coroutine helper as the capability gates, with a
/// synthetic syscall table so the *name* is a name and not `/bin/sh`. Each
/// question is checked for the pid and the command line independently, since
/// the command line is dropped when `/proc` cannot be read and the pid is not.
#[test]
fn every_gate_names_who_is_asking() {
    let lua = shipped_vm();
    prime_the_sandbox(&lua);

    // The gates, with whatever each one needs to reach a question. Paths
    // point at a file that exists, so the "creating a new name is not a
    // question" rule does not quietly answer on their behalf; the address
    // gates need an endpoint to decode.
    let dir = scratch_dir("agent-asker");
    let existing = dir.join("taken.txt");
    std::fs::write(&existing, "x\n").expect("seed");
    let existing = existing.to_string_lossy().to_string();
    let target = dir.join("other.txt").to_string_lossy().to_string();
    let addr = json!({ "family": "inet", "ip": "93.184.216.34", "port": 443 });

    let gates: Vec<String> = lua
        .load(
            r#"
        local policy = require("policy").new()
        local names = {}
        for name in pairs(policy) do names[#names + 1] = name end
        table.sort(names)
        return table.concat(names, "\n")
    "#,
        )
        .eval::<String>()
        .expect("gate names")
        .lines()
        .map(str::to_string)
        .collect();

    assert!(
        !gates.is_empty(),
        "the shipped policy has gates; an empty list would pass this vacuously"
    );

    let mut checked = 0;
    let skipped: Vec<String> = Vec::new();
    for gate in &gates {
        // A syscall table shaped for the gate: a name and pid always, and the
        // arguments it needs. `cmdline` is the same for all of them so that a
        // failure names the gate that forgot rather than an ambiguous string.
        let mut args = vec![json!(0); 6];
        let mut strs: Vec<(usize, String)> = vec![];
        let mut addr_slot = None;
        match gate.as_str() {
            // openat(dirfd, path, flags, …): slot 1 is the path, slot 2 flags.
            // A write flag, so the write branch is the one that asks.
            "openat" => {
                args[1] = json!(existing);
                args[2] = json!(1); // O_WRONLY
                strs.push((2, existing.clone()));
            }
            // …-at family: the path is slot 1, flags (where present) slot 2.
            "unlinkat" | "chmod" | "setxattr" | "removexattr" => {
                args[1] = json!(existing);
                args[2] = json!(0);
                strs.push((2, existing.clone()));
                if gate.ends_with("xattr") {
                    args[1] = json!(existing);
                    args[2] = json!(existing); // the attribute name
                    strs.push((3, existing.clone()));
                }
            }
            "fchmodat" => {
                args[1] = json!(existing);
                strs.push((2, existing.clone()));
            }
            "lsetxattr" | "lremovexattr" => {
                args[0] = json!(existing);
                args[1] = json!(existing);
                strs.push((1, existing.clone()));
                strs.push((2, existing.clone()));
            }
            // linkat(olddirfd, oldpath, newdirfd, newpath, flags) and
            // symlinkat(target, newdirfd, linkpath): two names each, the second
            // being the one being created.
            "linkat" => {
                args[1] = json!(existing);
                args[3] = json!(target);
                strs.push((2, existing.clone()));
                strs.push((4, target.clone()));
            }
            "symlinkat" => {
                args[0] = json!(existing);
                args[2] = json!(target);
                strs.push((1, existing.clone()));
                strs.push((3, target.clone()));
            }
            // The plain forms: same two names, slots 0 and 1. In the mask because
            // they are the ones glibc actually issues — `ln -s` never reaches
            // `symlinkat` — so a sweep that skipped them would not notice if they
            // stopped asking.
            "link" | "symlink" => {
                args[0] = json!(existing);
                args[1] = json!(target);
                strs.push((1, existing.clone()));
                strs.push((2, target.clone()));
            }
            // fchmod(fd, mode): the path comes from the *engine* reading the
            // descriptor back through /proc, which a synthetic syscall table
            // cannot fake — so the gate declines rather than waving it through,
            // which is what it does for a pipe. Asserted properly in its own test,
            // through a real command.
            "fchmod" => {
                args[0] = json!(7);
            }
            "renameat" | "renameat2" => {
                args[1] = json!(existing);
                args[3] = json!(target);
                strs.push((2, existing.clone()));
                strs.push((4, target.clone()));
            }
            "name_to_handle_at" => {
                args[1] = json!(existing);
                strs.push((2, target.clone()));
            }
            "connect" | "sendto" => {
                args[1] = json!(0x1000);
                addr_slot = Some(2);
            }
            "bind" => {
                args[1] = json!(0x1000);
                addr_slot = Some(2);
            }
            _ => {
                // The capability gates, and anything added later: no
                // arguments are decoded, which is itself part of the design.
            }
        }

        let sys = json!({
            "name": gate,
            "pid": 31337,
            "cmdline": "cargo build --release",
            "args": args,
        });

        let refs: Vec<(usize, &str)> = strs.iter().map(|(slot, t)| (*slot, t.as_str())).collect();
        let endpoint = addr.to_string();
        let addrs: Vec<(usize, &str)> = addr_slot
            .map(|slot| vec![(slot, endpoint.as_str())])
            .unwrap_or_default();
        let (q, _) = ask_through_gate_with_addr(&lua, 41, gate, &sys, &refs, &addrs, "true");
        let Some(q) = q else {
            // A gate that answered itself has no question to check. The
            // working directory is trusted, so a path inside it would be
            // silent — and that is correct behaviour, not a missing asker.
            continue;
        };
        let description: String = q.get("description").expect("a description");
        assert!(
            description.contains("(pid 31337)"),
            "{gate} does not name the pid that is asking: {description:?}"
        );
        assert!(
            description.contains("[cargo build --release]"),
            "{gate} does not name the command line of the asker: {description:?}"
        );
        checked += 1;
    }

    // **No** gate may be silent. A gate that answers itself instead of asking is
    // the failure this sweep exists to catch, and a bare `continue` hides it —
    // which is exactly what happened when `policy.link` was quietly neutered and
    // the sweep carried on passing.
    //
    // `fchmod` is the interesting one and it does ask, despite having no path: its
    // gate falls back to a plain yes/no when the descriptor resolves to nothing,
    // because "a gate that cannot describe the call" is a reason to ask about the
    // call, not a reason to wave it through. So it is checked here like any other.
    assert!(
        skipped.is_empty(),
        "every gate must ask. These answered themselves instead, which is the bug \
         this test exists to catch: {skipped:?}. All gates: {gates:?}"
    );
    assert_eq!(
        checked,
        gates.len(),
        "and every gate's question was checked: {checked} of {}",
        gates.len()
    );
    assert_eq!(
        checked + skipped.len(),
        gates.len(),
        "every gate was accounted for: checked {checked}, skipped {skipped:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// When `/proc` cannot be read the command line is dropped rather than
/// printed empty, and the pid is still there. A question reading
/// `... (pid 42) []` looks like an answer field the user left blank rather
/// than a process that has already exited.
#[test]
fn an_asker_with_no_command_line_names_only_its_pid() {
    let lua = shipped_vm();
    prime_the_sandbox(&lua);

    let sys = json!({
        "name": "bpf",
        "pid": 42,
        "cmdline": "",
        "args": [0, 0, 0, 0, 0, 0],
    });
    let (q, _) = ask_through_gate(&lua, 42, "bpf", &sys, &[], "true");
    let description: String = q
        .expect("the gate asked")
        .get("description")
        .expect("a description");
    assert!(
        description.contains("(pid 42)"),
        "the pid survives a process that cannot be read: {description:?}"
    );
    assert!(
        !description.contains("[]"),
        "and no empty brackets where the command line would be: {description:?}"
    );
}
