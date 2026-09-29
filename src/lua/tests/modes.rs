//! `agent.mode`: switching modes rewrites the prompt and the tool registry, and
//! a mode stays in force for the next request. With `agent.llm.usage` and the
//! compaction policy built on top of it, because that is where a mode earns its
//! keep.
use super::*;

use crate::testutil::unique_path;
    /// The lib loader requires modules in **alphabetical** order, so a module
    /// that captures a sibling's `agent.<name>` at load time gets `nil` when the
    /// sibling sorts later. `require("<name>")` is the order-independent way:
    /// it loads the sibling on demand, and the auto-scan's later require is a
    /// cache hit. Pinned here because the difference is silent.
    #[test]
    fn lib_modules_capture_siblings_with_require_not_agent() {
        let dir = fixture("order");
        std::fs::create_dir_all(dir.join("lib")).expect("fixture lib");
        // The sibling under test: publishes itself, and sorts *after* the two
        // modules that capture it.
        std::fs::write(
            dir.join("lib").join("seccomp.lua"),
            "local M = { O = { RDONLY = 0 } }\nagent.seccomp = M\nreturn M",
        )
        .expect("sibling module");
        // "aaa" loads first: agent.seccomp is not there yet.
        std::fs::write(
            dir.join("lib").join("aaa.lua"),
            "local via_agent = agent.seccomp\nlocal via_require = require(\"seccomp\")\n\
             return { via_agent = via_agent, via_require = via_require }",
        )
        .expect("early module");
        // "zzz" loads last, when agent.seccomp *is* there — so both work here,
        // which is exactly why the early one is the trap.
        std::fs::write(
            dir.join("lib").join("zzz.lua"),
            "return { via_agent = agent.seccomp ~= nil }",
        )
        .expect("late module");
        std::fs::copy(tree().join("api.lua"), dir.join("api.lua")).expect("api.lua");
        std::fs::write(dir.join("init.lua"), "agent.api_docs = require(\"api\")\n")
            .expect("init");

        let lua = Lua::new();
        setup_tree(&lua, None, None, &dir, &ConfigSource::Tree).expect("fixture tree setup");
        let problem: Option<String> = lua
            .load(
                r#"
            local early = package.loaded["aaa"]
            if early.via_agent ~= nil then
              return "agent.seccomp was already there for aaa (order changed?)"
            end
            if type(early.via_require) ~= "table" then
              return "require('seccomp') did not load the sibling"
            end
            -- It is the same table the sibling published.
            if early.via_require ~= agent.seccomp then return "different table" end
            if not package.loaded["zzz"].via_agent then return "zzz" end
            return nil
        "#,
            )
            .eval()
            .expect("load-order eval");
        assert!(
            problem.is_none(),
            "lib load order: {}",
            problem.unwrap_or_default()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The "always" flag is Lua's, and it reaches the answer: a question that
    /// carries a path offers the third answer, and the tool is what passes it
    /// across. (That a question *without* a path does not offer it is the
    /// ask-table's own business, pinned in ask's self-test.)
    #[test]
    fn the_always_flag_is_lua_s_and_reaches_the_handler() {
        // The tool runs on the shipped config VM, so the built-in configuration
        // is the source of both the tool and its policy — this VM is here to
        // fail loudly if that configuration ever stops loading.
        let _config = shipped_vm();
        // What the handler was told, per call.
        let seen: Rc<RefCell<Vec<(String, bool)>>> = Rc::new(RefCell::new(Vec::new()));
        let watch = seen.clone();
        let sink = PanelSink::default();
        let run = |args: &str, watch: Rc<RefCell<Vec<(String, bool)>>>| {
            invoke_mcp_tool_with_asks(
                "bash.bash",
                args,
                Some(&sink),
                // Records what it was told and says yes: the default policy asks
                // about every open, so denying the first one would kill the run
                // before it reached the write this is about.
                Some(Rc::new(move |text: &str, always: bool| {
                    watch.borrow_mut().push((text.to_string(), always));
                    AskAnswer::Allow
                })),
                &ConfigSource::Tree,
            )
            .expect("invoke")
        };

        // The shipped policy asks about every open with a path in the question,
        // so the third answer is on offer for each of them.
        let p = unique_path("ask-flag");
        // Seeded, so the write is an *overwrite* and therefore still a question.
        // Creating a name nothing holds is deliberately silent (see
        // `creating_a_new_name_is_not_a_question`), and `echo >` on a fresh path
        // would leave this test with no write to inspect.
        std::fs::write(&p, "before\n").expect("seed the target");
        let args = serde_json::json!({
            "cmdline": format!("echo x > {}", p.display()),
        })
        .to_string();
        let _ = run(&args, watch.clone());
        let asked = seen.borrow().clone();
        assert!(!asked.is_empty(), "the opens were asked about: {asked:?}");
        assert!(
            asked.iter().all(|(_, always)| *always),
            "every ask here carries a path, so all of them offer always: {asked:?}"
        );
        // The write is asked about too — it is the last one, because the default
        // policy asks about the program's own libraries before the command runs.
        let asked_about_target = asked
            .iter()
            .any(|(text, _)| text.contains(&p.display().to_string()));
        assert!(
            asked_about_target,
            "and the question for the write names its path: {asked:?}"
        );
        let _ = std::fs::remove_file(&p);

    }

    /// `agent.llm.usage` is the read-only token ledger of the **most recent**
    /// request: the numbers the server reported, refreshed after every turn, and
    /// seeded into every VM from a process-wide snapshot so a tool call and a
    /// `turn_completed` handler see the same counts.
    #[test]
    fn agent_usage_is_the_read_only_count_of_the_last_request() {
        let _usage = usage_guard();
        let lua = vm();

        // Before anything has run: a number, but honestly zero and *reported =
        // false* — "unknown", never a stale figure.
        let start: String = lua
            .load(
                r#"
            return string.format("%s/%s/%s/%s", agent.llm.usage.prompt, agent.llm.usage.completion,
                                 agent.llm.usage.total, tostring(agent.llm.usage.reported))
        "#,
            )
            .eval()
            .expect("usage");
        assert_eq!(start, "0/0/0/false", "nothing has been requested yet");

        // A request that reported both halves: total is their sum, and the
        // counts reach a *new* VM (the process-wide snapshot, not a field on the
        // config VM).
        record_usage(
            &lua,
            Usage {
                prompt: Some(1_200),
                completion: Some(345),
            },
        );
        let seen: String = lua
            .load(
                r#"
            return string.format("%d/%d/%d/%s", agent.llm.usage.prompt, agent.llm.usage.completion,
                                 agent.llm.usage.total, tostring(agent.llm.usage.reported))
        "#,
            )
            .eval()
            .expect("usage after record");
        assert_eq!(seen, "1200/345/1545/true");
        let fresh = new_vm().expect("a fresh VM");
        let seen_elsewhere: i64 = fresh
            .load("return agent.llm.usage.total")
            .eval()
            .expect("usage on another VM");
        assert_eq!(
            seen_elsewhere, 1_545,
            "a tool/event VM is seeded with the same count"
        );

        // One half only: the total is the sum of what *was* reported, and it is
        // still reported.
        record_usage(
            &lua,
            Usage {
                prompt: Some(10),
                completion: None,
            },
        );
        let half: String = lua
            .load("return agent.llm.usage.total .. '/' .. tostring(agent.llm.usage.completion)")
            .eval()
            .expect("partial usage");
        assert_eq!(half, "10/0", "the missing half counts as zero, not unknown");

        // Neither half: back to unknown rather than a stale number.
        record_usage(&lua, Usage::default());
        let none: String = lua
            .load("return agent.llm.usage.total .. '/' .. tostring(agent.llm.usage.reported)")
            .eval()
            .expect("no usage");
        assert_eq!(none, "0/false", "a server that says nothing leaves no stale total");

        // Read-only in fact: every field refuses a write, and says so.
        let refused: Option<String> = lua
            .load(
                r#"
            for _, k in ipairs({ "total", "prompt", "completion", "reported" }) do
              if pcall(function() agent.llm.usage[k] = 1 end) then return "writable: " .. k end
            end
            local ok, err = pcall(function() agent.llm.usage.total = 1 end)
            if not tostring(err):find("read%-only") then return "unclear: " .. tostring(err) end
            return nil
        "#,
            )
            .eval()
            .expect("read-only probe");
        assert!(
            refused.is_none(),
            "agent.llm.usage accepted a write: {}",
            refused.unwrap_or_default()
        );

        // The `usage` key is an ordinary key on `agent.llm`, so a stray
        // assignment can replace the proxy — but the property does not outlive
        // it. The next recording puts a locked table back, numbers included, and
        // so does a `/reload` (a config that replaced the whole `agent.llm`
        // would otherwise leave the surface incomplete until a request ran).
        lua.load("agent.llm.usage = { total = 999 }")
            .exec()
            .expect("replace the key");
        assert_eq!(
            lua.load("return agent.llm.usage.total")
                .eval::<i64>()
                .expect("after replace"),
            999,
            "the stray table is what Lua holds until the next request"
        );
        record_usage(&lua, Usage { prompt: Some(7), completion: None });
        let restored: String = lua
            .load("return agent.llm.usage.total .. '/' .. tostring(agent.llm.usage.reported)")
            .eval()
            .expect("restored");
        assert_eq!(restored, "7/true", "the next recording restores the lock");

        // And a config that replaces `agent.llm` wholesale: `/reload` re-seats
        // the counters, the endpoint keeps the user's values.
        apply_config_source(
            &lua,
            r#"
            agent.llm = { base_url = "http://kept/v1", model = "m", api_key = "" }
            "#,
        )
        .expect("a config that replaces the table");
        let after_reload: String = lua
            .load("return agent.llm.usage.total .. '/' .. agent.llm.base_url")
            .eval()
            .expect("after reload");
        assert_eq!(after_reload, "7/http://kept/v1", "reload re-seats the counters");
    }

    /// The rename is a rename: `agent.llm` is the settings table — the endpoint
    /// fields flat, beside the system prompt, the log settings, and the
    /// read-only token counters — and the old `agent.config` is gone rather than
    /// left behind as a second source of truth (a stale
    /// `agent.config.system_prompt` that silently did nothing would be worse
    /// than a loud failure).
    #[test]
    fn the_settings_table_is_agent_llm_and_the_old_name_is_gone() {
        let lua = shipped_vm();
        let problem: Option<String> = lua
            .load(
                r#"
            if agent.config ~= nil then return "agent.config still exists" end
            -- One table, flat: the endpoint fields are not nested under `llm`.
            if type(agent.llm.base_url) ~= "string" then return "base_url" end
            if type(agent.llm.model) ~= "string" then return "model" end
            if type(agent.llm.api_key) ~= "string" then return "api_key" end
            if type(agent.llm.system_prompt) ~= "string" then return "system_prompt" end
            if type(agent.llm.memory) ~= "table" then return "memory" end
            -- `false` is the "not configured" default, and is deliberately not
            -- a number: compaction is off until the user says what the window
            -- is, because a guessed one compacts at the wrong moment.
            if agent.llm.context_size ~= false then return "context_size" end
            if agent.llm.llm ~= nil then return "llm.llm" end
            -- And Rust reads it from there.
            local names = {}
            for name, _ in pairs(agent.llm) do names[#names + 1] = name end
            table.sort(names)
            return table.concat(names, ",")
        "#,
            )
            .eval()
            .expect("settings shape");
        assert_eq!(
            problem.as_deref(),
            Some("api_key,base_url,context_size,memory,model,system_prompt,usage"),
            "the settings table is flat and complete: every key the starter \
             config defines, plus the read-only counters"
        );
        assert_eq!(
            llm_config(&lua).expect("llm config").model,
            "gpt-4o-mini",
            "and Rust reads the endpoint from agent.llm — the entry script's default, \
             with no user config in the tree to override it"
        );
        assert!(
            system_prompt(&lua).expect("prompt").contains("coding agent"),
            "as well as the system prompt — the `coding` mode's, which the entry \
             script activates by default"
        );
    }

    /// The automatic compaction turn, driven on the real config VM — the VM the
    /// loop reads the prompt and the registry from, which is what makes a
    /// handler's mode switch reach the next turn (see [`EventRun::start`]).
    ///
    /// The trigger is a process-wide channel to the TUI's loop, so the "loop"
    /// here is a Lua stub: `agent.trigger` is a plain function on `agent`, and
    /// the handler calls it by name at call time, so replacing it records what
    /// the handler queued. That tests the handler's actual contract — what it
    /// does to the live config, and what it asks the loop for — without owning
    /// the one process-wide channel (see
    /// `trigger_queues_run_turn_commands_on_the_bound_channel`).
    #[test]
    fn context_pressure_arms_a_compaction_turn_and_lands_its_summary() {
        let _usage = usage_guard();
        // `new_vm` is the whole configuration now: one script, not two.
        let lua = new_vm().expect("VM");
        // A context window to measure against, and a mode with something to
        // switch away from.
        lua.load(
            r#"
            agent.llm.context_size = 20000
            agent.mode.new("work", {
              system_prompt = "WORK PROMPT",
              mcps = { fs = { name = "fs", tools = { read = true } } },
            })
            agent.mode.set("work")
            -- Stand in for the TUI's loop: record what the handler asks for.
            QUEUED = {}
            agent.trigger = function(a)
              QUEUED[#QUEUED + 1] = a
              return true     -- a bound loop accepts it
            end
        "#,
        )
        .exec()
        .expect("configure");
        let compact_prompt = mode_prompt(&lua, "compact");

        // A turn with room to spare: the handler does nothing.
        record_usage(&lua, Usage { prompt: Some(1_000), completion: Some(50) });
        // Eight messages, so cutting a 6-message tail actually drops something.
        let mut history: Vec<serde_json::Value> = (1..=4)
            .flat_map(|i| {
                [
                    json!({ "role": "user", "content": format!("ask {i}") }),
                    json!({ "role": "assistant", "content": format!("reply {i}") }),
                ]
            })
            .collect();
        let before = history.clone();
        assert!(fire_event_on_vm(&lua, "turn_completed", &json!({ "history": history })).expect("fire"));
        assert_eq!(queued(&lua).len(), 0, "plenty of room: nothing queued");
        assert_eq!(mode_current(&lua).as_deref(), Some("work"), "mode kept");
        assert_eq!(history, before, "and the conversation is untouched");
        lua.load("QUEUED = {}").exec().expect("reset the queue");

        // Context pressure (20000 - 9000 = 11000 < 15000 headroom): the handler
        // arms, switches to compact, and asks for a summary — on the VM the next
        // turn reads.
        record_usage(&lua, Usage { prompt: Some(9_000), completion: Some(50) });
        assert!(fire_event_on_vm(&lua, "turn_completed", &json!({ "history": history })).expect("fire"));
        let asked = queued(&lua);
        assert_eq!(asked.len(), 1, "one queued command: {asked:?}");
        assert!(
            asked[0].as_str().is_some_and(|u| u.contains("Compact")),
            "it asks for the summary as a user turn: {asked:?}"
        );
        assert_eq!(
            mode_current(&lua).as_deref(),
            Some("compact"),
            "the agent is in compact mode for the very next turn"
        );
        assert_eq!(
            system_prompt(&lua).expect("prompt"),
            compact_prompt,
            "which carries the compaction brief"
        );
        assert!(
            mcps_tool_defs(&lua).expect("defs").is_empty(),
            "and a compaction turn is offered no tools"
        );

        // The compaction turn runs and answers: the ask, then the summary. That
        // completion is the second event, and it is what must not re-arm (this
        // request carried the whole history too).
        lua.load("QUEUED = {}").exec().expect("reset the queue");
        let summary = "## Task\nship the feature\n\n## Next\nwrite the code";
        let mark = history.len();
        history.push(json!({ "role": "user", "content": "Compact the conversation now…" }));
        history.push(json!({ "role": "assistant", "content": summary }));
        assert!(
            fire_event_on_vm(&lua, "turn_completed", &json!({ "history": history })).expect("fire"),
            "the summary's own completion"
        );
        let replaced = queued(&lua);
        assert_eq!(replaced.len(), 1, "the replacement history is queued: {replaced:?}");
        let m = replaced[0].as_array().expect("a replacement history, not a message");
        assert_eq!(m[0]["role"], "system", "the summary leads the new history");
        assert_eq!(m[0]["content"], summary);
        assert_eq!(
            m.len(),
            1 + 6,
            "the summary plus a 6-message tail: {m:?}"
        );
        assert_eq!(
            &m[1..],
            &before[mark - 6..mark],
            "the tail is the last COMPACT_KEEP messages from *before* the \
             compaction turn, verbatim"
        );
        assert!(
            !m[1..].iter().any(|msg| msg["content"] == summary),
            "and the summary does not appear in the tail as well: {m:?}"
        );
        assert_eq!(
            mode_current(&lua).as_deref(),
            Some("work"),
            "the mode that was in force is back"
        );
        assert_eq!(
            system_prompt(&lua).expect("prompt"),
            "WORK PROMPT",
            "so the turn this starts runs in the restored mode"
        );

        // And it settles: the compacted history is small, so one more event
        // queues nothing — no compaction loop.
        lua.load("QUEUED = {}").exec().expect("reset the queue");
        record_usage(&lua, Usage { prompt: Some(300), completion: Some(20) });
        assert!(fire_event_on_vm(&lua, "turn_completed", &json!({ "history": m })).expect("fire"));
        assert_eq!(queued(&lua).len(), 0, "a compacted conversation does not re-trigger");
    }

    /// Without a context window there is no headroom to measure, so the
    /// automatic turn stays off — a wrong guess at a window would compact at the
    /// wrong moment, so "not configured" must mean "off", not "always".
    #[test]
    fn compaction_is_off_without_a_context_size() {
        let _usage = usage_guard();
        let lua = shipped_vm();
        lua.load("QUEUED = {}; agent.trigger = function(a) QUEUED[#QUEUED+1] = a; return true end")
            .exec()
            .expect("stub the loop");
        // A usage far past any plausible window, and no `context_size` set.
        record_usage(
            &lua,
            Usage {
                prompt: Some(1_000_000),
                completion: Some(1),
            },
        );
        assert!(
            fire_event_on_vm(&lua, "turn_completed", &json!({ "history": [] })).expect("fire"),
            "the handler is registered"
        );
        assert_eq!(queued(&lua).len(), 0, "no window, no automatic compaction");
        // The shipped config starts in the `coding` mode, so a mode *is* in
        // force — what matters here is that compaction did not switch one itself.
        assert_eq!(
            mode_current(&lua).as_deref(),
            Some("coding"),
            "and the only mode in force is the one the config started in"
        );
    }

    /// A handler can still suspend across the wait it asks for, on the shared
    /// VM: `agent.on_timeout` yields, the reactor resumes the *same* coroutine,
    /// and everything it had — locals and the config it changed — is still there.
    #[test]
    fn a_handler_may_yield_on_the_shared_vm_and_keep_its_state() {
        // `new_vm` is the whole configuration now: one script, not two.
        let lua = new_vm().expect("VM");
        lua.load(
            r#"
            agent.llm.system_prompt = "BEFORE THE WAIT"
            local seen = {}
            agent.on_event("turn_completed", function(info)
              seen[#seen + 1] = "start"
              agent.on_timeout(5)
              -- Resumed: the locals and the config both survived.
              seen[#seen + 1] = agent.llm.system_prompt
              agent.llm.system_prompt = "AFTER THE WAIT"
              seen[#seen + 1] = "end"
            end)
        "#,
        )
        .exec()
        .expect("register the waiting handler");

        let payload = json!({ "history": [] });
        let (mut run, step) = EventRun::start(&lua, "turn_completed", &payload)
            .expect("start")
            .expect("a handler is registered");
        assert!(
            matches!(step, EventStep::Waiting { .. }),
            "the handler suspended on its timer, as the reactor expects"
        );
        // The loop keeps running while it waits: the config it wrote before the
        // wait is readable, and the handler is mid-flight.
        assert_eq!(system_prompt(&lua).expect("prompt"), "BEFORE THE WAIT");
        let step = run.step().expect("resume on the timer");
        assert!(matches!(step, EventStep::Returned), "and then it finished");
        assert_eq!(
            system_prompt(&lua).expect("prompt"),
            "AFTER THE WAIT",
            "a write made after the wait lands on the live config"
        );
    }

    fn queued(lua: &mlua::Lua) -> Vec<serde_json::Value> {
        let json: String = lua
            .load("return agent.api.json_encode(QUEUED)")
            .eval()
            .expect("queued commands");
        match serde_json::from_str(&json).expect("queued json") {
            serde_json::Value::Array(items) => items,
            other => {
                assert_eq!(other, serde_json::json!({}), "queued shape");
                Vec::new()
            }
        }
    }

    /// The shipped `compact` mode: a spec that swaps the prompt for a compaction
    /// brief and the registry for *nothing*. "Disable all tools" has to mean all
    /// of them — including the shell, which only counts as a tool because the
    /// configuration registered it — and it has to be true at the tool-dispatch
    /// level, not merely in the advertised list.
    #[test]
    fn the_compact_mode_takes_every_tool_away() {
        let lua = shipped_vm();
        // The shipped config starts in the `coding` mode, so clear to the baseline
        // first: "the baseline" here means what `agent.mode.set()` restores, and
        // that is not the state the config left the VM in.
        lua.load("agent.mode.set()").exec().expect("clear to the baseline");
        let baseline = system_prompt(&lua).expect("baseline prompt");

        // Registered but inert: the baseline is untouched.
        let names: String = lua
            .load(r#"return table.concat(agent.mode.names(), ",")"#)
            .eval()
            .expect("mode names");
        assert!(
            names.split(',').any(|n| n == "compact"),
            "the shipped config registers the compact mode, got {names:?}"
        );
        assert_eq!(
            system_prompt(&lua).expect("baseline prompt"),
            baseline,
            "registering a mode does not switch to it"
        );
        let defs = mcps_tool_defs(&lua).expect("baseline defs");
        assert!(
            defs.iter().any(|d| d.name == "bash.bash"),
            "the shell is there before the switch"
        );

        lua.load(r#"agent.mode.set("compact")"#)
            .exec()
            .expect("switch");

        // The prompt half: Rust reads it per request, so the *next* request
        // carries it.
        let prompt = system_prompt(&lua).expect("compact prompt");
        assert_ne!(prompt, baseline, "the mode's prompt is in force");
        for section in ["## Task", "## Done", "## State", "## Next"] {
            assert!(
                prompt.contains(section),
                "the brief asks for {section}: {prompt}"
            );
        }
        assert!(
            prompt.contains("no tools"),
            "and says so: {}",
            prompt.lines().next().unwrap_or_default()
        );

        // The tool half: the catalog is empty, and a call is not merely
        // un-advertised — the dispatcher has nothing to run it with.
        assert!(
            mcps_tool_defs(&lua).expect("compact defs").is_empty(),
            "a compaction turn is offered no tools"
        );
        // Note the *other* half of "not offered": a tool is called by name
        // against the live registry, so a dropped tool is not callable only
        // because the loop refuses any name the request did not offer —
        // `main::may_run`, asserted there. What this layer guarantees is the
        // catalog: nothing to choose from, and nothing to call.

        // And back: both halves of the baseline return, shell included.
        lua.load("agent.mode.set()").exec().expect("clear");
        assert_eq!(
            system_prompt(&lua).expect("restored prompt"),
            baseline
        );
        let defs = mcps_tool_defs(&lua).expect("restored defs");
        let mut names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["bash.bash", "fs.apply_patch", "fs.hand_to_user", "fs.read", "fs.write_file"],
            "clearing the mode gives the tools back"
        );
    }
