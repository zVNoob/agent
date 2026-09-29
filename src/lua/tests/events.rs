//! `agent.on_event`, `agent.trigger` and `agent.on_timeout`: a handler as a
//! coroutine the loop steps, and a trigger as a command the loop receives.
use super::*;

#[test]
fn on_event_registers_a_handler_and_fire_event_invokes_it_with_the_payload() {
    // The read side of compaction: the handler receives the payload — the
    // conversation's history — as its argument, exactly the shape the
    // TUI's turn_completed event carries.
    let lua = vm();
    apply_config_source(
        &lua,
        r#"
            agent.on_event("turn_completed", function(info)
              agent._seen = info
            end)
            "#,
    )
    .expect("apply");
    fire_event_on_vm(
        &lua,
        "turn_completed",
        &serde_json::json!({
            "history": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "hello"},
            ]
        }),
    )
    .expect("fire");
    let first_role: String = lua
        .load("return agent._seen.history[1].role")
        .eval()
        .expect("payload round-trip");
    let last_content: String = lua
        .load("return agent._seen.history[2].content")
        .eval()
        .expect("payload round-trip");
    assert_eq!(first_role, "user");
    assert_eq!(last_content, "hello");
}

#[test]
fn on_event_without_a_handler_is_a_noop() {
    // No registration for the name, and an unknown event name: events are
    // opt-in, so both fire as Ok(()) rather than errors.
    let lua = vm();
    fire_event_on_vm(&lua, "bogus", &serde_json::json!({})).expect("no handler: no-op");
    apply_config_source(&lua, "agent.on_event(\"turn_completed\", function() end)").expect("apply");
    fire_event_on_vm(&lua, "turn_completed", &serde_json::json!({})).expect("registered: fire");
}

#[test]
fn on_timeout_falls_back_to_a_thread_sleep_outside_the_reactor() {
    // A VM that is not reactor-driven (tool threads, tests, top-level
    // config): `agent.on_timeout` keeps the historical `_sleep` behavior —
    // a real thread sleep, then `fn` — and reports `false` so callers can
    // tell the fallback from a cooperative wait.
    let lua = vm();
    let started = std::time::Instant::now();
    let fired: u32 = lua
        .load(
            r#"
                local fired = 0
                local first = agent.on_timeout(30, function() fired = 1 end)
                assert(first == false, "plain VM: on_timeout falls back and returns false")
                return fired
                "#,
        )
        .eval()
        .expect("on_timeout in a plain vm");
    assert_eq!(fired, 1, "the fn must still run after the wait");
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(25),
        "plain-VM on_timeout must actually sleep ({} elapsed)",
        started.elapsed().as_millis()
    );
}

#[test]
fn event_run_drives_the_handler_as_a_single_threaded_coroutine() {
    // The reactor-driven path behind `turn_completed`: `agent.on_timeout`
    // suspends the handler coroutine instead of sleeping the thread, and
    // `EventRun::step` resumes it when the reactor's timer fires —
    // strictly single-threaded, with nothing else frozen in between.
    let lua = vm();
    apply_config_source(
        &lua,
        r#"
            agent.on_event("turn_completed", function(info)
              agent.__acc = {}
              table.insert(agent.__acc, "start")
              local resumed = agent.on_timeout(20, function()
                table.insert(agent.__acc, "fn")
              end)
              assert(resumed, "reactor resume lands true at the yield site")
              table.insert(agent.__acc, "resumed-true")
              agent.on_timeout(5)
              table.insert(agent.__acc, "done")
            end)
            "#,
    )
    .expect("apply");
    let (mut run, step) = EventRun::start(
        &lua,
        "turn_completed",
        &serde_json::json!({ "history": [] }),
    )
    .expect("start")
    .expect("handler registered");
    // First resume: the handler ran up to its first wait.
    assert_eq!(step, EventStep::Waiting { ms: 20 });
    // Resume after the reactor's 20ms timer: fn ran, then the next wait.
    assert_eq!(
        run.step().expect("after 20ms"),
        EventStep::Waiting { ms: 5 }
    );
    // Resume after the 5ms timer: the handler completes.
    assert_eq!(run.step().expect("after 5ms"), EventStep::Returned);
    let acc: mlua::Table = run
        .lua()
        .globals()
        .get::<Table>("agent")
        .expect("agent table")
        .get("__acc")
        .expect("acc table");
    let joined: Vec<String> = (1..=4u64)
        .map(|i| acc.get::<String>(i).expect("acc entry"))
        .collect();
    assert_eq!(joined, ["start", "fn", "resumed-true", "done"]);
}

#[test]
fn event_run_rejects_a_stray_non_timeout_yield() {
    // A handler yielding a raw value (not an agent.on_timeout request)
    // surfaces an error instead of hanging the driver.
    let lua = vm();
    apply_config_source(
        &lua,
        r#"
            agent.on_event("turn_completed", function(info)
              coroutine.yield("stray")
            end)
            "#,
    )
    .expect("apply");
    let out = EventRun::start(&lua, "turn_completed", &serde_json::json!({}));
    let err = match out {
        Err(e) => e,
        Ok(_) => panic!("a stray yield must surface as a start error"),
    };
    assert!(
        err.contains("unsupported value"),
        "expected an unsupported-yield error, got: {err}"
    );
}

#[test]
fn event_handler_bash_runs_cooperatively_with_the_loop_live() {
    // An event handler calling `agent.bash` must not freeze the loop: on
    // the reactor every `_step` poll is non-blocking and the pump suspends
    // for a cadence between idle steps, so `EventRun::step` answers
    // `Waiting` all the way through a long-running command instead of the
    // pump blocking the thread. This is cooperative `agent.bash`.
    let lua = vm();
    apply_config_source(
        &lua,
        r#"
            agent.on_event("turn_completed", function(info)
              local r = agent.bash("sleep 0.3", {
                clock_nanosleep = function() return true end,
                nanosleep = function() return true end,
              }):run()
              agent.__done = { code = r.exit.code }
            end)
            "#,
    )
    .expect("apply");
    let (run, step) = EventRun::start(
        &lua,
        "turn_completed",
        &serde_json::json!({ "history": [] }),
    )
    .expect("start")
    .expect("handler registered");
    let started = std::time::Instant::now();
    let (run, waits) = drive_event_to_completion(run, step);
    // The sandbox itself ran to completion with exit 0...
    let done = event_agent_field(&run, "__done");
    assert_eq!(done.get::<i64>("code").expect("exit code"), 0);
    // ...and the coroutine suspended across wall-clock time, multiple
    // times, each an idle-cadence wait — the loop stayed live rather
    // than the pump blocking for the whole sleep.
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(200),
        "a 0.3s sleep must span wall time ({} elapsed)",
        started.elapsed().as_millis()
    );
    assert!(
        waits >= 2,
        "a 0.3s sleep must suspend repeatedly, got {waits} waits"
    );
}

#[test]
fn event_handler_bash_streams_output_and_returns_the_result() {
    // A handler's bash (here small enough that the whole run can fit in
    // one slice) still streams output through the callbacks and hands the
    // handler the full result table: stdout, exit code, no denials.
    let lua = vm();
    apply_config_source(
        &lua,
        r#"
            agent.on_event("turn_completed", function(info)
              local out = {}
              local r = agent.bash("echo cooperative", {
                write = function() return true end,
              }, {
                on_stdout = function(c) out[#out + 1] = c end,
              }):run()
              agent.__bash = {
                stdout = r.stdout, code = r.exit.code,
                denied = r.denied, chunks = table.concat(out),
              }
            end)
            "#,
    )
    .expect("apply");
    let (run, step) = EventRun::start(
        &lua,
        "turn_completed",
        &serde_json::json!({ "history": [] }),
    )
    .expect("start")
    .expect("handler registered");
    let (run, _waits) = drive_event_to_completion(run, step);
    let t = event_agent_field(&run, "__bash");
    assert_eq!(t.get::<String>("stdout").expect("stdout"), "cooperative\n");
    assert_eq!(t.get::<i64>("code").expect("exit code"), 0);
    assert_eq!(t.get::<u64>("denied").expect("denied"), 0);
    assert_eq!(t.get::<String>("chunks").expect("chunks"), "cooperative\n");
}

#[test]
fn event_handler_bash_auto_denies_a_policy_ask() {
    // A background handler has no ask UI, so a policy that raises an ask
    // auto-denies (exactly like headless runs): the tracee is killed, the
    // run terminates, and the handler gets the final result with denied.
    let lua = vm();
    apply_config_source(
        &lua,
        r#"
            agent.on_event("turn_completed", function(info)
              local r = agent.bash("echo ask-me", {
                write = function(sys)
                  local function uask(v) return coroutine.yield(v) end
                  return uask("write in a handler?")
                end,
              }):run()
              agent.__bash = { denied = r.denied, stdout = r.stdout }
            end)
            "#,
    )
    .expect("apply");
    let (run, step) = EventRun::start(
        &lua,
        "turn_completed",
        &serde_json::json!({ "history": [] }),
    )
    .expect("start")
    .expect("handler registered");
    let (run, _waits) = drive_event_to_completion(run, step);
    let t = event_agent_field(&run, "__bash");
    assert!(
        t.get::<u64>("denied").expect("denied") >= 1,
        "the ask auto-denies"
    );
    assert_eq!(
        t.get::<String>("stdout").expect("stdout"),
        "",
        "killed before output"
    );
}

#[test]
fn plain_context_bash_run_without_an_ask_handler_raises() {
    // Outside the reactor (tool threads, top-level config), `run()` has no
    // cooperative auto-deny: an ask without an `on_ask` handler keeps
    // raising, so a caller that drops the handler on the floor hears it.
    let lua = vm();
    let bad = lua
        .load(
            r#"
                local r = agent.bash("echo nope", {
                  write = function() return coroutine.yield("ask") end,
                }):run()
                return "ran"
                "#,
        )
        .eval::<String>();
    let e = match bad {
        Err(e) => e.to_string(),
        Ok(_) => panic!("an ask without on_ask must raise in a plain VM"),
    };
    assert!(
        e.contains("no on_ask handler"),
        "expected the ask error, got: {e}"
    );
}

#[test]
fn trigger_registration_requires_a_string_name_and_function_handler() {
    let lua = vm();
    // agent.on_event / agent.trigger live in lua/init.lua, like the rest
    // of the config machinery; load it (with an empty user source) first.
    apply_config_source(&lua, "").expect("driver");
    let bad = lua
        .load("agent.on_event(42, function() end)")
        .eval::<mlua::Value>();
    assert!(bad.is_err(), "event name must be a string");
    let bad = lua
        .load("agent.on_event(\"turn_completed\", 7)")
        .eval::<mlua::Value>();
    assert!(bad.is_err(), "handler must be a function");
}

#[test]
fn trigger_queues_run_turn_commands_on_the_bound_channel() {
    // The channel is process-global and two tests have something to say
    // about it, so claim it for the whole body rather than binding and
    // hoping to be the one that got there first. The guard also proves the
    // slot was free, since it unbinds before binding.
    let loop_channel = claim_trigger_channel();
    assert!(loop_channel.is_empty(), "a claimed channel starts empty");

    // All three shapes a trigger argument can take.
    let lua = vm();
    apply_config_source(&lua, "").expect("driver");

    // No argument: a continuation of the current conversation.
    let ok: bool = lua.load("return agent.trigger()").eval().expect("trigger");
    assert!(ok, "bound channel -> queued");
    match loop_channel.recv().expect("command") {
        AgentCommand::RunTurn {
            history: None,
            user: None,
        } => {}
        other => panic!("continuation expected, got {other:?}"),
    }

    // A string: a submitted user message.
    let ok: bool = lua
        .load("return agent.trigger('compact and continue')")
        .eval()
        .expect("trigger");
    assert!(ok);
    match loop_channel.recv().expect("command") {
        AgentCommand::RunTurn {
            history: None,
            user: Some(u),
        } => {
            assert_eq!(u, "compact and continue")
        }
        other => panic!("user message expected, got {other:?}"),
    }

    // An array of messages: a history replacement — the write side.
    let ok: bool = lua
        .load(
            "return agent.trigger({ {role='system', content='summary'}, \
                   {role='user', content='tail'} })",
        )
        .eval()
        .expect("trigger");
    assert!(ok);
    match loop_channel.recv().expect("command") {
        AgentCommand::RunTurn {
            history: Some(h),
            user: None,
        } => {
            assert_eq!(h[0]["role"], "system");
            assert_eq!(h[0]["content"], "summary");
            assert_eq!(h[1]["role"], "user");
            assert_eq!(h[1]["content"], "tail");
        }
        other => panic!("history replacement expected, got {other:?}"),
    }

    // A non-array table and other argument types are rejected: agent.trigger
    // must not silently turn a typo into a history wipe.
    let err = lua
        .load("return agent.trigger({role='system'})")
        .eval::<mlua::Value>();
    assert!(err.is_err(), "an object is not a message array");
    let err = lua.load("return agent.trigger(42)").eval::<mlua::Value>();
    assert!(err.is_err(), "a number is not a prompt");
}

/// With nothing bound, the primitives that reach the loop report `false`
/// rather than raising — so a headless caller (the probe, a bare VM) can
/// branch on the answer.
///
/// Its own test because the channel is process-global: asserting the unbound
/// case inside the test that claims the slot would be a race, and having
/// done that is what made the suite order-dependent in the first place.
#[test]
fn the_loop_primitives_report_false_with_no_loop_attached() {
    // Unbound *and* held for the whole body: the guard is what keeps another
    // test from rebinding the channel between here and the calls below.
    let _unbound = release_trigger_channel();
    let lua = vm();
    apply_config_source(&lua, "").expect("driver");

    let unbound: bool = lua
        .load("return agent.trigger()")
        .eval()
        .expect("unbound trigger does not raise");
    assert!(!unbound, "no loop attached -> false, so Lua can branch");

    // Same contract from the input primitives, same reason: a binding whose
    // edit went nowhere would look like a key that does nothing, which is
    // the one failure a keybinding must not have.
    for call in [
        "return agent.api.input_insert('x')",
        "return agent.api.input_backspace()",
        "return agent.api.input_clear()",
    ] {
        let got: bool = lua.load(call).eval().expect("input op with no loop");
        assert!(!got, "{call} reports that nothing was queued");
    }
}
