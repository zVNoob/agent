//! `agent.bash` and the substrate under it: the policy-callback contract, the
//! syscall mask, Ask-as-yield, and the `/proc` introspection that lets a policy
//! name a path instead of a pointer.
use super::*;

    #[test]
    fn runtime_is_luajit_and_evaluates() {
        let lua = Lua::new();
        let sum: i64 = lua.load("return 21 * 2").eval().expect("lua eval of 21*2");
        assert_eq!(sum, 42);
        // LuaJIT implements the Lua 5.1 ABI, so `_VERSION` reads "Lua 5.1";
        // the LuaJIT-specific identity lives in the `jit` library's version.
        let version: String = lua
            .globals()
            .get::<mlua::Table>("jit")
            .expect("jit library present")
            .get("version")
            .expect("jit.version exists");
        assert!(
            version.contains("LuaJIT"),
            "expected the vendored LuaJIT runtime, got {version:?}"
        );
    }

    #[test]
    fn rust_values_cross_into_lua_and_back() {
        let lua = Lua::new();
        lua.globals()
            .set("saved", "payload".to_string())
            .expect("set global");
        let round: String = lua
            .load("return saved .. '!'")
            .eval()
            .expect("concat round-trip");
        assert_eq!(round, "payload!");
    }

    #[test]
    fn coroutine_yield_then_resume_with_verdict() {
        // The Ask↔verdict primitive, exercised bare: a coroutine that yields
        // once (the "ask"), is resumed with an answer, and the yield site
        // receives it before the coroutine completes. This is precisely the
        // shape `Verdict::Ask`/`resolve_ask` takes across the Rust↔Lua
        // boundary. (The body must be a thread-wrapped *function*: yielding
        // at the top level of a chunk crosses a C-call boundary and is
        // rejected — as the future policy layer will too.)
        let lua = Lua::new();
        let body: mlua::Function = lua
            .load(
                r#"
            return function()
                local asked = coroutine.yield("frozen syscall")
                return "decided: " .. asked
            end
            "#,
            )
            .eval()
            .expect("load coroutine body");
        let thread = lua
            .create_thread(body)
            .expect("wrap coroutine body in a thread");

        // First resume runs the function to its yield: Rust receives the ask.
        let ask: String = thread.resume(()).expect("resume to yield");
        assert_eq!(ask, "frozen syscall");

        // Second resume carries the verdict: the Lua yield site sees it.
        let result: String = thread.resume("allow").expect("resume with verdict");
        assert_eq!(result, "decided: allow");

        // The coroutine finished: a further resume must refuse.
        let e = thread
            .resume::<mlua::Value>(())
            .expect_err("dead coroutine");
        assert!(
            matches!(e, mlua::Error::CoroutineUnresumable),
            "expected CoroutineUnresumable, got {e:?}"
        );
    }

    #[test]
    fn agent_bash_echo_streams_and_completes() {
        // Push callbacks receive the streamed chunks; s:run() returns the
        // completed result table. stdout/"hello\n" arrives (as one or more
        // chunks), stderr is empty. ALLOW_ALL names no syscalls, so the mask
        // is empty: a pure-builtin `echo` performs no masked syscall at all
        // — zero intercepts, and the run completes because nothing needed
        // deciding (un-named syscalls run free).
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            local opts, out, err = collect()
            local s = agent.bash("echo hello", allowall, opts)
            local r = s:run()
            return r.stdout == "hello\n" and r.exit.code == 0
                   and table.concat(out) == "hello\n" and table.concat(err) == ""
                   and r.denied == 0 and r.syscalls == 0
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "expected a clean allow-all echo run");
    }

    #[test]
    fn empty_policy_traces_nothing_and_the_command_runs() {
        // A policy's syscall-name keys are the interception mask: `{}` names
        // nothing, so nothing is traced — the command runs free under the
        // kernel default and completes cleanly with zero intercepted
        // syscalls (the engine's fork-family mask adds nothing for a
        // builtin). The old fail-closed contract (unlisted ⇒ denied) is
        // gone: unlisted syscalls are simply not decided.
        let lua = vm();
        let r: mlua::Table = lua
            .load(r#"return agent.bash("echo nope", {}):run()"#)
            .eval()
            .expect("eval");
        let exit: mlua::Table = r.get("exit").expect("exit");
        let code: i64 = exit.get("code").expect("code");
        let denied: u64 = r.get("denied").expect("denied");
        let syscalls: u64 = r.get("syscalls").expect("syscalls");
        let stdout: String = r.get("stdout").expect("stdout");
        assert_eq!(code, 0, "nothing was denied");
        assert_eq!(denied, 0, "an empty policy denies nothing");
        assert_eq!(syscalls, 0, "an empty policy traces nothing");
        assert_eq!(stdout, "nope\n", "the command ran to completion");
    }

    #[test]
    fn bare_policy_traps_only_its_named_syscalls() {
        // `{ write = allow }` is a *bare* partial table: under the old
        // fail-closed contract its first un-named syscall would have killed
        // the run; under the named-mask contract only writes are intercepted
        // (and allowed) while execve/read/stat/… run straight through the
        // kernel. Proves the mask is exactly the table's keys.
        let lua = vm();
        let r: mlua::Table = lua
            .load(r#"return agent.bash("echo hi", { write = function() return true end }):run()"#)
            .eval()
            .expect("eval");
        let exit: mlua::Table = r.get("exit").expect("exit");
        assert_eq!(exit.get::<i64>("code").expect("code"), 0);
        let denied: u64 = r.get("denied").expect("denied");
        let syscalls: u64 = r.get("syscalls").expect("syscalls");
        let stdout: String = r.get("stdout").expect("stdout");
        assert_eq!(stdout, "hi\n");
        assert_eq!(denied, 0);
        assert!(syscalls >= 1, "writes are named, so they are intercepted");
    }

    #[test]
    fn yield_in_policy_callback_is_an_ask() {
        // The core Ask round-trip, driven through the pump: the execve
        // callback calls a user-asking function which yields — the raw value
        // is re-yielded to whoever resumed s.pump; resuming with `true`
        // delivers the verdict to the yield site and the run completes.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              -- the syscall table reaches the callback intact
              assert(s.name == "execve" and s.nr == 59, "execve identity")
              assert(type(s.pid) == "number" and s.pid > 0, "pid present")
              assert(type(s.args) == "table" and s.args[1] ~= nil, "args present")
              -- user-asking function: yields the ask; the resume-verdict lands here
              local function uask(v) return coroutine.yield(v) end
              return uask(s.name)
            end
            local opts, out = collect()
            local s = agent.bash("echo asked", allowall, opts)
            local ok1, ask = coroutine.resume(s.pump)
            assert(ok1, tostring(ask))
            assert(ask == "execve", "ask is the raw yielded value, got " .. tostring(ask))
            local ok2, r = coroutine.resume(s.pump, true)
            assert(ok2, tostring(r))
            assert(coroutine.status(s.pump) == "dead", "pump finished after the verdict")
            return r.stdout == "asked\n" and r.exit.code == 0
                   and table.concat(out) == "asked\n"
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "ask/yield round-trip failed");
    }

    #[test]
    fn callback_error_kills_tree_and_propagates() {
        // A raising callback never bubbles into the driver: the sandbox is
        // killed on the spot and the error reaches whoever resumed the pump.
        let lua = vm();
        let (errored, errmsg): (bool, String) = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            allowall.execve = function() error("boom") end
            local s = agent.bash("echo x", allowall)
            local ok, e = coroutine.resume(s.pump)
            return ok == false, tostring(e)
            "#
            ))
            .eval()
            .expect("eval");
        assert!(
            errored,
            "expected the pump resume to error, got a completed resume"
        );
        assert!(errmsg.contains("boom"), "expected boom, got {errmsg:?}");
    }

    #[test]
    fn denying_a_specific_syscall_kills_mid_run() {
        // Everything allowed except `write`: bash's first stdout write denies,
        // which is final — the tree dies with SIGKILL.
        let lua = vm();
        let r: mlua::Table = lua
            .load(format!(
                r#"
            local policy = {ALLOW_ALL}
            policy.write = function() return false end
            return agent.bash("echo hi", policy):run()
            "#
            ))
            .eval()
            .expect("eval");
        let exit: mlua::Table = r.get("exit").expect("exit");
        let signal: i64 = exit.get("signal").expect("signal");
        let denied: u64 = r.get("denied").expect("denied");
        assert_eq!(signal, libc::SIGKILL as i64, "denied write kills the tree");
        assert!(denied >= 1, "write was denied");
    }

    #[test]
    fn multi_chunk_output_streams_whole() {
        // 20k lines ≈ 140KB, far beyond one 64KB pipe chunk: the pushed
        // output arrives in multiple callback invocations and the
        // concatenation is exact.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            local opts, out = collect()
            local s = agent.bash("seq 1 20000", allowall, opts)
            local r = s:run()
            local count, first, last = 0, nil, nil
            for line in table.concat(out):gmatch("[^\n]+") do
              count = count + 1
              if count == 1 then first = line end
              last = line
            end
            return count == 20000 and first == "1" and last == "20000"
                   and #out >= 2 and r.stdout == table.concat(out)
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "expected all 20000 seq lines, streamed whole");
    }

    #[test]
    fn bash_argument_validation() {
        let lua = vm();
        let ok: bool = lua
            .load(
                r#"
            local ok1 = pcall(agent.bash, "echo x", nil)
            local ok2 = pcall(agent.bash, 42, {})
            local ok3 = pcall(agent.bash, "echo x", {}, 5)
            local ok4 = pcall(agent.bash, "echo x", {}, { on_stdout = 5 })
            local ok5 = pcall(agent.bash, "echo x", {}, { on_stderr = "s" })
            local ok6 = pcall(agent.bash, "echo x", {}, { on_exit = false })
            return ok1 == false and ok2 == false and ok3 == false and ok4 == false
                   and ok5 == false and ok6 == false
            "#,
            )
            .eval()
            .expect("eval");
        assert!(ok, "arg validation errors");
    }

    #[test]
    fn yield_across_pcall_crosses_and_resumes() {
        // Pins the actual LuaJIT behavior for a yield inside a `pcall`ed
        // function (relevant to user-written callbacks): unlike a yield at a
        // chunk's top level (rejected — the substrate test above), a yield
        // inside `pcall` crosses the boundary: the coroutine suspends, the
        // resumer receives the yielded value, and a second resume continues
        // the pcalled function. The driver never relies on this (it cannot
        // catch callback errors across pcall the same way), but callbacks may.
        let lua = Lua::new();
        let ok: bool = lua
            .load(
                r#"
            local co = coroutine.create(function()
              return pcall(function() return coroutine.yield("nope") end)
            end)
            local ok1, v = coroutine.resume(co)
            if not (ok1 and v == "nope") then
              return false, tostring(v)
            end
            -- resume with a value: the yield site inside the pcalled
            -- function receives it, the function returns it, pcall returns
            -- (true, value), and the coroutine finishes with all of it.
            local ok2, pcall_ok, ret = coroutine.resume(co, "back")
            return ok2 == true and pcall_ok == true and ret == "back"
            "#,
            )
            .eval()
            .expect("eval");
        assert!(ok, "yield across pcall must suspend/resume cleanly");
    }

    #[test]
    fn ask_round_trip_is_stable_under_repetition() {
        // Regression for the asker-excluded freeze: repeated ask→allow round
        // trips must complete. A full-tree SIGSTOP-freeze used to interrupt
        // the asker's notification wait — the kernel discarded the pending
        // notification, so the restarted syscall re-asked forever. The bridge
        // now freezes only the *other* processes (never the asker), and each
        // of these round trips rides the freeze → allow → completion-wait →
        // thaw cycle.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              local function uask(v) return coroutine.yield(v) end
              return uask(s.name)
            end
            for i = 1, 15 do
              local opts, out = collect()
              local s = agent.bash("echo round", allowall, opts)
              local ok1, ask = coroutine.resume(s.pump)
              assert(ok1, tostring(ask))
              assert(ask == "execve", "ask " .. i .. " is execve, got " .. tostring(ask))
              local ok2, r = coroutine.resume(s.pump, true)
              assert(ok2, tostring(r))
              assert(coroutine.status(s.pump) == "dead", "pump finished in round " .. i)
              assert(r.stdout == "round\n" and r.exit.code == 0
                     and table.concat(out) == "round\n", "round " .. i .. " failed")
            end
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "ask round-trip must be stable across runs");
    }

    #[test]
    fn multi_ask_per_syscall_round_trips_a_deny() {
        // A callback may ask more than once for one syscall: each yield is a
        // separate ask re-yielded to the caller, each resumed verdict is
        // delivered to the yield site, and only the callback's final return
        // value is the decision. Here two asks resolve (true, false) → the
        // callback returns false → deny. The deny kills the tree *before*
        // the errno is replayed (the thread is still parked in its
        // notification wait), so the run deterministically ends in SIGKILL
        // even under this narrow mask — no post-deny exit path can race it.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              local function uask(v) return coroutine.yield(v) end
              local v1 = uask(s.name .. "/first")
              local v2 = uask(s.name .. "/second")
              return v1 and v2
            end
            local s = agent.bash("echo multi", allowall)
            local ok1, ask1 = coroutine.resume(s.pump)
            assert(ok1, tostring(ask1))
            assert(ask1 == "execve/first", "first ask, got " .. tostring(ask1))
            local ok2, ask2 = coroutine.resume(s.pump, true)
            assert(ok2, tostring(ask2))
            assert(ask2 == "execve/second", "second ask, got " .. tostring(ask2))
            local ok3, res = coroutine.resume(s.pump, false)
            assert(ok3, tostring(res))
            return type(res) == "table" and res.exit.signal == 9 and res.denied >= 1
            "#
            ))
            .eval()
            .expect("eval");
        assert!(
            ok,
            "multi-ask per syscall must round-trip to the final verdict"
        );
    }

    #[test]
    fn multi_ask_per_syscall_round_trips_an_allow() {
        // Same multi-ask flow, both verdicts true → the syscall runs and the
        // run completes normally.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              local function uask(v) return coroutine.yield(v) end
              local v1 = uask(s.name .. "/first")
              local v2 = uask(s.name .. "/second")
              return v1 and v2
            end
            local opts, out = collect()
            local s = agent.bash("echo multi", allowall, opts)
            local ok1, ask1 = coroutine.resume(s.pump)
            assert(ok1, tostring(ask1))
            assert(ask1 == "execve/first")
            local ok2, ask2 = coroutine.resume(s.pump, true)
            assert(ok2, tostring(ask2))
            assert(ask2 == "execve/second")
            local ok3, r = coroutine.resume(s.pump, true)
            assert(ok3, tostring(r))
            assert(coroutine.status(s.pump) == "dead", "pump finished after the verdicts")
            return r.stdout == "multi\n" and r.exit.code == 0 and table.concat(out) == "multi\n"
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "multi-ask allow must complete");
    }

    #[test]
    fn bash_streams_stdout_and_stderr_in_order() {
        // Pushed chunks arrive per-stream in write order; stdout and stderr
        // go to their own callbacks.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            local opts, out, err = collect()
            local s = agent.bash("echo out; echo err >&2; echo out2", allowall, opts)
            local r = s:run()
            return table.concat(out) == "out\nout2\n" and table.concat(err) == "err\n"
                   and r.exit.code == 0
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "expected streamed stdout out,out2 and stderr err");
    }

    #[test]
    fn write_feeds_stdin_and_output_streams() {
        // Full-duplex through the stream object: s:write_stdin feeds the
        // tracee's stdin, s:close_stdin signals EOF, and cat echoes the bytes
        // back through on_stdout and into the captured result.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            local opts, out = collect()
            local s = agent.bash("cat", allowall, opts)
            s:write_stdin("hello\n")
            s:close_stdin()
            local r = s:run()
            return table.concat(out) == "hello\n"
                   and r.stdout == "hello\n" and r.exit.code == 0
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "expected cat to echo the written stdin");
    }

    #[test]
    fn sibling_output_completes_after_an_ask() {
        // While a policy ask holds the background child's write of "ping",
        // the parent's write of "pong" is *also* parked — both processes'
        // writes are in the masked set (this policy names `execve` and
        // `write`), so nothing enters the pipes until the
        // supervisor allows it. The tree is not frozen though: the parent
        // keeps executing until its own write (intercepted before the
        // verdict, thanks to the sleep) queues after the child's ask. After
        // the verdict the child's write completes first (resolve_ask), then
        // the queued parent write — pushed through the callbacks in that
        // order, with no bytes lost. `root` is the *first* execve's pid;
        // later execs (e.g. /usr/bin/sleep) must not clobber it.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            local root = nil
            allowall.execve = function(s)
              if root == nil then root = s.pid end
              return true
            end
            allowall.write = function(s)
              if s.pid ~= root then
                local function uask(v) return coroutine.yield(v) end
                return uask("sibling write")
              end
              return true
            end
            local opts, out = collect()
            local s = agent.bash("echo ping & sleep 0.05; echo pong; wait", allowall, opts)
            local ok1, ask = coroutine.resume(s.pump)
            assert(ok1, tostring(ask))
            assert(ask == "sibling write",
                   "first ask is the child's write, got " .. tostring(ask))
            -- The parent's "pong" write happens on its own timeline; keep the
            -- ask open long enough that it is provably intercepted and queued
            -- before the verdict.
            os.execute("sleep 0.15")
            local ok2, r = coroutine.resume(s.pump, true)
            assert(ok2, tostring(r))
            assert(coroutine.status(s.pump) == "dead", "pump finished after the ask")
            return r.exit.code == 0 and table.concat(out) == "ping\npong\n"
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "queued sibling output must complete after the ask");
    }

    #[test]
    fn pull_reader_wrapper_drives_the_pump() {
        // The user's pull-reader pattern: wrap the pump in *their own*
        // coroutine, collect pushed chunks, and re-yield asks to their
        // resumer. Asks and output interleave with no corruption because the
        // drive chain (user coroutine → pump → callback sub-coroutine) is
        // pure Lua frames end to end — no ask yield crosses a C call.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              local function uask(v) return coroutine.yield(v) end
              return uask(s.name)
            end
            local chunks = {{}}
            local s = agent.bash("echo pull", allowall,
                                 {{ on_stdout = function(c) chunks[#chunks + 1] = c end }})
            local user_co = coroutine.create(function()
              local pump = s.pump
              local pending
              while true do
                local ok, ev = coroutine.resume(pump, pending)
                pending = nil
                assert(ok, tostring(ev))
                if coroutine.status(pump) == "dead" then return ev end
                pending = coroutine.yield("user sees: " .. tostring(ev))
              end
            end)
            local ok1, ask = coroutine.resume(user_co)
            assert(ok1, tostring(ask))
            assert(ask == "user sees: execve",
                   "ask surfaced through the wrapper, got " .. tostring(ask))
            local ok2, r = coroutine.resume(user_co, true)
            assert(ok2, tostring(r))
            assert(coroutine.status(user_co) == "dead", "wrapper finished")
            return r.stdout == "pull\n" and r.exit.code == 0
                   and table.concat(chunks) == "pull\n"
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "pull-reader wrapper must drive the pump without bugs");
    }

    #[test]
    fn run_with_on_ask_answers_asks() {
        // The non-interactive driver: s:run(on_ask) answers asks raised by
        // user-asking functions and returns the result; the ask value is
        // passed through verbatim.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              local function uask(v) return coroutine.yield(v) end
              return uask(s.name)
            end
            local opts, out = collect()
            local s = agent.bash("echo askus", allowall, opts)
            local asked_n = 0
            local r = s:run(function(ask)
              assert(ask == "execve", "on_ask got the raw ask, got " .. tostring(ask))
              asked_n = asked_n + 1
              return true
            end)
            return r.stdout == "askus\n" and r.exit.code == 0 and asked_n == 1
                   and table.concat(out) == "askus\n"
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "s:run(on_ask) must answer asks and complete");
    }

    #[test]
    fn run_without_on_ask_handler_raises_on_ask() {
        // Ask with no handler: s:run() raises a clear error instead of
        // silently auto-answering. (The pump stays suspended at the ask; VM
        // teardown cleans the parked tree up.)
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              local function uask(v) return coroutine.yield(v) end
              return uask(s.name)
            end
            local s = agent.bash("echo nope", allowall)
            local ok, e = pcall(function() return s:run() end)
            return ok == false and tostring(e):find("on_ask") ~= nil
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "run() without on_ask must raise on an ask");
    }

    #[test]
    fn detached_without_callbacks_completes() {
        // "Ignore it entirely": no output callbacks at all — output is
        // discarded by the config, yet the run still completes and the final
        // result is produced.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            local s = agent.bash("echo ignored", allowall)
            local r = s:run()
            return r.exit.code == 0 and r.stdout == "ignored\n" and r.denied == 0
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "detached run without callbacks must complete");
    }

    #[test]
    fn callbacks_are_assignable_and_on_exit_fires() {
        // The pump reads the callback fields at drive time: they may be
        // installed after construction (how pull readers redirect push into a
        // queue), and on_exit fires with the very result table run returns.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            local late, exited = {{}}, nil
            local s = agent.bash("echo late", allowall)
            s.on_stdout = function(c) late[#late + 1] = c end
            s.on_exit = function(r) exited = r end
            local r = s:run()
            return exited ~= nil and exited == r and r.exit.code == 0
                   and r.stdout == "late\n" and table.concat(late) == "late\n"
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "assignable callbacks and on_exit must work");
    }

    #[test]
    fn non_boolean_callback_kills_and_raises() {
        // A callback whose completion value is not a boolean: the sandbox is
        // killed on the spot and the driver raises instead of guessing.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            allowall.execve = function() return "maybe" end
            local s = agent.bash("echo x", allowall)
            local ok, e = coroutine.resume(s.pump)
            return ok == false and tostring(e):find("boolean") ~= nil
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "non-boolean completion must kill and raise");
    }

    #[test]
    fn non_function_policy_entry_kills_and_raises() {
        // A policy entry that is not a callback function: same kill + raise.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local policy = {ALLOW_ALL}
            policy.execve = 42
            local s = agent.bash("echo x", policy)
            local ok, e = coroutine.resume(s.pump)
            return ok == false and tostring(e):find("not a callback") ~= nil
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "non-function policy entry must kill and raise");
    }

    #[test]
    fn lua_bash_runs_a_command_under_an_allow_policy() {
        // `lua::bash` — Rust's one-shot wrapper over agent.bash — runs a
        // sandboxed command and reports the captured output and exit status.
        // ALLOW_ALL is a bare expression, so it is wrapped in `return`.
        // ALLOW_ALL names no syscalls → empty mask → nothing intercepted:
        // a pure-builtin echo reports zero intercepts yet still runs (its
        // un-named syscalls went straight through the kernel).
        let out = run_bash("echo sandboxed", &format!("return {ALLOW_ALL}"), None, None)
            .expect("bash ran");
        assert_eq!(out.stdout, "sandboxed\n");
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.exit_signal, None);
        assert!(!out.failed());
        assert_eq!(out.syscalls, 0, "ALLOW_ALL names no syscalls to trap");
        assert_eq!(out.denied, 0);
    }

    #[test]
    fn lua_policy_blocks_openat_read_write() {
        // `exec 3<>file` opens the file read-write (O_RDWR | O_CREAT) — the
        // first such openat is denied: the open fails EPERM and the engine
        // kills the tree, so the process cannot exit cleanly. (bash's own
        // /dev/tty probe — O_RDWR|O_NONBLOCK — is exempted so the policy is
        // testing the real open, not startup.)
        let policy = r#"
        local p = setmetatable({}, { __index = function() return function() return true end end })
        p.openat = function(sys)
          local flags = sys.args[3]
          if flags == 2050 then return true end -- /dev/tty probe
          return (flags % 4) ~= 2
        end
        return p
        "#;
        let out = run_bash(
            "exec 3<>/tmp/lua-bash-denied-rw; echo unreachable",
            policy,
            None,
            None,
        )
        .expect("bash ran");
        assert!(out.denied >= 1, "at least one read-write openat denied");
        assert!(out.failed(), "a denied rw open must not exit cleanly");
        assert!(
            !out.stdout.contains("unreachable"),
            "the tracee dies before the echo after a denied open"
        );
    }

    /// A policy that *asks* (yields) on write `openat`s — the shape the bash
    /// tool's own policy uses, minus the flag decoding.
    const ASK_ON_WRITE_POLICY: &str = r#"
    local p = setmetatable({}, { __index = function() return function() return true end end })
    local function uask(v) return coroutine.yield(v) end
    p.openat = function(sys)
      local flags = sys.args[3]
      if flags == 2050 then return true end -- /dev/tty probe
      if flags % 4 ~= 0 then return uask({ description = "openat requests write" }) end
      return true
    end
    return p
    "#;

    #[test]
    fn lua_bash_auto_denies_an_ask_without_a_handler() {
        // A policy that raises an ask never hangs a run: with no ask handler
        // (`agent.api.ask_user` on a headless VM) the ask resolves to deny,
        // exactly like the flat deny the policy used to return — same outcome,
        // terminated. The tool's overlay around it is covered by
        // `the_bash_tool_panels_a_denial`.
        let _ = std::fs::remove_file("/tmp/lua-bash-ask-auto-deny");
        let out = run_bash(
            "exec 3<>/tmp/lua-bash-ask-auto-deny; echo unreachable",
            ASK_ON_WRITE_POLICY,
            None,
            None,
        )
        .expect("bash ran");
        assert!(out.denied >= 1, "the ask auto-denies without a handler");
        assert!(out.failed(), "a denied ask must not exit cleanly");
        assert!(
            !out.stdout.contains("unreachable"),
            "the tracee dies before the echo"
        );
    }

    #[test]
    fn an_ask_handler_routes_its_verdicts() {
        // The interactive path: the VM's ask handler decides each frozen
        // syscall. Allowing the write open lets the command complete and create
        // its file; denying it reproduces the headless outcome. (The overlay
        // and the status line around an ask are the *tool's* — see
        // `the_bash_tool_...` below.)
        for p in ["/tmp/lua-bash-ask-allow", "/tmp/lua-bash-ask-deny"] {
            let _ = std::fs::remove_file(p);
        }
        let out = run_bash(
            "echo ask-write > /tmp/lua-bash-ask-allow",
            ASK_ON_WRITE_POLICY,
            None,
            Some(Rc::new(|_, _always: bool| AskAnswer::Allow)),
        )
        .expect("bash ran");
        assert_eq!(out.denied, 0, "the handler allowed the write open");
        assert!(!out.failed(), "an allowed write lets the run finish");
        assert!(
            std::path::Path::new("/tmp/lua-bash-ask-allow").exists(),
            "the allowed open created the file"
        );

        let out = run_bash(
            "exec 3<>/tmp/lua-bash-ask-deny; echo unreachable",
            ASK_ON_WRITE_POLICY,
            None,
            Some(Rc::new(|_, _always: bool| AskAnswer::Deny(None))),
        )
        .expect("bash ran");
        assert!(out.denied >= 1, "a denied ask blocks the syscall");
        assert!(out.failed(), "a denied ask must not exit cleanly");
        assert!(
            !std::path::Path::new("/tmp/lua-bash-ask-deny").exists(),
            "a denied open must not create the file"
        );

        let _ = std::fs::remove_file("/tmp/lua-bash-ask-allow");
        let _ = std::fs::remove_file("/tmp/lua-bash-ask-deny");
    }

    #[test]
    fn an_ask_verdicts_reason_surfaces_on_the_result() {
        // An ask is a yielded user-asking call resumed with its verdict; a
        // verdict object from the ask handler (`AskAnswer::Deny(Some(..))`)
        // therefore carries the reason exactly like a policy's
        // `agent.deny(reason)` — on the outcome here, and on the panel status
        // line where the tool renders it (`the_bash_tool_panels_a_denial`).
        let out = run_bash(
            "exec 3<>/tmp/lua-bash-ask-reason; echo unreachable",
            ASK_ON_WRITE_POLICY,
            None,
            Some(Rc::new(|_, _always: bool| AskAnswer::Deny(Some("user said no".to_string())))),
        )
        .expect("bash ran");
        assert!(out.denied >= 1, "the ask denial blocks the write");
        assert!(out.failed(), "a denied ask must not exit cleanly");
        assert_eq!(
            out.denied_reason.as_deref(),
            Some("user said no"),
            "the ask handler's reason travels on the result"
        );
        assert!(
            !std::path::Path::new("/tmp/lua-bash-ask-reason").exists(),
            "the denied open must not create the file"
        );

        let _ = std::fs::remove_file("/tmp/lua-bash-ask-reason");
    }

    #[test]
    fn an_ask_verdict_allow_succeeds_like_true() {
        // `AskAnswer::Allow` resumed into the asking callback behaves exactly
        // like the boolean `true` verdict.
        let out = run_bash(
            "exec 3<>/tmp/lua-bash-ask-allow-v; echo via-ask-allow",
            ASK_ON_WRITE_POLICY,
            None,
            Some(Rc::new(|_, _always: bool| AskAnswer::Allow)),
        )
        .expect("bash ran");
        assert_eq!(out.denied, 0, "an allowed ask lets the run finish");
        assert!(!out.failed());
        assert_eq!(out.stdout, "via-ask-allow\n");
        assert_eq!(out.denied_reason, None);
        assert!(
            std::path::Path::new("/tmp/lua-bash-ask-allow-v").exists(),
            "the allowed open created the file"
        );
        let _ = std::fs::remove_file("/tmp/lua-bash-ask-allow-v");
    }

    #[test]
    fn syscall_table_carries_the_caller_cmdline_from_proc() {
        // Every policy callback can see *who* is asking: the syscall table
        // carries the caller's pid and its `/proc/<pid>/cmdline`. The tracee
        // is spawned as `bash -c "<cmdline>"`; the pre-exec `execve` still
        // shows the *inherited* argv (the forked child is a copy of the
        // sandbox's own process), but from the moment bash runs every
        // intercepted syscall's caller argv holds the full -c line — asserted
        // on every syscall of the run here.
        let policy = r#"
        local function inspect(sys)
          assert(type(sys.pid) == "number" and sys.pid > 0, "pid present")
          assert(type(sys.cmdline) == "string" and sys.cmdline ~= "",
                 "caller cmdline is a readable string")
          if sys.name ~= "execve" then
            assert(sys.cmdline:find("cmdl-ask", 1, true) ~= nil,
                   "cmdline is the caller's bash -c line: " .. tostring(sys.cmdline))
          end
          return true
        end
        -- `execve` and `write` are the named mask: exactly those are
        -- intercepted, and each one passes through `inspect`.
        local policy = {}
        policy.execve = inspect
        policy.write = inspect
        return policy
        "#;
        let out = run_bash("echo cmdl-ask", policy, None, None)
            .expect("bash ran");
        assert_eq!(out.stdout, "cmdl-ask\n");
        assert!(!out.failed());
    }

    #[test]
    fn read_cstr_parses_a_nul_terminated_string_from_a_targets_memory() {
        // The dereference primitive: reads a NUL-terminated C string from the
        // target's address space (here, the test process's own), and yields
        // None for an unreadable pointer rather than erroring.
        let s = std::ffi::CString::new("hello from the sandbox supervisor").unwrap();
        let got = read_cstr(std::process::id() as i32, s.as_ptr() as u64, CSTRING_CAP)
            .expect("self memory is readable");
        assert_eq!(got, "hello from the sandbox supervisor");
        assert_eq!(
            read_cstr(std::process::id() as i32, 0, CSTRING_CAP),
            None,
            "null ptr"
        );
        assert_eq!(
            read_cstr(
                std::process::id() as i32,
                0xdead_beef_dead_beef,
                CSTRING_CAP
            ),
            None,
            "bogus pointer is None, not an error"
        );
    }

    #[test]
    fn cstring_arg_positions_name_the_string_slots_per_syscall() {
        // The `sys.str` dereference map: which 0-based `args` slots are C
        // strings for each syscall, with fd slots and out-buffers excluded.
        assert_eq!(
            cstring_positions("execve"),
            Some(&[0][..]),
            "execve: program"
        );
        assert_eq!(
            cstring_positions("openat"),
            Some(&[1][..]),
            "openat: dirfd, path"
        );
        assert_eq!(
            cstring_positions("rename"),
            Some(&[0, 1][..]),
            "rename: old, new"
        );
        assert_eq!(
            cstring_positions("symlinkat"),
            Some(&[0, 2][..]),
            "symlinkat: target, link"
        );
        assert_eq!(
            cstring_positions("mount"),
            Some(&[0, 1, 2, 3][..]),
            "mount: four strings"
        );
        assert_eq!(
            cstring_positions("getcwd"),
            None,
            "getcwd's arg is an out-buffer, not a string"
        );
        assert_eq!(
            cstring_positions("read"),
            None,
            "fd-based syscalls have no string args"
        );
        assert_eq!(
            cstring_positions("nosuchsyscall"),
            None,
            "unknown names: no positions"
        );
    }

    #[test]
    fn cwd_resolution_is_gated_on_at_fdcwd_for_dirfd_syscalls() {
        // The dirfd family (openat & friends) resolves relative names against
        // a caller-held fd, invisible to us — only AT_FDCWD means "the cwd".
        let at_fdcwd = libc::AT_FDCWD as u64;
        let mut args = [0u64; 6];
        args[0] = at_fdcwd;
        assert!(
            cwd_resolution_ok("openat", 1, args),
            "AT_FDCWD: resolve vs cwd"
        );
        args[0] = 3;
        assert!(
            !cwd_resolution_ok("openat", 1, args),
            "real dirfd: pass the name through"
        );

        // symlinkat: the target (0) is cwd-relative, the linkpath (2) follows
        // the fd in slot 1.
        args[0] = 0;
        args[1] = at_fdcwd;
        assert!(cwd_resolution_ok("symlinkat", 0, args));
        assert!(
            cwd_resolution_ok("symlinkat", 2, args),
            "AT_FDCWD linkpath resolves"
        );
        args[1] = 5;
        assert!(
            !cwd_resolution_ok("symlinkat", 2, args),
            "dirfd'd linkpath passes through"
        );
        assert!(
            cwd_resolution_ok("symlinkat", 0, args),
            "target is still cwd-relative"
        );

        // Plain pathname syscalls have no dirfd at all.
        assert!(cwd_resolution_ok("execve", 0, args));
        assert!(cwd_resolution_ok("unlink", 0, args));
        assert!(cwd_resolution_ok("mount", 0, args));
    }

    #[test]
    fn resolve_path_chases_symlinks_and_collapses_dotdot() {
        // A temp sandwich: base/a/x.txt real file, base/b/link.txt a symlink
        // to it. Resolution must land on the *actual* file either way.
        use std::os::unix::fs::symlink;
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let base = std::env::temp_dir().join(format!(
            "agent-resolve-{:x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let a = base.join("a");
        let b = base.join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("x.txt"), "x").unwrap();
        symlink(a.join("x.txt"), b.join("link.txt")).unwrap();
        let real = |p: &std::path::Path| p.canonicalize().unwrap().to_string_lossy().into_owned();

        // An existing file resolves to its canonical path.
        assert_eq!(
            resolve_path(None, a.join("x.txt").to_str().unwrap()),
            real(&a.join("x.txt"))
        );

        // A symlink resolves to the actual file it points at.
        assert_eq!(
            resolve_path(None, b.join("link.txt").to_str().unwrap()),
            real(&a.join("x.txt"))
        );

        // ".." is collapsed: a/../a/x.txt is a/x.txt.
        let dod = a.join("..").join("a").join("x.txt");
        assert_eq!(
            resolve_path(None, dod.to_str().unwrap()),
            real(&a.join("x.txt"))
        );

        // A missing tail keeps its literal form: an uncreated file passes the
        // name through (it cannot resolve to a file that does not exist), and
        // an unrefinable absolute path stays as it was given.
        let newborn = a.join("soon.txt");
        assert_eq!(
            resolve_path(None, newborn.to_str().unwrap()),
            newborn.to_string_lossy()
        );

        // A missing prefix passes the name through unchanged.
        let gone = base.join("nope").join("deep");
        assert_eq!(
            resolve_path(None, gone.to_str().unwrap()),
            gone.to_string_lossy()
        );
        let nowhere = "/this/does/not/exist-zz";
        assert_eq!(resolve_path(None, nowhere), nowhere);
        assert_eq!(resolve_path(None, ""), "");

        // Relative names resolve against the given cwd when the file exists
        // (canonical target); a missing file passes the name through.
        assert_eq!(resolve_path(Some(&a), "x.txt"), real(&a.join("x.txt")));
        assert_eq!(resolve_path(Some(&a), "soon.txt"), "soon.txt");

        // Dangling symlinks: the target doesn't exist yet, but the *intended*
        // location still lands — where the file will live.
        symlink("missing-zz.txt", b.join("dangling.txt")).unwrap();
        assert_eq!(
            resolve_path(None, b.join("dangling.txt").to_str().unwrap()),
            b.join("missing-zz.txt").to_string_lossy().into_owned()
        );
        symlink("/this/does/not/exist-zz", b.join("absdangling.txt")).unwrap();
        assert_eq!(
            resolve_path(None, b.join("absdangling.txt").to_str().unwrap()),
            "/this/does/not/exist-zz"
        );

        // A chain of dangling links unwinds to the final intended target.
        symlink("dangling.txt", b.join("chain.txt")).unwrap();
        assert_eq!(
            resolve_path(None, b.join("chain.txt").to_str().unwrap()),
            b.join("missing-zz.txt").to_string_lossy().into_owned()
        );

        // A cycle of dangling links gives up (hop cap) and stays literal — no
        // hang, name passes through.
        symlink("cycle-b", b.join("cycle-a")).unwrap();
        symlink("cycle-a", b.join("cycle-b")).unwrap();
        assert_eq!(
            resolve_path(None, b.join("cycle-a").to_str().unwrap()),
            b.join("cycle-a").to_string_lossy().into_owned()
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn proc_cmdline_reads_argv_from_the_proc_tree() {
        // `/proc/<pid>/cmdline` of the test process itself: readable and it
        // names the test binary (cargo runs it as target/debug/deps/agent-*).
        let line = proc_cmdline(std::process::id() as i32);
        assert!(!line.is_empty(), "self cmdline is readable");
        assert!(
            line.contains("agent"),
            "it is the test binary's argv: {line}"
        );
        // A pid that cannot exist yields the empty string, never an error.
        assert_eq!(proc_cmdline(1 << 30), "");
    }

    #[test]
    fn lua_policy_denied_reason_surfaces_on_the_result() {
        // `agent.deny(reason)` — the `Denied(reason)` arm of the policy sum
        // type — denies like `false`, but carries the reason out on the run's
        // result. (The tool renders it as `Denied: <reason>` on the panel; see
        // `the_bash_tool_panels_a_denial`.)
        let policy = r#"
        local p = setmetatable({}, { __index = function() return function() return true end end })
        p.openat = function()
          return agent.deny("openat is forbidden here")
        end
        return p
        "#;
        let out = run_bash("echo unreachable", policy, None, None)
            .expect("bash ran");
        assert!(out.denied >= 1, "a denied reason still denies");
        assert!(out.failed(), "a denied run must not exit cleanly");
        assert_eq!(
            out.denied_reason.as_deref(),
            Some("openat is forbidden here"),
            "the reason travels on the result"
        );
    }

    #[test]
    fn lua_policy_allow_constructor_runs_the_command() {
        // The `Allow` arm: `agent.allow()` behaves exactly like `true`.
        let policy = r#"
        local p = setmetatable({}, { __index = function() return function() return agent.allow() end end })
        return p
        "#;
        let out = run_bash("echo allowed-via-ctor", policy, None, None)
            .expect("bash ran");
        assert!(!out.failed());
        assert_eq!(out.stdout, "allowed-via-ctor\n");
        assert_eq!(out.denied, 0);
    }

    #[test]
    fn lua_policy_rejects_a_non_verdict_table_return() {
        // Only booleans and `agent.allow()`/`agent.deny(reason)` are legal
        // callback results; a hand-rolled table is an error, not a deny.
        // `execve` is named so the callback actually runs (a metatable-only
        // policy would trace nothing and never call anything).
        let e = run_bash(
            "echo hi",
            r#"
            local p = setmetatable({}, { __index = function() return function() return { verdict = "deny" } end end })
            p.execve = function() return { verdict = "deny" } end
            return p
            "#,
            None,
            None,
        )
        .expect_err("a malformed verdict is an error, not a run");
        assert!(
            e.contains("must return a boolean or agent.allow()/agent.deny(reason)"),
            "{e}"
        );
    }

    #[test]
    fn lua_bash_surfaces_policy_and_run_errors() {
        // A policy that is not a table and a callback that raises both
        // surface as Err with the Lua-side message (never a hung run).
        let e = run_bash("echo hi", "return 42", None, None).unwrap_err();
        assert!(e.contains("policy") || e.contains("agent.bash"), "{e}");
        let e = run_bash(
            "echo hi",
            r#"
            local p = setmetatable({}, { __index = function() return function() return true end end })
            p.execve = function(sys) error('policy exploded') end
            return p
            "#,
            None,
            None,
        )
        .unwrap_err();
        assert!(e.contains("policy exploded"), "{e}");
    }

    #[test]
    fn engine_loses_no_output_under_always_ask() {
        // Isolate the Lua layer entirely: drive the engine exactly as the
        // bridge does — always-Ask decider, digest every Blocked with
        // resolve_ask(Allow), drain output — and confirm no byte is lost at
        // completion. Any failure here is an engine-level bug reachable from
        // agent.bash.
        for _ in 0..50 {
            let mut sb =
                seccomp::Sandbox::spawn("bash", &["-c", "echo multi"], |_| Verdict::Ask, &[1])
                    .expect("spawn");
            let r = loop {
                let slots = sb.poll_slots();
                if slots.is_empty() {
                    match sb.step(0).expect("step") {
                        Step::Finished(r) => break r,
                        other => panic!("tree gone but step returned {other:?}"),
                    }
                }
                let mut pfds: Vec<libc::pollfd> = slots.iter().map(|(_, p)| *p).collect();
                let pr = unsafe {
                    libc::poll(
                        pfds.as_mut_ptr(),
                        pfds.len() as libc::nfds_t,
                        seccomp::DEFAULT_POLL_TIMEOUT_MS,
                    )
                };
                if pr == -1 {
                    panic!("poll: {}", std::io::Error::last_os_error());
                }
                if pr == 0 {
                    continue;
                }
                let mut listener_revents = 0i16;
                for (k, p) in pfds.iter().enumerate() {
                    if p.revents != 0 && slots[k].0 == FdSlot::Listener {
                        listener_revents = p.revents;
                    }
                }
                match sb.step(listener_revents).expect("step") {
                    Step::Blocked { .. } => sb.resolve_ask(Verdict::Allow).expect("resolve_ask"),
                    Step::Event(_) | Step::Idle => {}
                    Step::Finished(r) => break r,
                }
            };
            let stdout = String::from_utf8_lossy(&r.stdout).into_owned();
            assert_eq!(stdout, "multi\n", "output lost at completion: {stdout:?}");
            assert_eq!(r.exit.code, Some(0));
        }
    }

    #[test]
    fn raw_driver_primitives_are_exposed() {
        // The raw `agent.api` surface drives the same run the driver sugar
        // does: spawn, step, decide, and the finished result.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            local h = agent.api.spawn("echo raw", {{"write"}})
            local decided, finished = 0, nil
            while finished == nil do
              local s = agent.api.step(h)
              if s.kind == "blocked" then
                local cb = allowall[s.syscall.name]
                agent.api.decide(h, cb(s.syscall))
                decided = decided + 1
              elseif s.kind == "finished" then
                finished = s.result
              end
            end
            return finished.stdout == "raw\n" and finished.exit.code == 0 and decided > 0
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "raw driver primitives failed");
    }
