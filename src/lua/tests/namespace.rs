//! The namespace itself: the `agent` table, the `agent.api` bridge and its
//! lock, the auto-required `lib/*` modules, and the LuaJIT runtime underneath.
use super::*;

use crate::testutil::unique_path;
    /// `print` goes to the status bar once a screen is attached, and to stdout
    /// when there is not one — because a TUI owns the terminal, and because a
    /// headless run still has to be debuggable.
    ///
    /// The two branches are mutually exclusive on a process-global, so the
    /// whole test is serialized against the others that touch it.
    #[test]
    fn print_follows_the_screen() {
        let _guard = crate::status::exclusive();
        crate::status::reset();
        let lua = vm();

        // Detached: nothing lands on the status line.
        lua.load(r#"print("to stdout")"#).exec().expect("print");
        assert!(
            crate::status::status_line().get().is_none(),
            "with no screen, print must not become a status"
        );

        // Attached: it becomes the status line, tab-joined like Lua's own.
        crate::status::attach();
        lua.load(r#"print("hello", 42, "world")"#).exec().expect("print");
        assert_eq!(
            crate::status::status_line().get().unwrap().text,
            "hello\t42\tworld",
            "Lua's print semantics: any number of args, joined with tabs"
        );

        // A `__tostring` metamethod is honoured, as `print` requires.
        lua.load(
            r#"
            local t = setmetatable({}, { __tostring = function() return "POINT" end })
            print(t)
        "#,
        )
        .exec()
        .expect("print a table");
        assert_eq!(crate::status::status_line().get().unwrap().text, "POINT");

        // Multi-line print keeps one row: the rest would land on the input box.
        lua.load(r#"print("one\ntwo")"#).exec().expect("print");
        assert_eq!(crate::status::status_line().get().unwrap().text, "one");

        crate::status::reset();
    }

    /// Every `lua/lib/**.lua` is required at VM setup, and a lib module
    /// publishes itself as `agent.<name>`: no require at the use site, and
    /// `package.loaded` holds the same table.
    #[test]
    fn lib_modules_are_loaded_registered_and_cached() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            for _, name in ipairs({ "utils", "seccomp", "ask", "mode" }) do
              local m = package.loaded[name]
              if type(m) ~= "table" then return name .. " not in package.loaded" end
              if agent[name] ~= m then return "agent." .. name .. " is not the module" end
              if require(name) ~= m then return "require re-ran " .. name end
              local good, err = pcall(m._selftest)
              if not good then return name .. " selftest: " .. tostring(err) end
            end
            -- Usable through the agent namespace, without a require.
            if agent.utils.string.trim("  x  ") ~= "x" then return "trim" end
            return nil
        "#,
            )
            .eval()
            .expect("loader eval");
        assert!(
            problem.is_none(),
            "lua/lib: {}",
            problem.unwrap_or_default()
        );
    }

    /// The lib's answers must match the hand-rolled arithmetic the shipped
    /// policy does today (`flags % 4 ~= 0`, and the `%`-chain that decodes
    /// O_CREAT/O_TRUNC/O_APPEND) over the whole flag range — otherwise
    /// switching `lua/policy.lua` over would silently change what is asked.
    #[test]
    fn seccomp_lib_agrees_with_the_hand_rolled_openat_rule() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            local sc = agent.seccomp
            -- 1. The ask/allow decision, over every flag value in range.
            for flags = 0, 4096, 7 do
              -- lua/policy.lua: `if sc.check(..., "WRITE") then ask_trust_write(...)`
              if (flags % 4 ~= 0) ~= sc.check("openat", flags, "WRITE") then
                return "write mismatch at " .. flags
              end
            end
            -- 2. The description, over the bits that file's decoder names
            -- (O_WRONLY/O_RDWR + O_CREAT/O_TRUNC/O_APPEND). `describes` is a
            -- superset elsewhere — it also names O_NOCTTY and friends, and
            -- appends unnamed bits in hex — so this is the exact-overlap case.
            local named = { 64, 512, 1024 }
            local names = { "O_CREAT", "O_TRUNC", "O_APPEND" }
            for acc = 1, 2 do
              for mask = 0, 7 do
                local flags = acc
                -- A callable table: `agent.ask("q")` asks, and the helpers hang
            -- off the same table.
            if type(agent.ask) ~= "table" then return "agent.ask" end
            if agent.ask ~= require("ask") then return "not require('ask')" end
            for _, helper in ipairs({ "ask", "of", "denied", "reason", "deny",
                                      "for_syscall", "drive", "build" }) do
              if type(agent.ask[helper]) ~= "function" then return "ask." .. helper end
            end
            local expected = { (acc == 1) and "O_WRONLY" or "O_RDWR" }
                for i = 1, 3 do
                  if math.floor(mask / (2 ^ (i - 1))) % 2 == 1 then
                    flags = flags + named[i]
                    expected[#expected + 1] = names[i]
                  end
                end
                local decoded = table.concat(expected, "|")
                if decoded ~= sc.describes("openat", flags) then
                  return "decode mismatch at " .. flags .. ": " .. decoded ..
                         " vs " .. sc.describes("openat", flags)
                end
              end
            end
            return nil
        "#,
            )
            .eval()
            .expect("equivalence eval");
        assert!(
            problem.is_none(),
            "agent.seccomp vs policy: {}",
            problem.unwrap_or_default()
        );
    }

    /// The bridge is one locked, annotated namespace: `agent.api.<name>` for
    /// every primitive, no `_`-prefixed leftovers on `agent`, reads work, and
    /// every write path is refused.
    #[test]
    fn api_namespace_is_locked_and_annotated() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            -- Reads work, and the friendly layer is untouched.
            if type(agent.api) ~= "table" then return "agent.api missing" end
            if type(agent.api.step) ~= "function" then return "agent.api.step" end
            if type(agent.bash) ~= "function" then return "agent.bash" end
            -- The old flat names are gone (the user's own fields are not ours).
            for _, name in ipairs({ "_spawn", "_step", "_decide", "_kill",
                                    "_panel_create", "_json_encode", "_memory_flush" }) do
              if agent[name] ~= nil then return "agent." .. name .. " still exists" end
            end
            -- Assignments are refused, and say so.
            local ok, err = pcall(function() agent.api.step = function() end end)
            if ok then return "assignment was allowed" end
            if not tostring(err):find("read%-only") then return "unhelpful error: " .. tostring(err) end
            -- Adding a new key is refused the same way.
            ok = pcall(function() agent.api.sneaky = function() return true end end)
            if ok or agent.api.sneaky ~= nil then return "new key was allowed" end
            -- Replacing a primitive is a no-op, not a takeover.
            local real = agent.api.step
            pcall(function() agent.api.step = function() return "hijacked" end end)
            if agent.api.step ~= real then return "primitive was replaced" end
            -- The metatable is hidden, so the real table cannot be reached.
            if getmetatable(agent.api) ~= false then return "metatable visible" end
            if pcall(setmetatable, agent.api, {}) then return "setmetatable allowed" end
            return nil
        "#,
            )
            .eval()
            .expect("api lock eval");
        assert!(
            problem.is_none(),
            "agent.api: {}",
            problem.unwrap_or_default()
        );
    }

    /// `agent.api_docs` documents the whole bridge: one entry per primitive,
    /// each with a summary — which the loader already enforces at startup, so
    /// this pins the *shape* a consumer (or `agent.help`) can rely on.
    #[test]
    fn api_docs_cover_the_bridge() {
        let lua = vm();
        let (count, problems): (usize, String) = lua
            .load(
                r#"
            local bad, n = {}, 0
            for name, entry in pairs(agent.api_docs) do
              n = n + 1
              if type(entry) ~= "table" or type(entry.summary) ~= "string"
                 or entry.summary == "" then
                bad[#bad + 1] = name
              end
              for _, arg in ipairs(entry.args or {}) do
                if type(arg) ~= "table" or type(arg[1]) ~= "string"
                   or type(arg[2]) ~= "string" or type(arg[3]) ~= "string" then
                  bad[#bad + 1] = name .. ".args"
                end
              end
            end
            return n, table.concat(bad, ",")
        "#,
            )
            .eval()
            .expect("api_docs eval");
        // Every primitive is documented: the VM would not have built otherwise,
        // so the count is the bridge's size.
        assert_eq!(count, 36, "lua/api.lua should annotate all 36 primitives");
        assert!(problems.is_empty(), "malformed annotation entries: {problems}");
    }

    /// A bridge primitive still works through the namespace (the JSON boundary
    /// is the cheapest one to exercise end to end).
    #[test]
    fn api_bridge_functions_still_work() {
        let lua = vm();
        let round: String = lua
            .load(
                r#"
            local text = agent.api.json_encode({ ok = true, items = { 1, 2 } })
            local back = agent.api.json_decode(text)
            return text .. "|" .. tostring(back.ok) .. "|" .. tostring(#back.items)
        "#,
            )
            .eval()
            .expect("json bridge");
        assert_eq!(round, r#"{"items":[1,2],"ok":true}|true|2"#);
    }

    /// The shipped config registers the filesystem connection by name, from the
    /// module: `agent.mcps.fs = require("fs")` is the whole registration.
    #[test]
    fn shipped_config_registers_the_fs_connection_from_the_module() {
        let lua = shipped_vm();
        let problem: Option<String> = lua
            .load(
                r#"
            local conn = agent.mcps.fs
            if type(conn) ~= "table" then return "agent.mcps.fs" end
            if conn.name ~= "fs" then return "connection name: " .. tostring(conn.name) end
            -- The registration *is* the module (one table, not a copy).
            if conn ~= require("fs") then return "not the module" end
            if conn ~= agent.fs then return "agent.fs is not the module" end
            -- The tool set the module ships.
            local names = {}
            for name in pairs(conn.tools) do names[#names + 1] = name end
            table.sort(names)
            if table.concat(names, ",") ~= "apply_patch,hand_to_user,read,write_file" then
              return "tools: " .. table.concat(names, ",")
            end
            -- Each is a callable agent.utils.tool with a description and a schema.
            for name, tool in pairs(conn.tools) do
              if type(tool.description) ~= "string" or tool.description == "" then
                return name .. ": description"
              end
              if type(tool.signature) ~= "table" or tool.signature.type ~= "object" then
                return name .. ": schema"
              end
              if type(tool.callback) ~= "function" then return name .. ": callback" end
            end
            -- The pure diff engine rides along, with no agent config needed.
            if type(agent.fs.patch.apply) ~= "function" then return "patch.apply" end
            if #agent.fs.patch.split("a\nb\n") ~= 3 then return "patch.split" end
            return nil
        "#,
            )
            .eval()
            .expect("fs registration eval");
        assert!(
            problem.is_none(),
            "agent.mcps.fs: {}",
            problem.unwrap_or_default()
        );
    }

    /// The auto-route: a *request* whose response is an event stream. The POST
    /// goes out over the request transport; the `text/event-stream` content-type
    /// then upgrades the body into parsed events on `on_event` — the MCP
    /// streamable-HTTP case, where one endpoint answers with JSON *or* a stream
    /// and the client cannot know in advance. Raw bytes still reach `on_chunk`.
    #[tokio::test]
    async fn http_upgrades_a_request_response_into_events() {
        let fake = FakeHttpServer::start(|_req: FakeRequest| {
            FakeServerReply::StreamEvents(vec![
                // Deliberately split mid-frame: the parser must hold the partial
                // event until the rest arrives.
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":".to_string(),
                "1,\"result\":{\"ok\":true}}\n\n".to_string(),
                "data: bare\n\n".to_string(),
                ": a comment\n\n".to_string(),
            ])
        });
        let lua = vm();
        let problem: Option<String> = eval_reactor(
            &lua,
            &format!(
                r##"
            local events, chunks, done = {{}}, {{}}, nil
            local s = agent.http("POST", "{url}", {{
              body = '{{"jsonrpc":"2.0","id":1,"method":"initialize"}}',
              headers = {{ ["content-type"] = "application/json" }},
              on_chunk = function(c) chunks[#chunks + 1] = c end,
              on_event = function(event, data)
                events[#events + 1] = (event or "message") .. "|" .. data
              end,
              on_done = function(o) done = o end,
            }})
            -- The route is chosen up front from the request...
            if s.route ~= "request" then return "route: " .. tostring(s.route) end
            s:run()
            -- ...and upgraded by the response headers.
            if not s.event_stream then return "no upgrade" end
            if #events ~= 2 then return "#events=" .. #events end
            if events[1] ~= 'message|{{"jsonrpc":"2.0","id":1,"result":{{"ok":true}}}}' then
              return "event 1: " .. events[1]
            end
            if events[2] ~= "message|bare" then return "event 2: " .. events[2] end
            if s.status ~= 200 then return "status: " .. tostring(s.status) end
            if #chunks == 0 then return "on_chunk saw no bytes" end
            -- on_done reports the status *and* how many events arrived.
            if not done or done.status ~= 200 or done.events ~= 2 then
              return "on_done events: " .. tostring(done and done.events)
            end
            return nil
        "##,
                url = fake.url("/mcp")
            ),
        )
        .await
        .expect("upgrade eval");
        assert!(
            problem.is_none(),
            "event-stream upgrade: {}",
            problem.unwrap_or_default()
        );
    }

    /// The runtime is lib modules now: bash (+ verdicts), the panels, the
    /// HTTP transport and the MCP client each live in `lua/lib/<name>.lua`,
    /// are auto-required, and publish themselves on `agent` — the same table
    /// `require` hands back. The embedded driver is down to the cooperative
    /// wait it never gave up.
    #[test]
    fn lib_modules_publish_themselves_on_agent() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            -- A module with one entry point returns the function itself.
            if agent.mcp ~= require("mcp") then return "agent.mcp" end
            -- A module that publishes several fields returns a table of them.
            local bash, panel, http = require("bash"), require("panel"), require("http")
            for _, pair in ipairs({ { "bash", bash }, { "allow", bash },
                                    { "deny", bash }, { "panel", panel },
                                    { "split_panel", panel }, { "http", http } }) do
              if agent[pair[1]] ~= pair[2][pair[1]] then
                return "agent." .. pair[1] .. " is not the module's"
              end
            end
            -- A pure-library module publishes its own namespace.
            if agent.utils ~= require("utils") then return "agent.utils" end
            if agent.seccomp ~= require("seccomp") then return "agent.seccomp" end
            -- The registry the MCP client registers connections into.
            if type(agent.mcps) ~= "table" then return "agent.mcps" end
            -- `agent.sse` was merged into `agent.http`: one interface, two routes.
            if agent.sse ~= nil then return "agent.sse still exists" end
            -- What the embedded driver still owns: the cooperative wait.
            if type(agent.on_timeout) ~= "function" then return "agent.on_timeout" end
            return nil
        "#,
            )
            .eval()
            .expect("module layout eval");
        assert!(
            problem.is_none(),
            "runtime layout: {}",
            problem.unwrap_or_default()
        );
    }

    /// A mode switch overwrites both halves, and both reaches the runtime the
    /// way it reads them: `system_prompt()` is re-read per request and
    /// `mcps_tool_defs` reindexes `agent.mcps` per request — so a switch is
    /// live without a restart. Connections are shared by reference (the mode
    /// and the registry name the same table); the registry itself is a fresh
    /// copy, so a stray runtime write cannot push back into the mode's spec.
    #[test]
    fn a_mode_switch_overwrites_the_prompt_and_the_tool_registry() {
        let lua = neutral_vm();
        let before = system_prompt(&lua).expect("baseline prompt");
        let problem: Option<String> = lua
            .load(
                r#"
            -- Two connections, one of them the real fs module.
            local fs = require("fs")
            local other = { name = "other", tools = {} }
            agent.mode.new("writing", {
              description = "can edit",
              system_prompt = "MODE PROMPT",
              mcps = { fs = fs, other = other },
            })
            agent.mode.new("bare", {})

            if #agent.mode.names() ~= 2 then return "names" end
            if agent.mode.current() ~= nil then return "starts on the baseline" end

            agent.mode.set("writing")
            if agent.mode.current() ~= "writing" then return "current" end
            if agent.llm.system_prompt ~= "MODE PROMPT" then return "prompt" end
            local keys = {}
            for name in pairs(agent.mcps) do keys[#keys + 1] = name end
            table.sort(keys)
            if table.concat(keys, ",") ~= "fs,other" then
              return "registry: " .. table.concat(keys, ",")
            end
            if not rawequal(agent.mcps.fs, fs) then return "fs is a copy" end
            if not rawequal(agent.mcps.other, other) then return "other is a copy" end
            if rawequal(agent.mcps, agent.mode.mcps()) then return "registry aliased" end
            -- A stray runtime write cannot reach the mode's spec.
            agent.mcps.scratch = { name = "scratch", tools = {} }
            if agent.mode.mcps().scratch ~= nil then return "write leaked into the spec" end

            -- A mode with no mcps yields an empty registry, never nil: Rust
            -- reindexes `agent.mcps` per request and would fail on nil.
            agent.mode.set("bare")
            if agent.llm.system_prompt ~= "" then return "bare prompt" end
            if type(agent.mcps) ~= "table" or next(agent.mcps) ~= nil then
              return "bare registry"
            end

            -- Back to the baseline, both halves.
            agent.mode.set()
            if agent.mode.current() ~= nil then return "current after reset" end
            if agent.llm.system_prompt == "MODE PROMPT" then return "prompt not restored" end
            if pcall(agent.mode.set, "nope") then return "unknown mode accepted" end
            return nil
        "#,
            )
            .eval()
            .expect("mode switch eval");
        assert!(
            problem.is_none(),
            "agent.mode: {}",
            problem.unwrap_or_default()
        );
        // And the prompt half as *Rust* reads it: per request, no restart.
        assert_eq!(
            system_prompt(&lua).expect("prompt after reset"),
            before,
            "the baseline prompt is what Rust sends"
        );
        let defs = mcps_tool_defs(&lua).expect("reindex after reset");
        assert!(
            defs.is_empty(),
            "the baseline registry is what Rust advertises: {:?}",
            defs.iter().map(|d| &d.name).collect::<Vec<_>>()
        );
    }

    /// The switch as the runtime sees it mid-session: register, switch, and the
    /// very next request's tool list *and* system prompt are the mode's.
    #[test]
    fn a_mode_is_live_for_the_next_request() {
        let lua = neutral_vm();
        lua.load(
            r#"
            agent.mode.new("scoped", {
              system_prompt = "SCOPED PROMPT",
              mcps = { fs = require("fs") },
            })
        "#,
        )
        .exec()
        .expect("register");
        // Still the baseline: nothing switched, so nothing changed.
        assert_ne!(system_prompt(&lua).expect("prompt"), "SCOPED PROMPT");
        assert!(
            mcps_tool_defs(&lua).expect("reindex").is_empty(),
            "registering a mode does not activate it"
        );

        lua.load(r#"agent.mode.set("scoped")"#)
            .exec()
            .expect("switch");
        assert_eq!(system_prompt(&lua).expect("prompt"), "SCOPED PROMPT");
        let defs = mcps_tool_defs(&lua).expect("reindex");
        let mut names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["fs.apply_patch", "fs.hand_to_user", "fs.read", "fs.write_file"],
            "the mode's tools are what the next request advertises"
        );
    }

    /// Ask once, remember afterwards: the trust table answers the second
    /// question about a path without putting it to the user, and only for what
    /// was trusted.
    ///
    /// Driven through a real sandboxed run, so the trusted path is one the
    /// *engine* resolved (`agent.seccomp.path`) — the trust table matches on that,
    /// not on anything a policy made up.
    #[test]
    fn ask_and_remember_trusts_a_path_for_the_rest_of_the_run() {
        const POLICY: &str = r#"
        local sc, ask = require("seccomp"), require("ask")
        local p = setmetatable({}, { __index = function() return function() return true end end })
        p.openat = function(sys)
          local flags = sc.arg(sys, "openat")
          if sc.is_tty_probe(flags) then return true end
          if sc.check("openat", flags, "WRITE") then
            return ask(ask.for_syscall(sys, "write", sc.describes("openat", flags)))
          end
          return true
        end
        return p
        "#;
        let path = unique_path("ask-trust");
        let _ = std::fs::remove_file(&path);
        // The same file, opened twice: two questions if nothing is remembered.
        let cmdline = format!("echo one > {0}; echo two > {0}", path.display());
        let watched = path.to_string_lossy().to_string();

        // Headless: an ask auto-denies, so the first open fails and nothing is
        // trusted — the run cannot get past the first redirect.
        let out = run_bash(&cmdline, POLICY, None, None).expect("bash ran");
        assert!(out.denied >= 1, "no handler, so the ask denies: {out:?}");
        assert!(!path.exists(), "and nothing was written");

        // The same run, with a handler that answers "always allow this": the flag
        // rides with the verdict and `ask` — the side that knows the path —
        // records it. Two opens, one question.
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let out = run_bash(
            &cmdline,
            POLICY,
            None,
            Some(Rc::new(move |text: &str, _always: bool| {
                seen.borrow_mut().push(text.to_string());
                AskAnswer::AllowAndTrust
            })),
        )
        .expect("bash ran");
        let questions = asked.borrow().clone();
        assert!(
            !questions.is_empty(),
            "the first open is a question: {questions:?}"
        );
        assert!(
            questions[0].contains(&watched),
            "and it names the path that was trusted: {:?}",
            questions[0]
        );
        assert_eq!(
            questions.len(),
            1,
            "the second open of the trusted path is silent: {questions:?}"
        );
        assert_eq!(out.denied, 0, "nothing was denied: {out:?}");
        assert_eq!(
            std::fs::read_to_string(&path).expect("written"),
            "two\n",
            "the whole command ran"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// `ask_trust_write` is the whole decision in one call: trusted already,
    /// asked once if not, and remembered **only** on "always". Two opens of the
    /// same file in one command make the difference visible — a plain yes is for
    /// this time, so it is asked again; an "always" is remembered, so it is not.
    #[test]
    fn ask_trust_write_remembers_only_on_always() {
        const POLICY: &str = r#"
        local sc, ask = require("seccomp"), require("ask")
        local p = setmetatable({}, { __index = function() return function() return true end end })
        p.openat = function(sys)
          local flags = sc.arg(sys, "openat")
          if sc.is_tty_probe(flags) then return true end
          if sc.check("openat", flags, "WRITE") then
            -- One call: trusted? ask? remember an "always"?
            return ask.ask_trust_write(sc.path(sys), "write " .. sc.describes("openat", flags))
          end
          return true
        end
        return p
        "#;
        let path = unique_path("ask-trust-w");

        // A plain yes: both opens are allowed, and neither is remembered, so the
        // second open asks again.
        let _ = std::fs::remove_file(&path);
        let cmdline = format!("echo one > {0}; echo two > {0}", path.display());
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let out = run_bash(
            &cmdline,
            POLICY,
            None,
            Some(Rc::new(move |text: &str, _always: bool| {
                seen.borrow_mut().push(text.to_string());
                AskAnswer::Allow
            })),
        )
        .expect("bash ran");
        assert_eq!(out.denied, 0, "a yes allows both opens: {out:?}");
        assert_eq!(
            asked.borrow().len(),
            2,
            "a plain yes is for this time, so the second open asks too: {:?}",
            asked.borrow()
        );
        assert_eq!(std::fs::read_to_string(&path).expect("written"), "two\n");
        let _ = std::fs::remove_file(&path);

        // "Always": remembered, so the second open is silent.
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let out = run_bash(
            &cmdline,
            POLICY,
            None,
            Some(Rc::new(move |text: &str, _always: bool| {
                seen.borrow_mut().push(text.to_string());
                AskAnswer::AllowAndTrust
            })),
        )
        .expect("bash ran");
        assert_eq!(out.denied, 0, "an always allows both opens: {out:?}");
        assert_eq!(
            asked.borrow().len(),
            1,
            "an always is remembered, so the second open is silent: {:?}",
            asked.borrow()
        );
        assert_eq!(std::fs::read_to_string(&path).expect("written"), "two\n");
        let _ = std::fs::remove_file(&path);

        // A refusal ends the run at the first ask — the engine kills the tracee,
        // so there is no second open to observe. (That a denial is not
        // remembered is pinned at the Lua level, in ask's own self-test: it
        // needs a coroutine, not a dying process.)
        let _ = std::fs::remove_file(&path);
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let out = run_bash(
            &cmdline,
            POLICY,
            None,
            Some(Rc::new(move |text: &str, _always: bool| {
                seen.borrow_mut().push(text.to_string());
                AskAnswer::Deny(None)
            })),
        )
        .expect("bash ran");
        assert!(out.denied >= 1, "the refusal stopped the run: {out:?}");
        assert_eq!(
            asked.borrow().len(),
            1,
            "asked once, then the refusal killed the tracee: {:?}",
            asked.borrow()
        );
        assert!(!path.exists(), "and nothing was written");
    }

    /// A file inside a trusted *folder* is trusted — that is the containment
    /// rule the whole directory trust rests on, and it has to hold in both
    /// tables and stop at a real boundary. (The `dir` flag is what makes it
    /// work: trusting a directory trusts its subtree, trusting a *file* trusts
    /// only itself.)
    #[test]
    fn a_file_inside_a_trusted_folder_is_trusted() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            local ask = agent.ask
            ask.forget_all()

            -- A trusted directory covers what is inside it, in both tables.
            ask.trust("/usr/share")
            local read_in = ask.is_trusted("/usr/share/doc/lua/readme.md")
            ask.trust_write("/etc")
            local write_in = ask.is_write_trusted("/etc/ssl/certs/ca.pem")
            local write_in_also_read = ask.is_trusted("/etc/ssl/certs/ca.pem")
            -- A *file* trusted inside a directory does not extend to the
            -- directory: only the path itself.
            ask.trust("/usr/share/doc")
            local file_covered = ask.is_trusted("/usr/share/doc/lua")
            -- Tidied and trailing-slash spellings resolve to the same answer.
            local messy = ask.is_trusted("/usr/share/./doc/../share/man/man1/x.1.gz")
            local trailing = ask.is_trusted("/usr/share/doc/")
            -- The boundary: a sibling whose name merely starts with the trusted
            -- one is *not* inside it.
            local sibling = ask.is_trusted("/usr/sharefoo")
            local root_sibling = ask.is_write_trusted("/etcfoo")
            -- Nothing in a folder the user never named.
            local elsewhere = ask.is_write_trusted("/opt/other/file")

            ask.forget_all()
            if not read_in then return "a file inside a trusted dir (read)" end
            if not write_in then return "a file inside a write-trusted dir" end
            if not write_in_also_read then return "and trust_write implies trust" end
            if not file_covered then return "a trusted file that is a dir path" end
            if not messy then return "a tidied path inside it" end
            if not trailing then return "a trailing slash" end
            if sibling then return "a sibling sharing the prefix" end
            if root_sibling then return "a sibling of a write-trusted dir" end
            if elsewhere then return "a folder nobody named" end
            return nil
        "#,
            )
            .eval()
            .expect("containment walk");
        assert!(
            problem.is_none(),
            "containment: {}",
            problem.unwrap_or_default()
        );
    }

    /// A trusted *directory* covers its subtree, and the boundary is respected:
    /// `/tmp` trusted does not trust `/tmpfoo`. Also the resolution forms — `~`,
    /// a relative path, `.`/`..` tidied — and that the table is left clean.
    #[test]
    fn a_trusted_directory_covers_its_subtree_only() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            local ask = agent.ask
            ask.forget_all()
            ask.trust("/tmp")
            local inside = ask.is_trusted("/tmp/agent-trust-probe/deep/file.txt")
            local sibling = ask.is_trusted("/tmpfoo")
            local itself = ask.is_trusted("/tmp")
            -- The same directory reached the way a user would write it.
            local messy = ask.is_trusted("/tmp/./a/../b/c.txt")
            -- A trusted file is *not* a trusted directory.
            ask.trust("/etc/hostname")
            local file_only = ask.is_trusted("/etc/hostname/sub")
            -- The write table is its own question: "trusted at all" is not
            -- "writable", and `trust_write` implies both.
            ask.trust_write("/opt/scratch")
            local write_only = ask.is_write_trusted("/opt/scratch")
            local write_also_general = ask.is_trusted("/opt/scratch")
            ask.trust("/opt/read-only")
            local general_only = not ask.is_write_trusted("/opt/read-only")
            local narrow = ask.forget_write("/opt/scratch")
            local narrow_took_write = not ask.is_write_trusted("/opt/scratch")
            local narrow_kept_general = ask.is_trusted("/opt/scratch")
            -- A path that is not there is trusted as a single file, which is
            -- the point: the write a policy asks about is usually the creation
            -- of the file. The narrow reading, so it covers no subtree.
            ask.trust("definitely/not/here")
            local missing_exact = ask.is_trusted("definitely/not/here")
            local missing_child = ask.is_trusted("definitely/not/here/under")
            -- `~` and a relative path resolve to the same entries.
            local home_ok, tilde_ok = true, true
            if os.getenv("HOME") then
              ask.trust("~")
              tilde_ok = ask.is_trusted(os.getenv("HOME"))
            end
            local cwd_ok = true
            if os.getenv("PWD") then
              local here = ask.trust("lua")
              cwd_ok = here:sub(1, 1) == "/" and not here:find("%.%.")
            end
            ask.forget_all()
            local left = #ask.trusted_paths()
            if not inside then return "a file inside the trusted dir" end
            if sibling then return "a sibling sharing the prefix" end
            if not itself then return "the directory itself" end
            if not messy then return "a tidied path inside it" end
            if file_only then return "a trusted file trusted a child path" end
            if not missing_exact then return "the missing path itself" end
            if missing_child then return "a missing path trusted a subtree" end
            if not write_only then return "the write table did not record" end
            if not write_also_general then return "trust_write did not write both" end
            if not general_only then return "general trust implied write trust" end
            if not narrow then return "forget_write reported nothing" end
            if not narrow_took_write then return "forget_write left the write" end
            if not narrow_kept_general then return "forget_write took the general trust" end
            if not tilde_ok then return "a tilde" end
            if not cwd_ok then return "a relative path" end
            if left ~= 0 then return "forget_all left " .. left end
            return nil
        "#,
            )
            .eval()
            .expect("trust walk");
        assert!(problem.is_none(), "trust: {}", problem.unwrap_or_default());
    }

    /// The flag-checking lib, exercised the way a policy uses it: the syscall
    /// table carries flags, and the answer comes from the name.
    #[test]
    fn seccomp_lib_decodes_flags_by_name() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            local sc = agent.seccomp
            -- openat(dirfd, path, flags): a write open with create + append.
            local sys = { name = "openat", pid = 42, args = { -100, "/tmp/x", 1089 } }
            if not sc.check_sys(sys, "openat", "WRITE") then return "write open" end
            if not sc.check_sys(sys, "openat", { "CREATE", "APPEND" }) then return "creat+append" end
            if sc.check_sys(sys, "openat", "TRUNCATE") then return "truncate" end
            if sc.describes("openat", sc.arg(sys, "openat")) ~= "O_WRONLY|O_CREAT|O_APPEND" then
              return "describes: " .. sc.describes("openat", 1089)
            end
            -- The tty probe is exempt, and named rather than a literal.
            if not sc.is_tty_probe({ name = "openat", args = { -100, "/dev/tty", 2050 } }) then
              return "tty probe"
            end
            if sc.TTY_PROBE_FLAGS ~= 2050 then return "TTY_PROBE_FLAGS" end
            -- Other families go through the same call.
            if not sc.check("access", 6, { "R", "W" }) then return "access rw" end
            if not sc.check("mmap.prot", 5, { "R", "X" }) then return "prot rx" end
            return nil
        "#,
            )
            .eval()
            .expect("seccomp eval");
        assert!(
            problem.is_none(),
            "agent.seccomp: {}",
            problem.unwrap_or_default()
        );
    }

    /// `lua/init.lua` is the one top-level script the loader runs, and it runs
    /// on every VM: the config surface is there without anyone calling a config
    /// helper first. Two halves of it — the settings table `agent.llm` (the entry
    /// script's) and the read-only `agent.llm.usage` counters (the bridge's) — plus
    /// the two names that must *not* come back: `agent.config`, which the
    /// settings table replaced, and `agent.policy`, which never existed as a
    /// namespace.
    #[test]
    fn entry_script_defines_the_config_surface_on_every_vm() {
        let lua = vm();
        let missing: Option<String> = lua
            .load(
                r#"
            local absent = {}
            for name, t in pairs({
              llm = "table", shq = "function",
              on_event = "function", trigger = "function", memory = "table",
            }) do
              if type(agent[name]) ~= t then absent[#absent + 1] = name end
            end
            -- The tool constructor is `agent.utils.tool` now, from
            -- `lua/lib/utils.lua`; the old bare name is not kept alive.
            if type(agent.utils.tool) ~= "function" then absent[#absent+1] = "utils.tool" end
            if agent.tool ~= nil then absent[#absent+1] = "agent.tool exists" end
            if type(agent.memory.flush) ~= "function" then absent[#absent+1] = "memory.flush" end
            -- A sandbox policy is a per-call table, not a namespace: there is
            -- deliberately no `agent.policy` to consult, and nothing may put
            -- one back. Same for the old `agent.config`: the settings table is
            -- `agent.llm` and nothing may keep the old name alive.
            if agent.policy ~= nil then absent[#absent+1] = "agent.policy exists" end
            if agent.config ~= nil then absent[#absent+1] = "agent.config exists" end
            -- The defaults the entry script owns.
            if agent.llm.base_url ~= "https://api.openai.com/v1" then
              return "llm.base_url", nil
            end
            if agent.llm.model ~= "gpt-4o-mini" then return "llm.model", nil end
            if agent.llm.api_key ~= "" then return "llm.api_key", nil end
            -- The script's own default is `""`, but it also activates the
            -- `coding` mode, so what is in force is that mode's prompt. What
            -- matters here is that it is a string the next request can send.
            if type(agent.llm.system_prompt) ~= "string" then
              absent[#absent+1] = "llm.system_prompt"
            end
            if type(agent.llm.memory) ~= "table" then absent[#absent+1] = "llm.memory" end
            -- The read-only counters, and read-only in fact.
            if type(agent.llm.usage.total) ~= "number" then absent[#absent+1] = "llm.usage.total" end
            if type(agent.llm.usage.reported) ~= "boolean" then
              absent[#absent+1] = "llm.usage.reported"
            end
            if pcall(function() agent.llm.usage.total = 1 end) then
              absent[#absent+1] = "agent.llm.usage is writable"
            end
            if #absent > 0 then return table.concat(absent, ","), nil end
            return nil
        "#,
            )
            .eval()
            .expect("entry script eval");
        assert!(
            missing.is_none(),
            "lua/init.lua did not define: {}",
            missing.unwrap_or_default()
        );
    }

    /// The loader's promise about the standard library, asserted so a mlua bump
    /// that narrows the safe subset cannot quietly take it away: the modules the
    /// shipped tree and the docs rely on are there, and the two withheld ones
    /// are the two we expect to be withheld (see [`STDLIB`]).
    #[test]
    fn stdlib_is_available_to_config_policies_and_tools() {
        let lua = vm();
        let report: String = lua
            .load(
                r#"
            local out = {}
            for _, name in ipairs({ "os", "io", "package", "coroutine", "string",
                                    "table", "math" }) do
              out[#out + 1] = name .. "=" .. type(_G[name])
            end
            -- What agent.ask.trust actually uses to resolve and identify a path.
            out[#out + 1] = "os.getenv=" .. type(os.getenv)
            out[#out + 1] = "os.rename=" .. type(os.rename)
            out[#out + 1] = "io.open=" .. type(io.open)
            -- Withheld by the safe subset, on purpose: loading either needs an
            -- unsafe state, which would also re-enable C modules.
            out[#out + 1] = "debug=" .. type(debug)
            out[#out + 1] = "ffi=" .. type(ffi)
            return table.concat(out, " ")
        "#,
            )
            .eval()
            .expect("stdlib probe");
        for module in [
            "os=table",
            "io=table",
            "package=table",
            "coroutine=table",
            "string=table",
            "table=table",
            "math=table",
            "os.getenv=function",
            "os.rename=function",
            "io.open=function",
            "debug=nil",
            "ffi=nil",
        ] {
            assert!(
                report.split(' ').any(|pair| pair == module),
                "stdlib: {module} missing from {report}"
            );
        }
    }

    /// The whole agent namespace now comes from `lua/lib/`, and every module
    /// also resolves by name through the search path — `require("bash")`,
    /// `require("on_timeout")` and friends are the same values `agent.*`
    /// publishes. There is no `driver` module and no `package.preload` entry
    /// left: the tree is the only source.
    #[test]
    fn the_agent_namespace_comes_from_the_lib_tree() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            -- Nothing of *ours* is preloaded any more: the loader only sets
            -- package.path. (LuaJIT's own stdlib preloads — string.buffer,
            -- jit.util — are still there; we do not touch those.)
            if package.preload["driver"] ~= nil then return "driver is preloaded" end
            if package.loaded["driver"] ~= nil then return "the driver is still loaded" end
            -- Each module is both on `agent` and reachable by name.
            if require("bash").bash ~= agent.bash then return "bash" end
            if require("panel").panel ~= agent.panel then return "panel" end
            if require("http").http ~= agent.http then return "http" end
            if require("mcp") ~= agent.mcp then return "mcp" end
            if require("on_timeout") ~= agent.on_timeout then return "on_timeout" end
            if require("utils") ~= agent.utils then return "utils" end
            if require("seccomp") ~= agent.seccomp then return "seccomp" end
            if require("ask") ~= agent.ask then return "ask" end
            -- The verdicts, the panel helpers, the cooperative wait.
            for _, name in ipairs({ "bash", "deny", "allow", "panel", "split_panel",
                                    "http", "mcp", "on_timeout" }) do
              if type(agent[name]) ~= "function" then return "agent." .. name end
            end
            return nil
        "#,
            )
            .eval()
            .expect("namespace eval");
        assert!(
            problem.is_none(),
            "agent namespace: {}",
            problem.unwrap_or_default()
        );
    }
