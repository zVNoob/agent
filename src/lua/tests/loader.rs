//! A hand-built `lua/` tree on disk, and the loader's resolution order when
//! there is no shipped tree to fall back on.
use super::*;

    /// A fixture tree loads exactly as the shipped one does: nested modules
    /// resolve through the dotted name, a top-level module through the tree
    /// root, both are auto-required at setup *before* the entry script runs
    /// (which the script itself records), a lib module's own
    /// `agent.<name> = M` registration survives, and each stays cached.
    #[test]
    fn a_fixture_tree_loads_nested_root_and_entry_in_order() {
        let dir = fixture("tree");
        std::fs::create_dir_all(dir.join("lib").join("net")).expect("fixture dirs");
        std::fs::write(
            dir.join("lib").join("net").join("http.lua"),
            "return { url = 'http' }",
        )
        .expect("nested module");
        // A lib module following the convention: it publishes itself on agent.
        std::fs::write(
            dir.join("lib").join("widgets.lua"),
            "local M = { n = 2 }\nagent.widgets = M\nreturn M",
        )
        .expect("self-registering module");
        std::fs::write(dir.join("lib").join("shadowed.lua"), "return { from = 'lib' }")
            .expect("lib module");
        // Same name at the tree root: `lib/` must win.
        std::fs::write(dir.join("shadowed.lua"), "return { from = 'root' }").expect("root module");
        std::fs::write(dir.join("only_root.lua"), "return { from = 'root' }")
            .expect("root-only module");
        // The entry script records which of the fixture modules were already
        // loaded by the time it ran, and publishes the bridge annotations
        // exactly as the shipped `lua/init.lua` does.
        std::fs::write(
            dir.join("init.lua"),
            r#"
            agent.api_docs = require("api")
            __init_saw = {}
            for _, name in ipairs({ "net.http", "only_root", "shadowed", "widgets" }) do
              __init_saw[name] = package.loaded[name] ~= nil
            end
            __init_saw.agent_widgets = agent.widgets and agent.widgets.n or nil
            "#,
        )
        .expect("entry script");
        // The real annotation file: a fixture tree has to satisfy the same
        // bridge/annotation check the shipped one does.
        std::fs::copy(tree().join("api.lua"), dir.join("api.lua")).expect("copy api.lua");

        let lua = Lua::new();
        setup_tree(&lua, None, None, &dir, &ConfigSource::Tree).expect("fixture tree setup");
        let problem: Option<String> = lua
            .load(
                r#"
            -- lib modules (nested ones included) were required before init ran.
            if not __init_saw["net.http"] then return "net.http not preloaded" end
            if not __init_saw["shadowed"] then return "shadowed not preloaded" end
            -- The tree root is require()-able but not auto-loaded: only lib/ is.
            if __init_saw["only_root"] then return "only_root was auto-loaded" end
            if require("net.http").url ~= "http" then return "nested module" end
            if require("only_root").from ~= "root" then return "root module" end
            -- lib/ outranks the tree root on a name collision.
            if require("shadowed").from ~= "lib" then return "lib precedence" end
            -- Cached: a re-require is the same table.
            if package.loaded["net.http"] ~= require("net.http") then return "cache" end
            -- A lib module's self-registration is live, and it is the module.
            if __init_saw.agent_widgets ~= 2 then return "agent.widgets" end
            if agent.widgets ~= package.loaded["widgets"] then return "widgets table" end
            return nil
        "#,
            )
            .eval()
            .expect("fixture eval");
        assert!(
            problem.is_none(),
            "fixture tree: {}",
            problem.unwrap_or_default()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The two tool shapes the live TUI run could not reach, because the local
    /// model narrates a tool call as prose instead of emitting one: a tool that
    /// draws nothing, and a tool that fails.
    ///
    /// Both are run through the real registry on a real VM, because the claim
    /// being pinned is not "the loop suppresses a box" — it is the whole
    /// arrangement: a tool has nothing to draw if it does not draw, and the
    /// model learns the outcome either way. The transcript's half of that is in
    /// `main.rs`, where the folding happens.
    #[test]
    fn a_silent_tool_and_a_failing_tool_both_reach_the_model_and_draw_nothing() {
        let dir = fixture("quiet");
        std::fs::create_dir_all(dir.join("lib")).expect("fixture dir");
        std::fs::copy(tree().join("api.lua"), dir.join("api.lua")).expect("api.lua");
        // The tool table written out rather than built with `agent.utils.tool`:
        // a fixture tree has no `lib/` modules, so `agent.utils` is nil. This is
        // the shape `utils.tool` produces (`lua/lib/utils.lua`), spelled here so
        // the test does not need the whole tree to mean one thing.
        std::fs::write(
            dir.join("init.lua"),
            r#"
            agent.api_docs = require("api")
            local function tool(description, callback)
              return { description = description,
                       signature = { type = "object", properties = {} },
                       callback = callback }
            end
            agent.mcps = {}
            agent.mcps.quiet = {
              name = "quiet",
              tools = {
                silent = tool("Succeed without drawing anything.", function()
                  return { ok = true, result = "done" }
                end),
                broken = tool("Raise without drawing anything.", function()
                  error("the tool fell over")
                end),
              },
            }
            "#,
        )
        .expect("entry script");

        let sink = crate::panels::PanelSink::default();
        let lua = Lua::new();
        setup_tree(&lua, Some(&sink), None, &dir, &ConfigSource::Tree).expect("fixture setup");

        // A tool that draws nothing has nothing to draw.
        let ran = invoke_tool_asking(&lua, "quiet.silent", "{}", None)
            .expect("the silent tool runs");
        let (_body, content) = ran.expect("the registry holds quiet.silent");
        assert!(
            sink.ops().is_empty(),
            "a tool that drew nothing queued no panel op: {:?}",
            sink.ops()
        );
        assert!(
            content.contains("done"),
            "and the model is told it worked: {content}"
        );

        // A tool that fails draws nothing either, and says nothing — the
        // transcript honours that. The model still gets the error.
        let err = invoke_tool_asking(&lua, "quiet.broken", "{}", None)
            .expect_err("a raising tool is an error");
        assert!(
            sink.ops().is_empty(),
            "a failure drew nothing either: {:?}",
            sink.ops()
        );
        assert!(
            err.contains("fell over"),
            "but the model is told why: {err}"
        );
    }

    /// A tree without an entry script is a load-time error naming the file it
    /// wanted (the tree ships with the binary, so a missing one is a broken
    /// install, not something to paper over with an empty default).
    #[test]
    fn a_tree_without_an_entry_script_fails_by_name() {
        let dir = fixture("no-init");
        std::fs::create_dir_all(dir.join("lib")).expect("fixture dir");
        let lua = Lua::new();
        let err = setup_tree(&lua, None, None, &dir, &ConfigSource::Tree).expect_err("a tree without init.lua must fail");
        let text = err.to_string();
        assert!(
            text.contains("init.lua") && text.contains(&dir.display().to_string()),
            "error should name the missing entry script, got: {text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The tree resolution order, without touching the process environment
    /// (which other tests' VMs would race on): an explicit dir wins; else
    /// `lua/` beside the executable when it has an `init.lua`; else `lua/` in
    /// the working directory.
    #[test]
    fn lua_dir_resolution_order() {
        let explicit = PathBuf::from("/srv/shared/lua");
        assert_eq!(
            lua_dir_in(Some(explicit.clone()), Some(PathBuf::from("/opt/bin/agent"))),
            explicit
        );
        // Beside the executable: an exe under <repo>/bin/ finds <repo>/lua.
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(
            lua_dir_in(None, Some(repo.join("bin"))),
            repo.join("lua")
        );
        // No lua/init.lua beside the executable -> the working directory.
        assert_eq!(
            lua_dir_in(None, Some(repo.join("bin").join("deep"))),
            PathBuf::from("lua")
        );
        assert_eq!(lua_dir_in(None, None), PathBuf::from("lua"));
    }

    /// The tree the tests load is the one the repo ships: an entry script plus
    /// at least one lib module (a missing tree would make every VM test fail
    /// above, so this only pins the shape).
    #[test]
    fn shipped_tree_has_an_entry_script_and_lib_modules() {
        let dir = tree();
        assert!(
            dir.join("init.lua").is_file(),
            "{} is missing the entry script",
            dir.display()
        );
        let modules = std::fs::read_dir(dir.join("lib"))
            .expect("lua/lib")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("lua"))
            .count();
        assert!(modules > 0, "no lua/lib/*.lua modules shipped");
    }
