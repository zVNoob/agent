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
    std::fs::write(
        dir.join("lib").join("shadowed.lua"),
        "return { from = 'lib' }",
    )
    .expect("lib module");
    // Same name at the tree root: `lib/` must win.
    std::fs::write(dir.join("shadowed.lua"), "return { from = 'root' }").expect("root module");
    std::fs::write(dir.join("only_root.lua"), "return { from = 'root' }")
        .expect("root-only module");
    // The entry script records which of the fixture modules were already loaded
    // by the time it ran.
    std::fs::write(
        dir.join("init.lua"),
        r#"
            __init_saw = {}
            for _, name in ipairs({ "net.http", "only_root", "shadowed", "widgets" }) do
              __init_saw[name] = package.loaded[name] ~= nil
            end
            __init_saw.agent_widgets = agent.widgets and agent.widgets.n or nil
            "#,
    )
    .expect("entry script");
    // The real annotation file: a fixture tree has to satisfy the same
    // bridge/documentation check the shipped one does.
    std::fs::copy(
        tree().join("agent_api.meta.lua"),
        dir.join("agent_api.meta.lua"),
    )
    .expect("copy agent_api.meta.lua");

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
    std::fs::copy(
        tree().join("agent_api.meta.lua"),
        dir.join("agent_api.meta.lua"),
    )
    .expect("agent_api.meta.lua");
    // The tool table written out rather than built with `agent.utils.tool`:
    // a fixture tree has no `lib/` modules, so `agent.utils` is nil. This is
    // the shape `utils.tool` produces (`lua/lib/utils.lua`), spelled here so
    // the test does not need the whole tree to mean one thing.
    std::fs::write(
        dir.join("init.lua"),
        r#"
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
    let ran = invoke_tool_asking(&lua, "quiet.silent", "{}", None).expect("the silent tool runs");
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
    let err = setup_tree(&lua, None, None, &dir, &ConfigSource::Tree)
        .expect_err("a tree without init.lua must fail");
    let text = err.to_string();
    assert!(
        text.contains("init.lua") && text.contains(&dir.display().to_string()),
        "error should name the missing entry script, got: {text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The tree resolution order, against **real directories on disk** rather
/// than paths that might or might not exist.
///
/// The old version of this test asserted the order with hypothetical paths,
/// which meant it passed whatever the lookup did as long as it returned
/// *something* plausible: it could not tell a search from a fallback. Each
/// step here builds the layout it is testing for, so "found it" means the
/// directory really was there and the search really did reach it.
///
/// The contract, in order:
///
///   1. `$AGENT_LUA_DIR` wins outright — it is not even probed for
///      existence, because an operator who set it means it.
///   2. `<prefix>/share/agent/lua`, found by walking *up* from the
///      executable. This is the install layout and the only one a release
///      build depends on.
///   3. `lua` beside the executable, for a hand-copied binary.
///   4. the tree it was built from, in debug builds only.
///
/// And the one that is *not* on the list: the working directory. There is a
/// test for that below, because it is the absence that matters most.
#[test]
fn lua_dir_resolution_order() {
    let explicit = PathBuf::from("/srv/shared/lua");
    assert_eq!(
        lua_dir_in(
            Some(explicit.clone()),
            Some(PathBuf::from("/opt/bin/agent"))
        ),
        explicit,
        "the explicit dir wins without being probed, even against an exe path \
             that would otherwise resolve"
    );

    // Build a real install layout: <root>/bin/agent, <root>/share/agent/lua.
    let root = crate::testutil::scratch_dir("agent-install-layout");
    let bin = root.join("bin");
    let shared = root.join("share").join("agent").join("lua");
    std::fs::create_dir_all(&bin).expect("bin");
    std::fs::create_dir_all(&shared).expect("share");
    std::fs::write(shared.join("init.lua"), "-- installed\n").expect("entry script");
    let exe = bin.join("agent");
    assert_eq!(
        lua_dir_in(None, Some(exe.clone())),
        shared,
        "the install layout is found by walking up from the executable: the \
             tree is a *sibling* of bin/, not a child of it"
    );

    // Now a tree beside the executable instead — no share/ anywhere.
    let beside = bin.join("lua");
    std::fs::create_dir_all(&beside).expect("beside");
    std::fs::write(beside.join("init.lua"), "-- beside\n").expect("entry script");
    assert_eq!(
        lua_dir_in(None, Some(exe.clone())),
        shared,
        "share/ wins over a tree beside the executable: the install layout is \
             the real one and a stray lua/ next to the binary should not shadow it"
    );
    let _ = std::fs::remove_dir_all(shared.parent().unwrap());

    assert_eq!(
        lua_dir_in(None, Some(exe)),
        beside,
        "with no share/ tree, one beside the executable is the next place"
    );

    // Neither: with nothing on disk the lookup returns its last candidate,
    // so that the caller reports the very path it failed on rather than
    // inventing a second one at the error site.
    let nothing = bin.join("elsewhere");
    std::fs::create_dir_all(&nothing).expect("nothing");
    let candidates = lua_dir_candidates(None, Some(nothing.join("agent")));
    let last = candidates.last().expect("at least one candidate");
    assert_eq!(
        lua_dir_in(None, Some(nothing.join("agent"))),
        last.1,
        "the last candidate is returned, not a fresh guess"
    );
    // In a debug build that last candidate is the checkout, which does hold a
    // tree — that is the whole reason it is there. In a release build it is a
    // path on the build machine, which is exactly the case that must *not*
    // silently succeed, so that a broken install is reported rather than
    // papered over.
    assert_eq!(
        cfg!(debug_assertions),
        last.1.join("init.lua").is_file(),
        "the build-time fallback is only usable in debug builds; in release it \
             is a stale path that has to fail loudly. last={last:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The working directory is not on the list, and that is a security property
/// rather than a tidiness one.
///
/// The lookup used to end in `PathBuf::from("lua")`, so a `lua/` directory
/// in whatever directory you happened to be in was enough to supply the
/// tree — including `lua/policy.lua`, which is the sandbox policy. For a tool
/// whose entire job is asking before it touches a file, running it from a
/// checkout of anything at all would silently swap the shipped policy for
/// whatever was lying in `./lua`.
///
/// Built as a real directory and `set_current_dir`'d into, so this fails if
/// the fallback ever comes back. The cwd is restored afterwards even on
/// failure, since every other test in the suite resolves paths against it.
#[test]
fn a_lua_directory_in_the_working_directory_is_never_the_tree() {
    let dir = crate::testutil::scratch_dir("agent-cwd-lua");
    std::fs::create_dir_all(dir.join("lua")).expect("cwd tree");
    std::fs::write(dir.join("lua/init.lua"), "-- from the cwd\n").expect("entry script");
    let entry = dir.join("lua/init.lua");
    assert!(entry.is_file(), "the decoy is real: {}", entry.display());

    let before = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&dir).expect("into the decoy");
    // An exe path that cannot resolve: <dir>/bin/agent, with no share/ and
    // nothing beside it.
    let found = lua_dir_in(None, Some(dir.join("bin/agent")));
    std::env::set_current_dir(&before).expect("back");

    // **Resolve before comparing.** The fallback this forbids is the bare
    // relative path `lua`, so comparing it to the absolute decoy path passes
    // whether or not the fallback is present — the first version of this test did
    // exactly that and caught nothing. Anchoring the found path to the directory
    // that was current at the time is what makes the two comparable.
    let resolved = if found.is_absolute() {
        found.clone()
    } else {
        dir.join(&found)
    };
    assert_ne!(
        resolved.canonicalize().ok(),
        dir.join("lua").canonicalize().ok(),
        "a tree in the working directory must not be picked up: the lookup \
         returned {found:?}, which from {} is the decoy",
        dir.display()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The message for a missing tree has to name where it looked. The version it
/// replaced was `lua lib: lua/lib: No such file or directory (os error 2)`,
/// which came from failing to *read* a directory rather than from noticing the
/// tree was absent — so it named one arbitrary candidate and said nothing
/// about the install layout or the one variable that overrides everything.
#[test]
fn the_missing_tree_message_names_every_place_it_looked() {
    let candidates = lua_dir_candidates(None, Some(PathBuf::from("/opt/bin/agent")));
    let msg = missing_tree_message(&candidates);
    for (what, dir) in &candidates {
        assert!(
            msg.contains(dir.to_string_lossy().as_ref()),
            "the message omits {what} at {}: {msg}",
            dir.display()
        );
    }
    assert!(
        msg.contains("AGENT_LUA_DIR"),
        "and it must name the one thing that overrides all of them: {msg}"
    );
    assert!(
        msg.contains("share"),
        "and the install layout, which is the answer for most people: {msg}"
    );
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

/// The bridge's documentation is checked against the real bridge, both ways, and
/// each direction is its own way to be wrong: a primitive nobody wrote down is
/// folklore, and a declaration for a primitive that is gone is a promise the agent
/// cannot keep.
///
/// The check reads `lua/agent_api.meta.lua` rather than `require`ing it — a
/// `---@meta` file is comments, and running it would define functions against the
/// *locked* bridge table. So these drive a fixture tree with a doctored copy of that
/// file, which is the only way to reach the failure at all.
#[test]
fn a_primitive_with_no_declaration_stops_the_vm() {
    let dir = fixture("undocumented");
    std::fs::create_dir_all(dir.join("lib")).expect("fixture dir");
    std::fs::write(dir.join("init.lua"), "-- nothing\n").expect("init");
    let meta = std::fs::read_to_string(tree().join("agent_api.meta.lua")).expect("read meta");
    // Drop `step`: a real edit would be adding a Rust primitive and forgetting this.
    let doctored = meta
        .lines()
        .filter(|l| !l.trim_start().starts_with("function agent.api.step("))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(dir.join("agent_api.meta.lua"), doctored).expect("meta");

    let lua = Lua::new();
    let err = setup_tree(&lua, None, None, &dir, &ConfigSource::Tree)
        .expect_err("an undocumented primitive must not build");
    let msg = err.to_string();
    assert!(
        msg.contains("no declaration") && msg.contains("step"),
        "the message names the primitive and the reason, not just a failure: {msg}"
    );
}

#[test]
fn a_declaration_for_a_primitive_that_is_gone_stops_the_vm() {
    let dir = fixture("stale-decl");
    std::fs::create_dir_all(dir.join("lib")).expect("fixture dir");
    std::fs::write(dir.join("init.lua"), "-- nothing\n").expect("init");
    let meta = std::fs::read_to_string(tree().join("agent_api.meta.lua")).expect("read meta");
    // A renamed primitive: the declaration outlived the function.
    let doctored = format!("{meta}\nfunction agent.api.spawn_v2(cmdline) end\n");
    std::fs::write(dir.join("agent_api.meta.lua"), doctored).expect("meta");

    let lua = Lua::new();
    let err = setup_tree(&lua, None, None, &dir, &ConfigSource::Tree)
        .expect_err("a declaration for a primitive that does not exist must not build");
    let msg = err.to_string();
    assert!(
        msg.contains("do not exist") && msg.contains("spawn_v2"),
        "the message names the stale declaration: {msg}"
    );
}
