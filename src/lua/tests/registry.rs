//! The tool registry: that every `agent.mcps` connection is translated into the
//! request's tool catalog, and that a mode can narrow it.
use super::*;

use crate::testutil::unique_path;
/// `lua/agent_api.meta.lua` documents the whole bridge, and the loader refuses to
/// build a VM when the two disagree — so the interesting fact left to pin here is
/// the one the loader's check cannot see.
///
/// The loader compares *sets*: it answers "is every primitive declared?" and "is
/// every declaration real?". A declaration written twice passes both, because a
/// `BTreeSet` keeps one. That is worth catching, since the duplicated stub is the
/// kind of edit that looks like tidying, and it leaves two places to update the next
/// time the signature changes.
///
/// The declared side comes from [`declared_primitives`] rather than a scan written
/// here: a second implementation of the marker would agree with the loader until the
/// day it did not, and then it would be the thing disagreeing while claiming to
/// check it.
#[test]
fn the_lua_ls_annotations_cover_exactly_the_bridge_once_each() {
    // The bridge, from the function the loader itself builds it with — `agent.api` is
    // a locked proxy whose `pairs` yields nothing on purpose, so the names are not
    // reachable from Lua at all.
    let lua = new_vm().expect("vm");
    let api = crate::lua::bridge::install_api(&lua, None, None).expect("bridge");
    let mut bridge: Vec<String> = Vec::new();
    for pair in api.pairs::<String, mlua::Value>() {
        bridge.push(pair.expect("a bridge entry").0);
    }
    bridge.sort();
    assert_eq!(
        bridge.len(),
        40,
        "the bridge's size is part of the contract"
    );

    let meta = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("lua/agent_api.meta.lua");
    let declared = crate::lua::bridge::declared_primitives(&meta).expect("read the meta file");

    let untyped: Vec<&str> = bridge
        .iter()
        .filter(|b| !declared.contains(*b))
        .map(String::as_str)
        .collect();
    let invented: Vec<&str> = declared
        .iter()
        .filter(|d| !bridge.contains(d))
        .map(String::as_str)
        .collect();
    assert!(
        untyped.is_empty(),
        "lua/agent_api.meta.lua leaves these primitives untyped: {untyped:?}"
    );
    assert!(
        invented.is_empty(),
        "lua/agent_api.meta.lua annotates these, which are not primitives: {invented:?}"
    );

    // The set comparison above cannot see a duplicate; the line count can.
    let occurrences = std::fs::read_to_string(&meta)
        .expect("read the meta file")
        .lines()
        .filter(|l| l.trim_start().starts_with("function agent.api."))
        .count();
    assert_eq!(
        occurrences,
        bridge.len(),
        "each primitive is declared exactly once — the loader compares sets, so a \
         second stub for one primitive would pass it"
    );
}

/// `lua/mcps.lua` is the shipped connection set as one registry — the same
/// tools `lua/init.lua` registers, obtainable in a single require, and usable
/// as a mode's tool set.
///
/// Its *name* is pinned here too, because getting it wrong is silent: `mcp`
/// is `lua/lib/mcp.lua` (the client), `lib/` is ahead of the root on
/// `package.path`, and a root `mcp.lua` would be shadowed rather than
/// preferred. So this asserts that `require("mcps")` is the registry and
/// that `require("mcp")` is still the client.
#[test]
fn mcps_module_is_the_shipped_connection_registry() {
    let lua = shipped_vm();

    // It is a registry of connections, not a tool: keyed by name, each value
    // carrying the connection's own tools.
    let problem: Option<String> = lua
        .load(
            r#"
        local mcps = require("mcps")
        if type(mcps) ~= "table" then return "not a table" end
        for _, name in ipairs({ "fs", "bash" }) do
          local conn = mcps[name]
          if type(conn) ~= "table" then return name .. " missing" end
          if type(conn.tools) ~= "table" then return name .. " is not a connection" end
          if next(conn.tools) == nil then return name .. " has no tools" end
          if agent.mcps[name] ~= conn then
            return name .. " is not the same connection the config registered"
          end
        end
        return nil
    "#,
        )
        .eval()
        .expect("mcps eval");
    assert!(
        problem.is_none(),
        "lua/mcps.lua: {}",
        problem.unwrap_or_default()
    );

    // The two names are two different modules, which is the whole reason for
    // the plural.
    let which: String = lua
        .load(
            r#"
        local client = require("mcp")
        if client ~= agent.mcp then return "require('mcp') is not agent.mcp" end
        if client == require("mcps") then return "mcp and mcps are the same table" end
        return "ok"
    "#,
        )
        .eval()
        .expect("which mcp");
    assert_eq!(which, "ok", "the singular name is still the client");

    // And it is usable as a mode's tool set, which is the other reason to
    // have it: an explicitly named set, rather than the "all" sentinel. The
    // check is Rust's own reindex, so it is the catalog the model would be
    // offered, not Lua's opinion of it.
    let baseline: Vec<String> = mcps_tool_defs(&lua)
        .expect("baseline defs")
        .iter()
        .map(|d| d.name.clone())
        .collect();
    lua.load(
        r#"
        agent.mode.new("named", { mcps = require("mcps"), system_prompt = "N" })
        agent.mode.set("named")
    "#,
    )
    .exec()
    .expect("switch to the named mode");
    let offered: Vec<String> = mcps_tool_defs(&lua)
        .expect("named defs")
        .iter()
        .map(|d| d.name.clone())
        .collect();
    assert_eq!(
        offered, baseline,
        "the mode offers exactly the shipped registry"
    );
    let current: Option<String> = lua
        .load("return agent.mode.current()")
        .eval()
        .expect("current");
    assert_eq!(
        current.as_deref(),
        Some("named"),
        "and it is the mode in force"
    );
}

/// The `coding` mode is the *permissive* half of the mode machinery: it
/// changes the prompt and leaves the tool set exactly as it is, so the mode a
/// session actually works in cannot go stale against the connections its
/// config registered.
///
/// The contrast is the point: `compact` narrows to nothing, `coding` narrows
/// to nothing *less*, and the sentinel is what makes "everything" expressible
/// without listing connections that may not be registered yet.
#[test]
fn the_coding_mode_keeps_every_tool_and_changes_only_the_prompt() {
    let lua = shipped_vm();
    // The shipped config already starts in `coding`, so clear to the baseline
    // first: this test is about what a switch *does*, and starting from the
    // mode itself would make the switch a no-op and prove nothing.
    lua.load("agent.mode.set()")
        .exec()
        .expect("clear to the baseline");
    let tools_before = mcps_tool_defs(&lua).expect("baseline defs");
    let mut before: Vec<&str> = tools_before.iter().map(|d| d.name.as_str()).collect();
    before.sort_unstable();
    assert!(
        before.contains(&"fs.read") && before.contains(&"fs.write_file"),
        "the baseline has the file tools: {before:?}"
    );
    let baseline_prompt = system_prompt(&lua).expect("baseline prompt");

    // Switching to it registers and applies in one step.
    lua.load(r#"agent.mode.set("coding")"#)
        .exec()
        .expect("switch");
    let tools_after = mcps_tool_defs(&lua).expect("coding defs");
    let mut after: Vec<&str> = tools_after.iter().map(|d| d.name.as_str()).collect();
    after.sort_unstable();
    assert_eq!(after, before, "every tool is still offered, tool for tool");

    // The prompt is the other half. The shipped config's *default* prompt is
    // the same wording, so "the mode's prompt differs from the baseline" is
    // not a property this VM can show — what it can show is that the prompt
    // in force while `coding` is the coding prompt, and that the mode's own
    // spec carries it.
    let prompt = system_prompt(&lua).expect("coding prompt");
    // Both halves, not one phrase. The prompt used to describe only the
    // editing path, which left a task that changes nothing with no guidance
    // at all; asserting on one remembered sentence would not have caught
    // that, and would not catch a half-removed path either.
    assert!(
        prompt.contains("coding agent")
            && prompt.contains("To understand code")
            && prompt.contains("To change code"),
        "the coding prompt is what is sent, with both paths in it: {prompt:.80}"
    );
    let spec_prompt: String = lua
        .load("return agent.mode.get('coding').system_prompt")
        .eval()
        .expect("spec prompt");
    assert_eq!(
        spec_prompt, prompt,
        "and it is the one the mode carries, not a copy that drifted"
    );
    let _ = baseline_prompt; // the default wording; see above

    // And the mode knows which one is in force.
    let current: Option<String> = lua
        .load("return agent.mode.current()")
        .eval()
        .expect("current");
    assert_eq!(current.as_deref(), Some("coding"));

    // The mode names its tool set, so it is exactly the shipped registry and
    // nothing more: a connection registered afterwards is *not* in it. (The
    // `"all"` sentinel is the other way round, and `agent.mode._selftest`
    // pins that directly.)
    lua.load(
            r#"
        agent.mcps.later = { name = "later", tools = { ping = agent.utils.tool(
          "a tool registered after the mode", { type = "object", properties = {} }, function() return "pong" end) } }
        agent.mode.set("coding")
    "#,
        )
        .exec()
        .expect("re-apply after registering");
    let names: Vec<String> = mcps_tool_defs(&lua)
        .expect("defs")
        .iter()
        .map(|d| d.name.clone())
        .collect();
    assert!(
        !names.contains(&"ping".to_string()),
        "a named registry is what the mode said it is, not the session's: {names:?}"
    );

    // Clearing restores the baseline prompt and the baseline registry — and
    // that registry is a *snapshot* taken at the first switch, which is what
    // keeps a connection registered mid-session out of it.
    lua.load("agent.mode.set()").exec().expect("clear");
    assert_eq!(
        system_prompt(&lua).expect("restored prompt"),
        baseline_prompt,
        "the baseline prompt is back"
    );
    let restored_defs = mcps_tool_defs(&lua).expect("restored defs");
    let restored: Vec<&str> = restored_defs.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(
        restored, before,
        "and so is the baseline tool set — the mode added nothing"
    );
}

/// A mode narrows what the agent can reach: its connection set replaces
/// `agent.mcps`, so a tool the mode leaves out is neither advertised to the
/// next request nor callable — and clearing the mode brings it back.
///
/// The read-only view is a *new connection* holding the *same tool tables*
/// as the full one (the reference semantics `mcps` relies on), which is how
/// a mode trims a connection's tool set without rebuilding it.
#[test]
fn a_mode_narrows_the_tool_set() {
    let lua = shipped_vm();
    let dir = unique_path("agent-mode-fs");
    let _ = std::fs::remove_dir_all(&dir);
    // `None` = the mode does not offer the tool at all. A tool the mode
    // *does* offer still has to be answered: the file tools ask before they
    // touch anything, so a write is only as available as the last yes.
    let write = |name: &str| -> Option<bool> {
        let args = serde_json::json!({
            "path": dir.join(name).to_string_lossy(),
            "content": "payload\n",
        })
        .to_string();
        invoke_tool(&lua, "fs.write_file", &args)
            .expect("invoke")
            .and_then(|(body, _)| serde_json::from_str::<serde_json::Value>(&body).ok())
            .and_then(|v| v["ok"].as_bool())
    };
    let asked_write = |name: &str| -> Option<bool> {
        let args = serde_json::json!({
            "path": dir.join(name).to_string_lossy(),
            "content": "payload\n",
        })
        .to_string();
        let (v, _asked) = tool_allowed("fs.write_file", &args);
        v["ok"].as_bool()
    };

    // Baseline: the full connection, so the write is offered and works.
    let defs = mcps_tool_defs(&lua).expect("baseline defs");
    let baseline: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
    assert!(
        baseline.contains(&"fs.write_file"),
        "baseline: {baseline:?}"
    );
    assert_eq!(
        asked_write("baseline.txt"),
        Some(true),
        "the baseline write goes through, once allowed"
    );

    // A mode whose connection exposes only the two read tools.
    lua.load(
        r#"
            local fs = require("fs")
            local read_only = {
              name = "fs_read_only",
              description = "reads only",
              tools = { read = fs.tools.read },
            }
            agent.mode.new("read_only", {
              description = "no edits",
              system_prompt = "You may read, not write.",
              mcps = { fs_read_only = read_only },
            })
            agent.mode.set("read_only")
        "#,
    )
    .exec()
    .expect("set read-only mode");

    let defs = mcps_tool_defs(&lua).expect("mode defs");
    let mut names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["fs_read_only.read"],
        "the mode advertises exactly the tools *its* connection exposes — \
             qualified by that connection's name, not the built-in one's"
    );
    assert_eq!(
        write("blocked.txt"),
        None,
        "a tool the mode omits is not callable at all"
    );
    assert!(!dir.join("blocked.txt").exists(), "nothing was written");
    assert_eq!(
        system_prompt(&lua).expect("prompt"),
        "You may read, not write.",
        "the mode's prompt half is what the next request sends"
    );

    // Clearing the mode restores both halves.
    lua.load("agent.mode.set()").exec().expect("clear mode");
    let defs = mcps_tool_defs(&lua).expect("restored defs");
    let mut restored: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
    restored.sort_unstable();
    assert_eq!(
        restored,
        [
            "bash.bash",
            "fs.apply_patch",
            "fs.hand_to_user",
            "fs.read",
            "fs.write_file"
        ],
        "clearing the mode restores the configured tool set"
    );
    assert_eq!(
        asked_write("allowed.txt"),
        Some(true),
        "clearing the mode restores the write tool, once allowed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
