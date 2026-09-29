//! Agent configuration in Lua: the LLM endpoint, the system prompt, and the
//! tool registry.
//!
//! Everything the agent is *made of* is read out of Lua on demand — never
//! cached in Rust, and never mirrored in an environment variable. The section
//! banner below explains why; this is also where a tool is *invoked* (the
//! blocking driver [`invoke_tool`], used when there is no loop to step a
//! coroutine).
//!
use std::path::Path;

use mlua::{Lua, Table};

use crate::panels::PanelSink;

use super::run::{ToolRun, ToolStep};
use super::tree::lua_dir;
use super::usage::install_usage;
use super::vm::{AskAnswer, AskHandler, new_vm_with_ask_from, user_config};

// ---------------------------------------------------------------------------
// Agent configuration in Lua: the LLM endpoint, the system prompt, the tools.
// ---------------------------------------------------------------------------
//
// The agent's configuration lives in Lua, not in environment variables. A
// user config (`~/.config/agent/init.lua`, see [`ensure_config`]) is loaded
// after `lua/init.lua` and can set:
//
//   1. the LLM endpoint — `agent.llm = { base_url, model, api_key }`,
//      which used to be the AGENT_BASE_URL / AGENT_MODEL / AGENT_API_KEY
//      environment variables (the TUI builds `api::ChatConfig` from it);
//   2. the system prompt — `agent.llm.system_prompt`, sent as the leading
//      `system` message of every request;
//   3. the tools — plain `agent.mcps` entries: [`agent.utils.tool`] objects and the
//      connections `agent.mcp` opens. That table is the whole registry.
//   4. event hooks — `agent.on_event("turn_completed", fn)` registers a
//      handler Rust fires when a full user turn ends, with the conversation
//      in the payload (`{ history = {...} }`): the read side of compaction.
//      The handler runs **cooperatively on the agent's single reactor
//      thread** as a coroutine (see [`EventRun`]): each `agent.on_timeout`
//      wait suspends it until the reactor's timer fires, so the loop never
//      blocks on handler I/O — strictly single-threaded; the old
//      fire-and-forget background thread is gone. A handler calling
//      `agent.bash` runs it **cooperatively** the same way: on the reactor
//      `_step` polls are non-blocking and the pump suspends for a cadence
//      between idle steps, so a long-running command yields
//      [`EventStep::Waiting`] all the way through and the loop stays live
//      (asks auto-deny — no ask UI in a background handler);
//   5. driving the loop — `agent.trigger(...)` forces a new inference, and an
//      array argument **replaces** the loop's in-memory history first (a
//      compacted history handed back): the write side of compaction.
//
// Two primitives are enough to steer the agent, and composing them is the
// user's job, not the runtime's: the **system prompt** says what the agent
// should do, and a **reactive policy table** — the seccomp policy
// `agent.bash` takes — says what its commands may do, deciding per syscall at
// runtime. Grouping those two into a named, switchable pair *is* modelled, but
// only as a Lua mechanism (`lua/lib/mode.lua` → `agent.mode`):
// `agent.mode.set(name)` overwrites `agent.mcps` and
// `agent.llm.system_prompt`, both of which Rust re-reads per request, so a
// switch is live without a restart. The same goes for
// compaction: Rust only supplies the event (read), the trigger (force an
// inference), and the history replacement (write) — what to summarize and
// how is Lua's decision.
//
// Persistence is the same deal with a default: the loop archives every
// history message to an append-only, block-compressed conversation log on
// disk (`crate::memory`) shared behind a process-wide mutex
// ([`bind_memory`] — path and on/off from `agent.llm.memory`), flushing
// at turn boundaries and on exit. Lua reads and writes the same store
// through `agent.memory.append / latest / flush / path`. The archive is a
// raw append-only transcript: compaction shrinks only the *in-memory*
// history, never what was logged.
//
// Rust **never caches** the registry. Every request reindexes `agent.mcps`
// (the live table) and every tool call runs on the config VM itself — so an
// config edit shows up on the very next request, with no stale Rust state,
// and whatever a tool decided (a trusted path, a trusted server) is still there
// on the next one. The only Rust state is the config VM, and the process is
// single-threaded, so it never has to cross a thread. mlua is built without the
// `send` feature (Cargo.toml is frozen), which is what makes that a constraint
// rather than a choice: a `Lua` is not `Send`, and a tool is therefore a
// coroutine the event loop steps, not work handed to a thread of its own.

// The runtime machinery for the Lua configuration — the built-in defaults,
// which a user's copy then edits — lives in the entry script
// `lua/init.lua`, which [`load_init`] runs on every VM (so it is always present
// by the time anything reads `agent.llm`). It requires the driver itself
// (`require("driver")`) for the `agent.bash` / `agent.memory` half of the
// namespace; the `agent.*` namespace itself comes from `lua/lib/`. Its
// assignments are `or`-guarded, so re-loading never clobbers user values — which
// is also why a config assigns `agent.llm.<field>` rather than replacing the
// table: the keys it does not mention (`memory`) have to survive.
//
// One piece of the surface is *not* Lua at all: `agent.llm.usage`, the read-only
// token counts of the last request, is written by the loop (see [`record_usage`])
// and seeded into every VM.

/// Where a VM's configuration comes from.
///
/// The split is not tidiness: one of these reads and writes the invoking user's
/// home directory, and a test suite that did that by accident would be testing
/// the machine rather than the code. So the home-directory path is opt-in, and
/// [`ConfigSource::Tree`] is what every test gets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConfigSource {
    /// The shipped `lua/init.lua`, run where it lies. Touches no `$HOME`.
    #[default]
    Tree,
    /// The user's `~/.config/agent/init.lua`, seeded from the shipped one the
    /// first time. What the agent binaries run on.
    UserHome(Option<std::path::PathBuf>),
}

/// How a VM's configuration came to be, so the caller can say so at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigOrigin {
    /// The shipped `init.lua` was run directly; no user config is involved.
    Tree,
    /// The user's `init.lua` already existed and was run.
    Existing,
    /// The user's `init.lua` did not exist, so the shipped one was copied there
    /// and run. It is now *theirs* to edit.
    Seeded,
}

/// The user's configuration file, seeded from the tree's `init.lua` when it does
/// not exist yet.
///
/// This is the difference between a program that ships a configuration file and
/// one that ships a *template*: after the first run the file at
/// `~/.config/agent/init.lua` is the agent's configuration, and the copy beside
/// the binary is only what it was seeded from. Editing it is the supported way
/// to configure anything, and `/reload` re-reads it.
///
/// The consequence to be aware of: upgrading the agent does **not** update a
/// config that has already been seeded, because the user's file is now the
/// authority. Delete it to be re-seeded from whatever ships next.
///
/// A home that cannot be written (a read-only `$HOME`, a container running as
/// nobody) is not fatal: the tree's own `init.lua` is run instead and the caller
/// is told, because an agent with its defaults beats an agent that will not
/// start.
pub fn ensure_config(
    tree: &Path,
    home: Option<&std::path::Path>,
) -> (std::path::PathBuf, ConfigOrigin) {
    let shipped = tree.join("init.lua");
    let Some(home) = home else {
        return (shipped, ConfigOrigin::Tree);
    };
    let dir = home.join(".config").join("agent");
    let path = dir.join("init.lua");
    if path.is_file() {
        return (path, ConfigOrigin::Existing);
    }
    if let Err(why) = std::fs::create_dir_all(&dir)
        .and_then(|()| std::fs::copy(&shipped, &path))
    {
        eprintln!(
            "[agent] could not write {} ({why}); using the built-in defaults",
            path.display()
        );
        return (shipped, ConfigOrigin::Tree);
    }
    (path, ConfigOrigin::Seeded)
}

pub fn apply_config_source(lua: &Lua, source: &str) -> Result<(), String> {
    if source.trim().is_empty() {
        return Ok(());
    }
    lua.load(source)
        .exec()
        .map_err(|e| format!("config: ~/.config/agent/init.lua: {e}"))?;
    // A config that assigns the whole table (`agent.llm = { ... }`) drops the
    // read-only counters along with anything it did not mention. Put them back
    // now rather than leaving the surface incomplete until the next request
    // happens to record one.
    install_usage(lua).map_err(|e| format!("config: agent.llm.usage: {e}"))?;
    Ok(())
}

/// Load the user's config (see [`config_path`]) into `lua`. Missing
/// file -> `Ok(false)` with the driver defaults in place; loaded -> `Ok(true)`.
pub fn load_config_file(lua: &Lua) -> Result<bool, String> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let (path, origin) = ensure_config(&lua_dir(), home.as_deref());
    if origin == ConfigOrigin::Tree {
        return Ok(false);
    }
    let source = std::fs::read_to_string(&path)
        .map_err(|e| format!("config: read {}: {e}", path.display()))?;
    apply_config_source(lua, &source)?;
    Ok(true)
}

/// The LLM endpoint the agent talks to, read from `agent.llm` (the Lua
/// configuration, replacing the AGENT_BASE_URL / AGENT_MODEL / AGENT_API_KEY
/// environment variables).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
}

/// Read `agent.llm.{base_url, model, api_key}`, falling back per-field to the
/// defaults both `lua/init.lua` and api.rs's old `from_env` agree on.
pub fn llm_config(lua: &Lua) -> Result<LlmConfig, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("config: agent table: {e}"))?;
    let mut llm = LlmConfig {
        base_url: "https://api.openai.com/v1".to_string(),
        api_key: String::new(),
        model: "gpt-4o-mini".to_string(),
    };
    if let Ok(t) = agent.get::<Table>("llm") {
        llm.base_url = t.get("base_url").unwrap_or(llm.base_url);
        llm.api_key = t.get("api_key").unwrap_or(llm.api_key);
        llm.model = t.get("model").unwrap_or(llm.model);
    }
    Ok(llm)
}

/// The system prompt the agent sends as the leading `system` message of every
/// request: `agent.llm.system_prompt` (`""` — the default — means none, so
/// requests start with the conversation itself).
///
/// Read per request off the live config VM, like the tool registry: editing it
/// in the user's config, and reloading changes what the model is told next turn.
pub fn system_prompt(lua: &Lua) -> Result<String, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("config: agent table: {e}"))?;
    let config: Table = agent.get("llm").map_err(|e| format!("config: agent.llm: {e}"))?;
    Ok(config.get("system_prompt").unwrap_or_default())
}

/// One tool advertised by `agent.mcps`, at lib level — the bins translate it
/// into their own `api::ToolDef` (api.rs lives per-binary).
#[derive(Debug, Clone)]
pub struct McpToolDef {
    pub name: String,
    pub description: String,
    /// The tool's advertised `inputSchema`, already a JSON object schema.
    pub parameters: serde_json::Value,
}

/// The name a tool is advertised and called by: `{connection}.{tool}`.
///
/// Connections are a namespace, and the name the model sees has to carry it.
/// A bare `list_issues` from two MCP servers is not one tool, it is two tools
/// with one name — and the registry resolves a bare name by scanning every
/// connection and taking the first hit, so the loser is unreachable rather than
/// merely ambiguous. Qualifying at the point of advertisement means the
/// collision cannot be expressed.
///
pub(crate) fn qualified_name(conn: &str, tool: &str) -> String {
    format!("{conn}.{tool}")
}

pub(super) fn split_qualified(name: &str) -> Option<(&str, &str)> {
    name.split_once('.')
        .filter(|(conn, tool)| !conn.is_empty() && !tool.is_empty())
}

/// Reindex `agent.mcps` in `lua`: read the live registry and return one
/// [`McpToolDef`] per registered tool, sorted by name for a stable order.
///
/// Called **per request** and never cached — see the section docs. The result
/// reflects whatever the table holds at that moment (a hand-built connection
/// from `agent.utils.tool`, or one `agent.mcp` opened), so the caller re-derives
/// its advertised tool list on every request instead of keeping a Rust-side
/// snapshot.
pub fn mcps_tool_defs(lua: &Lua) -> Result<Vec<McpToolDef>, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("mcps: agent table: {e}"))?;
    let mcps: Table = agent
        .get("mcps")
        .map_err(|e| format!("mcps: agent.mcps: {e}"))?;
    let mut defs = Vec::new();
    for pair in mcps.pairs::<String, Table>() {
        let (conn_name, conn) = pair.map_err(|e| format!("mcps: conn: {e}"))?;
        let tools: Table = conn
            .get("tools")
            .map_err(|e| format!("mcps: {conn_name}.tools: {e}"))?;
        for pair in tools.pairs::<String, Table>() {
            let (tool_name, tool) = pair.map_err(|e| format!("mcps: tool: {e}"))?;
            let name = qualified_name(&conn_name, &tool_name);
            let description: String = tool.get("description").unwrap_or_default();
            let signature: mlua::Value = tool.get("signature").unwrap_or(mlua::Value::Nil);
            let parameters = crate::mcp::lua_to_json( &signature)
                .map_err(|e| format!("mcps: {name} signature: {e}"))?;
            defs.push(McpToolDef {
                name,
                description,
                parameters,
            });
        }
    }
    defs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(defs)
}

/// Invoke a tool registered in `agent.mcps` on an already-configured VM (the
/// user configuration applied).
///
/// Returns `Ok(None)` when `name` is not in the registry — the caller's cue to
/// refuse it (the agent loop additionally gates on what the request offered);
/// `Ok(Some((body, content)))` with the MCP-shaped result
/// (`{ok, result, error, denied}`) as JSON text; `Err` for JSON / VM failures.
pub fn invoke_tool(
    lua: &Lua,
    name: &str,
    arguments: &str,
) -> Result<Option<(String, String)>, String> {
    invoke_tool_asking(lua, name, arguments, None)
}

/// [`invoke_tool`], answering any question the tool asks with `on_ask` — the
/// same wiring [`ToolRun`] gives the TUI, driven to completion right here
/// instead of by the event loop.
///
/// This is the **blocking** driver: for tests, the headless probe, and any
/// caller with no reactor to step a coroutine. The tool still runs as a Lua
/// coroutine on `lua` (that is what lets it ask at all), but each ask is
/// answered immediately by `on_ask` — or denied, with no handler, exactly as
/// `agent.api.ask_user` denies when no one is there. A sandbox's cooperative
/// cadence waits are pumped here by the same immediate resume, so a long command
/// is waited out rather than slept through.
pub fn invoke_tool_asking(
    lua: &Lua,
    name: &str,
    arguments: &str,
    on_ask: Option<AskHandler>,
) -> Result<Option<(String, String)>, String> {
    // Nobody is going to give this coroutine slices: it is being driven to
    // completion right here, on this thread, with no reactor in between. So the
    // VM is *not* marked reactor-driven for the call — a sandbox run inside the
    // tool then blocks in `agent.api.step` as its wait, which is the only way a
    // reactor-less driver can make progress. (The TUI drives the same tool with
    // `ToolRun` directly, where the marker is right and the loop is the reactor.)
    // Restored afterwards, so a tool that switched modes or armed a timer is
    // unaffected either way.
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("config: {name}: agent table: {e}"))?;
    let was_reactor = agent.get::<mlua::Value>("__on_reactor").ok();
    agent
        .set("__on_reactor", false)
        .map_err(|e| format!("config: {name}: reactor marker: {e}"))?;
    let driven = drive_blocking(lua, name, arguments, on_ask);
    match &was_reactor {
        Some(v) => {
            agent
                .set("__on_reactor", v.clone())
                .map_err(|e| format!("config: {name}: reactor restore: {e}"))?;
        }
        None => {
            let _ = agent.set("__on_reactor", mlua::Value::Nil);
        }
    }
    driven
}

/// The blocking drive loop, factored out so the marker handling above can wrap
/// it. Returns the same `(body, content)` shape as before.
fn drive_blocking(
    lua: &Lua,
    name: &str,
    arguments: &str,
    on_ask: Option<AskHandler>,
) -> Result<Option<(String, String)>, String> {
    let Some((mut run, mut step)) = ToolRun::start(lua, name, arguments)? else {
        return Ok(None);
    };
    loop {
        match step {
            ToolStep::Returned(text) => return Ok(Some((text.clone(), text))),
            ToolStep::Ask { text, always } => {
                let verdict = match &on_ask {
                    Some(h) => verdict_to_lua(lua, &h(&text, always)),
                    // Nobody to ask: a tool must never hang on an orphaned
                    // question, so this is a denial.
                    None => mlua::Value::Boolean(false),
                };
                step = run
                    .answer(verdict)
                    .map_err(|e| format!("config: {name}: {e}"))?;
            }
            ToolStep::Waiting { .. } => {
                step = run
                    .wait()
                    .map_err(|e| format!("config: {name}: {e}"))?;
            }
        }
    }
}

/// An [`AskAnswer`] as the value a yield site receives — the same normalization
/// `agent.api.ask_user` does, so a tool cannot tell which driver answered it:
/// the TUI's loop builds one and hands it to [`ToolRun::answer`], and
/// `invoke_tool_asking` does the same for the blocking driver.
pub fn verdict_to_lua(lua: &Lua, answer: &AskAnswer) -> mlua::Value {
    let table = lua.create_table().expect("verdict table");
    match answer {
        AskAnswer::Allow => mlua::Value::Boolean(true),
        AskAnswer::Deny(reason) => match reason {
            None => mlua::Value::Boolean(false),
            Some(why) => {
                table
                    .set("__agent_verdict", "deny")
                    .and_then(|()| table.set("reason", why.as_str()))
                    .expect("verdict fields");
                mlua::Value::Table(table)
            }
        },
        AskAnswer::AllowAndTrust => {
            table
                .set("__agent_verdict", "allow")
                .and_then(|()| table.set("trust", true))
                .expect("verdict fields");
            mlua::Value::Table(table)
        }
    }
}

/// [`invoke_tool`] on a fresh, thread-safe VM: loads the user configuration
/// (the entry script + any user config), then invokes. Used by the TUI's
/// background tool threads, so the VM lives and dies here — it never crosses
/// threads afterwards (mlua is built without `send`).
///
/// With no ask handler an asking policy auto-denies (see
/// [`invoke_mcp_tool_with_asks`]), so this is the headless entry point.
pub fn invoke_mcp_tool(
    name: &str,
    arguments: &str,
    sink: Option<&PanelSink>,
) -> Result<Option<(String, String)>, String> {
    invoke_mcp_tool_with_asks(name, arguments, sink, None, &user_config())
}

/// [`invoke_mcp_tool`] whose VM carries a user-permission ask handler, so a
/// tool that drives a sandbox can put its policy's questions to the user:
/// `agent.api.ask_user` on that VM calls `on_ask` and blocks for the verdict,
/// exactly as the TUI's tool thread does. The shell's panel-driving wrapper
/// lives in Lua now (`lua/bash_tool.lua`), so *every* tool gets this, not just
/// the shell.
///
/// `Ok(None)` still means "no such tool in `agent.mcps`": the registry is the
/// only place a tool can come from, so the caller has nothing to fall back to.
pub fn invoke_mcp_tool_with_asks(
    name: &str,
    arguments: &str,
    sink: Option<&PanelSink>,
    on_ask: Option<AskHandler>,
    config: &ConfigSource,
) -> Result<Option<(String, String)>, String> {
    let handler = on_ask.clone();
    // `config` is a parameter rather than a guess: a tool invoked on its own
    // should see the same configuration the agent does, but a test asserting on
    // tool behaviour must not depend on whoever is running it.
    let (lua, _) =
        new_vm_with_ask_from(sink, on_ask, config).map_err(|e| format!("config: vm: {e}"))?;
    // The handler goes to the *driver*, not only to the VM: a question the tool
    // raises is a yield the driver answers. It is installed on the VM as well
    // (`agent.api.ask_user`), for the Lua code that asks by calling it directly
    // rather than by yielding — the shell tool's own ask handler, outside a
    // reactor context.
    invoke_tool_asking(&lua, name, arguments, handler)
}
