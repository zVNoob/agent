//! Building a VM: the standard library it loads, the `agent` table, and the
//! ask handler a question reaches.
//!
//! This is the entry half of the namespace — everything a caller needs to get
//! from nothing to a running `agent` — plus the two types the rest of the tree
//! passes around: [`AskAnswer`] (what a handler decided) and [`AskHandler`] (the
//! handler itself). [`SinkSlot`] is the one userdata shell it owns — the panel
//! sink, which [`super::bridge`] fills and [`clear_sink`] empties. The other
//! userdata in the namespace, the sandbox handle, lives with the primitives it
//! wraps, in [`super::sandbox`].
//!
use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use mlua::{AnyUserData, Lua, Table, UserData};

use crate::panels::PanelSink;

use super::bridge::{install_api, load_api_docs, lock_table, verify_api_annotations};
use super::config::{ConfigOrigin, ConfigSource, ensure_config};
use super::tree::{install_require, load_init, load_init_at, load_lib_modules, lua_dir};
use super::usage::install_usage;

/// The standard library every VM is created with.
///
/// The standard library is **available**: mlua's safe subset already carries
/// everything the shipped tree needs — `os`, `io`, `package`, `coroutine`,
/// `string`, `table`, `math` — so config, policies and tools may use it
/// directly rather than shelling out for something `os.getenv` or `io.open`
/// answers. `agent.ask.trust` is the worked example: it resolves and identifies
/// a path with `os.rename` / `io.open` alone, where the alternative is a
/// sandboxed subprocess per question.
///
pub(super) const STDLIB: mlua::StdLib = mlua::StdLib::ALL_SAFE;

/// A fresh LuaJIT VM with the `agent` namespace pre-installed.
/// A VM's panel-sink slot, published into the VM's globals so Rust can reach it
/// again by VM. It carries no methods: the only thing anyone does with it is
/// read and write the slot it holds, which [`install_sink`] and
/// [`clear_sink`] do from Rust.
pub struct SinkSlot(pub(crate) Rc<RefCell<Option<PanelSink>>>);

impl UserData for SinkSlot {}

/// Point `lua`'s panel primitives at `sink` until [`clear_sink`] — the loop
/// installs the current round's sink on its own long-lived config VM before a
/// tool call, and clears it after, so a panel opened outside a round reaches no
/// panel at all (exactly what a VM built with no sink used to do).
pub fn install_sink(lua: &Lua, sink: &PanelSink) -> mlua::Result<()> {
    let any: AnyUserData = lua.globals().get("__agent_sink")?;
    let slot = any.borrow::<SinkSlot>()?;
    *slot.0.borrow_mut() = Some(sink.clone());
    Ok(())
}

/// Drop the VM's panel sink, so panel operations after this go nowhere.
pub fn clear_sink(lua: &Lua) -> mlua::Result<()> {
    let any: AnyUserData = lua.globals().get("__agent_sink")?;
    let slot = any.borrow::<SinkSlot>()?;
    *slot.0.borrow_mut() = None;
    Ok(())
}

pub fn new_vm() -> mlua::Result<Lua> {
    new_vm_with_sink(None)
}

/// The VM the agent binaries run on: its configuration is the user's
/// `~/.config/agent/init.lua`, seeded from the shipped one the first time.
///
/// Returns the VM and where its configuration came from, so startup can say so
/// — a user who has never run the agent before should be told that the file now
/// exists and is theirs, because that is the moment they can edit it.
///
/// Use [`new_vm_with_sink`] for an embedded or test VM instead: this one reads
/// and writes the invoking user's home directory.
pub fn new_agent_vm(sink: Option<&PanelSink>) -> Result<(Lua, ConfigOrigin), String> {
    new_vm_with_ask_from(sink, None, &user_home_config())
}

/// The configuration the *agent* runs on: the user's `~/.config/agent/init.lua`,
/// seeded from the shipped one when it is not there yet.
///
/// Public because "invoke a tool on a VM configured like the agent's" is a real
/// thing a binary may want, and because it is better passed explicitly than
/// inferred: a function that quietly reads the invoking user's home directory is
/// a function whose behaviour depends on who is running it.
pub fn user_config() -> ConfigSource {
    user_home_config()
}

/// The configuration the *agent* runs on: the user's `~/.config/agent/init.lua`,
/// seeded from the shipped one when it is not there yet.
fn user_home_config() -> ConfigSource {
    ConfigSource::UserHome(std::env::var_os("HOME").map(std::path::PathBuf::from))
}

pub(super) fn new_vm_with_ask_from(
    sink: Option<&PanelSink>,
    on_ask: Option<AskHandler>,
    config: &ConfigSource,
) -> Result<(Lua, ConfigOrigin), String> {
    let tree = lua_dir();
    let origin = match config {
        ConfigSource::Tree => ConfigOrigin::Tree,
        ConfigSource::UserHome(home) => ensure_config(&tree, home.as_deref()).1,
    };
    let lua = Lua::new_with(STDLIB, mlua::LuaOptions::default())
        .map_err(|e| format!("lua: {e}"))?;
    setup_tree(&lua, sink, on_ask, &tree, config).map_err(|e| e.to_string())?;
    Ok((lua, origin))
}

/// [`new_vm`] with an optional panel sink (see `setup_inner`).
pub fn new_vm_with_sink(sink: Option<&PanelSink>) -> mlua::Result<Lua> {
    new_vm_with_ask(sink, None)
}

/// [`new_vm_with_sink`] plus the user-permission ask handler that
/// `agent.api.ask_user` calls: this is what makes a *tool* (a registered
/// `agent.mcps` entry, run as a coroutine on this VM by
/// [`invoke_mcp_tool_with_asks`]) able to put a question to the user. Without
/// one the primitive auto-denies, so an asking policy always terminates.
pub fn new_vm_with_ask(
    sink: Option<&PanelSink>,
    on_ask: Option<AskHandler>,
) -> mlua::Result<Lua> {
    let lua = Lua::new_with(STDLIB, mlua::LuaOptions::default())
        .map_err(|e| mlua::Error::external(format!("lua VM: {e}")))?;
    setup_inner(&lua, sink, on_ask)?;
    Ok(lua)
}

/// Run a Lua chunk that may *suspend* on the agent's reactor, and collect its
/// return values — the test-side twin of what the event loop does with a tool
/// call or an event handler.
///
/// The chunk runs in a Lua thread, marked reactor-driven, so `agent.on_timeout`
/// (and the stream transports' own cadence waits) *suspend* rather than sleep
/// the thread. Each suspension is answered here with a real `tokio` sleep, which
/// is what lets a request's task — now a task on that same single-threaded
/// reactor, not a transport thread — actually make progress. A test that polls a
/// stream this way is therefore testing the shipped path, not a threaded
/// approximation of it.
#[cfg(test)]
pub(crate) async fn eval_reactor<T: mlua::FromLuaMulti>(
    lua: &Lua,
    chunk: &str,
) -> mlua::Result<T> {
    let agent: Table = lua.globals().get("agent")?;
    agent.set("__on_reactor", true)?;
    let thread = lua.load(chunk).into_function()?;
    let thread = lua.create_thread(thread)?;
    // Bounded, so a chunk that never finishes fails the test instead of hanging it.
    for _ in 0..100_000 {
        let out: mlua::MultiValue = thread.resume(())?;
        match thread.status() {
            mlua::thread::ThreadStatus::Resumable => {
                let ms: i64 = out
                    .iter()
                    .next()
                    .and_then(|v| v.as_table())
                    .and_then(|t| t.get::<mlua::Value>("ms").ok())
                    .and_then(|v| match v {
                        mlua::Value::Integer(n) => Some(n),
                        _ => None,
                    })
                    .unwrap_or(0);
                if ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(ms as u64)).await;
                } else {
                    tokio::task::yield_now().await;
                }
            }
            // The coroutine is done: hand its return values back the way
            // `Function::eval` would, so a caller's `let (a, b): (A, B) = …`
            // still works.
            _ => {
                return <T as mlua::FromLuaMulti>::from_lua_multi(out, lua);
            }
        }
    }
    Err(mlua::Error::RuntimeError(
        "eval_reactor: the chunk never finished".into(),
    ))
}

/// The answer to a user-permission ask. An ask is a yielded user-asking call
/// resumed with its verdict — either a bare boolean or an [`AskAnswer`], which
/// additionally carries a reason. `Deny(Some(reason))` lands exactly like a
/// policy's `agent.deny(reason)`: `denied_reason` on the outcome, `Denied:
/// <reason>` on the panel status line, and `denied_reason` in the tool JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskAnswer {
    /// The frozen syscall runs normally.
    Allow,
    /// The syscall runs, *and the path is remembered*: the "always allow this"
    /// answer. It travels with the ask rather than as a side effect, because the
    /// handler is handed the question as text and has no path to record — the
    /// asking side does, and `agent.ask` puts it in its trust table (so the same
    /// path is not asked about again in this run).
    AllowAndTrust,
    /// The syscall is denied; the optional string names why.
    Deny(Option<String>),
}

/// An ask handler: given the formatted ask text, produce the verdict —
/// allow, or deny with an optional reason (see [`AskAnswer`]).
///
/// A VM created by [`new_vm_with_ask`] carries one, and `agent.api.ask_user` on
/// that VM calls it: the tool thread forwards the question to the TUI's event
/// loop, blocks while the user answers, and returns the verdict, which the
/// sandbox delivers to the asking thread. The handler is also told whether the
/// question may be answered with "always" — Lua's call, passed as
/// `agent.api.ask_user(text, always)`: only a question carrying something to
/// remember (a path) offers the third answer, so a plain yes/no question is
/// never handed an "always" the asking side has nowhere to put. The Lua side is
/// `lua/bash_tool.lua`'s ask handler, so every tool that drives a sandbox can
/// ask — where before only the shell could.
/// The handler a question reaches: given the text and whether `[a]lways` is on
/// offer, the user's answer. A shared `Rc` because two things need it — the VM's
/// `agent.api.ask_user` and the [`ToolRun`] driver — and they must be the *same*
/// handler, or a tool would be answered by whichever one happened to be bound.
/// `Rc`, not `Arc`: a question is asked and answered on the one thread driving
/// the tool, so it never crosses a thread and need not be `Send`.
pub type AskHandler = std::rc::Rc<dyn Fn(&str, bool) -> AskAnswer + 'static>;


/// Install the `agent` namespace into `lua` (globals table `agent` plus the
/// Lua driver primitives), then load the shipped `lua/` tree: every
/// `lua/lib/**.lua` module and the `lua/init.lua` entry script. No panel sink:
/// `agent.api.panel_*` are no-ops.
pub fn setup(lua: &Lua) -> mlua::Result<()> {
    setup_inner(lua, None, None)
}

/// [`setup`] with an optional panel sink, so `agent.api.panel_*` emissions from
/// policy/tool Lua are buffered for the TUI to apply (headless: `None`).
fn setup_inner(lua: &Lua, sink: Option<&PanelSink>, on_ask: Option<AskHandler>) -> mlua::Result<()> {
    setup_tree(lua, sink, on_ask, &lua_dir(), &ConfigSource::default())
}

/// [`setup_inner`] against an explicit `lua/` tree instead of the resolved
/// one — the seam the loader tests drive fixture trees through.
pub(super) fn setup_tree(
    lua: &Lua,
    sink: Option<&PanelSink>,
    on_ask: Option<AskHandler>,
    dir: &Path,
    config: &ConfigSource,
) -> mlua::Result<()> {
    // The bridge first: every primitive in one locked table, so the entry
    // script and the lib modules can call them while they load.
    let api = install_api(lua, sink, on_ask)?;
    let agent = lua.create_table()?;
    agent.set("api", lock_table(lua, api.clone(), "api")?)?;
    lua.globals().set("agent", agent)?;
    install_require(lua, dir)?;
    load_lib_modules(lua, dir)?;
    // The settings table, created empty, before any configuration runs.
    //
    // A configuration assigns *fields* of it and never the table itself, and it
    // has to be able to: the user's `~/.config/agent/init.lua` may be three
    // lines long, and a file that cannot set `agent.llm.base_url` without
    // first inventing the table is not a configuration. Every field defaults
    // independently on the Rust side (`llm_config`, `memory_config`), so an
    // absent key means "the default", and the starter config can still spell
    // every value out where a user would go to change it.
    {
        let agent: Table = lua.globals().get("agent")?;
        let existing: mlua::Value = agent.get("llm")?;
        if !matches!(existing, mlua::Value::Table(_)) {
            agent.set("llm", lua.create_table()?)?;
        }
    }
    // The bridge's annotations, required by the *loader* rather than by the
    // configuration script. The drift check below is a statement about the
    // bridge, so it cannot depend on a file the user is invited to edit: making
    // `agent.api_docs` the configuration's job meant that deleting one line from
    // your own config stopped the agent with a message about a missing require.
    load_api_docs(lua)?;
    // The configuration script: the user's, seeded from the tree's on first run
    // (see `ConfigSource`). Exactly one script runs — the user's file is not an
    // overlay on top of the shipped one, it *is* the configuration.
    match config {
        ConfigSource::Tree => load_init(lua, dir)?,
        ConfigSource::UserHome(home) => {
            let (path, _) = ensure_config(dir, home.as_deref());
            load_init_at(lua, &path)?;
        }
    }
    // The read-only token counters of the most recent request, seeded from the
    // process-wide snapshot so *every* VM agrees (see `record_usage`). They live
    // inside `agent.llm`, which is why this runs after the entry script created
    // it.
    install_usage(lua)?;
    // The annotations were loaded above; they and the bridge must not drift
    // apart.
    verify_api_annotations(lua, &api)?;
    Ok(())
}

/// An engine failure as a Lua error, flattening the `anyhow` context chain
/// into the message (`{e:#}`) — a policy sees the whole cause, not its last
/// line.
pub(super) fn err_to_mlua(e: anyhow::Error) -> mlua::Error {
    mlua::Error::RuntimeError(format!("{e:#}"))
}
