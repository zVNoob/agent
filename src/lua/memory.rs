//! `agent.memory.*` — the read side of the conversation log.
//!
//! One [`Memory`](crate::memory::Memory) is opened by the loop at startup and
//! bound here, so the write side (what the loop archives) and the read side
//! (what Lua compaction asks for) are the same file. Binding is a startup
//! decision and is deliberately not something Lua can call.
//!
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use mlua::{Lua, Table};

use crate::memory::Memory;

use super::bridge::opts_bool;

// ---------------------------------------------------------------------------
// Conversation log (`agent.memory`): the save-to-disk side of the agent.
// One `crate::memory::Memory` is opened by the TUI (or probe) at startup and
// shared behind a process-wide mutex; the loop archives every history message
// through [`memory_append_many`] (a watermark — each message exactly once),
// flushes at turn boundaries and on exit, and Lua reaches the same store via
// the `agent.memory` primitives in `lua/init.lua`.
// ---------------------------------------------------------------------------

pub(super) static MEMORY: OnceLock<Arc<Mutex<Memory>>> = OnceLock::new();

/// Bind the process-wide conversation log (see `MEMORY`). Returns `None`
/// when already bound. Like the trigger channel, this is a startup decision:
/// `/reload` re-reads the user config but cannot rebind the store.
pub fn bind_memory(mem: Arc<Mutex<Memory>>) -> Option<()> {
    MEMORY.set(mem).ok()
}

/// Whether a conversation log is open. The loop checks this before archiving,
/// so a disabled store costs nothing and logs nothing.
pub fn memory_is_bound() -> bool {
    MEMORY.get().is_some()
}

/// The `agent.llm.memory` settings: whether the conversation log is open at
/// all and where it lives. Defaults: enabled, `~/.config/agent/history.amem`
/// (else `./history.amem` when HOME is unset).
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    /// `false` (`agent.llm.memory.enabled = false`): no log opens, the
    /// loop archives nothing, `agent.memory` actions raise "no log open".
    pub enabled: bool,
    /// Where the append-only log lives (`agent.llm.memory.path`).
    pub path: PathBuf,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig {
            enabled: true,
            path: default_memory_path(),
        }
    }
}

pub(super) fn default_memory_path() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => Path::new(&home)
            .join(".config")
            .join("agent")
            .join("history.amem"),
        None => PathBuf::from("history.amem"),
    }
}

/// Read `agent.llm.memory` from the config VM (fields absent -> defaults).
pub fn memory_config(lua: &Lua) -> Result<MemoryConfig, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("memory config: agent table: {e}"))?;
    let config: Table = agent
        .get("llm")
        .map_err(|e| format!("memory config: agent.llm: {e}"))?;
    let mut cfg = MemoryConfig::default();
    let Ok(t) = config.get::<Table>("memory") else {
        return Ok(cfg); // not configured: defaults
    };
    if let Some(enabled) =
        opts_bool(&t, "enabled").map_err(|e| format!("memory config: enabled: {e}"))?
    {
        cfg.enabled = enabled;
    }
    if let Ok(p) = t.get::<String>("path") {
        cfg.path = PathBuf::from(p);
    }
    Ok(cfg)
}

/// The on-disk location of the open log, when one is bound.
pub fn memory_path() -> Option<PathBuf> {
    MEMORY
        .get()
        .map(|m| m.lock().map(|g| g.path().to_path_buf()).unwrap_or_default())
}

/// Append one JSON message (a string) to the conversation log; returns the
/// message's sequence number. Raises when no log is open or the append fails.
pub fn memory_append(json: &str) -> Result<u64, String> {
    let mut mem = MEMORY
        .get()
        .ok_or_else(|| "agent.memory: no log open (agent.llm.memory?)".to_string())?
        .lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?;
    mem.append(json)
        .map_err(|e| format!("agent.memory: append: {e}"))
}

/// Append several history messages in one lock — the loop's watermark
/// archive. The values are already JSON (they came from the history), so this
/// is a pure serialize-and-append. Returns the last appended sequence.
pub fn memory_append_many(messages: &[serde_json::Value]) -> Result<u64, String> {
    let mut mem = MEMORY
        .get()
        .ok_or_else(|| "agent.memory: no log open (agent.llm.memory?)".to_string())?
        .lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?;
    let mut seq = 0;
    for m in messages {
        let text = serde_json::to_string(m).map_err(|e| format!("agent.memory: encode: {e}"))?;
        seq = mem
            .append(&text)
            .map_err(|e| format!("agent.memory: append: {e}"))?;
    }
    Ok(seq)
}

/// The newest `n` messages as JSON lines (oldest → newest).
pub fn memory_latest(n: usize) -> Result<Vec<String>, String> {
    let mut mem = MEMORY
        .get()
        .ok_or_else(|| "agent.memory: no log open (agent.llm.memory?)".to_string())?
        .lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?;
    mem.latest(n)
        .map_err(|e| format!("agent.memory: latest: {e}"))
}

/// Seal buffered messages into the on-disk log now (group commit). With no
/// open log this is a no-op (`Ok(())`), so exit paths need not branch.
pub fn memory_flush() -> Result<(), String> {
    let Some(mem) = MEMORY.get() else {
        return Ok(());
    };
    let mut mem = mem
        .lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?;
    mem.flush().map_err(|e| format!("agent.memory: flush: {e}"))
}

/// `agent.api.memory_path() -> string | nil` — the open log's location; `nil`
/// when none is open (disabled or unbound). Informational, so it returns nil
/// rather than raising like the actions do.
pub(super) fn lua_memory_path(_: &Lua, (): ()) -> mlua::Result<Option<String>> {
    Ok(memory_path().map(|p| p.display().to_string()))
}

/// `agent.api.memory_append(message) -> seq` — `message` is a JSON string or a
/// table (encoded automatically, so history messages round-trip as written).
pub(super) fn lua_memory_append(_: &Lua, msg: mlua::Value) -> mlua::Result<u64> {
    let text = match msg {
        mlua::Value::String(s) => s.to_str()?.to_string(),
        other => {
            let json = crate::mcp::lua_to_json( &other).map_err(|e| {
                mlua::Error::RuntimeError(format!("agent.memory.append: encode: {e}"))
            })?;
            serde_json::to_string(&json).map_err(|e| {
                mlua::Error::RuntimeError(format!("agent.memory.append: encode: {e}"))
            })?
        }
    };
    memory_append(&text).map_err(mlua::Error::RuntimeError)
}

/// `agent.api.memory_latest(n) -> array` — the newest `n` messages, JSON strings.
pub(super) fn lua_memory_latest(lua: &Lua, n: usize) -> mlua::Result<Table> {
    let msgs = memory_latest(n).map_err(mlua::Error::RuntimeError)?;
    let t = lua.create_table()?;
    for (i, m) in msgs.iter().enumerate() {
        t.set(i + 1, m.clone())?;
    }
    Ok(t)
}

/// `agent.api.memory_flush() -> true` — seal buffered messages to disk now.
pub(super) fn lua_memory_flush(_: &Lua, (): ()) -> mlua::Result<bool> {
    memory_flush().map_err(mlua::Error::RuntimeError)?;
    Ok(true)
}
