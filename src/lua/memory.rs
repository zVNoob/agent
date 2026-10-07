//! `agent.memory.*` — the read side of the conversation log.
//!
//! One [`Memory`](crate::memory::Memory) is opened by the loop at startup and
//! bound here, so the write side (what the loop archives) and the read side
//! (what Lua compaction asks for) are the same file. Binding is a startup
//! decision and is deliberately not something Lua can call.
//!
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

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

pub(super) static MEMORY: OnceLock<RwLock<Option<Arc<Mutex<Memory>>>>> = OnceLock::new();

/// The current log, cloned out from under the registry lock so no caller holds
/// it across the `Memory`'s own mutex.
///
/// [`bind_memory`] is the *first* one and is a startup decision ([`MEMORY`] is
/// rebindable now, but binding on top of an open log is still refused — see
/// [`memory_new`] for starting a fresh one). Every reader goes through this, so
/// the answer to "is a log open" is one place.
fn current() -> Result<Arc<Mutex<Memory>>, String> {
    MEMORY
        .get()
        .and_then(|g| g.read().ok()?.clone())
        .ok_or_else(|| "agent.memory: no log open (agent.llm.memory?)".to_string())
}

/// Bind the process-wide conversation log (see `MEMORY`). Returns `None`
/// when already bound. Like the trigger channel, this is a startup decision:
/// `/reload` re-reads the user config but cannot rebind the store.
///
/// Refusing to rebind is the *point*: two writers to one archive would
/// interleave, and nothing downstream could tell them apart. A fresh log is a
/// different verb and has its own entry — [`memory_new`].
pub fn bind_memory(mem: Arc<Mutex<Memory>>) -> Option<()> {
    let global = MEMORY.get_or_init(|| RwLock::new(None));
    let mut slot = global.write().ok()?;
    if slot.is_some() {
        return None;
    }
    *slot = Some(mem);
    Some(())
}

/// Whether a conversation log is open. The loop checks this before archiving,
/// so a disabled store costs nothing and logs nothing.
pub fn memory_is_bound() -> bool {
    current().is_ok()
}

/// Start a new conversation log: flush and close the current one, move it aside,
/// and open a fresh file where it was.
///
/// The rotation keeps the old scrollback on disk next to the active file
/// (`<old>.amem` -> `<old>-<YYYYMMDD-HHMMSS>.amem`), so a session boundary is a
/// file boundary and a session is always its own archive. The active path stays
/// `agent.llm.memory.path`, so the next request reads the same convention it
/// always did.
///
/// Returns the path the old log moved to. Raises when the new file cannot be
/// opened — the old one is flushed and closed first either way, because a
/// session that cannot start fresh is worse off open-ended.
pub fn memory_new() -> Result<PathBuf, String> {
    let global = MEMORY.get_or_init(|| RwLock::new(None));
    let old = current()?;
    let old_path = old
        .lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?
        .path()
        .to_path_buf();
    let rotated = rotated_path(&old_path);

    // Close the old one first: `close` flushes (`crate::memory::Memory::close`), so
    // nothing it buffered is lost when the file moves. Rename, then open fresh —
    // order matters, because a rename of a file that is still being written is how
    // a log ends up split in two.
    old.lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?
        .close()
        .map_err(|e| format!("agent.memory: close old log: {e}"))?;
    std::fs::rename(&old_path, &rotated)
        .map_err(|e| format!("agent.memory: move old log aside: {e}"))?;
    let fresh = Memory::open(&old_path).map_err(|e| format!("agent.memory: open new log: {e}"))?;

    let mut slot = global
        .write()
        .map_err(|_| "agent.memory: registry lock poisoned".to_string())?;
    *slot = Some(Arc::new(Mutex::new(fresh)));
    Ok(rotated)
}

/// `<old>.amem` -> `<old>-<YYYYMMDD-HHMMSS>.amem`, in the same directory.
fn rotated_path(old: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let stem = old
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "history".to_string());
    old.with_file_name(format!("{stem}-{stamp}.amem"))
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
    // `agent.llm` is a convention Rust reads and never creates, so its absence is a
    // config that enabled nothing rather than a broken one. Defaults either way.
    let mut cfg = MemoryConfig::default();
    let Ok(llm) = agent.get::<Table>("llm") else {
        return Ok(cfg); // not configured: defaults
    };
    let Ok(t) = llm.get::<Table>("memory") else {
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
    current()
        .ok()
        .map(|m| m.lock().map(|g| g.path().to_path_buf()).unwrap_or_default())
}

/// Append one JSON message (a string) to the conversation log; returns the
/// message's sequence number. Raises when no log is open or the append fails.
pub fn memory_append(json: &str) -> Result<u64, String> {
    let mem = current()?;
    let mut mem = mem
        .lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?;
    mem.append(json)
        .map_err(|e| format!("agent.memory: append: {e}"))
}

/// Append several history messages in one lock — the loop's watermark
/// archive. The values are already JSON (they came from the history), so this
/// is a pure serialize-and-append. Returns the last appended sequence.
pub fn memory_append_many(messages: &[serde_json::Value]) -> Result<u64, String> {
    let mem = current()?;
    let mut mem = mem
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
    let mem = current()?;
    let mut mem = mem
        .lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?;
    mem.latest(n)
        .map_err(|e| format!("agent.memory: latest: {e}"))
}

/// Seal buffered messages into the on-disk log now (group commit). With no
/// open log this is a no-op (`Ok(())`), so exit paths need not branch.
pub fn memory_flush() -> Result<(), String> {
    let Ok(mem) = current() else {
        return Ok(());
    };
    mem.lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?
        .flush()
        .map_err(|e| format!("agent.memory: flush: {e}"))
}

/// `agent.api.memory_path() -> string | nil` — the open log's location; `nil`
/// when none is open (disabled or unbound). Informational, so it returns nil
/// rather than raising like the actions do.
pub(super) fn lua_memory_path(_: &Lua, (): ()) -> mlua::Result<Option<String>> {
    Ok(memory_path().map(|p| p.display().to_string()))
}

/// `agent.api.memory_new() -> rotated_path` — start a new conversation log:
/// flush and close the current one, move it aside, open a fresh file where it
/// was. Returns where the old log went.
pub(super) fn lua_memory_new(_: &Lua, (): ()) -> mlua::Result<String> {
    memory_new()
        .map(|p| p.display().to_string())
        .map_err(mlua::Error::RuntimeError)
}

/// `agent.api.memory_append(message) -> seq` — `message` is a JSON string or a
/// table (encoded automatically, so history messages round-trip as written).
pub(super) fn lua_memory_append(_: &Lua, msg: mlua::Value) -> mlua::Result<u64> {
    let text = match msg {
        mlua::Value::String(s) => s.to_str()?.to_string(),
        other => {
            let json = crate::mcp::lua_to_json(&other).map_err(|e| {
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
