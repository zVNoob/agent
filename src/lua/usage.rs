//! `agent.llm.usage` — the read-only token counts of the most recent request.
//!
//! A process-wide snapshot rather than a field on the config VM, because the
//! turn is finished and about to be archived on one side while a
//! `turn_completed` handler reads it on the other. The section banner below
//! spells out why that is the shape it is.
//!
use std::sync::OnceLock;

use mlua::{Lua, Table};

use super::bridge::lock_table;

// ---------------------------------------------------------------------------
// Token usage: `agent.llm.usage`, read-only, refreshed after every request.
//
// The counts the server reported for the **most recent** request — nothing
// cumulative, so a compaction shrinks what the next turn reports. Servers
// differ in how they say it: an OpenAI-compatible `usage` block
// (`prompt_tokens` / `completion_tokens`), or llama.cpp's `timings`
// (`prompt_n` / `predicted_n`), which this also reads. A server that reports
// neither leaves `reported = false` and the counts at zero — "unknown", never a
// stale number from an earlier turn or a zero that reads as "free".
//
// It sits beside the endpoint and the system prompt rather than beside the
// tools, because it *describes the request* — what the model was sent and what
// it cost — where `agent.mcps` describes what it could do.
//
// Why a process-wide snapshot rather than a field on the config VM: a value
// written on the main thread's VM would be invisible to the VMs that actually
// run Lua — a tool call, a `turn_completed` handler — because each gets a fresh
// one. The numbers are plain `Copy` data, so a snapshot every VM can be seeded
// from is both simpler and more honest: Lua sees the count as of its own VM's
// creation.
// ---------------------------------------------------------------------------

/// The prompt/completion token counts of one request, as the server reported
/// them. `None` on either side means the server did not say.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub prompt: Option<u64>,
    pub completion: Option<u64>,
}

impl Usage {
    /// Prompt + completion over the halves the server *did* report; `None` when
    /// it reported neither.
    pub fn total(&self) -> Option<u64> {
        match (self.prompt, self.completion) {
            (None, None) => None,
            (p, c) => Some(p.unwrap_or(0) + c.unwrap_or(0)),
        }
    }
}

pub(super) static LAST_USAGE: OnceLock<std::sync::Mutex<Usage>> = OnceLock::new();

pub(super) fn last_usage() -> Usage {
    LAST_USAGE
        .get()
        .and_then(|m| m.lock().ok().map(|g| *g))
        .unwrap_or_default()
}

/// Serialize the tests that read or write the process-wide usage snapshot, and
/// clear it. The snapshot is process-wide by design — that is how a tool VM and
/// the config VM agree on the counts — so tests that assert on it would
/// otherwise race each other through the shared state.
#[cfg(test)]
pub(super) fn usage_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(slot) = LAST_USAGE.get()
        && let Ok(mut usage) = slot.lock()
    {
        *usage = Usage::default();
    }
    guard
}

/// Record the counts of a finished request: every VM created from here on sees
/// them, and the config VM's own `agent.llm.usage` is refreshed in place.
pub fn record_usage(lua: &Lua, usage: Usage) {
    let slot = LAST_USAGE.get_or_init(|| std::sync::Mutex::new(Usage::default()));
    if let Ok(mut guard) = slot.lock() {
        *guard = usage;
    }
    if let Some(t) = usage_backing(lua) {
        let _ = write_usage(&t, usage);
        return;
    }
    // Missing or not the locked proxy: a config that replaced `agent.llm` (or
    // the `usage` key in it) dropped it. Put a locked table back rather than
    // leave Lua holding a writable one — or none at all.
    let _ = install_usage(lua);
}

pub(super) fn usage_backing(lua: &Lua) -> Option<Table> {
    let proxy = lua
        .globals()
        .get::<Table>("agent")
        .ok()?
        .get::<Table>("llm")
        .ok()?
        .get::<Table>("usage")
        .ok()?;
    let mt = proxy.metatable()?;
    let real = mt.get::<Table>("__index").ok()?;
    // Only trust our own proxy: a plain table with an `__index` of another
    // shape is not the read-only view.
    if mt.get::<mlua::Value>("__newindex").is_ok() {
        Some(real)
    } else {
        None
    }
}

/// Attach the read-only usage view to `agent.llm`, if the configuration declared
/// one.
///
/// Runs *after* the configuration, and deliberately does not create `agent.llm` to
/// have somewhere to put it: `agent.llm` is a convention the configuration owns, and
/// a config that never mentions it cannot read `agent.llm.usage` either — naming the
/// field is what creates the table, by assignment. So a config that says nothing
/// about the model gets no usage view, which is consistent rather than lossy.
pub(super) fn install_usage(lua: &Lua) -> mlua::Result<()> {
    let Ok(agent) = lua.globals().get::<Table>("agent") else {
        return Ok(());
    };
    let Ok(llm) = agent.get::<Table>("llm") else {
        return Ok(());
    };
    llm.set("usage", usage_proxy(lua, last_usage())?)
}

pub(super) fn write_usage(t: &Table, usage: Usage) -> mlua::Result<()> {
    t.set("prompt", usage.prompt.unwrap_or(0))?;
    t.set("completion", usage.completion.unwrap_or(0))?;
    t.set("total", usage.total().unwrap_or(0))?;
    t.set("reported", usage.total().is_some())?;
    Ok(())
}

pub(super) fn usage_proxy(lua: &Lua, usage: Usage) -> mlua::Result<Table> {
    let real = lua.create_table()?;
    write_usage(&real, usage)?;
    lock_table(lua, real, "llm.usage")
}
