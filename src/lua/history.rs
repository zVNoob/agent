//! The conversation history, owned by Lua.
//!
//! `agent.history` is the current conversation — every message from the
//! compaction point on — and `agent.api.history_append(message)` is the one
//! way a new message joins it. The primitive appends to the table *and*
//! archives the message to the conversation log, in that order, so a message
//! cannot be in one and missing from the other: the log first (it is what a
//! resumed session is seeded from — the reverse order would lose a message
//! on a crash between the two), then the table. With no log open — memory
//! disabled — the table is still the conversation and only the archive is
//! skipped.
//!
//! The stored message is the JSON round trip of what was passed in, so what a
//! request reads back is exactly what the log holds: messages are data, and
//! the normalization is what keeps one shape on the wire, in the table, and on
//! disk.
//!
//! Rust seeds the table once, from the cold-start replay ([`seed_history`]),
//! and after that only the log's flush and the table's *existence* are Rust's
//! business. The turn handler reads the table to build requests, appends to it
//! as turns produce messages, and compacts it by plain assignment
//! (`agent.history = { summary, … }`) — which is why the write side of
//! compaction is no longer a call into Rust. The loop knows nothing about the
//! conversation: it fires events, runs tools, and draws.

use mlua::{Lua, Table, Value};

/// The `agent.history` table — an array of message tables, oldest first.
fn history_table(lua: &Lua) -> mlua::Result<Table> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| mlua::Error::RuntimeError(format!("agent.history: {e}")))?;
    agent
        .get("history")
        .map_err(|e| mlua::Error::RuntimeError(format!("agent.history: {e}")))
}

/// Fill `agent.history` with the cold-start replay's messages, oldest first.
///
/// Once per process, right after the replay is read: the messages earlier
/// sessions archived are already in the log, so this is a *table*, not an
/// archive — and a session that never turns is a table nothing appends to.
/// Replaces whatever is in the table (a fresh process has an empty one) and
/// returns how many messages the conversation resumed with.
pub fn seed_history(lua: &Lua, messages: &[serde_json::Value]) -> Result<usize, String> {
    let table = history_table(lua).map_err(|e| e.to_string())?;
    // Whatever is in the table is replaced: a fresh process has an empty one,
    // and a stale entry must not survive into the resumed conversation.
    for i in 1..=table.raw_len() {
        table
            .raw_set(i, Value::Nil)
            .map_err(|e| format!("agent.history: seed: {e}"))?;
    }
    for (i, m) in messages.iter().enumerate() {
        let value =
            crate::mcp::json_to_lua(lua, m).map_err(|e| format!("agent.history: seed: {e}"))?;
        table
            .raw_set(i + 1, value)
            .map_err(|e| format!("agent.history: seed: {e}"))?;
    }
    Ok(messages.len())
}

/// `agent.api.history_append(message) -> seq` — add one message to the
/// conversation and to the log. `message` is a table (encoded automatically,
/// so it round-trips as written) or a JSON string.
pub(super) fn lua_history_append(lua: &Lua, msg: Value) -> mlua::Result<u64> {
    let json = match msg {
        Value::String(s) => serde_json::from_str::<serde_json::Value>(&s.to_str()?)
            .map_err(|e| mlua::Error::RuntimeError(format!("agent.history.append: {e}")))?,
        other => crate::mcp::lua_to_json(&other)
            .map_err(|e| mlua::Error::RuntimeError(format!("agent.history.append: encode: {e}")))?,
    };
    let text = serde_json::to_string(&json)
        .map_err(|e| mlua::Error::RuntimeError(format!("agent.history.append: encode: {e}")))?;
    // The log first: a resumed session is seeded from it, so an archive that
    // failed must not leave a message that only the live table knows about.
    let seq = if super::memory::memory_is_bound() {
        super::memory::memory_append(&text).map_err(mlua::Error::RuntimeError)?
    } else {
        0
    };
    let table = history_table(lua)?;
    let len = table.raw_len();
    table
        .set(
            len + 1,
            crate::mcp::json_to_lua(lua, &json)
                .map_err(|e| mlua::Error::RuntimeError(format!("agent.history.append: {e}")))?,
        )
        .map_err(|e| mlua::Error::RuntimeError(format!("agent.history.append: {e}")))?;
    Ok(seq)
}
