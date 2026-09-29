//! Tool calls and event handlers as coroutines the loop steps.
//!
//! Both are the same shape — a Lua thread Rust owns, resumed until it yields a
//! question, a wait, or its return value — so they share one file: [`ToolRun`]
//! for a call into `agent.mcps`, [`EventRun`] for a `turn_completed` handler,
//! and [`AgentCommand`] for the input edits and forced turns a handler asks the
//! loop for on the way.
//!
use std::sync::RwLock;

#[cfg(test)]
use std::cell::RefCell;

use mlua::{Lua, Table};
use tokio::sync::mpsc;

use crate::panels::{Remember, remember_label};

use super::config::split_qualified;
use super::vm::{AskAnswer, AskHandler};

// ---------------------------------------------------------------------------
// A tool call, driven cooperatively on the agent's single reactor thread
// ---------------------------------------------------------------------------

/// One step of a reactor-driven tool call coroutine ([`ToolRun`]).
#[derive(Debug, Clone, PartialEq)]
pub enum ToolStep {
    /// The tool asked the user a question. `text` is what the prompt shows and
    /// `remember` is what its third answer is called, if it has one — Lua's
    /// `always`, normalised by [`remember_label`] so a grant narrower than
    /// "always" keeps its own name. Resume with the verdict (see
    /// [`ToolRun::answer`]).
    Ask { text: String, remember: Remember },
    /// The tool suspended on a reactor wait: an `agent.on_timeout` inside the
    /// tool, or the sandbox's own cooperative cadence between idle steps (the
    /// drive loop in `lua/lib/bash.lua` yields one every time `agent.api.step`
    /// has nothing ready). Resume after `ms` — nothing is delivered to the
    /// yield site.
    Waiting { ms: u64 },
    /// The tool returned: its result value, already encoded as the MCP JSON
    /// text that becomes the tool result in the conversation.
    Returned(String),
}

/// A tool call driven **cooperatively** on the agent's single reactor thread,
/// on the agent's own configuration VM — the same [`EventRun`] shape, for the
/// other kind of Lua code that used to get a thread of its own.
///
/// Two things follow from running on that VM rather than a throwaway one. State
/// a tool writes is still there next call: a path trusted with `[a]lways` is
/// remembered, a mode a tool switches persists, a counter a tool increments
/// accumulates. And there is no second VM to build, so the config is parsed
/// once per process instead of once per tool call.
///
/// The coroutine is what makes a *question* possible at all: a tool callback is
/// reached across the mlua boundary, where `coroutine.yield` cannot cross, so
/// the callback runs in a Lua thread that this type owns and steps. The VM is
/// marked reactor-driven, so a sandbox run inside the tool yields its cadence
/// ([`ToolStep::Waiting`]) instead of blocking the loop in `agent.api.step`.
pub struct ToolRun<'lua> {
    lua: &'lua Lua,
    thread: mlua::Thread,
    name: String,
}

impl<'lua> ToolRun<'lua> {
    /// Begin the named tool from `agent.mcps` on `lua`, with `arguments` as its
    /// single argument. `Ok(None)` when the registry holds no such tool — the
    /// registry is the only place a tool can come from, so there is nothing to
    /// fall back to.
    pub fn start(
        lua: &'lua Lua,
        name: &str,
        arguments: &str,
    ) -> Result<Option<(ToolRun<'lua>, ToolStep)>, String> {
        let Some(call) = lookup_tool(lua, name)? else {
            return Ok(None);
        };
        let args_json: serde_json::Value = serde_json::from_str(arguments)
            .map_err(|e| format!("config: {name}: bad arguments JSON: {e}"))?;
        let args_lua = crate::mcp::json_to_lua(lua, &args_json)
            .map_err(|e| format!("config: {name}: arguments decode: {e}"))?;
        // Same marker `EventRun::start` sets: on this VM `agent.on_timeout` and
        // the sandbox pump suspend for the reactor instead of sleeping a thread.
        let agent: Table = lua
            .globals()
            .get("agent")
            .map_err(|e| format!("config: {name}: agent table: {e}"))?;
        agent
            .set("__on_reactor", true)
            .map_err(|e| format!("config: {name}: reactor marker: {e}"))?;
        let thread = lua
            .create_thread(call)
            .map_err(|e| format!("config: {name}: coroutine: {e}"))?;
        let mut run = ToolRun {
            lua,
            thread,
            name: name.to_string(),
        };
        let step = run
            .resume_with(Some(args_lua))
            .map_err(|e| format!("config: {name}: {e}"))?;
        Ok(Some((run, step)))
    }

    /// Answer the question from the last [`ToolStep::Ask`]. `verdict` is what
    /// `agent.api.ask_user` would have returned: `true`, `false`, or a denial
    /// table carrying a reason. It is delivered to the yield site, so the asking
    /// code resumes exactly as a plain `yes` would have.
    pub fn answer(&mut self, verdict: mlua::Value) -> Result<ToolStep, String> {
        self.resume_with(Some(verdict))
    }

    /// Resume a [`ToolStep::Waiting`] wait. Nothing lands at the yield site, so
    /// this takes no value.
    pub fn wait(&mut self) -> Result<ToolStep, String> {
        self.resume_with(None)
    }

    /// The VM the tool runs on — the agent's own config VM, borrowed for as
    /// long as the call lasts.
    pub fn lua(&self) -> &Lua {
        self.lua
    }

    /// The tool's name, for error messages.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// One resume: the first lands `arg` as the callback's argument, later ones
    /// at the value of the last `coroutine.yield`.
    fn resume_with(&mut self, arg: Option<mlua::Value>) -> Result<ToolStep, String> {
        let res: mlua::Value = self
            .thread
            .resume(arg)
            .map_err(|e| format!("config: {}: {e}", self.name))?;
        match self.thread.status() {
            mlua::thread::ThreadStatus::Resumable => decode_tool_ask(res),
            // Dead: the values are the callback's returns, and a tool returns
            // the one result value the MCP shape defines.
            _ => {
                let json = crate::mcp::lua_to_json(&res)
                    .map_err(|e| format!("config: {}: result encode: {e}", self.name))?;
                let text = serde_json::to_string(&json)
                    .map_err(|e| format!("config: {}: {e}", self.name))?;
                Ok(ToolStep::Returned(text))
            }
        }
    }
}

pub(super) fn decode_tool_ask(yielded: mlua::Value) -> Result<ToolStep, String> {
    if let mlua::Value::Table(t) = &yielded {
        if let Ok(Some(tag)) = t.get::<Option<String>>("__agent_await") {
            return match tag.as_str() {
                "timeout" => {
                    let ms: i64 = t
                        .get("ms")
                        .map_err(|e| format!("tool: await timeout ms: {e}"))?;
                    Ok(ToolStep::Waiting {
                        ms: ms.max(0) as u64,
                    })
                }
                other => Err(format!("tool: unknown await request {other:?}")),
            };
        }
        // An ask table: `description` names the question, `always` says what the
        // prompt's third answer is called (`true` for the plain `lways`, a
        // string for a grant with a narrower life). Both are optional, because
        // a hand-built ask may carry neither.
        let text = match t.get::<mlua::Value>("description") {
            Ok(mlua::Value::String(s)) => s.to_string_lossy().to_string(),
            Ok(mlua::Value::Nil) | Err(_) => String::new(),
            Ok(other) => other
                .to_string()
                .map_err(|e| format!("tool: ask description: {e}"))?,
        };
        let remember = match t.get::<mlua::Value>("always") {
            Ok(v) => remember_label(&v),
            Err(_) => None,
        };
        return Ok(ToolStep::Ask { text, remember });
    }
    // A bare string is the other ask shape: the question, with nothing to
    // remember and so no `[a]lways` on offer.
    match yielded {
        mlua::Value::String(s) => Ok(ToolStep::Ask {
            text: s.to_string_lossy().to_string(),
            remember: None,
        }),
        mlua::Value::Nil => Ok(ToolStep::Ask {
            text: String::new(),
            remember: None,
        }),
        other => Err(format!(
            "tool yielded an unsupported value {} (only agent.ask and \
             agent.on_timeout yield inside a tool)",
            other.type_name()
        )),
    }
}

/// The callable a connection advertises under `name`, or `None` when the
/// registry holds no such tool. A tool object is a callable table: it carries a
/// `callback` function (what `agent.utils.tool` builds; `agent.mcp` produced ones
/// fall back to their `__call` metamethod, which routes through the connection).
pub(super) fn lookup_tool(lua: &Lua, name: &str) -> Result<Option<mlua::Function>, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("config: agent table: {e}"))?;
    let mcps: Table = match agent.get("mcps") {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let Some((conn_name, tool_name)) = split_qualified(name) else {
        // Not a name this agent ever advertises. Refused rather than guessed at.
        return Ok(None);
    };
    let Ok(conn) = mcps.get::<Table>(conn_name) else {
        return Ok(None);
    };
    // A connection holds its tools in `conn.tools[name]`; `agent.mcp` also
    // mirrors the same tables as `conn[name]` for Lua callers. Either is a hit,
    // so a hand-built connection needs nothing but its `tools` table.
    let tool = match conn
        .get::<Table>("tools")
        .and_then(|tools| tools.get::<mlua::Value>(tool_name))
    {
        Ok(mlua::Value::Table(t)) => t,
        _ => match conn.get::<mlua::Value>(tool_name) {
            Ok(mlua::Value::Table(t)) => t,
            _ => return Ok(None),
        },
    };
    let call = match tool.get::<mlua::Function>("callback").ok() {
        Some(cb) => cb,
        None => {
            let mt = tool
                .metatable()
                .ok_or_else(|| format!("config: {name}: tool has no callback or __call"))?;
            mt.get("__call")
                .map_err(|e| format!("config: {name}: __call: {e}"))?
        }
    };
    Ok(Some(call))
}

pub(super) fn decode_await(yielded: mlua::Value) -> Result<EventStep, String> {
    let mlua::Value::Table(t) = &yielded else {
        return Err(format!(
            "event handler: yielded an unsupported value {} (only \
             agent.on_timeout yields inside a handler)",
            yielded.type_name()
        ));
    };
    let tag: Option<String> = t
        .get("__agent_await")
        .map_err(|e| format!("event handler: await table: {e}"))?;
    match tag.as_deref() {
        Some("timeout") => {
            let ms: i64 = t
                .get("ms")
                .map_err(|e| format!("event handler: await timeout ms: {e}"))?;
            Ok(EventStep::Waiting {
                ms: ms.max(0) as u64,
            })
        }
        other => Err(format!("event handler: unknown await request {other:?}")),
    }
}

/// `agent.trigger(...) -> boolean` — force the agent loop to run a new
/// inference. With no argument: a continuation of the current conversation.
/// With a string: the text behaves like a submitted user message. With an
/// array of message tables: the array **replaces** the loop's in-memory
/// history (the write side of compaction) before the turn runs — usually a
/// summary message + the recent tail, exactly the "compacted history" a
/// `turn_completed` handler computed from the event payload.
///
/// The command is queued on the loop's trigger channel (see
/// [`AgentCommand`]) and the loop starts it at the next idle moment. Returns
/// `true` when queued; `false` when no loop is bound to the channel (the
/// headless probe, tests) so Lua can decide what that means.
/// `agent.api.input_insert(text)` / `input_backspace()` / `input_clear()` — change
/// the input line from Lua.
///
/// The route that makes the `key` event more than a picker. A handler that could
/// only *name* an action had a closed vocabulary baked into Rust, so "insert a
/// newline" had to be an action whether or not anyone wanted it, and nothing else
/// could ever type into the box on demand. With this, a binding can do whatever
/// Lua can do to the line, and the shipped table is free to stop treating
/// `newline` as special.
///
/// Returns `true` when queued and `false` when no loop is attached — the same
/// contract as [`agent.trigger`](crate::lua), and for the same reason: a binding
/// that silently dropped its own edit would look like a key that does nothing.
///
/// Ungated, unlike a key *binding*: the letter rule ("a bare letter is a
/// character first") governs which key may mean a command, and this is already
/// inside a command. So a chord bound to `input_insert("0")` inserts a `0`
/// mid-sentence, which is what a leader key is for.
pub(super) fn lua_input_op(op: InputOp) -> mlua::Result<bool> {
    send_to_loop(AgentCommand::Input(op))
}

pub(super) fn lua_trigger(_: &Lua, args: mlua::MultiValue) -> mlua::Result<bool> {
    let cmd = match args.into_iter().next() {
        None => AgentCommand::RunTurn {
            history: None,
            user: None,
        },
        Some(mlua::Value::String(s)) => AgentCommand::RunTurn {
            history: None,
            user: Some(s.to_str()?.to_string()),
        },
        Some(mlua::Value::Table(t)) => {
            let json = crate::mcp::lua_to_json(&mlua::Value::Table(t)).map_err(|e| {
                mlua::Error::RuntimeError(format!("agent.trigger: history decode: {e}"))
            })?;
            match json {
                // The history replacement must be an array of messages.
                serde_json::Value::Array(items) => AgentCommand::RunTurn {
                    history: Some(items),
                    user: None,
                },
                other => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "agent.trigger: expected an array of messages, got {}",
                        json_kind(&other)
                    )));
                }
            }
        }
        Some(v) => {
            return Err(mlua::Error::RuntimeError(format!(
                "agent.trigger: expected nothing, a string, or an array of messages, got {}",
                v.type_name()
            )));
        }
    };
    // The one difference from `send_to_loop` is the message: "the loop is gone"
    // names the primitive that noticed, because a user seeing it will be looking
    // at whatever called `agent.trigger`.
    let slot = TRIGGER_TX.read().map_err(|_| {
        mlua::Error::RuntimeError("agent.trigger: the trigger channel lock is poisoned".into())
    })?;
    match slot.as_ref() {
        Some(tx) => tx
            .send(cmd)
            .map_err(|_| mlua::Error::RuntimeError("agent.trigger: the agent loop is gone".into()))
            .map(|_| true),
        None => Ok(false),
    }
}

/// `agent.api.ask_user(text, always)`: put a question to the user and wait for
/// the verdict. This is the *tool-side* half of the ask protocol — a registered
/// `agent.mcps` tool whose callback drives a sandbox (the shipped `bash`) needs
/// its policy's asks answered by whoever is running the tool. It is not a
/// blocking call: the tool yields, which hands the question to the event loop
/// and parks the tracee's syscall frozen, and the loop resumes the same
/// coroutine with the answer once you have given one.
///
/// Returns the value the ask protocol accepts ([`AskAnswer`] mapped to the
/// wire shape `agent.ask` normalizes): `true` to allow the frozen syscall run,
/// `false` to deny it with no reason, or a deny verdict carrying the reason the
/// user-side handler gave. With no handler bound — headless runs, tests, the
/// probe — it auto-denies with a bare `false`, so an asking policy always
/// terminates instead of waiting on a user who cannot answer.
///
/// The Lua-side entry point is `agent.ask` (yield-based, for policies driven
/// from the event loop) and `agent.api.ask_user` (this one, for tools); a tool
/// callback wires the two with `stream:run(function(a) … end)`, which is what
/// `lua/bash_tool.lua` does.
pub(super) fn lua_ask_user(
    on_ask: Option<AskHandler>,
) -> impl Fn(&Lua, (String, Option<bool>)) -> mlua::Result<mlua::Value> {
    move |lua: &Lua, (text, always): (String, Option<bool>)| match &on_ask {
        // Headless: nobody to ask, so the ask denies and the run stays
        // read-only. An "always" nobody can give is not an allow.
        None => Ok(mlua::Value::Boolean(false)),
        Some(ask) => Ok(match ask(&text, always.unwrap_or(false)) {
            AskAnswer::Allow => mlua::Value::Boolean(true),
            AskAnswer::AllowAndTrust => {
                // A table, because the flag has to travel with the answer: the
                // asking side (which knows the path) is the one that acts on it.
                let t = lua.create_table()?;
                t.set("__agent_verdict", "allow")?;
                t.set("trust", true)?;
                mlua::Value::Table(t)
            }
            AskAnswer::Deny(None) => mlua::Value::Boolean(false),
            AskAnswer::Deny(Some(reason)) => {
                let t = lua.create_table()?;
                t.set("__agent_verdict", "deny")?;
                t.set("reason", reason)?;
                mlua::Value::Table(t)
            }
        }),
    }
}

/// The Lua-facing name of a JSON value, for the `agent.trigger` argument error.
fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}
/// One command a Lua handler sends the agent loop. The loop (the TUI's `run`)
/// consumes these on its idle select — the compaction primitives are how Lua
/// drives the loop: `on_event("turn_completed")` hears that a turn finished
/// (the conversation travels in the event payload, the **read** side), and
/// `agent.trigger` starts the next inference, optionally carrying a replaced
/// history (the **write** side).
#[derive(Debug, Clone)]
pub enum AgentCommand {
    /// Force a new inference now. `history` replaces the loop's in-memory
    /// conversation before the turn runs (a compaction replacement, divided
    /// into a summary message + recent tail); `user` behaves like a submitted
    /// user message pushed onto the history. At most one of the two is set.
    RunTurn {
        history: Option<Vec<serde_json::Value>>,
        user: Option<String>,
    },
    /// Change the input line: [`InputOp`].
    Input(InputOp),
}

/// What Lua may do to the input line.
///
/// The input box is loop state — a `String` on the `App` — and the `key` event is
/// the only thing a config has to change it from. Until this existed the action
/// vocabulary was the sole route to it, which meant the set of things a key
/// could do was frozen into [`crate::tui::Action`] whether a user wanted it or
/// not: there was no way for a binding to insert text, so a newline had to be
/// `Action::Newline` and nothing else could ever type into the box on demand.
///
/// Append-only, and deliberately so. There is no cursor, so "insert" means "at
/// the end", and a primitive that pretended otherwise would be inventing a
/// position model the widget does not have. `Backspace` is the mirror of
/// `Append` and the two together are enough to build anything a key table
/// actually needs — a leader key inserting a snippet, a chord typing a
/// character — without a second primitive for "delete a word".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputOp {
    /// Append text to the input line.
    Append(String),
    /// Remove the last character, if there is one.
    Backspace,
    /// Empty the line, as `Ctrl+u` in readline does.
    Clear,
}

/// The one channel `agent.trigger` and `agent.api.input_*` send to.
///
/// An `RwLock` rather than a `OnceLock` because *binding* is a process-lifetime
/// fact — the TUI binds once at startup and the channel is then the only route
/// from Lua to the loop — while the cell itself has to be resettable, since the
/// state is process-global by design and more than one test has something to say
/// about it. A `OnceLock` has no `clear`, and writing through its address is
/// undefined behaviour; the write lock is what serialises the reset against the
/// senders, which take the read side and are ordinary safe code.
static TRIGGER_TX: RwLock<Option<mpsc::UnboundedSender<AgentCommand>>> = RwLock::new(None);

/// Bind the trigger channel the agent loop drains (see [`AgentCommand`]).
/// Returns `None` when already bound — the TUI binds once at startup.
pub fn bind_trigger_channel(tx: mpsc::UnboundedSender<AgentCommand>) -> Option<()> {
    let mut slot = TRIGGER_TX.write().ok()?;
    if slot.is_some() {
        return None;
    }
    *slot = Some(tx);
    Some(())
}

/// A hold on the process-wide trigger channel, for a test that needs it to
/// itself.
///
/// The channel is global by design, and the suite has three things to say about
/// it: the input primitives report `false` with no loop attached, `alt+enter`
/// queues a newline, and `agent.trigger` queues a `RunTurn`. Those cannot all be
/// true at once, and neither can two tests each believe they own the slot — so a
/// test that touches this takes one of these instead, and the exclusivity is the
/// point: without it the failures are order-dependent rather than real.
#[cfg(test)]
static EXCLUSIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) struct TriggerChannelGuard {
    _serialised: std::sync::MutexGuard<'static, ()>,
    rx: RefCell<mpsc::UnboundedReceiver<AgentCommand>>,
}

#[cfg(test)]
impl TriggerChannelGuard {
    /// The next command the loop was sent, or `None` if nothing has been queued.
    pub(crate) fn recv(&self) -> Option<AgentCommand> {
        self.rx.borrow_mut().try_recv().ok()
    }

    /// Whether the queue is empty — used to assert that a claimed channel starts
    /// clean, so a test cannot pass on a leftover.
    pub(crate) fn is_empty(&self) -> bool {
        self.rx.borrow_mut().try_recv().is_err()
    }
}

/// Unbind the trigger channel, for a test that needs there to be *no* loop.
///
/// Shares the suite-wide lock with [`claim_trigger_channel`] and holds it for the
/// duration, so it cannot race a test that has legitimately claimed the channel:
/// "nobody is bound" is only observable while nobody else is driving.
#[cfg(test)]
pub(crate) fn release_trigger_channel() -> TriggerChannelGuard {
    let _serialised = EXCLUSIVE.lock().unwrap_or_else(|e| e.into_inner());
    let mut slot = TRIGGER_TX.write().expect("the trigger channel lock");
    *slot = None;
    drop(slot);
    let (_tx, rx) = mpsc::unbounded_channel::<AgentCommand>();
    TriggerChannelGuard {
        _serialised,
        rx: RefCell::new(rx),
    }
}

/// Claim the trigger channel for one test: unbind whatever is there, bind a
/// fresh one, and hold the suite-wide lock until the guard is dropped.
///
/// The lock is held for the guard's whole life, not just for the binding, so
/// two tests cannot interleave their claims — the exclusivity a mutex gives you
/// only if you hold it across the work, which is the entire point here.
#[cfg(test)]
pub(crate) fn claim_trigger_channel() -> TriggerChannelGuard {
    let serialised = EXCLUSIVE.lock().unwrap_or_else(|e| e.into_inner());
    let (tx, rx) = mpsc::unbounded_channel::<AgentCommand>();
    {
        let mut slot = TRIGGER_TX.write().expect("the trigger channel lock");
        *slot = Some(tx);
    }
    TriggerChannelGuard {
        _serialised: serialised,
        rx: RefCell::new(rx),
    }
}

/// Send one command to the loop, or report that there is no loop.
///
/// `Ok(false)` rather than an error when nothing is bound, because that is what
/// the Lua-facing callers promise their own callers: `agent.api.input_*` and
/// `agent.trigger` both return a boolean that means "the loop was told", and a
/// binding whose edit went nowhere would look like a key that does nothing.
fn send_to_loop(cmd: AgentCommand) -> mlua::Result<bool> {
    let slot = TRIGGER_TX.read().map_err(|_| {
        mlua::Error::RuntimeError("agent: the trigger channel lock is poisoned".into())
    })?;
    match slot.as_ref() {
        Some(tx) => tx
            .send(cmd)
            .map_err(|_| {
                mlua::Error::RuntimeError("agent.api.input_*: the agent loop is gone".into())
            })
            .map(|_| true),
        None => Ok(false),
    }
}

/// Fire a registered event and hand back what its handler returned, as a string.
///
/// This exists for the one event whose *return value is the answer*: `key`, where
/// a handler returns the name of the action the key should perform, or nothing to
/// leave the key to its default binding. Every other event ignores the return,
/// and goes through [`fire_event_on_vm`] instead — which is the honest shape for
/// a notification, and keeps "this event is a question" out of the generic path.
///
/// A handler that returns something other than a string or nil is an error: the
/// caller has to be able to tell "no answer" from "a badly-typed answer", and
/// quietly treating the second as the first is how a binding silently dies.
///
/// Runs as a plain call, like [`fire_event_on_vm`]: a keypress handler must not
/// be able to yield. A `key` handler that slept would be holding up the only
/// thread that reads input, and there is no reactor behind it to resume on.
pub fn fire_event_returning(
    lua: &Lua,
    name: &str,
    payload: &serde_json::Value,
) -> Result<Option<String>, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("event: agent table: {e}"))?;
    let events: Table = match agent.get("_events") {
        Ok(t) => t,
        // No registrations on this VM: events are opt-in, so nothing to ask.
        Err(_) => return Ok(None),
    };
    let handler: mlua::Function = match events.get(name) {
        Ok(f) => f,
        Err(_) => return Ok(None), // no handler for this event: the default stands
    };
    let payload_lua =
        crate::mcp::json_to_lua(lua, payload).map_err(|e| format!("event: payload: {e}"))?;
    let answer: mlua::Value = handler
        .call(payload_lua)
        .map_err(|e| format!("event {name}: {e}"))?;
    match answer {
        mlua::Value::Nil => Ok(None),
        mlua::Value::String(s) => Ok(Some(s.to_string_lossy().to_string())),
        mlua::Value::Boolean(b) if !b => Ok(None),
        other => Err(format!(
            "event {name}: a handler must return an action name or nil, got {}",
            other.type_name()
        )),
    }
}

/// Fire a registered event on `lua`, which must already have the user's
/// configuration applied (entry script + user config, whose top-level
/// `agent.on_event(...)` calls registered the handlers). The handler runs in
/// the calling thread as a plain call — no coroutine, no reactor; the TUI drives
/// its own handler through [`EventRun`] instead, so it can yield.
///
/// Returns whether a handler was registered and ran (events are opt-in, so
/// `false` is normal), and the handler's own error otherwise.
pub fn fire_event_on_vm(
    lua: &Lua,
    name: &str,
    payload: &serde_json::Value,
) -> Result<bool, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("event: agent table: {e}"))?;
    let events: Table = match agent.get("_events") {
        Ok(t) => t,
        // No registrations on this VM: events are opt-in, so nothing to fire.
        Err(_) => return Ok(false),
    };
    let handler: mlua::Function = match events.get(name) {
        Ok(f) => f,
        Err(_) => return Ok(false), // no handler for this event: opt-in
    };
    let payload_lua =
        crate::mcp::json_to_lua(lua, payload).map_err(|e| format!("event: payload: {e}"))?;
    handler
        .call::<()>(payload_lua)
        .map(|_| true)
        .map_err(|e| format!("event {name}: {e}"))
}

/// One step of a reactor-driven event handler coroutine ([`EventRun`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStep {
    /// The handler returned.
    Returned,
    /// The handler suspended on an `agent.on_timeout(ms, ...)` wait; the
    /// reactor must resume it after `ms` milliseconds (it passes `true` back
    /// into the yield site).
    Waiting { ms: u64 },
}

/// A `turn_completed`-style event handler driven **cooperatively** on the
/// agent's single reactor thread — the strictly single-threaded successor to
/// the fire-and-forget background thread.
///
/// The handler runs as a Lua coroutine **on the agent's own configuration VM**
/// (the same one the loop reads the system prompt and the tool registry from),
/// not on a throwaway one. That is what lets a handler *change* the agent rather
/// than merely watch it: a mode it switches, a setting it writes, and a flag it
/// arms are all still there when the turn it triggers runs — and when the next
/// event arrives. It is also why the coroutine may span turns: `Lua` state
/// outlives each `coroutine.resume`, so a handler suspended on a timer resumes
/// with everything it had.
///
/// Every `agent.on_timeout(ms, ...)` wait yields a
/// `{ __agent_await = "timeout", ms = ms }` request to the driver, which decodes
/// it into [`EventStep::Waiting`]; the caller (the TUI loop) arms a reactor timer
/// and calls [`EventRun::step`] when it fires. The `Lua` state never leaves the
/// thread that created it (mlua here is built without the `send` feature). A
/// handler that calls `coroutine.yield` directly yields an undecodable value and
/// errors.
pub struct EventRun<'lua> {
    lua: &'lua Lua,
    thread: mlua::Thread,
}

impl<'lua> EventRun<'lua> {
    /// Resume the handler for `name` on `lua` for the first time, with
    /// `payload` as its argument. `Ok(None)` when no handler is registered for
    /// `name` (events are opt-in).
    pub fn start(
        lua: &'lua Lua,
        name: &str,
        payload: &serde_json::Value,
    ) -> Result<Option<(EventRun<'lua>, EventStep)>, String> {
        let agent: Table = lua
            .globals()
            .get("agent")
            .map_err(|e| format!("event: agent table: {e}"))?;
        let events: Table = match agent.get("_events") {
            Ok(t) => t,
            // No init script / no registrations on this VM: events are
            // opt-in, so there is nothing to fire.
            Err(_) => return Ok(None),
        };
        let handler: mlua::Function = match events.get(name) {
            Ok(f) => f,
            Err(_) => return Ok(None), // no handler for this event: opt-in
        };
        let payload_lua =
            crate::mcp::json_to_lua(lua, payload).map_err(|e| format!("event: payload: {e}"))?;
        // Mark this VM as reactor-driven: `agent.on_timeout` now suspends the
        // running coroutine instead of falling back to a thread sleep.
        agent
            .set("__on_reactor", true)
            .map_err(|e| format!("event: reactor marker: {e}"))?;
        let thread = lua
            .create_thread(handler)
            .map_err(|e| format!("event: coroutine: {e}"))?;
        let mut run = EventRun { lua, thread };
        let step = run
            .resume_with(Some(payload_lua))
            .map_err(|e| format!("event {name}: {e}"))?;
        Ok(Some((run, step)))
    }

    /// Resume the suspension: the reactor's timer for the last
    /// [`EventStep::Waiting`] fired. `true` lands back at the yielding
    /// `agent.on_timeout` call site.
    pub fn step(&mut self) -> Result<EventStep, String> {
        self.resume_with(Some(mlua::Value::Boolean(true)))
    }

    /// The VM the handler runs on — the agent's own config VM, borrowed for as
    /// long as the run lasts (tests inspect its globals afterwards).
    pub fn lua(&self) -> &Lua {
        self.lua
    }

    /// One resume: the first call lands `arg` as the handler function's
    /// argument; later calls land it as the value of the last `coroutine.yield`
    /// (`None` resumes with no value at all).
    fn resume_with(&mut self, arg: Option<mlua::Value>) -> Result<EventStep, String> {
        let res: mlua::Value = self.thread.resume(arg).map_err(err_to_event)?;
        match self.thread.status() {
            mlua::thread::ThreadStatus::Resumable => decode_await(res),
            _ => Ok(EventStep::Returned),
        }
    }
}

pub(super) fn err_to_event(e: mlua::Error) -> String {
    format!("event handler: {e}")
}
