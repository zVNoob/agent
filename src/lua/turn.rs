//! `agent.api.turn` — one model request, as a polled stream.
//!
//! The substrate half of running a conversation. It sends **one** chat-completion
//! request with everything it needs as arguments and yields the response as events.
//! It does not run a conversation: there is no tool loop here, no inheritance, and no
//! policy. Deciding what to send, what a tool call means, and what to send next is
//! the caller's job — and doing it in Lua is what makes a subagent scriptable by
//! whoever is running the agent.
//!
//! ## Everything is an argument
//!
//! Endpoint, credential, model, messages and tools all arrive as parameters, and
//! this module reads **no globals**: not `agent.llm`, not `agent.mcps`, not the
//! active mode, and not even whether any of them exist. Those are conventions the
//! configuration owns (`lua/init.lua`); a caller that wants their defaults supplies
//! them, which is a decision about *whose* defaults rather than a silent one.
//!
//! A parameter that is absent is an error naming it. Defaulting here would put a
//! second source of truth next to `agent.llm`, and the two would drift.
//!
//! ## Why a handle rather than a result
//!
//! The whole transport is poll-based, and not by accident: one reactor, one thread,
//! and a tool is already a coroutine the loop steps. `http_req` returns a handle
//! that `http_step` drains; this is the same shape for the same reason, and it is
//! what lets a nested turn accumulate while the agent's own stream is still going.
//!
//! Failures arrive as an `error` **event** rather than as a Lua error, because the
//! caller is mid-turn inside a coroutine and a raise would unwind it past the tool
//! that asked. Argument errors do raise — they happen before anything is in flight,
//! and there is nothing to unwind.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use mlua::{Lua, Table, Value};

use crate::api::{Chat, ChatConfig, ToolCallDelta, ToolDef, TurnEvent};

/// One queued event, already in the shape Lua will see.
enum TurnEv {
    Content(String),
    Reasoning(String),
    ToolCall(ToolCallDelta),
    Usage(serde_json::Value),
    Timings(serde_json::Value),
    /// The assembled result, so the caller does not have to re-derive it.
    ///
    /// Rust emits the deltas *and* the finished turn, because the two are for
    /// different consumers: the deltas are for drawing (into a panel, chunk by
    /// chunk), and the assembled turn is for *history* — and a route that assembled
    /// its own would be a second `TurnBuilder`, in Lua, that the Rust one would have
    /// to stay in step with forever. Reasoning travels separately, for the same
    /// reason `Turn` drops it: it is observed, not conversation.
    Done {
        content: String,
        reasoning: String,
        tool_calls: Vec<crate::api::ToolCall>,
        usage: Option<serde_json::Value>,
        timings: Option<serde_json::Value>,
    },
    Error(String),
}

/// The in-flight request: where its events queue up, and how to stop it.
#[derive(Clone)]
struct Session {
    queue: Arc<Mutex<VecDeque<TurnEv>>>,
    abort: Arc<AtomicBool>,
}

/// Every nested turn this process has open, keyed by handle.
struct Transport {
    next: AtomicI64,
    posts: Mutex<HashMap<i64, Session>>,
}

fn transport() -> &'static Transport {
    static T: OnceLock<Transport> = OnceLock::new();
    T.get_or_init(|| Transport {
        next: AtomicI64::new(1),
        posts: Mutex::new(HashMap::new()),
    })
}

/// The shared HTTP client. `reqwest::Client` is a handle over a connection pool, so
/// one for the process is the right number — see [`Chat::connect_with`].
fn http_client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(reqwest::Client::new)
}

fn err(msg: impl Into<String>) -> mlua::Error {
    mlua::Error::RuntimeError(format!("agent.api.turn: {}", msg.into()))
}

/// A Lua value as JSON, for the request body.
fn as_json(v: &Value) -> Result<serde_json::Value, mlua::Error> {
    crate::mcp::lua_to_json(v)
}

/// The `messages` argument: an array of message tables, in order.
fn messages_from_lua(t: &Table) -> Result<Vec<serde_json::Value>, mlua::Error> {
    let mut out = Vec::new();
    for pair in t.clone().pairs::<Value, Value>() {
        let (_, v) = pair.map_err(|e| err(e.to_string()))?;
        out.push(as_json(&v)?);
    }
    Ok(out)
}

/// The `tools` argument: an array of `{ name, description?, parameters? }`.
///
/// **Not** the wire shape, which is `{ type = "function", function = { … } }`. That
/// shape is what goes on the wire, and it cannot be written in a Lua table
/// constructor at all: `function` is a keyword, so the key has to be bracketed
/// (`["function"] = …`) and a substrate argument nobody can type is not an argument.
/// So the flat form is what a caller passes and [`ToolDef`] is assembled here —
/// `type` has exactly one legal value, so there is nothing to be gained by making the
/// caller state it.
fn tools_from_lua(t: &Table) -> Result<Vec<ToolDef>, mlua::Error> {
    let mut out = Vec::new();
    for pair in t.clone().pairs::<Value, Value>() {
        let (_, v) = pair.map_err(|e| err(e.to_string()))?;
        let v = as_json(&v)?;
        let at = out.len();
        let name = v
            .get("name")
            .and_then(|n| n.as_str())
            .filter(|n| !n.trim().is_empty())
            .ok_or_else(|| {
                err(format!(
                    "tools[{at}] has no `name`: a tool is \
                     {{ name, description, parameters? }}"
                ))
            })?
            .to_string();
        // `description` is **required**, and that is not pedantry: it is the only
        // thing the model has to go on when deciding whether to call this, so a tool
        // without one is a tool it will never reach for. Requiring it also rejects the
        // shape that would otherwise slip through — a *connection* table
        // (`{ name = "fs", tools = { … } }`) has a name and no description, and
        // accepting it would send the model a tool called `fs` with an empty schema.
        let description = v
            .get("description")
            .and_then(|d| d.as_str())
            .filter(|d| !d.trim().is_empty())
            .ok_or_else(|| {
                err(format!(
                    "tools[{at}] has no `description`: a tool is \
                     {{ name, description, parameters? }}, and the description is how \
                     the model knows it may call it"
                ))
            })?
            .to_string();
        // `parameters` defaults, because a tool taking nothing is ordinary and a
        // caller should not have to write an empty schema to say so.
        let parameters = v
            .get("parameters")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({ "type": "object", "properties": {} }));
        out.push(ToolDef {
            kind: "function".to_string(),
            function: crate::api::FunctionDef {
                name,
                description,
                parameters,
            },
        });
    }
    Ok(out)
}

/// `agent.api.turn(base_url, api_key, model, messages, tools) -> handle`
///
/// Sends the request and returns immediately; the response is drained by
/// [`lua_turn_step`].
pub(super) fn lua_turn(
    _lua: &Lua,
    (base_url, api_key, model, messages, tools): (String, String, String, Table, Table),
) -> mlua::Result<i64> {
    if base_url.trim().is_empty() {
        return Err(err("base_url is required and was empty"));
    }
    if model.trim().is_empty() {
        return Err(err("model is required and was empty"));
    }
    let messages = messages_from_lua(&messages)?;
    let tools = tools_from_lua(&tools)?;

    let id = transport().next.fetch_add(1, Ordering::Relaxed);
    let session = Session {
        queue: Arc::new(Mutex::new(VecDeque::new())),
        abort: Arc::new(AtomicBool::new(false)),
    };
    transport()
        .posts
        .lock()
        .unwrap()
        .insert(id, session.clone());

    let config = ChatConfig {
        base_url,
        api_key,
        model,
    };
    // A task on the agent's own reactor, for the same reason `http_req` spawns one:
    // there is no thread to hand this to — the caller is a coroutine on that
    // reactor, and the response is consumed by polling, never by waiting.
    //
    // Checked rather than assumed. `tokio::spawn` *panics* with no runtime, and a
    // panic raised on the way out of a `pcall` in Lua does not reliably come back as
    // an error the caller can see — it was observed arriving as a success. A primitive
    // that cannot run here says so.
    if tokio::runtime::Handle::try_current().is_err() {
        transport().posts.lock().unwrap().remove(&id);
        return Err(err(
            "no reactor to run the request on; call this from a driven coroutine \
             (`agent.on_timeout` marks one) rather than from a bare thread",
        ));
    }
    tokio::spawn(async move {
        drive(config, tools, messages, session).await;
    });
    Ok(id)
}

/// The request, and the queue it fills.
async fn drive(
    config: ChatConfig,
    tools: Vec<ToolDef>,
    messages: Vec<serde_json::Value>,
    session: Session,
) {
    let push = |ev: TurnEv| session.queue.lock().unwrap().push_back(ev);
    let mut builder = crate::api::TurnBuilder::new();
    // `Turn` deliberately has no reasoning field — it is observed, not kept in
    // conversation history — so it is accumulated beside the builder and emitted with
    // the result, which is the only way the caller can draw it.
    let mut reasoning = String::new();
    let chat = Chat::connect_with(http_client().clone(), &config, tools);
    let mut stream = match chat.stream_turn(&messages).await {
        Ok(s) => s,
        Err(e) => {
            // A refusal, an unreachable host, a non-2xx: all of it is an event, so
            // the caller decides what a failed subagent means.
            push(TurnEv::Error(format!("{e:#}")));
            return;
        }
    };
    use futures_util::StreamExt;
    loop {
        // The abort flag is checked before every poll, not after: a caller who
        // closed the handle while the socket was idle should not wait out the
        // timeout that is still running.
        if session.abort.load(Ordering::Relaxed) {
            return; // closed under us: no Done, nobody is listening
        }
        let next = stream.next().await;
        let Some(event) = next else {
            break; // the response ended: normal completion
        };
        match event {
            Ok(TurnEvent::Content(s)) => {
                builder.apply(TurnEvent::Content(s.clone()));
                push(TurnEv::Content(s));
            }
            Ok(TurnEvent::Reasoning(s)) => {
                reasoning.push_str(&s);
                push(TurnEv::Reasoning(s));
            }
            Ok(TurnEvent::ToolCallDelta(d)) => {
                builder.apply(TurnEvent::ToolCallDelta(d.clone()));
                push(TurnEv::ToolCall(d));
            }
            Ok(TurnEvent::Usage(v)) => {
                builder.apply(TurnEvent::Usage(v.clone()));
                push(TurnEv::Usage(v));
            }
            Ok(TurnEvent::Timings(v)) => {
                builder.apply(TurnEvent::Timings(v.clone()));
                push(TurnEv::Timings(v));
            }
            // A truncated body: the stream failed part-way rather than refusing.
            Err(e) => {
                push(TurnEv::Error(format!("{e:#}")));
                return;
            }
        }
    }
    let turn = builder.finish();
    push(TurnEv::Done {
        content: turn.content,
        reasoning,
        tool_calls: turn.tool_calls,
        usage: turn.usage,
        timings: turn.timings,
    });
}

/// `agent.api.turn_step(handle) -> event | nil`
///
/// `nil` when nothing has arrived yet — the caller is expected to wait on
/// `agent.on_timeout` and come back, which is what every other pump in the tree
/// does. A terminal event (`done` or `error`) unregisters the handle, so it cannot
/// be stepped again.
pub(super) fn lua_turn_step(lua: &Lua, handle: i64) -> mlua::Result<Option<Table>> {
    let session = transport().posts.lock().unwrap().get(&handle).cloned();
    let Some(session) = session else {
        return Ok(None);
    };
    let ev = session.queue.lock().unwrap().pop_front();
    let Some(ev) = ev else {
        return Ok(None);
    };
    // Terminality comes off the enum rather than re-read from the table: matching the
    // converted shape would mean the `kind` string is load-bearing for control flow,
    // so renaming an event could silently change when a handle unregisters.
    let (table, terminal) = event_to_lua(lua, ev)?;
    if terminal {
        transport().posts.lock().unwrap().remove(&handle);
    }
    Ok(Some(table))
}

/// One event as a Lua table, and whether it ends the stream.
fn event_to_lua(lua: &Lua, ev: TurnEv) -> mlua::Result<(Table, bool)> {
    let t = lua.create_table()?;
    match ev {
        TurnEv::Content(s) => {
            t.set("kind", "content")?;
            t.set("text", s)?;
        }
        TurnEv::Reasoning(s) => {
            t.set("kind", "reasoning")?;
            t.set("text", s)?;
        }
        TurnEv::ToolCall(d) => {
            t.set("kind", "tool_call")?;
            t.set("index", d.index as i64)?;
            if let Some(id) = d.id {
                t.set("id", id)?;
            }
            if let Some(name) = d.name {
                t.set("name", name)?;
            }
            if let Some(args) = d.arguments {
                t.set("arguments", args)?;
            }
        }
        TurnEv::Usage(v) => {
            t.set("kind", "usage")?;
            t.set("usage", lua_to_lua(lua, &v)?)?;
        }
        TurnEv::Timings(v) => {
            t.set("kind", "timings")?;
            t.set("timings", lua_to_lua(lua, &v)?)?;
        }
        TurnEv::Done {
            content,
            reasoning,
            tool_calls,
            usage,
            timings,
        } => {
            t.set("kind", "done")?;
            t.set("content", content)?;
            t.set("reasoning", reasoning)?;
            let calls = lua.create_table()?;
            for (i, c) in tool_calls.iter().enumerate() {
                let call = lua.create_table()?;
                call.set("id", c.id.as_str())?;
                call.set("name", c.name.as_str())?;
                call.set("arguments", c.arguments.as_str())?;
                calls.set(i + 1, call)?;
            }
            t.set("tool_calls", calls)?;
            if let Some(u) = usage {
                t.set("usage", lua_to_lua(lua, &u)?)?;
            }
            if let Some(tm) = timings {
                t.set("timings", lua_to_lua(lua, &tm)?)?;
            }
            return Ok((t, true));
        }
        TurnEv::Error(m) => {
            t.set("kind", "error")?;
            t.set("message", m)?;
            return Ok((t, true));
        }
    }
    Ok((t, false))
}

/// JSON as Lua, so a `usage` block arrives as a table rather than as text to
/// re-parse. `null` becomes `nil`, which is what a Lua caller means by "absent".
fn lua_to_lua(lua: &Lua, v: &serde_json::Value) -> mlua::Result<Value> {
    Ok(match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i)
            } else {
                Value::Number(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => Value::String(lua.create_string(s)?),
        serde_json::Value::Array(a) => {
            let t = lua.create_table()?;
            for (i, item) in a.iter().enumerate() {
                t.set(i + 1, lua_to_lua(lua, item)?)?;
            }
            Value::Table(t)
        }
        serde_json::Value::Object(o) => {
            let t = lua.create_table()?;
            for (k, item) in o {
                t.set(k.as_str(), lua_to_lua(lua, item)?)?;
            }
            Value::Table(t)
        }
    })
}

/// `agent.api.turn_close(handle) -> nothing`
///
/// Aborts the request and drops the queue. The spawned task notices the flag before
/// its next event and returns, so this is prompt rather than a cancellation the
/// caller has to wait out.
pub(super) fn lua_turn_close(_lua: &Lua, handle: i64) -> mlua::Result<()> {
    if let Some(session) = transport().posts.lock().unwrap().remove(&handle) {
        session.abort.store(true, Ordering::Relaxed);
    }
    Ok(())
}

/// Decode a `turn` handler's return value — the assembled-turn table the
/// `agent.turn` route's `:run()` produces — into the [`Turn`] the loop's
/// end-of-turn path runs on, plus the reasoning, which `Turn` deliberately
/// drops (it is not conversation history; the loop archives it separately).
///
/// Missing fields take the empty answer, so a handler that built the table by
/// hand — a test double, a canned reply — needs only the keys it has. A value
/// that is not a table at all is the error it looks like.
pub fn turn_from_lua(value: mlua::Value) -> Result<(crate::api::Turn, String), String> {
    let json = crate::mcp::lua_to_json(&value).map_err(|e| format!("turn handler result: {e}"))?;
    if !json.is_object() {
        return Err(format!(
            "turn handler result: expected the assembled-turn table, got {}",
            match &json {
                serde_json::Value::Null => "null",
                serde_json::Value::Bool(_) => "a boolean",
                serde_json::Value::Number(_) => "a number",
                serde_json::Value::String(_) => "a string",
                serde_json::Value::Array(_) => "an array",
                serde_json::Value::Object(_) => unreachable!(),
            }
        ));
    }
    let obj = || json.as_object();
    let text = |key: &str| {
        obj()
            .and_then(|o| o.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let tool_calls = obj()
        .and_then(|o| o.get("tool_calls"))
        .and_then(|v| v.as_array())
        .map(|calls| {
            calls
                .iter()
                .filter_map(|c| {
                    Some(crate::api::ToolCall {
                        id: c.get("id")?.as_str()?.to_string(),
                        name: c.get("name")?.as_str()?.to_string(),
                        arguments: c.get("arguments")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let reasoning = text("reasoning");
    let turn = crate::api::Turn {
        content: text("content"),
        tool_calls,
        usage: obj().and_then(|o| o.get("usage")).cloned(),
        timings: obj().and_then(|o| o.get("timings")).cloned(),
    };
    Ok((turn, reasoning))
}

/// Register the three primitives on the bridge.
pub(super) fn install(lua: &Lua, api: &Table) -> mlua::Result<()> {
    api.set("turn", lua.create_function(lua_turn)?)?;
    api.set("turn_step", lua.create_function(lua_turn_step)?)?;
    api.set("turn_close", lua.create_function(lua_turn_close)?)?;
    Ok(())
}
