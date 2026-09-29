//! MCP (Model Context Protocol) client substrate.
//!
//! Two transports live here, both owned by Rust; the protocol on top of them
//! ("initialize"/"tools/list"/"tools/call" correlation, per-server policy,
//! tool registry) lives in Lua ([`crate::lua`]), so this module stays
//! stateless at the protocol level.
//!
//! - the **JSON text boundary**: [`install_bridge`] adds `agent.api.json_encode` /
//!   `agent.api.json_decode` to the `agent` namespace, converting between Lua
//!   values and JSON text. The bridge walks [`mlua::Value`] directly over
//!   `serde_json` — no extra mlua features — and distinguishes JSON arrays
//!   from objects *by table content*: a table whose keys are exactly `1..n`
//!   encodes as an array, anything else as an object (empty tables are
//!   `{}`); see [`lua_to_json`].
//! - the **stdio framing**: one JSON-RPC message per line on each pipe
//!   ([`read_line`] / [`write_line`]), used by the `mcp_fake` reference
//!   server (`src/bin/mcp_fake.rs`) — the MCP stdio transport, against
//!   servers that run *inside* the seccomp sandbox (`agent.mcp` in
//!   [`crate::lua`]).
//! - the **streamable HTTP(S) transport**: `reqwest` as a task on the agent's
//!   own single reactor (see the transport section below) — the MCP streamable
//!   HTTP transport, driven from Lua by the `agent.http` stream objects
//!   in [`crate::lua`].
//! - the **wire types**: the JSON-RPC 2.0 [`Message`] shape the MCP protocol
//!   is built on.

use mlua::{Lua, Table, Value};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use futures_util::StreamExt;

/// Bytes needed only in test builds: the fake HTTP server helpers below are
/// shared with the `src/lua/tests/` suite.
#[cfg(test)]
use std::io::{Read, Write};

/// A JSON-RPC 2.0 id (this client uses sequential integers).
pub type RpcId = i64;

/// A JSON-RPC 2.0 error object (carried in a response in place of `result`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Json>,
}

/// One JSON-RPC 2.0 message. Requests and responses carry an `id`
/// (a *request* also carries `method`); notifications carry a `method` and
/// no `id`. Parsed from a wire line with
/// `serde_json::from_str::<Message>`; built with the constructors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Message {
    Request {
        jsonrpc: String,
        id: RpcId,
        method: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        params: Option<Json>,
    },
    Response {
        jsonrpc: String,
        id: RpcId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Json>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<RpcError>,
    },
    Notification {
        jsonrpc: String,
        method: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        params: Option<Json>,
    },
}

impl Message {
    pub fn request(id: RpcId, method: &str, params: Option<Json>) -> Self {
        Message::Request {
            jsonrpc: "2.0".into(),
            id,
            method: method.into(),
            params,
        }
    }

    pub fn response(id: RpcId, result: Option<Json>, error: Option<RpcError>) -> Self {
        Message::Response {
            jsonrpc: "2.0".into(),
            id,
            result,
            error,
        }
    }

    pub fn notification(method: &str, params: Option<Json>) -> Self {
        Message::Notification {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
        }
    }

    /// The id, if this message carries one.
    pub fn id(&self) -> Option<RpcId> {
        match self {
            Message::Request { id, .. } | Message::Response { id, .. } => Some(*id),
            Message::Notification { .. } => None,
        }
    }
}

/// MCP stdio framing: one JSON-RPC message per line on each pipe.
///
/// Read one message line (the trailing newline is stripped). `Ok(None)` at
/// EOF.
pub fn read_line<R: std::io::BufRead>(r: &mut R) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);
    Ok(Some(trimmed.to_owned()))
}

/// Write one message line and flush.
pub fn write_line<W: std::io::Write>(w: &mut W, line: &str) -> std::io::Result<()> {
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()
}

// ---------------------------------------------------------------------------
// Streamable HTTP(S) transport.
//
// `reqwest` runs as a task on the agent's own single reactor — there is no
// transport thread, because the caller is already a coroutine on that reactor.
// The response is consumed by *polling*, never by waiting, which is what lets
// the synchronous Lua pump drive it. Lua fires a request with
// `agent.api.http_req` or opens an SSE stream with `agent.api.sse_open`,
// receives a numeric **handle**, and pumps results with `agent.api.http_step` /
// `agent.api.sse_step` — one buffered event per call. Response bodies stream in
// as `chunk` events; SSE `data:` lines arrive as `event` events; the terminal
// event (done/error) unregisters the handle.
//
// The transport task only ever touches Rust data: per-handle event queues,
// behind a mutex, filled by the task and drained by the pump. Lua values (event
// tables) are materialized at pump time, on the thread that owns the VM. Rust
// owns TLS, HTTP framing, and SSE parsing; everything above the byte level
// (protocol, correlation, callbacks) is Lua's — see `agent.http` in
// [`crate::lua`].
// ---------------------------------------------------------------------------

/// How long a live stream's task waits between abort checks.
const STREAM_POLL: Duration = Duration::from_millis(500);

/// One buffered event of an in-flight HTTP request.
#[derive(Debug, Clone)]
enum HttpEv {
    /// Response status line + headers (always first).
    Headers {
        status: u16,
        headers: Vec<(String, String)>,
    },
    /// A chunk of the response body, streamed as it arrives.
    Chunk(String),
    /// The response ended cleanly.
    Done,
    /// A transport-level failure (unreachable host, timeout, ...).
    Error(String),
}

/// One buffered event of an open SSE stream.
#[derive(Debug, Clone)]
enum SseEv {
    /// A complete Server-Sent Event.
    Event { event: String, data: String },
    /// The stream ended (EOF, or the server closed it).
    Done,
    /// A transport-level failure.
    Error(String),
}

/// One HTTP request's parameters, bundled so the spawned task can take it whole
/// without an argument list.
struct HttpReqSpec {
    method: reqwest::Method,
    url: String,
    headers: Vec<(String, String)>,
    body: String,
    timeout_ms: u64,
    queue: Arc<Mutex<VecDeque<HttpEv>>>,
    abort: Arc<AtomicBool>,
}

/// The transport registry: the maps of live HTTP/SSE sessions, keyed by the
/// handles Lua holds.
struct HttpTransport {
    posts: Mutex<HashMap<i64, Session<HttpEv>>>,
    sses: Mutex<HashMap<i64, Session<SseEv>>>,
    next_id: AtomicI64,
}

struct Session<E> {
    queue: Arc<Mutex<VecDeque<E>>>,
    abort: Arc<AtomicBool>,
}

impl<E> Clone for Session<E> {
    fn clone(&self) -> Self {
        Session {
            queue: self.queue.clone(),
            abort: self.abort.clone(),
        }
    }
}

/// The single process-wide transport registry (created on first use).
///
/// It holds only the live sessions — the response queues the Lua side pops and
/// the abort flags `http_close` / `sse_close` set. The *work* is a `tokio` task
/// on the agent's own single-threaded reactor, spawned by the primitive that
/// starts it: there is no transport thread, because every caller (a tool, an
/// event handler) is already running inside that reactor as a Lua coroutine, and
/// `lua/lib/http.lua` hands the loop a slice between polls rather than waiting
/// for the body.
fn http_transport() -> &'static HttpTransport {
    static T: OnceLock<HttpTransport> = OnceLock::new();
    T.get_or_init(|| HttpTransport {
        posts: Mutex::new(HashMap::new()),
        sses: Mutex::new(HashMap::new()),
        next_id: AtomicI64::new(1),
    })
}

/// The shared HTTP client. Built once, on the reactor, the first time a request
/// is fired (reqwest's connector needs a runtime context to exist at all).
fn http_client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("agent reqwest client")
    })
}

/// One HTTP request, executed as a task on the agent's reactor. The status line and
/// headers are queued first, then the body as it streams in, then `Done` (or
/// `Error`). `timeout_ms == 0` means no timeout.
async fn http_req_task(client: reqwest::Client, spec: HttpReqSpec) {
    let HttpReqSpec {
        method,
        url,
        headers,
        body,
        timeout_ms,
        queue,
        abort,
    } = spec;
    let push = |ev: HttpEv| queue.lock().unwrap().push_back(ev);
    let timed = async {
        let mut req = client.request(method, &url);
        for (k, v) in &headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let stream = match req.body(body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let hs = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_str().to_ascii_lowercase(),
                            v.to_str().unwrap_or("").to_owned(),
                        )
                    })
                    .collect();
                push(HttpEv::Headers {
                    status,
                    headers: hs,
                });
                resp.bytes_stream()
            }
            Err(e) => {
                push(HttpEv::Error(format!("{e}")));
                return;
            }
        };
        let mut stream = stream;
        loop {
            if abort.load(Ordering::Relaxed) {
                return;
            }
            match tokio::time::timeout(STREAM_POLL, stream.next()).await {
                Err(_) => continue,
                Ok(Some(Ok(chunk))) => {
                    push(HttpEv::Chunk(String::from_utf8_lossy(&chunk).into_owned()))
                }
                Ok(Some(Err(e))) => {
                    push(HttpEv::Error(format!("{e}")));
                    return;
                }
                Ok(None) => {
                    push(HttpEv::Done);
                    return;
                }
            }
        }
    };
    if timeout_ms > 0 {
        let out = tokio::time::timeout(Duration::from_millis(timeout_ms), timed).await;
        if out.is_err() {
            push(HttpEv::Error(format!(
                "request timed out after {timeout_ms}ms"
            )));
        }
    } else {
        timed.await;
    }
}

/// One SSE GET, run as a task on the agent's reactor. Each complete event is
/// queued as it parses; EOF queues `Done`.
async fn sse_task(
    client: reqwest::Client,
    url: String,
    headers: Vec<(String, String)>,
    queue: Arc<Mutex<VecDeque<SseEv>>>,
    abort: Arc<AtomicBool>,
) {
    let push = |ev: SseEv| queue.lock().unwrap().push_back(ev);
    let mut req = client.get(&url);
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let stream = match req.send().await {
        Ok(resp) if resp.status().is_success() => resp.bytes_stream(),
        Ok(resp) => {
            push(SseEv::Error(format!("HTTP {}", resp.status())));
            return;
        }
        Err(e) => {
            push(SseEv::Error(format!("{e}")));
            return;
        }
    };
    let mut stream = stream;
    let mut parser = SseParser::default();
    loop {
        if abort.load(Ordering::Relaxed) {
            return;
        }
        match tokio::time::timeout(STREAM_POLL, stream.next()).await {
            Err(_) => continue,
            Ok(Some(Ok(chunk))) => {
                for ev in parser.push(&chunk) {
                    push(ev);
                }
            }
            Ok(Some(Err(e))) => {
                push(SseEv::Error(format!("{e}")));
                return;
            }
            Ok(None) => {
                for ev in parser.finish() {
                    push(ev);
                }
                push(SseEv::Done);
                return;
            }
        }
    }
}

/// Incremental Server-Sent Events parser: buffers bytes, splits on newlines,
/// and emits one [`SseEv::Event`] per blank line (a streamed `data:` value
/// spanning several lines is joined with `\n`).
///
/// This is the *transport's* parser: it decodes the body of
/// `agent.api.sse_open`. A request that turns out to answer with
/// `content-type: text/event-stream` is parsed by `new_parser`/`parser_push` in
/// `lua/lib/http.lua` instead, because the decision happens in Lua. Two
/// implementations of one spec, in two languages, on the two sides of that
/// decision — so a change to the spec's edges has to be made in both.
#[derive(Default)]
struct SseParser {
    buf: Vec<u8>,
    event: String,
    data: String,
}

impl SseParser {
    fn push(&mut self, bytes: &[u8]) -> Vec<SseEv> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = self.buf.drain(..=nl).collect();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if let Some(ev) = self.handle_line(&line) {
                out.push(ev);
            }
        }
        out
    }

    /// Flush an unterminated trailing event: any bytes that never ended in a
    /// newline are treated as a final line, then the buffered fields dispatch
    /// (a stream may close without the trailing blank line).
    fn finish(&mut self) -> Vec<SseEv> {
        let tail = std::mem::take(&mut self.buf);
        let mut out = Vec::new();
        if !tail.is_empty() {
            let mut line = tail;
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if let Some(ev) = self.handle_line(&line) {
                out.push(ev);
            }
        }
        if let Some(ev) = self.dispatch() {
            out.push(ev);
        }
        out
    }

    /// One newline-terminated line: `data:`/`event:` fields accumulate into
    /// the current event; a blank line dispatches it; `:...` comments and
    /// `id:`/`retry:` fields are ignored.
    fn handle_line(&mut self, line: &[u8]) -> Option<SseEv> {
        if line.is_empty() {
            self.dispatch()
        } else if line[0] == b':' {
            None
        } else if line.starts_with(b"data:") {
            self.data.push_str(&field_value(&line[5..]));
            self.data.push('\n');
            None
        } else if line.starts_with(b"event:") {
            self.event = field_value(&line[6..]);
            None
        } else {
            // id: / retry: and unknown fields: not needed by this client.
            None
        }
    }

    fn dispatch(&mut self) -> Option<SseEv> {
        if self.data.is_empty() {
            self.event.clear();
            return None;
        }
        while self.data.ends_with('\n') {
            self.data.pop();
        }
        let ev = SseEv::Event {
            event: self.event.clone(),
            data: self.data.clone(),
        };
        self.event.clear();
        self.data.clear();
        Some(ev)
    }
}

/// The value of a `data:` / `event:` field line: everything after the colon,
/// stripping the single optional leading space.
fn field_value(rest: &[u8]) -> String {
    let rest = rest.strip_prefix(b" ").unwrap_or(rest);
    String::from_utf8_lossy(rest).into_owned()
}

fn headers_to_lua(lua: &Lua, hs: &[(String, String)]) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    for (k, v) in hs {
        t.set(k.as_str(), lua.create_string(v.as_str())?)?;
    }
    Ok(t)
}

fn lua_headers_to_vec(t: &Table) -> mlua::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for pair in t.pairs::<Value, Value>() {
        let (k, v) = pair?;
        let k = match &k {
            Value::String(s) => s.to_str()?.to_owned(),
            Value::Integer(i) => i.to_string(),
            Value::Number(n) => n.to_string(),
            other => {
                return Err(mlua::Error::RuntimeError(format!(
                    "agent: header names must be strings, got {}",
                    other.type_name()
                )));
            }
        };
        let v = match &v {
            Value::String(s) => s.to_str()?.to_owned(),
            Value::Integer(i) => i.to_string(),
            Value::Number(n) => n.to_string(),
            other => {
                return Err(mlua::Error::RuntimeError(format!(
                    "agent: header value for {k:?} must be a string or number, got {}",
                    other.type_name()
                )));
            }
        };
        out.push((k, v));
    }
    Ok(out)
}

/// `agent.api.reverse_dns(ip) -> hostname | nil` — the name for a literal
/// address, or `nil` when it has none.
///
/// A reverse lookup, so the *question* a connection raises can name a host rather
/// than only an address: "connect to api.github.com (140.82.121.6)" instead of a
/// bare number the user has to recognize. A miss is normal and cheap — a
/// container's internal address usually has no PTR — and never an error, so a
/// policy can always fall back to the address alone.
fn lua_reverse_dns(_: &Lua, ip: String) -> mlua::Result<Option<String>> {
    let addr: std::net::IpAddr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return Ok(None),
    };
    // A literal loopback/link-local name needs no resolver, and the resolver
    // cannot answer for it anyway.
    if matches!(addr, std::net::IpAddr::V4(v4) if v4.is_loopback()) {
        return Ok(Some("localhost".into()));
    }
    // Port 0 is a placeholder: a reverse lookup keys on the address alone.
    let mut names = match std::net::ToSocketAddrs::to_socket_addrs(&(addr, 0)) {
        Ok(n) => n,
        Err(_) => return Ok(None),
    };
    // A reverse lookup can answer with several names; the first is the canonical
    // one, and the rest are aliases the user does not need to see.
    Ok(names.next().map(|n| n.to_string()))
}

/// `agent.api.http_req(method, url, headers, body, timeout_ms) -> handle`.
///
/// Fires a request as a task on the agent's reactor. The response is consumed through
/// `agent.api.http_step(handle)` (never blocks): `headers` → one or more
/// `chunk`s → `done`, or `error`. `timeout_ms == 0` disables the timeout.
fn lua_http_req(
    _lua: &Lua,
    (method, url, headers, body, timeout_ms): (String, String, Table, mlua::LuaString, i64),
) -> mlua::Result<i64> {
    let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| {
        mlua::Error::RuntimeError(format!("agent.api.http_req: invalid method {method:?}"))
    })?;
    let headers = lua_headers_to_vec(&headers)?;
    let body = String::from_utf8_lossy(&body.as_bytes()).into_owned();
    let t = http_transport();
    let id = t.next_id.fetch_add(1, Ordering::Relaxed);
    let session = Session {
        queue: Arc::new(Mutex::new(VecDeque::new())),
        abort: Arc::new(AtomicBool::new(false)),
    };
    t.posts.lock().unwrap().insert(id, session.clone());
    let spec = HttpReqSpec {
        method,
        url,
        headers,
        body,
        timeout_ms: timeout_ms.max(0) as u64,
        queue: session.queue,
        abort: session.abort,
    };
    // A task on the agent's own reactor. There is no thread to hand this to: the
    // caller is already a coroutine on that reactor, and the response is consumed
    // by polling (`http_step`), never by waiting.
    tokio::spawn(async move {
        http_req_task(http_client().clone(), spec).await;
    });
    Ok(id)
}

/// `agent.api.http_step(handle) -> event | nil` — pop the next buffered event
/// (`{kind="headers", status, headers}`, `{kind="chunk", data}`,
/// `{kind="done"}`, `{kind="error", message}`); `nil` when nothing new has
/// arrived. Popping a terminal event unregisters the handle.
fn lua_http_step(lua: &Lua, handle: i64) -> mlua::Result<Option<Table>> {
    let t = http_transport();
    let queue = t.posts.lock().unwrap().get(&handle).map(|s| s.queue.clone());
    let Some(queue) = queue else {
        return Ok(None);
    };
    let Some(ev) = queue.lock().unwrap().pop_front() else {
        return Ok(None);
    };
    match ev {
        HttpEv::Headers { status, headers } => {
            let tab = lua.create_table()?;
            tab.set("kind", "headers")?;
            tab.set("status", status as i64)?;
            tab.set("headers", headers_to_lua(lua, &headers)?)?;
            Ok(Some(tab))
        }
        HttpEv::Chunk(data) => {
            let tab = lua.create_table()?;
            tab.set("kind", "chunk")?;
            tab.set("data", lua.create_string(data.as_str())?)?;
            Ok(Some(tab))
        }
        // Terminal for both transports, and identical in shape: report it, and
        // unregister so the handle cannot be stepped again. `http_step` and
        // `sse_step` differ only in what they can *also* report.
        HttpEv::Done => {
            drop(queue);
            t.posts.lock().unwrap().remove(&handle);
            terminal_event(lua, "done", None)
        }
        HttpEv::Error(message) => {
            drop(queue);
            t.posts.lock().unwrap().remove(&handle);
            terminal_event(lua, "error", Some(message))
        }
    }
}

/// The two terminal events both routes share, rendered to Lua. One function
/// rather than two: they are the same table apart from the `kind`, and a
/// divergence here would be a bug neither route's test could see, since each
/// tests its own.
fn terminal_event(lua: &Lua, kind: &str, message: Option<String>) -> mlua::Result<Option<Table>> {
    let tab = lua.create_table()?;
    tab.set("kind", kind)?;
    if let Some(message) = message {
        tab.set("message", message)?;
    }
    Ok(Some(tab))
}

/// Abort a session and drop it from `sessions`, reporting whether it was there.
///
/// Both `http_close` and `sse_close` are this, against a different table.
fn close_session<E>(sessions: &Mutex<HashMap<i64, Session<E>>>, handle: i64) -> mlua::Result<bool> {
    let Some(session) = sessions.lock().unwrap().remove(&handle) else {
        return Ok(false);
    };
    session.abort.store(true, Ordering::Relaxed);
    Ok(true)
}

/// `agent.api.http_close(handle) -> bool` — abort the request and drop its
/// queue. The background task unwinds on its next idle poll.
fn lua_http_close(_: &Lua, handle: i64) -> mlua::Result<bool> {
    close_session(&http_transport().posts, handle)
}

/// `agent.api.sse_open(url, headers) -> handle` — open an SSE stream as a task
/// on the agent's reactor. Consume with `agent.api.sse_step`;
/// `Accept: text/event-stream` is the caller's header choice.
fn lua_sse_open(_: &Lua, (url, headers): (String, Table)) -> mlua::Result<i64> {
    let headers = lua_headers_to_vec(&headers)?;
    let t = http_transport();
    let id = t.next_id.fetch_add(1, Ordering::Relaxed);
    let session = Session {
        queue: Arc::new(Mutex::new(VecDeque::new())),
        abort: Arc::new(AtomicBool::new(false)),
    };
    t.sses.lock().unwrap().insert(id, session.clone());
    let queue = session.queue;
    let abort = session.abort;
    let client = http_client().clone();
    tokio::spawn(async move {
        sse_task(client, url, headers, queue, abort).await;
    });
    Ok(id)
}

/// `agent.api.sse_step(handle) -> event | nil` — pop the next buffered SSE event
/// (`{kind="event", event, data}`, `{kind="done"}`, `{kind="error", message}`);
/// `nil` when nothing new has arrived. Popping a terminal event unregisters
/// the handle.
fn lua_sse_step(lua: &Lua, handle: i64) -> mlua::Result<Option<Table>> {
    let t = http_transport();
    let queue = t.sses.lock().unwrap().get(&handle).map(|s| s.queue.clone());
    let Some(queue) = queue else {
        return Ok(None);
    };
    let Some(ev) = queue.lock().unwrap().pop_front() else {
        return Ok(None);
    };
    match ev {
        SseEv::Event { event, data } => {
            let tab = lua.create_table()?;
            tab.set("kind", "event")?;
            tab.set("event", event)?;
            tab.set("data", data)?;
            Ok(Some(tab))
        }
        // The same two terminal tables the request route returns.
        SseEv::Done => {
            drop(queue);
            t.sses.lock().unwrap().remove(&handle);
            terminal_event(lua, "done", None)
        }
        SseEv::Error(message) => {
            drop(queue);
            t.sses.lock().unwrap().remove(&handle);
            terminal_event(lua, "error", Some(message))
        }
    }
}


/// `agent.api.sse_close(handle) -> bool` — abort the stream and drop its queue.
fn lua_sse_close(_: &Lua, handle: i64) -> mlua::Result<bool> {
    close_session(&http_transport().sses, handle)
}

/// `agent.api.sleep(ms)` — block the current Lua thread for `ms` milliseconds.
///
/// Internal. The *public* timer is `agent.on_timeout(ms, fn)`
/// (`lua/lib/on_timeout.lua`), which on a reactor-driven coroutine suspends it
/// and on anything else falls through to this — a real thread sleep, which is
/// the old pump cadence. The reactor path never reaches here.
fn lua_sleep(_: &Lua, ms: i64) -> mlua::Result<()> {
    if ms > 0 {
        std::thread::sleep(Duration::from_millis(ms as u64));
    }
    Ok(())
}

/// Install the JSON text boundary and the HTTP(S) transport primitives into
/// the bridge table (`agent.api`): `json_encode(value) -> text`,
/// `json_decode(text) -> value`, `http_req` / `http_step` / `http_close`,
/// `sse_open` / `sse_step` / `sse_close`, and `sleep(ms)` — the internal
/// thread-sleep fallback for the public `agent.on_timeout` timer. Each is
/// annotated in `lua/api.lua`; the loader refuses a VM whose annotations and
/// this table disagree.
pub fn install_bridge(lua: &Lua, api: &Table) -> mlua::Result<()> {
    api.set("json_encode", lua.create_function(lua_json_encode)?)?;
    api.set("json_decode", lua.create_function(lua_json_decode)?)?;
    api.set("http_req", lua.create_function(lua_http_req)?)?;
    api.set("reverse_dns", lua.create_function(lua_reverse_dns)?)?;
    api.set("http_step", lua.create_function(lua_http_step)?)?;
    api.set("http_close", lua.create_function(lua_http_close)?)?;
    api.set("sse_open", lua.create_function(lua_sse_open)?)?;
    api.set("sse_step", lua.create_function(lua_sse_step)?)?;
    api.set("sse_close", lua.create_function(lua_sse_close)?)?;
    api.set("sleep", lua.create_function(lua_sleep)?)?;
    Ok(())
}

fn lua_json_encode(_: &Lua, value: Value) -> mlua::Result<String> {
    let json = lua_to_json( &value)?;
    serde_json::to_string(&json)
        .map_err(|e| mlua::Error::RuntimeError(format!("agent.api.json_encode: {e}")))
}

fn lua_json_decode(lua: &Lua, text: String) -> mlua::Result<Value> {
    let json: Json = serde_json::from_str(&text)
        .map_err(|e| mlua::Error::RuntimeError(format!("agent.api.json_decode: {e}")))?;
    json_to_lua(lua, &json)
}

/// Lua value → `serde_json` value.
///
/// Mapping rules (the JSON text boundary's contract):
///
/// - `nil`     → `null`
/// - `true`/`false` → booleans
/// - numbers   → JSON numbers (integers preserved; non-finite floats error)
/// - strings   → JSON strings
/// - tables    → a JSON **array** when the keys are exactly `1..n` (dense,
///   `n > 0`); a JSON **object** when the keys are strings (an empty table
///   is `{}`). Mixed or non-dense integer keys error — JSON cannot express
///   them.
/// - functions / userdata / threads → error (not JSON-able)
pub fn lua_to_json(v: &Value) -> mlua::Result<Json> {
    match v {
        Value::Nil => Ok(Json::Null),
        Value::Boolean(b) => Ok(Json::Bool(*b)),
        Value::Integer(i) => Ok(Json::from(*i)),
        Value::Number(n) => {
            let num = serde_json::Number::from_f64(*n).ok_or_else(|| {
                mlua::Error::RuntimeError(format!("agent.api.json_encode: non-finite number {n}"))
            })?;
            Ok(Json::Number(num))
        }
        Value::String(s) => Ok(Json::String(s.to_str()?.to_owned())),
        Value::Table(t) => {
            let mut entries: Vec<(i64, Json)> = Vec::new();
            let mut obj: serde_json::Map<String, Json> = serde_json::Map::new();
            let mut saw_int = false;
            let mut saw_str = false;
            for pair in t.pairs::<Value, Value>() {
                let (k, val) = pair?;
                let j = lua_to_json(&val)?;
                match &k {
                    Value::Integer(i) if *i >= 1 => {
                        saw_int = true;
                        entries.push((*i, j));
                    }
                    Value::String(s) => {
                        saw_str = true;
                        obj.insert(s.to_str()?.to_owned(), j);
                    }
                    other => {
                        return Err(mlua::Error::RuntimeError(format!(
                            "agent.api.json_encode: table key of type {} is not JSON-able \
                             (keys must be strings, or integers 1..n for an array)",
                            other.type_name()
                        )));
                    }
                }
            }
            if saw_int && saw_str {
                return Err(mlua::Error::RuntimeError(
                    "agent.api.json_encode: mixed integer/string keys are not JSON-able".to_string(),
                ));
            }
            if saw_int {
                // Array, but the keys must be exactly 1..n (dense, no holes).
                let n = entries.len();
                let mut arr = vec![Json::Null; n];
                for (i, j) in entries {
                    let idx = usize::try_from(i)
                        .ok()
                        .and_then(|u| u.checked_sub(1))
                        .filter(|u| *u < n)
                        .ok_or_else(|| {
                            mlua::Error::RuntimeError(format!(
                                "agent.api.json_encode: table keys are not a dense 1..{n} array"
                            ))
                        })?;
                    arr[idx] = j;
                }
                Ok(Json::Array(arr))
            } else if saw_str {
                Ok(Json::Object(obj))
            } else {
                Ok(Json::Object(serde_json::Map::new()))
            }
        }
        other => Err(mlua::Error::RuntimeError(format!(
            "agent.api.json_encode: {} is not JSON-able",
            other.type_name()
        ))),
    }
}

/// `serde_json` value → Lua value (the inverse of [`lua_to_json`], mapping
/// `null` → `nil`, numbers → integers when integral, arrays/objects →
/// tables).
pub fn json_to_lua(lua: &Lua, j: &Json) -> mlua::Result<Value> {
    Ok(match j {
        Json::Null => Value::Nil,
        Json::Bool(b) => Value::Boolean(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                Value::Number(f)
            } else {
                return Err(mlua::Error::RuntimeError(format!(
                    "agent.api.json_decode: unrepresentable number {n}"
                )));
            }
        }
        Json::String(s) => Value::String(lua.create_string(s)?),
        Json::Array(a) => {
            let t = lua.create_table()?;
            for (i, e) in a.iter().enumerate() {
                t.raw_set((i as i64) + 1, json_to_lua(lua, e)?)?;
            }
            Value::Table(t)
        }
        Json::Object(o) => {
            let t = lua.create_table()?;
            for (k, e) in o {
                t.raw_set(k.clone(), json_to_lua(lua, e)?)?;
            }
            Value::Table(t)
        }
    })
}

#[cfg(test)]
pub(crate) use tests::{FakeHttpServer, FakeRequest, FakeResponse, FakeServerReply};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::{TcpListener, TcpStream};

    /// A fresh VM with only the JSON boundary installed (no sandbox needed —
    /// the bridge is pure conversion), mounted the way the loader mounts it.
    fn json_vm() -> mlua::Result<mlua::Lua> {
        let lua = mlua::Lua::new();
        let api = lua.create_table()?;
        install_bridge(&lua, &api)?;
        let agent = lua.create_table()?;
        agent.set("api", api)?;
        lua.globals().set("agent", agent)?;
        Ok(lua)
    }

    #[test]
    fn bridge_round_trips_nested_values() {
        let lua = json_vm().expect("vm");
        let ok: bool = lua
            .load(
                r#"
            local enc = agent.api.json_encode({
              a = 1, b = "x", c = true, d = 1.5,
              list = { 1, 2, 3 },
              nested = { k = "v", arr = { false, true } },
            })
            local dec = agent.api.json_decode(enc)
            return dec.a == 1 and dec.b == "x" and dec.c == true and dec.d == 1.5
                   and dec.list[1] == 1 and dec.list[2] == 2 and dec.list[3] == 3
                   and #dec.list == 3
                   and dec.nested.k == "v" and dec.nested.arr[1] == false
                   and dec.nested.arr[2] == true and #dec.nested.arr == 2
            "#,
            )
            .eval()
            .expect("eval");
        assert!(ok, "bridge must round-trip nested Lua values");
    }

    #[test]
    fn bridge_encodes_arrays_objects_and_empty() {
        let lua = json_vm().expect("vm");
        let (seq, obj, empty, nilv): (String, String, String, String) = lua
            .load(
                r#"
            return agent.api.json_encode({ 1, 2, 3 }),
                   agent.api.json_encode({ a = 1, b = 2 }),
                   agent.api.json_encode({}),
                   agent.api.json_encode(nil)
            "#,
            )
            .eval()
            .expect("eval");
        assert_eq!(seq, "[1,2,3]");
        assert_eq!(obj, r#"{"a":1,"b":2}"#);
        assert_eq!(empty, "{}");
        assert_eq!(nilv, "null");
    }

    #[test]
    fn bridge_decode_handles_nested_json() {
        let lua = json_vm().expect("vm");
        // An empty JSON array must decode to a dense sequence (len 0) and an
        // empty object to an empty table.
        let (arr_len, obj_keys): (usize, usize) = lua
            .load(
                r#"
            local arr = agent.api.json_decode('["a", "b"]')
            local obj = agent.api.json_decode('{"x": 1, "y": 2}')
            local empty = agent.api.json_decode('{}')
            local n = 0
            for _ in pairs(empty) do n = n + 1 end
            return #arr, n
            "#,
            )
            .eval()
            .expect("eval");
        assert_eq!(arr_len, 2);
        assert_eq!(obj_keys, 0);
    }

    #[test]
    fn bridge_rejects_bad_keys_and_unsupported_values() {
        let lua = json_vm().expect("vm");
        let (bool_key, func, nan): (bool, bool, bool) = lua
            .load(
                r#"
            local e1 = pcall(agent.api.json_encode, { [true] = 1 })
            local e2 = pcall(agent.api.json_encode, { f = function() end })
            local e3 = pcall(agent.api.json_encode, 0/0)
            return e1 == false, e2 == false, e3 == false
            "#,
            )
            .eval()
            .expect("eval");
        assert!(
            bool_key && func && nan,
            "bad keys / functions / NaN must error"
        );
    }

    #[test]
    fn framing_splits_lines_and_reports_eof() {
        let mut buf: &[u8] = b"hello\nworld\r\nlast";
        assert_eq!(read_line(&mut buf).expect("l1"), Some("hello".into()));
        assert_eq!(read_line(&mut buf).expect("l2"), Some("world".into()));
        assert_eq!(read_line(&mut buf).expect("l3"), Some("last".into()));
        assert_eq!(read_line(&mut buf).expect("eof"), None);

        let mut out: Vec<u8> = Vec::new();
        write_line(&mut out, "{\"a\":1}").expect("w");
        assert_eq!(out, b"{\"a\":1}\n");
    }

    #[test]
    fn message_types_round_trip_on_the_wire() {
        let m = Message::request(
            7,
            "tools/call",
            Some(json!({ "name": "probe_tool", "arguments": { "text": "hi" } })),
        );
        assert_eq!(m.id(), Some(7));
        let line = serde_json::to_string(&m).expect("ser");
        let back: Message = serde_json::from_str(&line).expect("de");
        assert_eq!(back, m);

        let n = Message::notification("notifications/initialized", Some(json!({})));
        assert_eq!(n.id(), None);
        let back: Message =
            serde_json::from_str(&serde_json::to_string(&n).expect("ser")).expect("de");
        assert_eq!(back, n);

        let r = Message::response(7, Some(json!({ "ok": true })), None);
        let back: Message =
            serde_json::from_str(&serde_json::to_string(&r).expect("ser")).expect("de");
        assert_eq!(back, r);
    }

    // ---------------------------------------------------------------------
    // Transport host: a tiny fake HTTP server for the transport tests.
    // ---------------------------------------------------------------------

    #[derive(Debug)]
    pub(crate) struct FakeRequest {
        pub method: String,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }

    #[derive(Debug)]
    pub(crate) struct FakeResponse {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }

    /// A chunk pushed into an open fake stream.
    #[derive(Debug)]
    pub(crate) enum FakeChunk {
        Data(String),
        End,
    }

    pub(crate) enum FakeServerReply {
        /// A single complete response (connection closes afterwards).
        Response(FakeResponse),
        /// An SSE-style streamed reply: write every block, then finish.
        StreamEvents(Vec<String>),
        /// A chunked stream held open; the test pushes `FakeChunk`s through
        /// the slot (the sender appears once the request lands).
        StreamOpen(Arc<Mutex<Option<std::sync::mpsc::Sender<FakeChunk>>>>),
    }

    /// A minimal HTTP server answering every connection with one reply from
    /// the responder closure. Handles one request per connection (reqwest
    /// reconnects), parses the request line, headers, and (when
    /// `Content-Length` is present) the body.
    pub(crate) struct FakeHttpServer {
        pub addr: std::net::SocketAddr,
        stop: Arc<AtomicBool>,
    }

    impl FakeHttpServer {
        pub fn start<F>(responder: F) -> FakeHttpServer
        where
            F: Fn(FakeRequest) -> FakeServerReply + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake http");
            let addr = listener.local_addr().expect("local addr");
            let stop = Arc::new(AtomicBool::new(false));
            let stop2 = stop.clone();
            let responder = Arc::new(responder);
            std::thread::Builder::new()
                .name("fake-http".into())
                .spawn(move || {
                    for conn in listener.incoming() {
                        if stop2.load(Ordering::Relaxed) {
                            break;
                        }
                        if let Ok(stream) = conn {
                            let responder = responder.clone();
                            let _ =
                                std::thread::spawn(move || handle_connection(stream, &*responder));
                        }
                    }
                })
                .expect("spawn fake http thread");
            FakeHttpServer { addr, stop }
        }

        pub fn url(&self, path: &str) -> String {
            format!("http://{}{}", self.addr, path)
        }
    }

    impl Drop for FakeHttpServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    fn read_request(stream: &mut TcpStream) -> Option<FakeRequest> {
        let mut buf: Vec<u8> = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match stream.read(&mut byte) {
                Ok(0) | Err(_) => return None,
                Ok(_) => {
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    if buf.len() > 64 * 1024 {
                        return None;
                    }
                }
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let mut lines = head.lines();
        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_owned();
        let _path = parts.next()?.to_owned();
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut content_length = 0usize;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim().to_owned();
                if k == "content-length" {
                    content_length = v.parse().unwrap_or(0);
                }
                headers.push((k, v));
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            stream.read_exact(&mut body).ok()?;
        }
        Some(FakeRequest {
            method,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }

    fn write_raw(stream: &mut TcpStream, s: &str) -> std::io::Result<()> {
        stream.write_all(s.as_bytes())?;
        stream.flush()
    }

    fn write_chunk(stream: &mut TcpStream, s: &str) -> std::io::Result<()> {
        write!(stream, "{:x}\r\n{}\r\n", s.len(), s)?;
        stream.flush()
    }

    fn handle_connection(
        mut stream: TcpStream,
        responder: &(dyn Fn(FakeRequest) -> FakeServerReply + Send + Sync),
    ) {
        let Some(req) = read_request(&mut stream) else {
            return;
        };
        match responder(req) {
            FakeServerReply::Response(r) => {
                let mut head = format!(
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    r.status,
                    status_reason(r.status),
                    r.body.len()
                );
                for (k, v) in &r.headers {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                let _ = write_raw(&mut stream, &head);
                let _ = write_raw(&mut stream, &r.body);
            }
            FakeServerReply::StreamEvents(events) => {
                let _ = write_raw(
                    &mut stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                     Cache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n",
                );
                for ev in events {
                    if write_chunk(&mut stream, &ev).is_err() {
                        return;
                    }
                }
                let _ = write_raw(&mut stream, "0\r\n\r\n");
            }
            FakeServerReply::StreamOpen(slot) => {
                let _ = write_raw(
                    &mut stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                     Cache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n",
                );
                let (tx, rx) = std::sync::mpsc::channel::<FakeChunk>();
                *slot.lock().unwrap() = Some(tx);
                loop {
                    match rx.recv_timeout(Duration::from_secs(30)) {
                        Ok(FakeChunk::Data(s)) => {
                            if write_chunk(&mut stream, &s).is_err() {
                                return;
                            }
                        }
                        Ok(FakeChunk::End) => {
                            let _ = write_raw(&mut stream, "0\r\n\r\n");
                            return;
                        }
                        Err(_) => return,
                    }
                }
            }
        }
    }

    fn status_reason(status: u16) -> &'static str {
        match status {
            200 => "OK",
            202 => "Accepted",
            204 => "No Content",
            400 => "Bad Request",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "OK",
        }
    }

    // ---------------------------------------------------------------------
    // Transport tests.
    // ---------------------------------------------------------------------

    /// A fresh VM with the bridge (JSON boundary + HTTP transport) mounted on
    /// `agent.api`, the way the loader mounts it.
    fn transport_vm() -> mlua::Result<mlua::Lua> {
        let lua = mlua::Lua::new();
        let api = lua.create_table()?;
        install_bridge(&lua, &api)?;
        let agent = lua.create_table()?;
        agent.set("api", api)?;
        lua.globals().set("agent", agent)?;
        Ok(lua)
    }

    #[test]
    fn sse_parser_assembles_events_across_chunks() {
        let mut p = SseParser::default();
        let evs1 = p.push(b"event: message\ndata: {\"jsonrpc\":\"2.0\",");
        assert!(evs1.is_empty(), "no event yet (incomplete data line)");
        let evs2 = p.push(b"\"id\":7}\n\n");
        assert_eq!(evs2.len(), 1);
        match &evs2[0] {
            SseEv::Event { event, data } => {
                assert_eq!(event, "message");
                assert_eq!(data, r#"{"jsonrpc":"2.0","id":7}"#);
            }
            other => panic!("expected an event, got {other:?}"),
        }
    }

    #[test]
    fn sse_parser_handles_comments_crlf_and_finish() {
        let mut p = SseParser::default();
        let evs = p.push(b": keep-alive\r\ndata: a\r\n\r\nevent: e\ndata: b\r\ndata: c\r\n\r\n");
        assert_eq!(evs.len(), 2);
        match &evs[1] {
            SseEv::Event { event, data } => {
                assert_eq!(event, "e");
                assert_eq!(data, "b\nc");
            }
            other => panic!("expected event, got {other:?}"),
        }
        // An unterminated trailing event is flushed by finish() at EOF.
        let mut p2 = SseParser::default();
        p2.push(b"data: dangling");
        let fin = p2.finish();
        assert_eq!(fin.len(), 1);
        match &fin[0] {
            SseEv::Event { data, .. } => assert_eq!(data, "dangling"),
            other => panic!("expected dangling event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn http_req_streams_response_chunks_then_done() {
        let slot = Arc::new(Mutex::new(None));
        let fake = FakeHttpServer::start({
            let slot = slot.clone();
            move |req: FakeRequest| {
                assert_eq!(req.method, "POST");
                assert_eq!(req.body, "ping");
                FakeServerReply::StreamOpen(slot.clone())
            }
        });
        // Push the body in two pieces with a gap so they cannot coalesce.
        let pusher = std::thread::spawn({
            let slot = slot.clone();
            move || {
                let tx = {
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    loop {
                        if let Some(tx) = slot.lock().unwrap().clone() {
                            break tx;
                        }
                        if std::time::Instant::now() > deadline {
                            panic!("fake server never registered its stream slot");
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                };
                tx.send(FakeChunk::Data("chunk one ".into())).unwrap();
                std::thread::sleep(Duration::from_millis(150));
                tx.send(FakeChunk::Data("chunk two".into())).unwrap();
                std::thread::sleep(Duration::from_millis(10));
                tx.send(FakeChunk::End).unwrap();
            }
        });
        let lua = transport_vm().expect("vm");
        let out: String = crate::lua::eval_reactor(
            &lua,
            &format!(
                r#"
            local id = agent.api.http_req("POST", "{url}", {{}}, "ping", 5000)
            local evs, status = {{}}, nil
            for _ = 1, 10000 do
              local ev = agent.api.http_step(id)
              if ev == nil then
                coroutine.yield({{ __agent_await = "timeout", ms = 2 }})
              elseif ev.kind == "chunk" then
                evs[#evs + 1] = ev.data
              elseif ev.kind == "headers" then
                status = ev.status
              elseif ev.kind == "done" then
                if status ~= 200 then error("unexpected status " .. tostring(status)) end
                return table.concat(evs) .. "|" .. #evs
              elseif ev.kind == "error" then
                error("transport error: " .. ev.message)
              end
            end
            error("stream never finished")
            "#,
                url = fake.url("/"),
            ),
        )
        .await
        .expect("eval");
        pusher.join().expect("pusher");
        let (joined, n) = out.rsplit_once('|').expect("body|nchunks");
        assert_eq!(joined, "chunk one chunk two");
        assert!(
            n.parse::<usize>().unwrap_or(0) >= 2,
            "body must arrive streamed, got {n} chunk event(s)"
        );
    }

    #[tokio::test]
    async fn http_req_reports_transport_error() {
        // A port with nothing listening on it.
        let dead = TcpListener::bind("127.0.0.1:0").expect("bind");
        let dead_addr = dead.local_addr().expect("addr");
        drop(dead);
        let lua = transport_vm().expect("vm");
        let kind: String = crate::lua::eval_reactor(
            &lua,
            &format!(
                r#"
            local id = agent.api.http_req("POST", "http://{addr}/", {{}}, "x", 3000)
            for _ = 1, 5000 do
              local ev = agent.api.http_step(id)
              if ev == nil then
                coroutine.yield({{ __agent_await = "timeout", ms = 2 }})
              elseif ev.kind == "error" then
                return ev.kind
              end
            end
            error("no error surfaced")
            "#,
                addr = dead_addr,
            ),
        )
        .await
        .expect("eval");
        assert_eq!(kind, "error");
    }

    #[tokio::test]
    async fn sse_stream_delivers_events_then_done() {
        let fake = FakeHttpServer::start(|_req: FakeRequest| {
            FakeServerReply::StreamEvents(vec![
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"
                    .to_string(),
                "event: note\ndata: hello\n\n".to_string(),
            ])
        });
        let lua = transport_vm().expect("vm");
        let count: i64 = crate::lua::eval_reactor(
            &lua,
            &format!(
                r#"
            local id = agent.api.sse_open("{url}", {{ ["accept"] = "text/event-stream" }})
            local n = 0
            for _ = 1, 5000 do
              local ev = agent.api.sse_step(id)
              if ev == nil then
                coroutine.yield({{ __agent_await = "timeout", ms = 2 }})
              elseif ev.kind == "event" then
                n = n + 1
              elseif ev.kind == "done" then
                return n
              elseif ev.kind == "error" then
                error("sse error: " .. ev.message)
              end
            end
            error("sse stream never finished")
            "#,
                url = fake.url("/events"),
            ),
        )
        .await
        .expect("eval");
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn sse_close_drops_the_handle() {
        let slot = Arc::new(Mutex::new(None));
        let fake = FakeHttpServer::start({
            let slot = slot.clone();
            move |_req: FakeRequest| FakeServerReply::StreamOpen(slot.clone())
        });
        let lua = transport_vm().expect("vm");
        // Open, close, then step: the handle is gone, so step yields nil and
        // a second close reports false.
        let out: String = crate::lua::eval_reactor(
            &lua,
            &format!(
                r#"
            local id = agent.api.sse_open("{url}", {{}})
            assert(agent.api.sse_close(id) == true, "first close")
            local ev = agent.api.sse_step(id)
            return tostring(ev == nil) .. "|" .. tostring(agent.api.sse_close(id) == false)
            "#,
                url = fake.url("/events"),
            ),
        )
        .await
        .expect("eval");
        let (stepped, closed) = out.rsplit_once('|').expect("stepped|closed");
        assert_eq!(stepped, "true", "step after close must be nil");
        assert_eq!(closed, "true", "second close must report false");
    }
}
