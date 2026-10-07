//! Server-communicating logic for chat completions: tool definitions,
//! connection config, request plumbing, SSE parsing, and turn accounting.
//!
//! This module performs **no stdio** in production code paths: streamed
//! tokens are surfaced to the caller as [`TurnEvent`]s on an async stream,
//! and the caller decides what to print or buffer. The only stdio that may
//! ever appear here is debugging output inside `#[cfg(test)]` code.

use anyhow::{Context, Result};
use async_stream::stream;
use futures_util::{Stream, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::pin::Pin;

// ---------------------------------------------------------------------------
// Tool definitions (pure API-level: shapes + request plumbing; no execution,
// no agent decision logic).
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct FunctionDef {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ToolDef {
    #[serde(rename = "type")]
    pub kind: String, // "function"
    pub function: FunctionDef,
}

// ---------------------------------------------------------------------------
// Connection config (environment-driven).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ChatConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
}

impl ChatConfig {
    pub fn from_env() -> Self {
        Self {
            base_url: std::env::var("AGENT_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com/v1".to_string()),
            api_key: std::env::var("AGENT_API_KEY").unwrap_or_else(|_| String::new()),
            model: std::env::var("AGENT_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Streamed turn events: what the caller observes while a turn is in flight.
// ---------------------------------------------------------------------------

/// One fragment of a streamed tool call. `id`/`name` typically arrive in the
/// first delta for an `index`; `arguments` arrive as JSON-string fragments.
#[derive(Debug, Clone)]
pub struct ToolCallDelta {
    pub index: usize,
    pub id: Option<String>,
    pub name: Option<String>,
    pub arguments: Option<String>,
}

/// Everything the caller may want to observe during one streamed turn.
/// The stream ends when the response is fully consumed; aggregate the
/// fragments with [`TurnBuilder`] to recover the completed [`Turn`].
#[derive(Debug, Clone)]
pub enum TurnEvent {
    /// A fragment of the model's visible answer.
    Content(String),
    /// A fragment of the model's reasoning (kept out of conversation history).
    Reasoning(String),
    /// A fragment of a requested tool call.
    ToolCallDelta(ToolCallDelta),
    /// OpenAI-style usage stats, when the server reports them (final chunk).
    Usage(Value),
    /// llama.cpp timing/token stats, when the server reports them (final chunk).
    Timings(Value),
}

// ---------------------------------------------------------------------------
// Turn accounting: a single request + streamed response.
// ---------------------------------------------------------------------------

/// Raw streamed tool call being assembled from delta chunks.
#[derive(Default)]
struct ToolCallAcc {
    id: String,
    name: String,
    arguments: String, // accumulated raw JSON-string fragments
}

impl ToolCallAcc {
    fn has_anything(&self) -> bool {
        !self.name.is_empty() || !self.arguments.is_empty()
    }
}

/// Completed tool call, ready to be echoed back to the server as
/// `{"role":"assistant","tool_calls":[...]}`.
#[derive(Clone, Debug)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

/// Everything produced by one streamed chat turn.
#[derive(Debug)]
pub struct Turn {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    /// OpenAI-style usage, when the server reports it (non-streaming mostly).
    pub usage: Option<Value>,
    /// llama.cpp timing/token stats, when the server reports it (streaming).
    pub timings: Option<Value>,
}

impl Turn {
    /// True when the model requested tool usage instead of (or before) answering.
    pub fn wants_tools(&self) -> bool {
        !self.tool_calls.is_empty()
    }

    /// The token counts this turn reported, in whichever dialect the server
    /// speaks: an OpenAI-compatible `usage` block (`prompt_tokens` /
    /// `completion_tokens`) or llama.cpp's `timings` (`prompt_n` /
    /// `predicted_n`). `None` on a half the server did not mention, and both
    /// `None` when it mentioned neither — which is what `agent.llm.usage.reported`
    /// says to Lua.
    pub fn tokens(&self) -> crate::lua::Usage {
        let n = |v: &Value, key: &str| v.get(key).and_then(Value::as_u64);
        if let Some(u) = &self.usage {
            return crate::lua::Usage {
                prompt: n(u, "prompt_tokens"),
                completion: n(u, "completion_tokens"),
            };
        }
        if let Some(t) = &self.timings {
            return crate::lua::Usage {
                prompt: n(t, "prompt_n"),
                completion: n(t, "predicted_n"),
            };
        }
        crate::lua::Usage::default()
    }

    /// One-line token/timing summary, if the server reported one. No stdio.
    pub fn summary(&self) -> Option<String> {
        if let Some(t) = &self.timings {
            let n = t["predicted_n"].as_u64();
            let pps = t["predicted_per_second"].as_f64();
            match (n, pps) {
                (Some(n), Some(pps)) => Some(format!("--- {n} tokens, {pps:.0} tok/s ---")),
                _ => Some(serde_json::to_string_pretty(t).unwrap_or_default()),
            }
        } else {
            self.usage
                .as_ref()
                .map(|u| serde_json::to_string_pretty(u).unwrap_or_default())
        }
    }
}

/// Build the assistant message carrying the requested tool calls (echoed back
/// to the server so it can "see" the calls it made).
pub fn assistant_tool_message(calls: &[ToolCall]) -> Value {
    let calls: Vec<Value> = calls
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "type": "function",
                "function": {"name": c.name, "arguments": c.arguments},
            })
        })
        .collect();
    json!({"role": "assistant", "content": null, "tool_calls": calls})
}

/// Accumulates [`TurnEvent`]s into a completed [`Turn`].
#[derive(Default)]
pub struct TurnBuilder {
    content: String,
    tool_calls: Vec<ToolCallAcc>,
    usage: Option<Value>,
    timings: Option<Value>,
}

impl TurnBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, event: TurnEvent) {
        match event {
            TurnEvent::Content(d) => self.content.push_str(&d),
            TurnEvent::Reasoning(_) => {} // observed only; not kept in history
            TurnEvent::Usage(u) => self.usage = Some(u),
            TurnEvent::Timings(t) => self.timings = Some(t),
            TurnEvent::ToolCallDelta(d) => {
                while self.tool_calls.len() <= d.index {
                    self.tool_calls.push(ToolCallAcc::default());
                }
                let slot = &mut self.tool_calls[d.index];
                if let Some(id) = d.id.filter(|id| !id.is_empty()) {
                    slot.id = id;
                }
                if let Some(n) = d.name {
                    slot.name = n;
                }
                if let Some(a) = d.arguments {
                    slot.arguments.push_str(&a);
                }
            }
        }
    }

    pub fn finish(self) -> Turn {
        let tool_calls: Vec<ToolCall> = self
            .tool_calls
            .into_iter()
            .filter(|c| c.has_anything())
            .map(|c| ToolCall {
                id: if c.id.is_empty() {
                    "call_0".into()
                } else {
                    c.id
                },
                name: c.name,
                arguments: c.arguments.trim().into(),
            })
            .collect();
        // Order is the *index* order, and it is already: `self.tool_calls` is
        // indexed by `d.index`, so a call's slot is where the stream said it was,
        // however the payloads were interleaved.
        //
        // This used to sort by **id string**, on the reasoning that a server
        // "may deliver deltas out of order per `index`". That reasoning is wrong
        // in both halves: the vector is indexed by `index`, so ordering is
        // structural and needs no help; and ids are opaque — `toolu_01H…`,
        // `call_abc123` — so sorting by one scrambles a parallel group into an
        // order the model never chose. Servers match results by id and mostly do
        // not care, but a group that must be answered together is answered in
        // the order it was asked in, and that is not this code's to rearrange.
        Turn {
            content: self.content,
            tool_calls,
            usage: self.usage,
            timings: self.timings,
        }
    }
}

/// The payload of one SSE `data:` line, or `None` when the line is not one:
/// a different field, the `[DONE]` sentinel, or an empty payload.
fn sse_payload(line: &str) -> Option<&str> {
    line.strip_prefix("data:")
        .map(str::trim)
        .filter(|payload| *payload != "[DONE]" && !payload.is_empty())
}

/// Turn one SSE `data:` payload into the caller-visible events it carries.
///
/// Pure: it parses and nothing else. Accumulation is [`TurnBuilder`]'s job, and
/// it is the *only* accumulator — this function used to keep a second one
/// (`TurnAccState`) alongside it, which no production code ever read.
///
/// Public because the binary is a separate crate and the loop's own tests need
/// to drive it: where an assistant turn becomes request history is `main.rs`,
/// and the ordering there is exactly what a provider rejects when it is wrong. A
/// test that cannot reach the parser cannot drive the loop.
pub fn acc_sse(payload: &str) -> Vec<TurnEvent> {
    let mut events = Vec::new();
    let Ok(evt) = serde_json::from_str::<Value>(payload) else {
        return events;
    };
    let ch = &evt["choices"][0];

    if let Some(d) = ch["delta"]["content"].as_str() {
        events.push(TurnEvent::Content(d.to_string()));
    }
    if let Some(d) = ch["delta"]["reasoning_content"].as_str() {
        events.push(TurnEvent::Reasoning(d.to_string()));
    }
    // Tool calls stream as: delta.tool_calls[i].{index,id,function.name,function.arguments}
    if let Some(tcs) = ch["delta"]["tool_calls"].as_array() {
        for tc in tcs {
            let delta = ToolCallDelta {
                index: tc["index"].as_u64().unwrap_or(0) as usize,
                id: tc["id"].as_str().map(str::to_string),
                name: tc["function"]["name"].as_str().map(str::to_string),
                arguments: tc["function"]["arguments"].as_str().map(str::to_string),
            };
            if delta.id.is_some() || delta.name.is_some() || delta.arguments.is_some() {
                events.push(TurnEvent::ToolCallDelta(delta));
            }
        }
    }
    if let Some(u) = evt.get("usage") {
        events.push(TurnEvent::Usage(u.clone()));
    }
    // llama.cpp reports timing/token stats in the final chunk instead of `usage`.
    if let Some(t) = evt.get("timings") {
        events.push(TurnEvent::Timings(t.clone()));
    }
    events
}

// ---------------------------------------------------------------------------
// Chat client: owns the connection parameters and drives one turn at a time.
// ---------------------------------------------------------------------------

/// A stream of [`TurnEvent`]s for a single request; ends when the SSE body is
/// fully consumed. Errors surface as `Err` stream items.
pub type TurnStream = Pin<Box<dyn Stream<Item = Result<TurnEvent, anyhow::Error>> + Send>>;

pub struct Chat {
    client: Client,
    url: String,
    api_key: String,
    model: String,
    tools: Vec<ToolDef>,
}

impl Chat {
    pub fn connect(config: &ChatConfig, tools: Vec<ToolDef>) -> Self {
        Self::connect_with(Client::new(), config, tools)
    }

    /// [`Chat::connect`] over a caller-supplied HTTP client.
    ///
    /// `reqwest::Client` owns a connection pool and a client is meant to outlive a
    /// request, so building one per turn throws the pool away every time — which is
    /// invisible for the main loop's one client and wasteful for a nested turn, where
    /// a client is constructed per request precisely because model, endpoint and tool
    /// set are arguments. `Client` is a handle over shared state, so cloning one per
    /// turn is cheap and the connections are kept.
    pub fn connect_with(client: Client, config: &ChatConfig, tools: Vec<ToolDef>) -> Self {
        Self {
            client,
            url: format!("{}/chat/completions", config.base_url.trim_end_matches('/')),
            api_key: config.api_key.clone(),
            model: config.model.clone(),
            tools,
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.url
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn tools(&self) -> &[ToolDef] {
        &self.tools
    }

    /// Fire one chat completion request and return a stream of events.
    ///
    /// The HTTP request itself is sent (and errors checked) here; the returned
    /// stream only parses the SSE body, so it is pure and stdio-free.
    pub async fn stream_turn(&self, messages: &[Value]) -> Result<TurnStream> {
        let mut request = self.client.post(&self.url);
        if !self.api_key.is_empty() {
            request = request.bearer_auth(&self.api_key);
        }

        let body = json!({
            "model": self.model,
            "messages": messages,
            "stream": true,
            "tools": self.tools,
            "tool_choice": "auto",
        });

        let response = request
            .json(&body)
            .send()
            .await
            .with_context(|| format!("request to {} failed", self.url))?;

        let status = response.status();
        if !status.is_success() {
            let err: Value = response
                .json()
                .await
                .context("decoding JSON error response body")?;
            anyhow::bail!("server error {status}: {err}");
        }

        let byte_stream = response.bytes_stream();

        let events = stream! {
            let mut byte_stream = byte_stream;
            let mut line_buf: Vec<u8> = Vec::with_capacity(4096);

            while let Some(chunk) = byte_stream.next().await {
                let chunk = chunk.context("reading response stream")?;
                for &b in chunk.iter() {
                    if b == b'\n' {
                        let line = String::from_utf8_lossy(&line_buf).trim().to_string();
                        if let Some(payload) = sse_payload(&line) {
                            for event in acc_sse(payload) {
                                yield Ok(event);
                            }
                        }
                        line_buf.clear();
                    } else {
                        line_buf.push(b);
                    }
                }
            }
            // Trailing line without a newline at EOF.
            if !line_buf.is_empty() {
                let line = String::from_utf8_lossy(&line_buf).trim().to_string();
                if let Some(payload) = sse_payload(&line) {
                    for event in acc_sse(payload) {
                        yield Ok(event);
                    }
                }
            }
        };

        Ok(Box::pin(events))
    }
}

// ---------------------------------------------------------------------------
// Tests: pure SSE parsing. (The only place stdio may appear in this file.)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse SSE payloads into a finished [`Turn`], the way the loop does:
    /// every event `acc_sse` produces, through `TurnBuilder`, and nothing else.
    /// A test that fed a second accumulator instead would prove a path the
    /// product never takes.
    fn turn_of(payloads: &[&str]) -> Turn {
        let mut builder = TurnBuilder::new();
        for payload in payloads {
            for event in acc_sse(payload) {
                builder.apply(event);
            }
        }
        builder.finish()
    }

    #[test]
    fn assembles_content_across_fragments() {
        let turn = turn_of(&[
            r#"{"choices":[{"delta":{"content":"Hel"}}]}"#,
            r#"{"choices":[{"delta":{"content":"lo"}}]}"#,
        ]);
        assert_eq!(turn.content, "Hello");
    }

    /// Reasoning is *surfaced* but not *kept*: it is drawn live and never
    /// enters conversation history, so [`TurnBuilder::apply`] drops it. Pinned
    /// because the events still have to arrive — the reasoning block is drawn
    /// from the stream, not from the finished turn.
    #[test]
    fn reasoning_reaches_the_caller_but_never_the_turn() {
        let mut seen = Vec::new();
        for event in acc_sse(r#"{"choices":[{"delta":{"reasoning_content":"think "}}]}"#)
            .into_iter()
            .chain(acc_sse(
                r#"{"choices":[{"delta":{"reasoning_content":"hard"}}]}"#,
            ))
        {
            if let TurnEvent::Reasoning(d) = &event {
                seen.push(d.clone());
            }
        }
        assert_eq!(seen, ["think ", "hard"], "the caller sees every fragment");

        let turn = turn_of(&[
            r#"{"choices":[{"delta":{"reasoning_content":"think "}}]}"#,
            r#"{"choices":[{"delta":{"content":"answer"}}]}"#,
        ]);
        assert_eq!(turn.content, "answer", "the answer is kept");
        assert!(
            !turn.content.contains("think"),
            "and the reasoning never leaks into it: {}",
            turn.content
        );
    }

    #[test]
    fn assembles_tool_call_across_deltas() {
        let turn = turn_of(&[
            // id + name arrive on the first delta
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"probe_tool","arguments":""}}]}}]}"#,
            // arguments arrive as fragments
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"a\":"}}]}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"4,\"b\":5}"}}]}}]}"#,
        ]);

        assert_eq!(turn.tool_calls.len(), 1);
        let call = &turn.tool_calls[0];
        assert_eq!(call.id, "call_1");
        assert_eq!(call.name, "probe_tool");
        assert_eq!(call.arguments, r#"{"a":4,"b":5}"#);
    }

    #[test]
    fn tracks_timings_and_usage() {
        let turn = turn_of(&[
            r#"{"choices":[{"delta":{"content":"x"}}],"usage":{"total_tokens":7}}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"timings":{"predicted_n":9}}"#,
        ]);
        assert_eq!(turn.usage.as_ref().unwrap()["total_tokens"], 7);
        assert_eq!(turn.timings.as_ref().unwrap()["predicted_n"], 9);
    }

    #[test]
    fn build_recovers_turn_from_events() {
        let mut builder = TurnBuilder::new();
        builder.apply(TurnEvent::Content("Hi".into()));
        builder.apply(TurnEvent::ToolCallDelta(ToolCallDelta {
            index: 0,
            id: Some("c1".into()),
            name: Some("probe_tool".into()),
            arguments: Some(r#"{"a":1,"b":2}"#.into()),
        }));
        let turn = builder.finish();
        assert_eq!(turn.content, "Hi");
        assert!(turn.wants_tools());
        assert_eq!(turn.tool_calls[0].name, "probe_tool");
        assert_eq!(turn.tool_calls[0].arguments, r#"{"a":1,"b":2}"#);
    }

    /// A payload the server never meant for us is dropped, not turned into an
    /// empty event: an unparseable line, and the `[DONE]` sentinel.
    #[test]
    fn unparseable_and_sentinel_lines_yield_nothing() {
        assert!(acc_sse("not json at all").is_empty());
        assert!(
            sse_payload("data: [DONE]").is_none(),
            "the sentinel is not a payload"
        );
        assert!(sse_payload("data: ").is_none(), "nor is an empty one");
        assert!(
            sse_payload("event: ping").is_none(),
            "nor another SSE field"
        );
        assert_eq!(sse_payload("data: {}"), Some("{}"));
    }

    #[test]
    fn stats_survive_event_to_turn_path() {
        // Regression: stats must ride the event stream, all the way to the turn
        // the summary line and `agent.llm.usage` read.
        let turn = turn_of(&[
            r#"{"choices":[{"delta":{"content":"x"}}],"usage":{"total_tokens":7}}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"timings":{"predicted_n":9,"predicted_per_second":114.0}}"#,
        ]);
        assert_eq!(turn.usage.as_ref().unwrap()["total_tokens"], 7);
        assert_eq!(turn.timings.as_ref().unwrap()["predicted_n"], 9);
        let summary = turn.summary().unwrap();
        assert!(summary.contains("9 tokens"), "summary was: {summary}");
        assert!(summary.contains("114 tok/s"), "summary was: {summary}");

        // `tokens()` reads whichever dialect the server spoke. This turn carried
        // an OpenAI `usage` block *and* llama.cpp `timings`; `usage` wins,
        // and this payload's `total_tokens` is not a count `tokens()` can map,
        // so both halves are `None` — the shape `agent.llm.usage.reported`
        // reports as "the server said nothing usable".
        let usage_only = turn_of(&[
            r#"{"choices":[{"delta":{"content":"x"}}],"usage":{"prompt_tokens":11,"completion_tokens":4}}"#,
        ]);
        let t = usage_only.tokens();
        assert_eq!(t.prompt, Some(11));
        assert_eq!(t.completion, Some(4));
        assert_eq!(turn.tokens(), crate::lua::Usage::default());
    }
    /// Two tool calls in ONE assistant message — the "parallel tool call" shape —
    /// must accumulate as two calls, each keeping its own id, name and arguments.
    ///
    /// The shape providers stream for it: a call announced with id, name and the
    /// first sliver of its arguments; the second call announced in the *same*
    /// payload, which several do; then the argument chunks **interleaved**, each
    /// addressed by `index` rather than by position in the array.
    ///
    /// The payloads are built rather than written out because they are nested JSON —
    /// the arguments are JSON *inside* the delta, inside the choices array — and
    /// hand-writing that escaping is how a test ends up asserting on its own typos.
    /// The chunk arguments are raw strings for the same reason: they are JSON text,
    /// and every level of escaping between the test and the payload is another place
    /// to lose a quote.
    #[test]
    fn parallel_tool_calls_accumulate_into_separate_calls() {
        /// One `data:` payload announcing or extending one tool call.
        fn delta(index: usize, id: Option<&str>, name: Option<&str>, args: Option<&str>) -> String {
            let mut tc = format!("{{\"index\":{index}");
            if let Some(id) = id {
                tc.push_str(&format!(",\"id\":\"{id}\",\"type\":\"function\""));
            }
            if name.is_some() || args.is_some() {
                tc.push_str(",\"function\":{");
                if let Some(n) = name {
                    tc.push_str(&format!("\"name\":\"{n}\""));
                    if args.is_some() {
                        tc.push(',');
                    }
                }
                if let Some(a) = args {
                    // The arguments are themselves JSON text, so they go in as a JSON
                    // string: quotes and backslashes in the chunk are escaped once,
                    // here, and nowhere else.
                    let escaped = a.replace('\\', "\\\\").replace('"', "\\\"");
                    tc.push_str(&format!("\"arguments\":\"{escaped}\""));
                }
                tc.push('}');
            }
            tc.push('}');
            format!("{{\"choices\":[{{\"delta\":{{\"tool_calls\":[{tc}]}}}}]}}")
        }

        let payloads = [
            // Call 0 announced, with the first sliver of its arguments.
            delta(0, Some("call_a"), Some("fs.read"), Some(r#"{"path":""#)),
            // Call 1 announced in the *same* payload, as several providers do.
            delta(1, Some("call_b"), Some("bash.bash"), Some(r#"{"cmd":""#)),
            // Argument chunks, interleaved and out of issue order.
            delta(1, None, None, Some(r#"ls"}"#)),
            delta(0, None, None, Some(r#"/a"}"#)),
        ];

        let mut b = TurnBuilder::new();
        for p in &payloads {
            for ev in acc_sse(p) {
                b.apply(ev);
            }
        }
        let turn = b.finish();

        assert!(
            turn.wants_tools(),
            "two tool calls means the turn wants tools"
        );
        let got: Vec<(String, String, String)> = turn
            .tool_calls
            .iter()
            .map(|c| (c.id.clone(), c.name.clone(), c.arguments.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    "call_a".to_string(),
                    "fs.read".to_string(),
                    r#"{"path":"/a"}"#.to_string()
                ),
                (
                    "call_b".to_string(),
                    "bash.bash".to_string(),
                    r#"{"cmd":"ls"}"#.to_string()
                ),
            ],
            "both calls, each with its own id, name and *complete* arguments — the \
         interleaved chunks must land on the call that owns the index, or a tool \
         is handed the other call's arguments"
        );
    }

    /// The calls keep the order the model asked for them in, whatever their ids.
    ///
    /// `finish` sorted by **id string**, which is arbitrary: providers mint ids like
    /// `toolu_01H…` or `call_abc123`, so two calls issued B-then-A come back A-then-B.
    /// Most servers match results by id and never notice — but the order is not the
    /// model's to lose, and re-sorting by an opaque string buys nothing.
    ///
    /// Asserted with ids whose lexicographic order is the *reverse* of the issue
    /// order, so a sort by id cannot pass by accident.
    #[test]
    fn parallel_tool_calls_keep_the_order_they_were_issued_in() {
        let payloads = [
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_z","type":"function","function":{"name":"bash.bash","arguments":"{}"}}]}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_a","type":"function","function":{"name":"fs.read","arguments":"{}"}}]}}]}"#,
        ];
        let mut b = TurnBuilder::new();
        for p in payloads {
            for ev in acc_sse(p) {
                b.apply(ev);
            }
        }
        let ids: Vec<String> = b.finish().tool_calls.into_iter().map(|c| c.id).collect();
        assert_eq!(
            ids,
            vec!["call_z".to_string(), "call_a".to_string()],
            "issue order, not id order — `call_z` was asked first and sorting by id \
         would put it second"
        );
    }
}
