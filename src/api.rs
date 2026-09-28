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
    pub fn tokens(&self) -> agent::lua::Usage {
        let n = |v: &Value, key: &str| v.get(key).and_then(Value::as_u64);
        if let Some(u) = &self.usage {
            return agent::lua::Usage {
                prompt: n(u, "prompt_tokens"),
                completion: n(u, "completion_tokens"),
            };
        }
        if let Some(t) = &self.timings {
            return agent::lua::Usage {
                prompt: n(t, "prompt_n"),
                completion: n(t, "predicted_n"),
            };
        }
        agent::lua::Usage::default()
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
        let mut tool_calls: Vec<ToolCall> = self
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
        // Server may deliver deltas out of order per `index`; sort for stability.
        tool_calls.sort_by(|a, b| a.id.cmp(&b.id));
        Turn {
            content: self.content,
            tool_calls,
            usage: self.usage,
            timings: self.timings,
        }
    }
}

/// Parse one SSE `data:` payload into a list of caller-visible events.
/// Pure: no printing, no side effects beyond `acc` bookkeeping.
/// The payload of one SSE `data:` line, or `None` when the line is not one:
/// a different field, the `[DONE]` sentinel, or an empty payload.
fn sse_payload(line: &str) -> Option<&str> {
    line.strip_prefix("data:")
        .map(str::trim)
        .filter(|payload| *payload != "[DONE]" && !payload.is_empty())
}

fn acc_sse(payload: &str, acc: &mut TurnAccState) -> Vec<TurnEvent> {
    let mut events = Vec::new();
    let Ok(evt) = serde_json::from_str::<Value>(payload) else {
        return events;
    };
    let ch = &evt["choices"][0];

    if let Some(d) = ch["delta"]["content"].as_str() {
        acc.content.push_str(d);
        events.push(TurnEvent::Content(d.to_string()));
    }
    if let Some(d) = ch["delta"]["reasoning_content"].as_str() {
        acc.reasoning.push_str(d);
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
                acc.note_tool_delta(&delta);
                events.push(TurnEvent::ToolCallDelta(delta));
            }
        }
    }
    if let Some(u) = evt.get("usage") {
        acc.usage = Some(u.clone());
        events.push(TurnEvent::Usage(u.clone()));
    }
    // llama.cpp reports timing/token stats in the final chunk instead of `usage`.
    if let Some(t) = evt.get("timings") {
        acc.timings = Some(t.clone());
        events.push(TurnEvent::Timings(t.clone()));
    }
    events
}

/// Internal bookkeeping for one SSE stream (feed by `acc_sse`).
struct TurnAccState {
    content: String,
    reasoning: String,
    tool_calls: Vec<ToolCallAcc>,
    usage: Option<Value>,
    timings: Option<Value>,
}

impl TurnAccState {
    fn new() -> Self {
        Self {
            content: String::new(),
            reasoning: String::new(),
            tool_calls: Vec::new(),
            usage: None,
            timings: None,
        }
    }

    fn note_tool_delta(&mut self, delta: &ToolCallDelta) {
        while self.tool_calls.len() <= delta.index {
            self.tool_calls.push(ToolCallAcc::default());
        }
        let slot = &mut self.tool_calls[delta.index];
        if let Some(id) = delta.id.as_ref().filter(|id| !id.is_empty()) {
            slot.id = id.clone();
        }
        if let Some(n) = &delta.name {
            slot.name = n.clone();
        }
        if let Some(a) = &delta.arguments {
            slot.arguments.push_str(a);
        }
    }
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
        Self {
            client: Client::new(),
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
            let mut acc = TurnAccState::new();

            while let Some(chunk) = byte_stream.next().await {
                let chunk = chunk.context("reading response stream")?;
                for &b in chunk.iter() {
                    if b == b'\n' {
                        let line = String::from_utf8_lossy(&line_buf).trim().to_string();
                        if let Some(payload) = sse_payload(&line) {
                            for event in acc_sse(payload, &mut acc) {
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
                    for event in acc_sse(payload, &mut acc) {
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

    #[test]
    fn assembles_content_across_fragments() {
        let mut acc = TurnAccState::new();
        acc_sse(r#"{"choices":[{"delta":{"content":"Hel"}}]}"#, &mut acc);
        acc_sse(r#"{"choices":[{"delta":{"content":"lo"}}]}"#, &mut acc);
        assert_eq!(acc.content, "Hello");
    }

    #[test]
    fn collects_reasoning_separately() {
        let mut acc = TurnAccState::new();
        acc_sse(
            r#"{"choices":[{"delta":{"reasoning_content":"think "}}]}"#,
            &mut acc,
        );
        acc_sse(
            r#"{"choices":[{"delta":{"reasoning_content":"hard"}}]}"#,
            &mut acc,
        );
        assert_eq!(acc.reasoning, "think hard");
        assert!(acc.content.is_empty());
    }

    #[test]
    fn assembles_tool_call_across_deltas() {
        let mut acc = TurnAccState::new();
        // id + name arrive on the first delta
        acc_sse(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"probe_tool","arguments":""}}]}}]}"#,
            &mut acc,
        );
        // arguments arrive as fragments
        acc_sse(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"a\":"}}]}}]}"#,
            &mut acc,
        );
        acc_sse(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"4,\"b\":5}"}}]}}]}"#,
            &mut acc,
        );

        assert_eq!(acc.tool_calls.len(), 1);
        let call = &acc.tool_calls[0];
        assert_eq!(call.id, "call_1");
        assert_eq!(call.name, "probe_tool");
        assert_eq!(call.arguments, r#"{"a":4,"b":5}"#);
    }

    #[test]
    fn tracks_timings_and_usage() {
        let mut acc = TurnAccState::new();
        acc_sse(
            r#"{"choices":[{"delta":{"content":"x"}}],"usage":{"total_tokens":7}}"#,
            &mut acc,
        );
        acc_sse(
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"timings":{"predicted_n":9}}"#,
            &mut acc,
        );
        assert_eq!(acc.usage.as_ref().unwrap()["total_tokens"], 7);
        assert_eq!(acc.timings.as_ref().unwrap()["predicted_n"], 9);
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

    #[test]
    fn stats_survive_event_to_turn_path() {
        // Regression: stats must ride the event stream, not just `TurnAccState`.
        let mut acc = TurnAccState::new();
        let mut events = acc_sse(
            r#"{"choices":[{"delta":{"content":"x"}}],"usage":{"total_tokens":7}}"#,
            &mut acc,
        );
        events.extend(acc_sse(
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"timings":{"predicted_n":9,"predicted_per_second":114.0}}"#,
            &mut acc,
        ));

        let mut builder = TurnBuilder::new();
        for event in events {
            builder.apply(event);
        }
        let turn = builder.finish();
        assert_eq!(turn.usage.as_ref().unwrap()["total_tokens"], 7);
        assert_eq!(turn.timings.as_ref().unwrap()["predicted_n"], 9);
        let summary = turn.summary().unwrap();
        assert!(summary.contains("9 tokens"), "summary was: {summary}");
        assert!(summary.contains("114 tok/s"), "summary was: {summary}");
    }
}
