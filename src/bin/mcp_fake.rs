//! A minimal MCP stdio server — the reference implementation for exercising
//! the Lua MCP client (`agent.mcp` in `src/lua.rs`) and the JSON text
//! boundary (`src/mcp.rs`).
//!
//! Speaks the MCP stdio transport (JSON-RPC 2.0, one message per line) and
//! advertises a fixed tool set: `sum` (adds two numbers) and `fail` (a
//! result with `isError`).
//!
//! Run it under the sandbox and wire it into the Lua MCP client with a
//! transport func: `func(request_json, on_streaming_response_json)` carries
//! each request to the server and streams the reply lines (one JSON-RPC
//! message per stdout line) back through the callback:
//!
//! ```lua
//! -- func: send request_json to the server, feed every completed reply line
//! -- into on_streaming_response_json (see src/lua.rs for the full contract)
//! agent.mcps.demo = agent.mcp("demo", function(request_json, on_streaming_response_json)
//!   -- ... spawn "target/debug/mcp_fake" with agent.bash, forward each
//!   -- stdout line (framed as a full JSON-RPC message) into the callback ...
//! end)
//! print(agent.mcps.demo.sum({ a = 2, b = 40 }).result.content[1].text)
//! ```

use std::io::BufReader;

use anyhow::Context;
use serde_json::{Value as Json, json};

use agent::mcp::{self, Message, RpcError};

fn main() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    while let Some(line) = mcp::read_line(&mut reader)? {
        let msg: Message =
            serde_json::from_str(&line).with_context(|| format!("bad request line: {line:?}"))?;
        let Some(id) = msg.id() else {
            continue; // notifications: nothing to reply to
        };
        let reply = match &msg {
            Message::Request { method, params, .. } => {
                handle_request(id, method, params.as_ref()).context(method.clone())?
            }
            _ => continue, // servers never answer responses
        };
        mcp::write_line(&mut out, &serde_json::to_string(&reply)?)?;
    }
    Ok(())
}

fn handle_request(id: mcp::RpcId, method: &str, params: Option<&Json>) -> anyhow::Result<Json> {
    let params = params.cloned().unwrap_or_else(|| json!({}));
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-03-26",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "mcp_fake", "version": "0.1.0" },
        }),
        "tools/list" => json!({
            "tools": [
                {
                    "name": "sum",
                    "description": "add two numbers",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "a": { "type": "number" },
                            "b": { "type": "number" },
                        },
                        "required": ["a", "b"],
                    },
                },
                {
                    "name": "fail",
                    "description": "always fail",
                    "inputSchema": { "type": "object" },
                },
            ]
        }),
        "ping" => json!({}),
        "tools/call" => {
            let name = params.get("name").and_then(Json::as_str).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match name {
                "sum" => {
                    let a = args.get("a").and_then(Json::as_f64).unwrap_or(0.0);
                    let b = args.get("b").and_then(Json::as_f64).unwrap_or(0.0);
                    json!({
                        "content": [{ "type": "text", "text": (a + b).to_string() }],
                        "isError": false,
                    })
                }
                "fail" => json!({ "content": [], "isError": true }),
                other => {
                    return Ok(serde_json::to_value(Message::response(
                        id,
                        None,
                        Some(RpcError {
                            code: -32602,
                            message: format!("unknown tool: {other}"),
                            data: None,
                        }),
                    ))?);
                }
            }
        }
        other => {
            return Ok(serde_json::to_value(Message::response(
                id,
                None,
                Some(RpcError {
                    code: -32601,
                    message: format!("method not found: {other}"),
                    data: None,
                }),
            ))?);
        }
    };
    // id kept in sync with the request; the Message type pins the wire shape.
    Ok(serde_json::to_value(Message::response(
        id,
        Some(result),
        None,
    ))?)
}
