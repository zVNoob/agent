//! `agent.mcp` / `agent.mcps` — the pure-Lua MCP client against an in-process
//! fake transport: handshake, tool registry, callbacks, per-call streaming, and
//! the panels a call draws for itself.
use super::*;

#[test]
fn mcp_fake_handshake_registers_tools_and_calls_them() {
    // The full agent.mcp flow against an in-process fake transport func:
    // handshake (initialize -> initialized notification -> tools/list),
    // tool objects registered on the connection with their fields, and
    // request/response tool calls correlated by id — all through
    // func(request_json, on_streaming_response_json). No process: the
    // transport is injected and the protocol lives in Lua.
    let lua = vm();
    let ok: bool = lua
        .load(format!(
            "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
            body = r#"
            local func = fake_mcp_func(handlers)
            agent.mcps.fake = agent.mcp("fake", func)
            local conn = agent.mcps.fake
            -- handshake results surfaced on the connection
            assert(conn.serverInfo.name == "lua-fake", "serverInfo.name")
            assert(conn.protocolVersion == "2025-03-26", "protocolVersion")
            -- tool objects: callable tables with signature/description fields
            assert(type(conn.probe) == "table" and getmetatable(conn.probe).__call ~= nil,
                   "probe tool callable")
            assert(conn.probe.description == "probe text back", "probe description")
            assert(conn.probe.signature.type == "object", "probe signature")
            assert(conn.probe.signature.required[1] == "text", "probe signature required")
            assert(conn.tools.probe == conn.probe, "same tool in conn.tools")
            assert(type(conn.sum) == "table" and getmetatable(conn.sum).__call ~= nil,
                   "sum tool callable")
            -- tool calls return a table with ok/result/error/denied fields
            local r1 = conn.probe({ text = "hi there" })
            assert(r1.ok == true and r1.denied == false and r1.error == nil, "probe ok")
            assert(r1.result.content[1].type == "text", "probe content type")
            assert(r1.result.content[1].text == "hi there", "probe text")
            local r2 = conn.sum({ a = 2, b = 40 })
            assert(r2.ok == true and r2.denied == false, "sum ok")
            assert(r2.result.content[1].text == "42", "sum 2+40, got " ..
                   tostring(r2.result and r2.result.content and r2.result.content[1]
                            and r2.result.content[1].text))
            conn:close()
            assert(agent.mcps.fake == nil, "close unregisters the connection")
            return true
            "#
        ))
        .eval()
        .expect("eval");
    assert!(ok, "mcp handshake/tool-call flow failed");
}

#[test]
fn mcp_tool_policy_denies_without_touching_the_wire() {
    // Tool-level approval is a plain Lua allow-list (no Ask machinery):
    // a `false` verdict denies the call locally — the transport func is
    // never invoked — and the connection is unaffected for other tools.
    let lua = vm();
    let ok: bool = lua
        .load(format!(
            "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
            body = r#"
            local calls = 0
            local base = fake_mcp_func(handlers)
            local conn = agent.mcp("fake", function(request_json, on_streaming_response_json)
              calls = calls + 1
              base(request_json, on_streaming_response_json)
            end)
            conn.probe.policy = function(args) return args.text ~= "forbidden" end
            local a = conn.probe({ text = "ok" })
            assert(a.ok == true and a.denied == false, "allowed call passes")
            assert(a.result.content[1].text == "ok", "allowed call result")
            local before = calls
            local b = conn.probe({ text = "forbidden" })
            assert(b.ok == false and b.denied == true, "denied call fails locally")
            assert(calls == before, "denied call never touches the wire")
            local c = conn.sum({ a = 1, b = 2 })
            assert(c.ok == true and c.result.content[1].text == "3", "other tools unaffected")
            conn:close()
            return true
            "#
        ))
        .eval()
        .expect("eval");
    assert!(ok, "mcp tool policy flow failed");
}

#[test]
fn mcp_tool_callback_overrides_the_rpc() {
    // tool.callback short-circuits the RPC: any return is the tool result
    // verbatim; a `false` return denies (used for stubs / dry-runs).
    let lua = vm();
    let ok: bool = lua
        .load(format!(
            "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
            body = r#"
            local conn = agent.mcp("fake", fake_mcp_func(handlers))
            conn.probe.callback = function(args) return "dry-run:" .. args.text end
            local r = conn.probe({ text = "x" })
            assert(r.ok == true and r.result == "dry-run:x", "callback result takes over")
            conn.probe.callback = function() return false end
            local d = conn.probe({ text = "x" })
            assert(d.ok == false and d.denied == true, "callback false denies")
            conn:close()
            return true
            "#
        ))
        .eval()
        .expect("eval");
    assert!(ok, "mcp tool callback flow failed");
}

#[test]
fn mcp_close_marks_dead_and_invokes_on_close() {
    // close() marks the connection dead (later tool calls fail fast with
    // a result error, not a raise), unregisters from agent.mcps, and lets
    // the transport release its resources via opts.on_close.
    let lua = vm();
    let ok: bool = lua
        .load(format!(
            "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
            body = r#"
            local closed = false
            local conn = agent.mcp("tmp", fake_mcp_func(handlers),
                                   { on_close = function() closed = true end })
            local r = conn.probe({ text = "before" })
            assert(r.ok == true, "works before close")
            conn:close()
            assert(closed == true, "on_close called")
            assert(conn.alive == false, "connection marked dead")
            local a = conn.probe({ text = "after" })
            assert(a.ok == false and a.error ~= nil, "connection dead after close")
            local okd, derr = conn:request("tools/list", {})
            assert(okd == nil and derr ~= nil, "request fails fast on a dead connection")
            return true
            "#
        ))
        .eval()
        .expect("eval");
    assert!(ok, "mcp close flow failed");
}

#[test]
fn mcp_validation_and_handshake_failures() {
    // Argument validation happens before any transport contact; handshake
    // failures (transport raise, absent response, RPC error) raise out of
    // agent.mcp, so a connection is only ever handed back ready to go.
    let lua = vm();
    let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            assert(not pcall(agent.mcp, 7, function() end), "bad name rejected")
            assert(not pcall(agent.mcp, "n"), "missing func rejected")
            assert(not pcall(agent.mcp, "n", "not a function"), "non-function func rejected")
            assert(not pcall(agent.mcp, "n", function() end, 5), "bad opts rejected")
            assert(not pcall(agent.mcp, "n", function() end, { on_message = 5 }), "bad opt rejected")
            assert(not pcall(agent.mcp, "n", function() end, { protocolVersion = 7 }),
                   "bad protocolVersion rejected")
            -- handshake: a func that never streams a response raises
            assert(not pcall(agent.mcp, "gone", function() end),
                   "initialize without a response raises")
            -- handshake: a transport raise raises
            assert(not pcall(agent.mcp, "boom", function() error("network down") end),
                   "transport raise during handshake raises")
            -- handshake: an initialize RPC error raises
            local errfunc = fake_mcp_func({
              initialize = function(req)
                return { { jsonrpc = "2.0", id = req.id,
                           error = { code = -32000, message = "no such server" } } }
              end,
            })
            assert(not pcall(agent.mcp, "err", errfunc), "initialize rpc error raises")
            return true
            "#
            ))
            .eval()
            .expect("eval");
    assert!(ok, "mcp validation/handshake-failure flow failed");
}

#[test]
fn mcp_streams_notifications_before_the_response() {
    // The callback is a *stream*: a single func round may deliver id-less
    // notifications first and the response last; the driver routes each —
    // notifications into opts.on_message, the matching response to the
    // pending request.
    let lua = vm();
    let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local notes = {}
            local base_call = handlers["tools/call"]
            handlers["tools/call"] = function(req)
              local msgs = base_call(req)
              table.insert(msgs, 1, { jsonrpc = "2.0", method = "notes/changed", params = { n = 1 } })
              table.insert(msgs, 2, { jsonrpc = "2.0", method = "notes/changed", params = { n = 2 } })
              return msgs
            end
            local conn = agent.mcp("s", fake_mcp_func(handlers),
                                   { on_message = function(m) notes[#notes + 1] = m end })
            local r = conn.probe({ text = "x" })
            assert(r.ok == true and r.result.content[1].text == "x", "response still resolves")
            assert(#notes == 2, "both notifications streamed, got " .. tostring(#notes))
            assert(notes[1].method == "notes/changed" and notes[2].params.n == 2,
                   "notifications routed to on_message in order")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
    assert!(ok, "mcp streaming-notification flow failed");
}

#[test]
fn mcp_tool_call_transport_errors_surface_as_results() {
    // A func that raises mid-round, or that returns without streaming the
    // response, surfaces as { ok = false, error } — never a raise out of
    // the tool call. Non-JSON streamed text goes to on_badline.
    let lua = vm();
    let ok: bool = lua
        .load(format!(
            "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
            body = r#"
            local conn = agent.mcp("s", fake_mcp_func(handlers))
            -- func raises: transport error
            conn.func = function() error("boom") end
            local r = conn.probe({ text = "x" })
            assert(r.ok == false and r.error ~= nil and r.error:find("boom", 1, true) ~= nil,
                   "func raise becomes a request error, got " .. tostring(r.error))
            -- func returns without streaming the response: protocol error
            conn.func = function(request_json, on_streaming_response_json) end
            local r2 = conn.sum({ a = 1, b = 2 })
            assert(r2.ok == false and r2.error ~= nil and
                   r2.error:find("no response", 1, true) ~= nil,
                   "missing response errors, got " .. tostring(r2.error))
            -- non-JSON text streamed by the func: on_badline, then the round
            -- still fails as unanswered
            local noted
            local conn2 = agent.mcp("b", fake_mcp_func(handlers),
                                    { on_badline = function(text, why) noted = { text, why } end })
            conn2.func = function(request_json, on_streaming_response_json)
              on_streaming_response_json('not json at all')
            end
            local r3 = conn2.probe({ text = "x" })
            assert(r3.ok == false and r3.error ~= nil and
                   r3.error:find("no response", 1, true) ~= nil,
                   "badline round still errors, got " .. tostring(r3.error))
            assert(noted ~= nil and noted[1] == 'not json at all', "on_badline saw the bad text")
            conn:close()
            conn2:close()
            return true
            "#
        ))
        .eval()
        .expect("eval");
    assert!(ok, "mcp transport-error flow failed");
}

#[test]
fn mcp_notify_sends_without_expecting_a_response() {
    // conn:notify is fire-and-forget: func carries the notification over
    // the wire, but nothing streamed back is awaited (id-less messages
    // still dispatch into on_message).
    let lua = vm();
    let ok: bool = lua
        .load(format!(
            "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
            body = r#"
            local calls = 0
            local base = fake_mcp_func(handlers)
            local conn = agent.mcp("s", function(request_json, on_streaming_response_json)
              calls = calls + 1
              base(request_json, on_streaming_response_json)
            end, { on_message = function() end })
            local before = calls
            local okn, nerr = conn:notify("notifications/cancelled", { reason = "bye" })
            assert(okn == true and nerr == nil, "notify accepted")
            assert(calls == before + 1, "notify went through func")
            conn:close()
            return true
            "#
        ))
        .eval()
        .expect("eval");
    assert!(ok, "mcp notify flow failed");
}

#[test]
fn mcp_per_call_streaming_routes_progress_and_messages_then_settles() {
    // Phase-A streaming: conn:invoke(name, args, { on_progress, on_message })
    // — a round carrying on_progress injects `_meta.progressToken` into the
    // request params (shallow-copied, never mutating the caller's table),
    // notifications streamed back during the round route to the per-call
    // callbacks in order, and the result still settles atomically.
    let lua = vm();
    let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local base_call = handlers["tools/call"]
            local seen_request_meta
            local global_hits = 0
            handlers["tools/call"] = function(req)
              local msgs = base_call(req)
              if req.params.arguments.text ~= nil then
                seen_request_meta = req.params._meta
                local token = seen_request_meta and seen_request_meta.progressToken or nil
                table.insert(msgs, 1, { jsonrpc = "2.0", method = "notifications/progress",
                                        params = { progressToken = token, progress = 1, total = 2 } })
                table.insert(msgs, 2, { jsonrpc = "2.0", method = "notes/changed", params = { n = 1 } })
              end
              return msgs
            end
            local conn = agent.mcp("s", fake_mcp_func(handlers),
                                   { on_message = function() global_hits = global_hits + 1 end })
            local events = {}
            local r = conn:invoke("probe", { text = "x" }, {
              on_progress = function(m) events[#events + 1] = "progress:" .. tostring(m.params.progressToken) end,
              on_message  = function(m) events[#events + 1] = "message:" .. tostring(m.params.n) end,
            })
            assert(r.ok == true and r.result.content[1].text == "x", "response still settles")
            assert(seen_request_meta ~= nil and type(seen_request_meta.progressToken) == "string",
                   "on_progress opts the request in with a progressToken")
            assert(#events == 2, "both streamed messages surfaced, got " .. tostring(#events))
            assert(events[1] == "progress:" .. seen_request_meta.progressToken,
                   "progress routed with the matching token, got " .. events[1])
            assert(events[2] == "message:1", "per-call on_message routed in order, got " .. events[2])
            assert(global_hits == 0, "per-call on_message won over the global one")
            -- on_progress-only callopts: no _meta injected with on_message alone.
            local args = { text = "y" }
            local r2 = conn:invoke("probe", args, { on_message = function() end })
            assert(r2.ok == true, "on_message-only round settles")
            assert(args._meta == nil, "caller's params table is never mutated")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
    assert!(ok, "mcp per-call streaming failed");
}

#[test]
fn mcp_progress_without_on_progress_falls_back_to_global() {
    // Streaming is opt-in: without on_progress no `_meta.progressToken` is
    // injected and progress notifications fall through to the global
    // opts.on_message, exactly like any other inbound notification.
    //
    // This is now the `draw = false` case, and that scoping is the point:
    // a connection that draws sets `on_progress` on the caller's behalf, so
    // the opt-out is the only way to get the old wire behaviour — which is
    // why it forwards the callopts *untouched* rather than merely skipping
    // the panel. The default path is `mcp_a_wire_call_draws_its_own_panel`.
    let lua = vm();
    let ok: bool = lua
        .load(format!(
            "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
            body = r#"
            local base_call = handlers["tools/call"]
            local seen_request_meta
            handlers["tools/call"] = function(req)
              local msgs = base_call(req)
              seen_request_meta = req.params._meta
              local token = seen_request_meta and seen_request_meta.progressToken or nil
              table.insert(msgs, 1, { jsonrpc = "2.0", method = "notifications/progress",
                                      params = { progressToken = token, progress = 1 } })
              return msgs
            end
            local notes = {}
            local conn = agent.mcp("s", fake_mcp_func(handlers),
                                   { draw = false,
                                     on_message = function(m) notes[#notes + 1] = m end })
            local r = conn.probe({ text = "x" })
            assert(r.ok == true and r.result.content[1].text == "x", "response still settles")
            assert(seen_request_meta == nil, "no progressToken without on_progress")
            assert(#notes == 1 and notes[1].method == "notifications/progress",
                   "progress fell back to the global on_message")
            conn:close()
            return true
            "#
        ))
        .eval()
        .expect("eval");
    assert!(ok, "mcp opt-in progress fallback failed");
}

/// An MCP tool cannot report itself — its code is across the wire — so the
/// connection draws the panel on its behalf. This is that, end to end
/// through the real protocol against the in-process fake.
///
/// The assertions are the ones that make it the *same* behaviour a local
/// tool gets rather than a different one: a titled panel, opened before the
/// request, holding the result's **text** rather than its JSON envelope.
#[test]
fn mcp_a_wire_call_draws_its_own_panel() {
    let sink = crate::panels::PanelSink::default();
    let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
    let ok: bool = lua
        .load(format!(
            "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
            body = r#"
            local conn = agent.mcp("wiki", fake_mcp_func(handlers))
            local r = conn.probe({ text = "hi there" })
            assert(r.ok == true, "the call still returns its result")
            conn:close()
            return true
            "#
        ))
        .eval()
        .expect("eval");
    assert!(ok, "mcp drawing path failed");

    // Opened *before* the result arrived, so a slow call is visibly in
    // flight rather than appearing all at once when it finishes. The order
    // of the ops is the evidence.
    let ops = sink.ops();
    assert!(
        matches!(ops.first(), Some(PanelOp::Create { .. })),
        "the panel is created first, then filled: {ops:?}"
    );

    let panel = drawn(&sink);
    // Titled the way tools are named everywhere else.
    assert!(
        panel.contains("┌─ wiki.probe"),
        "a panel titled {{connection}}.{{tool}}: {panel:?}"
    );
    // The result's text, not the envelope around it.
    assert!(
        panel.contains("hi there"),
        "the text block is shown: {panel:?}"
    );
    assert!(
        !panel.contains("\"content\"") && !panel.contains("\"type\":\"text\""),
        "and not the JSON envelope it arrived in: {panel:?}"
    );
}

/// `draw = false` is the escape hatch, and it has to be exact: no panel ops
/// at all, and the request on the wire byte for byte what it always was.
#[test]
fn mcp_draw_false_keeps_the_call_silent_and_the_wire_unchanged() {
    let sink = crate::panels::PanelSink::default();
    let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
    let ok: bool = lua
        .load(format!(
            "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
            body = r#"
            local base_call = handlers["tools/call"]
            handlers["tools/call"] = function(req)
              __seen_meta = req.params._meta
              return base_call(req)
            end
            local conn = agent.mcp("wiki", fake_mcp_func(handlers), { draw = false })
            local r = conn.probe({ text = "hi there" })
            assert(r.ok == true, "and the call still works")
            assert(__seen_meta == nil, "no _meta at all: the callopts went through untouched")
            conn:close()
            return true
            "#
        ))
        .eval()
        .expect("eval");
    assert!(ok, "the draw=false path failed");
    assert!(
        sink.ops().is_empty(),
        "and an opted-out connection draws nothing: {:?}",
        sink.ops()
    );
}

/// The two shapes that are not a plain text result, and one failure. All
/// three used to be a wall of JSON or nothing at all.
#[test]
fn mcp_panels_show_text_json_and_failure() {
    let sink = crate::panels::PanelSink::default();
    let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
    let ok: bool = lua
        .load(format!(
            "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
            body = r#"
            -- A result with no text block at all: shown as indented JSON, so a
            -- structured result is never reduced to nothing.
            handlers["tools/call"] = function(req)
              if req.params.name == "structured" then
                return { { jsonrpc = "2.0", id = req.id,
                           result = { content = { { type = "image", data = "…" } },
                                      meta = { rows = 2, ok = true } } } }
              end
              if req.params.name == "boom" then
                return { { jsonrpc = "2.0", id = req.id,
                           error = { code = -32000, message = "the server said no" } } }
              end
              -- The shape a real server actually uses for a failed tool: the
              -- call succeeds, `isError` is set, and the content is a generic
              -- sentence. Checked because a real `mcp` server does exactly
              -- this, so a failure can arrive looking like a result.
              if req.params.name == "iserr" then
                return { { jsonrpc = "2.0", id = req.id,
                           result = { isError = true,
                                      content = { { type = "text",
                                                    text = "Error executing tool iserr" } } } } }
              end
              error("fake func: unexpected tool " .. tostring(req.params.name))
            end
            -- Two more tools for these cases, advertised alongside the usual.
            local base_list = handlers["tools/list"]
            handlers["tools/list"] = function(req)
              local msgs = base_list(req)
              for _, t in ipairs({ "structured", "boom", "iserr" }) do
                table.insert(msgs[1].result.tools, {
                  name = t, description = t,
                  inputSchema = { type = "object", properties = {} } })
              end
              return msgs
            end
            local conn = agent.mcp("wiki", fake_mcp_func(handlers))
            conn.structured({})
            conn.boom({})
            conn.iserr({})
            conn:close()
            return true
            "#
        ))
        .eval()
        .expect("eval");
    assert!(ok, "mcp result shapes failed");

    let panel = drawn(&sink);
    // Indented, and it kept the structure rather than printing it flat.
    assert!(
        panel.contains("\"rows\": 2") && panel.contains("\"ok\": true"),
        "a textless result is shown as indented JSON: {panel:?}"
    );
    assert!(
        panel.contains("the server said no"),
        "and a JSON-RPC failure is reported in the call's own panel: {panel:?}"
    );
    // A tool that failed while the call succeeded: `isError` with a generic
    // sentence, which is what a real MCP server sends. Unmarked it would be
    // indistinguishable from a result.
    assert!(
        panel.contains("error: Error executing tool iserr"),
        "an isError result is marked as the failure it is: {panel:?}"
    );
}

/// A tool with a Lua `callback` is running on this VM, so it can ask for
/// its own panel. Drawing for it too would be the double output the whole
/// arrangement exists to prevent — so this path is left alone.
#[test]
fn mcp_a_callback_tool_is_left_to_draw_itself() {
    let sink = crate::panels::PanelSink::default();
    let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
    let ok: bool = lua
        .load(format!(
            "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
            body = r#"
            local conn = agent.mcp("wiki", fake_mcp_func(handlers))
            -- The override: same connection, but this tool answers in Lua.
            -- The same override shape `mcp_tool_callback_overrides_the_rpc`
            -- uses: a callback on a tool the server advertised.
            conn.probe.callback = function()
              return { content = { { type = "text", text = "answered here" } } }
            end
            local r = conn.probe({})
            assert(r.ok == true, "the callback answers")
            conn:close()
            return true
            "#
        ))
        .eval()
        .expect("eval");
    assert!(ok, "the callback-tool path failed");
    assert!(
        sink.ops().is_empty(),
        "a tool that can draw for itself is not drawn for: {:?}",
        sink.ops()
    );
}

#[test]
fn mcp_invoke_rejects_bad_callopts_and_unknown_tool() {
    // conn:invoke validates callopts up front (a programming error raises,
    // it must never half-over-the-wire) and reports unknown tools as a
    // result error, matching the tool-object shape.
    let lua = vm();
    let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local conn = agent.mcp("s", fake_mcp_func(handlers))
            assert(not pcall(function() conn:invoke("probe", {}, 5) end),
                   "non-table callopts raises")
            assert(not pcall(function() conn:invoke("probe", {}, { on_progress = "x" }) end),
                   "non-function on_progress raises")
            assert(not pcall(function() conn:invoke("probe", {}, { on_message = 7 }) end),
                   "non-function on_message raises")
            local u = conn:invoke("nope", {}, { on_progress = function() end })
            assert(u.ok == false and u.error ~= nil and u.error:find("unknown tool", 1, true) ~= nil,
                   "unknown tool reports a result error")
            local e = conn:invoke("probe", { text = "z" })
            assert(e.ok == true and e.result.content[1].text == "z", "plain conn:invoke works")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
    assert!(ok, "mcp invoke validation failed");
}

#[test]
fn mcp_tool_call_round_is_coroutine_wrappable() {
    // Wrapping an MCP round in a coroutine works: the request/dispatch
    // chain from the coroutine to the streaming callbacks is pure Lua, so
    // on_progress may yield progress events to the pump and the final
    // result arrives on the next resume. Phase-B async is up to users; this
    // is the guarantee they build on.
    let lua = vm();
    let ok: bool = lua
        .load(format!(
            "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
            body = r#"
            local base_call = handlers["tools/call"]
            handlers["tools/call"] = function(req)
              local msgs = base_call(req)
              if req.params.arguments.text ~= nil then
                local token = req.params._meta and req.params._meta.progressToken
                table.insert(msgs, 1, { jsonrpc = "2.0", method = "notifications/progress",
                                        params = { progressToken = token, progress = 1 } })
              end
              return msgs
            end
            local conn = agent.mcp("s", fake_mcp_func(handlers))
            local co = coroutine.create(function()
              local r = conn:invoke("probe", { text = "hi" }, {
                on_progress = function(m) coroutine.yield({ kind = "progress", p = m }) end,
              })
              coroutine.yield({ kind = "done", r = r })
            end)
            local seen = {}
            local done
            while true do
              local okco, ev = coroutine.resume(co)
              assert(okco, "coroutine body ran clean")
              if ev == nil then break end
              seen[#seen + 1] = ev.kind
              if ev.kind == "done" then
                done = ev.r
                break
              end
            end
            assert(done ~= nil and done.ok == true and done.result.content[1].text == "hi",
                   "final result arrives through the coroutine wrapper")
            assert(#seen == 2 and seen[1] == "progress" and seen[2] == "done",
                   "progress yielded to the pump before done, got " .. table.concat(seen, ","))
            assert(coroutine.resume(co), "coroutine finishes cleanly after done")
            conn:close()
            return true
            "#
        ))
        .eval()
        .expect("eval");
    assert!(ok, "mcp coroutine wrapper failed");
}

#[test]
fn mcp_json_bridge_is_wired_into_the_agent_vm() {
    // The JSON text boundary (src/mcp.rs) is installed on the real agent
    // namespace, not only on bare VMs.
    let lua = vm();
    let ok: bool = lua
            .load(
                r#"
            local enc = agent.api.json_encode({ jsonrpc = "2.0", id = 7, method = "tools/call",
                                            params = { name = "probe", arguments = { text = "hi" } } })
            local dec = agent.api.json_decode(enc)
            return dec.id == 7 and dec.method == "tools/call" and dec.params.name == "probe"
                   and dec.params.arguments.text == "hi"
            "#,
            )
            .eval()
            .expect("eval");
    assert!(ok, "json bridge must work inside the agent VM");
}

// ---------------------------------------------------------------------
// HTTP(S) transport: `agent.http` (both routes) against the fake server.
// ---------------------------------------------------------------------
