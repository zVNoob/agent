//! `agent.api.stream_turn` — the substrate half of a nested model request.
//!
//! The properties worth pinning are the ones a caller would otherwise discover by
//! getting them wrong: that a refusal is an **event** rather than an error (the
//! caller is mid-turn in a coroutine, and a raise would unwind it past the tool that
//! asked); that an absent argument is an **error** rather than a default (nothing
//! here reads `agent.llm`, so there is no second source of truth to drift); and that
//! closing is prompt rather than a cancellation to wait out.

use super::*;

use crate::mcp::{FakeHttpServer, FakeResponse, FakeServerReply};

#[tokio::test]
async fn a_refused_request_arrives_as_an_error_event() {
    let vm = new_vm().expect("vm");
    let got: Option<String> = eval_reactor(
        &vm,
        r#"
        local h = agent.api.stream_turn("http://127.0.0.1:9/v1", "", "m", {}, {})
        local seen = {}
        for _ = 1, 200 do
          local ev = agent.api.stream_turn_step(h)
          if ev == nil then agent.on_timeout(5) goto continue end
          seen[#seen + 1] = ev.kind
          if ev.kind == "done" or ev.kind == "error" then break end
          ::continue::
        end
        return seen[#seen]
    "#,
    )
    .await
    .expect("pump the turn");
    assert_eq!(
        got.as_deref(),
        Some("error"),
        "a refused request is an event, not a raise: the caller is mid-turn inside \\
         a coroutine, and unwinding it past the tool that asked is worse than a \\
         value it can branch on"
    );
}

#[tokio::test]
async fn a_terminal_event_unregisters_the_handle() {
    let vm = new_vm().expect("vm");
    let ok: bool = eval_reactor(
        &vm,
        r#"
        local h = agent.api.stream_turn("http://127.0.0.1:9/v1", "", "m", {}, {})
        while true do
          local ev = agent.api.stream_turn_step(h)
          if ev == nil then agent.on_timeout(5) goto continue end
          if ev.kind == "done" or ev.kind == "error" then break end
          ::continue::
        end
        return agent.api.stream_turn_step(h) == nil
    "#,
    )
    .await
    .expect("pump the turn");
    assert!(
        ok,
        "a finished handle steps to nil rather than re-serving its terminal event, so \\
         a pump cannot see `done` twice"
    );
}

#[tokio::test]
async fn a_missing_argument_is_an_error_naming_it() {
    let vm = new_vm().expect("vm");
    let problems: String = vm
        .load(
            r#"
            local bad = {}
            local function attempt(what, f)
              local ok, err = pcall(f)
              if not ok then bad[#bad + 1] = what .. ": " .. tostring(err) end
            end
            -- No defaults anywhere on this path: nothing reads `agent.llm`, so an
            -- absent argument is the caller's mistake to see, not something to paper
            -- over with a value that might disagree with `agent.llm`.
            attempt("base_url", function()
              agent.api.stream_turn("", "k", "m", {}, {})
            end)
            attempt("model", function()
              agent.api.stream_turn("http://x/v1", "k", "", {}, {})
            end)
            attempt("nameless tool", function()
              agent.api.stream_turn("http://x/v1", "k", "m", {}, { { nope = true } })
            end)
            attempt("undescribed tool", function()
              agent.api.stream_turn("http://x/v1", "k", "m", {}, { { name = "fs" } })
            end)
            return table.concat(bad, " | ")
        "#,
        )
        .eval()
        .expect("eval");
    assert!(
        problems.contains("base_url"),
        "the empty endpoint is named: {problems}"
    );
    assert!(
        problems.contains("model is required"),
        "the empty model is named — the whole message, not the word: an earlier \
         failure here also mentions the model in passing, and a substring loose \
         enough to match that pins nothing: {problems}"
    );
    assert!(
        problems.contains("tools[0]") && problems.contains("has no `name`"),
        "and a tool entry with no name says what a tool is: {problems}"
    );
    assert!(
        problems.contains("has no `description`"),
        "and a tool with no description says why one is required — it is how the \
         model knows it may call the tool: {problems}"
    );
}

#[tokio::test]
async fn closing_is_safe_on_a_handle_that_never_existed() {
    let vm = new_vm().expect("vm");
    let ok: bool = vm
        .load("local ok = pcall(agent.api.stream_turn_close, 999999) return ok")
        .eval()
        .expect("eval");
    assert!(
        ok,
        "close is idempotent from the caller's side: a pump that gives up early, or \\
         races its own terminal event, must not have to distinguish those"
    );
}

#[tokio::test]
async fn the_tools_argument_is_the_wire_shape_not_a_connection() {
    // A connection table (`{ name, tools = { … } }`) is the *convention* shape the
    // registry uses; the primitive takes the request shape. Conflating them would put
    // `mcps_tool_defs` — a registry reader — inside the bridge, which is the
    // dependency this primitive exists to keep out.
    let vm = new_vm().expect("vm");
    let problems: String = vm
        .load(
            r#"
            local out = {}
            local ok = pcall(agent.api.stream_turn, "http://127.0.0.1:9/v1", "", "m",
                             {}, { { name = "fs", tools = {} } })
            if ok then out[#out + 1] = "a connection was accepted" end
            return table.concat(out, "")
        "#,
        )
        .eval()
        .expect("eval");
    assert_eq!(
        problems, "",
        "a connection-shaped tools entry is refused rather than quietly sent to the \\
         server as an empty tool"
    );
}

/// The Lua the test drives: one turn, pumped to its terminal event.
///
/// `goto`/`::continue::` because a step returning `nil` means "nothing yet" and the
/// wait is `agent.on_timeout` — the same shape every other pump in the tree has.
const CHUNK: &str = r#"
    local h = agent.api.stream_turn("{url}", "sk-test", "the-model",
      { { role = "user", content = "first" },
        { role = "assistant", content = "second" } },
      { { name = "noop", description = "does nothing",
          parameters = { type = "object", properties = {} } } })
    while true do
      local ev = agent.api.stream_turn_step(h)
      if ev == nil then agent.on_timeout(5) goto continue end
      if ev.kind == "done" or ev.kind == "error" then break end
      ::continue::
    end
    return true
"#;

/// The request that goes out is the one that was passed: messages in order, tools
/// in the wire shape, and the model asked for by name.
///
/// Against a dead endpoint none of that is observable, and "it did not raise" is a
/// weak thing to assert about a request body — so this reads the body the fake server
/// received. The three that matter are the three a conversion can quietly lose:
/// message order (a request whose history arrives reordered is a request the model
/// answers to the wrong conversation), the tool list (empty tools would make a tool
/// agent unable to act, silently), and the model name.
#[tokio::test]
async fn the_request_carries_the_messages_tools_and_model_it_was_given() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new((String::new(), Vec::new())));
    let sink = seen.clone();
    let fake = FakeHttpServer::start(move |req| {
        let mut slot = sink.lock().unwrap();
        slot.0 = req.body.clone();
        slot.1 = req.headers.clone();
        FakeServerReply::Response(FakeResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            // A one-event stream: `data: [DONE]` is a complete, empty response.
            body: "data: [DONE]\n\n".into(),
        })
    });

    let vm = new_vm().expect("vm");
    // Interpolated with `replace`, not `format!`: every brace in this chunk is real
    // Lua, and doubling them by hand to survive `format!` is a way to ship a chunk
    // that does not parse.
    let chunk = CHUNK.replace("{url}", &fake.url("/v1"));
    let ok: bool = eval_reactor(&vm, &chunk).await.expect("eval");

    assert!(ok, "the turn ran to a terminal event");
    let (sent, headers) = seen.lock().unwrap().clone();
    assert!(
        sent.contains("\"model\":\"the-model\""),
        "the model asked for by name: {sent}"
    );
    assert!(
        sent.find("\"first\"").unwrap_or(usize::MAX)
            < sent.find("\"second\"").unwrap_or(usize::MAX),
        "messages in the order given — history that arrives reordered is a \
         conversation the model answers wrongly: {sent}"
    );
    assert!(
        sent.contains("\"noop\""),
        "the tool list reaches the server at all: {sent}"
    );
    assert!(
        sent.contains("\"stream\":true"),
        "and it is a streamed request, which is what the step protocol assumes: {sent}"
    );
    assert!(
        headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("authorization") && v == "Bearer sk-test"),
        "the credential goes out as a bearer token — a header, so asserting on the \
         body would have passed with no authorization at all: {headers:?}"
    );
}
