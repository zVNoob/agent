//! `agent.api.turn` — the substrate half of a nested model request.
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
        local h = agent.api.turn("http://127.0.0.1:9/v1", "", "m", {}, {})
        local seen = {}
        for _ = 1, 200 do
          local ev = agent.api.turn_step(h)
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
        local h = agent.api.turn("http://127.0.0.1:9/v1", "", "m", {}, {})
        while true do
          local ev = agent.api.turn_step(h)
          if ev == nil then agent.on_timeout(5) goto continue end
          if ev.kind == "done" or ev.kind == "error" then break end
          ::continue::
        end
        return agent.api.turn_step(h) == nil
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
              agent.api.turn("", "k", "m", {}, {})
            end)
            attempt("model", function()
              agent.api.turn("http://x/v1", "k", "", {}, {})
            end)
            attempt("nameless tool", function()
              agent.api.turn("http://x/v1", "k", "m", {}, { { nope = true } })
            end)
            attempt("undescribed tool", function()
              agent.api.turn("http://x/v1", "k", "m", {}, { { name = "fs" } })
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
        .load("local ok = pcall(agent.api.turn_close, 999999) return ok")
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
            local ok = pcall(agent.api.turn, "http://127.0.0.1:9/v1", "", "m",
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
    local h = agent.api.turn("{url}", "sk-test", "the-model",
      { { role = "user", content = "first" },
        { role = "assistant", content = "second" } },
      { { name = "noop", description = "does nothing",
          parameters = { type = "object", properties = {} } } })
    while true do
      local ev = agent.api.turn_step(h)
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
// ===================== `agent.turn` — the route =====================

const TURN_PUMP: &str = r#"
    local s = agent.turn(OPTS)
    while true do
      local ev = s:step()
      if ev == nil then agent.on_timeout(5) goto continue end
      if ev.kind == "done" or ev.kind == "error" then return ev end
      ::continue::
    end
"#;

/// Drive `agent.turn` to its terminal event and return it. `opts` is the Lua
/// literal the route is called with.
async fn drive_turn(vm: &Lua, opts: &str) -> mlua::Value {
    let chunk = TURN_PUMP.replace("OPTS", opts);
    eval_reactor(vm, &chunk).await.expect("drive the turn")
}

/// The body the fake server captured from a turn request.
async fn request_body(opts: &str, set_up: &str) -> serde_json::Value {
    let body = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let sink = body.clone();
    let fake = FakeHttpServer::start(move |req| {
        *sink.lock().unwrap() = req.body.clone();
        FakeServerReply::Response(FakeResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            body: "data: [DONE]\\n\\n".into(),
        })
    });
    let vm = shipped_vm();
    // Defaults first, then the test's own setup, so an override the test writes
    // wins over the canned baseline rather than being reset by it.
    vm.load(format!(
        "agent.llm = agent.llm or {{}}
        agent.llm.base_url = \"{}\"
        agent.llm.api_key = \"sk\"
        agent.llm.model = \"m\"
        agent.llm.system_prompt = \"\"
        {set_up}",
        fake.url("/v1")
    ))
    .eval::<()>()
    .expect("configure the convention");
    let _ = drive_turn(&vm, opts).await;
    let text = body.lock().unwrap().clone();
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("the body is JSON: {text}"))
}

#[tokio::test]
async fn turn_inherits_the_conventions_when_nothing_is_overridden() {
    let body = request_body(
        "{ messages = { { role = \"user\", content = \"hi\" } } }",
        "",
    )
    .await;
    assert_eq!(body["model"], "m", "the convention's model, by default");
    assert_eq!(body["messages"].as_array().expect("messages").len(), 1);
    assert_eq!(
        body["messages"][0]["role"], "user",
        "and no system message is prepended when the prompt is empty"
    );
    let tools = body["tools"].as_array().expect("a tool list");
    assert!(
        !tools.is_empty(),
        "the shipped registry's tools reach the request by default"
    );
    assert!(
        tools.iter().any(|t| t["function"]["name"]
            .as_str()
            .map(|n| n.contains('.'))
            .unwrap_or(false)),
        "and they carry the registry's qualified names: {tools:?}"
    );
}

#[tokio::test]
async fn turn_overrides_beat_the_conventions() {
    let body = request_body(
        "{ model = \"other-model\", messages = { { role = \"user\", content = \"hi\" } } }",
        "",
    )
    .await;
    assert_eq!(
        body["model"], "other-model",
        "an override wins over agent.llm.model"
    );
}

/// An override of the endpoint itself: the request must land on the endpoint the
/// caller named, not the one the convention configured. Tested with a *second*
/// server so the override is observable rather than inferred from a model string.
#[tokio::test]
async fn turn_a_base_url_override_goes_to_the_caller_s_endpoint() {
    let hits = |_n| {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let seen2 = seen.clone();
        let server = FakeHttpServer::start(move |_req| {
            *seen2.lock().unwrap() += 1;
            FakeServerReply::Response(FakeResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())],
                body: "data: [DONE]\n\n".into(),
            })
        });
        (server, seen)
    };
    let (convention, convention_hits) = hits(0);
    let (override_server, override_hits) = hits(0);

    let vm = shipped_vm();
    vm.load(format!(
        "agent.llm = agent.llm or {{}} agent.llm.base_url = \"{}\"",
        convention.url("/v1")
    ))
    .eval::<()>()
    .expect("configure");
    let _ = drive_turn(
        &vm,
        &format!(
            "{{ base_url = \"{}\", messages = {{ {{ role = \"user\", content = \"hi\" }} }} }}",
            override_server.url("/v1")
        ),
    )
    .await;

    assert_eq!(
        *override_hits.lock().unwrap(),
        1,
        "the caller's endpoint received the request"
    );
    assert_eq!(
        *convention_hits.lock().unwrap(),
        0,
        "and the convention's did not — an override that silently fell back would \
         have sent it there"
    );
}

#[tokio::test]
async fn turn_prepends_the_system_prompt_as_a_message() {
    let body = request_body(
        "{ messages = { { role = \"user\", content = \"hi\" } } }",
        "agent.llm = agent.llm or {} agent.llm.system_prompt = \"You are terse.\"",
    )
    .await;
    assert_eq!(
        body["messages"][0],
        serde_json::json!({"role": "system", "content": "You are terse."}),
        "the prompt becomes the leading system message"
    );
    assert_eq!(body["messages"][1]["content"], "hi");
}

#[tokio::test]
async fn turn_callers_system_beats_the_prompt() {
    let body = request_body(
        "{ system = \"Caller wins.\", messages = { { role = \"user\", content = \"hi\" } } }",
        "agent.llm = agent.llm or {} agent.llm.system_prompt = \"Convention loses.\"",
    )
    .await;
    assert_eq!(
        body["messages"][0]["content"], "Caller wins.",
        "the caller's `system` is the message sent, not the convention's prompt"
    );
}

#[tokio::test]
async fn turn_an_empty_system_silences_the_prompt() {
    // `""` and absent are different answers: the caller said *no* system message.
    let body = request_body(
        "{ system = \"\", messages = { { role = \"user\", content = \"hi\" } } }",
        "agent.llm = agent.llm or {} agent.llm.system_prompt = \"Convention loses.\"",
    )
    .await;
    assert_eq!(
        body["messages"][0]["role"], "user",
        "an empty `system` is a system message silenced, not the prompt back"
    );
}

#[tokio::test]
async fn turn_run_returns_the_assembled_turn() {
    let fake = FakeHttpServer::start(move |_req| {
        FakeServerReply::Response(FakeResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            // A minimal, valid OpenAI stream: one content delta, then DONE.
            body: "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n\
                   data: [DONE]\n\n"
                .into(),
        })
    });
    let vm = shipped_vm();
    vm.load(format!(
        "agent.llm = agent.llm or {{}}
         agent.llm.base_url = \"{}\"",
        fake.url("/v1")
    ))
    .eval::<()>()
    .expect("configure");

    let result: mlua::Table = eval_reactor(
        &vm,
        r#"
        local s = agent.turn({ messages = { { role = "user", content = "hi" } } })
        return s:run()
    "#,
    )
    .await
    .expect("drive the turn");
    let content: String = result.get("content").expect("content");
    assert_eq!(content, "hello", "the assembled answer is returned whole");
    let calls: mlua::Table = result.get("tool_calls").expect("tool_calls");
    assert_eq!(
        calls.len().expect("len"),
        0,
        "no tool calls in a plain answer"
    );
    assert!(
        result.get::<mlua::Value>("reasoning").is_ok(),
        "and reasoning is there to draw even when empty"
    );
}

// ===================== the main-loop seam: `turn` event → assembled turn =====================

/// Step an `EventRun` to completion the way the loop would, answering each
/// `on_timeout` wait immediately (with a small real sleep, so the transport
/// task gets to fill the queue between polls) and each `agent.await_tools`
/// yield with `on_tools`'s resume value — the round's answer.
async fn drive_event_with_tools(
    run: &mut EventRun<'_>,
    mut step: EventStep,
    mut on_tools: impl FnMut(&mlua::Table) -> mlua::Value,
) {
    for _ in 0..1000 {
        match step {
            EventStep::Returned => return,
            EventStep::Waiting { .. } => {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                step = run.step().expect("step the handler");
            }
            EventStep::Tools { turn } => {
                let reply = on_tools(&turn);
                step = run.resume_value(reply).expect("resume with the round");
            }
        }
    }
    panic!("the handler never finished — a hang, not a test to wait out");
}

/// The same drive for a turn with no tool calls in it.
async fn drive_event(run: &mut EventRun<'_>, step: EventStep) {
    drive_event_with_tools(run, step, |_| {
        panic!("a tools yield has no round here to run")
    })
    .await
}

#[tokio::test]
async fn the_shipped_turn_handler_drives_a_request_and_returns_the_turn() {
    // The whole Lua half of the main turn, as the loop drives it: fire the
    // "turn" event on the shipped configuration, and the registered handler
    // (`agent.main_turn`) drives `agent.turn` on the payload's history and
    // hands the assembled turn back as its return value.
    let body = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let sink = body.clone();
    let fake = FakeHttpServer::start(move |req| {
        *sink.lock().unwrap() = req.body.clone();
        FakeServerReply::Response(FakeResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            body: "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"thinking…\"}}]}\n\n\
                   data: {\"choices\":[{\"delta\":{\"content\":\"the answer\"}}]}\n\n\
                   data: [DONE]\n\n"
                .into(),
        })
    });
    let vm = shipped_vm();
    vm.load(format!(
        "agent.llm = agent.llm or {{}}
         agent.llm.base_url = \"{}\"",
        fake.url("/v1")
    ))
    .eval::<()>()
    .expect("configure");
    // The sink the loop would install: the handler's drawing has to reach it,
    // or the stream the user watches is the one thing the test never checked.
    let sink = crate::panels::PanelSink::continuing_from(0);
    install_sink(&vm, &sink).expect("install the sink");

    let payload = serde_json::json!({
        "history": [ { "role": "user", "content": "the question" } ]
    });
    let (mut run, step) = EventRun::start(&vm, "turn", &payload)
        .expect("start")
        .expect("the shipped tree registers a turn handler");
    drive_event(&mut run, step).await;
    let ops = sink.drain();
    let drew = |title: &str| {
        let id = ops.iter().find_map(|op| match op {
            crate::panels::PanelOp::Create { id, title: t, .. } if t == title => Some(*id),
            _ => None,
        });
        let id = id.unwrap_or_else(|| panic!("a \"{title}\" block was drawn: {ops:?}"));
        ops.iter().any(|op| matches!(op, crate::panels::PanelOp::Append { id: a, text } if *a == id && !text.is_empty()))
    };
    assert!(
        drew("reasoning"),
        "reasoning streams into its own block: {ops:?}"
    );
    assert!(
        drew("response"),
        "and the answer into the response block: {ops:?}"
    );
    let returned = run
        .take_returned()
        .expect("a request handler's return is the answer");
    let (turn, reasoning) = turn_from_lua(returned).expect("the assembled turn decodes");
    assert_eq!(turn.content, "the answer");
    assert!(!turn.wants_tools(), "a plain answer asks for no tool round");
    assert!(
        reasoning.contains("thinking…"),
        "reasoning comes back with the turn, for the log: {reasoning:?}"
    );

    // And the request the handler sent is the conversation it was given, with
    // the configured endpoint reached through the route — not a default.
    let sent = body.lock().unwrap().clone();
    assert!(
        sent.contains("the question"),
        "the payload's history is what was sent: {sent}"
    );
}

#[test]
fn turn_from_lua_decodes_the_assembled_turn_table() {
    let vm = new_vm().expect("vm");
    let value = vm
        .load(
            r#"return {
                content = "done",
                reasoning = "because",
                tool_calls = { { id = "c1", name = "fs.read", arguments = "{\"path\":\"x\"}" } },
                usage = { prompt_tokens = 3, completion_tokens = 4 },
            }"#,
        )
        .eval::<mlua::Value>()
        .expect("table");
    let (turn, reasoning) = turn_from_lua(value).expect("decode");
    assert_eq!(turn.content, "done");
    assert_eq!(reasoning, "because");
    assert_eq!(turn.tool_calls.len(), 1);
    assert_eq!(turn.tool_calls[0].name, "fs.read");
    let tokens = turn.tokens();
    assert_eq!(tokens.prompt, Some(3));
    assert_eq!(tokens.completion, Some(4));

    // A hand-built table needs only the keys it has: the rest are the empty
    // answer, not an error.
    let value = vm
        .load(r#"return { content = "just text" }"#)
        .eval::<mlua::Value>()
        .expect("table");
    let (turn, reasoning) = turn_from_lua(value).expect("decode");
    assert_eq!(turn.content, "just text");
    assert!(!turn.wants_tools());
    assert!(reasoning.is_empty());
    assert_eq!(turn.tokens().prompt, None);

    // A non-table answer is the error it looks like.
    let value = vm
        .load(r#"return "not a turn""#)
        .eval::<mlua::Value>()
        .expect("string");
    let err = turn_from_lua(value).expect_err("a string is not a turn");
    assert!(
        err.contains("expected the assembled-turn table"),
        "the error says what was expected: {err}"
    );
}

#[tokio::test]
async fn the_shipped_turn_handler_runs_the_tool_loop() {
    // The whole Stage 2 contract on the Lua side: the handler drives the
    // first request, suspends on `agent.await_tools` with the assembled turn,
    // and — resumed with the round's results — extends its history and drives
    // the next request. The fake server answers request 1 with a tool call
    // and request 2 (recognisable by the tool result in its body) with the
    // final answer.
    let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = bodies.clone();
    let fake = FakeHttpServer::start(move |req| {
        sink.lock().unwrap().push(req.body.clone());
        let body = if req.body.contains("\"role\":\"tool\"") {
            // The continuation: prove the handler's history grew by the call
            // and its result by answering with a phrase of our own.
            "data: {\"choices\":[{\"delta\":{\"content\":\"the tool said hi\"}}]}\n\n\
             data: [DONE]\n\n"
                .to_string()
        } else {
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"fs.read\",\"arguments\":\"{\\\"path\\\":\\\"x\\\"}\"}}]}}]}\n\n\
             data: [DONE]\n\n"
                .to_string()
        };
        FakeServerReply::Response(FakeResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            body,
        })
    });
    let vm = shipped_vm();
    vm.load(format!(
        "agent.llm = agent.llm or {{}}
         agent.llm.base_url = \"{}\"",
        fake.url("/v1")
    ))
    .eval::<()>()
    .expect("configure");
    let sink_handle = crate::panels::PanelSink::continuing_from(0);
    install_sink(&vm, &sink_handle).expect("install the sink");

    let payload = serde_json::json!({
        "history": [ { "role": "user", "content": "read x for me" } ]
    });
    let (mut run, step) = EventRun::start(&vm, "turn", &payload)
        .expect("start")
        .expect("the shipped tree registers a turn handler");

    let mut yielded_turns = Vec::new();
    let lua = run.lua();
    drive_event_with_tools(&mut run, step, |turn| {
        // The yield must carry the assembled turn — the loop folds *that*.
        let calls: mlua::Table = turn.get("tool_calls").expect("tool_calls");
        assert_eq!(
            calls.len().expect("len"),
            1,
            "the yield carries the turn that asked for the round"
        );
        yielded_turns.push(turn.get::<String>("content").unwrap_or_default());
        // The loop's answer: one folded result per call, in order.
        round_results_reply(
            lua,
            &[(
                "call_1".to_string(),
                "{\"ok\":true,\"result\":\"hi\"}".to_string(),
            )],
            false,
        )
        .expect("the round's reply")
    })
    .await;

    assert_eq!(yielded_turns.len(), 1, "one round was handed to the loop");
    let returned = run.take_returned().expect("the handler answered");
    let (turn, _) = turn_from_lua(returned).expect("the final turn decodes");
    assert_eq!(turn.content, "the tool said hi");
    assert!(!turn.wants_tools(), "the final turn ends the loop");

    // And the second request really carried the extended history: the
    // assistant's wire-shaped calls and the tool's result, in order.
    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies.len(), 2, "two requests went out");
    let second = &bodies[1];
    let calls_at = second.find("\"tool_calls\"").expect("the calls message");
    let result_at = second
        .find("\\\"ok\\\":true")
        .expect("the tool result message");
    assert!(
        calls_at < result_at,
        "the calls precede the results — the protocol's order: {second}"
    );
    assert!(
        second.contains("\"name\":\"fs.read\"") && second.contains("call_1"),
        "the wire shape the server expects: {second}"
    );
}

#[tokio::test]
async fn a_stopped_round_comes_back_as_the_sentinel() {
    // Interrupting the round ends the turn: the loop resumes the handler with
    // `{ stopped = true }`, and the handler passes the sentinel straight back
    // — everything about the turn is folded already, so returning the turn
    // itself would fold it twice.
    let fake = FakeHttpServer::start(move |_req| {
        FakeServerReply::Response(FakeResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            body: "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"fs.read\",\"arguments\":\"{}\"}}]}}]}\n\n\
                   data: [DONE]\n\n"
                .into(),
        })
    });
    let vm = shipped_vm();
    vm.load(format!(
        "agent.llm = agent.llm or {{}}
         agent.llm.base_url = \"{}\"",
        fake.url("/v1")
    ))
    .eval::<()>()
    .expect("configure");

    let payload = serde_json::json!({
        "history": [ { "role": "user", "content": "read x for me" } ]
    });
    let (mut run, step) = EventRun::start(&vm, "turn", &payload)
        .expect("start")
        .expect("the shipped tree registers a turn handler");
    let lua = run.lua();
    drive_event_with_tools(&mut run, step, |_turn| {
        stopped_reply(lua).expect("the stopped reply")
    })
    .await;

    let returned = run.take_returned().expect("the handler answered");
    assert!(
        matches!(
            turn_reply_from_lua(returned).expect("decodes"),
            TurnReply::Stopped
        ),
        "the handler passes the stopped sentinel straight back"
    );
}
