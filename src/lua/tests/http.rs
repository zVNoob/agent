//! `agent.http` — both routes (a streaming body, and an SSE stream) against
//! the fake server.
use super::*;

    #[tokio::test]
    async fn agent_http_streams_body_into_on_chunk_and_on_done() {
        // The request goes out with body + headers; the response status,
        // headers and streamed body arrive through the callbacks.
        let fake = FakeHttpServer::start(|req: FakeRequest| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.body, r#"{"hello":"world"}"#);
            assert!(
                req.headers
                    .iter()
                    .any(|(k, v)| k == "content-type" && v == "application/json"),
                "content-type header must reach the server"
            );
            FakeServerReply::Response(FakeResponse {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: req.body,
            })
        });
        let lua = vm();
        let ok: bool = eval_reactor(
            &lua,
            &format!(
                r#"
            local chunks, done = {{}}, nil
            local s = agent.http("POST", "{url}", {{
              body = '{{"hello":"world"}}',
              headers = {{ ["content-type"] = "application/json" }},
              on_chunk = function(c) chunks[#chunks + 1] = c end,
              on_done = function(o) done = o end,
            }})
            s:run()
            assert(done ~= nil and done.status == 200, "on_done carries the status")
            assert(done.headers["content-type"] == "application/json", "headers surface")
            assert(table.concat(chunks) == '{{"hello":"world"}}', "body streamed")
            assert(s.status == 200, "stream object exposes the status")
            s:close()
            return true
            "#,
                url = fake.url("/http")
            ),
        )
        .await
        .expect("eval");
        assert!(ok, "agent.http streaming flow failed");
    }

    #[tokio::test]
    async fn agent_http_reports_transport_error_to_on_error() {
        // A port with nothing listening: on_error fires (not a raise).
        let dead = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let dead_addr = dead.local_addr().expect("addr");
        drop(dead);
        let lua = vm();
        let ok: bool = eval_reactor(
            &lua,
            &format!(
                r#"
            local err = nil
            local s = agent.http("POST", "http://{addr}/nope", {{
              body = "x",
              on_error = function(e) err = e end,
            }})
            s:run()
            assert(err ~= nil, "on_error must fire on a transport failure")
            assert(s.error ~= nil and s.done == true, "stream object records the error")
            s:close()
            return true
            "#,
                addr = dead_addr
            ),
        )
        .await
        .expect("eval");
        assert!(ok, "agent.http transport-error flow failed");
    }

    #[tokio::test]
    async fn agent_sse_streams_events_into_on_event() {
        let fake = FakeHttpServer::start(|_req: FakeRequest| {
            FakeServerReply::StreamEvents(vec![
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"
                    .to_string(),
                "event: note\ndata: hello\n\n".to_string(),
            ])
        });
        let lua = vm();
        let ok: bool = eval_reactor(
            &lua,
            &format!(
                r#"
            local got, closed = {{}}, false
            local s = agent.http("GET", "{url}", {{
              headers = {{ ["accept"] = "text/event-stream" }},
              on_event = function(event, data) got[#got + 1] = event .. "|" .. data end,
              on_done = function() closed = true end,
            }})
            s:run()
            assert(#got == 2, "both SSE events arrive")
            assert(got[1] == 'message|{{"jsonrpc":"2.0","id":1,"result":{{"ok":true}}}}', got[1])
            assert(got[2] == "note|hello", got[2])
            assert(closed, "on_done fires at the stream end")
            s:close()
            return true
            "#,
                url = fake.url("/events")
            ),
        )
        .await
        .expect("eval");
        assert!(ok, "the event-stream route of agent.http failed");
    }

    #[test]
    fn agent_http_sse_validation() {
        // Bad args are rejected before anything is fired.
        let lua = vm();
        let ok: bool = lua
            .load(
                r#"
            assert(not pcall(agent.http, 42, "http://x", {}), "bad method rejected")
            assert(not pcall(agent.http, "POST", "ftp://x", {}), "non-http url rejected")
            assert(not pcall(agent.http, "POST", "http://x", 5), "bad opts rejected")
            assert(not pcall(agent.http, "POST", "http://x", { on_chunk = "nope" }), "bad cb rejected")
            assert(not pcall(agent.http, "POST", "http://x", { headers = 5 }), "bad headers rejected")
            assert(not pcall(agent.http, "GET", nil, {}), "bad url rejected")
            assert(not pcall(agent.http, "GET", "http://x", { on_event = 5 }), "bad cb rejected")
            -- The stream route is what on_event + no body selects; the SSE
            -- transport is not reachable as a separate interface anymore.
            assert(agent.sse == nil, "agent.sse is merged into agent.http")
            return true
            "#,
            )
            .eval()
            .expect("eval");
        assert!(ok, "transport validation must reject bad args");
    }
