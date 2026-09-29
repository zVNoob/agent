//! Trust outliving the call that granted it, and a question the driver has to
//! answer as a step.
use super::*;

use crate::testutil::scratch_dir;
    /// A tool call runs on the agent's own VM, so what it decides *persists*:
    /// a path trusted with `[a]lways` is not asked about again on the next call.
    /// That is the whole point of running tools on the config VM rather than a
    /// throwaway one — the trust tables used to die with the tool's own VM, so
    /// every operation asked, every time.
    #[test]
    fn a_tool_calls_trust_outlives_the_call_that_granted_it() {
        let lua = shipped_vm();
        let dir = scratch_dir("agent-toolrun-trust");
        let args = |name: &str| {
            serde_json::json!({
                "path": dir.join(name).to_string_lossy(),
                "content": "payload\n",
            })
            .to_string()
        };

        // A plain yes is for that one operation: the next call asks again.
        let (v, asked) = drive_on_vm(&lua, "fs.write_file", &args("a.txt"), |_, _| AskAnswer::Allow);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked.len(), 1, "asked: {asked:?}");
        let (v, asked) = drive_on_vm(&lua, "fs.write_file", &args("a.txt"), |_, _| AskAnswer::Allow);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked.len(), 1, "a plain yes is not remembered: {asked:?}");

        // "always" *is* remembered, because the tables live on this VM now.
        let (v, asked) = drive_on_vm(&lua, "fs.write_file", &args("a.txt"), |_, _| {
            AskAnswer::AllowAndTrust
        });
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked.len(), 1, "asked once: {asked:?}");
        let (v, asked) =
            drive_on_vm(&lua, "fs.write_file", &args("a.txt"), |_, _| AskAnswer::Deny(None));
        assert_eq!(v["ok"], true, "the remembered path needs no answer: {v}");
        assert!(asked.is_empty(), "and asks nothing at all: {asked:?}");

        // A different path is a different question: trust is a path, not a
        // blanket permission.
        let (v, asked) = drive_on_vm(&lua, "fs.write_file", &args("b.txt"), |_, _| AskAnswer::Allow);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked.len(), 1, "another path still asks: {asked:?}");

        // And forgetting the *write* trust puts that question back — while the
        // path stays trusted for reading, which is the narrow revocation
        // `forget_write` exists for. (It is also the check that catches a write
        // being allowed on read-trust alone: the general entry is still here.)
        let forgotten = dir.join("a.txt").to_string_lossy().to_string();
        let hit: bool = lua
            .load(format!("return agent.ask.forget_write({forgotten:?})"))
            .eval()
            .expect("forget_write");
        assert!(hit, "the path was write-trusted: {forgotten}");
        let read_still: bool = lua
            .load(format!("return agent.ask.is_trusted({forgotten:?})"))
            .eval()
            .expect("is_trusted");
        assert!(read_still, "and read-trust is untouched by a write revocation");
        let (v, asked) = drive_on_vm(&lua, "fs.write_file", &args("a.txt"), |_, _| AskAnswer::Allow);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked.len(), 1, "a forgotten path asks again: {asked:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other half of the loop's contract: a question reaches the loop as a
    /// step, with the wording the user sees and Lua's own `always` flag — and
    /// the answer is delivered back to the yield site as a plain value.
    #[test]
    fn a_tool_question_is_a_step_the_driver_answers() {
        let lua = shipped_vm();
        let dir = scratch_dir("agent-toolrun-ask");
        let target = dir.join("notes.txt");
        let args = serde_json::json!({ "path": target.to_string_lossy() }).to_string();

        // A read that is refused: the tool reports the denial, and the loop's
        // answer is what decided it.
        let (mut run, step) = ToolRun::start(&lua, "fs.read", &args)
            .expect("start")
            .expect("registered read");
        let (text, remember) = match step {
            ToolStep::Ask { text, remember } => (text, remember),
            other => panic!("expected a question, got {other:?}"),
        };
        assert_eq!(
            text,
            format!("Allow read {}", target.to_string_lossy()),
            "the question names the path"
        );
        assert_eq!(
            remember.as_deref(),
            Some(ALWAYS_LABEL),
            "a file operation can be remembered, and says so by name"
        );
        let step = run
            .answer(verdict_to_lua(
                &lua,
                &AskAnswer::Deny(Some("user said no".to_string())),
            ))
            .expect("answer");
        let ToolStep::Returned(body) = step else {
            panic!("a denial finishes the call, got {step:?}")
        };
        let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["denied"], true, "{v}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("user said no"),
            "and it carries the reason the user gave: {v}"
        );
        assert!(!target.exists(), "a refused read creates nothing");

        // A question with nothing to remember does not offer "always": a bare
        // string ask has no path, so `[a]lways` would have nothing to record.
        lua.load(
            r#"
            agent.mcps.askonce = { name = "askonce", tools = { askonce = {
              description = "ask once",
              callback = function() return agent.ask("a question with no path") end,
            } } }
        "#,
        )
        .exec()
        .expect("register a bare-ask tool");
        let (mut run, step) = ToolRun::start(&lua, "askonce.askonce", "{}").expect("start").unwrap();
        match step {
            ToolStep::Ask { text, remember } => {
                assert_eq!(text, "a question with no path");
                assert!(
                    remember.is_none(),
                    "nothing to remember, so no third answer at all"
                );
            }
            other => panic!("expected a question, got {other:?}"),
        }
        let step = run
            .answer(verdict_to_lua(&lua, &AskAnswer::Allow))
            .expect("answer");
        assert!(matches!(step, ToolStep::Returned(_)), "{step:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }
