//! The file tools under the hood: the Lua `apply_patch` engine, and each read
//! or write asking about the path it resolved.
use super::*;

    /// than reading it off `agent`) keeps this usable on a bare VM.
    fn patch_apply(lua: &mlua::Lua, old: &str, diff: &str) -> serde_json::Value {
        lua.globals().set("PATCH_OLD", old).expect("set PATCH_OLD");
        lua.globals()
            .set("PATCH_DIFF", diff)
            .expect("set PATCH_DIFF");
        let json: String = lua
            .load(
                r#"
                local ok, res = pcall(require("fs").patch.apply, PATCH_OLD, PATCH_DIFF)
                if not ok then
                  return agent.api.json_encode({ ok = false, error = tostring(res) })
                end
                return agent.api.json_encode({ ok = true, content = res.content,
                                            added = res.added, removed = res.removed,
                                            before = res.before_changed, after = res.after_changed })
                "#,
            )
            .eval::<String>()
            .expect("run the fs patch engine");
        serde_json::from_str(&json).expect("patch apply result json")
    }

    #[test]
    fn patch_engine_applies_unified_diffs_in_lua() {
        let lua = shipped_vm();

        // Basic replace: context, counts, optional heading — and the changed
        // line spans in both directions.
        let v = patch_apply(
            &lua,
            "zero\none\ntwo\nthree\nfour\n",
            "--- a/x\n+++ b/x\n@@ -2,2 +2,3 @@ tune\n one\n-two\n+two and a half\n+THREE!\n",
        );
        assert_eq!(v["ok"], true, "basic apply failed: {v}");
        assert_eq!(
            v["content"],
            "zero\none\ntwo and a half\nTHREE!\nthree\nfour\n"
        );
        assert_eq!(v["added"], 2);
        assert_eq!(v["removed"], 1);
        assert_eq!(v["before"], serde_json::json!([[3, 3]]));
        assert_eq!(v["after"], serde_json::json!([[3, 4]]));

        // Multiple hunks, applied strictly in order.
        let v = patch_apply(
            &lua,
            "a\nb\nc\nd\ne\n",
            "@@ -1,2 +1,2 @@\n-a\n+x\n b\n@@ -4,2 +4,2 @@\n d\n-e\n+y\n",
        );
        assert_eq!(v["ok"], true, "multi-hunk failed: {v}");
        assert_eq!(v["content"], "x\nb\nc\nd\ny\n");

        // Insertion anchored by context; pure deletion with trailing context.
        let v = patch_apply(&lua, "a\nb\nc\n", "@@ -2,1 +2,2 @@\n b\n+mid\n");
        assert_eq!(v["ok"], true, "insert failed: {v}");
        assert_eq!(v["content"], "a\nb\nmid\nc\n");
        let v = patch_apply(&lua, "a\nb\nc\n", "@@ -1,1 +1,1 @@\n-a\n b\n");
        assert_eq!(v["ok"], true, "delete failed: {v}");
        assert_eq!(v["content"], "b\nc\n");

        // Bare "@@" headers (no position info at all) and line numbers that
        // lie — location is content-based, so drift changes nothing.
        let v = patch_apply(&lua, "x\ny\n", "@@\n x\n-y\n+z\n");
        assert_eq!(v["ok"], true, "bare header failed: {v}");
        assert_eq!(v["content"], "x\nz\n");
        let v = patch_apply(
            &lua,
            "one\ntwo\nthree\n",
            "@@ -100,1 +100,1 @@\n-two\n+deux\n",
        );
        assert_eq!(v["ok"], true, "wrong numbers failed: {v}");
        assert_eq!(v["content"], "one\ndeux\nthree\n");

        // Content lines that themselves start with '-' or '+' survive intact:
        // "--stay" removes the file line "-stay", "-+ move" removes the line
        // "+ move", and " -a" is a context line whose text is "-a".
        let v = patch_apply(
            &lua,
            "-stay\n+ move\n",
            "@@ -1,2 +1,2 @@\n--stay\n-+ move\n+-stay\n+= gone\n",
        );
        assert_eq!(v["ok"], true, "prefix content failed: {v}");
        assert_eq!(v["content"], "-stay\n= gone\n");
        assert_eq!(v["removed"], 2);
        assert_eq!(v["added"], 2);
        assert_eq!(v["before"], serde_json::json!([[1, 2]]));
        assert_eq!(v["after"], serde_json::json!([[1, 2]]));
        let v = patch_apply(&lua, "-a\nb\n", "@@ -1,2 +1,2 @@\n -a\n-b\n+c\n");
        assert_eq!(v["ok"], true, "dash context failed: {v}");
        assert_eq!(v["content"], "-a\nc\n");

        // The file's trailing newline is preserved on both sides, and a file
        // without one keeps none.
        let v = patch_apply(&lua, "a\nb\n", "@@ -1,1 +1,1 @@\n-a\n+x\n");
        assert_eq!(v["content"], "x\nb\n");
        let v = patch_apply(&lua, "a\nb", "@@ -1,1 +1,1 @@\n-a\n+x\n");
        assert_eq!(v["content"], "x\nb");

        // CRLF input is matched as LF and rewritten as LF on apply.
        let v = patch_apply(&lua, "a\r\nb\r\n", "@@ -1,2 +1,2 @@\n a\n-b\n+b2\n");
        assert_eq!(v["ok"], true, "crlf failed: {v}");
        assert_eq!(v["content"], "a\nb2\n");

        // A context-only hunk is a legal no-op (an already-applied patch).
        let v = patch_apply(&lua, "a\nb\n", "@@ -1,2 +1,2 @@\n a\n b\n");
        assert_eq!(v["ok"], true, "no-op failed: {v}");
        assert_eq!(v["content"], "a\nb\n");
        assert_eq!(v["added"], 0);
        assert_eq!(v["removed"], 0);

        // Already-applied hunks are no-ops, not duplications: re-applying a
        // pure insertion (the added lines already follow the context) and a
        // replacement (the old side is gone, the new side is present) both
        // reproduce the file exactly.
        let insert = "@@ -2,1 +2,2 @@\n b\n+mid\n";
        let v = patch_apply(&lua, "a\nb\nc\n", insert);
        assert_eq!(v["content"], "a\nb\nmid\nc\n", "first insert: {v}");
        let v = patch_apply(&lua, "a\nb\nmid\nc\n", insert);
        assert_eq!(v["content"], "a\nb\nmid\nc\n", "re-insert no-op: {v}");
        assert_eq!(v["added"], 0);
        let replace = "@@ -2,2 +2,2 @@\n b\n-c\n+d\n";
        let v = patch_apply(&lua, "a\nb\nc\n", replace);
        assert_eq!(v["content"], "a\nb\nd\n", "first replace: {v}");
        let v = patch_apply(&lua, "a\nb\nd\n", replace);
        assert_eq!(v["content"], "a\nb\nd\n", "re-replace no-op: {v}");
        assert_eq!(v["removed"], 0);
        assert_eq!(v["added"], 0);

        // Error paths are clean, named failures — never partial applies.
        let v = patch_apply(&lua, "a\n", "--- a/x\n+++ b/x\n");
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("no @@ hunks"));
        let v = patch_apply(&lua, "a\n", "@@ -0,0 +1,1 @@\n+nope\n");
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("without context"));
        let v = patch_apply(&lua, "a\n", "@@ -1,1 +1,1 @@\n-wrong\n+x\n");
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("does not match"));
        let v = patch_apply(&lua, "a\n", "@@ -1,1 +1,1 @@\nplain text line\n");
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("unexpected line"));
    }

    /// `write_file` asks before it writes, and the answer is the only gate:
    /// nothing is created until the user says yes, and a refusal creates nothing
    /// at all.
    #[test]
    fn write_file_asks_before_it_writes() {
        let dir = std::env::temp_dir().join(format!("agent-write-file-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let target = dir.join("nested/deep/hello.txt");
        let args = |content: &str| {
            serde_json::json!({
                "path": target.to_string_lossy().to_string(),
                "content": content,
            })
            .to_string()
        };

        // Refused: not one byte, not one directory.
        let (v, asked) = call_tool_asking("fs.write_file", &args("nope\n"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], false, "a refused write is not ok: {v}");
        assert_eq!(v["denied"], true, "and it says it was denied: {v}");
        assert_eq!(asked.len(), 1, "one question: {asked:?}");
        assert!(
            asked[0].contains("Allow write") && asked[0].contains(&target.to_string_lossy().to_string()),
            "the question names the write and the path: {:?}",
            asked[0]
        );
        assert!(!dir.exists(), "a refused write created nothing");

        // Allowed: the file lands verbatim, parent directories and all.
        let (v, asked) = tool_allowed("fs.write_file", &args("hello\nsandbox\n"));
        assert_eq!(v["ok"], true, "write failed: {v}");
        assert_eq!(v["result"]["bytes"], 14);
        assert_eq!(v["result"]["lines"], 2);
        assert_eq!(asked.len(), 1, "and it asked exactly once: {asked:?}");
        assert_eq!(
            std::fs::read_to_string(&target).expect("file on disk"),
            "hello\nsandbox\n",
            "content landed verbatim and the parent directories were created"
        );

        // Overwriting is a write too: it asks again, because a plain yes is for
        // that one operation.
        let (v, asked) = tool_allowed("fs.write_file", &args("x"));
        assert_eq!(v["ok"], true, "overwrite failed: {v}");
        assert_eq!(v["result"]["bytes"], 1);
        assert_eq!(asked.len(), 1, "asked again: {asked:?}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "x");

        // Missing required argument: validation catches it before the ask, so
        // nothing is even questioned.
        let (v, asked) = tool_allowed("fs.write_file", r#"{"content":"hi"}"#);
        assert_eq!(v["ok"], false, "validation error: {v}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("path"),
            "the error names the missing argument: {v}"
        );
        assert!(asked.is_empty(), "and nothing was asked: {asked:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `read` covers a file and a directory, and asks before either.
    ///
    /// The stdlib opens a directory happily and only fails on the *read*, so
    /// which one this is gets decided by `read(0)` returning nil — asserted
    /// here by both branches working, because a probe that guessed wrong would
    /// make one of them a clean error instead.
    #[test]
    fn the_read_tools_ask_and_return_the_file_directly() {
        let dir = std::env::temp_dir().join(format!("agent-fs-tools-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let target = dir.join("notes.txt");
        std::fs::write(&target, "alpha\nbeta\n").expect("seed");
        let path = target.to_string_lossy().to_string();
        let args = serde_json::json!({ "path": &path }).to_string();

        // A refused read returns the denial, not a complaint about the file.
        let (v, asked) = call_tool_asking("fs.read", &args, AskAnswer::Deny(None));
        assert_eq!(v["ok"], false, "a refused read is not ok: {v}");
        assert_eq!(v["denied"], true, "and it says it was denied: {v}");
        assert_eq!(asked.len(), 1, "one question: {asked:?}");
        assert!(
            asked[0].contains("Allow read") && asked[0].contains(&path),
            "the question names the read and the path: {:?}",
            asked[0]
        );

        // Allowed: the bytes, numbered by this module now (no `cat -n`).
        let (v, _asked) = tool_allowed("fs.read", &args);
        assert_eq!(v["ok"], true, "read failed: {v}");
        let content = v["result"]["content"].as_str().unwrap_or_default();
        assert_eq!(content, "1\talpha\n2\tbeta\n", "numbered, and nothing else: {content:?}");

        // The same tool, on a directory: the listing, and the same question.
        let dir_args =
            serde_json::json!({ "path": dir.to_string_lossy().to_string() }).to_string();
        let (v, asked) = tool_allowed("fs.read", &dir_args);
        assert_eq!(v["ok"], true, "listing a directory failed: {v}");
        assert!(
            v["result"]["content"].as_str().unwrap_or_default().contains("notes.txt"),
            "the listing names the file: {v}"
        );
        assert_eq!(asked.len(), 1, "asked once: {asked:?}");
        assert!(
            asked[0].contains("Allow read"),
            "a listing is still a read: {:?}",
            asked[0]
        );

        // A directory that is not there is a clean error, not a crash.
        let missing =
            serde_json::json!({ "path": dir.join("nope").to_string_lossy().to_string() })
                .to_string();
        let (v, _) = tool_allowed("fs.read", &missing);
        assert_eq!(v["ok"], false, "reading a missing path fails cleanly: {v}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ask_lib_asks_from_a_policy_and_keeps_the_reason() {
        // Asks on any write open, using agent.seccomp for the flags and
        // agent.ask for the question — no magic numbers, no raw yield.
        const POLICY: &str = r#"
        local sc, ask = agent.seccomp, agent.ask
        local p = setmetatable({}, { __index = function() return function() return true end end })
        p.openat = function(sys)
          local flags = sc.arg(sys, "openat")
          if sc.is_tty_probe(flags) then return true end
          if sc.check("openat", flags, "WRITE") then
            return ask(ask.for_syscall(sys, "write", sc.describes("openat", flags)))
          end
          return true
        end
        return p
        "#;
        let path = std::env::temp_dir().join(format!("ask-lib-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let cmdline = format!("echo asked > {}", path.display());

        // Denied: the handler's reason is what the outcome reports.
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let out = run_bash(
            &cmdline,
            POLICY,
            None,
            Some(Rc::new(move |text: &str, _always: bool| {
                seen.borrow_mut().push(text.to_string());
                AskAnswer::Deny(Some("the operator said no".to_string()))
            })),
        )
        .expect("bash ran");
        assert!(out.denied >= 1, "the ask denied the write open");
        assert!(out.failed(), "a denied ask must not exit cleanly");
        assert_eq!(
            out.denied_reason.as_deref(),
            Some("the operator said no"),
            "the handler's reason survives the ask"
        );
        assert!(!path.exists(), "a denied open must not create the file");
        let questions = asked.borrow().clone();
        assert_eq!(questions.len(), 1, "one ask: {questions:?}");
        assert!(
            questions[0].contains("openat (pid") && questions[0].contains("requests write"),
            "the question is the canonical description: {}",
            questions[0]
        );

        // Allowed: the same policy, allowed, completes the run.
        let out = run_bash(
            &cmdline,
            POLICY,
            None,
            Some(Rc::new(|_, _always: bool| AskAnswer::Allow)),
        )
        .expect("bash ran");
        assert_eq!(out.denied, 0, "an allowed ask lets the open through");
        assert!(!out.failed(), "the allowed run finishes: {out:?}");
        assert_eq!(
            std::fs::read_to_string(&path).expect("written"),
            "asked\n",
            "the allowed write landed"
        );
        let _ = std::fs::remove_file(&path);

        // The no-handler case, through ask.drive: a denial that names itself
        // rather than the exception s:run() would raise mid-run.
        let lua = vm();
        lua.globals().set("ASK_CMDLINE", cmdline.clone()).expect("cmdline");
        lua.globals().set("ASK_POLICY", POLICY).expect("policy");
        let reason: Option<String> = lua
            .load(
                r#"
            -- `run_bash` takes a policy *source string* (it splices it into a
            -- chunk); agent.bash wants the table, so build it here.
            local policy = assert(load(ASK_POLICY))()
            local s = agent.bash(ASK_CMDLINE, policy, {})
            -- ask.drive with no handler: the ask resolves to a denial.
            local r = agent.ask.drive(s)
            return r.denied > 0 and r.denied_reason or nil
        "#,
            )
            .eval()
            .expect("ask.drive eval");
        assert!(
            reason.as_deref().is_some_and(|r| r.starts_with("no ask handler")),
            "the default handler names the missing handler, got {reason:?}"
        );
    }

    /// A reasonless denial must stay reasonless all the way to the outcome:
    /// `denied_reason = nil` and a bare "Denied" on the panel. A policy that
    /// *asks* and is answered with a plain `false` is exactly that case — and
    /// it is how the headless bash tool denies (no user to ask).
    #[test]
    fn a_reasonless_ask_denial_carries_no_reason() {
        const POLICY: &str = r#"
        local sc, ask = agent.seccomp, agent.ask
        local p = setmetatable({}, { __index = function() return function() return true end end })
        p.openat = function(sys)
          local flags = sc.arg(sys, "openat")
          if sc.is_tty_probe(flags) then return true end
          if sc.check("openat", flags, "WRITE") then
            -- The path comes from the module too: no sys.str indexing here.
            return ask("write open on " .. (sc.path(sys) or "?"))
          end
          return true
        end
        return p
        "#;
        let path = std::env::temp_dir().join(format!("ask-noreason-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        // Headless: no ask handler, so `agent.api.ask_user` answers `false`.
        let out = run_bash(&format!("echo x > {}", path.display()), POLICY, None, None)
            .expect("bash ran");
        assert!(out.denied >= 1, "the ask denied the write open");
        assert_eq!(
            out.denied_reason, None,
            "a plain false must not fabricate a reason"
        );
        assert!(!path.exists(), "nothing was written");
        let _ = std::fs::remove_file(&path);

        // The path really does reach the question: the file name appears in the
        // description, resolved by the engine (not raw from `sys.str`).
        let wanted = path.file_name().unwrap().to_string_lossy().to_string();
        let out = run_bash(
            &format!("echo x > {}", path.display()),
            POLICY,
            None,
            Some(Rc::new(move |text: &str, _always: bool| {
                assert!(text.contains(&wanted), "the question names the file: {text}");
                AskAnswer::Deny(Some("no".to_string()))
            })),
        )
        .expect("bash ran");
        assert!(out.denied >= 1);
    }

    #[test]
    fn apply_patch_tool_edits_a_file_and_reports_changes() {
        let dir =
            std::env::temp_dir().join(format!("agent-apply-patch-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let target = dir.join("script.txt");
        std::fs::create_dir_all(&dir).expect("make scratch dir");
        std::fs::write(&target, "one\ntwo\nthree\n").expect("seed file");

        // Insert a line after "two": the tool reads, applies, writes, and
        // reports the count of changed lines.
        let patch = "@@ -2,1 +2,2 @@\n two\n+two and a half\n";
        let args = serde_json::json!({
            "path": target.to_string_lossy().to_string(),
            "patch": patch,
        })
        .to_string();
        // A patch is one write decision: one question, then the read the diff
        // needs and the write itself, both direct.
        let (v, asked) = tool_allowed("fs.apply_patch", &args);
        let body = v.to_string();
        assert_eq!(asked.len(), 1, "one question for the whole patch: {asked:?}");
        assert!(
            asked[0].contains("Allow write")
                && asked[0].contains(&target.to_string_lossy().to_string()),
            "the question names the write and the path: {:?}",
            asked[0]
        );
        assert_eq!(v["ok"], true, "patch failed: {body}");
        assert_eq!(v["result"]["changed"], true);
        assert_eq!(v["result"]["added"], 1);
        assert_eq!(v["result"]["removed"], 0);
        assert_eq!(
            std::fs::read_to_string(&target).expect("read back"),
            "one\ntwo\ntwo and a half\nthree\n"
        );

        // Applying the identical patch again is a no-op: matched by content,
        // the recomputed text equals the file, so nothing is rewritten.
        let (v, _) = tool_allowed("fs.apply_patch", &args);
        let body = v.to_string();
        assert_eq!(v["ok"], true, "idempotent apply failed: {body}");
        assert_eq!(v["result"]["changed"], false, "{body}");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "one\ntwo\ntwo and a half\nthree\n",
            "a no-op patch leaves the file untouched"
        );

        // A hunk that does not match the file is a clean error and nothing is
        // written — the failed apply never corrupts the file.
        let bad = serde_json::json!({
            "path": target.to_string_lossy().to_string(),
            "patch": "@@ -1,1 +1,1 @@\n-nope\n+yes\n",
        })
        .to_string();
        let (v, _) = tool_allowed("fs.apply_patch", &bad);
        let body = v.to_string();
        assert_eq!(v["ok"], false, "bad patch errors: {body}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("does not match"),
            "the error names the failing hunk: {body}"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "one\ntwo\ntwo and a half\nthree\n",
            "a failed patch left the file alone"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
