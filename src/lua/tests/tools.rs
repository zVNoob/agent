//! The shipped tools as the model meets them: `bash` (`lua/bash_tool.lua` +
//! `lua/policy.lua`) and the file tools (`lua/fs.lua`). These look at what the
//! *user* sees — a panel, a dialog, a captured stdout — rather than at what the
//! model gets back.
use super::*;

use crate::testutil::scratch_dir;
    /// The compact spec is a *table*, not a side effect: requiring it registers
    /// nothing, so `agent.mode.new("compact", require("compact"))` is the whole
    /// setup and a spec can be inspected, copied, or composed before it is
    /// named. A `require` that quietly switched modes would make the setup line
    /// mean two things.
    #[test]
    fn the_compact_spec_is_inert_until_it_is_named() {
        let lua = shipped_vm();
        // The shipped config starts in the `coding` mode, so clear to the baseline
        // first: "the baseline" here means what `agent.mode.set()` restores, and
        // that is not the state the config left the VM in.
        lua.load("agent.mode.set()").exec().expect("clear to the baseline");
        let baseline = system_prompt(&lua).expect("prompt");
        let spec: String = lua
            .load(
                r#"
            local spec = require("compact")
            if agent.mode.current() ~= nil then return "a require switched modes" end
            if type(spec.system_prompt) ~= "string" or spec.system_prompt == "" then
              return "no prompt"
            end
            if type(spec.mcps) ~= "table" or next(spec.mcps) ~= nil then
              return "the registry is not empty"
            end
            if type(spec.description) ~= "string" then return "no description" end
            -- The same table every time: one spec, many possible names.
            if require("compact") ~= spec then return "require re-ran it" end
            return spec.description
        "#,
            )
            .eval()
            .expect("compact spec");
        assert!(spec.contains("compact"), "{spec}");
        assert_eq!(
            system_prompt(&lua).expect("prompt"),
            baseline,
            "and the baseline prompt never moved"
        );
    }

    // -----------------------------------------------------------------------
    // The `bash` tool, as a connection: `lua/bash_tool.lua` + `lua/policy.lua`
    // are what the built-in ToolDef used to be, and every assertion here is
    // about the *shipped* path — the registry advertises it, the MCP reply is
    // well-formed, and the panel/ask seam behaves. (The engine contract under
    // `agent.bash` itself is pinned by the `run_bash` tests above.)
    // -----------------------------------------------------------------------

    /// The shell is a registered connection, advertised like every other tool —
    /// and it is the *only* built-in-looking thing in the catalog, because there
    /// are no built-ins.
    #[test]
    fn the_bash_tool_is_an_ordinary_registered_tool() {
        let lua = shipped_vm();
        let defs = mcps_tool_defs(&lua).expect("reindex");
        let mut names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["bash.bash", "fs.apply_patch", "fs.hand_to_user", "fs.read", "fs.write_file"],
            "the shell is advertised because the config registered it, nothing else is"
        );
        let def = defs
            .into_iter()
            .find(|d| d.name == "bash.bash")
            .expect("bash.bash def");
        assert!(
            def.description.contains("seccomp sandbox"),
            "the tool describes itself: {}",
            def.description
        );
        let required: Vec<String> = serde_json::from_value(def.parameters["required"].clone())
            .expect("required is a list");
        assert_eq!(required, ["cmdline"], "cmdline is required");
    }

    #[test]
    fn the_bash_tool_runs_a_command_and_reports_the_outcome() {
        let sink = PanelSink::default();
        let v = call_bash(r#"{"cmdline":"echo from the lua tool"}"#, &sink, allow_all());
        assert_eq!(v["ok"], true, "a run that completes is ok: {v}");
        assert_eq!(v["result"]["stdout"], "from the lua tool\n");
        assert_eq!(v["result"]["stderr"], "");
        assert_eq!(v["result"]["exit_code"], 0);
        assert!(v["result"]["exit_signal"].is_null(), "no signal on a clean exit");
        // No `syscalls` field: a raw total of every trapped call said nothing
        // about the command, and `denied` is the number a reader can act on.
        assert!(
            v["result"].get("syscalls").is_none(),
            "the syscall total is gone: {v}"
        );
        assert_eq!(v["result"]["denied"], 0);
        assert!(v["result"]["denied_reason"].is_null());

        // A non-zero exit is still a completed run: `ok` means "the tool ran",
        // and the status is in the result for the model to read.
        let v = call_bash(r#"{"cmdline":"exit 3"}"#, &sink, allow_all());
        assert_eq!(v["ok"], true, "a failing command is not a tool failure: {v}");
        assert_eq!(v["result"]["exit_code"], 3);
    }

    #[test]
    fn the_bash_tool_rejects_a_missing_cmdline() {
        let sink = PanelSink::default();
        // Never a sandboxed run: a bad argument is the tool's own error.
        let v = call_bash("{}", &sink, None);
        assert_eq!(v["ok"], false, "{v}");
        assert!(
            v["error"].as_str().unwrap_or_default().contains("cmdline"),
            "the error names the argument: {v}"
        );
        assert!(sink.ops().is_empty(), "no run, so no panel: {:?}", sink.ops());
    }

    /// Headless, the shipped policy's ask auto-denies, so the shell stays
    /// read-only: the write-open fails, the file is never created, and the reply
    /// says the tool did not complete.
    #[test]
    fn the_bash_tool_blocks_write_opens_headless() {
        let sink = PanelSink::default();
        for p in ["/tmp/agent-lua-bash-w", "/tmp/agent-lua-bash-rw"] {
            let _ = std::fs::remove_file(p);
        }
        for (cmdline, path) in [
            ("echo w > /tmp/agent-lua-bash-w; echo past", "/tmp/agent-lua-bash-w"),
            (
                "exec 3<>/tmp/agent-lua-bash-rw; echo past",
                "/tmp/agent-lua-bash-rw",
            ),
        ] {
            let v = call_bash(
                &serde_json::json!({ "cmdline": cmdline }).to_string(),
                &sink,
                None,
            );
            assert_eq!(v["ok"], false, "the write was refused: {v}");
            assert!(
                v["result"]["denied"].as_u64().unwrap() >= 1,
                "the denied counter moved: {cmdline}: {v}"
            );
            assert!(
                v["error"].as_str().unwrap_or_default().starts_with("denied:"),
                "the error says why: {v}"
            );
            // A reasonless denial invents no reason.
            assert!(
                v["result"]["denied_reason"].is_null(),
                "an ask-denial carries no reason: {cmdline}: {v}"
            );
            assert!(
                !std::path::Path::new(path).exists(),
                "a denied open must not create {path}"
            );
            assert!(
                !v["result"]["stdout"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("past"),
                "the tracee dies before the echo after a denied open"
            );
        }
    }

    #[test]
    fn the_bash_tool_streams_stdout_into_a_result_panel() {
        // The round's sink flows through the tool's VM into the Lua driver: the
        // panel is created before the sandbox spawns, each stdout chunk is
        // appended as it arrives, and a status line finishes it.
        let sink = PanelSink::default();
        let v = call_bash(r#"{"cmdline":"echo from sandbox"}"#, &sink, allow_all());
        assert_eq!(v["ok"], true, "{v}");
        let ops = sink.ops();
        let PanelOp::Create {
            id,
            title,
            boxed,
            conceal_box,
        } = &ops[0]
        else {
            panic!("expected Create first, got {:?}", ops[0]);
        };
        assert_eq!(*id, 1);
        assert_eq!(title, "echo from sandbox", "the command is the title");
        assert!(*boxed && !*conceal_box, "a raw tool-style box, {ops:?}");
        let mut streamed = String::new();
        for op in &ops[1..] {
            match op {
                PanelOp::Append { id, text } => {
                    assert_eq!(*id, 1, "all appends target the stream panel");
                    streamed.push_str(text);
                }
                // The overlay an ask sets and clears, interleaved with the
                // stream. The default policy asks about every open, so a run that
                // needs a library has one; the overlay seam itself is pinned by
                // `the_bash_tool_panels_a_denial`.
                PanelOp::Overlay { id, .. } => assert_eq!(*id, 1, "the overlay is the same panel"),
                other => panic!("expected Append or Overlay, got {other:?}"),
            }
        }
        assert_eq!(
            streamed, "from sandbox\nexited with exit code 0",
            "the stream plus its status line"
        );
    }

    /// The title is one row, so a command with newlines or runs of whitespace
    /// in it is flattened — otherwise a multi-line command would break the top
    /// border of its own box. The renderer cuts a title that is still too wide.
    #[test]
    fn the_bash_tool_titles_its_panel_with_one_line_of_the_command() {
        let cases = [
            (r#"{"cmdline":"echo a && echo b"}"#, "echo a && echo b"),
            (r#"{"cmdline":"echo a\n\necho b"}"#, "echo a echo b"),
            (r#"{"cmdline":"  echo\ta  "}"#, "echo a"),
            (r#"{"cmdline":"for i in 1 2 3; do echo $i; done"}"#, "for i in 1 2 3; do echo $i; done"),
        ];
        for (args, want) in cases {
            let sink = PanelSink::default();
            let v = call_bash(args, &sink, allow_all());
            assert_eq!(v["ok"], true, "{args}: {v}");
            let ops = sink.ops();
            let Some(PanelOp::Create { title, .. }) = ops.first() else {
                panic!("{args}: expected a Create first");
            };
            assert_eq!(title, want, "{args}");
            assert!(
                !title.contains('\n') && !title.contains('\r'),
                "a title is one row: {title:?}"
            );
        }
    }

    /// A denied run streams whatever arrived before the kill (often nothing) and
    /// appends "Denied" instead of an exit line. The ask it raises is drawn by
    /// the event loop, not by the tool.
    #[test]
    fn the_bash_tool_panels_a_denial() {
        let _ = std::fs::remove_file("/tmp/agent-lua-bash-panel-deny");
        let sink = PanelSink::default();
        let v = call_bash(
            r#"{"cmdline":"exec 3<>/tmp/agent-lua-bash-panel-deny; echo past"}"#,
            &sink,
            None,
        );
        assert!(v["result"]["denied"].as_u64().unwrap() >= 1, "open denied");
        assert!(
            !v["result"]["stdout"].as_str().unwrap_or_default().contains("past"),
            "the tracee dies before the echo"
        );
        let _ = std::fs::remove_file("/tmp/agent-lua-bash-panel-deny");

        let ops = sink.ops();
        let mut streamed = String::new();
        for op in &ops {
            if let PanelOp::Append { text, .. } = op {
                streamed.push_str(text);
            }
        }
        assert_eq!(streamed, "Denied", "a denied run appends its status line");

        // The dialog is the tool's own, on the panel the command is running in:
        // `p:ask` sets it, waits, and clears it, so the question appears inside
        // the run's box and leaves when the verdict lands. The driver draws
        // nothing and adds no message of its own.
        let dialogs: Vec<&PanelOp> = ops
            .iter()
            .filter(|op| matches!(op, PanelOp::Overlay { .. }))
            .collect();
        assert_eq!(dialogs.len(), 2, "asked, then cleared: {ops:?}");
        let PanelOp::Overlay { id, text, always } = dialogs[0] else {
            unreachable!("filtered above");
        };
        assert_eq!(*id, 1, "on the command's own panel, not another message");
        let desc = text.as_deref().unwrap_or_default();
        assert!(
            desc.contains("The process want to") && desc.contains('/'),
            "the dialog shows the question and the path it is about: {desc:?}"
        );
        assert!(*always, "a path can be remembered, so `always` is offered");
        let PanelOp::Overlay { text, .. } = dialogs[1] else {
            unreachable!("filtered above");
        };
        assert!(text.is_none(), "and it clears once the verdict lands");
    }

    /// The interactive path: the call's ask handler decides each frozen syscall.
    /// Allowing the write lets the command finish and create its file; denying
    /// it reproduces the headless outcome — and a denial that names a reason
    /// carries it all the way into the tool JSON and the panel status line.
    #[test]
    fn the_bash_tool_routes_ask_verdicts() {
        let _ = std::fs::remove_file("/tmp/agent-lua-bash-allow");
        let allow_sink = PanelSink::default();
        let v = call_bash(
            r#"{"cmdline":"echo written > /tmp/agent-lua-bash-allow"}"#,
            &allow_sink,
            Some(Rc::new(|_, _always: bool| AskAnswer::Allow)),
        );
        assert_eq!(v["ok"], true, "an allowed write completes: {v}");
        assert_eq!(v["result"]["denied"], 0);
        assert!(
            std::path::Path::new("/tmp/agent-lua-bash-allow").exists(),
            "the allowed open created the file"
        );
        assert!(
            v["result"]["stdout"].as_str().unwrap().is_empty(),
            "the echo went to the file, not stdout: {v}"
        );

        let _ = std::fs::remove_file("/tmp/agent-lua-bash-deny");
        let deny_sink = PanelSink::default();
        let v = call_bash(
            r#"{"cmdline":"exec 3<>/tmp/agent-lua-bash-deny; echo past"}"#,
            &deny_sink,
            Some(Rc::new(|_, _always: bool| AskAnswer::Deny(Some("user refused".to_string())))),
        );
        assert_eq!(v["ok"], false, "a refused write is not ok: {v}");
        assert_eq!(v["result"]["denied_reason"], "user refused");
        assert!(
            v["error"].as_str().unwrap_or_default().contains("user refused"),
            "the reply carries the reason: {v}"
        );
        assert!(
            !std::path::Path::new("/tmp/agent-lua-bash-deny").exists(),
            "a denied open must not create the file"
        );
        // The status line names the reason too.
        let streamed: String = deny_sink
            .ops()
            .iter()
            .filter_map(|op| match op {
                PanelOp::Append { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(streamed, "Denied: user refused");
        let _ = std::fs::remove_file("/tmp/agent-lua-bash-allow");
        let _ = std::fs::remove_file("/tmp/agent-lua-bash-deny");
    }

    /// The file tools ask, and the question names the path the agent is really
    /// about — including where that came from when the model wrote something
    /// else. A relative path is resolved before the user is asked, so the
    /// question is answerable: "allow writing this" means nothing if the user
    /// cannot see which file.
    #[test]
    fn the_file_tools_ask_about_the_resolved_path() {
        let dir = scratch_dir("agent-fs-ask");
        let target = dir.join("notes.txt");
        std::fs::write(&target, "x\n").expect("seed");
        let path = target.to_string_lossy().to_string();

        // A model that writes an absolute path: asked about exactly that.
        let (v, asked) = tool_allowed("fs.read", &serde_json::json!({ "path": &path }).to_string());
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked, vec![format!("Allow read {path}")], "the whole question");

        // A path the model wrote that is not the path it means: the question
        // carries the resolved one and says where it came from. The spelling here
        // is untidy rather than relative — it resolves to the *same* file through
        // a `..` — because the working directory is trusted by `lua/init.lua`, and
        // a relative path would resolve inside it and never be asked about at all.
        // (Which is the grant working, not a gap in it.)
        //
        // Built from the real `dir`, so the detour still lands on the file the
        // fixture wrote — a hand-spelled path naming the pid would break the
        // moment `unique_path`'s counter made the two names differ.
        let untidy = format!("{}/./x/../notes.txt", dir.display());
        std::fs::create_dir_all(dir.join("x")).expect("the segment the path detours through");
        let (v, asked) =
            tool_allowed("fs.read", &serde_json::json!({ "path": &untidy }).to_string());
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(
            asked,
            vec![format!("Allow read {path}, which is the symlink of {untidy}")],
            "resolved, and the model's own spelling named"
        );

        // A write asks the write question about the same resolved path.
        let (v, asked) = tool_allowed(
            "fs.write_file",
            &serde_json::json!({ "path": &path, "content": "y\n" }).to_string(),
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked, vec![format!("Allow write {path}")], "a write asks about writing");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "y\n", "and it wrote");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `read` names the file it read, and shows nothing else.
    ///
    /// The withheld half is the point. A tool call puts nothing in the
    /// transcript, so this panel is the *only* trace of the read — and it is
    /// still not the file. The content is the model's to have; printing it here
    /// too would put every read back on screen a second time, which is the
    /// duplication the per-call result boxes were removed for.
    #[test]
    fn read_names_the_path_and_withholds_the_content() {
        let dir = scratch_dir("agent-fs-read");
        let target = dir.join("secret.txt");
        // Distinctive enough that finding it in a panel op would be unambiguous.
        std::fs::write(&target, "CANARY-LINE-ONE\nCANARY-LINE-TWO\n").expect("seed");
        let path = target.to_string_lossy().to_string();

        let sink = PanelSink::default();
        let (body, _) = invoke_mcp_tool_with_asks(
            "fs.read",
            &serde_json::json!({ "path": &path }).to_string(),
            Some(&sink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("the shipped config registers fs.read");

        // The model still gets the file, in full — this is a panel, not a
        // truncation of the tool's result.
        assert!(
            body.contains("CANARY-LINE-ONE") && body.contains("CANARY-LINE-TWO"),
            "the model reads the whole file: {body}"
        );

        let drawn: Vec<String> = sink
            .ops()
            .iter()
            .map(|op| match op {
                PanelOp::Create { title, .. } => format!("┌─ {title}"),
                PanelOp::Append { text, .. } => text.clone(),
                _ => String::new(),
            })
            .collect();
        let panel = drawn.join("\n");
        assert!(
            panel.contains("┌─ fs.read"),
            "titled like every other tool panel: {panel:?}"
        );
        assert!(
            panel.contains(&path),
            "and it names the path: {panel:?}"
        );
        assert!(
            !panel.contains("CANARY"),
            "and shows none of the content: {panel:?}"
        );
        // One line, because the path the model wrote *is* the path. The second
        // line is for when it is not — see the untidy case below.
        // Only the title and the text ops: the overlay ops that put the
        // question up and take it down are not part of what the panel says.
        let body_lines: Vec<&String> = drawn
            .iter()
            .filter(|l| !l.starts_with('┌') && !l.is_empty())
            .collect();
        assert_eq!(
            body_lines,
            vec![&format!("{path}\n")],
            "exactly the resolved path, and nothing else: {panel:?}"
        );

        // A path that is not the one it means: both are shown, because a panel
        // naming only the resolved one would leave the model looking at a file
        // it never wrote, and the *question* already names the other.
        //
        // Built from the real `dir`, so the detour still lands on the file the
        // fixture wrote — a hand-spelled path naming the pid would break the
        // moment the counter made two paths differ.
        let untidy = format!("{}/./x/../secret.txt", dir.display());
        std::fs::create_dir_all(dir.join("x")).expect("the segment the path detours through");
        let usink = PanelSink::default();
        invoke_mcp_tool_with_asks(
            "fs.read",
            &serde_json::json!({ "path": &untidy }).to_string(),
            Some(&usink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("registered");
        let ubody: String = usink
            .ops()
            .iter()
            .filter_map(|op| match op {
                PanelOp::Append { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert!(
            ubody.contains(&path) && ubody.contains(&untidy),
            "both paths when they differ: {ubody:?}"
        );
        assert!(
            ubody.contains("which is the symlink of"),
            "and it says which is which: {ubody:?}"
        );

        // The path is the whole of it: one panel, no line numbers, no envelope.
        assert_eq!(
            drawn
                .iter()
                .filter(|l| l.starts_with('┌'))
                .count(),
            1,
            "exactly one panel for one read: {panel:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A read the user refuses still says so, in the panel it already opened.
    /// A tool call is silent everywhere else, so a panel that appeared and then
    /// `write_file` shows the bytes it wrote, with the file's own grammar
    /// declared — the reverse of `read`, and deliberately so: a read's
    /// content is the model's to consume, but a write changes the user's files,
    /// so what landed on disk is the thing being checked.
    #[test]
    fn write_file_shows_the_content_with_its_language_declared() {
        let dir = scratch_dir("agent-fs-write");
        let target = dir.join("shown.rs");
        let path = target.to_string_lossy().to_string();
        // Something the grammar will actually recognise, so "highlighted" is a
        // claim about a real parse rather than about a fence.
        let content = "fn main() {\n    let x: u32 = 7;\n    println!(\"{}\", x);\n}\n";

        let sink = PanelSink::default();
        let (body, _) = invoke_mcp_tool_with_asks(
            "fs.write_file",
            &serde_json::json!({ "path": &path, "content": content }).to_string(),
            Some(&sink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("the shipped config registers fs.write_file");

        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            content,
            "and it wrote the bytes verbatim"
        );
        assert!(body.contains("written") || body.contains("bytes"), "the model is told: {body}");

        // The panel, and the grammar on it.
        let ops = sink.ops();
        let split = ops
            .iter()
            .find_map(|op| match op {
                PanelOp::Split { title, panes, .. } => Some((title.clone(), panes.clone())),
                _ => None,
            })
            .unwrap_or_else(|| panic!("write_file drew no split panel: {ops:?}"));
        assert!(
            split.0.starts_with("write_file: ") && split.0.contains(&path),
            "titled with the tool and the file it changed: {:?}", split.0
        );
        assert_eq!(split.1.len(), 1, "one pane: there is only an \'after\'");
        assert_eq!(
            split.1[0].lang.as_deref(),
            Some("rust"),
            "and the file's own grammar, which is the whole of \'highlighted\': {:?}",
            split.1[0]
        );
        assert_eq!(
            split.1[0].caption,
            format!("{} lines, {} bytes", content.lines().count(), content.len()),
            "the caption sizes it, and agrees: {:?}",
            split.1[0].caption
        );

        // The content is in the pane, and the pane is the only copy on screen.
        let pane_text = ops
            .iter()
            .find_map(|op| match op {
                PanelOp::SetPane { text, .. } => Some(text.clone()),
                _ => None,
            })
            .unwrap_or_default();
        assert!(pane_text.contains("fn main()"), "the content is shown: {pane_text:?}");
        assert_eq!(pane_text, content, "and shown as written, not reformatted");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A one-line file gets "1 line", not "1 lines". Caught by looking at a
    /// live panel rather than by any test: the first run of this said "1 lines"
    /// and it was the sort of thing a reader stops trusting the rest of the box
    /// The permission question is drawn, as a dialog, inside the panel of the
    /// tool that raised it.
    ///
    /// This is the fix for a question asked into the void. `raise_ask` was a
    /// bare `coroutine.yield`: it reached the loop, which remembered that
    /// something was outstanding so a key press could be read as a verdict, and
    /// the loop drew *nothing* — its own comment claimed the question was
    /// already on screen, which is true only of an ask that came through
    /// `panel:ask`. So `read` and `write_file` sat waiting on a question
    /// nobody could see, with the input hint still reading "Enter sends".
    #[test]
    fn a_file_tools_question_is_a_dialog_on_its_own_panel() {
        let dir = scratch_dir("agent-fs-askpanel");

        // The panel ids each tool opened, and the overlays asked on them.
        let overlays = |sink: &PanelSink| -> Vec<(u64, Option<String>, bool)> {
            sink.ops()
                .iter()
                .filter_map(|op| match op {
                    PanelOp::Overlay { id, text, always } => Some((*id, text.clone(), *always)),
                    _ => None,
                })
                .collect()
        };
        let panel_ids = |sink: &PanelSink| -> Vec<u64> {
            sink.ops()
                .iter()
                .filter_map(|op| match op {
                    PanelOp::Create { id, .. } | PanelOp::Split { id, .. } => Some(*id),
                    _ => None,
                })
                .collect()
        };

        // A read, on a path nothing trusts.
        let target = dir.join("asked.txt");
        std::fs::write(&target, "x\n").expect("seed");
        let path = target.to_string_lossy().to_string();
        let sink = PanelSink::default();
        invoke_mcp_tool_with_asks(
            "fs.read",
            &serde_json::json!({ "path": &path }).to_string(),
            Some(&sink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("registered");

        let ids = panel_ids(&sink);
        assert_eq!(ids.len(), 1, "read opened one panel: {ids:?}");
        let asked = overlays(&sink);
        assert_eq!(
            asked.len(),
            2,
            "the question went up and came back down: {asked:?}"
        );
        assert_eq!(
            asked[0].0, ids[0],
            "and it is a dialog on the read panel, not somewhere else: {asked:?}"
        );
        assert_eq!(
            asked[0].1.as_deref(),
            Some(format!("Allow read {path}").as_str()),
            "naming the path being read: {asked:?}"
        );
        assert!(
            asked[0].2,
            "and offering [a]lways, which is what makes the answer rememberable"
        );
        assert_eq!(
            asked[1],
            (ids[0], None, false),
            "the dialog is cleared once answered, so it cannot outlive its question"
        );

        // A write asks on its own panel too — a different one.
        let wtarget = dir.join("asked2.txt");
        let wpath = wtarget.to_string_lossy().to_string();
        let wsink = PanelSink::default();
        invoke_mcp_tool_with_asks(
            "fs.write_file",
            &serde_json::json!({ "path": &wpath, "content": "y\n" }).to_string(),
            Some(&wsink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("registered");
        let wids = panel_ids(&wsink);
        let wasked = overlays(&wsink);
        assert_eq!(wids.len(), 1, "write_file opened one panel: {wids:?}");
        assert_eq!(wasked[0].0, wids[0], "its question is on its own panel");
        assert_eq!(
            wasked[0].1.as_deref(),
            Some(format!("Allow write {wpath}").as_str()),
            "and it is the write question: {wasked:?}"
        );

        // A trusted path asks nothing at all, so it has no dialog: the grant is
        // the point, and a panel that appeared to ask would be a lie.
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A split panel can host a dialog. `apply_patch` needs it: the ask gates the
    /// write, the panel it lands in is the before/after view, and the captions
    /// are fixed at creation — which is why they say "before"/"after" and not
    /// the line counts, which need the very read the ask is gating.
    #[test]
    fn a_split_panel_can_host_the_question_too() {
        let dir = scratch_dir("agent-fs-patchask");
        let target = dir.join("patched.txt");
        std::fs::write(&target, "one\ntwo\n").expect("seed");
        let path = target.to_string_lossy().to_string();

        let sink = PanelSink::default();
        let (body, _) = invoke_mcp_tool_with_asks(
            "fs.apply_patch",
            &serde_json::json!({
                "path": &path,
                "patch": "@@ -1,2 +1,2 @@
 one
-two
+two-changed
",
            })
            .to_string(),
            Some(&sink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("registered");
        assert!(body.contains("changed"), "the patch applied: {body}");

        let split_id = sink
            .ops()
            .iter()
            .find_map(|op| match op {
                PanelOp::Split { id, panes, .. } => Some((*id, panes.clone())),
                _ => None,
            })
            .expect("apply_patch drew a split panel");
        let ops = sink.ops();
        let asked: Vec<PanelOp> = ops
            .iter()
            .filter(|op| matches!(op, PanelOp::Overlay { text: Some(_), .. }))
            .cloned()
            .collect();
        assert_eq!(asked.len(), 1, "the write was asked about: {asked:?}");
        match &asked[0] {
            PanelOp::Overlay { id, text, always } => {
                assert_eq!(*id, split_id.0, "asked on the patch panel itself");
                assert_eq!(
                    text.as_deref(),
                    Some(format!("Allow write {path}").as_str()),
                    "naming the file being patched"
                );
                assert!(*always, "with [a]lways offered");
            }
            _ => unreachable!(),
        }
        assert_eq!(
            split_id.1[0].caption, "before",
            "captions are fixed at creation, so they cannot carry the line counts"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
    /// over.
    #[test]
    fn a_one_line_file_is_captioned_in_the_singular() {
        let dir = scratch_dir("agent-fs-cap");
        let target = dir.join("one.txt");
        let path = target.to_string_lossy().to_string();

        let caption = |content: &str| -> String {
            let sink = PanelSink::default();
            invoke_mcp_tool_with_asks(
                "fs.write_file",
                &serde_json::json!({ "path": &path, "content": content }).to_string(),
                Some(&sink),
                Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
                &ConfigSource::Tree,
            )
            .expect("invoke")
            .expect("registered");
            sink.ops()
                .iter()
                .find_map(|op| match op {
                    PanelOp::Split { panes, .. } => Some(panes[0].caption.clone()),
                    _ => None,
                })
                .expect("a panel")
        };

        assert_eq!(caption("one line, no newline"), "1 line, 20 bytes");
        assert_eq!(caption("one line\n"), "1 line, 9 bytes");
        assert_eq!(caption("two\nlines\n"), "2 lines, 10 bytes");
        assert_eq!(caption(""), "0 lines, 0 bytes");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A refused write says so, in the panel that is already on screen showing
    /// what the agent was trying to put there.
    #[test]
    fn a_refused_write_says_so_beside_the_content_it_would_have_written() {
        let dir = scratch_dir("agent-fs-wdeny");
        let target = dir.join("refused.rs");
        let path = target.to_string_lossy().to_string();
        let content = "fn denied() -> bool { true }\n";

        let sink = PanelSink::default();
        invoke_mcp_tool_with_asks(
            "fs.write_file",
            &serde_json::json!({ "path": &path, "content": content }).to_string(),
            Some(&sink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Deny(None))),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("registered");

        assert!(
            !target.exists(),
            "and it wrote nothing"
        );
        let pane_text: String = sink
            .ops()
            .iter()
            .filter_map(|op| match op {
                PanelOp::SetPane { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert!(
            pane_text.contains("fn denied()"),
            "the content is still shown — this is what the agent wanted to do: {pane_text:?}"
        );
        assert!(
            pane_text.contains("not allowed"),
            "and the refusal is right there: {pane_text:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
    /// said nothing would be the one shape worse than silence.
    #[test]
    fn a_refused_read_says_so_in_its_own_panel() {
        let dir = scratch_dir("agent-fs-deny");
        let target = dir.join("denied.txt");
        std::fs::write(&target, "x\n").expect("seed");
        let path = target.to_string_lossy().to_string();

        let sink = PanelSink::default();
        let (_, _) = invoke_mcp_tool_with_asks(
            "fs.read",
            &serde_json::json!({ "path": &path }).to_string(),
            Some(&sink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Deny(None))),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("registered");

        let panel: String = sink
            .ops()
            .iter()
            .map(|op| match op {
                PanelOp::Append { text, .. } => text.clone(),
                _ => String::new(),
            })
            .collect();
        assert!(
            panel.contains(&path),
            "the file is still named — the panel was opened before the ask: {panel:?}"
        );
        assert!(
            panel.contains("not allowed"),
            "and the refusal is in the panel, not only in the model's result: {panel:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file operation *offers* "always" — a path is exactly what the trust
    /// tables remember — and every operation is asked, because the tables are
    /// per VM and each tool call gets a fresh one. That limitation is the honest
    /// state of it: within a call there is a single ask anyway, so what the
    /// answer buys today is nothing for these tools. Remembering across calls
    /// wants the same treatment `agent.llm.usage` has: a process-wide snapshot
    /// the VM is seeded from.
    #[test]
    fn a_file_operation_offers_always_and_asks_every_time() {
        let dir = scratch_dir("agent-fs-always");
        let args = |name: &str| {
            serde_json::json!({
                "path": dir.join(name).to_string_lossy(),
                "content": "payload\n",
            })
            .to_string()
        };
        let offered: Rc<RefCell<Vec<bool>>> = Rc::new(RefCell::new(Vec::new()));
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        // One write, with the handler recording what it was told.
        let call = |name: &str| {
            let seen_asks = asked.clone();
            let seen_offered = offered.clone();
            let sink = PanelSink::default();
            let (body, _) = invoke_mcp_tool_with_asks(
                "fs.write_file",
                &args(name),
                Some(&sink),
                Some(Rc::new(move |text: &str, always: bool| {
                    seen_offered.borrow_mut().push(always);
                    seen_asks.borrow_mut().push(text.to_string());
                    AskAnswer::Allow
                })),
                &ConfigSource::Tree,
            )
            .expect("invoke")
            .expect("registered write_file");
            serde_json::from_str::<serde_json::Value>(&body).expect("tool json")
        };

        // The first write: allowed, and "always" was on offer for it.
        let v = call("a.txt");
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(offered.borrow().as_slice(), [true], "always is offered");

        // A second, different file asks again — the trust tables are per VM.
        let v = call("b.txt");
        assert_eq!(v["ok"], true, "{v}");
        // And the same file again is no different: nothing crosses a call.
        let v = call("a.txt");
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(
            asked.borrow().len(),
            3,
            "every operation is asked, even a repeat of the same path: {:?}",
            asked.borrow()
        );
        // Within a call, though, "always" is real: a command that writes the
        // same file twice asks once (see ask_trust_write_remembers_only_on_always).
        let _ = std::fs::remove_dir_all(&dir);
    }
