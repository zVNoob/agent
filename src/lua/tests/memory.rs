//! `agent.memory.*` — append, read back the tail, flush, and the configured
//! path.
use super::*;

use crate::testutil::{scratch_dir, unique_path};
#[test]
fn memory_primitives_append_read_flush_path() {
    // One test owns the process-wide log (OnceLock), like the trigger
    // channel: assert the unbound behavior first, then bind a temporary
    // log and exercise the whole Lua surface plus the loop-side helpers.
    let lua = vm();
    apply_config_source(&lua, "").expect("driver");

    // Unbound: the write actions raise "no log open"; path() is nil and
    // flush() is a harmless no-op (exit paths must not fail on it).
    let err = lua
        .load("return agent.memory.append('{}')")
        .eval::<mlua::Value>();
    assert!(err.is_err(), "unbound append must raise");
    let err = lua
        .load("return agent.memory.latest(1)")
        .eval::<mlua::Value>();
    assert!(err.is_err(), "unbound latest must raise");
    let _: bool = lua
        .load("return agent.memory.flush()")
        .eval()
        .expect("unbound flush no-op");
    let path_nil: bool = lua
        .load("return agent.memory.path() == nil")
        .eval()
        .expect("unbound path is nil");
    assert!(path_nil, "informational path() is nil when unbound");

    let dir = unique_path("agent-memory");
    let file = dir.join("history.amem");
    let _ = std::fs::remove_dir_all(&dir); // stale from a crashed earlier run
    std::fs::create_dir_all(&dir).expect("temp dir");
    let mem = Arc::new(Mutex::new(Memory::open(&file).expect("open")));
    assert!(bind_memory(mem).is_some(), "first bind wins");

    // path() reflects the open log.
    let p: String = lua.load("return agent.memory.path()").eval().expect("path");
    assert!(p.ends_with("history.amem"), "path is the open log: {p}");

    // append a table (auto-encoded) and a JSON string; both return the
    // message's sequence number.
    let seq1: u64 = lua
        .load("return agent.memory.append({ role='user', content='hi' })")
        .eval()
        .expect("append table");
    let seq2: u64 = lua
        .load("return agent.memory.append('{\"role\":\"assistant\",\"content\":\"hello\"}')")
        .eval()
        .expect("append string");
    assert_eq!((seq1, seq2), (1, 2), "per-process sequences, oldest first");

    // latest(n) reads them back in append order, as JSON strings.
    let n: usize = lua
        .load("return #agent.memory.latest(10)")
        .eval()
        .expect("count");
    assert_eq!(n, 2);
    let first: String = lua
        .load("return agent.memory.latest(10)[1]")
        .eval()
        .expect("first message");
    let v: serde_json::Value = serde_json::from_str(&first).expect("valid JSON line");
    assert_eq!(v["role"], "user");
    assert_eq!(v["content"], "hi");

    // The loop-side helpers share the same store: append_many + latest.
    let seq = memory_append_many(&[
        serde_json::json!({"role": "user", "content": "two"}),
        serde_json::json!({"role": "assistant", "content": "messages"}),
    ])
    .expect("append_many");
    assert_eq!(seq, 4);
    assert_eq!(
        memory_latest(10).expect("latest").len(),
        4,
        "one log, one writer"
    );

    // flush() seals to disk and a fresh open of the same file sees it.
    let ok: bool = lua
        .load("return agent.memory.flush()")
        .eval()
        .expect("flush");
    assert!(ok);
    assert!(memory_is_bound());
    let mut reread = Memory::open(&file).expect("reopen");
    assert_eq!(
        reread.latest(10).expect("latest from disk").len(),
        4,
        "flushed messages are on disk"
    );

    // `memory_new` rotates: flush + close the current log, move it aside, open a
    // fresh one at the same active path. The old scrollback stays on disk.
    //
    // One record is left *unflushed* on purpose: if `memory_new` did not flush
    // before moving the file, it would vanish with the segment that was still
    // buffered, and nothing in the rotated file would ever show it.
    let _: u64 = lua
        .load("return agent.memory.append({ role='user', content='still buffered' })")
        .eval()
        .expect("an unflushed message");
    let rotated: String = lua
        .load("return agent.memory.new()")
        .eval()
        .expect("memory.new");
    assert!(
        rotated.contains("history-") && rotated.ends_with(".amem"),
        "the old log moved to a timestamped sibling: {rotated}"
    );
    // The new log is open and empty — a fresh session starts at its own front.
    let p2: String = lua.load("return agent.memory.path()").eval().expect("path");
    assert!(
        p2.ends_with("history.amem"),
        "the active path is the same one it always was: {p2}"
    );
    let empty: usize = lua
        .load("return #agent.memory.latest(10)")
        .eval()
        .expect("fresh log is empty");
    assert_eq!(empty, 0, "a new conversation starts with no scrollback");
    // …but the old one is still on disk, whole, at the rotated path. Five records:
    // the four flushed before, plus the one that was still buffered — the one that
    // proves `memory_new` flushed before it moved the file.
    let mut old = Memory::open(&rotated).expect("open the old log");
    assert_eq!(
        old.latest(10).expect("latest").len(),
        5,
        "the old session's scrollback is preserved next to the active file, \
         including the record that was still buffered when it rotated"
    );
    // And writing resumes into the new log, cleanly.
    let seq: u64 = lua
        .load("return agent.memory.append({ role='user', content='fresh start' })")
        .eval()
        .expect("append to the new log");
    assert_eq!(seq, 1, "sequences restart with the new file");

    // --- the two ways a conversation changes, and what each does to the log ---
    //
    // The rules are short — **append to add, assign to compact** — and the
    // mistake is expensive in both directions: appending on compaction writes
    // the summary to the log a second time, and growing the conversation without
    // the log loses those messages on the next session. Pinned here, against a
    // real log, rather than left to the shape of the code that calls it.
    lua.load("agent.history = {}").exec().expect("start empty");

    // The append: the conversation grows by one *and* the log does — same
    // message, from the one call. Counted relative to what is already in this
    // log ("fresh start" above is in it), because the point is the delta.
    let before: usize = memory_latest(10).expect("read").len();
    lua.load("agent.history_append({ role='user', content='the question' })")
        .exec()
        .expect("append");
    let read = memory_latest(10).expect("read the log");
    assert_eq!(
        read.len(),
        before + 1,
        "an appended message is archived at once: {read:?}"
    );
    let logged: serde_json::Value =
        serde_json::from_str(&read[read.len() - 1]).expect("a message is JSON");
    assert_eq!(logged["role"], "user");
    assert_eq!(logged["content"], "the question");
    let len: usize = lua
        .load("return #agent.history")
        .eval()
        .expect("history length");
    assert_eq!(len, 1, "and the conversation grew by one");

    // The compaction: the conversation is replaced, and the log is not. The
    // dropped messages are already archived; the summary standing in for them
    // must not be written twice, which is why compaction assigns.
    lua.load("agent.history_append({ role='assistant', content='the answer' })")
        .exec()
        .expect("append the answer");
    lua.load("agent.history = { { role='system', content='summary' } }")
        .exec()
        .expect("compact");
    let conversation: String = lua
        .load("return agent.api.json_encode(agent.history)")
        .eval()
        .expect("encode the conversation");
    assert!(
        conversation.contains("summary") && !conversation.contains("the question"),
        "the compacted conversation is the summary alone: {conversation}"
    );
    let after_compact = memory_latest(10).expect("read the log");
    assert_eq!(
        after_compact.len(),
        before + 2,
        "the log still holds both conversation messages: {after_compact:?}"
    );
    assert!(
        !after_compact.iter().any(|line| line.contains("summary")),
        "and no summary was archived: {after_compact:?}"
    );

    // One more append after the compaction lands on top: the two stayed in step
    // across the rewrite.
    lua.load("agent.history_append({ role='user', content='next' })")
        .exec()
        .expect("append after compacting");
    let tail = memory_latest(10).expect("read the log");
    assert_eq!(
        tail.len(),
        before + 3,
        "the next message is archived too: {tail:?}"
    );
    assert!(
        tail[tail.len() - 1].contains("next"),
        "and it is the newest: {tail:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn memory_config_reads_enabled_path_and_defaults() {
    // `agent.llm.memory` steers where and whether the log opens: an
    // explicit table wins, absent fields fall back to defaults (enabled,
    // ~/.config/agent/history.amem, else ./history.amem).
    let lua = vm();
    apply_config_source(
        &lua,
        "agent.llm.memory = { enabled = false, path = '/tmp/other.amem' }",
    )
    .expect("driver + override");
    let cfg = memory_config(&lua).expect("read config");
    assert!(!cfg.enabled, "enabled = false opts out of saving");
    assert_eq!(cfg.path, std::path::PathBuf::from("/tmp/other.amem"));

    let lua = vm();
    apply_config_source(&lua, "").expect("driver");
    let cfg = memory_config(&lua).expect("defaults");
    assert!(cfg.enabled, "absent config defaults to enabled");
    assert!(
        cfg.path.to_string_lossy().ends_with("history.amem"),
        "default path names the log: {}",
        cfg.path.display()
    );
}
/// The `key` event is a *question*, and its answer is the handler's return
/// value — which is the whole reason it does not go through
/// [`fire_event_on_vm`], where a return value is discarded.
///
/// Three answers, and the third is the one that matters: `nil` and `false`
/// both mean "not bound, use the default", and a handler that returns
/// something else is a broken binding table rather than an unbound key.
/// Treating it as "unbound" would make the table fail silently, which is the
/// failure mode [`Action::parse`] also refuses.
#[test]
fn the_key_event_hands_back_the_action_the_handler_named() {
    let lua = new_vm().expect("VM");
    lua.load(
        r#"
        SEEN = nil
        agent.on_event("key", function(k)
          SEEN = k.spec
          if k.spec == "alt+c" then return "conceal" end
          if k.spec == "q" then return "quit" end
          return nil
        end)
    "#,
    )
    .exec()
    .expect("register");

    let spec = |lua: &mlua::Lua| -> Option<String> {
        let seen: mlua::Value = lua.load("return SEEN").eval().expect("read back");
        seen.as_string().map(|s| s.to_string_lossy().to_string())
    };

    let answer = fire_event_returning(&lua, "key", &json!({ "spec": "alt+c" }));
    assert_eq!(answer.expect("no error").as_deref(), Some("conceal"));
    assert_eq!(spec(&lua).as_deref(), Some("alt+c"), "and the key arrives");

    assert_eq!(
        fire_event_returning(&lua, "key", &json!({ "spec": "j" })).expect("no error"),
        None,
        "an unbound key is None, not an error: the default stands"
    );
    assert_eq!(spec(&lua).as_deref(), Some("j"), "and it was still asked");

    // An event nobody registered is the same answer as an unbound key. The
    // shipped config *does* register one, so it is removed rather than assumed
    // away — and that is the interesting case anyway, because a user is expected
    // to delete the table.
    let bare = new_vm().expect("VM");
    bare.load("agent._events.key = nil")
        .exec()
        .expect("unregister");
    assert_eq!(
        fire_event_returning(&bare, "key", &json!({ "spec": "q" })).expect("no error"),
        None,
        "events are opt-in: a VM with no handler has no opinion"
    );
}

/// What the user actually sees while a write is being decided.
///
/// Every other test in this area checks the *ops* — that a panel was opened,
/// that an overlay was set on it, that the ids match. None of them render
/// anything, so "the ops are right" and "the user can see what they are
/// approving" are different claims, and only the second one is the one that
/// matters for a permission prompt: a write is the one tool call where the
/// content is the thing being consented to.
///
/// The frame is built from the op *prefix* up to and including the ask. That
/// is the moment the user is looking at: the panel is filled, the dialog is
/// up, and the verdict has not been given — the tool then clears the overlay
/// on its way out, so replaying the whole stream would show the finished
/// state with no question on it, which is precisely what must not be
/// mistaken for the real one.
#[test]
fn a_write_being_decided_shows_its_content_and_the_dialog_together() {
    use crate::panels::{PanelOp, PanelSink};

    let dir = scratch_dir("agent-writeframe");
    let target = dir.join("consent.rs");
    let path = target.to_string_lossy().to_string();
    let content = "fn main() {\n    let secret = 7;\n}\n";

    // Refused, so nothing is written and the refusal lands in the panel too.
    let sink = PanelSink::default();
    invoke_mcp_tool_with_asks(
        "fs.write_file",
        &serde_json::json!({ "path": &path, "content": content }).to_string(),
        Some(&sink),
        Some(Rc::new(|_: &str, _: bool| {
            AskAnswer::Deny(Some("no".into()))
        })),
        &ConfigSource::Tree,
    )
    .expect("invoke")
    .expect("registered");

    // The prefix: everything up to and including the question.
    let prefix = PanelSink::default();
    let mut saw_ask = false;
    for op in sink.ops() {
        saw_ask |= matches!(op, PanelOp::Overlay { text: Some(_), .. });
        prefix.push(op);
        if saw_ask {
            break;
        }
    }
    assert!(saw_ask, "the write was questioned at all");

    let mut app = crate::tui::App::default();
    app.drain_panel_ops(&prefix);
    let (w, h) = (76u16, 26u16);
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).expect("terminal");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    let buf = terminal.backend().buffer().clone();
    let frame: String = (0..h)
        .map(|y| {
            (0..w)
                .map(|x| {
                    buf.cell((x, y))
                        .map(|c| c.symbol())
                        .unwrap_or(" ")
                        .to_string()
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        frame.contains("consent.rs"),
        "the panel names the file being written:\n{frame}"
    );
    assert!(
        frame.contains("let secret = 7;"),
        "and shows the bytes that would land on disk — a permission prompt \
                 about content the user cannot see is not consent:\n{frame}"
    );
    assert!(
        frame.contains("[y]es") && frame.contains("[a]lways"),
        "with the dialog on that same panel:\n{frame}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
