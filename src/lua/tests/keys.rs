//! What the loop owns rather than the namespace: panel ids across tool
//! rounds, and a key handler whose answer has to name a real action.
use super::*;

/// A second tool round gets its own panel, not the first round's.
///
/// This is the bug, and it is invisible to any test that uses one sink: the
/// per-round sink that carries both the round's Lua and Rust id producers
/// restarts its counter, while the id→message map it is looked up in lives
/// for the whole session. So round two's first panel took an id round one had
/// used, found the existing record, and appended itself to that message — a
/// write's content landing in the read box above it, and its dialog drawn
/// there instead of on its own. The dialog usually ended up off the top of
/// the viewport, which is why the report was "it asks, and `y` works, but
/// there is no dialog".
///
/// Built by hand rather than through two tool calls, because the harness makes
/// a fresh VM per call and would number both rounds from 1 for a different
/// reason — the same wrong number, arrived at honestly, which is worth
/// pinning here and leaving alone there.
#[test]
fn a_second_round_opens_its_own_panel_and_asks_on_it() {
    use crate::panels::{PanelOp, PanelSink};

    let mut app = crate::tui::App::default();

    // Round one: a read, which is what a session almost always starts with.
    let first = PanelSink::default();
    let read_id = first.alloc_id();
    first.push(PanelOp::Create {
        id: read_id,
        title: "fs.read".into(),
        boxed: true,
        conceal_box: true,
    });
    first.push(PanelOp::Append {
        id: read_id,
        text: "cppreact.hpp\n".into(),
    });
    app.drain_panel_ops(&first);

    // Round two: a write, on a sink that continues the numbering.
    let second = PanelSink::continuing_from(first.next_id());
    let write_id = second.alloc_id();
    second.push(PanelOp::Split {
        id: write_id,
        title: "write_file: cppreact.hpp".into(),
        panes: vec![crate::panels::PaneInit {
            caption: "2 lines".into(),
            lang: Some("cpp".into()),
        }],
    });
    second.push(PanelOp::Overlay {
        id: write_id,
        text: Some("Allow write cppreact.hpp".into()),
        remember: Some(ALWAYS_LABEL.into()),
    });
    app.drain_panel_ops(&second);

    assert_ne!(
        write_id, read_id,
        "the two rounds must not share an id, or the second panel is the first"
    );
    assert_eq!(
        app.panel.messages.len(),
        2,
        "two boxes on screen, not one with both jobs in it"
    );
    assert_eq!(
        app.panel.messages[0].text, "cppreact.hpp\n",
        "the read is its own"
    );
    assert!(
        app.panel.messages[1].overlay.is_some(),
        "and the dialog is on the write's panel, not the read's"
    );
    assert!(
        app.panel.messages[0].overlay.is_none(),
        "the read panel is left alone"
    );
}

/// A restarted sink *would* collide, which is the bug this fix is about — so
/// it is pinned as a fact about [`PanelSink::default`] rather than left as a
/// trap for the next person to walk into.
#[test]
fn a_fresh_sink_starts_at_one_which_is_why_the_loop_continues_it() {
    use crate::panels::PanelSink;
    let a = PanelSink::default();
    assert_eq!(a.alloc_id(), 1);
    let b = PanelSink::continuing_from(a.next_id());
    assert_eq!(b.alloc_id(), 2, "the mark carries");
    assert_eq!(b.alloc_id(), 3);
    assert_eq!(a.alloc_id(), 2, "and the old sink is unaffected");
    assert_eq!(
        PanelSink::default().alloc_id(),
        1,
        "a default sink really does restart — the hazard, stated"
    );
}

#[test]
fn a_key_handler_that_answers_with_nonsense_is_an_error() {
    for (body, why) in [
        ("return false", "false means unbound, not an error"),
        ("return 7", "a number is not an action name"),
        ("return {}", "a table is not an action name"),
    ] {
        let lua = new_vm().expect("VM");
        lua.load(format!("agent.on_event('key', function(k) {body} end)"))
            .exec()
            .expect("register");
        let got = fire_event_returning(&lua, "key", &json!({ "spec": "q" }));
        if why.starts_with("false") {
            assert_eq!(got.expect("no error"), None, "{why}");
        } else {
            let err = got.expect_err(why);
            assert!(err.contains("must return an action name"), "{why}: {err}");
        }
    }
    // A handler that raises is reported as itself, with the event named.
    let lua = new_vm().expect("VM");
    lua.load("agent.on_event('key', function(k) error('boom') end)")
        .exec()
        .expect("register");
    let err = fire_event_returning(&lua, "key", &json!({ "spec": "q" })).expect_err("raises");
    assert!(err.contains("event key"), "the event is named: {err}");
    assert!(err.contains("boom"), "and so is the failure: {err}");
}
/// The shipped config's binding table, row by row.
///
/// This is the test that makes the table load-bearing in a *checked* way. Every
/// key Rust used to hold moved into it, so a deleted or misspelled row is not a
/// missing feature — it is an app you cannot type into, and nothing else would
/// say so: the loop reports no error and the key is simply a letter. Both
/// directions are pinned, so a row that starts resolving to something *else* is
/// as visible as one that stops resolving at all.
#[test]
fn the_shipped_binding_table_resolves_to_real_actions() {
    // Claimed up front and held for the whole body: the table binds
    // `alt+enter`, which queues an input edit onto the process-global
    // channel, and the loop below asserts on that channel. Claiming later
    // would race another test for the slot.
    let exclusive = claim_trigger_channel();
    let lua = new_vm().expect("VM");
    let ask = |spec: &str| {
        fire_event_returning(&lua, "key", &serde_json::json!({ "spec": spec }))
            .expect("the handler did not raise")
    };

    for (spec, want) in [
        ("enter", Some("send")),
        ("esc", Some("quit")),
        ("q", Some("quit")),
        ("alt+c", Some("conceal")),
        ("j", Some("scroll_down")),
        ("down", Some("scroll_down")),
        ("k", Some("scroll_up")),
        ("up", Some("scroll_up")),
        ("home", Some("top")),
        ("end", Some("bottom")),
        // A screen, not a line: these were bound to the one-row scroll, which left
        // no key anywhere that moved a page.
        ("pageup", Some("page_up")),
        ("pagedown", Some("page_down")),
    ] {
        assert_eq!(ask(spec).as_deref(), want, "{spec} is bound to {want:?}");
    }

    // `alt+enter` is a *call*, not a name: it queues an input edit and
    // answers nothing. The table has a `newline` row because `Action::Newline`
    // exists, but this config deliberately spells it as the call — a chord
    // bound to `input_insert("\n")` can insert anything, not only a
    // newline, and the op is the honest spelling of what it does.
    //
    // The edit reaches the loop over a process-global channel, so the channel
    // is claimed for the body and what the handler queued is checked: that is
    // the only way to tell a queued newline from a dropped one, which is the
    // distinction the binding table exists to make. Claimed *before* the loop
    // above, which fires `alt+enter` too.
    assert_eq!(ask("alt+enter"), None, "the newline is queued, not named");
    assert!(
        matches!(exclusive.recv(), Some(AgentCommand::Input(InputOp::Append(s))) if s == "\n"),
        "and the queue holds the newline the handler inserted, not a dropped edit"
    );

    // Unbound, so the letter gate and the two Rust keys are all that stand
    // between a keypress and the input line.
    assert_eq!(ask("ctrl+q"), None, "nothing is bound to ctrl+q");
    assert_eq!(ask("f5"), None, "nor to f5");

    // And every name the table can produce is one the app knows — the check that
    // catches a typo in the table before it becomes a dead key.
    for spec in [
        "enter", "esc", "q", "alt+c", "j", "k", "home", "end", "pageup", "pagedown",
    ] {
        if let Some(name) = ask(spec) {
            assert!(
                crate::tui::Action::parse(&name).is_ok(),
                "{spec} resolves to {name:?}, which is not an action"
            );
        }
    }
}
