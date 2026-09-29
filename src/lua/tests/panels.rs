//! `agent.panel` and `agent.split_panel` driving the sink, including the
//! headless no-op case, and the panel ops a *policy* emits from inside a
//! sandboxed run.
use super::*;

#[test]
fn agent_panel_drives_the_sink() {
    let sink = PanelSink::default();
    let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
    lua.load(
        r#"
            local p = agent.panel("log", { boxed = false, conceal_box = false })
            p:append("line one\n")
            p:append("line two\n")
            p:highlight(0, 9, "bold.cyan")
            p:set("replaced")
            p:clear_regions()
            return true
            "#,
    )
    .eval::<bool>()
    .expect("eval");
    assert_eq!(
        sink.ops(),
        vec![
            PanelOp::Create {
                id: 1,
                title: "log".into(),
                boxed: false,
                conceal_box: false
            },
            PanelOp::Append {
                id: 1,
                text: "line one\n".into()
            },
            PanelOp::Append {
                id: 1,
                text: "line two\n".into()
            },
            PanelOp::Highlight {
                id: 1,
                start: 0,
                end: 9,
                style: "bold.cyan".into()
            },
            PanelOp::Set {
                id: 1,
                text: "replaced".into()
            },
            PanelOp::ClearRegions { id: 1 },
        ]
    );
}

#[test]
fn agent_panel_defaults_and_is_noop_headless() {
    // No sink: the calls succeed but record nothing.
    let lua = vm();
    let ok: bool = lua
        .load(
            r#"
                local p = agent.panel("log")
                p:append("x")
                p:highlight(0, 1, "bold")
                return p.id >= 1
                "#,
        )
        .eval()
        .expect("eval headless panel calls");
    assert!(ok, "headless panel calls are graceful no-ops");
    // Default opts: boxed and conceal_box both on.
    let sink = PanelSink::default();
    let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
    lua.load(r#"agent.panel("log") return true"#)
        .eval::<bool>()
        .expect("eval");
    assert_eq!(
        sink.ops(),
        vec![PanelOp::Create {
            id: 1,
            title: "log".into(),
            boxed: true,
            conceal_box: true
        }]
    );
}

#[test]
fn agent_panel_rejects_bad_options() {
    let lua = vm();
    let ok: bool = lua
        .load(
            r#"
            assert(not pcall(agent.panel, "log", { boxed = "yes" }), "non-bool boxed rejected")
            assert(not pcall(agent.panel, nil, {}), "nil title rejected")
            assert(not pcall(agent.api.panel_highlight, 1, 0, 2, nil), "nil style rejected")
            return true
            "#,
        )
        .eval()
        .expect("eval");
    assert!(ok, "panel arg validation rejects bad values");
}

#[test]
fn agent_split_panel_drives_the_sink() {
    // `agent.split_panel` is the sibling driving API of `agent.panel`:
    // one titled box, several regions, each pane with its own text and
    // declared language (the building block for a Lua `apply_patch`).
    let sink = PanelSink::default();
    let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
    lua.load(
        r#"
            local p = agent.split_panel("apply_patch", {
                { caption = "before", lang = "bash" },
                "after",
            })
            p:set(1, "echo old")
            p:set(2, "echo new")
            p:highlight(2, 5, 8, "bold.green")
            p:lang(1, "bash")
            p:clear_regions(2)
            return true
            "#,
    )
    .eval::<bool>()
    .expect("eval");
    assert_eq!(
        sink.ops(),
        vec![
            PanelOp::Split {
                id: 1,
                title: "apply_patch".into(),
                panes: vec![
                    PaneInit {
                        caption: "before".into(),
                        lang: Some("bash".into())
                    },
                    PaneInit {
                        caption: "after".into(),
                        lang: None
                    },
                ],
            },
            PanelOp::SetPane {
                id: 1,
                pane: 1,
                text: "echo old".into()
            },
            PanelOp::SetPane {
                id: 1,
                pane: 2,
                text: "echo new".into()
            },
            PanelOp::HighlightPane {
                id: 1,
                pane: 2,
                start: 5,
                end: 8,
                style: "bold.green".into(),
            },
            PanelOp::SetPaneLang {
                id: 1,
                pane: 1,
                lang: Some("bash".into())
            },
            PanelOp::ClearPaneRegions { id: 1, pane: 2 },
        ]
    );
}

#[test]
fn agent_split_panel_is_a_noop_headless_and_validates() {
    // No sink: the calls succeed and ids still allocate (per-VM counter).
    let lua = vm();
    let ok: bool = lua
        .load(
            r#"
                local p = agent.split_panel("t", { "a", "b" })
                p:set(2, "x")
                p:highlight(1, 0, 1, "bold")
                p:lang(2, nil)
                return p.id >= 1
                "#,
        )
        .eval()
        .expect("eval headless split panel calls");
    assert!(ok, "headless split panel calls are graceful no-ops");
    let ok: bool = lua
            .load(
                r#"
                assert(not pcall(agent.split_panel, "t", {}), "empty panes rejected")
                assert(not pcall(agent.split_panel, "t", { 42 }), "non-string/table pane rejected")
                assert(not pcall(agent.split_panel, "t", { { caption = 5 } }), "bad caption rejected")
                assert(not pcall(agent.split_panel, "t", { { lang = 5 } }), "bad lang rejected")
                assert(not pcall(agent.split_panel, "t", nil), "nil panes rejected")
                assert(not pcall(agent.split_panel), "missing args rejected")
                return true
                "#,
            )
            .eval()
            .expect("eval");
    assert!(ok, "split panel validation rejects bad input");
    // A pane table with neither caption nor lang is fine (blank pane).
    let sink = PanelSink::default();
    let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
    lua.load(r#"agent.split_panel("t", { {} }) return true"#)
        .eval::<bool>()
        .expect("eval");
    assert_eq!(
        sink.ops(),
        vec![PanelOp::Split {
            id: 1,
            title: "t".into(),
            panes: vec![PaneInit {
                caption: "".into(),
                lang: None
            }],
        }]
    );
}

#[test]
fn the_policy_can_emit_panel_ops() {
    // Policy Lua (inside a real sandboxed run) drives `agent.panel`; the
    // ops land in the round's sink while the sandbox outcome stays intact.
    // The wrapper's "bash result" panel streams in after the policy's own
    // panel (ids from the same sink allocator, so they never collide).
    let sink = PanelSink::default();
    let policy = r#"
local policy = setmetatable({}, { __index = function() return function() return true end end })
local p = agent.panel("sandbox-note", { boxed = false })
p:append("run started\n")
return policy
"#;
    let out = run_bash("echo hi", policy, Some(&sink), None).expect("bash run");
    assert_eq!(out.stdout, "hi\n");
    assert!(!out.failed());
    // Only the policy's own panel: the "bash result" stream panel around the
    // run is the *tool's* (`lua/bash_tool.lua`), asserted in
    // `the_bash_tool_streams_stdout_into_a_result_panel`.
    let _ = &sink;
    assert_eq!(
        sink.ops(),
        vec![
            PanelOp::Create {
                id: 1,
                title: "sandbox-note".into(),
                boxed: false,
                conceal_box: true
            },
            PanelOp::Append {
                id: 1,
                text: "run started\n".into()
            },
        ]
    );
}

#[test]
fn the_policy_can_emit_split_panel_ops() {
    // The end-to-end shape of a Lua `apply_patch`: policy Lua (inside a
    // real sandboxed run) shows the before/after regions in one split
    // panel — captions plus per-pane declared languages — and the ops
    // stream into the round's sink next to the wrapper's result panel.
    let sink = PanelSink::default();
    let policy = r#"
local policy = setmetatable({}, { __index = function() return function() return true end end })
local p = agent.split_panel("apply_patch", {
    { caption = "before", lang = "bash" },
    { caption = "after", lang = "bash" },
})
p:set(1, "echo old")
p:set(2, "echo new")
p:highlight(2, 5, 8, "bold.green")
return policy
"#;
    let out = run_bash("echo hi", policy, Some(&sink), None).expect("bash run");
    assert_eq!(out.stdout, "hi\n");
    assert!(!out.failed());
    assert_eq!(
        sink.ops(),
        vec![
            PanelOp::Split {
                id: 1,
                title: "apply_patch".into(),
                panes: vec![
                    PaneInit {
                        caption: "before".into(),
                        lang: Some("bash".into())
                    },
                    PaneInit {
                        caption: "after".into(),
                        lang: Some("bash".into())
                    },
                ],
            },
            PanelOp::SetPane {
                id: 1,
                pane: 1,
                text: "echo old".into()
            },
            PanelOp::SetPane {
                id: 1,
                pane: 2,
                text: "echo new".into()
            },
            PanelOp::HighlightPane {
                id: 1,
                pane: 2,
                start: 5,
                end: 8,
                style: "bold.green".into(),
            },
        ]
    );
}

// -----------------------------------------------------------------------
// Agent config in Lua: the endpoint, the system prompt, and the tools the
// user registers into `agent.mcps` — the registry Rust reindexes per
// request, never cached.
// -----------------------------------------------------------------------
