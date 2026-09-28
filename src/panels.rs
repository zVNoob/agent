//! The Lua → TUI panel op stream.
//!
//! Lua code running inside the `agent` namespace (a sandbox policy, an MCP
//! tool handler, …) cannot touch the terminal directly — `tools::execute`
//! and `lua::bash` are pure functions, and the VM may one day run off the
//! main thread. Instead the `agent.api.panel_*` primitives push [`PanelOp`]
//! records into a [`PanelSink`]; the TUI drains the sink (once per tool
//! round in synchronous runs, once per frame once runs go async) and applies
//! the ops to its [`TurnPanel`](crate::tui::TurnPanel). With no sink
//! (headless runs, tests) panel calls are graceful no-ops.
//!
//! Besides the single-body ops (`Create`/`Set`/…), a panel can be *split*:
//! [`PanelOp::Split`] frames several [`PaneInit`] regions in one box, each
//! with its own text and declared grammar, so e.g. an `apply_patch` tool shows
//! the same code before/after with tree-sitter highlighting on both sides.
//!
//! The op language is deliberately TUI-free — no ratatui types: a highlight
//! `style` is a plain string spec, resolved to a [`Style`](ratatui::style::Style)
//! at apply time — so the ops are unit-testable without a screen and
//! serializable later.

use std::sync::{Arc, Mutex};

use serde_json::Value;

/// One panel operation emitted by Lua and applied by the TUI transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanelOp {
    /// Register panel `id` with its box title/options. The message only
    /// materializes on the first `Append`/`Set` (mirroring
    /// [`TurnPanel::stream_append_boxed`](crate::tui::TurnPanel)).
    Create {
        id: u64,
        title: String,
        /// Render inside a click-collapsible bordered box (`true` default).
        boxed: bool,
        /// Boxes titled for live blocks follow the markup-conceal toggle
        /// (`true` default; tool-call boxes pass `false`).
        conceal_box: bool,
    },
    /// Append text to the panel, re-highlighting it as it grows.
    Append { id: u64, text: String },
    /// Replace the panel's whole content, re-highlighting it.
    Set { id: u64, text: String },
    /// Declare the panel's content language (e.g. `"json"`): the highlighter
    /// runs that grammar *directly* on the text instead of the markdown
    /// pipeline, so the body renders syntax-highlighted without a ```lang
    /// fence. `None` reverts to the markdown pipeline. Applied on the next
    /// materialization or text change.
    SetLang { id: u64, lang: Option<String> },
    /// Add a styled byte region to the panel's content (merged with the
    /// markdown segments; clamped to the current text length).
    Highlight {
        id: u64,
        start: usize,
        end: usize,
        /// A style spec like `"bold"`, `"bold.cyan"`, or a capture name.
        style: String,
    },
    /// Drop all previously set regions.
    ClearRegions { id: u64 },
    /// Register a *split* panel `id`: one titled box whose body is `panes`
    /// separate sub-regions, each with its own caption, text, and highlighting
    /// language. Unlike [`PanelOp::Create`] the message materializes
    /// immediately (the pane frame is the content: empty panes render as
    /// captioned blank columns/rows), and per-pane ops drive the regions after.
    /// The box is always drawn (the split layout is the frame).
    Split {
        id: u64,
        title: String,
        panes: Vec<PaneInit>,
    },
    /// Replace pane `pane` (1-based) of a split panel's text, re-highlighting
    /// the pane with its declared language.
    SetPane { id: u64, pane: usize, text: String },
    /// Declare pane `pane`'s highlighting language (the direct-grammar path,
    /// like [`PanelOp::SetLang`]); `None` renders the pane's text plain.
    SetPaneLang {
        id: u64,
        pane: usize,
        lang: Option<String>,
    },
    /// Add a styled byte region to pane `pane` (bounds within that pane's own
    /// text, clamped like [`PanelOp::Highlight`]).
    HighlightPane {
        id: u64,
        pane: usize,
        start: usize,
        end: usize,
        style: String,
    },
    /// Drop all previously set regions of pane `pane`.
    ClearPaneRegions { id: u64, pane: usize },
    /// Set (`Some`) or clear (`None`) the panel's user-permission dialog: drawn
    /// at the bottom *inside* the boxed message (only boxed panels render it),
    /// so a question belongs to the panel that raised it rather than becoming a
    /// panel of its own. A pending ask pins the viewport so the dialog is
    /// visible and expands a collapsed box; clearing it returns the panel to its
    /// plain boxed rendering when the run resumes.
    ///
    /// `always` is whether the question had something to remember, and it is
    /// what decides the key prompt in the dialog's title — `[a]lways` is only
    /// offered when the answer is one the agent can act on. Ignored when
    /// clearing.
    Overlay {
        id: u64,
        text: Option<String>,
        always: bool,
    },
}

/// Initialization for one pane of a [`PanelOp::Split`] panel: its caption and
/// an optional declared highlighting language (each pane runs its own grammar
/// independently, so a patch panel can show tree-sitter-highlighted code on
/// both the "before" and "after" sides).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneInit {
    pub caption: String,
    pub lang: Option<String>,
}

/// An order-preserving, thread-safe buffer of [`PanelOp`]s, plus the round's
/// panel-id allocator — both producers (policy/tool Lua via `agent.api.panel_*`
/// and `tools::execute`'s Rust side) draw ids from the same sink, so a Lua
/// panel and a Rust-emitted panel in one round can never collide. Cheap to
/// clone (an `Arc`); the TUI is the single consumer ([`PanelSink::drain`]),
/// and the Lua VM / tool executors are the producers ([`PanelSink::push`]).
#[derive(Debug, Clone)]
pub struct PanelSink(Arc<Mutex<SinkState>>);

#[derive(Debug, Default)]
struct SinkState {
    ops: Vec<PanelOp>,
    next_id: u64,
}

impl Default for PanelSink {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(SinkState::default())))
    }
}

impl PanelSink {
    /// Allocate the next panel id for this round (1, 2, 3, … per sink).
    pub fn alloc_id(&self) -> u64 {
        let mut s = self.0.lock().expect("panel sink poisoned");
        s.next_id += 1;
        s.next_id
    }

    /// The id this sink's next [`PanelSink::alloc_id`] will hand out — the
    /// high-water mark, for a caller that is about to start a *new* sink and
    /// wants the ids to continue rather than restart.
    pub fn next_id(&self) -> u64 {
        self.0.lock().expect("panel sink poisoned").next_id
    }

    /// A sink whose id sequence continues from `next`.
    ///
    /// The scope of a panel id is the id→message map of the
    /// [`TurnPanel`](crate::tui::TurnPanel) it will be looked up in, which lives
    /// for the whole session — so a *per-round* counter is the wrong scope, even
    /// though sharing the sink between the round's Lua and Rust producers makes
    /// it look right. Only the round boundary reset it, and the damage was
    /// confined to the boundary and therefore invisible in any test that used one
    /// sink: round two's first panel was handed id 1, found round one's id-1
    /// record, and appended itself to *that* message. A write's content landed
    /// in the read panel above it, its dialog was drawn there rather than on its
    /// own box — and because a read panel is small and the write came later, the
    /// dialog usually scrolled off the top, leaving a question the user could
    /// answer with `y` but not one they could see.
    ///
    /// So the counter travels with the transcript it numbers, and the round
    /// boundary carries the mark rather than clearing it.
    pub fn continuing_from(next: u64) -> Self {
        Self(Arc::new(Mutex::new(SinkState {
            ops: Vec::new(),
            next_id: next,
        })))
    }

    /// Record one op, oldest first.
    pub fn push(&self, op: PanelOp) {
        self.0.lock().expect("panel sink poisoned").ops.push(op);
    }

    /// Take and clear all buffered ops, oldest first.
    pub fn drain(&self) -> Vec<PanelOp> {
        std::mem::take(&mut self.0.lock().expect("panel sink poisoned").ops)
    }

    /// A clone of the buffered ops (for asserting on them in tests).
    pub fn ops(&self) -> Vec<PanelOp> {
        self.0.lock().expect("panel sink poisoned").ops.clone()
    }
}

/// Render `value` as a boxed transcript panel whose body is the pretty-printed
/// JSON *declared* as `"json"`: the panel's [`PanelOp::SetLang`] tells the
/// highlighter to run the runtime-loaded `json` grammar directly on the text,
/// which themes it with the shared capture table (`property` keys cyan,
/// `string` green, `number` yellow, `boolean` red, `constant.builtin`
/// magenta, punctuation gray) — real tree-sitter syntax highlighting with no
/// tokenizer of our own and no ```lang fence to parse or conceal.
///
/// This is a *general* JSON-panel helper on the Rust side of the panel API
/// (the Lua side is `agent.panel`): pick any `Value`, hand it a title, and a
/// boxed, syntax-highlighted JSON panel appears. It is not wired to any
/// specific tool — it exists as the documented showcase of the
/// `SetLang`/direct-highlight path, kept honest by the tests below.
pub fn emit_json_panel(sink: &PanelSink, title: &str, value: &Value) {
    let text = serde_json::to_string_pretty(value).expect("json panel value serializes");
    let id = sink.alloc_id();
    sink.push(PanelOp::Create {
        id,
        title: title.to_string(),
        boxed: true,
        conceal_box: false,
    });
    sink.push(PanelOp::Set { id, text });
    sink.push(PanelOp::SetLang {
        id,
        lang: Some("json".to_string()),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grammars::Catalog;
    use crate::tui::{MarkdownHighlighter, TurnPanel};
    use ratatui::style::Color;

    /// A highlighter plus the [`Catalog`] that backs it: the `Language`s the
    /// highlighter holds point into the catalog's dlopen'd grammar `.so`s, so
    /// the catalog must outlive the highlighter (the TUI's `main` keeps its
    /// catalog alive for the whole process; dropping it would `dlclose` the
    /// grammar and dangle every `Language`).
    struct CachedHl {
        _catalog: Catalog,
        hl: MarkdownHighlighter,
    }

    /// Build a [`MarkdownHighlighter`] from the runtime grammar cache and
    /// keep the backing catalog alive; `None` when the grammars were never
    /// built (the TUI never ran), so tests degrade gracefully on machines
    /// without a cache.
    fn cached_highlighter() -> Option<CachedHl> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        let mut catalog = Catalog::new();
        let ok = runtime.block_on(async {
            let results = catalog
                .ensure_many(&["markdown", "markdown_inline", "json"])
                .await;
            results.iter().all(|(_, r)| r.is_ok())
        });
        if !ok {
            return None;
        }
        let hl = MarkdownHighlighter::from_catalog(&catalog)?;
        Some(CachedHl {
            _catalog: catalog,
            hl,
        })
    }

    #[test]
    fn sink_buffers_and_drains_in_order() {
        let s = PanelSink::default();
        s.push(PanelOp::Create {
            id: 1,
            title: "a".into(),
            boxed: true,
            conceal_box: true,
        });
        s.push(PanelOp::Append {
            id: 1,
            text: "hi".into(),
        });
        assert_eq!(s.ops().len(), 2);
        let drained = s.drain();
        assert_eq!(
            drained[0],
            PanelOp::Create {
                id: 1,
                title: "a".into(),
                boxed: true,
                conceal_box: true
            }
        );
        assert_eq!(
            drained[1],
            PanelOp::Append {
                id: 1,
                text: "hi".into()
            }
        );
        assert!(s.ops().is_empty(), "drain empties the buffer");
    }

    #[test]
    fn sink_allocates_unique_ids() {
        let s = PanelSink::default();
        assert_eq!((s.alloc_id(), s.alloc_id(), s.alloc_id()), (1, 2, 3));
        let clone = s.clone();
        assert_eq!(
            clone.alloc_id(),
            4,
            "the allocator lives in the shared state"
        );
    }

    #[test]
    fn emit_json_panel_declares_the_json_language() {
        let sink = PanelSink::default();
        emit_json_panel(
            &sink,
            "json result",
            &serde_json::json!({ "ok": true, "n": 42 }),
        );
        let ops = sink.ops();
        // No hand-rolled tokenizer and no ```json fence: the panel *declares*
        // its language and the highlighter runs the json grammar directly.
        assert_eq!(ops.len(), 3, "Create + Set + SetLang, got {ops:?}");
        assert_eq!(
            ops[0],
            PanelOp::Create {
                id: 1,
                title: "json result".into(),
                boxed: true,
                conceal_box: false
            }
        );
        let PanelOp::Set { id, text } = &ops[1] else {
            panic!("expected Set, got {:?}", ops[1]);
        };
        assert_eq!(*id, 1);
        assert_eq!(
            text, "{\n  \"n\": 42,\n  \"ok\": true\n}",
            "the body is the bare pretty json (serde_json sorts keys)"
        );
        let PanelOp::SetLang { id, lang } = &ops[2] else {
            panic!("expected SetLang, got {:?}", ops[2]);
        };
        assert_eq!(*id, 1);
        assert_eq!(lang.as_deref(), Some("json"));
    }

    #[test]
    fn json_panel_highlights_via_the_declared_language() {
        let Some(CachedHl { _catalog, hl }) = cached_highlighter() else {
            eprintln!("skipping: markdown/json grammars not cached on this machine");
            return;
        };
        let mut panel = TurnPanel::default();
        panel.set_highlighter(Some(hl));
        let sink = PanelSink::default();
        emit_json_panel(
            &sink,
            "json result",
            &serde_json::json!({
                "stdout": "from sandbox\n",
                "exit_code": 0,
                "denied": 0,
                "ok": true,
            }),
        );
        for op in sink.drain() {
            panel.apply_op(op);
        }

        let msg = &panel.messages[0];
        assert_eq!(msg.boxed.as_deref(), Some("json result"));
        assert_eq!(
            msg.lang.as_deref(),
            Some("json"),
            "language declared on the message"
        );
        assert!(
            msg.conceal.is_empty(),
            "direct json highlight conceals nothing"
        );
        let text = &msg.text;
        assert!(!text.contains("```"), "no fence in the panel body");
        let segs = &msg.segs;
        assert!(
            segs.windows(2).all(|w| w[0].start <= w[1].start),
            "tree-sitter segments are ordered, got {segs:?}"
        );

        // The loaded `json` grammar's theme (via the shared capture table):
        // object keys -> property (cyan), string values -> string (green),
        // numbers -> number (yellow), booleans -> boolean (red). Direct
        // grammar runs give *exact* boundaries — no fence, no injection
        // offsets — so every segment is matchable byte-for-byte.
        let key = text
            .find("\"exit_code\"")
            .expect("key present in panel text");
        let value = text
            .find("\"from sandbox\\n\"")
            .expect("stdout value present");
        let denied = text.find("\"denied\": 0").expect("denied field") + "\"denied\": ".len();
        let t = text.find("\"ok\": true").expect("ok field") + "\"ok\": ".len();
        assert!(
            segs.iter().any(|s| s.start == key
                && &text[s.start..s.end] == "\"exit_code\""
                && s.style.fg == Some(Color::LightCyan)),
            "object key must be property/cyan; segments: {segs:?}"
        );
        assert!(
            segs.iter().any(|s| s.start == value
                && &text[s.start..s.end] == "\"from sandbox\\n\""
                && s.style.fg == Some(Color::LightGreen)),
            "string value must be string/green; segments: {segs:?}"
        );
        assert!(
            segs.iter().any(|s| s.start == denied
                && &text[s.start..s.end] == "0"
                && s.style.fg == Some(Color::LightYellow)),
            "number must be number/yellow; segments: {segs:?}"
        );
        assert!(
            segs.iter().any(|s| s.start == t
                && &text[s.start..s.end] == "true"
                && s.style.fg == Some(Color::LightRed)),
            "boolean must be boolean/red; segments: {segs:?}"
        );
    }

    #[test]
    fn demo_rendered_bash_json_panel() {
        // `cargo test --lib demo_rendered_bash_json_panel -- --nocapture`
        let Some(CachedHl { _catalog, hl }) = cached_highlighter() else {
            eprintln!("(demo skipped: grammars not cached)");
            return;
        };
        let mut panel = TurnPanel::default();
        panel.set_highlighter(Some(hl));
        let sink = PanelSink::default();
        emit_json_panel(
            &sink,
            "json result",
            &serde_json::json!({
                "stdout": "from sandbox\n",
                "stderr": "",
                "exit_code": 0,
                "exit_signal": null,
                "syscalls": 190,
                "denied": 0,
            }),
        );
        for op in sink.drain() {
            panel.apply_op(op);
        }
        let msg = &panel.messages[0];
        println!(
            "\n--- json result panel (boxed={:?}, conceal_box={}, lang={:?}) ---",
            msg.boxed, msg.conceal_box, msg.lang
        );
        println!("{}", msg.text);
        println!("--- tree-sitter segments ---");
        for sg in &msg.segs {
            println!(
                "  [{:3}..{:3}] {:<40} fg={:?}",
                sg.start,
                sg.end,
                msg.text[sg.start..sg.end].replace('\n', "\\n"),
                sg.style.fg,
            );
        }
    }

    #[test]
    fn split_panel_ops_apply_to_the_turn_panel() {
        let sink = PanelSink::default();
        let id = sink.alloc_id();
        sink.push(PanelOp::Split {
            id,
            title: "apply_patch".into(),
            panes: vec![
                PaneInit {
                    caption: "before".into(),
                    lang: Some("bash".into()),
                },
                PaneInit {
                    caption: "after".into(),
                    lang: Some("bash".into()),
                },
            ],
        });
        sink.push(PanelOp::SetPane {
            id,
            pane: 1,
            text: "echo old\n".into(),
        });
        sink.push(PanelOp::SetPane {
            id,
            pane: 2,
            text: "echo new".into(),
        });
        sink.push(PanelOp::HighlightPane {
            id,
            pane: 2,
            start: 5,
            end: 99,
            style: "bold.green".into(),
        });

        let mut panel = TurnPanel::default();
        for op in sink.drain() {
            panel.apply_op(op);
        }

        assert_eq!(
            panel.messages.len(),
            1,
            "the split materializes its box on creation"
        );
        let m = &panel.messages[0];
        assert_eq!(m.boxed.as_deref(), Some("apply_patch"));
        let panes = m.panes.as_ref().expect("split panes present");
        assert_eq!(panes.len(), 2);
        assert_eq!(panes[0].caption, "before");
        assert_eq!(panes[0].lang.as_deref(), Some("bash"));
        assert_eq!(panes[0].text, "echo old\n");
        assert_eq!(panes[1].text, "echo new");
        assert!(
            panes[1]
                .user_segs
                .iter()
                .any(|sg| sg.start == 5 && sg.end == 8),
            "pane highlight clamped into the pane's own user regions: {:?}",
            panes[1].user_segs
        );
        assert!(
            panes[0].user_segs.is_empty(),
            "highlights target one pane, not the panel"
        );
    }

    #[test]
    fn split_ops_ignore_unknown_panels_and_bad_ranges() {
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Split {
            id: 1,
            title: "t".into(),
            panes: vec![PaneInit {
                caption: "only".into(),
                lang: None,
            }],
        });
        // Pane index 0, an out-of-range pane, and entirely unknown ids are
        // all no-ops (the op stream is data; validation happens here, not in
        // the producers).
        panel.apply_op(PanelOp::SetPane {
            id: 1,
            pane: 0,
            text: "x".into(),
        });
        panel.apply_op(PanelOp::SetPane {
            id: 1,
            pane: 2,
            text: "x".into(),
        });
        panel.apply_op(PanelOp::SetPaneLang {
            id: 99,
            pane: 1,
            lang: Some("json".into()),
        });
        panel.apply_op(PanelOp::HighlightPane {
            id: 1,
            pane: 1,
            start: 0,
            end: 99,
            style: "bold".into(),
        });
        panel.apply_op(PanelOp::ClearPaneRegions { id: 1, pane: 2 });

        let panes = panel.messages[0].panes.as_ref().expect("split message");
        assert_eq!(panes.len(), 1);
        assert!(panes[0].text.is_empty(), "the out-of-range ops did nothing");
        assert!(
            panes[0].user_segs.is_empty(),
            "clamped-to-empty highlight is a no-op"
        );
        assert_eq!(
            panel.messages.len(),
            1,
            "unknown-id ops didn't materialize anything"
        );
    }

    #[test]
    fn split_panel_pane_lang_highlights_with_the_declared_grammar() {
        let Some(CachedHl { _catalog, hl }) = cached_highlighter() else {
            eprintln!("skipping: markdown/json grammars not cached on this machine");
            return;
        };
        let mut panel = TurnPanel::default();
        panel.set_highlighter(Some(hl));
        panel.apply_op(PanelOp::Split {
            id: 1,
            title: "json diff".into(),
            panes: vec![
                PaneInit {
                    caption: "before".into(),
                    lang: None,
                },
                PaneInit {
                    caption: "after".into(),
                    lang: None,
                },
            ],
        });
        panel.apply_op(PanelOp::SetPane {
            id: 1,
            pane: 2,
            text: "{\"ok\": true}".into(),
        });
        assert!(
            panel.messages[0].panes.as_ref().unwrap()[1].segs.is_empty(),
            "panes without a declared language render plain"
        );
        panel.apply_op(PanelOp::SetPaneLang {
            id: 1,
            pane: 2,
            lang: Some("json".into()),
        });
        let panes = panel.messages[0].panes.as_ref().unwrap();
        let segs = &panes[1].segs;
        assert!(!segs.is_empty(), "the json grammar styled the pane");
        assert!(
            segs.windows(2).all(|w| w[0].start <= w[1].start),
            "pane segments ordered, got {segs:?}"
        );
        let key = panes[1].text.find("\"ok\"").expect("key present");
        assert!(
            segs.iter()
                .any(|s| s.start == key && s.style.fg == Some(Color::LightCyan)),
            "json key styled property/cyan inside the pane: {segs:?}"
        );
    }

    /// A split panel with **one** pane, which is what `fs.write_file` opens: a
    /// declared grammar needs a pane, and a single pane must still render as a
    /// plain full-width box rather than a one-column split with a divider
    /// beside it.
    #[test]
    fn a_one_pane_split_is_a_full_width_box_that_still_highlights() {
        let Some(CachedHl { _catalog, hl }) = cached_highlighter() else {
            eprintln!("skipping: markdown/json grammars not cached on this machine");
            return;
        };
        let mut panel = TurnPanel::default();
        panel.set_highlighter(Some(hl));
        panel.apply_op(PanelOp::Split {
            id: 1,
            title: "write_file: /tmp/shown.json".into(),
            panes: vec![PaneInit {
                caption: "1 line, 14 bytes".into(),
                lang: Some("json".into()),
            }],
        });
        panel.apply_op(PanelOp::SetPane {
            id: 1,
            pane: 1,
            text: "{\"ok\": true}".into(),
        });

        // Styled: the declared grammar ran, which is the whole claim about
        // "highlighted" — the op carrying a language would not prove this.
        let panes = panel.messages[0].panes.as_ref().unwrap();
        let segs = &panes[0].segs;
        assert!(!segs.is_empty(), "the json grammar styled the single pane");
        let key = panes[0].text.find("\"ok\"").expect("key present");
        assert!(
            segs.iter()
                .any(|s| s.start == key && s.style.fg == Some(Color::LightCyan)),
            "and styled it as a json key: {segs:?}"
        );

        // Full width: at 60 cells the content fits on one row with no divider
        // and no second column, which is what a one-pane split must look like.
        let rows: Vec<String> =
            crate::tui::BorderedRenderer::lines(&panel.messages, 60, true)
        .iter()
        .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
        .collect();
        let text = rows.join("\n");
        assert!(text.contains("write_file: /tmp/shown.json"), "titled: {text}");
        assert!(text.contains("1 line, 14 bytes"), "captioned: {text}");
        assert!(text.contains("{\"ok\": true}"), "the content is on one row: {text}");
        // No pane divider: every row carries exactly the box's own two bars, so
        // a one-pane split has nothing between the columns to draw.
        for row in rows.iter().filter(|r| r.starts_with('\u{2502}')) {
            assert_eq!(
                row.matches('\u{2502}').count(),
                2,
                "a body row with a third bar would be a pane divider: {row}"
            );
        }
        assert!(
            rows.iter().filter(|r| r.starts_with('\u{2502}')).count() >= 2,
            "the caption and the content are both body rows: {text}"
        );
    }

    #[test]
    fn demo_rendered_split_panel() {
        // `cargo test --lib demo_rendered_split_panel -- --nocapture`
        let mut panel = TurnPanel::default();
        let sink = PanelSink::default();
        let id = sink.alloc_id();
        sink.push(PanelOp::Split {
            id,
            title: "apply_patch".into(),
            panes: vec![
                PaneInit {
                    caption: "before".into(),
                    lang: None,
                },
                PaneInit {
                    caption: "after".into(),
                    lang: None,
                },
            ],
        });
        sink.push(PanelOp::SetPane {
            id,
            pane: 1,
            text: "fn main() {\n  let x = 1;\n  println!(\"{x}\");\n}\n".into(),
        });
        sink.push(PanelOp::SetPane {
            id,
            pane: 2,
            text: "fn main() {\n  let x = 2;\n  println!(\"{x}\");\n}\n".into(),
        });
        for op in sink.drain() {
            panel.apply_op(op);
        }
        for (w, label) in [(100usize, "wide / side-by-side"), (40, "narrow / stacked")] {
            println!("\n--- split panel at {w} cols ({label}) ---");
            for line in crate::tui::BorderedRenderer::lines(&panel.messages, w, true) {
                println!(
                    "{}",
                    line.spans
                        .iter()
                        .map(|s| s.content.as_ref())
                        .collect::<String>()
                );
            }
        }
    }
}
