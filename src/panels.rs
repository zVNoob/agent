//! The Lua → TUI panel op stream.
//!
//! Lua code running inside the `agent` namespace — a sandbox policy, a tool
//! handler, an MCP client — cannot touch the terminal: it is a coroutine the
//! event loop steps, and it has no business owning a screen. So the
//! `agent.api.panel_*` primitives push [`PanelOp`] records into a [`PanelSink`],
//! and the TUI drains that sink once per frame and applies the ops to its
//! [`TurnPanel`](crate::tui::TurnPanel). With no sink (headless runs, the
//! tests) a panel call is a graceful no-op.
//!
//! There is exactly one producer: the `agent.api.panel_*` bridge. Nothing in
//! Rust emits a [`PanelOp`] directly, which is what keeps the id space single.
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
    /// Declare pane `pane`'s highlighting language: the highlighter runs that
    /// grammar *directly* on the pane's text instead of the markdown pipeline,
    /// so it renders syntax-highlighted without a ```lang fence. `None` renders
    /// the pane's text plain. This is the only declared-language op: a single
    /// panel has no equivalent, because every shipped tool that shows code
    /// (`fs.write_file`, `fs.apply_patch`) uses a split panel.
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

/// An order-preserving, thread-safe buffer of [`PanelOp`]s, plus the panel-id
/// allocator. Ids are drawn here rather than per-producer because they are
/// scoped to the transcript's id→message map, which outlives a single tool
/// round: a counter that restarted each round would hand round two's first
/// panel an id round one had already used, and that panel's content would be
/// appended to the wrong message. Cheap to clone (an `Arc`); the TUI is the
/// single consumer ([`PanelSink::drain`]), and the Lua bridge is the only
/// producer ([`PanelSink::push`]).
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
