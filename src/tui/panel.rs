//! The turn panel: one distinct component owning the conversation and how it
//! renders.
//!
//! Each message body is highlighted as markdown when grammars are loaded
//! (see [`super::highlight`]): at push time the body is parsed with the
//! runtime-loaded markdown grammar (fenced bash/json and inline formatting
//! injected), producing styled byte segments — and the concealed marker
//! ranges — cached on the [`Message`]. Three rendering pipelines consume
//! them: the raw path ([`TurnPanel::build_lines_slice`], which clips and wraps
//! the segments against the raw text, untouched), the dedicated
//! [`ChatRenderer`], which
//! when markup conceal is on renders the *display* text (markers hidden)
//! with the same styles, and the [`BorderedRenderer`], a composition
//! "subclass" of the base path that frames opted-in messages in a titled
//! border for tool-call visuals (raw text inside, never concealed) and
//! collapses on click. Layout (tag, continuation indent, row heights) is
//! identical across pipelines — without a highlighter messages render plain.
//!
//! The component is deliberately dumb about its environment: it renders into
//! whatever [`Rect`] it is given, owns its own scroll state, and knows nothing
//! about keys — the shell decides when scrolling happens and calls
//! [`TurnPanel::scroll_up`] & co.
//!
//! The transcript keeps every message in memory (from the start of the session
//! up to compaction, which replaces history with a shorter summary) — but it
//! *renders* only the visible window. Each message caches its wrapped row
//! count ([`Message::rows`], invalidated when its text or box state changes,
//! or wholesale on a resize / conceal toggle), so scrolling, the scrollbar,
//! and the viewport are O(retained) integer arithmetic per frame, and the
//! only wrapping done per frame touches the messages actually on screen.
//! Tens of thousands of archived lines therefore cost no more per frame than a
//! few dozen; everything older stays safe in the append-only conversation log
//! (`crate::memory`) regardless.

use std::collections::HashMap;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use super::highlight::{MarkdownHighlighter, Segment, style_for_spec};
use super::wrap_lines;
use crate::panels::{PanelOp, Remember};

/// Cols reserved for the role tag (e.g. `assistant `) at the start of a
/// message's first row. Continuation rows are indented by the same amount.
const TAG_COLS: usize = 10;

/// Replace control characters with spaces, so every cell the layout counts is a
/// cell the renderer draws.
///
/// **The invariant this protects.** The layout measures content in `chars()`
/// and pads a row out to its column; ratatui **drops** control characters when it
/// draws (`filter(|symbol| !symbol.contains(char::is_control))`). A tab is one
/// char to the first and *nothing* to the second, so every one on a row is a cell
/// the padding promised and the frame never filled. The box's right border then
/// lands that many cells early — and the row spills past it, so the border is
/// missing and the panel reads as ragged rather than boxed.
///
/// A tab-indented file in an `apply_patch` before/after panel did exactly this:
/// the right border landed in **15 different columns**, one per distinct tab count
/// on a row. Any control character does it — `\t`, a `\r` from a CRLF file, an
/// escape byte out of command output.
///
/// **Why spaces and not a deletion.** Byte offsets into panel text cross this
/// boundary: `fs.apply_patch` computes `line_bytes` on the text it read and
/// passes those offsets to `p:highlight` (`lua/fs.lua`), so the text stored here
/// must be at least as long as the text the offsets were measured against, and
/// every offset before the substitution must still point where it did. A
/// substitution *of at least the same length* keeps both true; a deletion would
/// shift every later offset and tint the wrong lines.
///
/// A tab becomes [`TAB_CELLS`] spaces, not one. One space is the width that
/// guarantees the offsets, but it collapses indentation to nothing, and
/// indentation is the thing being shown — a tab-indented Lua file rendered one
/// space per tab looks like a wall of unindented text, which is worse than the
/// misalignment this replaced. The extra width cannot break an offset: it only
/// ever lands *after* the position it was measured at.
///
/// `\n` is left alone: it is structure, not content, and every wrapper here
/// splits on it.
fn renderable(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.chars().any(char::is_control) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\n' {
            out.push('\n');
        } else if c == '\t' {
            out.extend(std::iter::repeat_n(' ', TAB_CELLS));
        } else if c.is_control() {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Cells a tab is drawn as. Two, not the terminal's usual eight: a panel column
/// is often 40-60 cells wide and split between two panes, so eight spaces per
/// indent level eats the pane. Two keeps a tab-indented file legible at depth
/// while still showing the structure.
const TAB_CELLS: usize = 2;

/// The terminal cells `s` occupies when drawn — what ratatui's buffer will
/// actually hold.
///
/// **Not `chars().count()`.** A `char` is a code point and a cell is a column,
/// and they are not the same thing in either direction: an emoji or a CJK
/// character is one `char` and *two* cells, and a base letter with a combining
/// accent is two `chars` and *one* cell. Budgeting a row in chars while the
/// renderer draws cells is the same disagreement as [`renderable`]'s, one
/// layer over: the padding is computed for fewer cells than get drawn, so it
/// under-fills and the box's right edge slides out of the box.
///
/// The module used to measure in `chars()` on purpose — "grapheme/CJK-aware
/// wrapping is out of scope for the minimal UI" — which was defensible while
/// every row was ASCII. It stopped being defensible the moment a panel showed
/// an emoji: `fs.write_file` and `apply_patch` put arbitrary file contents in
/// front of the user, so the character set is whatever the repository holds.
///
/// Ratatui measures per grapheme cluster and drops control characters;
/// [`renderable`] has already removed those, so these agree for anything that
/// reaches here.
fn cells(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// The longest prefix of `s` that fits in `width` cells.
///
/// Cut on grapheme boundaries, never inside one: slicing by `char` can split a
/// base letter from its combining accent, which leaves a lone accent on the
/// next row and a byte range that no longer lines up with what was drawn.
fn take_cells(s: &str, width: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for g in s.graphemes(true) {
        let w = cells(g);
        if used + w > width {
            break;
        }
        used += w;
        out.push_str(g);
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
}

impl Role {
    fn tag(&self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Assistant => "assistant",
        }
    }

    fn style(&self) -> Style {
        match self {
            Role::User => Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            Role::Assistant => Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        }
    }
}

#[derive(Debug)]
pub struct Message {
    pub role: Role,
    pub text: String,
    /// Styled byte ranges covering `text` (empty = plain). Calculated once at
    /// push time by the panel's highlighter, so per-frame rendering only
    /// clips and wraps them.
    pub(crate) segs: Vec<Segment>,
    /// Lua panel regions ([`crate::panels::PanelOp::Highlight`]) — user-set
    /// styled byte ranges merged into `segs` after every markdown
    /// re-highlight, so they survive appends. Sorted by start; empty for
    /// plain messages and for Lua-unused messages.
    pub(crate) user_segs: Vec<Segment>,
    /// Source byte ranges hidden from the rendered output — ATX heading `#`
    /// markers, inline delimiter runs, and fence `` ``` `` delimiters
    /// (see [`ChatRenderer`]). Sorted and disjoint; empty for plain messages
    /// and when no highlighter is installed.
    pub(crate) conceal: Vec<(usize, usize)>,
    /// When set, the message renders inside a bordered "tool-call" box titled
    /// with the value (e.g. the tool name) — unless the title is a borderless
    /// block (`"reasoning"`/`"response"`, see [`is_borderless_box`]), which
    /// renders like a plain message without a frame. Any role may be boxed; a
    /// framed box uses the original (non-conceal) base rendering, so markers
    /// stay visible inside it.
    pub(crate) boxed: Option<String>,
    /// Declared highlighting language (e.g. `"json"`): when set, the
    /// highlighter runs that grammar *directly* on `text` instead of the
    /// markdown pipeline (see [`PanelOp::SetPaneLang`]). `None` = markdown, the
    /// default for every message.
    pub(crate) lang: Option<String>,
    /// When `boxed` is set, whether the box's *content* follows the markup-
    /// conceal toggle like plain messages (the reasoning/response blocks) —
    /// `false` for tool-call boxes, whose raw content must keep markers
    /// visible no matter the toggle. Borderless blocks always follow the
    /// toggle (they render through the plain-message path).
    pub(crate) conceal_box: bool,
    /// Display state: a boxed message collapsed to just its title and bottom
    /// border rows. Toggled by clicking the box (see [`TurnPanel::handle_click`]).
    pub(crate) collapsed: bool,
    /// When set, a boxed message draws a user-permission *dialog* at the bottom
    /// *inside* its box: a compact framed panel with the ask description and a
    /// key prompt. Set and cleared via [`PanelOp::Overlay`]; only boxed
    /// messages render it (see [`overlay_rows`]).
    pub(crate) overlay: Option<Overlay>,
    /// When set, the message is a *split* panel ([`PanelOp::Split`]): the box
    /// renders `panes` as framed sub-regions — side-by-side columns when the
    /// width allows, stacked below a rule when it doesn't — instead of one
    /// body. `text`/`segs`/`lang`/`conceal` are unused (each pane carries its
    /// own). Always boxed; collapse/overlay work as on any boxed message.
    pub(crate) panes: Option<Vec<PaneContent>>,
    /// Cached wrapped row count for the panel's current (width, conceal)
    /// view ([`TurnPanel::ensure_measured`]). Only meaningful while the
    /// panel's `measure_w`/`measure_conceal` match; invalidated wholesale on a
    /// resize or conceal toggle, or per-message by setting `dirty`.
    pub(crate) rows: usize,
    /// The message gained text, box state, panes, or an overlay since its
    /// `rows` was measured. Cleared by [`TurnPanel::ensure_measured`]; also
    /// set by the toggle paths (conceal, collapse) so the whole cache stays
    /// cheap to refresh — the transcript keeps every message in memory (up to
    /// the compaction point or the start of the session) and only *renders*
    /// the visible window, so this stale flag is what keeps per-frame work
    /// O(viewport) instead of O(retained).
    pub(crate) dirty: bool,
}

/// The dedicated chat renderer. With markup conceal enabled (the default) it
/// renders each message's *display* text (the message minus its concealed
/// marker ranges) with the cached [`Segment`] styles, so `# Plan` shows as
/// `Plan` and `` `code` `` as `code`. The raw segment path
/// ([`TurnPanel::build_lines_slice`]) is untouched and handles the off state, so
/// the toggle switches between two independent pipelines.
#[derive(Debug)]
pub struct ChatRenderer {
    conceal: bool,
}

impl Default for ChatRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl ChatRenderer {
    pub fn new() -> Self {
        Self { conceal: true } // markup conceal is on by default
    }

    pub fn set_conceal(&mut self, on: bool) {
        self.conceal = on;
    }

    pub fn conceal_enabled(&self) -> bool {
        self.conceal
    }

    /// Turn every message into styled, wrapped rows with markers concealed.
    /// Messages without conceal ranges render exactly as the original path
    /// ([`wrap_segments`]) — same bytes, same boundaries; concealed messages
    /// wrap on the display text with boundaries mapped through the conceal
    /// map, matching [`message_rows`] with conceal enabled so heights agree.
    pub fn lines(&self, messages: &[Message], content_w: usize) -> Vec<Line<'static>> {
        let text_w = content_w.saturating_sub(TAG_COLS + 1);
        let mut lines: Vec<Line<'static>> = Vec::new();
        for msg in messages {
            lines.extend(message_lines(msg, text_w, self.conceal));
        }
        if lines.is_empty() {
            lines.push(Line::raw("(no messages yet)"));
        }
        lines
    }
}

/// Whether `msg` is a *borderless* streamed block — the "reasoning" and
/// "response" blocks the agent loop streams via
/// [`TurnPanel::stream_append_boxed`]. They render (and measure) like plain
/// messages: no frame, no click-to-collapse — and the reasoning one is
/// dimmed so the model's thinking reads quieter than the answer. Tool-call
/// boxes and Lua panels keep their borders.
fn is_borderless_box(msg: &Message) -> bool {
    msg.boxed
        .as_deref()
        .is_some_and(|t| matches!(t, "reasoning" | "response"))
}

/// Lay [`Modifier::DIM`] onto every span of `lines` (the reasoning block's
/// "darker than normal" look): each span keeps its own style — role tag,
/// highlight colors, bold — with DIM layered on top.
fn dim_spans(lines: Vec<Line<'static>>) -> Vec<Line<'static>> {
    lines
        .into_iter()
        .map(|mut line| {
            for span in &mut line.spans {
                span.style = span.style.add_modifier(Modifier::DIM);
            }
            line
        })
        .collect()
}

/// A composition "subclass" of the chat renderer's *base* path: messages
/// that opted into a box (`Message::boxed`) are framed in a bordered title
/// bar (`┌─ tool −…─┐` … `└─…─┘`) for tool-call visuals — except the
/// borderless "reasoning"/"response" blocks (see `is_borderless_box`),
/// which render as plain messages (reasoning dimmed). Inside a framed box
/// the original non-conceal segment path renders the raw text — markup
/// markers stay visible no matter the conceal toggle, exactly like the base
/// renderer, *unless* the message's `conceal_box` opts its content into the
/// conceal path. Clicking a framed box toggles its collapse
/// (see [`TurnPanel::handle_click`]).
#[derive(Debug, Default)]
pub struct BorderedRenderer;

impl BorderedRenderer {
    /// Rows for a whole transcript: bordered `boxed` messages are framed,
    /// borderless ones (reasoning/response) and the rest render per the
    /// `conceal` toggle (same rows as the pipeline the toggle would normally
    /// pick). Boxed rows use the base path unless the message opts in via
    /// `conceal_box`.
    pub fn lines(messages: &[Message], content_w: usize, conceal: bool) -> Vec<Line<'static>> {
        let text_w = content_w.saturating_sub(TAG_COLS + 1);
        let mut lines: Vec<Line<'static>> = Vec::new();
        for msg in messages {
            if msg.boxed.is_some() {
                if is_borderless_box(msg) {
                    let mut rows = message_lines(msg, text_w, conceal);
                    if msg.boxed.as_deref() == Some("reasoning") {
                        rows = dim_spans(rows);
                    }
                    lines.extend(rows);
                } else {
                    lines.extend(boxed_lines(msg, content_w, conceal));
                }
            } else {
                lines.extend(message_lines(msg, text_w, conceal));
            }
        }
        if lines.is_empty() {
            lines.push(Line::raw("(no messages yet)"));
        }
        lines
    }
}

/// The conversation component: the message list plus its viewport state.
/// `scroll` is the row offset of the visible top within the rendered content;
/// `follow` means "stick to the bottom" (new messages keep the view pinned).
/// Follow starts on: a fresh panel has nothing to scroll and should show its
/// first messages immediately.
pub struct TurnPanel {
    pub messages: Vec<Message>,
    /// Implementation detail (row offset of the rendered content's top);
    /// `pub(crate)` only so the shell's tests can assert on it.
    pub(crate) scroll: usize,
    pub(crate) follow: bool,
    /// Markdown highlighter, when the grammars loaded. Without it (or on
    /// highlighting errors) messages render as plain text.
    highlighter: Option<MarkdownHighlighter>,
    /// The dedicated chat renderer (owns the markup-conceal toggle).
    renderer: ChatRenderer,
    /// The (width, conceal) pair every [`Message::rows`] value was measured
    /// for. A resize or conceal toggle makes the whole cache stale at once;
    /// `ensure_measured` then re-measures every message once.
    measure_w: usize,
    measure_conceal: bool,
    /// Lua panels (`agent.api.panel_*`): op id -> the panel's creation options
    /// and, once materialized, its message's index in `messages`. Ops for
    /// unknown ids are ignored.
    panels: HashMap<u64, PanelRecord>,
}

/// Creation options + materialized state of one Lua panel ([`PanelOp`]).
struct PanelRecord {
    title: String,
    boxed: bool,
    conceal_box: bool,
    /// Index into `messages` once the panel got its first content.
    msg_index: Option<usize>,
}

/// One region of a split panel message: its caption plus the same per-message
/// highlight state as [`Message`] — declared language, cached segments, and
/// user regions — so each pane runs its own grammar (e.g. `rust` on both the
/// "before" and "after" side of a patch).
#[derive(Debug)]
pub(crate) struct PaneContent {
    pub(crate) caption: String,
    pub(crate) text: String,
    pub(crate) lang: Option<String>,
    pub(crate) segs: Vec<Segment>,
    pub(crate) user_segs: Vec<Segment>,
}

impl std::fmt::Debug for TurnPanel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnPanel")
            .field("messages", &self.messages)
            .field("scroll", &self.scroll)
            .field("follow", &self.follow)
            .field("highlighter", &self.highlighter.is_some())
            .field("renderer", &self.renderer)
            .field("panels", &self.panels.len())
            .finish()
    }
}

impl Default for TurnPanel {
    fn default() -> Self {
        Self {
            messages: Vec::new(),
            scroll: 0,
            follow: true,
            highlighter: None,
            renderer: ChatRenderer::new(),
            measure_w: 0,
            measure_conceal: false,
            panels: HashMap::new(),
        }
    }
}

/// The message's [`Message::segs`] after a (re)highlight: the markdown
/// segments plus the Lua panel regions (`user_segs`), each clamped to the text
/// length, then **reduced to disjoint ranges** and sorted by start for the
/// clipping pipelines.
///
/// Disjoint is the whole point, and it was not true before. [`clip_segments`]
/// walks every segment and prints the slice each one covers, so two segments
/// over the same bytes print that text *twice* — the line appears doubled, and
/// the row is twice as wide as the layout budgeted, which pushes the box's
/// right border off its own edge.
///
/// Overlap is the normal case, not a corner: `fs.apply_patch` tints its changed
/// lines with `p:highlight`, and the pane's declared `lang` has the grammar
/// colour those same bytes. Every highlighted line of every patch was doubled.
///
/// **User regions win the bytes they cover**, and among themselves the *last*
/// one does. A caller asking for a tint on a line means it, so the grammar's
/// colouring of those bytes is dropped rather than drawn alongside;
/// `sort_by_key(start)` would not say that, since the grammar's segment for a
/// line usually starts before the region's and would win by accident, making the
/// red/green of a diff the one thing not drawn. Last-wins among the caller's own
/// regions is what makes layering work — dim a range, then bold part of it — and
/// is why they are taken in reverse.
fn merged_segs(markdown: Vec<Segment>, user: &[Segment], len: usize) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    // Bytes already spoken for, kept sorted and disjoint.
    let mut claimed: Vec<(usize, usize)> = Vec::new();
    for sg in user.iter().rev().chain(markdown.iter()) {
        let (start, end) = (sg.start.min(len), sg.end.min(len));
        for (start, end) in unclaimed(start, end, &claimed) {
            claimed.push((start, end));
            claimed.sort_unstable();
            out.push(Segment {
                start,
                end,
                style: sg.style,
            });
        }
    }
    out.sort_by_key(|sg| (sg.start, sg.end));
    out
}

/// The parts of `s..e` not already inside `claimed` (sorted, disjoint).
///
/// What makes a later, higher-priority segment *replace* an earlier one rather
/// than sit on top of it: the earlier bytes are subtracted off, so each byte of
/// the text ends up in exactly one segment and is therefore printed once.
fn unclaimed(s: usize, e: usize, claimed: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut cur = s;
    for &(cs, ce) in claimed {
        if ce <= cur {
            continue; // entirely before the range still to fill
        }
        if cs >= e {
            break; // and past its end, since `claimed` is sorted
        }
        if cs > cur {
            out.push((cur, cs.min(e))); // the gap in front of this claim
            cur = cs;
        }
        cur = cur.max(ce); // skip over the claimed bytes
        if cur >= e {
            break;
        }
    }
    if cur < e {
        out.push((cur, e));
    }
    out
}

/// Pane `pane` (1-based) of `messages[idx]`'s split panel — `None` when the
/// message is not a split panel or the pane is out of range (`0` counts as
/// out of range too). A free function so callers can pair it with a disjoint
/// `&mut self.highlighter` borrow (like the single-body arms pair
/// `&mut self.messages[idx]` with `rehighlight`).
fn pane_of(messages: &mut [Message], idx: usize, pane: usize) -> Option<&mut PaneContent> {
    let pi = pane.checked_sub(1)?;
    messages[idx].panes.as_mut()?.get_mut(pi)
}

impl TurnPanel {
    /// Install (or clear) the markdown highlighter; call before pushing
    /// messages so their segments are computed with it.
    pub fn set_highlighter(&mut self, highlighter: Option<MarkdownHighlighter>) {
        self.highlighter = highlighter;
    }

    /// The highlighter, for a caller that has to change it *and* then re-render
    /// the messages it affects. A disjoint borrow is not available for that from
    /// outside the module — `rehighlight` needs `&mut messages` while the
    /// highlighter is `&mut self` — so the two steps are sequenced here instead.
    pub fn highlighter_mut(&mut self) -> Option<&mut MarkdownHighlighter> {
        self.highlighter.as_mut()
    }

    /// Collapse every framed box in the transcript.
    ///
    /// For a resumed session, where the boxes are *history*: a long session has
    /// a panel per tool call, and expanding them all buries the conversation that
    /// is actually being resumed under screens of old output. Collapsed, each is
    /// its title and a `[+]`, and the transcript reads as the outline it is.
    ///
    /// Only framed boxes: the borderless streamed blocks (`reasoning`,
    /// `response`) have no frame and no collapse affordance — see
    /// [`is_borderless_box`] — so they are left exactly as replayed them.
    ///
    /// A no-op on a message with nothing to collapse, and idempotent, so calling
    /// it on a transcript that is already collapsed changes nothing.
    pub fn collapse_all_boxes(&mut self) {
        for msg in &mut self.messages {
            if msg.boxed.is_some() && !is_borderless_box(msg) && !msg.collapsed {
                msg.collapsed = true;
                msg.dirty = true;
            }
        }
    }

    /// Apply one Lua panel op ([`PanelOp`]) to the transcript. Panels render
    /// through exactly the same pipelines as every other message — `boxed`
    /// panels are the click-collapsible bordered boxes, plain panels are
    /// ordinary assistant messages — so the UI stays the familiar one. Ops
    /// for unknown panels and highlights before any content are ignored
    /// (the op stream is data; validation happens here, not in Lua).
    pub fn apply_op(&mut self, op: PanelOp) {
        match op {
            PanelOp::Create {
                id,
                title,
                boxed,
                conceal_box,
            } => {
                self.panels.insert(
                    id,
                    PanelRecord {
                        title,
                        boxed,
                        conceal_box,
                        msg_index: None,
                    },
                );
            }
            PanelOp::Append { id, text } => {
                let Some(idx) = self.ensure_panel(id) else {
                    return;
                };
                let msg = &mut self.messages[idx];
                msg.text.push_str(&renderable(&text));
                Self::rehighlight(&mut self.highlighter, msg);
            }
            PanelOp::Set { id, text } => {
                let Some(idx) = self.ensure_panel(id) else {
                    return;
                };
                let msg = &mut self.messages[idx];
                msg.text = renderable(&text).into_owned();
                Self::rehighlight(&mut self.highlighter, msg);
            }
            PanelOp::Highlight {
                id,
                start,
                end,
                style,
            } => {
                let Some(idx) = self.panels.get(&id).and_then(|p| p.msg_index) else {
                    return; // highlight before any content: nothing to style
                };
                let len = self.messages[idx].text.len();
                let (s, e) = (start.min(len), end.min(len));
                let (start, end) = (s.min(e), s.max(e));
                if start < end {
                    let style = style_for_spec(&style);
                    let msg = &mut self.messages[idx];
                    msg.user_segs.push(Segment { start, end, style });
                    msg.user_segs.sort_by_key(|sg| (sg.start, sg.end));
                }
                Self::rehighlight(&mut self.highlighter, &mut self.messages[idx]);
            }
            PanelOp::ClearRegions { id } => {
                let Some(idx) = self.panels.get(&id).and_then(|p| p.msg_index) else {
                    return;
                };
                let msg = &mut self.messages[idx];
                msg.user_segs.clear();
                Self::rehighlight(&mut self.highlighter, msg);
            }
            PanelOp::Split { id, title, panes } => {
                // The split is its own materializer: the pane frame *is* the
                // content, so the boxed message appears at creation (empty
                // panes render as captioned blank regions). A repeated Split
                // for a live id is ignored.
                if self.panels.contains_key(&id) {
                    return;
                }
                self.panels.insert(
                    id,
                    PanelRecord {
                        title,
                        boxed: true,
                        conceal_box: false,
                        msg_index: None,
                    },
                );
                let Some(idx) = self.ensure_panel(id) else {
                    return;
                };
                self.messages[idx].panes = Some(
                    panes
                        .into_iter()
                        .map(|p| PaneContent {
                            caption: p.caption,
                            lang: p.lang,
                            text: String::new(),
                            segs: Vec::new(),
                            user_segs: Vec::new(),
                        })
                        .collect(),
                );
                self.messages[idx].dirty = true; // pane captions were added
            }
            PanelOp::SetPane { id, pane, text } => {
                let Some(idx) = self.ensure_panel(id) else {
                    return;
                };
                let Some(p) = pane_of(&mut self.messages, idx, pane) else {
                    return;
                };
                p.text = renderable(&text).into_owned();
                Self::rehighlight_pane(&mut self.highlighter, p);
                self.messages[idx].dirty = true;
            }
            PanelOp::SetPaneLang { id, pane, lang } => {
                let Some(idx) = self.ensure_panel(id) else {
                    return;
                };
                let Some(p) = pane_of(&mut self.messages, idx, pane) else {
                    return;
                };
                if p.lang != lang {
                    p.lang = lang;
                    Self::rehighlight_pane(&mut self.highlighter, p);
                }
                self.messages[idx].dirty = true;
            }
            PanelOp::HighlightPane {
                id,
                pane,
                start,
                end,
                style,
            } => {
                let Some(idx) = self.ensure_panel(id) else {
                    return;
                };
                let Some(p) = pane_of(&mut self.messages, idx, pane) else {
                    return;
                };
                let len = p.text.len();
                let (s, e) = (start.min(len), end.min(len));
                let (start, end) = (s.min(e), s.max(e));
                if start < end {
                    let style = style_for_spec(&style);
                    p.user_segs.push(Segment { start, end, style });
                    p.user_segs.sort_by_key(|sg| (sg.start, sg.end));
                }
                Self::rehighlight_pane(&mut self.highlighter, p);
                self.messages[idx].dirty = true;
            }
            PanelOp::ClearPaneRegions { id, pane } => {
                let Some(idx) = self.ensure_panel(id) else {
                    return;
                };
                let Some(p) = pane_of(&mut self.messages, idx, pane) else {
                    return;
                };
                p.user_segs.clear();
                Self::rehighlight_pane(&mut self.highlighter, p);
                self.messages[idx].dirty = true;
            }
            PanelOp::Overlay { id, text, remember } => {
                let Some(idx) = self.ensure_panel(id) else {
                    return;
                };
                let msg = &mut self.messages[idx];
                msg.overlay = text.map(|t| Overlay {
                    text: t,
                    remember: remember.clone(),
                });
                msg.dirty = true; // the overlay adds rows inside the box
                if msg.overlay.is_some() {
                    // A pending permission ask must be legible: expand a
                    // collapsed box and pin the viewport to the bottom so the
                    // overlay (drawn inside the box) is on screen.
                    msg.collapsed = false;
                    self.follow = true;
                }
            }
        }
    }

    /// Materialize panel `id`'s message (its first `Append`/`Set`) if it
    /// doesn't have one yet, and return its index into `messages`. Unknown
    /// ids return `None` — their ops are ignored.
    fn ensure_panel(&mut self, id: u64) -> Option<usize> {
        let opts = {
            let rec = self.panels.get(&id)?;
            (rec.title.clone(), rec.boxed, rec.conceal_box)
        };
        if self.panels.get(&id).is_some_and(|p| p.msg_index.is_none()) {
            self.push_inner(
                Role::Assistant,
                String::new(),
                opts.1.then_some(opts.0),
                opts.2,
            );
            self.panels.get_mut(&id).expect("checked above").msg_index =
                Some(self.messages.len() - 1);
        }
        self.panels.get(&id).and_then(|p| p.msg_index)
    }

    pub fn push(&mut self, role: Role, text: String) {
        self.push_inner(role, text, None, false);
    }

    /// Push a message rendered inside a bordered box titled `tool` (e.g. the
    /// tool's name) — the "tool-call visual". Any role may be boxed. The box
    /// uses the original (non-conceal) base rendering, so markers stay
    /// visible inside it regardless of the conceal toggle.
    pub fn push_boxed(&mut self, role: Role, text: String, tool: String) {
        self.push_inner(role, text, Some(tool), false);
    }

    /// Append one streamed fragment to the conversation's current assistant
    /// message, re-highlighting it so markdown stays current as a turn
    /// streams in. If the last message isn't a plain assistant message — it's
    /// boxed, or the conversation ended with a user message — a fresh
    /// assistant message is started (so the first chunk creates the row the
    /// answer renders into). This is the agent loop's live-reply seam.
    pub fn stream_append(&mut self, text: &str) {
        let msg = match self.messages.last_mut() {
            Some(m) if m.role == Role::Assistant && m.boxed.is_none() => m,
            _ => {
                self.push(Role::Assistant, String::new());
                self.messages.last_mut().expect("just pushed")
            }
        };
        msg.text.push_str(&renderable(text));
        Self::rehighlight(&mut self.highlighter, msg);
    }

    /// Append one streamed fragment into a *borderless* assistant block
    /// titled `title` (a fresh block is started for the first chunk, and
    /// later chunks keep flowing into it as long as it's still the last
    /// message). This is the seam the agent loop uses to stream both the
    /// reasoning (title "reasoning") and the answer (title "response") live
    /// into their own blocks: the reasoning one renders dimmed — darker than
    /// the answer — and neither draws a frame (tool boxes,
    /// [`TurnPanel::push_boxed`], keep theirs). The block's content follows
    /// the markup-conceal toggle like a plain message.
    pub fn stream_append_boxed(&mut self, text: &str, title: String) {
        let msg = match self.messages.last_mut() {
            Some(m) if m.role == Role::Assistant && m.boxed.as_deref() == Some(title.as_str()) => m,
            _ => {
                self.push_inner(Role::Assistant, String::new(), Some(title), true);
                self.messages.last_mut().expect("just pushed")
            }
        };
        msg.text.push_str(&renderable(text));
        Self::rehighlight(&mut self.highlighter, msg);
    }

    /// Re-run the highlighter over `msg.text` (the streaming seam: a raw
    /// plain-text fragment may start/end mid-construct, so the whole message
    /// is re-highlighted every time it grows), merging the Lua panel regions
    /// (`user_segs`) back in. Takes the highlighter field rather than
    /// `&mut self` so it can run while `msg` still borrows `self.messages`.
    /// Marks the message's cached height stale, since its display text (and
    /// therefore its wrapped row count) may have changed.
    fn rehighlight(highlighter: &mut Option<MarkdownHighlighter>, msg: &mut Message) {
        msg.dirty = true;
        match highlighter {
            Some(hl) => {
                // A declared language (SetPaneLang) bypasses the markdown
                // pipeline and runs that grammar directly on the text.
                let h = match msg.lang.as_deref() {
                    Some(lang) => hl.highlight_lang(lang, &msg.text),
                    None => hl.highlight_message_with_conceal(&msg.text),
                };
                msg.conceal = h.conceal;
                msg.segs = merged_segs(h.segments, &msg.user_segs, msg.text.len());
            }
            None => {
                msg.conceal.clear();
                msg.segs = merged_segs(Vec::new(), &msg.user_segs, msg.text.len());
            }
        }
    }

    /// Re-highlight one pane after its text or language changed: the declared
    /// grammar runs directly on the pane's own text (the markdown pipeline
    /// never applies to panes — they hold raw code), and the pane's user
    /// regions are merged back in like [`Self::rehighlight`] does for whole
    /// messages. Unknown/unloaded languages degrade to plain text, matching
    /// `highlight_lang`. A free-standing associated fn so callers can pass the
    /// disjoint `&mut self.highlighter` while `pane` borrows `self.messages`.
    fn rehighlight_pane(highlighter: &mut Option<MarkdownHighlighter>, pane: &mut PaneContent) {
        let base = match highlighter {
            Some(hl) => match pane.lang.as_deref() {
                Some(lang) => hl.highlight_lang(lang, &pane.text).segments,
                None => Vec::new(),
            },
            None => Vec::new(),
        };
        pane.segs = merged_segs(base, &pane.user_segs, pane.text.len());
    }

    /// Re-highlight every message, so a grammar that arrived after they were
    /// rendered applies to them too.
    ///
    /// This is the "hot" half of hot loading, and it is safe to call on a
    /// transcript the user is looking at: a [`Segment`] carries a resolved
    /// [`Style`] rather than a capture index, and `wrap_segments` lays text out
    /// identically to `wrap_lines` for full-coverage segments (pinned by
    /// `wrap_segments_matches_wrap_lines_layout`). So re-styling changes no row
    /// count, moves no scroll position, and cannot shift the viewport under the
    /// pointer — which is the whole reason it can run mid-conversation instead of
    /// waiting for a restart.
    ///
    /// Returns how many messages changed, so a caller can say so rather than
    /// re-rendering on every frame for a grammar that arrived with nothing to
    /// improve.
    pub fn rehighlight_all(&mut self) -> usize {
        if self.highlighter.is_none() {
            return 0;
        }
        // The viewport is deliberately *not* touched. Follow is re-asserted only
        // if it was already on: a user who has scrolled up to read something must
        // not be yanked back to the bottom by a background grammar arriving.
        let follow = self.follow;
        let mut changed = 0;
        for msg in &mut self.messages {
            let before = (msg.segs.clone(), msg.conceal.clone());
            let panes_before = msg
                .panes
                .as_ref()
                .map(|p| p.iter().map(|pane| pane.segs.clone()).collect::<Vec<_>>());
            Self::rehighlight(&mut self.highlighter, msg);
            // **Panes too.** A `write_file` or `apply_patch` panel declares the
            // file's language when the panel is created, and every language except
            // the three preloaded ones (`markdown_inline`, `bash`, `json`) is
            // absent at that moment: `highlight_lang` records the language as
            // wanted and returns no segments, so the pane renders plain and then
            // waits for the grammar.
            //
            // It used to wait for ever, because this loop only touched whole
            // messages. So a Rust, Go or Python patch panel stayed unhighlighted
            // for the rest of the session however many grammars arrived — while
            // the *message* quoting the same code lit up. `rehighlight_pane` is
            // the same code the pane's own `SetPane`/`SetPaneLang` ops run, so
            // calling it here keeps one implementation rather than two.
            if let Some(panes) = msg.panes.as_mut() {
                for pane in panes {
                    Self::rehighlight_pane(&mut self.highlighter, pane);
                }
            }
            let panes_after = msg
                .panes
                .as_ref()
                .map(|p| p.iter().map(|pane| pane.segs.clone()).collect::<Vec<_>>());
            if before.0 != msg.segs || before.1 != msg.conceal || panes_before != panes_after {
                changed += 1;
            }
        }
        self.follow = follow;
        changed
    }

    fn push_inner(&mut self, role: Role, text: String, boxed: Option<String>, conceal_box: bool) {
        // Sanitized *before* the highlight runs, not after: the grammar sees
        // the same bytes the message will hold, so its segments (byte ranges)
        // stay aligned with the stored text. Doing it afterwards would leave
        // every offset measured against text that no longer exists.
        let text = renderable(&text).into_owned();
        let (segs, conceal) = match &mut self.highlighter {
            Some(hl) => {
                let h = hl.highlight_message_with_conceal(&text);
                (h.segments, h.conceal)
            }
            None => (Vec::new(), Vec::new()),
        };
        self.messages.push(Message {
            role,
            text,
            segs,
            conceal,
            user_segs: Vec::new(),
            boxed,
            conceal_box,
            collapsed: false,
            lang: None,
            overlay: None,
            panes: None,
            rows: 0,
            dirty: true, // measured on the next render (or an ensure_measured)
        });
    }

    /// Toggle markup concealment (see `ChatRenderer`); returns the new state.
    pub fn toggle_conceal(&mut self) -> bool {
        let on = !self.renderer.conceal_enabled();
        self.renderer.set_conceal(on);
        on
    }

    /// Whether markup concealment is currently enabled.
    pub fn conceal_enabled(&self) -> bool {
        self.renderer.conceal_enabled()
    }

    /// Scroll one row toward the top; disengages follow until the user is
    /// back at the bottom.
    pub fn scroll_up(&mut self) {
        self.follow = false;
        self.scroll = self.scroll.saturating_sub(1);
    }

    /// Scroll one row toward the bottom; follow re-engages automatically
    /// once the view reaches the bottom (see `Self::resolve_scroll`).
    pub fn scroll_down(&mut self) {
        self.scroll += 1;
    }

    pub fn jump_top(&mut self) {
        self.follow = false;
        self.scroll = 0;
    }

    pub fn jump_bottom(&mut self) {
        self.follow = true;
    }

    /// (Re)fill the per-message [`Message::rows`] cache for the current (width,
    /// conceal) view. When either changed since the last fill the whole list
    /// re-measures — one wrap per message, and that happens once per resize or
    /// conceal toggle; otherwise only the messages marked dirty (their text,
    /// box state, panes, or overlay changed) re-measure. After this, scroll
    /// positioning and the scrollbar are plain sums over cached ints, and the
    /// only wrapping per frame is the visible window (see [`Self::render`]).
    fn ensure_measured(&mut self, content_w: usize) {
        let conceal = self.renderer.conceal_enabled();
        if self.measure_w != content_w || self.measure_conceal != conceal {
            self.measure_w = content_w;
            self.measure_conceal = conceal;
            for m in &mut self.messages {
                m.rows = message_rows(m, content_w, conceal);
                m.dirty = false;
            }
        } else {
            for m in &mut self.messages {
                if m.dirty {
                    m.rows = message_rows(m, content_w, conceal);
                    m.dirty = false;
                }
            }
        }
    }

    /// Rows the full panel occupies once wrapped to `content_w` cells
    /// (re-measuring stale cached heights first). Heights come from the
    /// *display* text (markers removed) when conceal is on, so the scrollbar
    /// matches the rendered rows: concealed messages take fewer cells
    /// (`# Plan` no longer spends two on the marker and space).
    fn content_height(&mut self, content_w: usize) -> usize {
        self.ensure_measured(content_w);
        self.messages.iter().map(|m| m.rows).sum()
    }

    /// The first message overlapping global content row `offset`, plus how
    /// many rows of it sit above `offset` (the intra-message scroll for the
    /// viewport's [`Paragraph`]). `offset` is clamped by `resolve_scroll` to
    /// lie within the content, so `within < rows` of the returned message. The
    /// walk is over cached row counts — no wrapping.
    fn window_start(&self, offset: usize) -> (usize, usize) {
        let mut before = 0;
        for (i, m) in self.messages.iter().enumerate() {
            if before + m.rows > offset {
                return (i, offset - before);
            }
            before += m.rows;
        }
        (self.messages.len().saturating_sub(1), 0)
    }

    /// The last message whose rows overlap the viewport when the window starts
    /// at `start` with `within` rows already consumed by the scroll offset.
    /// Over-approximates by cached counts only — no wrapping.
    fn window_end(&self, start: usize, viewport: usize, within: usize) -> usize {
        let mut acc = self.messages[start].rows.saturating_sub(within);
        let mut end = start;
        while acc < viewport && end + 1 < self.messages.len() {
            end += 1;
            acc += self.messages[end].rows;
        }
        end
    }

    /// Turn a *slice* of messages into styled, wrapped rows — the windowed
    /// render path's base (conceal-off) pipeline. Byte-for-byte the same rows
    /// [`Self::build_lines`] produces for the same messages; only the input is
    /// limited to the visible window, so the frame's wrap cost is O(viewport),
    /// not O(retained). Messages carry their highlight segments from push time;
    /// here we only wrap them. Layout is identical to plain-text wrapping —
    /// the tag row and continuation indent are unchanged, only span boundaries
    /// differ. The original segment path renders markers as-is, no conceal.
    fn build_lines_slice(&self, msgs: &[Message], content_w: usize) -> Vec<Line<'static>> {
        let text_w = content_w.saturating_sub(TAG_COLS + 1);
        let mut lines: Vec<Line<'static>> = Vec::new();
        for msg in msgs {
            lines.extend(message_lines(msg, text_w, false));
        }
        lines
    }

    /// Turn every message into styled, wrapped rows — the full-transcript base
    /// pipeline. The render path only wraps the visible slice
    /// ([`Self::build_lines_slice`]); this full build survives for tests (and
    /// the parity test proves the windowed output equals it row for row).
    #[cfg(test)]
    fn build_lines(&self, content_w: usize) -> Vec<Line<'static>> {
        let mut lines = self.build_lines_slice(&self.messages, content_w);
        if lines.is_empty() {
            lines.push(Line::raw("(no messages yet)"));
        }
        lines
    }

    /// Resolve the scroll offset for a viewport of `viewport` rows, clamping
    /// and re-engaging follow when the view reaches the bottom. Returns the
    /// offset to pass to the transcript [`Paragraph`].
    fn resolve_scroll(&mut self, content_height: usize, viewport: usize) -> usize {
        let max = content_height.saturating_sub(viewport);
        if self.follow {
            self.scroll = max;
        } else {
            self.scroll = self.scroll.min(max);
        }
        if self.scroll >= max {
            self.follow = true;
        }
        self.scroll
    }

    /// Draw the panel (its borderless body, wrapped rows, and scrollbar)
    /// into `area`.
    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        // The chat log is borderless: the body fills `area` except for the
        // 1-cell scrollbar lane at the right edge.
        let body = Rect {
            x: area.x,
            y: area.y,
            width: area.width.saturating_sub(1),
            height: area.height,
        };
        let content_w = body.width as usize;
        let viewport = body.height as usize;
        // Heights come from the per-message cache (`ensure_measured` only
        // wraps messages whose text/state changed since they were measured)…
        let content_h = self.content_height(content_w);
        let offset = self.resolve_scroll(content_h, viewport);

        // …so the only wrapping per frame happens here, on the visible slice:
        // the messages overlapping [offset, offset + viewport). Older content
        // stays in memory (the transcript caches up to the compaction point
        // or the start of the session) but never gets wrapped again unless
        // it becomes visible.
        let (lines, scroll_rows) = if self.messages.is_empty() {
            (vec![Line::raw("(no messages yet)")], 0)
        } else {
            let (start, within) = self.window_start(offset);
            let end = self.window_end(start, viewport, within);
            let slice = &self.messages[start..=end];
            // Three pipelines: the original segment path when conceal is off,
            // the dedicated chat renderer (display text) when it is on — and
            // when any message is boxed, the bordered renderer frames the
            // boxed ones (raw base path inside) while rendering the rest per
            // the toggle. The pipeline is picked over the whole list so the
            // slice renders exactly as it would in the full build.
            let conceal = self.renderer.conceal_enabled();
            let lines = if self.messages.iter().any(|m| m.boxed.is_some()) {
                BorderedRenderer::lines(slice, content_w, conceal)
            } else if conceal {
                self.renderer.lines(slice, content_w)
            } else {
                self.build_lines_slice(slice, content_w)
            };
            // `within` rows of the slice sit above the viewport.
            (lines, within)
        };

        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .scroll((scroll_rows as u16, 0)),
            body,
        );
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            Rect {
                x: area.x.saturating_add(area.width.saturating_sub(1)),
                y: area.y,
                width: 1,
                height: area.height,
            },
            &mut ScrollbarState::new(content_h)
                .position(offset)
                .viewport_content_length(viewport),
        );
    }

    /// A left click at terminal coordinates `(col, row)` inside the panel's
    /// `area`, resolved to whatever it landed on.
    ///
    /// Two things are clickable and they are not the same kind of thing. A
    /// framed boxed message toggles its collapsed state — navigation, so it is
    /// safe to do by accident. A pending dialog's answers *decide a question*,
    /// so they come back as the letter inside the brackets and nothing here
    /// interprets it: the caller routes it through the same rule the keyboard
    /// uses, and a click therefore cannot mean something a keypress would not.
    pub fn handle_click(&mut self, col: usize, row: usize, area: Rect) -> Click {
        // Only the transcript body is clickable (not the scrollbar lane at
        // the right edge, or rows above/below the panel).
        let left = area.x as usize;
        let right = (area.x + area.width).saturating_sub(1) as usize;
        if col < left || col >= right || row < area.y as usize {
            return Click::Nothing;
        }
        // Screen row -> paragraph row, undoing the viewport's scroll offset.
        let content_row = (row - area.y as usize) + self.scroll;
        // Cached row counts (no wrapping on the common path — `ensure_measured`
        // re-measures only stale messages). The panel's body width equals
        // `content_w(area)`.
        // The *same* width `ensure_measured` used, and not `area.width`: the
        // row counts it cached were computed at `content_w`, and a body height
        // measured at a different width wraps differently and puts the answers
        // on the wrong row.
        let width = content_w(area);
        self.ensure_measured(width);
        let conceal = self.renderer.conceal_enabled();
        let mut acc = 0;
        for msg in &mut self.messages {
            let rows = msg.rows;
            if content_row < acc + rows {
                // The dialog's answers are checked first: they sit inside a
                // boxed message, and a click on one that fell through to the
                // collapse toggle would both answer the question *and* fold
                // the box it was drawn in.
                if let Some(overlay) = msg.overlay.as_ref() {
                    // Row 0 is the box's top border, then the body, then the
                    // dialog — whose first row is the one carrying the prompt.
                    let prompt_row = 1 + body_row_count(msg, width, conceal);
                    if content_row - acc == prompt_row {
                        // This row belongs to the dialog and does nothing else:
                        // a click on its border is not a click on the box, and
                        // letting it through would fold away the very question
                        // the pointer was aimed at.
                        let offset = col - left - FRAME_COLS - PROMPT_COL;
                        return match prompt_hit(&overlay_prompt(&overlay.remember), offset) {
                            Some(key) => Click::Answer(key),
                            None => Click::Nothing,
                        };
                    }
                }
                if msg.boxed.is_some() && !is_borderless_box(msg) {
                    msg.collapsed = !msg.collapsed;
                    msg.dirty = true; // collapse changes the row count
                    return Click::Toggled;
                }
                return Click::Nothing;
            }
            acc += rows;
        }
        Click::Nothing
    }
}

/// The paragraph's wrap width inside a panel of `area` (the rightmost
/// column is the scrollbar lane, not body).
fn content_w(area: Rect) -> usize {
    (area.width as usize).saturating_sub(1)
}

/// How many rows the *body* of a boxed message occupies — everything between
/// the box's top and bottom borders, excluding the pending dialog.
///
/// Extracted because two things need this number and must not compute it
/// differently: [`message_rows`], which stacks row counts down the transcript,
/// and [`TurnPanel::handle_click`], which maps a clicked row back to a message.
/// When the click handler worked the height out its own way, a one-row
/// disagreement would put the clickable answers a line above or below where they
/// are drawn — the failure mode of every hit test, and the reason this is a
/// function rather than an expression written out in two places.
fn body_row_count(msg: &Message, content_w: usize, conceal: bool) -> usize {
    let inner = content_w.saturating_sub(4);
    if msg.panes.is_some() {
        // Split body heights come from the pane layout, which reflows
        // side-by-side→stacked with the width ([`split_body_rows`] is the
        // single measure used here and in [`boxed_lines`]).
        return split_body_rows(msg, inner).len().max(1);
    }
    if conceal && msg.conceal_box {
        // Mirror `boxed_lines`: the conceal path hides markers, so the height
        // comes from the display text.
        let n = if msg.conceal.is_empty() {
            wrap_lines(&msg.text, inner).len()
        } else {
            wrap_concealed(msg, inner).len()
        };
        return n.max(1);
    }
    wrap_lines(&msg.text, inner).len().max(1)
}

/// Rows `msg` occupies; an empty message still takes one row (its tag line).
/// With conceal enabled the height comes from the display text (markers
/// removed) so it agrees with [`ChatRenderer::lines`]; otherwise the raw text
/// matches the original path. A boxed message adds its two border rows and
/// measures the base path unless its `conceal_box` opts the box content into
/// the conceal path (then it mirrors [`boxed_lines`] with the toggle on); a
/// collapsed box is just its title and bottom border. A boxed message with a
/// pending [`Message::overlay`] adds the overlay's rows (see [`overlay_rows`]).
fn message_rows(msg: &Message, content_w: usize, conceal: bool) -> usize {
    if msg.boxed.is_some() && !is_borderless_box(msg) {
        if msg.collapsed {
            return 2;
        }
        let rows = body_row_count(msg, content_w, conceal);
        let overlay = if msg.overlay.is_some() {
            overlay_rows(msg, content_w).len()
        } else {
            0
        };
        return rows + 2 + overlay;
    }
    let text_w = content_w.saturating_sub(TAG_COLS + 1);
    let text: std::borrow::Cow<'_, str> = if conceal {
        display_text(msg)
    } else {
        std::borrow::Cow::Borrowed(&msg.text)
    };
    wrap_lines(text.as_ref(), text_w).len().max(1)
}

/// Styled body rows for `msg` wrapped to `text_w` cells — the shared
/// per-message pipeline: the display text (markers hidden) when conceal is
/// on and the message has ranges, otherwise the original segment path
/// (raw text, `wrap_segments`/`wrap_lines`).
fn body_rows(msg: &Message, text_w: usize, conceal: bool) -> Vec<Vec<Span<'static>>> {
    if conceal && !msg.conceal.is_empty() {
        return wrap_concealed(msg, text_w);
    }
    if msg.segs.is_empty() {
        wrap_lines(&msg.text, text_w)
            .into_iter()
            .map(|row| vec![Span::raw(row)])
            .collect()
    } else {
        wrap_segments(&msg.text, &msg.segs, text_w)
    }
}

/// One message's full rows — the tag row (when the body isn't empty) plus
/// the indented continuation rows — shared by the original path
/// ([`TurnPanel::build_lines`]), the chat renderer, and the bordered
/// renderer's non-boxed messages.
fn message_lines(msg: &Message, text_w: usize, conceal: bool) -> Vec<Line<'static>> {
    let mut first = vec![Span::styled(
        format!("{:<TAG_COLS$}", msg.role.tag()),
        msg.role.style(),
    )];
    let rows = body_rows(msg, text_w, conceal);
    let mut out = Vec::with_capacity(rows.len());
    if let Some(r0) = rows.first()
        && r0.iter().any(|s| !s.content.is_empty())
    {
        first.extend(r0.iter().cloned());
    }
    out.push(Line::from(first));
    for row in rows.iter().skip(1) {
        let mut spans = vec![Span::raw(" ".repeat(TAG_COLS + 1))];
        spans.extend(row.iter().cloned());
        out.push(Line::from(spans));
    }
    out
}

/// Cut `title` to at most `room` cells, marking the cut with `…`.
///
/// Titles are model- and tool-authored text — the `bash` tool puts the command
/// line there — so "assume it fits" is not safe, and a box whose top border is
/// wider than its area wraps and destroys the frame. Cells, not bytes: the box
/// is drawn with a `chars()`-based fill, so this measures the same way (and
/// inherits the same wide-character approximation, noted in the module docs).
/// A `room` too small for the ellipsis itself is left empty rather than filled
/// with one.
fn fit_title(title: &str, room: usize) -> String {
    if cells(title) <= room {
        return title.to_string();
    }
    if room == 0 {
        return String::new();
    }
    if room == 1 {
        return "…".to_string();
    }
    let head: String = take_cells(title, room - 1);
    format!("{head}…")
}

/// A pending permission dialog on a boxed message: what is being asked, and what
/// its third answer is called — `None` when there is no third answer, which is
/// whenever the asking side had nothing to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Overlay {
    pub text: String,
    pub remember: Remember,
}

/// A boxed message's rows, replacing the role tag row: a title border
/// (`┌─ <tool> [−] ─…─┐`), content rows `│ … │` wrapping the base path at
/// `content_w - 4` (or the conceal path when the box opts in and the toggle
/// is on), and a bottom border (`└─…─┘`). `[−]`/`[+]` marks the
/// click-to-collapse/expand affordance; a collapsed box renders only the
/// title and bottom rows, with `[+]`. Row counts match [`message_rows`].
fn boxed_lines(msg: &Message, content_w: usize, conceal: bool) -> Vec<Line<'static>> {
    let inner = content_w.saturating_sub(4); // '│ ' body ' │'
    let title = msg.boxed.as_deref().unwrap_or("tool");
    let indicator = if msg.collapsed { "[+]" } else { "[−]" };

    // Title border, filled with ─ to exactly `content_w` cells. The title is
    // cut to whatever the frame leaves, so a title longer than the box is
    // shortened instead of overflowing — an overflowing border wraps to the next
    // terminal row and the box stops being a box.
    //
    // The reserved width is every cell around the title: `┌─ `, the space after
    // it, the indicator, the space before the fill, *and* the closing `┐`. The
    // last one is the easy one to forget, and forgetting it is off by exactly
    // one cell on every row.
    let fixed = cells("┌─ ") // 3
        + 1 // space between title and indicator
        + cells(indicator)
        + 1 // space between indicator and fill
        + cells("┐");
    let mut top = format!(
        "┌─ {} {indicator} ",
        fit_title(title, content_w.saturating_sub(fixed))
    );
    let fill = content_w.saturating_sub(cells(&top) + 1);
    top.push_str(&"─".repeat(fill));
    top.push('┐');
    let mut out = Vec::new();
    out.push(Line::raw(top));

    if !msg.collapsed {
        if msg.panes.is_some() {
            let inner = content_w.saturating_sub(4);
            for row in split_body_rows(msg, inner) {
                let used: usize = row.spans.iter().map(|s| cells(&s.content)).sum();
                let pad = " ".repeat(inner.saturating_sub(used));
                let mut spans = Vec::with_capacity(row.spans.len() + 2);
                spans.push(Span::raw("│ "));
                spans.extend(row.spans.iter().cloned());
                spans.push(Span::raw(format!("{pad} │")));
                out.push(Line::from(spans));
            }
            if msg.overlay.is_some() {
                out.extend(overlay_rows(msg, content_w));
            }
        } else {
            for row in body_rows(msg, inner, conceal && msg.conceal_box) {
                let used: usize = row.iter().map(|s| cells(&s.content)).sum();
                let pad = " ".repeat(inner.saturating_sub(used));
                let mut spans = Vec::with_capacity(row.len() + 2);
                spans.push(Span::raw("│ "));
                spans.extend(row);
                spans.push(Span::raw(format!("{pad} │")));
                out.push(Line::from(spans));
            }
            if msg.overlay.is_some() {
                out.extend(overlay_rows(msg, content_w));
            }
        }
    }

    let bottom = format!("└{}┘", "─".repeat(content_w.saturating_sub(2)));
    out.push(Line::raw(bottom));
    out
}

/// What a click in the transcript landed on.
///
/// [`Answer`](Click::Answer) is deliberately just a letter: the panel knows
/// where the dialog is drawn, and nothing about what an answer *means* — that
/// is the caller's rule, shared with the keyboard so the two cannot diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Click {
    /// A framed box toggled open or shut. Navigation, not a decision.
    Toggled,
    /// One of the dialog's answers: the letter inside the brackets, already
    /// lower-cased. The caller maps it with the same rule a key press uses, so
    /// `a` here means exactly what `a` on the keyboard means.
    Answer(char),
    /// Anywhere else: empty input, a borderless block, the scrollbar lane.
    Nothing,
}

/// Cells of frame between the panel's left edge and the text inside a box:
/// the `│` and its trailing space. Every row of a framed message starts with
/// them, and the click test has to step over them to reach the dialog.
const FRAME_COLS: usize = 2;

/// Cells of the dialog's own top border before the key prompt begins: `┌`, `─`,
/// and the space between.
///
/// One constant for both the hit test and [`overlay_title`], because the two
/// are the same fact about the same string and a disagreement between them puts
/// the clickable answers somewhere other than where they are drawn.
const PROMPT_COL: usize = 3;

/// The dialog's answers, as `(start, end, key)` columns measured from the start
/// of the prompt string.
///
/// A label is the bracketed letter *and* the word after it — `[y]es`, not just
/// the `y` — because the brackets say which key does it and the word is what a
/// pointer is aiming at. It runs to the next `·`, which is also where the visual
/// gap is, so a click on the gap or the `─` fill is nothing rather than a
/// lucky guess.
fn prompt_labels(prompt: &str) -> Vec<(usize, usize, char)> {
    let chars: Vec<char> = prompt.chars().collect();
    let mut out = Vec::new();
    let mut open: Option<usize> = None;
    for (col, &ch) in chars.iter().enumerate() {
        match ch {
            '[' => open = Some(col),
            ']' => {
                let Some(start) = open.take() else { continue };
                // Up to the next `·`, then back off the space in front of it:
                // the label is the bracketed key and the word after it, and the
                // gap is a gap. Leaving the space inside made a click *between*
                // two answers answer the first one, which is the sort of thing
                // that reads as "the mouse is broken" and is not.
                let mut end = chars[col + 1..]
                    .iter()
                    .position(|c| *c == '\u{00B7}')
                    .map_or(chars.len(), |d| col + 1 + d);
                while end > start + 3 && chars[end - 1].is_whitespace() {
                    end -= 1;
                }
                let key = chars.get(start + 1).copied().unwrap_or('?');
                out.push((start, end, key.to_ascii_lowercase()));
            }
            _ => {}
        }
    }
    out
}

/// The answer a click at `offset` columns into the prompt lands on, if any.
fn prompt_hit(prompt: &str, offset: usize) -> Option<char> {
    prompt_labels(prompt)
        .into_iter()
        .find(|(start, end, _)| offset >= *start && offset < *end)
        .map(|(_, _, key)| key)
}

/// The dialog's top border, carrying the key prompt in its title.
///
/// The bracketed letters are underlined, because they are clickable as well as
/// typeable and a target drawn exactly like the text beside it is a target
/// nobody goes looking for. The fill is measured on the plain string first, so
/// adding a style cannot quietly change the width — and the labels come from
/// [`prompt_labels`] and the offset from [`PROMPT_COL`], the same two the click
/// test uses, so the underline cannot land somewhere the click does not.
fn overlay_title(prompt: &str, inner: usize, style: Style) -> Line<'static> {
    let head = format!("┌─ {prompt} ");
    let fill = inner.saturating_sub(cells(&head) + 1);
    let border = format!("{head}{}┐", "─".repeat(fill));
    let labels = prompt_labels(prompt);
    let hot = style.add_modifier(Modifier::UNDERLINED);
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut buf = String::new();
    let mut lit = false;
    for (col, ch) in border.chars().enumerate() {
        let now = labels
            .iter()
            .any(|(start, end, _)| col >= PROMPT_COL + start && col < PROMPT_COL + end);
        if now != lit && !buf.is_empty() {
            let done = std::mem::take(&mut buf);
            spans.push(Span::styled(done, if lit { hot } else { style }));
        }
        lit = now;
        buf.push(ch);
    }
    if !buf.is_empty() {
        spans.push(Span::styled(buf, if lit { hot } else { style }));
    }
    frame_spans(spans, style)
}

/// The key prompt drawn as the dialog's title: the user answers the pending
/// permission ask with `y` (allow) or `n` (deny) while the sandbox keeps the
/// asking syscall frozen — and with `a` as well when the question had something
/// to remember, which is the only case where a third answer is one the agent
/// can act on rather than a promise it cannot keep.
///
/// The third answer's *name* comes from the ask rather than from here, because
/// not every remembering answer is an "always": a capability is remembered for
/// the sandbox run it was accepted in, and draws `lways this run` so the limit
/// is on screen while the choice is being made. The bracket and the `a` are
/// this function's — the text after them is not, which is what stops a caller
/// from offering a key the handler does not answer.
fn overlay_prompt(remember: &Remember) -> String {
    match remember {
        None => "[y]es \u{00B7} [n]o".to_string(),
        Some(label) => format!("[y]es \u{00B7} [n]o \u{00B7} [a]{label}"),
    }
}

/// Style of the overlay's frame and title. Deliberately distinct from the
/// body rows: bold yellow on a dark band reads as a modal inset, so the ask
/// is unmistakable against the streamed output above it.
fn overlay_title_style() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD)
}

/// Style of the overlay's description rows.
fn overlay_body_style() -> Style {
    Style::default().fg(Color::Yellow).bg(Color::DarkGray)
}

/// The user-permission overlay rows for a boxed message, drawn at the bottom
/// *inside* the box (between the last body row and the box's bottom border):
/// a framed mini-panel
///
/// ```text
/// │ ┌─ [y] allow · [n] deny ─────┐ │
/// │ │ openat (pid 7) requests …  │ │
/// │ └────────────────────────────┘ │
/// ```
///
/// The description is wrapped to the inner width and capped at two rows, so
/// the overlay stays ~3–4 rows tall. Each returned row already carries the
/// outer box's `│ … │` framing and spans exactly `content_w` cells like the
/// body rows, so the outer borders stay aligned. Rendered only for boxed
/// messages with [`Message::overlay`] set; row counts agree with
/// [`message_rows`].
fn overlay_rows(msg: &Message, content_w: usize) -> Vec<Line<'static>> {
    let inner = content_w.saturating_sub(4);
    let Some(overlay) = msg.overlay.as_ref() else {
        return Vec::new();
    };
    let desc = overlay.text.as_str();
    let title = overlay_title_style();
    let body = overlay_body_style();
    let mut out = Vec::new();

    // Mini-panel top border, filled with ─ to the full inner width. The key
    // prompt lives in the title, so it stays on one line and never competes
    // with the description for the row budget below.
    out.push(overlay_title(
        &overlay_prompt(&overlay.remember),
        inner,
        title,
    ));

    // The dialog's own box is `inner` cells wide, so its body row
    // `│ text │` has to come to `inner` too: four cells of chrome — the two
    // borders and the two spaces. This was `inner - 2`, which made every body
    // row a cell wider than the border it sits in: a broken right edge, easy to
    // miss when the dialog was a rare overlay and impossible to miss now that
    // every question is drawn this way.
    let text_w = inner.saturating_sub(4);
    let mut lines = wrap_lines(desc, text_w);
    if lines.is_empty() {
        lines.push(String::new());
    }
    if lines.len() > 2 {
        lines.truncate(2);
        let last = lines.last_mut().expect("non-empty after truncate");
        if cells(last) < text_w {
            last.push('…');
        }
    }
    for line in lines {
        let used = cells(&line);
        let pad = " ".repeat(text_w.saturating_sub(used));
        out.push(frame_row(format!("│ {line}{pad} │"), body));
    }

    let bottom = format!("└{}┘", "─".repeat(inner.saturating_sub(2)));
    out.push(frame_row(bottom, title));
    out
}

/// Wrap one `inner`-wide overlay row in the outer box's `│ … │` framing so
/// the row spans exactly `content_w` cells, matching the boxed body rows.
fn frame_row(content: String, style: Style) -> Line<'static> {
    frame_spans(vec![Span::styled(content, style)], style)
}

/// [`frame_row`] for a row whose middle is already split into spans.
fn frame_spans(content: Vec<Span<'static>>, style: Style) -> Line<'static> {
    let mut spans = vec![Span::styled("│ ", style)];
    spans.extend(content);
    spans.push(Span::styled(" │", style));
    Line::from(spans)
}

/// Minimum cells a side-by-side pane column gets before the panes stack
/// instead. Picked so a two-pane patch box stays readable on an 80-col
/// terminal (~37 cells per pane) and stacks on narrower ones.
const MIN_PANE_COL: usize = 20;

/// Vertical rule drawn between side-by-side panes.
const PANE_DIVIDER: &str = "│";

/// How a split panel's body lays out at `inner` cells of width.
enum SplitLayout {
    /// Every pane gets its own column (widths differ by at most one cell).
    SideBySide(Vec<usize>),
    /// Panes stack full-width, a dim rule row between each.
    Stacked,
}

/// The pane layout for `inner` content cells: side-by-side whenever the inner
/// width fits every pane's minimum plus the rule cells between them, stacked
/// otherwise. Heights and drawing both go through this, so rows always agree.
fn split_layout(inner: usize, n: usize) -> SplitLayout {
    let n = n.max(1);
    if inner >= n * MIN_PANE_COL + (n - 1) {
        let avail = inner - (n - 1);
        let base = avail / n;
        let rem = avail % n;
        let cols = (0..n)
            .map(|i| if i < rem { base + 1 } else { base })
            .collect();
        SplitLayout::SideBySide(cols)
    } else {
        SplitLayout::Stacked
    }
}

/// Pane captions render dim-bold so they read as column heads, not content.
fn pane_caption_style() -> Style {
    Style::default()
        .fg(Color::Gray)
        .add_modifier(Modifier::BOLD)
}

/// A pane's caption row, clipped to `width` cells (long captions truncate
/// rather than overflow into the pane divider or the box border).
fn caption_row(caption: &str, width: usize) -> Line<'static> {
    let text: String = caption.chars().take(width).collect();
    Line::from(Span::styled(text, pane_caption_style()))
}

/// One pane's wrapped body rows at `width` cells: raw text when the pane has
/// no segments, styled wrapped segments otherwise — the same split
/// [`body_rows`] makes for whole messages, only per-pane.
fn pane_body_rows(pane: &PaneContent, width: usize) -> Vec<Line<'static>> {
    if pane.segs.is_empty() {
        wrap_lines(&pane.text, width)
            .into_iter()
            .map(Line::raw)
            .collect()
    } else {
        wrap_segments(&pane.text, &pane.segs, width)
            .into_iter()
            .map(Line::from)
            .collect()
    }
}

/// One pane column's rows: caption (when non-empty) then the wrapped body.
fn pane_column_rows(pane: &PaneContent, width: usize) -> Vec<Line<'static>> {
    let mut rows = Vec::new();
    if !pane.caption.is_empty() {
        rows.push(caption_row(&pane.caption, width));
    }
    rows.extend(pane_body_rows(pane, width));
    rows
}

/// Pad a `Line`'s spans to exactly `width` cells. Rows never exceed their
/// width (wrapping and caption clipping guarantee it), so padding alone keeps
/// the pane grid aligned.
fn pad_line_to(line: &Line<'static>, width: usize) -> Vec<Span<'static>> {
    let used: usize = line.spans.iter().map(|s| cells(&s.content)).sum();
    let mut spans: Vec<Span<'static>> = Vec::with_capacity(line.spans.len() + 1);
    spans.extend(line.spans.iter().cloned());
    if used < width {
        spans.push(Span::raw(" ".repeat(width - used)));
    }
    spans
}

/// A split panel's body rows for `inner` cells of content width: panes
/// side-by-side (a `│` rule between the columns, shorter columns blank-padded)
/// or stacked full-width below a dim rule. Row spans already fill `inner`
/// cells, so the box's `│ … │` framing pads them to the full box width.
fn split_body_rows(msg: &Message, inner: usize) -> Vec<Line<'static>> {
    let panes = msg
        .panes
        .as_deref()
        .expect("split body rows on a split message");
    match split_layout(inner, panes.len()) {
        SplitLayout::SideBySide(cols) => {
            // The body height is the tallest column; rows beyond a column's
            // own length render blank for that column.
            let per: Vec<Vec<Line<'static>>> = panes
                .iter()
                .zip(&cols)
                .map(|(p, &col)| pane_column_rows(p, col))
                .collect();
            let height = per.iter().map(Vec::len).max().unwrap_or(1);
            let mut out = Vec::with_capacity(height);
            for r in 0..height {
                let mut spans: Vec<Span<'static>> = Vec::new();
                for (i, rows) in per.iter().enumerate() {
                    if i > 0 {
                        spans.push(Span::raw(PANE_DIVIDER));
                    }
                    let col_w = cols[i];
                    spans.extend(match rows.get(r) {
                        Some(line) => pad_line_to(line, col_w),
                        None => vec![Span::raw(" ".repeat(col_w))],
                    });
                }
                out.push(Line::from(spans));
            }
            out
        }
        SplitLayout::Stacked => {
            let mut out = Vec::new();
            for (i, p) in panes.iter().enumerate() {
                if i > 0 {
                    out.push(Line::styled(
                        "─".repeat(inner),
                        Style::default().fg(Color::Gray).add_modifier(Modifier::DIM),
                    ));
                }
                if !p.caption.is_empty() {
                    out.push(caption_row(&p.caption, inner));
                }
                out.extend(pane_body_rows(p, inner));
            }
            out
        }
    }
}

/// The visible text of `msg`: the message minus its concealed marker ranges.
fn display_text(msg: &Message) -> std::borrow::Cow<'_, str> {
    if msg.conceal.is_empty() {
        return std::borrow::Cow::Borrowed(&msg.text);
    }
    let mut out = String::with_capacity(msg.text.len());
    let mut prev = 0;
    for &(r0, r1) in &msg.conceal {
        out.push_str(&msg.text[prev..r0]);
        prev = r1;
    }
    out.push_str(&msg.text[prev..]);
    std::borrow::Cow::Owned(out)
}

/// The row algorithm every wrapper here shares: split on `\n`, chunk each
/// paragraph into `width`-char rows, and hand each row's byte range to `clip`.
///
/// The one thing that varies between wrappers is what happens *inside* a row —
/// a plain wrapper slices the string, a segment wrapper slices each segment, a
/// concealing one maps the range through the conceal map first. Keeping the loop
/// in one place is what makes "row text is byte-identical to [`wrap_lines`]"
/// true by construction rather than by three copies agreeing.
fn wrap_rows(
    text: &str,
    width: usize,
    clip: impl Fn(usize, usize) -> Vec<Span<'static>>,
) -> Vec<Vec<Span<'static>>> {
    if width == 0 {
        return vec![vec![]];
    }

    let mut rows: Vec<Vec<Span<'static>>> = Vec::new();
    // Byte offset of the current paragraph's start within `text`.
    let mut base = 0usize;
    for para in text.split('\n') {
        if para.is_empty() {
            rows.push(Vec::new());
            base += 1;
            continue;
        }
        // Byte offset of the current row's start within `para`, and the cells
        // that row has used so far.
        let mut row_start = 0usize;
        let mut used = 0usize;
        for (off, grapheme) in para.grapheme_indices(true) {
            let w = cells(grapheme);
            // Break *before* a grapheme that would overflow, never inside one.
            // A row is a run of cells, so a `char` count would both overfill a
            // row (an emoji is one char, two cells) and be free to split a base
            // letter from its combining accent.
            if used > 0 && used + w > width {
                rows.push(clip(base + row_start, base + off));
                row_start = off;
                used = 0;
            }
            used += w;
        }
        rows.push(clip(base + row_start, base + para.len()));
        base += para.len() + 1;
    }
    rows
}

/// Wrap a message that conceals some markers: rows come from the *display*
/// text (markers removed) with segment boundaries mapped through the conceal
/// ranges. Heights therefore match [`wrap_lines`] on the display text, which is
/// what [`message_rows`] assumes.
fn wrap_concealed(msg: &Message, width: usize) -> Vec<Vec<Span<'static>>> {
    let display = display_text(msg);
    let disp = display.as_ref();
    wrap_rows(disp, width, |bs, be| clip_concealed(disp, msg, bs, be))
}

/// One display-space row's spans: each cached segment clipped to the row's
/// display byte range, with its source boundaries translated through the
/// conceal map.
fn clip_concealed(display: &str, msg: &Message, bs: usize, be: usize) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    for sg in &msg.segs {
        let s = to_display(&msg.conceal, sg.start).max(bs);
        let e = to_display(&msg.conceal, sg.end).min(be);
        if s < e {
            out.push(Span::styled(display[s..e].to_string(), sg.style));
        }
    }
    out
}

/// Display-space byte offset of source byte offset `src`: `src` minus every
/// conceal range that ends before it. Ranges are sorted and disjoint.
fn to_display(conceal: &[(usize, usize)], src: usize) -> usize {
    let mut hidden = 0;
    for &(r0, r1) in conceal {
        if r1 <= src {
            hidden += r1 - r0;
        } else if src < r0 {
            break; // before this run, and so before every later one
        } else {
            // **Inside** a concealed run. `src` has no display position of its
            // own — those bytes are not drawn at all — so it maps to where the
            // run *starts*.
            //
            // Falling through to `src - hidden` here is what put a colour
            // boundary in the wrong place. A segment that begins on a hidden
            // delimiter — which every grammar segment over an inline span does,
            // because the span's Source range includes them — came back mapped
            // to a position *inside* the concealment instead of at its edge, so
            // the first characters of the span drew in the surrounding style.
            // In `- **`init.lua`**:` that was the `in` of `init.lua`, left in the
            // default colour while `it.lua` took the code span's.
            return r0 - hidden;
        }
    }
    src - hidden
}

/// Wrap styled segments exactly like [`wrap_lines`] wraps plain text: the same
/// rows, and within a row each segment clipped to the row's byte range. Row text
/// is byte-identical to `wrap_lines` — only span boundaries differ — so heights
/// computed from plain wrapping stay correct.
fn wrap_segments(text: &str, segs: &[Segment], width: usize) -> Vec<Vec<Span<'static>>> {
    wrap_rows(text, width, |bs, be| clip_segments(text, segs, bs, be))
}

/// One row's spans: each segment clipped to the row's byte range.
fn clip_segments(text: &str, segs: &[Segment], bs: usize, be: usize) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    for sg in segs {
        let s = sg.start.max(bs);
        let e = sg.end.min(be);
        if s < e {
            out.push(Span::styled(text[s..e].to_string(), sg.style));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panels::{ALWAYS_LABEL, PaneInit};

    /// Every row of a boxed panel ends on the box's right border, so the frame reads
    /// as a box instead of a ragged edge.
    ///
    /// Drawn into a real buffer and checked there, not on the rows the layout
    /// produced, because the two can disagree: the layout measures content in
    /// `chars()`, and ratatui **drops control characters** when it draws
    /// (`filter(|symbol| !symbol.contains(char::is_control))`). A tab is one char
    /// to the first and *nothing* to the second, so each one on a row is a cell
    /// the padding promised and the frame never filled — the border lands that
    /// many cells early and the row spills past it.
    ///
    /// Not hypothetical: a tab-indented Lua file in an `apply_patch` before/after
    /// panel put the right border in **15 different columns**, one per distinct
    /// tab count on a row.
    ///
    /// Driven through [`TurnPanel`] and [`PanelOp`] rather than by building a
    /// `Message` by hand, because the ops are where text is sanitized
    /// ([`renderable`]) and a hand-built message skips that — the test would
    /// then be asserting about a path nothing uses.
    fn assert_box_edge_holds(label: &str, body: &str, content_w: usize) {
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Split {
            id: 1,
            title: "apply_patch: config.lua".into(),
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
        for pane in [1, 2] {
            panel.apply_op(PanelOp::SetPane {
                id: 1,
                pane,
                text: body.into(),
            });
        }
        let lines = BorderedRenderer::lines(&panel.messages, content_w, true);
        let area = ratatui::layout::Rect::new(0, 0, content_w as u16, lines.len() as u16);
        let mut buf = ratatui::buffer::Buffer::empty(area);
        for (y, row) in lines.iter().enumerate() {
            ratatui::buffer::Buffer::set_line(&mut buf, 0, y as u16, row, content_w as u16);
        }
        // Skip the two border rows; the body rows are the ones that must agree.
        let wrong: Vec<usize> = (1..lines.len().saturating_sub(1))
            .filter(|&y| buf[(content_w as u16 - 1, y as u16)].symbol() != "│")
            .collect();
        assert!(
            wrong.is_empty(),
            "{label} at {content_w} cells: {} of {} body rows do not end on the border \
             (rows {wrong:?}); a control character is counted as a cell by the layout \
             and dropped by the renderer, so the frame overflows",
            wrong.len(),
            lines.len() - 2,
        );
    }

    /// A tab-indented file — what every `apply_patch`, `write_file` and `fs.read`
    /// panel shows for Lua, Python, Go, C or Make — keeps its border.
    #[test]
    fn a_tab_indented_body_keeps_the_box_border_in_one_column() {
        let body = "\t\tlocal x = 1\n\t\t\t\treturn x\n\t\tif x then\n\t\tend\nplain";
        for content_w in [80usize, 100, 120, 160, 200] {
            assert_box_edge_holds("tab-indented", body, content_w);
        }
    }

    /// The same for the other control characters ratatui drops. A CRLF file is
    /// the realistic one; the escape byte stands in for anything else that
    /// arrives in tool output.
    #[test]
    fn other_control_characters_keep_the_box_border_in_one_column() {
        let plain = "local x = 1\nreturn x";
        for content_w in [80usize, 120, 160] {
            assert_box_edge_holds("CRLF", &plain.replace('\n', "\r\n"), content_w);
            assert_box_edge_holds("stray ESC", &plain.replace('\n', "\x1b\n"), content_w);
            assert_box_edge_holds("BEL", &plain.replace('\n', "\u{7}\n"), content_w);
        }
    }

    /// A single trailing tab is the smallest case that shows it: one dropped cell
    /// on one row is enough to break that row's border, so a fix that only
    /// handled runs of tabs would leave this behind.
    #[test]
    fn one_lone_tab_is_enough_to_break_the_border() {
        assert_box_edge_holds("one tab", "local x = 1\n\treturn x", 120);
    }

    /// The sanitiser never *removes* a character, which is what lets it live at
    /// this boundary. `fs.apply_patch` reads a file, computes `line_bytes`
    /// against those exact bytes, and passes the offsets to `p:highlight` — so a
    /// control character replaced by *nothing* would shift every later offset and
    /// tint the wrong lines.
    ///
    /// The invariant is per character, not "the length is unchanged": every
    /// character of the source is still *there*, at its own position shifted only
    /// by the substitutions before it. A tab becomes `TAB_CELLS` spaces, so
    /// everything after one moves along — which is exactly why the offset has to
    /// be computed against the text the panel stores (`fs.lua` expands tabs
    /// itself for that reason), and why this test walks the mapping rather than
    /// comparing lengths.
    #[test]
    fn sanitising_keeps_byte_offsets_meaning_the_same_thing() {
        for raw in ["\tlocal x", "local x\r", "\x1b[0m", "a\tb\rc\x1b"] {
            let clean = renderable(raw);
            assert!(
                !clean.chars().any(|c| c.is_control() && c != '\n'),
                "no control character may reach the renderer: {raw:?} -> {clean:?}"
            );
            // Walk the source, tracking how far the substitutions so far have
            // pushed everything along, and require each surviving character to
            // still be the one the source had at that point.
            let mut shift = 0usize;
            for (i, c) in raw.char_indices() {
                if c == '\t' {
                    assert!(
                        clean[i + shift..].starts_with(&" ".repeat(TAB_CELLS)),
                        "a tab widens to {TAB_CELLS} spaces: {raw:?} -> {clean:?}"
                    );
                    shift += TAB_CELLS - 1;
                } else if c.is_control() {
                    // Substituted, but one for one: this is what makes a `\r`
                    // free, and it must not move anything either.
                    assert_eq!(
                        clean[i + shift..].chars().next(),
                        Some(' '),
                        "a control character becomes exactly one space: \
                         {raw:?} -> {clean:?}"
                    );
                } else {
                    assert_eq!(
                        clean[i + shift..].chars().next(),
                        Some(c),
                        "byte {i} still holds {:?}, shifted by {shift}: \
                         {raw:?} -> {clean:?}",
                        c
                    );
                }
            }
            assert!(
                clean.len() >= raw.len(),
                "a substitution never shortens the text: {raw:?} -> {clean:?}"
            );
        }
        // A tab becomes `TAB_CELLS` spaces, never a deletion — two keeps the
        // indentation legible in a narrow pane column.
        assert_eq!(renderable("\tx"), format!("{}x", " ".repeat(TAB_CELLS)));
        // The width itself, spelled out rather than in terms of the constant:
        // every other assertion here reads `TAB_CELLS`, so without this one
        // changing the constant to any other value would pass them all. Two is
        // what was asked for, and it is also the point — a tab-indented file
        // rendered one space per tab is a wall of unindented text.
        assert_eq!(TAB_CELLS, 2, "a tab is drawn as two spaces");
        assert_eq!(renderable("\tx"), "  x");
        // A `\r` is a single space: one byte in, one byte out, so CRLF costs
        // nothing and shifts nothing.
        assert_eq!(renderable("a\rb"), "a b");
        // Newline is structure, not content: every wrapper splits on it.
        assert_eq!(renderable("a\nb"), "a\nb");
        // Nothing to do is a no-op, and keeps the borrow.
        assert!(matches!(
            renderable("plain text"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    /// The offsets `apply_patch` passes still land on the lines it meant, which is
    /// what the whole byte-offset arrangement exists to protect.
    ///
    /// Pane 1 holds a tab-indented file and the tint is asked for a line *after*
    /// the tabs. Note the text is given here already expanded, because that is
    /// what Lua does: `fs.apply_patch` substitutes tabs for spaces itself, before
    /// `line_bytes` measures anything, precisely because `p:highlight` addresses
    /// the text `p:set` stored. `Rust`'s own expansion in `renderable` is the
    /// fallback for text that arrives with tabs still in it (bash output, model
    /// text), where nothing is measuring offsets against it.
    #[test]
    fn a_highlight_after_tabs_lands_on_the_line_it_named() {
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Split {
            id: 1,
            title: "apply_patch: config.lua".into(),
            panes: vec![PaneInit {
                caption: "before".into(),
                lang: None,
            }],
        });
        // Two tab-indented lines, then a third that is what gets tinted — the
        // shape `fs.lua` produces, tabs already widened.
        let pad = " ".repeat(TAB_CELLS);
        let body = format!("{pad}{pad}first\n{pad}{pad}{pad}second\n{pad}{pad}third");
        panel.apply_op(PanelOp::SetPane {
            id: 1,
            pane: 1,
            text: body.clone(),
        });
        let third = body.rfind("third").expect("third line");
        panel.apply_op(PanelOp::HighlightPane {
            id: 1,
            pane: 1,
            start: third,
            end: third + "third".len(),
            style: "bold.green".into(),
        });

        let pane = &panel.messages[0].panes.as_ref().expect("split")[0];
        let seg = pane.user_segs.last().expect("the region was recorded");
        let marked = &pane.text[seg.start..seg.end];
        assert_eq!(
            marked,
            "third",
            "the region still names the line the caller measured, even though the \
             tabs ahead of it were sanitised: got {marked:?} at {:?}",
            seg.start..seg.end
        );
    }

    /// Overlapping segments print their text **once**.
    ///
    /// `clip_segments` walks every segment and prints the slice it covers, so two
    /// segments over the same bytes used to render that text twice — and the row
    /// twice as wide as the layout budgeted, which put the box's right border
    /// past its own edge. Overlap is the *normal* case for a patch panel: the
    /// pane's `lang` has the grammar colour the changed lines and `p:highlight`
    /// tints the same lines, so every highlighted line of every `apply_patch` was
    /// doubled.
    #[test]
    fn overlapping_segments_print_their_text_once() {
        // A full-coverage grammar segment plus a user region over its head.
        let text = "one\ntwo\n";
        let segs = merged_segs(
            vec![Segment {
                start: 0,
                end: text.len(),
                style: Style::default().fg(Color::Blue),
            }],
            &[Segment {
                start: 0,
                end: 4,
                style: Style::default().add_modifier(Modifier::BOLD),
            }],
            text.len(),
        );
        let rows = wrap_segments(text, &segs, 40);
        // `wrap_segments` returns row spans, so the newlines live *between* rows
        // rather than inside them: the printed text is the rows joined.
        let shown: String = rows.iter().flatten().map(|s| s.content.as_ref()).collect();
        assert_eq!(
            shown, "onetwo",
            "every byte printed exactly once, in order — doubled text would \
             read 'oneone' or similar"
        );
        // The region won the bytes it covers, so the tint is actually visible —
        // the grammar colour must not be the one that survives there.
        assert!(
            segs[0].style.add_modifier.contains(Modifier::BOLD),
            "the caller's region wins its own bytes: {segs:?}"
        );
    }

    /// A 2-cell character keeps the box border in its column.
    ///
    /// The layout measures rows in `chars()` and pads them to a column, but
    /// ratatui draws an emoji (and anything else East Asian Wide) as *two*
    /// cells. A row holding one is therefore budgeted a cell short, the padding
    /// under-fills, and the right border slides out of the box — the same
    /// disagreement as a dropped control character, one layer over.
    #[test]
    fn a_two_cell_character_keeps_the_box_border_in_one_column() {
        // An emoji in the middle of a Lua-looking line, which is what a
        // `write_file`/`apply_patch` panel shows for any repository that uses one.
        assert_box_edge_holds("emoji", "\ttext = \"\u{1f40d} here\",\n\tlocal x = 1", 120);
        assert_box_edge_holds(
            "CJK",
            "\tlocal x = \"\u{4f60}\u{597d}\u{4e16}\u{754c}\"",
            120,
        );
        // A base letter and a combining accent: two `char`s, one cell. Measured in
        // chars it looks two cells too wide, so the border would land early.
        assert_box_edge_holds("combining", "\tlocal x = e\u{301}cole", 120);
    }

    /// A wide character must not push a row past its column, which is what
    /// `wrap_lines` and `wrap_segments` agreeing row-for-row exists to protect.
    #[test]
    fn a_row_of_emoji_fits_the_column_it_is_wrapped_to() {
        // Four two-cell emoji into a five-cell column: two fit (four cells) and a
        // third would not, so it breaks two-and-two. Measured in `char`s the four
        // would fit on one row — twice too wide, overrunning the box.
        let text = "🐍🐍🐍🐍";
        let rows = wrap_lines(text, 5);
        assert_eq!(
            rows,
            vec!["🐍🐍".to_string(), "🐍🐍".to_string()],
            "two rows of two emoji, not one row of four"
        );
        for row in &rows {
            assert!(
                cells(row) <= 5,
                "no row may exceed the column it was wrapped to: {row:?} is {} cells",
                cells(row)
            );
        }
        // And it is the same answer the segment path gives, or the two would
        // disagree about a message's height.
        let segs = vec![Segment {
            start: 0,
            end: text.len(),
            style: Style::default(),
        }];
        assert_eq!(
            wrap_segments(text, &segs, 5).len(),
            rows.len(),
            "the plain and highlighted wrappers must agree on height"
        );
        // Nothing is lost: every emoji survives, in order.
        assert_eq!(rows.concat(), text);
    }

    /// A panel rebuilt from archived ops draws exactly what the original drew.
    ///
    /// The archive test in `main.rs` proves the ops survive a round trip; this
    /// proves the round trip is *worth* something — that a resumed session's
    /// panel is the same box, row for row, and not merely the same data. That is
    /// the claim the feature makes, and it is the one a user would notice.
    #[test]
    fn a_panel_rebuilt_from_archived_ops_draws_the_same_box() {
        let ops = vec![
            PanelOp::Split {
                id: 7,
                title: "apply_patch: /tmp/x.lua".into(),
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
            },
            PanelOp::SetPane {
                id: 7,
                pane: 1,
                text: "\tlocal a = 1\n".into(),
            },
            PanelOp::SetPane {
                id: 7,
                pane: 2,
                text: "  local a = 2\n".into(),
            },
            PanelOp::HighlightPane {
                id: 7,
                pane: 2,
                start: 2,
                end: 9,
                style: "bold.green".into(),
            },
        ];

        // The archive step, as the loop performs it.
        let archived: Vec<serde_json::Value> =
            ops.iter().map(crate::panels::panel_record).collect();
        // The replay step, as a cold start performs it.
        let decoded: Vec<PanelOp> = archived
            .iter()
            .filter_map(crate::panels::panel_record_op)
            .collect();

        let mut live = TurnPanel::default();
        for op in &ops {
            live.apply_op(op.clone());
        }
        let mut restored = TurnPanel::default();
        for op in &decoded {
            restored.apply_op(op.clone());
        }

        assert_eq!(
            live.messages.len(),
            restored.messages.len(),
            "the rebuilt transcript holds the same messages"
        );
        for content_w in [80usize, 120, 200] {
            let a = BorderedRenderer::lines(&live.messages, content_w, true);
            let b = BorderedRenderer::lines(&restored.messages, content_w, true);
            assert_eq!(a.len(), b.len(), "same height at {content_w}");
            for (i, (x, y)) in a.iter().zip(&b).enumerate() {
                let at: String = x.spans.iter().map(|s| s.content.as_ref()).collect();
                let bt: String = y.spans.iter().map(|s| s.content.as_ref()).collect();
                assert_eq!(at, bt, "row {i} at {content_w} cells");
            }
        }

        // And it is the panel it claims to be: two captioned panes, with the
        // tint the caller asked for.
        let panes = restored.messages[0].panes.as_ref().expect("a split panel");
        assert_eq!(panes.len(), 2);
        assert_eq!(panes[0].caption, "before");
        assert_eq!(panes[1].caption, "after");
        assert_eq!(panes[1].text, "  local a = 2\n");
        assert_eq!(
            panes[1].user_segs,
            vec![Segment {
                start: 2,
                end: 9,
                style: crate::tui::highlight::style_for_spec("bold.green"),
            }],
            "the tint came back with it"
        );
    }

    /// Collapsing everything a resumed transcript drew is the difference between
    /// an outline and a wall.
    ///
    /// The property that makes it safe: the *drawing* is untouched. A collapsed
    /// box is two rows and keeps every span, so opening it gives back exactly
    /// what the session showed — which is what the resumed session is for.
    #[test]
    fn collapsing_the_transcript_keeps_the_drawing_behind_the_title() {
        let mut panel = TurnPanel::default();
        for op in [
            PanelOp::Create {
                id: 1,
                title: "ls -la".into(),
                boxed: true,
                conceal_box: false,
            },
            PanelOp::Append {
                id: 1,
                text: "README.md\nlua\n".into(),
            },
        ] {
            panel.apply_op(op);
        }
        let before = BorderedRenderer::lines(&panel.messages, 60, true);
        assert!(
            before.len() > 3,
            "expanded, the panel has a body: {} rows",
            before.len()
        );

        panel.collapse_all_boxes();
        let collapsed = BorderedRenderer::lines(&panel.messages, 60, true);
        assert_eq!(
            collapsed.len(),
            2,
            "a collapsed box is its title and its bottom border, and nothing else"
        );
        let text: String = collapsed.iter().map(|l| l.to_string()).collect();
        assert!(text.contains("ls -la"), "the title survives: {text}");
        assert!(
            text.contains("[+]"),
            "and offers itself for expansion: {text}"
        );

        // The drawing is still there. `collapsed` is the only thing that changed,
        // so flipping it back gives the original rows back byte for byte.
        panel.messages[0].collapsed = false;
        panel.messages[0].dirty = true;
        let reopened = BorderedRenderer::lines(&panel.messages, 60, true);
        let at = |rows: &[Line<'static>]| -> Vec<String> {
            rows.iter()
                .map(|l| l.spans.iter().map(|s| s.content.to_string()).collect())
                .collect()
        };
        assert_eq!(
            at(&reopened),
            at(&before),
            "expanding gives back exactly what was there"
        );
    }

    /// The borderless streamed blocks are left alone.
    ///
    /// `reasoning` and `response` have no frame and no collapse affordance —
    /// [`is_borderless_box`] — so there is nothing to collapse them *to*, and
    /// dimming a collapsed row would be the only visible effect. More to the
    /// point: collapsing must not become a way to hide a resumed turn's thinking,
    /// which is the one thing the user asked to have back.
    #[test]
    fn collapsing_leaves_the_borderless_blocks_alone() {
        let mut panel = TurnPanel::default();
        panel.stream_append_boxed("thinking about it", "reasoning".into());
        panel.stream_append_boxed("the answer", "response".into());
        panel.apply_op(PanelOp::Create {
            id: 1,
            title: "ls".into(),
            boxed: true,
            conceal_box: false,
        });
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "out".into(),
        });

        panel.collapse_all_boxes();
        let state: Vec<(Option<&str>, bool)> = panel
            .messages
            .iter()
            .map(|m| (m.boxed.as_deref(), m.collapsed))
            .collect();
        assert_eq!(
            state,
            vec![
                (Some("reasoning"), false),
                (Some("response"), false),
                (Some("ls"), true),
            ],
            "only the framed box collapsed — the borderless ones have no frame and \
             no affordance to collapse to"
        );
        let screen: String = BorderedRenderer::lines(&panel.messages, 60, true)
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.to_string())
                    .collect::<String>()
            })
            .collect();
        assert!(
            screen.contains("thinking about it"),
            "and the reasoning is still readable: {screen}"
        );
    }

    #[test]
    fn content_height_counts_wrapped_rows() {
        let mut panel = TurnPanel::default();
        panel.push(Role::User, "ab\ncd".into()); // rows at text width 4 → 2
        panel.push(Role::Assistant, "x".into()); // rows at text width 4 → 1
        assert_eq!(panel.content_height(15), 3);
    }

    #[test]
    fn resolve_scroll_follows_and_clamps() {
        let mut panel = TurnPanel::default();
        assert_eq!(panel.resolve_scroll(10, 5), 5); // follow: pinned to bottom
        assert!(panel.follow);

        panel.follow = false;
        panel.scroll = 0;
        assert_eq!(panel.resolve_scroll(10, 5), 0);
        assert!(!panel.follow);

        panel.scroll = 900; // clamp to the bottom of 10 rows in a 5-row view
        assert_eq!(panel.resolve_scroll(10, 5), 5);
        assert!(panel.follow, "reaching the bottom re-engages follow");

        // Content shorter than the viewport: nothing to scroll, always bottom.
        let mut panel = TurnPanel {
            follow: false,
            ..Default::default()
        };
        assert_eq!(panel.resolve_scroll(3, 8), 0);
        assert!(panel.follow);
    }

    #[test]
    fn build_lines_renders_tag_and_indents_continuation() {
        let mut panel = TurnPanel::default();
        panel.push(Role::User, "ab\ncd".into());
        // content_w 15 -> text width 4 -> rows "ab", "cd"
        let lines = panel.build_lines(15);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].spans[0].content.as_ref(), "user      ");
        assert_eq!(lines[0].spans[1].content.as_ref(), "ab");
        assert_eq!(lines[1].spans[0].content.as_ref(), "           "); // TAG_COLS+1
        assert_eq!(lines[1].spans[1].content.as_ref(), "cd");
    }

    #[test]
    fn empty_panel_renders_a_placeholder_row() {
        let panel = TurnPanel::default();
        let lines = panel.build_lines(40);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].spans[0].content, "(no messages yet)");
    }

    #[test]
    fn wrap_segments_matches_wrap_lines_layout() {
        for (text, width) in [
            ("", 4),
            ("ab\ncd", 4),
            ("a\n\nb", 4),
            ("abcdef", 3),
            ("abcd\nefgh", 3),
            ("x", 0),
            ("café ☕", 3), // multi-byte chars: slicing stays on char bounds
        ] {
            let plain = wrap_lines(text, width);
            let segs = vec![Segment {
                start: 0,
                end: text.len(),
                style: Style::default(),
            }];
            let rows = wrap_segments(text, &segs, width);
            assert_eq!(
                rows.len(),
                plain.len(),
                "row count width={width} text={text:?}"
            );
            for (row, expected) in rows.iter().zip(&plain) {
                let joined: String = row.iter().map(|s| s.content.as_ref()).collect();
                assert_eq!(joined, *expected, "width={width} text={text:?}");
            }
        }
    }

    /// Re-styling a message must not move the page — the assumption hot loading
    /// is built on.
    ///
    /// `wrap_segments_matches_wrap_lines_layout` proves it for a *single*
    /// full-coverage segment. A re-highlight after a grammar arrives produces the
    /// opposite shape: many segments with real boundaries, and a message that may
    /// have gone from plain to styled. Both are checked here, because the failure
    /// is a viewport that jumps under the pointer when a background fetch lands —
    /// which looks like nothing more than a flicker and is very hard to attribute.
    #[test]
    fn restyling_changes_no_row_count() {
        let text = "Intro paragraph that is reasonably long and will wrap.\n\n\
                    ```rust\nfn main() {\n    let x: u32 = 7;\n    println!(\"{x}\");\n}\n```\n\n\
                    A closing line, also long enough to wrap at narrow widths.\n";
        for width in [20usize, 40, 80] {
            let plain = wrap_lines(text, width);
            // Many segments, as a real highlight produces: one per token.
            let mut segs = Vec::new();
            let mut at = 0;
            for (i, _) in text.char_indices() {
                if i % 7 == 0 && i > at {
                    segs.push(Segment {
                        start: at,
                        end: i,
                        style: Style::default(),
                    });
                    at = i;
                }
            }
            segs.push(Segment {
                start: at,
                end: text.len(),
                style: Style::default(),
            });
            let styled = wrap_segments(text, &segs, width);
            assert_eq!(
                styled.len(),
                plain.len(),
                "width={width}: {} styled rows vs {} plain",
                styled.len(),
                plain.len()
            );
        }
    }

    /// `rehighlight_all` leaves the viewport exactly where the user put it.
    ///
    /// The failure this guards is specific: a background grammar arriving would
    /// scroll a transcript the user had deliberately scrolled up to read. Follow is
    /// re-asserted only if it was already on, so neither reading position nor
    /// follow-mode is disturbed.
    #[test]
    fn rehighlighting_leaves_the_viewport_alone() {
        let mut panel = TurnPanel::default();
        for i in 0..12 {
            panel.push(
                Role::Assistant,
                format!("message {i} with enough text to occupy a row or two"),
            );
        }
        panel.scroll = 4;
        panel.follow = false; // the user has scrolled up
        let before = (panel.scroll, panel.follow);
        let changed = panel.rehighlight_all();
        assert_eq!((panel.scroll, panel.follow), before, "untouched");
        // With no highlighter there is nothing to change, and it says so rather
        // than claiming work.
        assert_eq!(changed, 0, "no highlighter, so no message changed");
    }

    #[test]
    fn wrap_segments_splits_styled_spans_across_row_boundaries() {
        // "xxyy" at width 3 wraps to "xxy" + "y"; the second segment ("yy")
        // is split across the boundary.
        let text = "xxyy";
        let segs = vec![
            Segment {
                start: 0,
                end: 2,
                style: Style::default().fg(Color::Red),
            },
            Segment {
                start: 2,
                end: 4,
                style: Style::default().fg(Color::Blue),
            },
        ];
        let rows = wrap_segments(text, &segs, 3);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].len(), 2, "both styles present on row 0");
        assert_eq!(rows[0][0].content.as_ref(), "xx");
        assert_eq!(rows[0][0].style, segs[0].style);
        assert_eq!(rows[0][1].content.as_ref(), "y");
        assert_eq!(rows[0][1].style, segs[1].style);
        assert_eq!(rows[1].len(), 1);
        assert_eq!(rows[1][0].content.as_ref(), "y");
        assert_eq!(rows[1][0].style, segs[1].style);
    }

    #[test]
    fn build_lines_styles_message_body_from_segments() {
        let mut panel = TurnPanel::default();
        panel.push(Role::User, "say hi".into());
        // Without a highlighter the message renders plain...
        let lines = panel.build_lines(40);
        assert_eq!(lines[0].spans.len(), 2); // tag + plain body
        assert_eq!(lines[0].spans[1].content.as_ref(), "say hi");
        assert_eq!(lines[0].spans[1].style, Style::default());

        // ...and with segments the same body gets styled spans.
        panel.messages[0].segs = vec![
            Segment {
                start: 0,
                end: 4,
                style: Style::default(),
            },
            Segment {
                start: 4,
                end: 6,
                style: Style::default().fg(Color::Red),
            },
        ];
        let lines = panel.build_lines(40);
        assert_eq!(lines[0].spans.len(), 3); // tag + "say " + styled "hi"
        assert_eq!(lines[0].spans[1].content.as_ref(), "say ");
        assert_eq!(lines[0].spans[2].content.as_ref(), "hi");
        assert_eq!(lines[0].spans[2].style, Style::default().fg(Color::Red));
    }

    fn msg(text: &str, segs: Vec<Segment>, conceal: Vec<(usize, usize)>) -> Message {
        Message {
            role: Role::User,
            text: text.to_string(),
            segs,
            conceal,
            user_segs: Vec::new(),
            boxed: None,
            conceal_box: false,
            collapsed: false,
            lang: None,
            overlay: None,
            panes: None,
            rows: 0,
            dirty: true,
        }
    }

    /// A two-pane split message: captioned "before"/"after" regions holding
    /// a couple of short lines each (no highlighter, so raw plain panes).
    fn split_msg() -> Message {
        Message {
            role: Role::Assistant,
            text: String::new(),
            segs: Vec::new(),
            conceal: Vec::new(),
            user_segs: Vec::new(),
            boxed: Some("apply_patch".into()),
            conceal_box: false,
            collapsed: false,
            lang: None,
            overlay: None,
            panes: Some(vec![
                PaneContent {
                    caption: "before".into(),
                    text: "aaa\nbb".into(),
                    lang: None,
                    segs: Vec::new(),
                    user_segs: Vec::new(),
                },
                PaneContent {
                    caption: "after".into(),
                    text: "cc".into(),
                    lang: None,
                    segs: Vec::new(),
                    user_segs: Vec::new(),
                },
            ]),
            rows: 0,
            dirty: true,
        }
    }

    #[test]
    fn display_text_removes_concealed_ranges() {
        let m = msg("a**b**c", vec![], vec![(1, 3), (4, 6)]);
        assert_eq!(display_text(&m).as_ref(), "abc");
        let plain = msg("hello", vec![], vec![]);
        assert_eq!(display_text(&plain).as_ref(), "hello");
    }

    #[test]
    fn to_display_translates_boundaries() {
        let conceal = vec![(0, 2), (10, 12), (20, 23)];
        assert_eq!(to_display(&conceal, 0), 0);
        assert_eq!(to_display(&conceal, 2), 0);
        assert_eq!(to_display(&conceal, 5), 3);
        assert_eq!(to_display(&conceal, 12), 8);
        assert_eq!(to_display(&conceal, 23), 16);
        assert_eq!(to_display(&conceal, 30), 23);
        // Ordering is preserved across markers (monotone mapping).
        assert!(to_display(&conceal, 6) <= to_display(&conceal, 13));

        // An offset *inside* a concealed run has no display position of its own,
        // so it maps to where the run starts. This is the case the boundary
        // checks above miss, and it is the common one: a grammar segment for an
        // inline span starts on the span's opening delimiter, which concealment
        // has hidden.
        for inside in 0..2 {
            assert_eq!(
                to_display(&conceal, inside),
                0,
                "offset {inside} is inside the first concealed run"
            );
        }
        assert_eq!(to_display(&conceal, 10), 8, "the run's first byte");
        assert_eq!(to_display(&conceal, 11), 8, "and its second");
        assert_eq!(to_display(&conceal, 20), 16, "same at the third run");
        assert_eq!(to_display(&conceal, 22), 16);
        // Still monotone across the whole thing, which the segments rely on.
        let mapped: Vec<usize> = (0..30).map(|i| to_display(&conceal, i)).collect();
        assert!(
            mapped.windows(2).all(|w| w[0] <= w[1]),
            "the mapping must never go backwards: {mapped:?}"
        );
    }

    /// The rendered line is coloured by one style from end to end — the bug this
    /// whole pair of functions exists to prevent, in the shape it actually took.
    ///
    /// `- **`init.lua`**:` hides `**` + the opening backtick as one run and the
    /// closing backtick + `**` as another, and the code span's segment starts on
    /// the opening backtick. `to_display` used to map that offset *inside* the
    /// concealment rather than to its edge, so the segment was clipped two
    /// characters late: `in` drew in the surrounding style and `it.lua` in the
    /// code colour.
    #[test]
    fn an_inline_span_takes_its_style_across_the_whole_word() {
        let text = "- **`init.lua`**: x";
        // The concealment the merge produces: `**\`` and `` `** ``.
        let mut msg = Message {
            role: Role::Assistant,
            text: text.into(),
            segs: Vec::new(),
            conceal: vec![(2, 5), (13, 16)],
            user_segs: Vec::new(),
            boxed: None,
            conceal_box: false,
            collapsed: false,
            lang: None,
            overlay: None,
            panes: None,
            rows: 0,
            dirty: true,
        };
        let plain = Style::default().add_modifier(Modifier::BOLD);
        let code = Style::default()
            .fg(Color::LightGreen)
            .add_modifier(Modifier::BOLD);
        // What the highlighter produces: a default run for the text before,
        // the delimiters bold, the code span as one green run *starting on the
        // opening backtick*, the closing delimiters bold, and a default tail.
        msg.segs = vec![
            Segment {
                start: 0,
                end: 2,
                style: Style::default(),
            },
            Segment {
                start: 2,
                end: 4,
                style: plain,
            },
            Segment {
                start: 4,
                end: 14,
                style: code,
            },
            Segment {
                start: 14,
                end: 16,
                style: plain,
            },
            Segment {
                start: 16,
                end: 19,
                style: Style::default(),
            },
        ];

        let display = display_text(&msg);
        assert_eq!(display, "- init.lua: x", "the markers are hidden");

        let rows = wrap_concealed(&msg, 40);
        // One row at 40 cells, so these are that row's spans in order.
        let row = &rows[0];
        let line: String = row.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(line, "- init.lua: x", "the visible text, in order");

        // The word is one span in the code style. It used to be two: `in` in the
        // surrounding default and `it.lua` in the code colour, the boundary
        // landing two characters into the word.
        let word: Vec<&Span> = row
            .iter()
            .filter(|s| s.content.contains("init") || s.content.contains("lua"))
            .collect();
        let word_text: String = word.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(
            word_text, "init.lua",
            "and it is contiguous, not split: {word:?}"
        );
        for span in &word {
            assert_eq!(
                span.style, code,
                "`{}` must carry the code span's style, not {:?}",
                span.content, span.style
            );
        }
    }

    #[test]
    fn chat_renderer_hides_heading_and_inline_markers() {
        // "# Plan and **bold**" -> "Plan and bold"; the styled segment maps
        // across both concealed marker runs.
        let text = "# Plan and **bold**";
        let conceal = vec![(0, 2), (11, 13), (17, 19)];
        let segs = vec![Segment {
            start: 0,
            end: text.len(),
            style: Style::default(),
        }];
        let lines = ChatRenderer::new().lines(&[msg(text, segs, conceal)], 40);
        assert_eq!(lines.len(), 1, "display text fits one row");
        assert_eq!(lines[0].spans[0].content.as_ref(), "user      ");
        assert_eq!(lines[0].spans[1].content.as_ref(), "Plan and bold");
    }

    #[test]
    fn wrap_concealed_matches_display_wrap_lines() {
        // Wrapping happens on the *display* text, exactly like `wrap_lines`:
        // row count and content stay in lockstep with the plain-text wrap.
        let text = "**bold** and more words here to force wrapping";
        let conceal = vec![(0, 2), (7, 9)];
        let m = msg(
            text,
            vec![Segment {
                start: 0,
                end: text.len(),
                style: Style::default(),
            }],
            conceal,
        );
        let display = display_text(&m);
        let wrapped = wrap_concealed(&m, 9);
        let plain = wrap_lines(&display, 9);
        assert_eq!(wrapped.len(), plain.len());
        for (row, expected) in wrapped.iter().zip(&plain) {
            // Row text is byte-identical to the plain display wrap; only span
            // boundaries differ. Here the single segment spans the whole row.
            let joined: String = row.iter().map(|s| s.content.as_ref()).collect();
            assert_eq!(joined, *expected);
        }
    }

    #[test]
    fn fenced_code_content_is_never_concealed() {
        // Only the fence delimiters are hidden; the content between them
        // survives byte-for-byte (the renderer maps it verbatim through).
        let text = "```bash\nfor x in 1 2; do\n  echo $x\ndone\n```";
        let close = text.len() - 3;
        let conceal = vec![(0, 3), (close, close + 3)];
        let m = msg(text, vec![], conceal);
        let expected = "bash\nfor x in 1 2; do\n  echo $x\ndone\n";
        assert_eq!(display_text(&m).as_ref(), expected);
    }

    #[test]
    fn content_height_uses_display_text_when_concealing() {
        let mut panel = TurnPanel::default();
        // "**bold**" wraps to 2 rows at text width 4; the display text
        // "bold" fits one.
        panel.messages.push(msg(
            "**bold**",
            vec![Segment {
                start: 0,
                end: 8,
                style: Style::default(),
            }],
            vec![(0, 2), (6, 8)],
        ));
        let content_w = 15; // text width 4
        assert!(panel.renderer.conceal_enabled());
        assert_eq!(panel.content_height(content_w), 1);
        panel.renderer.set_conceal(false);
        assert_eq!(panel.content_height(content_w), 2);
    }

    #[test]
    fn transcript_caches_every_message_up_to_the_start() {
        // The transcript keeps all messages in memory (up to the compaction
        // point or the start of the session) — the sliding window only limits
        // what gets *rendered*, never what is retained. A flood never drops
        // the oldest messages; they stay reachable for scrollback.
        let mut panel = TurnPanel::default();
        for i in 0..2500 {
            panel.push(Role::User, format!("message {i}"));
        }
        assert_eq!(panel.messages.len(), 2500);
        assert_eq!(panel.messages[0].text, "message 0");
        assert_eq!(
            panel.messages.last().map(|m| m.text.as_str()),
            Some("message 2499")
        );
        // The whole list is still measured (cached heights — no trimming).
        assert_eq!(panel.content_height(40), 2500);
    }

    #[test]
    fn windowed_render_matches_the_full_transcript_rows() {
        // The visible-window render must show exactly the rows the full
        // build would at the same scroll offset: windowing only limits *which
        // messages* get wrapped per frame, it never changes the rows.
        let mut panel = TurnPanel::default();
        for i in 0..60 {
            let text = match i % 3 {
                0 => format!("message {i} {}", "x".repeat(60)), // wraps to 3 rows
                1 => format!("short {i}"),
                _ => format!("medium {i} {}", "y".repeat(35)),
            };
            panel.push(Role::User, text);
        }
        panel.renderer.set_conceal(false); // exercise the base pipeline
        let content_w = 40;
        let viewport = 12;
        let content_h = panel.content_height(content_w);
        let full = panel.build_lines(content_w);
        assert_eq!(full.len(), content_h, "cached heights equal the built rows");
        for offset in [0, 7, content_h / 2, content_h.saturating_sub(viewport)] {
            let (start, within) = panel.window_start(offset);
            let end = panel.window_end(start, viewport, within);
            let slice_lines = panel.build_lines_slice(&panel.messages[start..=end], content_w);
            let got = &slice_lines[within..(within + viewport).min(slice_lines.len())];
            let expected = &full[offset..(offset + viewport).min(full.len())];
            assert_eq!(got, expected, "visible window at scroll offset {offset}");
        }
    }

    #[test]
    fn rows_cache_refreshes_on_text_change_and_collapse() {
        let mut panel = TurnPanel::default();
        panel.push(Role::User, "one".into());
        panel.push(Role::User, "two".into());
        let content_w = 15; // text width 4
        assert_eq!(panel.content_height(content_w), 2);
        assert!(!panel.messages.iter().any(|m| m.dirty));

        // Streaming more text re-measures only the appended message. The last
        // message is a user one, so a fresh assistant message is started.
        panel.stream_append(" three four");
        // " three four" wraps to 3 rows at text width 4; "one" and "two"
        // keep their cached single rows.
        assert_eq!(panel.content_height(content_w), 5);
        assert_eq!(panel.messages[2].text, " three four");
        assert_eq!(panel.messages[2].rows, 3);
        assert_eq!(
            panel.messages[0].rows, 1,
            "other messages are not re-wrapped"
        );
        assert!(
            !panel.messages.iter().any(|m| m.dirty),
            "dirty cleared by measure"
        );

        // Collapsing a framed box shrinks it to title + bottom border rows.
        panel.push_boxed(Role::Assistant, "boxed body here".into(), "tool".into());
        assert_eq!(panel.content_height(content_w), 9, "5 + 4 boxed rows");
        let area = Rect {
            x: 0,
            y: 0,
            width: (content_w + 1) as u16,
            height: 30,
        };
        assert_eq!(
            panel.handle_click(1, 6, area),
            Click::Toggled,
            "click lands on the box body"
        );
        assert!(panel.messages[3].collapsed);
        assert_eq!(panel.content_height(content_w), 7, "collapsed box = 2 rows");
        assert!(!panel.messages.iter().any(|m| m.dirty));
    }

    #[test]
    fn toggle_conceal_switches_the_pipeline() {
        let mut panel = TurnPanel::default();
        assert!(panel.renderer.conceal_enabled(), "conceal defaults on");
        assert!(!panel.toggle_conceal());
        assert!(!panel.renderer.conceal_enabled());
        assert!(panel.toggle_conceal());
        assert!(panel.renderer.conceal_enabled());
    }

    #[test]
    fn conceal_off_renders_raw_markers() {
        // The off state must produce the original bytes, markers included.
        let mut panel = TurnPanel::default();
        panel
            .messages
            .push(msg("**bold**", vec![], vec![(0, 2), (6, 8)]));
        panel.renderer.set_conceal(false);
        let lines = panel.build_lines(40);
        assert_eq!(lines[0].spans[1].content.as_ref(), "**bold**");
    }

    /// The loop's side of a permission ask: the question becomes a dialog at the
    /// bottom of the panel that raised it, and leaves again when answered.
    ///
    /// This is the whole of the ask's *display* — the tool emits no dialog of its
    /// own, so there is exactly one place that decides where a question appears.
    /// Several panels, several dialogs: can two be open at once, and does each
    /// question land on the panel that raised it?
    ///
    /// Both, and the second half is the one that matters. `panel:ask` sets the
    /// dialog on **its own** panel by id, so two panels asking in turn each get
    /// their own dialog and neither can land on the other — which is what a
    /// "most recent boxed message" heuristic could not promise, and did not
    /// deliver once an answer had been rendered between the two questions.
    #[test]
    fn several_panels_are_open_at_once_and_each_dialog_stays_on_its_own() {
        let mut panel = TurnPanel::default();
        for (id, title) in [(1u64, "cat /etc/hostname"), (2, "cat /etc/hosts")] {
            panel.apply_op(PanelOp::Create {
                id,
                title: title.into(),
                boxed: true,
                conceal_box: false,
            });
            panel.apply_op(PanelOp::Append {
                id,
                text: "output\n".into(),
            });
        }
        assert_eq!(panel.messages.len(), 2, "both panels are open at once");

        let show = |p: &TurnPanel| {
            BorderedRenderer::lines(&p.messages, 56, true)
                .iter()
                .map(|l| {
                    l.spans
                        .iter()
                        .map(|s| s.content.as_ref())
                        .collect::<String>()
                })
                .collect::<Vec<String>>()
        };
        let dialog_for = |rows: &[String], path: &str| {
            rows.iter()
                .any(|l| l.contains("want to read") && l.contains(path))
        };

        // Panel 1 asks. The dialog is inside panel 1's box, and nowhere else.
        panel.apply_op(PanelOp::Overlay {
            id: 1,
            text: Some("The process want to read /etc/hostname".into()),
            remember: Some(ALWAYS_LABEL.into()),
        });
        let rows = show(&panel);
        assert!(
            dialog_for(&rows, "/etc/hostname"),
            "panel 1's own: {rows:?}"
        );
        assert!(
            !dialog_for(&rows, "/etc/hosts"),
            "and not on the other panel: {rows:?}"
        );
        // Both boxes are still on screen, and panel 2 is untouched.
        assert!(rows.iter().any(|l| l.contains("cat /etc/hostname")));
        assert!(rows.iter().any(|l| l.contains("cat /etc/hosts")));

        // Panel 1 is answered: its dialog goes, its box stays.
        panel.apply_op(PanelOp::Overlay {
            id: 1,
            text: None,
            remember: None,
        });
        // Panel 2 now asks, and the two never overlap.
        panel.apply_op(PanelOp::Overlay {
            id: 2,
            text: Some("The process want to read /etc/hosts".into()),
            remember: Some(ALWAYS_LABEL.into()),
        });
        let rows = show(&panel);
        assert!(
            !dialog_for(&rows, "/etc/hostname"),
            "the first dialog is gone: {rows:?}"
        );
        assert!(
            dialog_for(&rows, "/etc/hosts"),
            "the second is on panel 2: {rows:?}"
        );
        assert_eq!(
            rows.iter().filter(|l| l.contains("┌─ [y]es")).count(),
            1,
            "exactly one dialog on screen at a time: {rows:?}"
        );

        panel.apply_op(PanelOp::Overlay {
            id: 2,
            text: None,
            remember: None,
        });
        let rows = show(&panel);
        assert_eq!(
            rows.iter().filter(|l| l.contains("want to read")).count(),
            0,
            "and none left after both are answered: {rows:?}"
        );
        assert_eq!(panel.messages.len(), 2, "still two panels, neither grown");
    }

    #[test]
    fn a_permission_dialog_rides_the_bottom_of_the_tool_panel() {
        let mut panel = TurnPanel::default();

        // This is the path `panel:ask` takes, from Lua: the panel sets the
        // dialog on *itself* by id. Nothing searches the transcript for "the
        // panel this probably belongs to" — that search is what put a question
        // on whichever message happened to be boxed last, which is how a dialog
        // ended up on the previous answer instead of on the tool that asked.
        panel.apply_op(PanelOp::Create {
            id: 1,
            title: "cat /etc/hostname".into(),
            boxed: true,
            conceal_box: false,
        });
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "some output\n".into(),
        });
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "more output\n".into(),
        });
        panel.apply_op(PanelOp::Overlay {
            id: 1,
            text: Some("The process want to read /etc/hostname".into()),
            remember: Some(ALWAYS_LABEL.into()),
        });
        assert_eq!(
            panel.messages.len(),
            1,
            "a dialog is not a message: the transcript does not grow"
        );

        let content_w = 52;
        let render = |p: &TurnPanel| {
            BorderedRenderer::lines(&p.messages, content_w, true)
                .iter()
                .map(|l| {
                    l.spans
                        .iter()
                        .map(|s| s.content.as_ref())
                        .collect::<String>()
                })
                .collect::<Vec<String>>()
        };
        let shown = render(&panel);
        for (i, l) in shown.iter().enumerate() {
            assert_eq!(
                l.chars().count(),
                content_w,
                "row {i} is exactly the box width, or the border is broken: {l:?}"
            );
        }
        assert!(
            shown[0].starts_with("┌─ cat /etc/hostname"),
            "the panel keeps its own title: {:?}",
            shown[0]
        );
        // The dialog is a framed mini-panel: its top border carries the key
        // prompt, the question is the body under it.
        let dlg_top = shown
            .iter()
            .position(|l| l.contains("┌─ [y]es"))
            .expect("the dialog's key prompt is drawn");
        assert!(
            shown[dlg_top].contains("[a]lways"),
            "offered, because a path can be remembered: {:?}",
            shown[dlg_top]
        );
        let question = shown[dlg_top + 1].contains("The process want to read /etc/hostname");
        assert!(
            question,
            "and the question is its body: {:?}",
            shown[dlg_top + 1]
        );
        let dialog = dlg_top;
        // At the bottom: after the streamed output, before the box's own border.
        let last_body = shown.len() - 2;
        assert!(
            dialog
                > shown
                    .iter()
                    .position(|l| l.contains("more output"))
                    .unwrap(),
            "below the output: {shown:?}"
        );
        assert!(
            dialog < last_body,
            "and inside the box, above the closing border: {shown:?}"
        );

        // Asking again replaces the dialog rather than adding to it, so a run
        // that asks fifty times leaves one message and one dialog.
        panel.apply_op(PanelOp::Overlay {
            id: 1,
            text: Some("The process want to read /etc/hosts".into()),
            remember: Some(ALWAYS_LABEL.into()),
        });
        assert_eq!(panel.messages.len(), 1, "still one message");

        let shown = render(&panel);
        assert!(
            shown.iter().any(|l| l.contains("/etc/hosts")),
            "the new question replaces the old: {shown:?}"
        );
        assert_eq!(
            shown.iter().filter(|l| l.contains("┌─ [y]es")).count(),
            1,
            "exactly one dialog, showing the new question and not both: {shown:?}"
        );

        // Answered: the panel is the tool's alone again.
        panel.apply_op(PanelOp::Overlay {
            id: 1,
            text: None,
            remember: None,
        });
        let shown = render(&panel);
        assert!(
            !shown.iter().any(|l| l.contains("want to read")),
            "the dialog is gone: {shown:?}"
        );
        assert!(
            shown.iter().any(|l| l.contains("more output")),
            "output kept"
        );
        assert!(
            !shown.iter().any(|l| l.contains("want to read")),
            "and clearing again changes nothing"
        );
    }

    /// A question with nothing to remember must not offer `always`: the answer
    /// would be a promise the agent cannot keep.
    #[test]
    fn the_dialog_offers_always_only_when_there_is_something_to_remember() {
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Create {
            id: 1,
            title: "run".into(),
            boxed: true,
            conceal_box: false,
        });
        // A panel materializes on its first text, not on Create.
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "x".into(),
        });
        panel.apply_op(PanelOp::Overlay {
            id: 1,
            text: Some("The process want to reach example.com".into()),
            remember: None,
        });
        let flat: String = BorderedRenderer::lines(&panel.messages, 52, true)
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.as_ref()))
            .collect();
        assert!(flat.contains("[y]es") && flat.contains("[n]o"), "{flat}");
        assert!(!flat.contains("[a]lways"), "nothing to remember: {flat}");
    }

    /// A title is model- and tool-authored text — `bash` puts the command line
    /// there — so a long one must be cut, not allowed to overflow. An overflowed
    /// top border wraps to the next terminal row and the box stops being a box,
    /// which is exactly what this pins.
    #[test]
    fn a_title_too_long_for_the_box_is_cut_not_overflowed() {
        let m = Message {
            boxed: Some("echo hello && ls -la /very/long/path/to/somewhere".into()),
            ..msg("hi", vec![], vec![])
        };
        let lines = BorderedRenderer::lines(std::slice::from_ref(&m), 40, true);
        for (i, l) in lines.iter().enumerate() {
            let row: usize = l.spans.iter().map(|s| s.content.chars().count()).sum();
            assert_eq!(row, 40, "row {i} is exactly the box width, not wider");
        }
        let top = &lines[0].spans[0].content;
        assert!(top.starts_with("┌─ echo hello"), "{top}");
        assert!(
            top.contains('…'),
            "the cut is visible rather than silent: {top}"
        );
        assert!(top.ends_with('┐'), "{top}");
    }

    /// …at any width a box can be drawn at, which is 9 cells: the frame alone
    /// (`┌─ `, a space, the indicator, a space, `┐`) is 9, so below that there is
    /// no box to hold its width — a pre-existing floor, not something the title
    /// handling introduces, and narrow enough that no real terminal gets there.
    #[test]
    fn the_title_border_holds_its_width_at_every_drawable_size() {
        let long = "x".repeat(200);
        for w in 9..60usize {
            let m = Message {
                boxed: Some(long.clone()),
                ..msg("hi", vec![], vec![])
            };
            let lines = BorderedRenderer::lines(std::slice::from_ref(&m), w, true);
            for l in &lines {
                let row: usize = l.spans.iter().map(|s| s.content.chars().count()).sum();
                assert_eq!(row, w, "width {w}: no row may exceed the box");
            }
        }
    }

    /// A title that fits is passed through untouched — the cut is for the
    /// overflow case only, and must not cost the common one.
    #[test]
    fn a_title_that_fits_is_untouched() {
        assert_eq!(fit_title("ls -la", 10), "ls -la");
        assert_eq!(fit_title("exactly-10", 10), "exactly-10");
        assert_eq!(fit_title("elevenchars", 10), "elevencha…");
        // A title of exactly the room is not cut: nothing was lost.
        assert_eq!(fit_title("abc", 3), "abc");
        // Too small for anything but the marker.
        assert_eq!(fit_title("abc", 1), "…");
        assert_eq!(fit_title("abc", 0), "");
    }

    /// A title that fits gets the full border treatment, at exactly the box
    /// width — the baseline the cutting above has to preserve.
    #[test]
    fn boxed_message_renders_a_full_box() {
        let m = Message {
            boxed: Some("bash".into()),
            ..msg("ls -la", vec![], vec![])
        };
        let lines = BorderedRenderer::lines(std::slice::from_ref(&m), 40, true);
        assert_eq!(lines.len(), 3);
        // Top: `┌─` title indicator, filled with ─ to exactly content_w.
        assert_eq!(
            lines[0].spans[0].content.as_ref(),
            format!("┌─ bash [−] {}┐", "─".repeat(27))
        );
        assert_eq!(lines[0].spans[0].content.as_ref().chars().count(), 40);
        // Content row: `│ ` + body + padding + ` │`, filling content_w cells.
        assert_eq!(lines[1].spans[0].content.as_ref(), "│ ");
        assert_eq!(lines[1].spans[1].content.as_ref(), "ls -la");
        assert_eq!(
            lines[1].spans[2].content.as_ref(),
            format!("{} │", " ".repeat(30))
        );
        let total: usize = lines[1]
            .spans
            .iter()
            .map(|s| s.content.chars().count())
            .sum();
        assert_eq!(total, 40, "content row fills the box width");
        // Bottom border.
        assert_eq!(
            lines[2].spans[0].content.as_ref(),
            format!("└{}┘", "─".repeat(38))
        );
    }

    #[test]
    fn panel_overlay_renders_inside_the_box_and_counts_rows() {
        // A pending permission dialog rides the PanelOp::Overlay op — which is
        // how a *tool* draws one, and how the loop's own rendering reaches the
        // same code (see `a_permission_dialog_rides_the_bottom_of_the_tool_panel`,
        // which is the path the TUI actually takes). It renders as a framed
        // mini-panel at the bottom *inside* the box (never outside), pins the
        // viewport so it is visible, expands a collapsed box, and clearing it
        // restores the plain boxed rows.
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Create {
            id: 1,
            title: "bash result".into(),
            boxed: true,
            conceal_box: false,
        });
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "one\ntwo".into(),
        });
        let desc = "openat (pid 7) requests write: O_WRONLY|O_CREAT";
        panel.apply_op(PanelOp::Overlay {
            id: 1,
            text: Some(desc.into()),
            remember: Some(ALWAYS_LABEL.into()),
        });
        assert_eq!(panel.messages.len(), 1);
        assert!(
            panel.follow,
            "setting an overlay pins the view to the bottom"
        );
        assert!(
            panel.messages[0].overlay.is_some(),
            "the message carries the ask"
        );

        let content_w = 40;
        let lines = BorderedRenderer::lines(&panel.messages, content_w, true);
        assert_eq!(
            lines.len(),
            message_rows(&panel.messages[0], content_w, true),
            "overlay rows count must agree with the renderer"
        );
        let render_line =
            |l: &Line<'static>| -> String { l.spans.iter().map(|s| s.content.as_ref()).collect() };
        let joined: Vec<String> = lines.iter().map(render_line).collect();
        assert!(
            joined
                .iter()
                .any(|l| l.contains("[y]es") && l.contains("[a]lways")),
            "the key prompt is the dialog title, and offers `always` because the \
             question had something to remember: {joined:?}"
        );
        assert!(
            joined.iter().any(|l| l.contains("requests write")),
            "the ask description renders inside the box: {joined:?}"
        );
        // The overlay sits between the body and the outer bottom border.
        let body = joined.iter().position(|l| l.contains("two"));
        let ov = joined.iter().position(|l| l.contains("[y]es"));
        let bot = joined
            .iter()
            .position(|l| l.starts_with('└') && !l.contains('│'));
        assert!(
            body.is_some() && ov.is_some() && bot.is_some(),
            "{joined:?}"
        );
        assert!(body.unwrap() < ov.unwrap() && ov.unwrap() < bot.unwrap());

        // A collapsed box is expanded by the pending overlay.
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "\nmore".into(),
        });
        panel.messages[0].collapsed = true;
        panel.apply_op(PanelOp::Overlay {
            id: 1,
            text: Some(desc.into()),
            remember: Some(ALWAYS_LABEL.into()),
        });
        assert!(
            !panel.messages[0].collapsed,
            "an ask reopens a collapsed box"
        );
        assert_eq!(
            BorderedRenderer::lines(&panel.messages, content_w, true).len(),
            message_rows(&panel.messages[0], content_w, true)
        );

        // Clearing the overlay returns the box to its plain rows.
        panel.apply_op(PanelOp::Overlay {
            id: 1,
            text: None,
            remember: None,
        });
        let m = &panel.messages[0];
        assert!(m.overlay.is_none());
        let inner = content_w.saturating_sub(4);
        let body_rows = wrap_lines(&m.text, inner).len().max(1);
        assert_eq!(message_rows(m, content_w, true), body_rows + 2);
        assert_eq!(
            BorderedRenderer::lines(&panel.messages, content_w, true).len(),
            body_rows + 2,
            "after clearing, the overlay is gone from the render too"
        );
    }

    #[test]
    fn boxed_message_renders_raw_markers_not_concealed() {
        // The box guarantees the non-conceal base: markers stay visible even
        // when conceal is on and the message carries conceal ranges.
        let m = Message {
            boxed: Some("bash".into()),
            ..msg("**bold**", vec![], vec![(0, 2), (6, 8)])
        };
        let lines = BorderedRenderer::lines(std::slice::from_ref(&m), 40, true);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1].spans[1].content.as_ref(), "**bold**");
    }

    #[test]
    fn collapsed_box_renders_just_title_and_keeps_height_parity() {
        let m = Message {
            boxed: Some("bash".into()),
            ..msg("ls -la", vec![], vec![])
        };
        let expanded = BorderedRenderer::lines(std::slice::from_ref(&m), 40, true);
        assert_eq!(
            message_rows(&m, 40, true),
            expanded.len(),
            "expanded parity"
        );

        let m = Message {
            boxed: Some("bash".into()),
            collapsed: true,
            ..msg("ls -la", vec![], vec![])
        };
        let collapsed = BorderedRenderer::lines(std::slice::from_ref(&m), 40, true);
        assert_eq!(collapsed.len(), 2, "collapsed box is just two border rows");
        assert_eq!(
            collapsed[0].spans[0].content.as_ref(),
            format!("┌─ bash [+] {}┐", "─".repeat(27))
        );
        assert_eq!(
            collapsed[1].spans[0].content.as_ref(),
            format!("└{}┘", "─".repeat(38))
        );
        assert_eq!(message_rows(&m, 40, true), 2);
    }

    #[test]
    fn click_toggles_a_boxed_message() {
        let mut panel = TurnPanel::default();
        panel.push_boxed(Role::Assistant, "ls -la".into(), "bash".into());
        panel.push(Role::User, "ok".into());
        let area = Rect {
            x: 0,
            y: 0,
            width: 42,
            height: 10,
        };
        // Paragraph rows: 0 top, 1 content, 2 bottom; user tag row 3. Screen
        // rows shift by area.y (the chat log has no block border).
        assert_eq!(
            panel.handle_click(5, 1, area),
            Click::Toggled,
            "content row of the box"
        );
        assert!(panel.messages[0].collapsed);
        assert_eq!(
            panel.handle_click(5, 1, area),
            Click::Toggled,
            "click again to expand"
        );
        assert!(!panel.messages[0].collapsed);
        assert_eq!(
            panel.handle_click(5, 4, area),
            Click::Nothing,
            "plain message is not a box"
        );
        assert_eq!(
            panel.handle_click(5, 2, area),
            Click::Toggled,
            "bottom border still hits the box"
        );
        assert!(panel.messages[0].collapsed);
    }

    #[test]
    fn click_outside_the_body_is_ignored() {
        let mut panel = TurnPanel::default();
        panel.push_boxed(Role::Assistant, "ls -la".into(), "bash".into());
        let area = Rect {
            x: 0,
            y: 1,
            width: 42,
            height: 10,
        };
        assert_eq!(
            panel.handle_click(41, 1, area),
            Click::Nothing,
            "scrollbar lane (right edge)"
        );
        assert_eq!(
            panel.handle_click(42, 1, area),
            Click::Nothing,
            "past the right edge"
        );
        assert_eq!(
            panel.handle_click(5, 0, area),
            Click::Nothing,
            "above the body (row < area.y)"
        );
        assert_eq!(
            panel.handle_click(5, 1, area),
            Click::Toggled,
            "body rows are clickable"
        );
        assert!(panel.messages[0].collapsed);
    }

    #[test]
    fn boxed_content_wraps_inside_the_box() {
        // Long text wraps at content_w - 4; every content row still fills the
        // full box width with padding, so the right border stays aligned.
        let text = "a very long line that must wrap inside the tool box";
        let m = Message {
            boxed: Some("read".into()),
            ..msg(text, vec![], vec![])
        };
        let lines = BorderedRenderer::lines(std::slice::from_ref(&m), 20, true);
        let wrapped = wrap_lines(text, 16); // content_w - 4
        assert_eq!(lines.len(), wrapped.len() + 2, "interior rows + 2 borders");
        for row in &lines[1..lines.len() - 1] {
            let total: usize = row.spans.iter().map(|s| s.content.chars().count()).sum();
            assert_eq!(total, 20, "every content row fills the box width");
        }
        assert_eq!(message_rows(&m, 20, true), lines.len());
    }

    #[test]
    fn mixed_boxed_and_concealed_transcript() {
        // A normal concealed message next to a boxed one: outside the box the
        // toggle applies, inside the box markers stay raw.
        let concealed = Message {
            role: Role::User,
            boxed: None,
            ..msg(
                "# Plan",
                vec![Segment {
                    start: 0,
                    end: 6,
                    style: Style::default(),
                }],
                vec![(0, 2)],
            )
        };
        let boxed = Message {
            role: Role::Assistant,
            boxed: Some("bash".into()),
            ..msg("echo **hi**", vec![], vec![(5, 7), (10, 12)])
        };
        let mut panel = TurnPanel::default();
        panel.messages.extend([Message { ..concealed }, boxed]);
        let lines = BorderedRenderer::lines(&panel.messages, 40, true);
        // Tag rows + body, then the box's 3 rows.
        let joined: Vec<String> = lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        assert!(
            joined[0].contains("Plan"),
            "concealed outside the box: {joined:?}"
        );
        assert!(
            joined.iter().any(|l| l.contains("echo **hi**")),
            "raw inside the box: {joined:?}"
        );
        // Height parity across the mixed transcript.
        let mut hs = 0;
        for m in &panel.messages {
            hs += message_rows(m, 40, true);
        }
        assert_eq!(hs, lines.len());
    }

    #[test]
    fn push_boxed_records_state() {
        let mut panel = TurnPanel::default();
        panel.push_boxed(Role::Assistant, "ls".into(), "bash".into());
        assert_eq!(panel.messages.len(), 1);
        assert_eq!(panel.messages[0].boxed.as_deref(), Some("bash"));
        assert!(!panel.messages[0].collapsed);
        assert_eq!(panel.messages[0].role, Role::Assistant);
        assert_eq!(panel.messages[0].text, "ls");
    }

    #[test]
    fn stream_append_creates_then_appends_one_message() {
        let mut panel = TurnPanel::default();
        panel.stream_append("Hel");
        panel.stream_append("lo");
        panel.stream_append(" world");
        assert_eq!(panel.messages.len(), 1, "streaming fills one message");
        assert_eq!(panel.messages[0].role, Role::Assistant);
        assert_eq!(panel.messages[0].text, "Hello world");
        assert!(panel.messages[0].boxed.is_none());
    }

    #[test]
    fn stream_append_starts_fresh_after_user_and_boxed_messages() {
        let mut panel = TurnPanel::default();
        panel.push(Role::User, "hi".into());
        panel.stream_append("answer");
        assert_eq!(panel.messages.len(), 2, "a user message starts a new one");
        assert_eq!(panel.messages[1].role, Role::Assistant);
        assert_eq!(panel.messages[1].text, "answer");

        // A tool-call box after the answer: the next fragment must not be
        // appended into the box — it starts another plain assistant message.
        panel.push_boxed(Role::Assistant, "args".into(), "echo".into());
        panel.stream_append("more");
        assert_eq!(panel.messages.len(), 4);
        assert_eq!(panel.messages[2].text, "args", "boxed body untouched");
        assert_eq!(panel.messages[2].boxed.as_deref(), Some("echo"));
        assert_eq!(panel.messages[3].text, "more");
        assert_eq!(panel.messages[3].role, Role::Assistant);
    }

    #[test]
    fn stream_append_boxed_flows_into_one_block_and_breaks_on_plain() {
        let mut panel = TurnPanel::default();
        panel.stream_append_boxed("Hel", "response".into());
        panel.stream_append_boxed("lo", "response".into());
        assert_eq!(panel.messages.len(), 1, "same box keeps accumulating");
        assert_eq!(panel.messages[0].text, "Hello");
        assert_eq!(panel.messages[0].boxed.as_deref(), Some("response"));
        assert!(
            panel.messages[0].conceal_box,
            "streamed blocks follow the toggle"
        );

        // A *different* block title starts a new box (e.g. reasoning flushed
        // while a prior response box is still last).
        panel.stream_append_boxed("think", "reasoning".into());
        assert_eq!(panel.messages.len(), 2);
        assert_eq!(panel.messages[1].text, "think");
        assert_eq!(panel.messages[1].boxed.as_deref(), Some("reasoning"));
        assert!(panel.messages[1].conceal_box);

        // …and after a plain message the streaming seam restarts a fresh box
        // rather than leaking into the plain row.
        panel.push(Role::Assistant, "summary".into());
        panel.stream_append_boxed("next", "response".into());
        assert_eq!(panel.messages.len(), 4);
        assert_eq!(panel.messages[2].text, "summary");
        assert_eq!(panel.messages[2].boxed, None);
        assert_eq!(panel.messages[3].text, "next");
        assert_eq!(panel.messages[3].boxed.as_deref(), Some("response"));
        assert!(panel.messages[3].conceal_box);
    }

    #[test]
    fn conceal_boxes_hide_markers_with_the_toggle_like_plain_messages() {
        // A reasoning/response block opts its *content* into the conceal path
        // AND renders borderless — exactly like a plain message: markers
        // visible with the toggle off, hidden with it on, and the row-height
        // tracker agrees (no frame rows).
        let cover = vec![Segment {
            start: 0,
            end: 128,
            style: Style::default(),
        }];
        let mut fb = Message {
            boxed: Some("response".into()),
            conceal_box: true,
            ..msg("**bold** text", cover, vec![(0, 2), (6, 8)])
        };
        let off = BorderedRenderer::lines(std::slice::from_ref(&fb), 40, false);
        let on = BorderedRenderer::lines(std::slice::from_ref(&fb), 40, true);
        assert_eq!(off.len(), 1, "borderless: no frame rows");
        assert_eq!(off[0].spans[1].content.as_ref(), "**bold** text");
        assert_eq!(on.len(), 1, "toggle on keeps one (concealed) row");
        assert_eq!(on[0].spans[1].content.as_ref(), "bold text");
        assert_eq!(message_rows(&fb, 40, true), on.len(), "conceal-on parity");
        assert_eq!(
            message_rows(&fb, 40, false),
            off.len(),
            "conceal-off parity"
        );

        // Concealing markers can shrink the wrapped height; the tracker must
        // agree with the renderer again (the raw 14-char bold string wraps
        // into more rows than the plain "abcdefghij" display text).
        fb.text = "**abcdefghij**".into();
        let off = BorderedRenderer::lines(std::slice::from_ref(&fb), 14, false);
        let on = BorderedRenderer::lines(std::slice::from_ref(&fb), 14, true);
        assert!(
            on.len() < off.len(),
            "the concealed display text wraps less"
        );
        assert_eq!(message_rows(&fb, 14, true), on.len());
        assert_eq!(message_rows(&fb, 14, false), off.len());

        // A plain tool box (no opt-in) stays framed and keeps raw markers
        // even with conceal on.
        let tb = Message {
            boxed: Some("bash".into()),
            ..msg("**bold**", vec![], vec![(0, 2), (6, 8)])
        };
        let raw = BorderedRenderer::lines(std::slice::from_ref(&tb), 40, true);
        assert_eq!(raw[1].spans[1].content.as_ref(), "**bold**");
        assert_eq!(message_rows(&tb, 40, true), raw.len(), "box parity");
    }

    #[test]
    fn reasoning_and_response_blocks_are_borderless_and_only_reasoning_is_dimmed() {
        // The agent loop's two streamed blocks shed their frames: reasoning
        // and response both render as plain assistant messages, reasoning
        // dimmed; only framed tool boxes keep `┌─…┐` and stay
        // click-collapsible.
        let mk = |title: &str, text: &str| Message {
            boxed: Some(title.into()),
            conceal_box: true,
            ..msg(text, vec![], vec![])
        };
        let mut all = vec![
            mk("reasoning", "**think** harder"),
            mk("response", "the **answer**"),
        ];
        all.push(Message {
            boxed: Some("bash".into()),
            ..msg("ls -la", vec![], vec![])
        });
        let lines = BorderedRenderer::lines(&all, 50, true);
        assert_eq!(
            lines.len(),
            5,
            "1 reasoning + 1 response row, then the box's 3 framed rows"
        );
        let joined: Vec<String> = lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        assert!(
            !joined[0].contains('┌'),
            "reasoning has no frame: {joined:?}"
        );
        assert!(
            !joined[1].contains('┌'),
            "response has no frame: {joined:?}"
        );
        assert!(
            joined[2].contains('┌'),
            "the tool box keeps its frame: {joined:?}"
        );

        let all_dim = |line: &Line<'static>| {
            line.spans
                .iter()
                .all(|s| s.style.add_modifier.contains(Modifier::DIM))
        };
        assert!(all_dim(&lines[0]), "reasoning (tag + body) is all dimmed");
        assert!(
            !all_dim(&lines[1]),
            "response keeps the normal assistant style"
        );
        assert!(!all_dim(&lines[2]), "the framed box stays undimmed");

        // Only framed boxes toggle on click; borderless blocks do not.
        let mut panel = TurnPanel::default();
        panel.stream_append_boxed("think", "reasoning".into());
        panel.push_boxed(Role::Assistant, "ls -la".into(), "bash".into());
        let area = Rect {
            x: 0,
            y: 0,
            width: 42,
            height: 10,
        };
        assert_eq!(
            panel.handle_click(5, 0, area),
            Click::Nothing,
            "a reasoning row is not a collapsible box"
        );
        assert_eq!(
            panel.handle_click(5, 1, area),
            Click::Toggled,
            "the framed tool box still toggles"
        );
        assert!(panel.messages[1].collapsed);
    }

    #[test]
    fn panel_ops_materialize_and_append_by_id() {
        // Lua panels are keyed by op id, not by "still the last message", so
        // interleaved panels keep flowing into their own messages.
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Create {
            id: 1,
            title: "first".into(),
            boxed: true,
            conceal_box: true,
        });
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "a".into(),
        });
        panel.apply_op(PanelOp::Create {
            id: 2,
            title: "second".into(),
            boxed: false,
            conceal_box: false,
        });
        panel.apply_op(PanelOp::Append {
            id: 2,
            text: "b".into(),
        });
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "c".into(),
        });
        assert_eq!(panel.messages.len(), 2);
        assert_eq!(panel.messages[0].boxed.as_deref(), Some("first"));
        assert_eq!(panel.messages[0].text, "ac");
        assert!(panel.messages[0].conceal_box);
        assert!(panel.messages[1].boxed.is_none());
        assert_eq!(panel.messages[1].text, "b");
        assert!(!panel.messages[1].conceal_box);
        assert_eq!(panel.messages[0].role, Role::Assistant);
    }

    /// Two regions over the same bytes come back **disjoint, last one winning**.
    ///
    /// They used to be kept as written — two overlapping segments, both drawn —
    /// and `clip_segments` prints the slice each one covers, so the overlapping
    /// text was rendered twice and the row came out twice as wide as the layout
    /// budgeted for it. That is not a corner case: it is what every
    /// `apply_patch` produces, where the pane's `lang` colours a line and
    /// `p:highlight` tints the same line.
    ///
    /// "Last wins" is the layering rule that makes both of those legible: a
    /// caller may dim a whole range and then bold part of it, and the second
    /// call is the more specific intention. Sorted-by-start would not express
    /// that, since the broader region usually starts first.
    #[test]
    fn overlapping_highlight_regions_become_disjoint_with_the_last_winning() {
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Create {
            id: 1,
            title: "log".into(),
            boxed: false,
            conceal_box: false,
        });
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "hello".into(),
        });
        panel.apply_op(PanelOp::Highlight {
            id: 1,
            start: 0,
            end: 5,
            style: "bold".into(),
        });
        panel.apply_op(PanelOp::Highlight {
            id: 1,
            start: 2,
            end: 99,
            style: "cyan".into(),
        });
        // No markdown highlighter in this panel: regions are the whole `segs`.
        let segs = &panel.messages[0].segs;
        assert_eq!(
            segs,
            &[
                // The part the *first* region still owns, since the second
                // (later, and narrower in practice) took 2..5 from it.
                Segment {
                    start: 0,
                    end: 2,
                    style: Style::default().add_modifier(Modifier::BOLD)
                },
                Segment {
                    start: 2,
                    end: 5,
                    style: Style::default().fg(Color::Cyan)
                },
            ],
            "disjoint, tiled over 0..5 exactly once, and the later region won \
             the bytes they shared"
        );
        // Capture-name styles still work as a fallback for unknown specs.
        panel.apply_op(PanelOp::Highlight {
            id: 1,
            start: 3,
            end: 4,
            style: "number".into(),
        });
        let segs = &panel.messages[0].segs;
        assert_eq!(segs[0].start, 0);
        assert!(
            segs.iter().any(|s| s.style.fg == Some(Color::LightYellow)),
            "{segs:?}"
        );
    }

    #[test]
    fn panel_highlight_clamps_and_normalizes_ranges() {
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Create {
            id: 1,
            title: "log".into(),
            boxed: false,
            conceal_box: false,
        });
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "abcd".into(),
        });
        panel.apply_op(PanelOp::Highlight {
            id: 1,
            start: 5,
            end: 2,
            style: "bold".into(),
        });
        assert_eq!(
            panel.messages[0].segs,
            &[Segment {
                start: 2,
                end: 4,
                style: Style::default().add_modifier(Modifier::BOLD)
            }]
        );
    }

    #[test]
    fn panel_set_replaces_text_keeping_regions() {
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Create {
            id: 1,
            title: "status".into(),
            boxed: false,
            conceal_box: false,
        });
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "hello".into(),
        });
        panel.apply_op(PanelOp::Highlight {
            id: 1,
            start: 0,
            end: 5,
            style: "bold".into(),
        });
        panel.apply_op(PanelOp::Set {
            id: 1,
            text: "world".into(),
        });
        let msg = &panel.messages[0];
        assert_eq!(msg.text, "world");
        assert_eq!(
            msg.segs.len(),
            1,
            "regions survive a set (clamped to the new text)"
        );
        assert_eq!(msg.segs[0].start, 0);
        assert_eq!(msg.segs[0].end, 5);
    }

    #[test]
    fn panel_clear_regions_drops_user_segments() {
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Create {
            id: 1,
            title: "log".into(),
            boxed: false,
            conceal_box: false,
        });
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "hello".into(),
        });
        panel.apply_op(PanelOp::Highlight {
            id: 1,
            start: 0,
            end: 5,
            style: "bold".into(),
        });
        assert_eq!(panel.messages[0].segs.len(), 1);
        panel.apply_op(PanelOp::ClearRegions { id: 1 });
        assert!(panel.messages[0].segs.is_empty());
    }

    #[test]
    fn panel_unknown_and_contentless_ops_are_ignored() {
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Append {
            id: 99,
            text: "nope".into(),
        });
        panel.apply_op(PanelOp::Set {
            id: 99,
            text: "nope".into(),
        });
        panel.apply_op(PanelOp::Highlight {
            id: 99,
            start: 0,
            end: 2,
            style: "bold".into(),
        });
        assert!(
            panel.messages.is_empty(),
            "unknown panels never materialize"
        );
        // A created-but-contentless panel cannot be highlighted either.
        panel.apply_op(PanelOp::Create {
            id: 7,
            title: "empty".into(),
            boxed: false,
            conceal_box: false,
        });
        panel.apply_op(PanelOp::Highlight {
            id: 7,
            start: 0,
            end: 2,
            style: "bold".into(),
        });
        assert!(
            panel.messages.is_empty(),
            "highlight before content stays a no-op"
        );
    }

    #[test]
    fn split_panel_is_side_by_side_wide_and_stacked_narrow() {
        let m = split_msg();
        // Wide (content_w 100 -> inner 96 >= 2 cols of 20 + rule): panes in
        // equal columns joined by a `│`, body height = tallest column.
        let wide = BorderedRenderer::lines(std::slice::from_ref(&m), 100, true);
        assert_eq!(
            wide.len(),
            message_rows(&m, 100, true),
            "heights agree with message_rows"
        );
        assert_eq!(
            wide.len(),
            3 + 2,
            "caption rows + 2 body rows + box borders"
        );
        let caption: String = wide[1].spans.iter().map(|s| s.content.as_ref()).collect();
        let cols: Vec<&str> = caption.split('│').map(|p| p.trim()).collect();
        assert_eq!(
            cols,
            ["", "before", "after", ""],
            "captions split across the rule"
        );
        let body: String = wide[2].spans.iter().map(|s| s.content.as_ref()).collect();
        let cols: Vec<&str> = body.split('│').map(|p| p.trim()).collect();
        assert_eq!(cols, ["", "aaa", "cc", ""], "pane bodies read side by side");

        // Narrow (content_w 30 -> inner 26 < 41): panes stack full-width with
        // a dim rule between them; the box borders frame the whole block.
        let narrow = BorderedRenderer::lines(std::slice::from_ref(&m), 30, true);
        assert_eq!(
            narrow.len(),
            message_rows(&m, 30, true),
            "heights agree with message_rows"
        );
        let flat: String = narrow
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.as_ref()))
            .collect();
        for needle in ["before", "aaa", "bb", "after", "cc"] {
            assert!(
                flat.contains(needle),
                "stacked panes keep every row: {needle:?}"
            );
        }
        // Exactly one rule row between the two stacked panes: the framed
        // `│ ──── │` trims to a pure ─ run; borders and text rows don't.
        let rules = narrow
            .iter()
            .filter(|l| {
                let s: String = l.spans.iter().map(|sp| sp.content.as_ref()).collect();
                let inner = s.trim_matches(|c: char| c == '│' || c == ' ');
                !inner.is_empty() && inner.chars().all(|c| c == '─')
            })
            .count();
        assert_eq!(rules, 1, "exactly one rule row between the stacked panes");
    }

    #[test]
    fn split_panel_partitions_columns_by_bounds() {
        // Three panes at a very wide content area: their captions and bodies
        // each land in their own column slice, never bleeding across.
        let mut m = split_msg();
        let mut panes = m.panes.take().expect("split panes");
        panes.push(PaneContent {
            caption: "third".into(),
            text: "dd".into(),
            lang: None,
            segs: Vec::new(),
            user_segs: Vec::new(),
        });
        m.panes = Some(panes);
        let wide = BorderedRenderer::lines(std::slice::from_ref(&m), 160, true);
        let text: String = wide[1].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.find("before").unwrap() < text.find("third").unwrap(),
            "third column after the second: {text:?}"
        );
        let cells: usize = wide[1]
            .spans
            .iter()
            .map(|s| s.content.chars().count())
            .sum();
        assert_eq!(cells, 160, "body rows fill the full box width");
    }

    #[test]
    fn split_panel_collapses_like_any_boxed_message() {
        let mut m = split_msg();
        m.collapsed = true;
        assert_eq!(
            message_rows(&m, 80, true),
            2,
            "collapsed: title + bottom only"
        );
        let lines = BorderedRenderer::lines(std::slice::from_ref(&m), 80, true);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].spans[0].content.as_ref().contains("[+]"));
    }

    #[test]
    fn split_panel_overlay_renders_inside_the_boxed_split() {
        let mut m = split_msg();
        m.overlay = Some(Overlay {
            text: "applying…".into(),
            remember: None,
        });
        let lines = BorderedRenderer::lines(std::slice::from_ref(&m), 80, true);
        assert_eq!(
            lines.len(),
            message_rows(&m, 80, true),
            "heights agree with message_rows"
        );
        let flat: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.as_ref()))
            .collect();
        assert!(
            flat.contains("applying"),
            "the ask/status seam draws inside the split box"
        );
        assert!(
            flat.contains("[y]es"),
            "the dialog's key prompt is present, and with no `always` offered — \
             nothing about a split panel's status note is worth remembering"
        );
    }

    /// The dialog's answers are clickable, and clickable exactly where they are
    /// drawn.
    ///
    /// Checked as a round trip: the columns are read out of the *rendered* row
    /// and handed straight to `handle_click`. The hit test and the renderer
    /// share no arithmetic, only the prompt string, so testing the arithmetic
    /// against itself would prove nothing — a one-cell slip puts the target
    /// beside the label rather than on it, and only a test that reads the real
    /// output can see that.
    #[test]
    fn the_dialogs_answers_are_clickable_wherever_they_are_drawn() {
        const W: usize = 64;
        let mut panel = TurnPanel::default();
        for op in [
            PanelOp::Create {
                id: 1,
                title: "cat /etc/hostname".into(),
                boxed: true,
                conceal_box: false,
            },
            PanelOp::Append {
                id: 1,
                text: "the process wants\n".into(),
            },
        ] {
            panel.apply_op(op);
        }
        panel.apply_op(PanelOp::Overlay {
            id: 1,
            text: Some("The process want to read /etc/hostname".into()),
            remember: Some(ALWAYS_LABEL.into()),
        });

        // The same render path the frame uses, so the columns below are the
        // columns on screen.
        let rows: Vec<String> = BorderedRenderer::lines(&panel.messages, W, true)
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        // `content_w` is the area's width less the scrollbar lane, so a panel
        // built at `W` is clicked through an area one wider.
        let area = Rect {
            x: 0,
            y: 0,
            width: (W + 1) as u16,
            height: 30,
        };
        let (row, title) = rows
            .iter()
            .enumerate()
            .find(|(_, l)| l.contains("[y]es"))
            .expect("the dialog is on screen");
        // Column of a substring in a given row, in cells — `str::find` gives
        // bytes and `·` is two of them, which is the whole reason this helper
        // exists.
        let col_of =
            |row: &str, needle: &str| row[..row.find(needle).expect("drawn")].chars().count();

        for (label, key) in [("[y]es", 'y'), ("[n]o", 'n'), ("[a]lways", 'a')] {
            let col = col_of(title, label);
            // Anywhere along the label, not just its first cell: the whole word
            // is the target, because that is the thing a pointer is aimed at.
            for probe in [col, col + label.chars().count() - 1] {
                assert_eq!(
                    panel.handle_click(probe, row, area),
                    Click::Answer(key),
                    "a click on {label} answers {key}"
                );
            }
        }

        // The gap between two answers is not an answer, and neither is the
        // border either side of them. Both are on the dialog's own row, and
        // both must stay inert rather than falling through to the box toggle.
        let gap = col_of(title, " · ");
        assert_eq!(
            panel.handle_click(gap, row, area),
            Click::Nothing,
            "the separator is not a verdict"
        );
        assert_eq!(
            panel.handle_click(title.chars().count() - 2, row, area),
            Click::Nothing,
            "nor is the border past the last answer"
        );

        // A row below the prompt is the box's again, and toggles it.
        let before = panel.messages[0].collapsed;
        let (body, body_row) = rows
            .iter()
            .enumerate()
            .find(|(_, l)| l.contains("the process wants"))
            .expect("the body is drawn");
        assert_eq!(
            panel.handle_click(col_of(body_row, "the process wants"), body, area),
            Click::Toggled
        );
        assert_ne!(panel.messages[0].collapsed, before, "and it did toggle");
    }

    /// Without "always" on offer the dialog draws two answers, and a third
    /// cannot be clicked into existence: the target list comes from the prompt
    /// that was drawn, not from a fixed set of keys.
    #[test]
    fn a_question_without_always_offers_exactly_two_answers() {
        const W: usize = 64;
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Create {
            id: 1,
            title: "ls".into(),
            boxed: true,
            conceal_box: false,
        });
        panel.apply_op(PanelOp::Overlay {
            id: 1,
            text: Some("The process want to list /home".into()),
            remember: None,
        });
        // The same render path the frame uses, so the columns below are the
        // columns on screen.
        let rows: Vec<String> = BorderedRenderer::lines(&panel.messages, W, true)
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        let (row, title) = rows
            .iter()
            .enumerate()
            .find(|(_, l)| l.contains("[n]o"))
            .expect("the dialog is on screen");
        assert!(!title.contains("[a]lways"), "and no third answer: {title}");
        let area = Rect {
            x: 0,
            y: 0,
            width: (W + 1) as u16,
            height: 30,
        };
        let col_of = |needle: &str| title[..title.find(needle).expect("drawn")].chars().count();
        assert_eq!(
            panel.handle_click(col_of("[n]o"), row, area),
            Click::Answer('n')
        );
        // Just past the last answer, where `a` would be if it were offered.
        assert_eq!(
            panel.handle_click(title.chars().count() - 2, row, area),
            Click::Nothing,
            "nothing there to click"
        );
    }

    /// The answers are drawn as if they can be clicked, because they can.
    ///
    /// An underline on the bracketed letter and its word, and on nothing else:
    /// the `─` either side and the `·` between are not targets, and marking them
    /// would be a promise the click test does not keep.
    #[test]
    fn only_the_answers_are_underlined_in_the_title() {
        let mut panel = TurnPanel::default();
        for op in [
            PanelOp::Create {
                id: 1,
                title: "cat /etc/hostname".into(),
                boxed: true,
                conceal_box: false,
            },
            PanelOp::Append {
                id: 1,
                text: "output\n".into(),
            },
            PanelOp::Overlay {
                id: 1,
                text: Some("The process want to read /etc/hostname".into()),
                remember: Some(ALWAYS_LABEL.into()),
            },
        ] {
            panel.apply_op(op);
        }
        let lines = BorderedRenderer::lines(&panel.messages, 64, true);
        let title = lines
            .iter()
            .find(|l| l.spans.iter().any(|s| s.content.as_ref().contains("[y]es")))
            .expect("the dialog is on screen");
        let underlined: String = title
            .spans
            .iter()
            .filter(|s| s.style.add_modifier.contains(Modifier::UNDERLINED))
            .map(|s| s.content.as_ref())
            .collect();
        assert_eq!(
            underlined, "[y]es[n]o[a]lways",
            "exactly the three answers, and nothing of the border"
        );
    }

    /// The key prompt's labels, from the string alone — the one place the hit
    /// test, the underline and the drawn row all get their shape.
    #[test]
    fn prompt_labels_are_the_bracketed_key_and_the_word_after_it() {
        let labels = prompt_labels("[y]es \u{00B7} [n]o \u{00B7} [a]lways");
        // `[y]es` is five cells, not four: the brackets are part of the label.
        assert_eq!(
            labels,
            vec![(0, 5, 'y'), (8, 12, 'n'), (15, 23, 'a')],
            "each label runs from its bracket to just before the next separator"
        );
        // Two labels, no third: the last one runs to the end of the string.
        assert_eq!(
            prompt_labels("[y]es \u{00B7} [n]o"),
            vec![(0, 5, 'y'), (8, 12, 'n')]
        );
        // Nothing bracketed, nothing clickable.
        assert!(prompt_labels("yes \u{00B7} no").is_empty());
        // Every column of a label hits it, and the columns around it do not.
        for col in 0..5 {
            assert_eq!(prompt_hit("[y]es", col), Some('y'));
        }
        assert_eq!(prompt_hit("[y]es", 5), None, "past the end of the label");
    }

    /// The third answer is named by the ask, and the name reaches the screen and
    /// the click target. This is the whole reason `always` is a string: a grant
    /// that lasts one run must not be drawn as `[a]lways`, and a label that is
    /// merely longer would shift where the clickable region sits — so both halves
    /// are checked, the glyphs and the target, and against each other.
    ///
    /// A narrower answer is not a smaller one: `lways this run` still answers
    /// `a`, and clicking it is still `Click::Answer('a')`.
    #[test]
    fn a_narrower_grant_is_drawn_and_clicked_under_its_own_name() {
        const W: usize = 64;
        let mut panel = TurnPanel::default();
        panel.apply_op(PanelOp::Create {
            id: 1,
            title: "cat /etc/hostname".into(),
            boxed: true,
            conceal_box: false,
        });
        panel.apply_op(PanelOp::Append {
            id: 1,
            text: "output\n".into(),
        });
        panel.apply_op(PanelOp::Overlay {
            id: 1,
            text: Some("the process wants an io_uring ring".into()),
            remember: Some("lways this run".into()),
        });

        let area = Rect {
            x: 0,
            y: 0,
            width: (W + 1) as u16,
            height: 30,
        };
        // The same render path the frame uses, so the columns below are the
        // columns on screen.
        let rows: Vec<String> = BorderedRenderer::lines(&panel.messages, W, true)
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        let (row, title) = rows
            .iter()
            .enumerate()
            .find(|(_, l)| l.contains("[n]o"))
            .expect("the dialog is on screen");

        assert!(
            title.contains("[a]lways this run"),
            "the third answer says what it remembers, not `always`: {title}"
        );
        assert!(
            !title.contains("[a]lways \u{00B7}"),
            "and it is not the plain one with a note after it, which would be two \
             answers where there is one: {title}"
        );

        let col_of = |needle: &str| title[..title.find(needle).expect("drawn")].chars().count();
        assert_eq!(
            panel.handle_click(col_of("[a]lways"), row, area),
            Click::Answer('a'),
            "the labelled key is the clickable target"
        );
        // Past the end of the longer word but still inside the label: the range
        // has to cover the whole of what was drawn, or a click on the words
        // answers nothing — which reads as a broken mouse rather than as a
        // narrower-than-expected target.
        assert_eq!(
            panel.handle_click(
                col_of("[a]lways") + "lways this run".chars().count() - 1,
                row,
                area
            ),
            Click::Answer('a'),
            "the target covers the label it drew, not just the bracketed letter"
        );
        assert_eq!(
            panel.handle_click(title.chars().count() - 1, row, area),
            Click::Nothing,
            "and stops at the end of the prompt, as before"
        );
    }

    /// The prompt is derived from the label rather than matched against a fixed
    /// set of strings, so a label with an interior bracket or a `·` cannot
    /// produce a prompt whose clickable ranges disagree with its own glyphs.
    /// Asserted on the labels that are actually in use rather than on the
    /// function, because that is where the disagreement would show.
    #[test]
    fn the_prompt_is_the_label_it_was_given() {
        assert_eq!(overlay_prompt(&None), "[y]es \u{00B7} [n]o");
        assert_eq!(
            overlay_prompt(&Some(ALWAYS_LABEL.into())),
            "[y]es \u{00B7} [n]o \u{00B7} [a]lways"
        );
        assert_eq!(
            overlay_prompt(&Some("lways this run".into())),
            "[y]es \u{00B7} [n]o \u{00B7} [a]lways this run"
        );
        // Every answer the prompt offers is clickable, whatever the label is.
        for label in ["lways", "lways this run", "lways until reload"] {
            let prompt = overlay_prompt(&Some(label.to_string()));
            for key in ['y', 'n', 'a'] {
                let at = prompt
                    .find(&format!("[{key}]"))
                    .unwrap_or_else(|| panic!("{prompt} offers {key}"));
                assert_eq!(
                    prompt_hit(&prompt, at),
                    Some(key),
                    "the [{key}] in {prompt} is where it is drawn"
                );
            }
        }
    }
}
