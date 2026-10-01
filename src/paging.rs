//! Reading older history out of the conversation log while the user scrolls.
//!
//! The transcript starts with a window — the newest [`REPLAY_BLOCKS`] blocks, which
//! is also the model's cold-start context — and grows *backwards* from there as the
//! view reaches the top of what is loaded. A log is unbounded and a session can be
//! enormous, so the whole of it is never resident.
//!
//! ## What a page is
//!
//! Whole blocks, one gesture's worth of them. Records are appended into
//! block-compressed blocks ([`agent::memory`]) and a block is what has to be
//! decompressed to reach any record inside it, so it is the only unit a byte offset
//! can name. Blocks are also sealed at turn boundaries, so a page is a turn or two
//! of history — the same shape the transcript already draws.
//!
//! ## The gesture
//!
//! Paging answers a *request*, not a state: a scroll towards older content that had
//! nowhere left to go ([`App::take_history_wanted`]). Two things follow, and both were
//! wrong the first time round.
//!
//! What comes back is **shown**, not restored. The offset stays where it was and the
//! older history is on screen. Restoring it instead — pushing the new content back
//! above the viewport — makes the gesture that fetched the history show none of it,
//! and the user has to scroll up through the whole page again to reach what they
//! asked for.
//!
//! And keying it off "the view is at the top" instead of "the user asked" reads the
//! entire log into memory on the first idle frame: the offset rests at 0 whenever the
//! transcript fits on screen, which is also where paging leaves it. The request has to
//! come from the keypress.
//!
//! ## What a page does *not* do
//!
//! It does not touch the request history. The model's context stays the
//! [`REPLAY_BLOCKS`]-block window it started as, because a user scrolling back to
//! read something is not asking to send it to a model, and silently growing the
//! context — and the bill — on a scroll gesture would be a surprise in the expensive
//! direction.
//!
//! ## Panel ids
//!
//! Panel ids are allocated per tool round and continue across rounds, so every
//! block of a long session has a panel numbered 1. Replaying two pages into one
//! transcript would have the second page's panel 1 attach to the first's — a box
//! titled with one command showing another one's output. Each page therefore rewrites
//! its ids into a range of its own.

use agent::memory;
use agent::panels;
use agent::tui::{App, HistoryItem, Role};
use serde_json::Value;

/// How many blocks a page brings.
const PAGE_BLOCKS: usize = 2;

/// Where the next page of history is, and whether there is one.
pub struct Pager {
    /// The log this pager reads. `None` until one is armed.
    ///
    /// Held rather than re-derived per page: an offset into a log means nothing
    /// without the log, and asking the VM for the path again on each page would let a
    /// config reload point the pager at a different file mid-scroll.
    path: Option<std::path::PathBuf>,
    /// Offset the next page is read from. `None` until a log is armed.
    at: Option<u64>,
    /// The log has no blocks older than `at`.
    exhausted: bool,
    /// One past the highest panel id handed out so far, across all pages.
    next_panel_id: u64,
}

impl Pager {
    /// A pager with nowhere to read from — the no-log case, where every call is a
    /// no-op rather than an error.
    pub fn new() -> Self {
        Pager {
            path: None,
            at: None,
            exhausted: true,
            next_panel_id: 1,
        }
    }

    /// Aim the pager at `path`, reading blocks older than byte offset `after`.
    ///
    /// `after` must come from the same read that built the window, not from a second
    /// read asking the log again — the two would disagree about where the window
    /// ends, and the disagreement is invisible: the transcript shows a record twice
    /// or skips one, and either looks like a rendering fault.
    pub fn resume_at(&mut self, path: &std::path::Path, after: u64) {
        self.path = Some(path.to_path_buf());
        self.at = Some(after);
        self.exhausted = memory::at_log_start(after);
    }

    /// Read and install one page, if the user asked for history the transcript did
    /// not have.
    ///
    /// Returns the rows added. Quietly a no-op when nothing was asked for, when there
    /// is nothing older, or when the width the panel measures at is not known yet —
    /// no frame drawn yet means no width to wrap the new history to.
    pub fn page(&mut self, app: &mut App) -> usize {
        if !app.take_history_wanted() || self.path.is_none() || self.exhausted {
            return 0;
        }
        let Some(at) = self.at else { return 0 };
        let Some(content_w) = app.panel_content_w() else {
            return 0;
        };
        let Some(path) = self.path.as_deref() else {
            return 0;
        };
        let page = match memory::read_before(path, at, PAGE_BLOCKS) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[agent] history page failed: {e}");
                self.exhausted = true;
                return 0;
            }
        };
        self.at = Some(page.next);
        if memory::at_log_start(page.next) {
            self.exhausted = true;
        }
        if page.records.is_empty() {
            return 0;
        }
        let items = self.items_for(&page.records);
        if items.is_empty() {
            // A page of records that draw nothing — a torn line, an empty turn.
            // Installing nothing would leave a scroll that appears not to move,
            // which reads as a broken key; the cursor has already advanced, so the
            // next nudge reads further back rather than spinning here.
            return 0;
        }
        app.panel.prepend_history(items, content_w)
    }

    /// Turn raw log lines into replayable items, with panel ids moved into this
    /// page's own range.
    ///
    /// One ordered list, because the log interleaves panels and messages and the
    /// transcript has to keep that order — a page split into "the panels" and "the
    /// words" would put a tool's box on the wrong side of the sentence that
    /// introduced it.
    fn items_for(&mut self, lines: &[String]) -> Vec<HistoryItem> {
        let base = self.next_panel_id;
        let mut out = Vec::with_capacity(lines.len());
        for line in lines {
            let Ok(record) = serde_json::from_str::<Value>(line) else {
                continue; // a torn record: skip it, never fatal
            };
            if let Some(op) = panels::panel_record_op(&record) {
                let Some(old) = op.panel_id() else { continue };
                let moved = op.with_panel_id(base + old);
                // Past the whole page, not past the largest id seen: ids are not
                // dense, and a page whose ids ran 1,2,9 must not let the next page
                // reuse 3.
                self.next_panel_id = self.next_panel_id.max(base + old + 1);
                out.push(HistoryItem::Op(moved));
                continue;
            }
            let (Some(role), Some(content)) = (record["role"].as_str(), record["content"].as_str())
            else {
                continue;
            };
            if content.is_empty() {
                continue; // an empty turn draws nothing
            }
            let role = match role {
                "user" => Role::User,
                "assistant" => Role::Assistant,
                // `tool` results are invisible, as they are live; the reasoning and
                // panel records were handled above.
                _ => continue,
            };
            out.push(HistoryItem::Message(role, content.to_string()));
        }
        out
    }
}

/// Page the transcript if the user asked for history it does not have.
///
/// A free function so the loop's frame stays the list of what it does, in order.
pub fn page_if_wanted(app: &mut App, pager: &mut Pager) -> usize {
    pager.page(app)
}
