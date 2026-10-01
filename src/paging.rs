//! Reading older history out of the conversation log while the user scrolls.
//!
//! The transcript starts with a window — the newest [`MEMORY_REPLAY_LATEST`]
//! messages, which is also the model's cold-start context — and grows *backwards*
//! from there as the view reaches the top of what is loaded. A log is unbounded
//! and a session can be enormous, so the whole of it is never resident.
//!
//! ## What a page is
//!
//! One read of the log's own unit of storage. Records are appended into
//! block-compressed blocks ([`agent::memory`]), and a block is what has to be
//! decompressed to reach any record inside it, so a page boundary that ignored
//! blocks would either re-read one per page or cut through one mid-record. The
//! read walks whole blocks and stops at the record count asked for, which lands
//! the boundary somewhere inside a block — cheaply, because the block was already
//! in hand.
//!
//! ## What a page does *not* do
//!
//! It does not touch the request history. The model's context stays the
//! [`MEMORY_REPLAY_LATEST`]-message window it started as, because a user
//! scrolling back to read something is not asking to send it to a model, and
//! silently growing the context — and the bill — on a scroll gesture would be a
//! surprise in the expensive direction.
//!
//! ## Panel ids
//!
//! Panel ids are allocated per tool round and continue across rounds, so every
//! chunk of a long session has a panel numbered 1. Replaying two chunks into one
//! transcript would have the second chunk's panel 1 attach to the first's — a box
//! titled with one command showing another one's output. Each page therefore
//! rewrites its ids into a range of its own.

use agent::memory;
use agent::panels;
use agent::tui::{App, HistoryItem, Role};
use serde_json::Value;

/// How many messages a page brings.
///
/// Deliberately small. The trigger is "the user scrolled to the top", and a page
/// far larger than a screenful means loading a lot before showing any of it, for a
/// gesture that is a nudge. Small also keeps the read to a block or two.
const PAGE_MESSAGES: usize = 8;

/// Where the next page of history is, and whether there is one.
pub struct Pager {
    /// The log this pager reads. `None` until one is armed.
    ///
    /// Held rather than re-derived per page: the cursor into a log means nothing
    /// without the log, and asking the VM for the path again on each page would
    /// let a config reload point the pager at a different file mid-scroll, leaving
    /// it reading from `at` an offset that means nothing there.
    path: Option<std::path::PathBuf>,
    /// Where the next page is read from. `None` until a log is opened.
    at: Option<agent::memory::Cursor>,
    /// The log has no records older than `at`.
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

    /// Aim the pager at `path`, reading records older than byte offset `after`.
    ///
    /// `after` must come from the same read that built the window, not from a
    /// second read asking the log again. The window is the newest `n` *messages*
    /// together with the panel records interleaved among them, so it is not a
    /// record range any record count could name — a block boundary is not a record
    /// boundary, and the two reads would disagree about where the window ends. The
    /// disagreement is invisible: the transcript shows a record twice, or skips
    /// one, and either looks like a rendering fault.
    pub fn resume_at(&mut self, path: &std::path::Path, after: agent::memory::Cursor) {
        self.path = Some(path.to_path_buf());
        self.at = Some(after);
        self.exhausted = after.exhausted();
    }

    /// Whether a page is waiting to be read.
    fn wants_page(&self) -> bool {
        self.at.is_some() && !self.exhausted
    }

    /// Read and install one page, if the view is at the top of what is loaded.
    ///
    /// Returns the rows added. Quietly a no-op when the view is not at the top,
    /// when there is nothing older, or when the width the panel measures at is not
    /// known yet — no frame drawn yet means no width to wrap the new history to.
    pub fn page(&mut self, app: &mut App) -> usize {
        if !self.wants_page() || !app.panel.at_loaded_top() {
            return 0;
        }
        let (Some(path), Some(at)) = (self.path.as_deref(), self.at) else {
            return 0;
        };
        let Some(content_w) = app.panel_content_w() else {
            return 0;
        };
        let page = match memory::read_before(path, at, PAGE_MESSAGES) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[agent] history page failed: {e}");
                self.exhausted = true;
                return 0;
            }
        };
        self.at = Some(page.next);
        if page.next.exhausted() {
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
                // `tool` results are invisible, as they are live; the reasoning
                // and panel records were handled above.
                _ => continue,
            };
            out.push(HistoryItem::Message(role, content.to_string()));
        }
        out
    }
}

/// Page the transcript if the view has reached the top of what is loaded.
///
/// A free function so the loop's frame stays the list of what it does, in order.
pub fn page_if_at_top(app: &mut App, pager: &mut Pager) -> usize {
    pager.page(app)
}
