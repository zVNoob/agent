//! Reading older history out of the conversation log while the user scrolls.
//!
//! The transcript starts with a window — the newest [`REPLAY_BLOCKS`] blocks, which
//! is also the model's cold-start context — and grows *backwards* from there as the
//! view reaches the top of what is loaded. A log is unbounded and a session can be
//! enormous, so the whole of it is never resident.
//!
//! ## What a page is
//!
//! One block. Records are appended into block-compressed blocks
//! ([`agent::memory`]) and a block is what has to be decompressed to reach any record
//! inside it, so it is the only unit a byte offset can name — which is what lets the
//! cursor be a single offset and the boundary between two pages be a place the log can
//! actually point at.
//!
//! The loop flushes at the end of every turn, which seals a block, so in practice a
//! block *is* a turn. That is a habit rather than a guarantee: a block is bounded by
//! [`agent::memory::Options::block_target`] and by nothing else, so the turn that runs
//! a command printing megabytes seals mid-turn instead, and a page is as large as
//! whatever went into it.
//!
//! One block may still be two records short of a whole panel, and the page reaches
//! back for the rest — see `page_has_orphan`.
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
use agent::panels::{self, PanelOp};
use agent::tui::{App, HistoryItem, Role};
use serde_json::Value;

/// How many blocks a page brings.
///
/// One. A block is bounded by size and nothing else — see
/// [`agent::memory::Options::block_target`] — so a page of two could be twice a turn's
/// output, decompressed, rebuilt and re-measured on one keypress. One block is already
/// "as much as went into it", and the next keypress brings the next.
const PAGE_BLOCKS: usize = 1;

/// How many extra blocks a page may read backwards to find the `Create` that opens a
/// panel it fills.
///
/// One is the answer in practice — a panel's opening and its body are adjacent records,
/// so a single boundary falls between them at most — and the bound is there so a log
/// that cannot be satisfied ends the reach instead of walking the whole file.
const MAX_PANEL_REACH: usize = 4;

/// Whether these records fill a panel that they do not also open.
///
/// The ids are the log's own, which is what makes this checkable before any remapping:
/// within one page a panel's `Create` and its content agree, and a disagreement means
/// the opening is in an older block.
fn page_has_orphan(records: &[String]) -> bool {
    let mut opened = std::collections::BTreeSet::new();
    let mut filled = std::collections::BTreeSet::new();
    for line in records {
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(op) = panels::panel_record_op(&record) else {
            continue;
        };
        let Some(id) = op.panel_id() else { continue };
        match op {
            PanelOp::Create { .. } => {
                opened.insert(id);
            }
            // Ops that put something in the panel. Styling and geometry address a panel
            // that has content already and neither open nor fill one.
            PanelOp::Append { .. }
            | PanelOp::Set { .. }
            | PanelOp::Split { .. }
            | PanelOp::SetPane { .. } => {
                filled.insert(id);
            }
            _ => {}
        }
    }
    filled.difference(&opened).next().is_some()
}

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
        let mut page = match memory::read_before(path, at, PAGE_BLOCKS) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[agent] history page failed: {e}");
                self.exhausted = true;
                return 0;
            }
        };
        // A page is a block, but a panel's `Create` and the text that fills it are two
        // records and a boundary can fall between them. Reading backwards, the content
        // is met *first* and its `Create` is in the next older block — so reach back
        // until the page opens everything it fills. Without this the two halves are
        // rewritten into different id ranges and neither draws: the panel vanishes
        // from a turn that has it.
        //
        // Bounded, and only while there is somewhere to reach: a log that opens with a
        // `Create` already lost cannot be repaired by reading further forward.
        let mut reach = 0;
        while reach < MAX_PANEL_REACH
            && !memory::at_log_start(page.next)
            && page_has_orphan(&page.records)
        {
            let older = match memory::read_before(path, page.next, 1) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[agent] history page failed: {e}");
                    break;
                }
            };
            if older.records.is_empty() {
                break;
            }
            page.records.splice(0..0, older.records);
            page.next = older.next;
            reach += 1;
        }
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
            // Reasoning is its own record kind, interleaved with the panels and
            // messages of the turn it belongs to — recognised here, in the one ordered
            // list, rather than in a pass of its own that would move it to the end of
            // the turn. Dropping it, as this did, lost the thinking from every paged-in
            // turn while the turns reconstructed at startup kept theirs.
            if record["kind"].as_str() == Some(panels::REASONING_RECORD) {
                if let Some(text) = record["text"].as_str() {
                    out.push(HistoryItem::Reasoning(text.to_string()));
                }
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
                // `tool` results are invisible, as they are live; the panel and
                // reasoning records were handled above.
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
