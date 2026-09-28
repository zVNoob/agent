//! The one-line status bar: what the agent is doing right now.
//!
//! The TUI draws it as a single fixed row at the bottom of the screen
//! ([`App::render`](crate::tui::App::render)). It exists because the two things
//! most worth reporting happen where there is no room to report them: grammar
//! acquisition runs at *startup*, before the first frame is drawn, and a cold
//! cache means a registry lookup, a tarball and a C compile per language —
//! which used to be a blank screen, then a line of `eprintln!` landing in the
//! middle of the alternate screen. And Lua's `print` wrote to stdout for the
//! same reason it had nowhere else to go.
//!
//! Deliberately TUI-free, like [`PanelOp`](crate::panels::PanelOp): no ratatui
//! types, just a string and a [`StatusKind`] the renderer resolves to a colour.
//! So `grammars` can report progress and `lua` can route `print` without either
//! depending on the screen.
//!
//! ## Last message wins
//!
//! One line, so one message: a second status *replaces* the first rather than
//! queueing. That is the right shape for progress ("installing rust" gives way
//! to "installing python") and it means a producer never has to think about
//! clearing. [`StatusLine::clear`] exists for the transition into a state with
//! nothing to say.
//!
//! ## Attached, or not
//!
//! [`attach`] is the switch that decides where `print` goes. Detached (the
//! default: the probe, the tests, `chat`) `print` writes to real stdout exactly
//! as it always has, so headless debugging is unchanged. Attached, it becomes a
//! status line — which also means it no longer corrupts a full-screen display.
//! Producers do not care either way: [`status_line`] exists before any TUI does, so a
//! message set during startup is on screen the moment there is a screen.

use std::sync::{Arc, Mutex, OnceLock};

/// How a status line should read. The renderer resolves these to colours; a
/// producer picks the kind, never the colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatusKind {
    /// Ordinary progress. The default.
    #[default]
    Info,
    /// Something did not work out. Left up rather than scrolled away, because a
    /// failure the user never saw is one they will hit again.
    Warn,
    /// The end of a sequence.
    Done,
}

/// One status line's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub text: String,
    pub kind: StatusKind,
}

#[derive(Debug, Default)]
struct State {
    current: Option<Status>,
    attached: bool,
}

/// A handle to the status line. Cheap to clone (`Arc` inside), and every clone
/// reads and writes the same line — so the frame that draws it and the code that
/// sets it need no wiring between them.
///
/// [`status_line`] is the process-wide one; a test or a second screen can make its own
/// with [`StatusLine::new`] rather than share global state.
#[derive(Debug, Clone, Default)]
pub struct StatusLine(Arc<Mutex<State>>);

impl StatusLine {
    /// A private line, attached to nothing — which is what `Default` gives.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the line, replacing whatever was there.
    pub fn set(&self, text: impl Into<String>, kind: StatusKind) {
        let mut s = self.0.lock().expect("status line poisoned");
        s.current = Some(Status {
            text: text.into(),
            kind,
        });
    }

    /// Set the line as ordinary progress.
    pub fn info(&self, text: impl Into<String>) {
        self.set(text, StatusKind::Info);
    }

    /// Set the line as a failure worth keeping up.
    pub fn warn(&self, text: impl Into<String>) {
        self.set(text, StatusKind::Warn);
    }

    /// Set the line as the end of a sequence.
    pub fn done(&self, text: impl Into<String>) {
        self.set(text, StatusKind::Done);
    }

    /// Set the line only if it does not already read `text` (and carry the same
    /// kind).
    ///
    /// For a caller that fires per *event* — the turn stream does, once per
    /// token — this costs one string compare instead of a lock and a fresh
    /// allocation, and stops the bar flickering between two spellings of the
    /// same state.
    pub fn set_if_changed(&self, text: &str, kind: StatusKind) {
        let mut s = self.0.lock().expect("status line poisoned");
        if s.current.as_ref().is_some_and(|c| c.text == text && c.kind == kind) {
            return;
        }
        s.current = Some(Status {
            text: text.to_string(),
            kind,
        });
    }

    /// The line's contents, or `None` when nothing has been set. Read once per
    /// frame; `None` draws an empty row.
    pub fn get(&self) -> Option<Status> {
        self.0.lock().expect("status line poisoned").current.clone()
    }

    /// Blank the line.
    pub fn clear(&self) {
        self.0.lock().expect("status line poisoned").current = None;
    }

    /// Whether a screen is drawing this line. Producers ignore it; it exists so
    /// `print` can tell "put it on the status bar" from "put it on stdout".
    pub fn attached(&self) -> bool {
        self.0.lock().expect("status line poisoned").attached
    }
}

/// The process-wide status line. It exists before any TUI does, which is the
/// point: a grammar install that begins during startup has somewhere to report
/// to, and the message is still there when the first frame is drawn.
pub fn status_line() -> &'static StatusLine {
    static LINE: OnceLock<StatusLine> = OnceLock::new();
    LINE.get_or_init(StatusLine::new)
}

/// Declare that a screen is drawing [`status_line`], so `print` routes there instead of
/// to stdout. Idempotent, and never undone — a TUI is entered once.
pub fn attach() {
    status_line().0.lock().expect("status line poisoned").attached = true;
}

/// Whether a screen has attached (see [`attach`]).
pub fn is_attached() -> bool {
    status_line().attached()
}

/// Set [`status_line`], as ordinary progress — the one-liner most producers want, and
/// what [`Catalog::with_progress`](crate::grammars::Catalog::with_progress)
/// callbacks are usually pointed at.
pub fn info(text: impl Into<String>) {
    status_line().info(text);
}

/// Set [`status_line`] as a failure worth leaving up.
pub fn warn(text: impl Into<String>) {
    status_line().warn(text);
}

/// Set [`status_line`] as the end of a sequence.
pub fn done(text: impl Into<String>) {
    status_line().done(text);
}

/// Report `text` on [`status_line`], as ordinary progress.
///
/// This is where Lua's `print` lands once a screen is attached, and the place a
/// multi-line `print` loses its shape: everything after the first newline is
/// dropped rather than silently overwriting the row below. A status line is not
/// a log — the transcript is, and `agent.panel` is how to write to it.
pub fn print_line(text: &str) {
    let one_line = match text.split_once(['\n', '\r']) {
        Some((first, _)) => first,
        None => text,
    };
    status_line().info(one_line);
}

/// Put the process-wide line back to a known state. Tests share one process, so
/// the global is a liability they need to be able to clear.
#[cfg(test)]
pub(crate) fn reset() {
    let mut s = status_line().0.lock().expect("status line poisoned");
    s.current = None;
    s.attached = false;
}

/// Serializes tests that touch the process-wide line.
///
/// `cargo test` runs a test binary's tests on many threads at once, and both
/// [`attach`] and [`reset`] are process-global — so a test that attaches would
/// otherwise flip the branch another test is asserting on. Holding this for the
/// duration of any test that reads or writes the global is what keeps
/// `print`'s two destinations independently testable.
#[cfg(test)]
pub(crate) fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_message_wins() {
        let line = StatusLine::new();
        assert_eq!(line.get(), None, "nothing set is nothing shown");
        line.info("installing markdown");
        line.info("installing bash");
        assert_eq!(line.get().unwrap().text, "installing bash");
        line.clear();
        assert_eq!(line.get(), None);
    }

    #[test]
    fn a_cloned_handle_is_the_same_line() {
        let line = StatusLine::new();
        let other = line.clone();
        other.warn("no grammar for wasm");
        assert_eq!(line.get().unwrap().kind, StatusKind::Warn);
    }

    #[test]
    fn the_raw_setters_do_not_rewrite_what_they_are_given() {
        // A Rust producer knows it is writing one line, so nothing is trimmed
        // behind its back; `print_line` is the adapter that has to cope with
        // whatever Lua hands it. The renderer clips an over-long row.
        let line = StatusLine::new();
        line.info("  spaced  ");
        assert_eq!(line.get().unwrap().text, "  spaced  ");
        line.info("two\nrows");
        assert_eq!(line.get().unwrap().text, "two\nrows");
    }

    #[test]
    fn print_line_drops_everything_past_the_first_break() {
        let _guard = exclusive();
        print_line("one\ntwo\rthree");
        assert_eq!(status_line().get().unwrap().text, "one");
        print_line("plain");
        assert_eq!(status_line().get().unwrap().text, "plain");
        reset();
    }

    #[test]
    fn attach_is_what_print_keys_off() {
        let _guard = exclusive();
        assert!(!is_attached(), "detached until a screen says otherwise");
        attach();
        assert!(is_attached());
        assert!(status_line().attached(), "the same answer, read off the line");
        reset();
        assert!(!is_attached(), "reset takes the screen back off");
    }
}
