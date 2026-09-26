//! Minimal chat-TUI demo: full-width transcript + input line, two roles.
//!
//! All rendering and interaction state live in [`agent::tui`] (unit-tested
//! there). This binary owns the parts that need a real terminal:
//!   - raw mode + alternate screen,
//!   - a background task translating crossterm events into an unbounded
//!     channel (same shape as the future agent integration, where this
//!     channel becomes a `select!` branch in the shared tokio reactor),
//!   - the on-demand redraw loop: no frame-rate timer, we repaint only when
//!     an event arrives, so an idle chat burns no CPU.
//!
//! Keys: type to edit the input (it grows/wraps as needed), Enter sends,
//! Alt+Enter inserts a newline, `q`/Esc/Ctrl+C quit, and `j`/`k`/arrows
//! scroll the transcript while the input line is empty (Home/End jump to
//! the top/bottom). Alt+c toggles markup concealment, Alt+t pushes a demo
//! tool call, and clicking a tool-call box collapses/expands it.

use agent::grammars::Catalog;
use agent::tui::{App, MarkdownHighlighter, Role};
use anyhow::Result;
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event as CrosstermEvent, EventStream,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures_util::StreamExt;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::{Write, stderr};
use tokio::sync::mpsc;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    enable_raw_mode()?;
    execute!(stderr(), EnterAlternateScreen)?;
    execute!(stderr(), EnableMouseCapture)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stderr()))?;

    // Terminal events -> channel, driven by the shared reactor (one task).
    let (tx, mut rx) = mpsc::unbounded_channel::<CrosstermEvent>();
    let reader = tokio::spawn(async move {
        let mut stream = EventStream::new();
        while let Some(event) = stream.next().await {
            match event {
                Ok(evt) => {
                    if tx.send(evt).is_err() {
                        break; // main loop gone
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut app = App::default();
    // Grammars come from the registry at runtime (no cargo involvement):
    // markdown parses each message; bash/json/markdown_inline are injected
    // into fences and inline formatting. Missing grammars degrade to plain
    // text, so the TUI still works offline or without a C compiler.
    let mut catalog = Catalog::new();
    let results = catalog
        .ensure_many(&["markdown", "markdown_inline", "bash", "json"])
        .await;
    for (lang, r) in &results {
        if let Err(e) = r {
            eprintln!("[chat] grammar {lang} unavailable ({e}); that content stays plain");
        }
    }
    app.set_highlight(MarkdownHighlighter::from_catalog(&catalog));
    app.push(
        Role::Assistant,
        "chat TUI ready — type a message below. \
         j/k or arrows scroll while the input is empty, Home/End jump, \
         Enter sends, q quits."
            .into(),
    );

    let outcome = run(&mut terminal, &mut rx, &mut app).await;

    reader.abort();
    execute!(stderr(), DisableMouseCapture)?;
    disable_raw_mode()?;
    execute!(stderr(), LeaveAlternateScreen)?;
    let _ = stderr().flush();
    outcome
}

/// Event loop: park on the channel (no polling), redraw only on events.
async fn run<W: Write>(
    terminal: &mut Terminal<CrosstermBackend<W>>,
    rx: &mut mpsc::UnboundedReceiver<CrosstermEvent>,
    app: &mut App,
) -> Result<()> {
    loop {
        let Some(event) = rx.recv().await else {
            break; // stdin closed / producer task ended
        };
        let quit = match event {
            CrosstermEvent::Key(key) => app.handle_key(key),
            CrosstermEvent::Mouse(ev) => {
                app.handle_mouse(ev);
                false
            }
            _ => false, // resize and friends: just redraw below
        };
        if quit {
            break;
        }
        terminal.autoresize()?;
        terminal.draw(|frame| app.render(frame))?;
    }
    Ok(())
}
