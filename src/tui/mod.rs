//! The chat TUI: a shell over the [`TurnPanel`] conversation component.
//!
//! Shell (`this module`): interaction state that spans the whole screen —
//! input line, layout, key dispatch, submit. The conversation itself and its
//! rendering live in the component, [`TurnPanel`]; message bodies are
//! highlighted as markdown there (see [`highlight`]) using grammars loaded at
//! runtime from the registry (`crate::grammars`).
//!
//! Layout is the classic chat: a full-width scrollable turn panel on top, an
//! input box below it that grows (and wraps) as you type, capped so the
//! panel keeps most of the screen. Rendering is on-demand (every event
//! redraws); the event loop itself lives elsewhere so the TUI can later sit
//! in the same tokio reactor as the sandboxes (see `src/bin/chat.rs`).

mod highlight;
mod panel;
pub use highlight::{MarkdownHighlighter, Segment};
pub use panel::{BorderedRenderer, Message, Role, TurnPanel};

use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Paragraph, Wrap};

/// Rows one mouse-wheel notch scrolls the transcript by.
const WHEEL_SCROLL_ROWS: usize = 3;

/// The chat screen: the turn panel plus the input line.
#[derive(Debug)]
pub struct App {
    pub panel: TurnPanel,
    pub input: String,
    /// Where the panel was drawn last frame, so mouse clicks can be mapped
    /// to panel rows between frames.
    panel_area: Option<Rect>,
    /// Demo echo: when on (the default, so `bin/chat.rs` stays a pure demo),
    /// `Enter` also appends a canned assistant echo of the input. The agent
    /// sets this off: the submitted text instead goes to the LLM client.
    pub echo: bool,
    /// The last submitted input, waiting for the caller (the agent loop) to
    /// consume it via [`App::take_submitted`]. `None` until `Enter` sends.
    submitted: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            panel: TurnPanel::default(),
            input: String::new(),
            panel_area: None,
            echo: true,
            submitted: None,
        }
    }
}

impl App {
    /// App-panel convenience; the panel itself is the canonical push target.
    pub fn push(&mut self, role: Role, text: String) {
        self.panel.push(role, text);
    }

    /// Push a tool-call message rendered inside a bordered box titled `tool`
    /// (markers stay visible inside; click the box to collapse/expand).
    pub fn push_boxed(&mut self, role: Role, text: String, tool: String) {
        self.panel.push_boxed(role, text, tool);
    }

    /// Append one streamed fragment of the assistant's reply (the panel
    /// starts a fresh assistant message for the first chunk; see
    /// [`TurnPanel::stream_append`]).
    pub fn stream_append(&mut self, chunk: &str) {
        self.panel.stream_append(chunk);
    }

    /// Append one streamed fragment of the assistant's reply into a
    /// borderless block titled `title` (see
    /// [`TurnPanel::stream_append_boxed`]). Used so a turn's reasoning and
    /// answer both render live as their own blocks — "reasoning" above,
    /// "response" below, borderless (the reasoning dimmed and darker than
    /// the answer, unlike the framed tool boxes); the content follows the
    /// markup-conceal toggle like a plain message.
    pub fn stream_append_boxed(&mut self, chunk: &str, title: String) {
        self.panel.stream_append_boxed(chunk, title);
    }

    /// Apply every op buffered in `sink` (Lua `agent.api.panel_*` emissions from
    /// a tool round) to the transcript, oldest first. Safe to call once per
    /// round (synchronous runs) or once per frame (once runs go async).
    pub fn drain_panel_ops(&mut self, sink: &crate::panels::PanelSink) {
        for op in sink.drain() {
            self.panel.apply_op(op);
        }
    }

    /// Consume the last submitted input (the text `Enter` sent), if the
    /// caller hasn't read it yet. The agent loop uses this to know when the
    /// user has asked something and what to send to the LLM.
    pub fn take_submitted(&mut self) -> Option<String> {
        self.submitted.take()
    }

    /// Handle a terminal mouse event. A left click on a boxed (tool-call)
    /// message toggles its collapsed state; a wheel notch over the panel
    /// scrolls the transcript ([`WHEEL_SCROLL_ROWS`] rows per notch) through
    /// the same follow-aware path as the `j`/`k` keys (scrolling up
    /// disengages follow; scrolling down re-engages it at the bottom).
    /// Events elsewhere (over the input box) and other buttons are ignored.
    pub fn handle_mouse(&mut self, ev: MouseEvent) {
        match ev.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let Some(area) = self.panel_area else {
                    return;
                };
                self.panel
                    .handle_click(ev.column as usize, ev.row as usize, area);
            }
            MouseEventKind::ScrollUp if self.pointer_over_panel(ev.row) => {
                for _ in 0..WHEEL_SCROLL_ROWS {
                    self.panel.scroll_up();
                }
            }
            MouseEventKind::ScrollDown if self.pointer_over_panel(ev.row) => {
                for _ in 0..WHEEL_SCROLL_ROWS {
                    self.panel.scroll_down();
                }
            }
            _ => {}
        }
    }

    /// Whether a (1-based) mouse row points inside the panel's last drawn
    /// area. Outside it — the input box or nothing drawn yet — wheel events
    /// are ignored.
    fn pointer_over_panel(&self, row: u16) -> bool {
        let Some(area) = self.panel_area else {
            return false;
        };
        row >= area.y && row < area.y.saturating_add(area.height)
    }

    /// Install the markdown highlighter (or clear it); call before pushing
    /// messages so their highlight segments are computed with it.
    pub fn set_highlight(&mut self, highlighter: Option<MarkdownHighlighter>) {
        self.panel.set_highlighter(highlighter);
    }

    /// Toggle markup concealment (rendering hides `#`/`**`/backtick markers;
    /// fenced-code content always renders verbatim); returns the new state.
    pub fn toggle_conceal(&mut self) -> bool {
        self.panel.toggle_conceal()
    }

    /// Handle one key press; returns `true` when the caller should quit.
    /// While the input line is non-empty, every printable key (including
    /// `q`, `j`, `k`) edits it; scrolling via `j/k` is only active when the
    /// input is empty. `Enter` submits, `Alt+Enter` inserts a newline,
    /// `Alt+c` toggles markup concealment (`#`/`**`/backtick markers hidden,
    /// fenced-code content always verbatim), and `Alt+t` pushes a demo
    /// tool-call message (a bordered box you can click to collapse).
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        let input_empty = self.input.is_empty();
        match key.code {
            KeyCode::Char('q') if input_empty => return true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::ALT) => {
                self.toggle_conceal();
            }
            KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::ALT) => {
                self.panel.push_boxed(
                    Role::Assistant,
                    "demo tool call:\n```bash\nls -la ~\n```\n**exit 0**".into(),
                    "bash".into(),
                );
            }
            KeyCode::Esc => return true,
            KeyCode::Char('j') | KeyCode::Down if input_empty => self.panel.scroll_down(),
            KeyCode::Char('k') | KeyCode::Up if input_empty => self.panel.scroll_up(),
            KeyCode::Home => self.panel.jump_top(),
            KeyCode::End => self.panel.jump_bottom(),
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::ALT) => {
                self.input.push('\n');
            }
            KeyCode::Enter => self.send(),
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(c) => self.input.push(c),
            _ => {}
        }
        false
    }

    /// Move the current input text into a user message (recording it via
    /// [`App::take_submitted`] for the agent loop), append the canned demo
    /// echo when [`App::echo`] is on, then pin the view to the new bottom.
    fn send(&mut self) {
        let text = self.input.trim().to_string();
        if text.is_empty() {
            return;
        }
        self.input.clear();
        self.panel.push(Role::User, text.clone());
        if self.echo {
            self.panel
                .push(Role::Assistant, format!("(demo) you said: {text}"));
        }
        self.submitted = Some(text);
        self.panel.jump_bottom();
    }

    /// Draw one frame: turn panel + input box that grows to fit its wrapped
    /// content (capped so the panel keeps room).
    pub fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let input_width = (area.width as usize).saturating_sub(2); // block borders
        let input_rows = wrap_lines(&self.input, input_width).len().max(1);
        let input_height = input_box_height(input_rows, area.height);

        let chunks =
            Layout::vertical([Constraint::Min(2), Constraint::Length(input_height)]).split(area);
        let transcript = chunks[0];
        let input = chunks[1];

        self.panel_area = Some(transcript);
        self.panel.render(frame, transcript);

        // Input box: wraps its text; when it outgrows the cap we scroll it so
        // the line being edited stays visible.
        let shown_rows = (input.height as usize).saturating_sub(2);
        let input_scroll = input_rows.saturating_sub(shown_rows);
        let placeholder = "Enter sends · Alt+Enter newline · Alt+c conceal · Alt+t tool · q quits";
        let input_text: std::borrow::Cow<'_, str> = if self.input.is_empty() {
            placeholder.into()
        } else {
            self.input.as_str().into()
        };
        frame.render_widget(
            Paragraph::new(input_text)
                .block(Block::bordered().title(" input "))
                .wrap(Wrap { trim: false })
                .scroll((input_scroll as u16, 0))
                .style(if self.input.is_empty() {
                    Style::default().fg(Color::DarkGray)
                } else {
                    Style::default()
                }),
            input,
        );

        // Cursor at the end of the typed text, mapped through the wrapped
        // rows (and the box's internal scroll).
        let (cur_row, cur_col) =
            cursor_position(&self.input, input_width, self.input.chars().count());
        let view_row = cur_row.saturating_sub(input_scroll);
        let cursor_x = input.x + 1 + cur_col.min(input_width.saturating_sub(1)) as u16;
        let cursor_y = input.y + 1 + view_row as u16;
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}

/// Split `text` into rows of at most `width` cells, breaking on `\n` too.
/// One cell per `char` — grapheme/CJK-aware wrapping is out of scope for the
/// minimal UI (a comment in the renderer notes the same approximation).
/// Shared by the shell (input box height, cursor) and the turn panel.
fn wrap_lines(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    let mut out = Vec::new();
    for para in text.split('\n') {
        if para.is_empty() {
            out.push(String::new());
            continue;
        }
        let mut rest = para;
        while !rest.is_empty() {
            let take = width.min(rest.chars().count());
            let chunk: String = rest.chars().take(take).collect();
            rest = &rest[chunk.len()..];
            out.push(chunk);
        }
    }
    out
}

/// Rows the input box should occupy: `content_rows` wrapped rows plus the two
/// border rows, capped so the turn panel keeps most of the screen (at least
/// three rows even on a tiny terminal).
fn input_box_height(content_rows: usize, area_height: u16) -> u16 {
    let cap = (area_height as usize / 2)
        .max(3)
        .min((area_height as usize).saturating_sub(2).max(3));
    (content_rows.max(1) + 2).min(cap) as u16
}

/// Map a char `index` into `text` to the (row, col) where the caret belongs,
/// at `width` cells per row. `\n` starts a new row (consuming the character);
/// reaching the row width wraps to the next row (consuming none). Used to pin
/// the input cursor, so `index` is normally the end of the text.
fn cursor_position(text: &str, width: usize, index: usize) -> (usize, usize) {
    let width = width.max(1);
    let mut row = 0;
    let mut col = 0;
    for (i, ch) in text.chars().enumerate() {
        if i >= index {
            break;
        }
        if ch == '\n' {
            row += 1;
            col = 0;
        } else {
            col += 1;
            if col >= width {
                row += 1;
                col = 0;
            }
        }
    }
    (row, col)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn enter_sends_user_and_echo_and_clears_input() {
        let mut app = App::default();
        for c in ['h', 'i'] {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.panel.messages.len(), 2);
        assert_eq!(app.panel.messages[0].role, Role::User);
        assert_eq!(app.panel.messages[0].text, "hi");
        assert_eq!(app.panel.messages[1].role, Role::Assistant);
        assert!(app.input.is_empty());
        assert!(app.panel.follow, "sending pins the view to the bottom");
    }

    #[test]
    fn empty_enter_is_ignored() {
        let mut app = App::default();
        app.handle_key(key(KeyCode::Enter));
        assert!(app.panel.messages.is_empty());
    }

    #[test]
    fn drain_panel_ops_applies_lua_panels() {
        let mut app = App::default();
        let sink = crate::panels::PanelSink::default();
        sink.push(crate::panels::PanelOp::Create {
            id: 1,
            title: "log".into(),
            boxed: false,
            conceal_box: false,
        });
        sink.push(crate::panels::PanelOp::Append {
            id: 1,
            text: "hi".into(),
        });
        app.drain_panel_ops(&sink);
        assert_eq!(app.panel.messages.len(), 1);
        assert_eq!(app.panel.messages[0].text, "hi");
        assert!(sink.ops().is_empty(), "drain consumes the sink");
    }

    #[test]
    fn q_quits_only_when_input_is_empty() {
        let mut app = App::default();
        assert!(app.handle_key(key(KeyCode::Char('q')))); // empty input: q quits

        let mut app = App::default();
        app.handle_key(key(KeyCode::Char('a')));
        app.handle_key(key(KeyCode::Char('q')));
        app.handle_key(key(KeyCode::Char('q')));
        assert_eq!(app.input, "aqq");
        assert!(!app.handle_key(key(KeyCode::Char('q')))); // still typing
        assert_eq!(app.input, "aqqq");
        assert!(app.handle_key(key(KeyCode::Esc))); // Esc always quits
    }

    #[test]
    fn backspace_edits_input() {
        let mut app = App::default();
        app.handle_key(key(KeyCode::Char('a')));
        app.handle_key(key(KeyCode::Char('b')));
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.input, "a");
    }

    #[test]
    fn jk_scroll_only_when_input_empty() {
        let mut app = App::default();
        app.panel.follow = false;
        app.panel.scroll = 3;
        app.handle_key(key(KeyCode::Char('j')));
        assert_eq!(app.panel.scroll, 4);
        app.handle_key(key(KeyCode::Char('k')));
        assert_eq!(app.panel.scroll, 3);
        // typing letters, not scrolling
        app.handle_key(key(KeyCode::Char('a')));
        app.handle_key(key(KeyCode::Char('k')));
        assert_eq!(app.input, "ak");
        assert_eq!(app.panel.scroll, 3);
    }

    #[test]
    fn wrap_lines_handles_newlines_and_width() {
        assert_eq!(wrap_lines("", 3), vec![""]);
        assert_eq!(wrap_lines("abcde", 2), vec!["ab", "cd", "e"]);
        assert_eq!(wrap_lines("a\nb", 5), vec!["a", "b"]);
        assert_eq!(wrap_lines("", 0), vec![""]);
    }

    #[test]
    fn alt_enter_adds_newline_without_sending() {
        let mut app = App::default();
        app.handle_key(key(KeyCode::Char('a')));
        let alt_enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT);
        assert!(!app.handle_key(alt_enter));
        app.handle_key(key(KeyCode::Char('b')));
        assert_eq!(app.input, "a\nb");
        assert!(app.panel.messages.is_empty(), "Alt+Enter must not submit");

        // Plain Enter still submits, preserving the internal newline.
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.panel.messages.len(), 2);
        assert_eq!(app.panel.messages[0].text, "a\nb");
        assert!(app.input.is_empty());
    }

    #[test]
    fn input_box_height_clamps() {
        assert_eq!(input_box_height(1, 24), 3); // single line + borders
        assert_eq!(input_box_height(4, 24), 6); // grows with content
        assert_eq!(input_box_height(50, 24), 12); // capped at half the screen
        assert_eq!(input_box_height(1, 5), 3); // tiny terminal floor
    }

    #[test]
    fn cursor_position_maps_wrapped_rows() {
        // "abcde" at width 3 wraps to ["abc", "de"]
        assert_eq!(cursor_position("abcde", 3, 0), (0, 0));
        assert_eq!(cursor_position("abcde", 3, 2), (0, 2));
        assert_eq!(cursor_position("abcde", 3, 3), (1, 0)); // before 'd'
        assert_eq!(cursor_position("abcde", 3, 5), (1, 2)); // end of text

        // Explicit newline forces a row break (and consumes a character)
        assert_eq!(cursor_position("ab\ncd", 5, 2), (0, 2));
        assert_eq!(cursor_position("ab\ncd", 5, 3), (1, 0));
        assert_eq!(cursor_position("ab\ncd", 5, 5), (1, 2));

        // Exactly a full row: the caret sits in the next-line slot
        assert_eq!(cursor_position("abc", 3, 3), (1, 0));
    }

    #[test]
    fn push_delegates_to_the_panel() {
        let mut app = App::default();
        app.push(Role::Assistant, "hi".into());
        assert_eq!(app.panel.messages.len(), 1);
    }

    #[test]
    fn send_records_submission_and_echo_defaults_on() {
        let mut app = App::default();
        assert!(
            app.echo,
            "demo echo defaults on (keeps bin/chat.rs identical)"
        );
        for c in ['h', 'i'] {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.panel.messages.len(), 2, "user message + demo echo");
        assert_eq!(app.take_submitted().as_deref(), Some("hi"));
        assert_eq!(app.take_submitted(), None, "submission is consumed once");
    }

    #[test]
    fn echo_off_suppresses_demo_echo_but_still_records_submission() {
        let mut app = App {
            echo: false, // the agent disables the demo echo
            ..App::default()
        };
        for c in ['h', 'i'] {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.panel.messages.len(), 1, "only the user message");
        assert_eq!(app.panel.messages[0].role, Role::User);
        assert_eq!(app.take_submitted().as_deref(), Some("hi"));
    }

    #[test]
    fn empty_send_never_records_a_submission() {
        let mut app = App::default();
        app.handle_key(key(KeyCode::Enter));
        assert!(app.panel.messages.is_empty());
        assert_eq!(app.take_submitted(), None);
    }

    #[test]
    fn stream_append_feeds_the_agent_reply_into_the_panel() {
        let mut app = App::default();
        app.push(Role::User, "q".into());
        app.stream_append("Hel");
        app.stream_append("lo");
        assert_eq!(app.panel.messages.len(), 2);
        assert_eq!(app.panel.messages[1].text, "Hello");
        assert_eq!(app.panel.messages[1].role, Role::Assistant);
    }

    #[test]
    fn alt_c_toggles_markup_conceal() {
        let mut app = App::default();
        assert!(app.panel.conceal_enabled(), "conceal defaults on");
        let alt_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::ALT);
        app.handle_key(alt_c);
        assert!(!app.panel.conceal_enabled());
        // Alt+c types nothing into the input (it is not a printable edit).
        assert!(app.input.is_empty());
        app.handle_key(alt_c);
        assert!(app.panel.conceal_enabled());
        // Ctrl+C still quits, plain 'c' still types.
        assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
    }

    #[test]
    fn alt_t_pushes_a_boxed_tool_message() {
        let mut app = App::default();
        let alt_t = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::ALT);
        assert!(!app.handle_key(alt_t));
        assert_eq!(app.panel.messages.len(), 1);
        assert_eq!(app.panel.messages[0].boxed.as_deref(), Some("bash"));
        assert!(app.input.is_empty(), "Alt+t is not a printable edit");
    }

    #[test]
    fn mouse_click_toggles_a_boxed_message() {
        let mut app = App::default();
        app.push_boxed(Role::Assistant, "ls -la".into(), "bash".into());
        app.push(Role::User, "ok".into());
        let mut terminal = Terminal::new(TestBackend::new(50, 12)).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();

        // Panel rows (borderless, so area.y = 0): expanded box 0 top, 1
        // content, 2 bottom; collapsing it shrinks to 0 title, 1 bottom.
        let click = |col, row| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: col,
            row,
            modifiers: KeyModifiers::NONE,
        };
        app.handle_mouse(click(5, 1));
        assert!(
            app.panel.messages[0].collapsed,
            "click on the box collapses it"
        );
        app.handle_mouse(click(5, 0));
        assert!(!app.panel.messages[0].collapsed, "second click expands it");

        // A plain (non-boxed) message is not clickable.
        app.handle_mouse(click(5, 3));
        assert!(
            !app.panel.messages[0].collapsed,
            "plain message rows do not toggle"
        );
    }

    #[test]
    fn mouse_release_is_ignored() {
        let mut app = App::default();
        app.push_boxed(Role::Assistant, "ls -la".into(), "bash".into());
        let mut terminal = Terminal::new(TestBackend::new(50, 12)).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        let release = MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: 5,
            row: 2,
            modifiers: KeyModifiers::NONE,
        };
        app.handle_mouse(release);
        assert!(!app.panel.messages[0].collapsed);
    }

    #[test]
    fn wheel_scrolls_the_transcript_through_the_panel() {
        let mut app = App::default();
        // Enough boxed messages to overflow the panel's viewport.
        for _ in 0..10 {
            app.push_boxed(
                Role::Assistant,
                "body\n```bash\nls\n```".into(),
                "bash".into(),
            );
        }
        let mut terminal = Terminal::new(TestBackend::new(50, 12)).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        let before = app.panel.scroll;
        assert!(before > 3, "content must actually overflow");

        // Wheel up over the panel: 3 rows up, follow disengages.
        let wheel = |kind, row| MouseEvent {
            kind,
            column: 20,
            row,
            modifiers: KeyModifiers::NONE,
        };
        app.handle_mouse(wheel(MouseEventKind::ScrollUp, 3));
        assert_eq!(app.panel.scroll, before - 3);
        assert!(!app.panel.follow, "wheel up must disengage follow");

        // Wheel down: back down, follow re-engages on the next resolve.
        app.handle_mouse(wheel(MouseEventKind::ScrollDown, 3));
        assert_eq!(app.panel.scroll, before);
        terminal.draw(|frame| app.render(frame)).unwrap();
        assert!(
            app.panel.follow,
            "reaching the bottom must re-engage follow"
        );
    }

    #[test]
    fn wheel_ignored_outside_the_panel_and_before_first_draw() {
        let mut app = App::default();
        for _ in 0..10 {
            app.push_boxed(
                Role::Assistant,
                "body\n```bash\nls\n```".into(),
                "bash".into(),
            );
        }
        // Before any draw there is no panel area: wheel is a no-op.
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 20,
            row: 3,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.panel.scroll, 0);

        let mut terminal = Terminal::new(TestBackend::new(50, 12)).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        let before = app.panel.scroll;
        // Row 10 sits in the input box (the panel is ~6 rows tall here): the
        // wheel must not scroll the transcript.
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 20,
            row: 10,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(
            app.panel.scroll, before,
            "wheel over the input box is ignored"
        );
    }
}
