//! The chat TUI: a shell over the [`TurnPanel`] conversation component.
//!
//! Shell (`this module`): interaction state that spans the whole screen —
//! input line, layout, key dispatch, submit. The conversation itself and its
//! rendering live in the component, [`TurnPanel`]; message bodies are
//! highlighted as markdown there (see `highlight`) using grammars loaded at
//! runtime from the registry (`crate::grammars`).
//!
//! Layout is the classic chat: a full-width scrollable turn panel on top, an
//! input box below it that grows (and wraps) as you type, capped so the
//! panel keeps most of the screen, and a one-line status bar along the bottom.
//! That bar is [`crate::status`] — the row is reserved whether or not there is
//! anything to say, so the transcript does not jump when something first is —
//! and it is where grammar progress and Lua's `print` are re-pointed, since a
//! full-screen terminal has nowhere else for either to go.
//!
//! Rendering is on-demand (every event
//! redraws); the event loop itself lives elsewhere so the TUI can later sit
//! in the same tokio reactor as the sandboxes (see `src/bin/chat.rs`).

mod highlight;
mod panel;

// Re-exported rather than made public: `Click` is part of how the app is
// driven (the event loop has to know what a click decided), while the panel
// module's geometry and rendering are its own business.
pub use highlight::{MarkdownHighlighter, Segment};
pub use panel::Click;
pub use panel::{BorderedRenderer, Message, Role, TurnPanel};

use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Paragraph, Wrap};

use crate::status::{StatusKind, StatusLine};

/// Rows one mouse-wheel notch scrolls the transcript by.
const WHEEL_SCROLL_ROWS: usize = 3;

/// The status bar's height: one row, and one row only.
const STATUS_HEIGHT: u16 = 1;

/// What every status line starts with, so the row is recognisable as a status
/// bar rather than a stray fragment of the transcript. The leading space keeps
/// it off the screen edge, the same margin the input box's border gives its
/// text.
const STATUS_PREFIX: &str = " › ";

/// [`STATUS_PREFIX`] in terminal cells, which is not its byte length: `›` is
/// three bytes of UTF-8 and one column, so `len()` would say 5 and the terminal
/// says 3. Spelled out rather than computed — `chars().count()` is not a const
/// fn — and `the_prefix_width_matches_its_cells` below fails if the two ever
/// disagree.
const STATUS_PREFIX_CELLS: usize = 3;

/// The chat screen: the turn panel, the input line, and a one-line status bar.
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
    /// The bottom status bar. A private, empty line by default, so a `chat.rs`
    /// demo draws a blank row and a test can assert on its own text; the agent
    /// hands it [`crate::status::line`] via [`App::set_status`].
    status: StatusLine,
}

impl Default for App {
    fn default() -> Self {
        Self {
            panel: TurnPanel::default(),
            input: String::new(),
            panel_area: None,
            echo: true,
            submitted: None,
            status: StatusLine::new(),
        }
    }
}

/// What the agent itself still binds, and what each is for.
///
/// Two keys, and the reason there are only two is that the rest of the table
/// moved to Lua: a `key` handler can name an [`Action`] or, now, call
/// `agent.api.input_insert` and reach the input line itself, so a binding needs
/// no Rust-side counterpart and the shipped config (`lua/init.lua`) is where the
/// defaults live. What is left is the part that is *about the agent* rather than
/// about a user's preferences:
///
/// * **`Ctrl+c`** — interrupt the running command. Not a preference: it is the
///   only way to stop a tool, and a `Ctrl+c` that quits the app instead takes
///   the user's work with it.
/// * **`Ctrl+d`** — leave. Also not a preference, and deliberately *not* `Ctrl+c`,
///   so the interrupt and the exit stay different keys. `Esc` and `q` used to
///   leave too; they do not any more, and a config that wants either back binds
///   it in Lua like anything else.
///
/// `Alt+Enter` was a third row here until `agent.api.input_insert` existed. It
/// had been justified as a *fallback* for terminals that cannot send the chord —
/// which was never true: a terminal that cannot send `Alt+Enter` does not deliver
/// a distinguishable event, so Rust would not have received it either. The
/// binding worked only on terminals that could send it, and on those a config
/// could do it perfectly well. It is a line in `lua/init.lua` now.
///
/// The hint is built from this table, so it describes what Rust does and nothing
/// else. A Lua binding table is invisible here, and saying so is more honest than
/// a hint that guesses.
const KEY_HELP: &[(&str, &str, &str)] = &[
    ("Ctrl+d", "quit", "quit"),
    ("Ctrl+c", "interrupt", "stop"),
];

/// The placeholder in an empty input box: [`KEY_HELP`] as one line.
///
/// It does not describe the Lua binding table, because the agent cannot read
/// that table's shape from here and a hint that guessed at it would be wrong
/// more often than not.
fn input_hint() -> String {
    KEY_HELP
        .iter()
        .map(|(shown, _, what)| format!("{shown} {what}"))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// What a key press can *mean*, independent of which key produced it.
///
/// Naming these is what makes a binding a pure mapping from a key to a meaning
/// and nothing else. The default table and a Lua `key` handler that returns
/// `"conceal"` ask the same question and go through the same
/// [`App::perform`], so a remapped key cannot develop behaviour of its own — the
/// failure mode of every configurable-key feature, where the defaults and the
/// remappings are two implementations that slowly disagree.
///
/// Text editing is deliberately *not* here. Backspace and printable characters
/// are not commands; they are what an unbound key falls through to
/// ([`App::handle_key`]), which is why a binding table only has to name the
/// handful of things a user might want to move somewhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Insert a newline into the input without sending it. `Alt+Enter`.
    Newline,
    /// Submit the input line. `Enter`, in a config's own table.
    Send,
    /// Leave. `Ctrl+d`, here.
    Quit,
    /// Stop whatever tool is running now. `Ctrl+c`, here.
    ///
    /// A distinct action rather than a flavour of quit because the two are not
    /// the same: one ends a command and leaves you in the app, the other throws
    /// away the session. A key that did both would be useless for both.
    Interrupt,
    /// Toggle markup concealment. `Alt+c`.
    Conceal,
    /// Scroll the transcript one notch. `j`/`k`, the arrows, the wheel.
    ScrollUp,
    ScrollDown,
    /// Jump to the start or end of the transcript. `Home`/`End`.
    Top,
    Bottom,
}

impl Action {
    /// Every action, in the order [`Action::parse`] reports them when it
    /// rejects a name. One list, so the error can be exhaustive.
    pub const ALL: &'static [Action] = &[
        Action::Newline,
        Action::Send,
        Action::Quit,
        Action::Interrupt,
        Action::Conceal,
        Action::ScrollUp,
        Action::ScrollDown,
        Action::Top,
        Action::Bottom,
    ];

    /// The name a Lua handler returns, and the one an error quotes.
    pub fn name(self) -> &'static str {
        match self {
            Action::Newline => "newline",
            Action::Send => "send",
            Action::Quit => "quit",
            Action::Interrupt => "interrupt",
            Action::Conceal => "conceal",
            Action::ScrollUp => "scroll_up",
            Action::ScrollDown => "scroll_down",
            Action::Top => "top",
            Action::Bottom => "bottom",
        }
    }

    /// The action a handler named, or an error listing the ones there are.
    ///
    /// Unknown names are an error rather than a shrug. A typo in a binding table
    /// is a dead key that looks configured, and a feature whose whole job is to
    /// be configured should not fail quietly at the moment of use.
    pub fn parse(name: &str) -> Result<Self, String> {
        Self::ALL
            .iter()
            .copied()
            .find(|a| a.name() == name)
            .ok_or_else(|| {
                format!(
                    "unknown action {name:?}; expected one of {}",
                    Self::ALL
                        .iter()
                        .map(|a| a.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }
}

/// What [`App::perform`] did, for the caller to act on.
///
/// Not a `bool` for "should I quit" any more, because there is now a second
/// answer the loop has to give: stopping a tool is not something the `App` can
/// do, since the sandbox lives inside the tool's Lua coroutine and not here.
/// Returning it keeps the *decision* in one place — a key means an action, an
/// action means an effect — and the *doing* in the loop, which is the only place
/// that knows about sandboxes and about leaving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Done; carry on.
    Continue,
    /// Leave the app.
    Quit,
    /// Stop the tool that is running, if any.
    Interrupt,
}

/// Whether this key would put a character into a message if nothing claimed it
/// first — a bare letter, and nothing else.
///
/// The modifiers are the whole test, and they are not redundant with the code:
/// crossterm reports `Ctrl+q` as `KeyCode::Char('q')`, so a rule that looked only
/// at the code would call a chord typeable and then refuse to let it interrupt
/// anything while a message was being typed. `CONTROL`, `ALT` and `SUPER` all
/// make a key untypable into a message; `SHIFT` does not, and is deliberately
/// not counted, because terminals disagree about whether they send it with a
/// shifted letter (see [`key_spec`]) and a capital `A` is still a character.
fn is_typeable(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char(_))
        && !key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
        && !key.modifiers.contains(KeyModifiers::SUPER)
}

/// The canonical name for a key, as a binding table writes it: `alt+enter`,
/// `ctrl+c`, `q`, `f5`, `up`.
///
/// One spelling per key from one place, because this string is the contract
/// between the table in Rust and the one in Lua, and a binding that silently
/// never matches is the worst failure a configurable-key feature can have.
///
/// **Shift is not reported for printable characters, and the letter is
/// lower-cased.** Terminals disagree about whether `A` arrives as `Char('A')`
/// with `SHIFT` set or as `Char('a')` without it, so a spec that preserved the
/// distinction would match on one terminal and not the next. `a` matches `a`,
/// `A` and `shift+a` alike; the cost is that shift-letter cannot be bound
/// separately from the letter, which costs nothing here because no action
/// distinguishes them. `SHIFT` *is* kept for named keys, where `shift+tab` is a
/// real and distinct thing.
pub fn key_spec(key: &KeyEvent) -> String {
    let named = !matches!(key.code, KeyCode::Char(_));
    let mut spec = String::new();
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        spec.push_str("ctrl+");
    }
    if key.modifiers.contains(KeyModifiers::ALT) {
        spec.push_str("alt+");
    }
    if named && key.modifiers.contains(KeyModifiers::SHIFT) {
        spec.push_str("shift+");
    }
    match key.code {
        KeyCode::Char(' ') => spec.push_str("space"),
        KeyCode::Char(c) => spec.push(c.to_ascii_lowercase()),
        KeyCode::Enter => spec.push_str("enter"),
        KeyCode::Esc => spec.push_str("esc"),
        KeyCode::Tab => spec.push_str("tab"),
        KeyCode::Backspace => spec.push_str("backspace"),
        KeyCode::Delete => spec.push_str("delete"),
        KeyCode::Insert => spec.push_str("insert"),
        KeyCode::Home => spec.push_str("home"),
        KeyCode::End => spec.push_str("end"),
        KeyCode::PageUp => spec.push_str("pageup"),
        KeyCode::PageDown => spec.push_str("pagedown"),
        KeyCode::Up => spec.push_str("up"),
        KeyCode::Down => spec.push_str("down"),
        KeyCode::Left => spec.push_str("left"),
        KeyCode::Right => spec.push_str("right"),
        KeyCode::F(n) => spec.push_str(&format!("f{n}")),
        // Whatever crossterm adds next. A name nothing should bind to is better
        // than an empty spec, which would be a key the table cannot name at all.
        other => spec.push_str(&format!("{other:?}").to_lowercase()),
    }
    spec
}

impl App {
    /// Draw `line` — the process-wide status line, normally — in the bottom
    /// row. Cloning an `Arc` is the whole wiring: every producer that already
    /// holds the handle now has somewhere to write.
    pub fn set_status(&mut self, line: StatusLine) {
        self.status = line;
    }

    /// What the status bar currently reads (`None` draws an empty row).
    pub fn status(&self) -> Option<crate::status::Status> {
        self.status.get()
    }

    /// Set the status bar from the screen's own side — for the messages the
    /// loop itself has, as opposed to the ones producers report.
    pub fn set_status_text(&mut self, text: impl Into<String>, kind: StatusKind) {
        self.status.set(text, kind);
    }

    /// [`App::set_status_text`], but only when the line does not already read
    /// `text`. The turn-stream branch calls this per event, so without it a
    /// streamed answer would re-set the same line once per token.
    pub fn set_status_text_if_changed(&mut self, text: &str, kind: StatusKind) {
        self.status.set_if_changed(text, kind);
    }

    /// Blank the status bar — what the loop does when the thing it was
    /// reporting has finished, so the bar never shows a state that has passed.
    pub fn clear_status(&mut self) {
        self.status.clear();
    }

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

    /// Handle a terminal mouse event, and report what it decided.
    ///
    /// A left click on one of a pending dialog's answers is a verdict, and comes
    /// back as the letter it names so the caller can apply the same rule the
    /// keyboard uses. A click on a framed message toggles its collapsed state;
    /// the wheel scrolls the transcript (`WHEEL_SCROLL_ROWS` rows per notch)
    /// through the same follow-aware path as the `j`/`k` keys (scrolling up
    /// disengages follow; scrolling down re-engages it at the bottom). Events
    /// elsewhere (over the input box) and other buttons are ignored.
    ///
    /// Only the answer is reported. Collapse is navigation and the panel has
    /// already done it, so there is nothing for the caller to act on — and a
    /// return value for every click would be an invitation to give the collapse
    /// semantics it does not have.
    pub fn handle_mouse(&mut self, ev: MouseEvent) -> Click {
        match ev.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let Some(area) = self.panel_area else {
                    return Click::Nothing;
                };
                self.panel
                    .handle_click(ev.column as usize, ev.row as usize, area)
            }
            // The wheel only moves the transcript, so it decides nothing and
            // reports nothing.
            MouseEventKind::ScrollUp if self.pointer_over_panel(ev.row) => {
                for _ in 0..WHEEL_SCROLL_ROWS {
                    self.panel.scroll_up();
                }
                Click::Nothing
            }
            MouseEventKind::ScrollDown if self.pointer_over_panel(ev.row) => {
                for _ in 0..WHEEL_SCROLL_ROWS {
                    self.panel.scroll_down();
                }
                Click::Nothing
            }
            _ => Click::Nothing,
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

    /// Handle one key press, and say what the caller still has to do.
    ///
    /// With no binding table in play this is just the three keys in `KEY_HELP`;
    /// everything else a config wants to bind, it binds in Lua and the loop calls
    /// [`App::perform`] directly. Anything that is not a command is text —
    /// backspace deletes, a printable character types itself — which is the rule
    /// the old `Alt+t` demo key broke: it swallowed a chord to draw a fake
    /// tool-call box, a demo of a rendering this app no longer does.
    pub fn handle_key(&mut self, key: KeyEvent) -> Effect {
        if key.kind != KeyEventKind::Press {
            return Effect::Continue;
        }
        if let Some(action) = self.default_action(key) {
            return self.perform(action);
        }
        match key.code {
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(c) => self.input.push(c),
            _ => {}
        }
        Effect::Continue
    }

    /// Apply a change to the input line that Lua asked for
    /// (`agent.api.input_insert` and its two siblings).
    ///
    /// The other half of the `key` event's reach. A handler that can only *name*
    /// an action has a closed vocabulary baked into Rust, so "insert a newline"
    /// had to be an [`Action::Newline`] whether a user wanted one or not, and
    /// nothing else could type into the box on demand. This is what makes the
    /// input line a place a binding table can reach, and it is deliberately
    /// ungated: the letter rule in [`App::key_may_act`] governs which *key* may
    /// mean a command, and by the time an op gets here a command has already been
    /// chosen. A leader key that inserts a digit mid-sentence is the point of a
    /// leader key.
    pub fn apply_input_op(&mut self, op: crate::lua::InputOp) {
        match op {
            crate::lua::InputOp::Append(text) => self.input.push_str(&text),
            crate::lua::InputOp::Backspace => {
                self.input.pop();
            }
            crate::lua::InputOp::Clear => self.input.clear(),
        }
    }

    /// Take a grammar into use, and apply it to what is already on screen.
    ///
    /// The hot half of hot loading, and the reason it can be done at all: adding
    /// a language extends the *shared* capture-name list, which every
    /// configuration is built against, so this rebuilds them — and a rebuilt
    /// configuration means every `Highlight` index has moved. Nothing rendered
    /// before this call is invalidated by that (segments carry resolved styles),
    /// but nothing rendered before it is *improved* either, so the transcript is
    /// re-highlighted here rather than left stale.
    ///
    /// Returns how many messages that actually changed, so a caller does not
    /// redraw a whole screen for a grammar that had nothing to say.
    pub fn add_grammar(
        &mut self,
        lang: &str,
        grammar: &crate::grammars::LoadedGrammar,
    ) -> usize {
        let Some(hl) = self.panel.highlighter_mut() else {
            return 0;
        };
        hl.add_language(lang, grammar);
        self.panel.rehighlight_all()
    }

    /// The fenced languages something on screen has asked to inline and that
    /// nothing has a grammar for, and clears the list.
    ///
    /// Drained rather than read, because the loop asks once per frame and a fetch
    /// takes seconds: a peek would re-request the same language every frame for as
    /// long as it is in flight.
    pub fn take_wanted_grammars(&mut self) -> Vec<String> {
        match self.panel.highlighter_mut() {
            Some(hl) => hl.take_wanted(),
            None => Vec::new(),
        }
    }

    /// Whether this key may mean a command right now rather than text.
    ///
    /// One rule: **a bare letter is a character first and a command second.** A
    /// letter reaches an action only when the input line is empty; a chord —
    /// anything with a modifier, or a named key like `Esc` — can never be a
    /// character, so it always does.
    ///
    /// This is the context gate the old default table had, kept but *moved*. It
    /// belonged to the table then, because the table was the only thing that
    /// could bind a letter. Now a Lua table can, and a gate that lived with the
    /// defaults would have been a trap: `BIND["q"] = "quit"` would quit the app
    /// halfway through the word "quick". Belonging to the key instead, it holds
    /// for every binding, which is the only place it can be relied on.
    ///
    /// A key this refuses is not swallowed — the loop falls through to
    /// [`App::handle_key`] and the letter types, which is what makes refusing
    /// safe.
    pub fn key_may_act(&self, key: &KeyEvent) -> bool {
        !is_typeable(key) || self.input.is_empty()
    }

    /// What `key` means under the two keys the agent binds for itself, or
    /// `None` when it is text rather than a command.
    ///
    /// Both are chords, so the letter gate in [`App::key_may_act`] never applies
    /// to them — which is why leaving is `Ctrl+d` and not `q`.
    fn default_action(&self, key: KeyEvent) -> Option<Action> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        Some(match key.code {
            KeyCode::Char('d') if ctrl => Action::Quit,
            KeyCode::Char('c') if ctrl => Action::Interrupt,
            _ => return None,
        })
    }

    /// Do an [`Action`], and say what the caller still has to do about it.
    ///
    /// The one implementation of what each action means, reached from the
    /// default table and from a Lua `key` handler alike.
    pub fn perform(&mut self, action: Action) -> Effect {
        match action {
            Action::Newline => {
                self.input.push('\n');
                Effect::Continue
            }
            Action::Send => {
                self.send();
                Effect::Continue
            }
            Action::Quit => Effect::Quit,
            // Not done here: the sandbox belongs to the tool's coroutine, and
            // this struct knows nothing about tools. The loop does, and it is
            // also the only place that can act between two steps of one.
            Action::Interrupt => Effect::Interrupt,
            Action::Conceal => {
                self.toggle_conceal();
                Effect::Continue
            }
            Action::ScrollUp => {
                self.panel.scroll_up();
                Effect::Continue
            }
            Action::ScrollDown => {
                self.panel.scroll_down();
                Effect::Continue
            }
            Action::Top => {
                self.panel.jump_top();
                Effect::Continue
            }
            Action::Bottom => {
                self.panel.jump_bottom();
                Effect::Continue
            }
        }
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
    /// content (capped so the panel keeps room), over a fixed one-line status
    /// bar.
    ///
    /// The bar's row is reserved whether or not there is anything to say, so
    /// the transcript does not jump a row the first time something is reported.
    pub fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let input_width = (area.width as usize).saturating_sub(2); // block borders
        let input_rows = wrap_lines(&self.input, input_width).len().max(1);
        // The status row is subtracted from what the input may grow into, so
        // the bar never gets pushed off the bottom of a short terminal.
        let body_height = area.height.saturating_sub(STATUS_HEIGHT);
        let input_height = input_box_height(input_rows, body_height);

        let chunks = Layout::vertical([
            Constraint::Min(2),
            Constraint::Length(input_height),
            Constraint::Length(STATUS_HEIGHT),
        ])
        .split(area);
        let transcript = chunks[0];
        let input = chunks[1];
        let status = chunks[2];

        self.panel_area = Some(transcript);
        self.panel.render(frame, transcript);

        // Input box: wraps its text; when it outgrows the cap we scroll it so
        // the line being edited stays visible.
        let shown_rows = (input.height as usize).saturating_sub(2);
        let input_scroll = input_rows.saturating_sub(shown_rows);
        let placeholder = input_hint();
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
        // rows (and the box's internal scroll). The status row is below the
        // input, so the input area's own `y` is unaffected by it.
        let (cur_row, cur_col) =
            cursor_position(&self.input, input_width, self.input.chars().count());
        let view_row = cur_row.saturating_sub(input_scroll);
        let cursor_x = input.x + 1 + cur_col.min(input_width.saturating_sub(1)) as u16;
        let cursor_y = input.y + 1 + view_row as u16;
        frame.set_cursor_position((cursor_x, cursor_y));

        self.render_status(frame, status);
    }

    /// The bottom row: the status line, prefixed so an empty bar still reads as
    /// a bar, and dimmed in the same grey as the input placeholder so it stays
    /// out of the way of the conversation.
    fn render_status(&self, frame: &mut Frame, area: Rect) {
        let Some(status) = self.status.get() else {
            return;
        };
        // A row too short to hold the prefix shows nothing rather than a stub
        // of one.
        if (area.width as usize) < STATUS_PREFIX_CELLS {
            return;
        }
        let style = match status.kind {
            StatusKind::Info => Style::default().fg(Color::DarkGray),
            StatusKind::Warn => Style::default().fg(Color::Yellow),
            StatusKind::Done => Style::default().fg(Color::Green),
        };
        let line = ratatui::text::Line::from(vec![
            ratatui::text::Span::styled(STATUS_PREFIX, style),
            // Truncated by the widget at the right edge, which is what a status
            // line should do with something too long for one row.
            ratatui::text::Span::raw(status.text),
        ]);
        frame.render_widget(Paragraph::new(line).style(style), area);
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
    use crate::testutil::unique_path;
    use super::*;
    use crate::lua::InputOp;
    use crate::panels::PanelOp;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Render one frame into a `w`x`h` test terminal and read the rows back as
    /// plain strings — so a layout assertion can be about *what is on screen*
    /// rather than about the rects the renderer chose.
    fn rows_of(app: &mut App, w: u16, h: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| {
                        buf.cell((x, y))
                            .map(|c| c.symbol())
                            .unwrap_or(" ")
                            .to_string()
                    })
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn enter_sends_user_and_echo_and_clears_input() {
        let mut app = App::default();
        for c in ['h', 'i'] {
            app.handle_key(key(KeyCode::Char(c)));
        }
        // `send` by name, not `Enter` by key: sending is a config's binding now,
        // and this test is about what sending does.
        app.perform(Action::Send);
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

    /// The two keys Rust keeps, and — as much as the point — the ones it does
    /// not.
    ///
    /// `q`, `Esc`, `Enter`, `Alt+c` and the scroll keys used to be here. They are
    /// not any more: they are a config's business, bound in Lua by name through
    /// the `key` event. Pinned as absences because that is the easy thing to
    /// reintroduce by accident — a "helpful" default in a new code path would
    /// quietly take a key back from the table that now owns it.
    #[test]
    fn rust_keeps_two_keys_and_gives_the_rest_to_lua() {
        let mut app = App::default();
        let ctrl = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);

        // The two, and what each means.
        assert_eq!(
            app.handle_key(ctrl('c')),
            Effect::Interrupt,
            "Ctrl+c stops the running command"
        );
        assert_eq!(app.handle_key(ctrl('d')), Effect::Quit, "Ctrl+d leaves");

        // Everything else is text now, which is the honest consequence of
        // moving the table: `q` and `Esc` are letters and nothing else until a
        // config says otherwise.
        for code in [KeyCode::Esc, KeyCode::Home, KeyCode::End, KeyCode::Up] {
            let mut app = App::default();
            assert_eq!(
                app.handle_key(key(code)),
                Effect::Continue,
                "{code:?} is not bound in Rust"
            );
            assert!(app.input.is_empty(), "and typed nothing");
        }
        // `q` used to quit. It is a letter now, and it lands in the input.
        let mut app = App::default();
        app.handle_key(key(KeyCode::Char('q')));
        assert_eq!(app.input, "q");

        // Enter does not submit either. This is the sharp edge of the cut-down:
        // without a binding table there is no way to talk to the agent at all,
        // which is why the shipped config carries one.
        let mut app = App::default();
        app.handle_key(key(KeyCode::Char('a')));
        assert_eq!(app.handle_key(key(KeyCode::Enter)), Effect::Continue);
        assert!(app.panel.messages.is_empty(), "Enter is not a Rust binding");
    }

    /// The hint names the three, and only the three. A hint that listed a Lua
    /// binding would be a guess, and a wrong guess about which keys work is worse
    /// than a short list.
    #[test]
    fn the_hint_names_exactly_the_keys_rust_binds() {
        let hint = input_hint();
        for shown in ["Ctrl+d", "Ctrl+c"] {
            assert!(hint.contains(shown), "{shown} is in the hint: {hint}");
        }
        for gone in ["q quits", "Esc", "Alt+c", "Enter sends", "Alt+Enter"] {
            assert!(
                !hint.contains(gone),
                "{gone} is not Rust's any more: {hint}"
            );
        }
    }

    #[test]
    fn backspace_edits_input() {
        let mut app = App::default();
        app.handle_key(key(KeyCode::Char('a')));
        app.handle_key(key(KeyCode::Char('b')));
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.input, "a");
    }

    /// A bare letter is a character first and a command second.
    ///
    /// This is the rule that makes a *Lua* binding table safe to write. When the
    /// context gate lived in the default table, moving the table to Lua would
    /// have quietly lost it, and `BIND["q"] = "quit"` would have quit the app
    /// halfway through the word "quick". Pin both halves: a letter waits for an
    /// empty input, and a chord never does.
    #[test]
    fn a_letter_is_a_character_first_and_a_command_second() {
        let mut app = App::default();
        let letter = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        let ctrl_q = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL);

        // Empty input: a letter may act.
        assert!(app.key_may_act(&letter), "an empty line has nothing to protect");
        assert!(app.key_may_act(&esc));

        // Mid-word: the letter is text, and refusing is safe because the loop
        // falls through to `handle_key`, which types it.
        app.input.push_str("quick brown qu");
        assert!(!app.key_may_act(&letter), "a letter mid-word is a character");
        // A chord can never be a character, so it always acts — which is why
        // leaving is `Ctrl+d` and not a letter.
        assert!(app.key_may_act(&esc), "Esc is not a character in any message");
        assert!(app.key_may_act(&ctrl_q));

        // And the refusal really does type rather than swallow.
        let mut app = App::default();
        app.input.push_str("qu");
        if !app.key_may_act(&letter) {
            app.handle_key(letter);
        }
        assert_eq!(app.input, "quq", "the letter landed");
    }

    /// Scrolling is an action, and the keys that used to do it are the config's
    /// business — so what is pinned here is the action, plus the fact that the
    /// letters themselves are inert again.
    #[test]
    fn scroll_is_an_action_and_jk_are_letters_again() {
        let mut app = App::default();
        app.panel.follow = false;
        app.panel.scroll = 3;
        assert_eq!(app.perform(Action::ScrollDown), Effect::Continue);
        assert_eq!(app.panel.scroll, 4);
        assert_eq!(app.perform(Action::ScrollUp), Effect::Continue);
        assert_eq!(app.panel.scroll, 3);
        // The keys that used to do this type now.
        app.handle_key(key(KeyCode::Char('j')));
        app.handle_key(key(KeyCode::Char('k')));
        assert_eq!(app.input, "jk", "not scrolling");
        assert_eq!(app.panel.scroll, 3);
    }

    #[test]
    fn wrap_lines_handles_newlines_and_width() {
        assert_eq!(wrap_lines("", 3), vec![""]);
        assert_eq!(wrap_lines("abcde", 2), vec!["ab", "cd", "e"]);
        assert_eq!(wrap_lines("a\nb", 5), vec!["a", "b"]);
        assert_eq!(wrap_lines("", 0), vec![""]);
    }

    /// A newline in the input line, which is what a config's `Alt+Enter` binding
    /// does — and, since `agent.api.input_insert` exists, no longer anything Rust
    /// does for a key.
    ///
    /// The op rather than the chord, because the chord is the config's business
    /// now; the behaviour it produces is the agent's, and this is the half of
    /// that which lives in Rust.
    #[test]
    fn an_input_op_writes_the_line_without_sending() {
        let mut app = App::default();
        app.handle_key(key(KeyCode::Char('a')));
        app.apply_input_op(InputOp::Append("\n".into()));
        app.handle_key(key(KeyCode::Char('b')));
        assert_eq!(app.input, "a\nb");
        assert!(app.panel.messages.is_empty(), "a newline must not submit");

        // The mirror, and the readline gesture.
        app.apply_input_op(InputOp::Backspace);
        assert_eq!(app.input, "a\n", "backspace on an empty tail does nothing");
        app.apply_input_op(InputOp::Append("cd".into()));
        app.apply_input_op(InputOp::Backspace);
        assert_eq!(app.input, "a\nc");
        app.apply_input_op(InputOp::Clear);
        assert!(app.input.is_empty(), "clear empties it");
    }

    /// `Alt+Enter` is a line in the shipped config, not a key Rust holds.
    ///
    /// Pinned because it was one, and because the reason it was moved was wrong:
    /// it had been kept as a fallback for terminals that cannot send the chord,
    /// which would have been no use at all — such a terminal does not deliver a
    /// distinguishable event, so Rust would not have received one either. The
    /// binding only ever worked on terminals that could send it, and on those a
    /// config could do it.
    #[test]
    fn alt_enter_is_not_a_rust_binding_any_more() {
        let mut app = App::default();
        let alt_enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT);
        assert_eq!(app.handle_key(alt_enter), Effect::Continue);
        assert!(
            app.input.is_empty(),
            "a chord Rust does not bind types nothing at all"
        );
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
        app.perform(Action::Send);
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
        app.perform(Action::Send);
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

    /// Conceal is a config's binding now, so this is the action rather than the
    /// key: the same [`Action`] a `key` handler returns by name, and the same
    /// `perform` the default table goes through.
    #[test]
    fn conceal_is_an_action_rather_than_a_key() {
        let mut app = App::default();
        assert!(app.panel.conceal_enabled(), "conceal defaults on");
        assert_eq!(app.perform(Action::Conceal), Effect::Continue);
        assert!(!app.panel.conceal_enabled());
        assert_eq!(app.perform(Action::Conceal), Effect::Continue);
        assert!(app.panel.conceal_enabled());
    }

    /// The demo key is gone, and an unbound chord is a character again.
    ///
    /// `Alt+t` used to push a fabricated tool-call box — a demo of a rendering
    /// this app stopped doing. Removing the key is only half of it: without the
    /// arm, `Alt+t` falls through to the printable branch, which is what any
    /// chord with no binding should do.
    #[test]
    fn an_unbound_chord_types_its_letter() {
        let mut app = App::default();
        let alt_t = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::ALT);
        assert_eq!(app.handle_key(alt_t), Effect::Continue);
        assert!(app.panel.messages.is_empty(), "and draws nothing");
        assert_eq!(app.input, "t", "so the character is typed");
    }

    /// The spelling is the contract between the two binding tables, so it is
    /// pinned — including the two decisions that are not obvious: a printable
    /// character ignores `SHIFT` and lower-cases, and a named key keeps it.
    #[test]
    fn a_key_has_one_canonical_name() {
        let spec = |code, mods| key_spec(&KeyEvent::new(code, mods));
        assert_eq!(spec(KeyCode::Enter, KeyModifiers::NONE), "enter");
        assert_eq!(spec(KeyCode::Enter, KeyModifiers::ALT), "alt+enter");
        assert_eq!(spec(KeyCode::Char('c'), KeyModifiers::CONTROL), "ctrl+c");
        assert_eq!(spec(KeyCode::Char('q'), KeyModifiers::NONE), "q");
        assert_eq!(spec(KeyCode::Up, KeyModifiers::NONE), "up");
        assert_eq!(spec(KeyCode::F(5), KeyModifiers::NONE), "f5");
        assert_eq!(spec(KeyCode::Char(' '), KeyModifiers::NONE), "space");
        assert_eq!(spec(KeyCode::Tab, KeyModifiers::SHIFT), "shift+tab");

        // Terminals disagree about whether `A` arrives with SHIFT set, so a
        // printable character must not encode the difference — otherwise a
        // binding for `a` works on one terminal and not the next.
        for (code, mods) in [
            (KeyCode::Char('a'), KeyModifiers::NONE),
            (KeyCode::Char('A'), KeyModifiers::NONE),
            (KeyCode::Char('A'), KeyModifiers::SHIFT),
            (KeyCode::Char('a'), KeyModifiers::SHIFT),
        ] {
            assert_eq!(key_spec(&KeyEvent::new(code, mods)), "a", "{code:?} {mods:?}");
        }
        // Modifiers compose in a fixed order, so `ctrl+alt+x` is one string and
        // not two depending on which terminal sent it.
        assert_eq!(
            spec(KeyCode::Char('x'), KeyModifiers::CONTROL | KeyModifiers::ALT),
            "ctrl+alt+x"
        );
    }

    /// An action name is what a binding table says and what an error quotes, so
    /// the two directions have to agree and a typo has to be loud.
    #[test]
    fn action_names_round_trip_and_a_typo_lists_the_real_ones() {
        for action in Action::ALL {
            assert_eq!(
                Action::parse(action.name()),
                Ok(*action),
                "{action:?} parses back to itself"
            );
        }
        let err = Action::parse("conceall").expect_err("a typo is not an action");
        assert!(err.contains("conceall"), "it quotes what was asked for: {err}");
        for action in Action::ALL {
            assert!(err.contains(action.name()), "and lists {action:?}: {err}");
        }
    }

    /// The point of [`Action`]: a bound key does the thing it was bound to,
    /// through the same code as the default — so `newline` and `Alt+Enter`
    /// cannot come to behave differently.
    #[test]
    fn a_bound_action_does_what_it_says() {
        let mut app = App::default();
        // `newline` appends without submitting, which is the whole difficulty:
        // `send` on the same input does something else entirely.
        app.input.push_str("hi");
        assert_eq!(app.perform(Action::Newline), Effect::Continue);
        assert_eq!(app.input, "hi\n", "a newline, and no message sent");
        assert!(app.panel.messages.is_empty());

        // `conceal` compared against itself rather than against a literal,
        // because which way it starts is the panel's business and not what this
        // is testing.
        let was = app.panel.conceal_enabled();
        assert_eq!(app.perform(Action::Conceal), Effect::Continue);
        assert_eq!(app.panel.conceal_enabled(), !was, "conceal toggles");
        assert_eq!(app.perform(Action::Conceal), Effect::Continue);
        assert_eq!(app.panel.conceal_enabled(), was, "and toggles back");

        // The two the loop has to act on, rather than the panel.
        assert_eq!(app.perform(Action::Quit), Effect::Quit);
        assert_eq!(
            app.perform(Action::Interrupt),
            Effect::Interrupt,
            "reported, not done: the sandbox is not this struct's to reach"
        );
        assert_eq!(app.perform(Action::ScrollDown), Effect::Continue);
    }

    /// The three keys Rust binds are named by an action each, so the table and
    /// the action vocabulary cannot drift apart.
    #[test]
    fn the_default_table_names_real_actions_and_the_hint_comes_from_it() {
        let hint = input_hint();
        for (shown, action, what) in KEY_HELP {
            assert!(
                Action::parse(action).is_ok(),
                "{shown} is bound to {action:?}, which is not an action"
            );
            assert_eq!(
                Action::parse(action).expect("checked").name(),
                *action,
                "and it parses back to itself"
            );
            assert!(
                hint.contains(what),
                "{shown} is advertised as {what:?}: {hint}"
            );
        }
        assert!(
            !hint.contains("Alt+t"),
            "the demo key is not advertised: {hint}"
        );
        assert_eq!(hint, "Ctrl+d quit · Ctrl+c stop");
    }

    /// The streaming indicator, end to end: set once per turn rather than once
    /// per token, and gone when the turn ends.
    #[test]
    fn the_streaming_indicator_appears_and_clears() {
        let mut app = App::default();
        app.push(Role::User, "hi".into());

        // Every stream event calls this, so it must not churn the bar.
        for _ in 0..500 {
            app.set_status_text_if_changed("streaming...", StatusKind::Info);
        }
        assert_eq!(
            rows_of(&mut app, 40, 8).last().unwrap().trim(),
            "› streaming..."
        );

        app.clear_status();
        assert!(
            rows_of(&mut app, 40, 8).last().unwrap().trim().is_empty(),
            "an ended turn leaves nothing stale on the bar"
        );
    }

    /// The status bar owns the bottom row, prefixed, and the rows above it are
    /// still the transcript and the input box.
    #[test]
    fn the_prefix_width_matches_its_cells() {
        assert_eq!(
            STATUS_PREFIX.chars().count(),
            STATUS_PREFIX_CELLS,
            "the prefix's cell count is spelled out as a const; keep them in step"
        );
    }

    /// Hot loading, end to end: a fenced language with no grammar is *noticed*,
    /// fetched in the background, taken into use, and applied to text that was
    /// already on screen.
    ///
    /// The order is the whole design and each step is a separate mechanism, so the
    /// test walks all of them: highlight (which finds the gap and names it),
    /// `take_wanted` (which drains it, so a per-frame poll does not re-request),
    /// `add_language` (which extends the shared capture list and rebuilds every
    /// configuration against it), and `rehighlight_all` (which re-styles the
    /// messages that had nothing).
    ///
    /// `#[ignore]`d for the same reason as its neighbours: it needs the network
    /// and a C compiler to obtain a grammar the highlighter does not ship with.
    /// Everything it asserts *apart from* having a grammar is covered hermetically
    /// by `adding_a_language_reports_whether_the_shared_list_moved` and
    /// `restyling_changes_no_row_count`; this is the join.
    #[tokio::test]
    #[ignore = "needs the network and a C compiler; run with --ignored"]
    async fn a_grammar_that_arrives_late_is_applied_to_text_already_rendered() {
        use super::*;
        use crate::grammars::Catalog;
        use std::fs;

        let dir = unique_path("agent-hot");
        let _ = fs::remove_dir_all(&dir);

        // A catalog with the app's own four, and deliberately *not* rust.
        let mut catalog = Catalog::new().with_cache_dir(&dir);
        for lang in ["markdown", "markdown_inline", "bash", "json"] {
            catalog
                .ensure(lang)
                .await
                .unwrap_or_else(|e| panic!("{lang} is required for this test: {e:#}"));
        }
        let hl = MarkdownHighlighter::from_catalog(&catalog);
        assert!(hl.is_some(), "the highlighter builds from the app's four");

        // A message with a rust block in it, rendered *before* the grammar exists.
        // A heading as well as a block, so there is something the *markdown*
        // layer captures: plain prose has no capture and comes out unstyled, which
        // would make "the highlighter is working" untestable here.
        let text = "# Fix\n\nHere is the change:\n\n```rust\nfn main() {\n    let x: u32 = 7;\n}\n```\n";
        let mut app = App::default();
        app.set_highlight(hl);
        // Named fns rather than closures: they borrow `app` immutably and are
        // called again after `app` has been mutated, which a closure would not
        // allow.
        fn style_at(app: &App, text: &str, needle: &str) -> Style {
            let at = text.find(needle).expect("the needle is in the text");
            app.panel.messages[0]
                .segs
                .iter()
                .find(|seg| seg.start <= at && at < seg.end)
                .map(|seg| seg.style)
                .unwrap_or_default()
        }
        /// How many distinct styles the block's bytes carry.
        ///
        /// The count, not the colours, because that is the honest measure of "is
        /// this block being parsed". An un-injected block is captured whole by the
        /// markdown grammar as `markup.raw.block`, and the theme paints `raw` light
        /// green — so it *looks* like code, one flat colour, while carrying no
        /// structure at all. Counting distinct styles is what separates that from
        /// a block with a real grammar behind it.
        fn distinct_styles_in_block(app: &App, text: &str) -> usize {
            let from = text.find("fn main").expect("the code is there");
            let to = text.rfind('}').expect("and its closing brace");
            let mut seen: Vec<Style> = Vec::new();
            for seg in &app.panel.messages[0].segs {
                if seg.end > from
                    && seg.start < to + 1
                    && !seen.contains(&seg.style)
                {
                    seen.push(seg.style);
                }
            }
            seen.len()
        }

        app.push(Role::Assistant, text.to_string());
        // The heading proves the markdown layer is working at all, so a flat block
        // below is the injection's doing and not a dead highlighter.
        assert_ne!(
            style_at(&app, text, "Fix"),
            Style::default(),
            "the heading is highlighted"
        );
        assert_eq!(
            distinct_styles_in_block(&app, text),
            1,
            "and the rust block is one flat colour: markup.raw.block painted as \
             `raw`, with no per-token structure behind it"
        );
        let (term_w, term_h) = (50u16, 18u16);
        let frame_before = rows_of(&mut app, term_w, term_h);

        // The gap was noticed, named once, and drained.
        assert_eq!(
            app.take_wanted_grammars(),
            vec!["rust"],
            "the rust block named itself"
        );

        // Fetched out of band, exactly as the loop's task does it.
        let mut worker = Catalog::new().with_cache_dir(&dir);
        let grammar = worker.ensure("rust").await.expect("rust acquires");

        // Taken into use. The boolean is the shared capture list moving, which is
        // what makes a re-render necessary rather than merely nice.
        let hl = app.panel.highlighter_mut().expect("a highlighter");
        assert!(hl.add_language("rust", grammar), "the list grew");
        assert!(hl.has_language("rust"), "so rust inlines now");
        assert!(
            hl.take_wanted().is_empty(),
            "and the gap is closed, so nothing is queued for it again"
        );

        // And the text already on screen picks it up, without the page moving.
        let changed = app.add_grammar("rust", grammar);
        assert_eq!(changed, 1, "exactly the one message that was missing it");
        assert!(
            distinct_styles_in_block(&app, text) > 1,
            "and the code that was one flat colour now has structure, without being \
             re-sent"
        );
        let frame_after = rows_of(&mut app, term_w, term_h);
        assert_eq!(
            frame_after.len(),
            frame_before.len(),
            "the same number of rows"
        );
        assert_eq!(
            frame_after.last().map(|s| s.trim()),
            frame_before.last().map(|s| s.trim()),
            "and the input box is where it was: re-styling must not reflow"
        );
        // `rows_of` collects cell *symbols*, so it is blind to styling by
        // construction — which makes it exactly the right instrument for "nothing
        // moved" and the wrong one for "something is now coloured". The styling
        // itself is asserted by `distinct_styles_in_block` above.

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_status_bar_is_the_bottom_row() {
        let mut app = App::default();
        app.push(Role::User, "hello".into());
        app.set_status_text("installing markdown (2/4)", StatusKind::Info);

        let rows = rows_of(&mut app, 44, 12);
        let last = &rows[rows.len() - 1];
        assert_eq!(
            last.trim(),
            "› installing markdown (2/4)",
            "the bar is the last row, prefixed: {last:?}"
        );
        // Nothing leaked into the row above it — one line means one line.
        assert!(
            !rows[rows.len() - 2].contains("installing"),
            "the bar must not wrap into the input box: {:?}",
            rows[rows.len() - 2]
        );
        assert!(
            rows.iter().any(|r| r.contains("hello")),
            "the transcript is still drawn above it"
        );
        assert!(
            rows.iter().any(|r| r.contains("Ctrl+c")),
            "the input box is still drawn, hint and all: {rows:?}"
        );
    }

    /// The bar's row is reserved from the first frame, so the transcript does
    /// not jump down the first time something is reported.
    #[test]
    fn the_status_row_is_reserved_before_anything_is_said() {
        let mut app = App::default();
        app.push(Role::User, "hello".into());
        let without = rows_of(&mut app, 44, 12);
        app.set_status_text("ready", StatusKind::Done);
        let with = rows_of(&mut app, 44, 12);
        assert_eq!(
            without[..without.len() - 1],
            with[..with.len() - 1],
            "only the bar's own row may differ"
        );
        assert!(
            without.last().unwrap().trim().is_empty(),
            "an unset bar is an empty row, not a missing one"
        );
    }

    /// A status too long for the row is cut at the edge rather than wrapped —
    /// a bar that grows is not a bar.
    #[test]
    fn an_over_long_status_is_clipped_to_one_row() {
        let mut app = App::default();
        app.set_status_text("x".repeat(200), StatusKind::Info);
        let rows = rows_of(&mut app, 20, 8);
        let last = &rows[rows.len() - 1];
        assert!(last.starts_with(STATUS_PREFIX.trim_end()), "{last:?}");
        assert_eq!(
            last.chars().filter(|c| *c == 'x').count(),
            20 - STATUS_PREFIX_CELLS,
            "the text is cut at the right edge, not wrapped"
        );
        assert!(
            rows[..rows.len() - 1].iter().all(|r| !r.contains('x')),
            "and no part of it appears on any other row: {rows:?}"
        );
    }

    /// `App` draws the handle it was given, so a producer holding a clone and
    /// the frame drawing the bar need no wiring between them.
    #[test]
    fn the_screen_and_a_producer_share_one_line() {
        let line = StatusLine::new();
        let mut app = App::default();
        app.set_status(line.clone());
        line.warn("grammar wasm unavailable");
        assert_eq!(
            rows_of(&mut app, 44, 10).last().unwrap().trim(),
            "› grammar wasm unavailable"
        );
        // And `App` can speak for itself, for the messages the loop owns.
        app.set_status_text("ready", StatusKind::Done);
        assert_eq!(line.get().unwrap().text, "ready");
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

    /// The whole path, from a pixel to a verdict: the cells the dialog draws its
    /// answers in are the cells whose click reports that answer.
    ///
    /// Read out of the rendered frame rather than computed, because the two ends
    /// of this — the border the title is drawn inside and the arithmetic that
    /// steps over it — are the only place a real off-by-one can hide, and the
    /// panel-level test that covers the geometry would not notice if the *frame*
    /// laid the row out somewhere else.
    #[test]
    fn clicking_a_drawn_answer_reports_that_answer() {
        let mut app = App::default();
        for op in [
            PanelOp::Create {
                id: 1,
                title: "cat /etc/hostname".into(),
                boxed: true,
                conceal_box: false,
            },
            PanelOp::Append {
                id: 1,
                text: "hostname\n".into(),
            },
            PanelOp::Overlay {
                id: 1,
                text: Some("The process want to read /etc/hostname".into()),
                always: true,
            },
        ] {
            app.panel.apply_op(op);
        }
        let (w, h) = (56u16, 20u16);
        let rows = rows_of(&mut app, w, h);
        let click = |col, row| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: col,
            row,
            modifiers: KeyModifiers::NONE,
        };

        for (label, key) in [("[y]es", 'y'), ("[n]o", 'n'), ("[a]lways", 'a')] {
            let row = rows
                .iter()
                .position(|l| l.contains(label))
                .unwrap_or_else(|| panic!("{label} is on screen: {rows:?}"));
            let title = &rows[row];
            let col = title[..title.find(label).expect("drawn")].chars().count() as u16;
            assert_eq!(
                app.handle_mouse(click(col, row as u16)),
                Click::Answer(key),
                "a click on the drawn {label} is a {key}"
            );
        }

        // The gap between two of them is not one of them, and must not quietly
        // answer the nearest — the click that decides a permission had better be
        // deliberate.
        let row = rows
            .iter()
            .position(|l| l.contains("[y]es"))
            .expect("drawn");
        // Cells, not bytes: `·` is two bytes wide and one cell, so the byte
        // offset of the separator is one column further right than it looks.
        let title = &rows[row];
        let at = title.find(" · ").expect("the separator is drawn");
        let gap = title[..at].chars().count() as u16;
        assert_eq!(
            app.handle_mouse(click(gap, row as u16)),
            Click::Nothing,
            "the gap answers nothing"
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
