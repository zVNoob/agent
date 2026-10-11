//! The agent binary: the chat TUI, the event loop, and the tool rounds that
//! connect them.
//!
//! This milestone wires the LLM client into the TUI:
//!   - type a message, press Enter, and the model's streamed answer renders
//!     live in the turn panel inside its own borderless "response" block;
//!     reasoning streams live into a separate borderless "reasoning" block
//!     above it, dimmed so the thinking reads darker than the answer (tool
//!     calls keep their framed, click-collapsible boxes; both streamed
//!     blocks follow the markup-conceal toggle like plain messages, so Alt+c
//!     hides markers inside them too),
//!   - when the model requests a tool, the agent runs it as a Lua coroutine on
//!     the config VM (`ToolRun`) — the `bash` tool reaches the seccomp sandbox
//!     through `agent.bash`, under the Lua policy in `lua/policy.lua` — and
//!     `Ctrl+c` interrupts that run through a per-run flag, not a signal;
//!   - the result is fed back as a `tool` message and the continuation is
//!     streamed. A turn chains as many tool rounds as the model asks for —
//!     there is no round cap, because a cap silently truncated real work; a
//!     runaway loop is stopped by the user instead (`Ctrl+c` ends the *turn*,
//!     not just the tool it was watching).
//!
//! Key semantics: Enter mid-turn is ignored (the typed text stays in the
//! input and submits once the current turn ends). `Ctrl+d` leaves and `Ctrl+c`
//! interrupts the running tool *and ends the turn*; every other key — `Enter`,
//! `Esc`, `q`, the scroll keys — is bound in Lua, because a keybinding table
//! that Rust could override would make config unreachable (see
//! `src/tui/mod.rs`).
//! `/reload` re-reads the user config (`~/.config/agent/init.lua`) — endpoint,
//! system prompt, `agent.mcps` tools — without restarting; `/save` flushes the
//! conversation log to disk and reports where it went. Nothing else is a local
//! command.
//!
//! The bottom of the screen is a one-line status bar (`agent::status`), which is
//! where anything *in progress* goes: `streaming...` while a turn's answer is
//! arriving, grammar acquisition, which runs before the first frame and is
//! seconds of download and C compile on a cold cache, and Lua's `print`, which is
//! re-pointed there so it cannot land in the middle of the alternate screen. The
//! bar exists before the TUI does, so a message set during startup is on screen
//! the moment there is a screen.
//!
//! A turn is **driven by Lua** — its tool loop included. On a submission or
//! an `agent.trigger` inference, the loop fires a `turn` event carrying
//! `{ history = {...} }`; the registered handler (`agent.main_turn` in the
//! shipped tree) drives each request through `agent.turn` — polling its queue
//! between `agent.on_timeout` waits, so the loop keeps rendering while the
//! model streams — draws the reasoning/response blocks, and when the answer
//! wants tools it suspends on `agent.await_tools(turn)`: the loop folds the
//! turn into the history and runs the round (asks, panels, Ctrl+C — the
//! mechanics stay here), then resumes the handler with the results. Handler
//! and tool coroutines never run nested; the loop alternates them. The
//! handler's return value is the turn's final answer. With no `turn` handler
//! registered the loop drives requests itself, the built-in default — events
//! are opt-in.
//!
//! Compaction primitives: after a full user turn ends, the loop fires
//! `turn_completed` (the conversation travels as `{ history = {...} }`) to
//! any `agent.on_event` handler — driven as a coroutine **cooperatively on
//! the loop's own single thread** (each `agent.on_timeout` wait suspends the
//! handler instead of freezing the TUI; the old background thread is gone) —
//! and Lua can force the next inference with `agent.trigger(...)` — an array
//! argument replaces the in-memory history first. History itself stays
//! Rust-owned here; Lua reads it via the event payload and writes it via the
//! trigger replacement.
//!
//! Persistence: the loop archives every history message to an append-only,
//! block-compressed log (`agent::memory`, opened at startup from
//! `agent.llm.memory` — path + on/off — and shared behind a mutex with
//! Lua's `agent.memory` primitives). Each message is logged exactly once via
//! a watermark and flushed at turn boundaries and on exit (`/save` flushes
//! early); compaction shrinks only the in-memory history, never the archive.
//! On startup a fresh session *continues* from the log: the newest
//! [`REPLAY_BLOCKS`] blocks are replayed into the transcript and the request
//! history (the watermark starts past them, so nothing is re-archived). Blocks,
//! not messages — see [`REPLAY_BLOCKS`]. That window bounds the model's context
//! and what is resident at once, not how far back the transcript can be read:
//! scrolling up past it pages older blocks out of the log as they are reached
//! (`paging`).
//!
//! Tool panels are archived too — as the [`agent::panels::PanelOp`]s that drew
//! them, spliced into the log where they sat in the transcript — so a resumed
//! session shows the before/after of every past patch rather than the model's
//! words with the tools that produced them silently missing. A log written
//! before that existed has no panel records and resumes as it always did; there
//! is no second, guess-at-it reconstruction.
//! All server-communicating logic lives in `api`; rendering and interaction
//! state live in `agent::tui`; the terminal setup mirrors `bin/chat.rs`.

use agent::api::Chat;
use agent::grammars::Catalog;
use agent::status::StatusKind;
use agent::tui::{Action, App, Click, Effect, MarkdownHighlighter, Role};

mod paging;
use anyhow::Result;
use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, Event as CrosstermEvent, EventStream, KeyCode,
    KeyEvent, KeyEventKind, KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures_util::StreamExt;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::{Write, stderr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

const REPLAY_BLOCKS: usize = 2;

const MOUSE_ON: &str = "\x1b[?1000h\x1b[?1006h";
const MOUSE_OFF: &str = "\x1b[?1000l\x1b[?1006l";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Rust ignores SIGPIPE, which turns `agent | head` into a panic on the way
    // out — the caller has gone and the tool dies with "failed printing to
    // stdout" instead of finishing. The default disposition is a silent exit,
    // which is what every other tool in a pipeline does. `unsafe` because
    // `signal` is `signal`; called before any other thread exists.
    //
    // SAFETY: `signal` with SIG_DFL is async-signal-safe, and this runs before
    // the runtime starts any thread of ours.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    // Configuration lives in Lua (~/.config/agent/init.lua, if it exists):
    // the LLM endpoint (base_url / model / api_key — formerly AGENT_BASE_URL /
    // AGENT_MODEL / AGENT_API_KEY), the system prompt, and the tools
    // registered in `agent.mcps`. `config_vm` stays on the main thread: every
    // request reindexes that live table and re-reads the prompt, while
    // per-call MCP tool invocations build their own VM on the tool thread.
    // The configuration is the user's own `~/.config/agent/init.lua`. On the
    // first run there isn't one, so the shipped `lua/init.lua` is copied there
    // and *that* is run — after which the file is theirs to edit, and `/reload`
    // re-reads it. The origin is reported because "a file appeared in your home
    // directory" is worth saying out loud, once, at the moment it happens.
    let (config_vm, origin) =
        agent::lua::new_agent_vm(None).map_err(|e| anyhow::anyhow!("config vm: {e}"))?;
    use agent::lua::ConfigOrigin;
    match origin {
        ConfigOrigin::Seeded => println!(
            "config: seeded ~/.config/agent/init.lua from the built-in one — \
             edit it to configure the agent, /reload to re-read"
        ),
        ConfigOrigin::Existing => {
            println!("config: ~/.config/agent/init.lua (user config loaded)")
        }
        ConfigOrigin::Refreshed => {
            // Said out loud because the file just changed under a user who may
            // have been reading it minutes ago. The rule is narrow — only a seed
            // nobody has edited is ever replaced — but "your configuration
            // updated itself" is not something to discover later.
            println!(
                "config: refreshed ~/.config/agent/init.lua from the shipped one — \
                 it was still the copy this agent seeded, with none of your edits \
                 in it"
            )
        }
        ConfigOrigin::Tree => {
            println!("config: no writable ~/.config/agent — using the built-in defaults")
        }
    }
    let llm = agent::lua::llm_config(&config_vm).map_err(anyhow::Error::msg)?;
    let config = agent::api::ChatConfig {
        base_url: llm.base_url,
        api_key: llm.api_key,
        model: llm.model,
    };
    if config.api_key.is_empty() {
        println!(
            "warning: no api_key in the Lua config; requests will lack an Authorization header"
        );
    }
    let chat = Chat::connect(&config, tool_defs(&config_vm)?);
    println!("model: {} · endpoint: {}", chat.model(), chat.endpoint());

    // The conversation log (save-to-disk): open one `Memory` per process when
    // `agent.llm.memory` enables it, shared behind a mutex with Lua's
    // `agent.memory` primitives — the loop archives every message to it and
    // flushes at turn boundaries and on exit (`/save` flushes early). Binding
    // is a startup decision: `/reload` re-reads the config but cannot rebind
    // the store (like the trigger channel). A failed open degrades to "no
    // persistence" rather than aborting the session.
    let mem_cfg = agent::lua::memory_config(&config_vm).map_err(anyhow::Error::msg)?;
    if mem_cfg.enabled {
        match agent::memory::Memory::open(&mem_cfg.path) {
            Ok(mem) => {
                agent::lua::bind_memory(Arc::new(Mutex::new(mem))).expect("memory log bound once");
                println!(
                    "memory: {} (append-only conversation log; saving to disk)",
                    mem_cfg.path.display()
                );
            }
            Err(e) => println!(
                "warning: conversation log {} failed to open: {e:#}",
                mem_cfg.path.display()
            ),
        }
    } else {
        println!("memory: disabled (agent.llm.memory.enabled = false)");
    }

    // Cold-start replay: a fresh session continues where the last one left
    // off — the newest REPLAY_BLOCKS archived messages become the
    // starting transcript/request history. The loop's save watermark starts
    // past them (see `run`), so the replayed prefix is never re-archived.
    let resumed = match agent::lua::memory_path() {
        Some(p) => cold_start(&p, REPLAY_BLOCKS),
        None => Replayed::empty(),
    };
    let replayed = resumed.records;
    // The conversation resumes into `agent.history` — the table the turn handler
    // reads and appends. This is the one place Rust writes it, once, at startup:
    // the archived prefix is already in the log, so it is a *table*, not an
    // archive, and a session that never turns is a table nothing appends to.
    let resumed_messages = replayed_request_history(&replayed);
    match agent::lua::seed_history(&config_vm, &resumed_messages) {
        Ok(n) if n > 0 => println!("memory: resumed {} archived messages", n),
        Ok(_) => {}
        Err(e) => println!("warning: conversation history not seeded: {e:#}"),
    }

    enable_raw_mode()?;
    // Bracketed paste, so a paste arrives as *one event carrying its text* rather
    // than as a stream of keypresses. Without it, pasting anything with a newline
    // in it sends the first line and delivers the rest as a second message — and
    // the receiver cannot tell that apart from the user pressing Enter, which is
    // why this has to be set by the terminal side and not guessed at here.
    // A terminal that does not support it ignores the sequence and pastes as
    // before, so this is strictly an improvement rather than a requirement.
    execute!(stderr(), EnterAlternateScreen, EnableBracketedPaste)?;
    write!(stderr(), "{MOUSE_ON}")?;
    let _ = stderr().flush();
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
    app.echo = false; // agent semantics: submissions go to the LLM, not a demo echo

    // The one path from Lua (background tool threads, event handlers) into
    // this loop: `agent.trigger` queues a forced inference here — possibly
    // carrying a replaced history, the write side of compaction — and the
    // loop's idle select drains it.
    let (lua_tx, mut lua_rx) = mpsc::unbounded_channel::<agent::lua::AgentCommand>();
    agent::lua::bind_trigger_channel(lua_tx).expect("trigger channel bound once");

    // Grammars come from the registry at runtime (no cargo involvement);
    // missing grammars degrade to plain text, so the TUI still works offline.
    //
    // This runs *before* the first frame, and a cold language is a registry
    // lookup, a tarball and a C compile — seconds of a blank screen otherwise.
    // So it reports through the status line, which exists before the TUI does
    // (see `crate::status`), and the last message is on screen the moment there
    // is a screen. Per language rather than `ensure_many`, so the bar can count
    // and name the step.
    agent::status::attach();
    app.set_status(agent::status::status_line().clone());
    const GRAMMARS: [&str; 4] = ["markdown", "markdown_inline", "bash", "json"];
    let mut catalog = Catalog::new().with_progress(|m| agent::status::info(m.to_string()));
    let mut failed = Vec::new();
    for (i, lang) in GRAMMARS.iter().enumerate() {
        app.set_status_text(
            format!("grammar {}/{}: {lang}", i + 1, GRAMMARS.len()),
            StatusKind::Info,
        );
        if let Err(e) = catalog.ensure(lang).await {
            // Kept up on the bar rather than printed: a failure the user never
            // saw is one they hit again. The content still renders, as text.
            app.set_status_text(
                format!("grammar {lang} unavailable ({e:#}) — that content stays plain"),
                StatusKind::Warn,
            );
            failed.push(lang.to_string());
        }
    }
    if failed.is_empty() {
        app.set_status_text("ready", StatusKind::Done);
    } else {
        agent::status::warn(format!(
            "ready — without highlighting for {}",
            failed.join(", ")
        ));
    }

    // Install the highlighter *before* pushing anything — including the
    // cold-start replay below — so every transcript row (resumed history,
    // the live turn, tool panels) runs through treesitter, not just the
    // messages streamed after the turn starts.
    app.set_highlight(MarkdownHighlighter::from_catalog(&catalog));

    // Render any resumed history before the welcome so the transcript reads
    // chronologically (old conversation first, "agent ready" status after).
    //
    // Tool panels come back with it. They are archived in transcript order (see
    // `splice_panel_records`), so walking the records once rebuilds what the user
    // was looking at — the before/after of every patch, every command's output —
    // rather than a session that shows the model's words with the tools that
    // produced them silently missing. A log written before panels were archived
    // simply has no panel records, and resumes as it always did.
    replay_transcript(&mut app, &replayed);
    // Armed from the *same* window the transcript just read, so the first page
    // starts exactly where that window's oldest record ends. A block boundary is
    // not a record boundary, so asking the log twice where "the last n" is can
    // disagree — and the panel would repeat one record or skip it.
    let mut pager = paging::Pager::new();
    if let Some(p) = agent::lua::memory_path() {
        pager.resume_at(&p, resumed.cursor);
    }
    let system_prompt = match agent::lua::system_prompt(&config_vm) {
        Ok(p) if !p.trim().is_empty() => " · system prompt set".to_string(),
        Ok(_) => " · no system prompt".to_string(),
        Err(_) => String::new(),
    };
    app.push(
        Role::Assistant,
        format!(
            "agent ready — {}{system_prompt} · tools: {}. Type a message and press Enter \
             (/reload re-reads the config; /save flushes the log to disk).",
            chat.model(),
            chat.tools()
                .iter()
                .map(|t| t.function.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );

    let outcome = run(
        &mut terminal,
        &mut rx,
        &mut lua_rx,
        &mut app,
        &config_vm,
        &mut catalog,
        &mut pager,
    )
    .await;

    // Group-commit whatever the loop buffered (a message archived in the same
    // iteration that quit never reached a turn-boundary flush).
    if let Err(e) = agent::lua::memory_flush() {
        eprintln!("[agent] final save to disk failed: {e}");
    }

    reader.abort();
    write!(stderr(), "{MOUSE_OFF}")?;
    disable_raw_mode()?;
    execute!(stderr(), DisableBracketedPaste, LeaveAlternateScreen)?;
    let _ = stderr().flush();
    outcome
}

enum Tick {
    Key(CrosstermEvent),
    Lua(agent::lua::AgentCommand),
    Event(()),
    LuaTurn,
    Pulse,
}

/// Whether pressing `key` submits the input (Enter without Alt).
fn is_submit_key(key: &KeyEvent) -> bool {
    key.code == KeyCode::Enter && !key.modifiers.contains(KeyModifiers::ALT)
}

struct ToolOutcome {
    id: String,
    result: Result<(String, String), String>,
}

struct ToolFlight<'lua> {
    id: String,
    run: agent::lua::ToolRun<'lua>,
    step: agent::lua::ToolStep,
}

impl ToolFlight<'_> {
    /// The call ended in an executor error rather than a result.
    fn failed(&self, why: String) -> ToolOutcome {
        ToolOutcome {
            id: self.id.clone(),
            result: Err(why),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AskChoice {
    Yes,
    No,
    Always,
}

/// What a key does when nothing has been bound to it, and the one rule that is
/// not a key at all: mid-turn, `Enter` is ignored, so a line being typed while
/// the model streams is not submitted and lost. A key explicitly bound to an
/// action skips the rule — it asked for what it asked for, and quietly dropping
/// it is the dead binding the `key` event exists to remove.
fn default_key(app: &mut App, key: crossterm::event::KeyEvent, busy: bool) -> Effect {
    if busy && is_submit_key(&key) {
        Effect::Continue
    } else {
        app.handle_key(key)
    }
}

/// Ask the Lua `key` handler what a key press should do.
///
/// Returns `None` when nothing is bound to it, which is the normal case and
/// means "carry on with the default". An `Err` is a binding that named an action
/// the app does not have, or a handler that failed; the caller reports it and
/// falls through to the default rather than swallowing the key, because a key
/// that does nothing at all is the failure mode that makes a binding table
/// unusable.
///
/// The payload is the whole contract with the Lua side, so it says three things
/// and no more: `spec` — the chord as a binding table writes it, from
/// [`key_spec`], the one spelling a table should match on — `char`, the
/// printable character or null, and the three modifiers. There is deliberately
/// no debug-formatted key name: that is a Rust enum's rendering, it would change
/// whenever crossterm is upgraded, and `spec` already answers the question.
fn resolve_key(vm: &mlua::Lua, key: &crossterm::event::KeyEvent) -> Option<Result<Action, String>> {
    let modifiers = key.modifiers;
    let payload = json!({
        "spec": agent::tui::key_spec(key),
        "char": match key.code {
            KeyCode::Char(c) => Value::String(c.to_string()),
            _ => Value::Null,
        },
        "ctrl": modifiers.contains(KeyModifiers::CONTROL),
        "alt": modifiers.contains(KeyModifiers::ALT),
        "shift": modifiers.contains(KeyModifiers::SHIFT),
    });
    match agent::lua::fire_event_returning(vm, "key", &payload) {
        Ok(None) => None,
        Ok(Some(name)) => Some(Action::parse(&name)),
        Err(why) => Some(Err(why)),
    }
}

/// Act on a verdict: put the answer the tool's coroutine will receive on its
/// next step, and the human-readable outcome on the status bar.
///
/// The decision goes on the status bar, not into the transcript. A cold command
/// asks dozens of times, and a message per answer buried the run it was
/// reporting on; the bar is one line and holds exactly the latest.
///
/// One function for the keyboard and the mouse, so the two cannot disagree —
/// a click and a keypress on the same letter must be the same decision, and
/// the cheapest way to guarantee that is to have only one of them.
fn record_verdict(app: &mut App, choice: AskChoice) -> agent::lua::AskAnswer {
    let answer = match choice {
        AskChoice::Yes => agent::lua::AskAnswer::Allow,
        AskChoice::Always => agent::lua::AskAnswer::AllowAndTrust,
        AskChoice::No => agent::lua::AskAnswer::Deny(Some("denied by user".to_string())),
    };
    let (outcome, kind) = match choice {
        AskChoice::Yes => ("allowed", agent::status::StatusKind::Done),
        AskChoice::Always => ("allowed, and remembered", agent::status::StatusKind::Done),
        AskChoice::No => ("denied", agent::status::StatusKind::Warn),
    };
    app.set_status_text(outcome, kind);
    answer
}

/// The three keys that answer a permission question, mapped to the three
/// answers. `y` and `n` always answer; `a` only answers when the question
/// offered a third answer — otherwise a stray `a` is not an answer to anything,
/// and treating it as one would remember something the asking side never
/// offered. *Which* third answer is the question's business (`panels::
/// Remember`); the verdict is the same one either way.
///
/// Returns `None` for any other key: while a question is on screen it is the
/// only thing that responds, so a keystroke is never mistaken for input text.
/// The loop's own keys are still live — `Ctrl+c` (stop the command asking) and
/// `Ctrl+d` (leave) — and a Lua key handler is deliberately *not* consulted
/// here, so a table cannot redirect a verdict.
fn ask_choice(code: KeyCode, remember: &agent::panels::Remember) -> Option<AskChoice> {
    match code {
        KeyCode::Char('y') | KeyCode::Char('Y') => Some(AskChoice::Yes),
        KeyCode::Char('n') | KeyCode::Char('N') => Some(AskChoice::No),
        KeyCode::Char('a') | KeyCode::Char('A') if remember.is_some() => Some(AskChoice::Always),
        _ => None,
    }
}

async fn next_event(event_rx: &mut Option<mpsc::UnboundedReceiver<()>>) -> Option<()> {
    match event_rx {
        Some(rx) => rx.recv().await,
        None => futures_util::future::pending().await,
    }
}

/// Start the next queued tool call, on `vm` and on this thread.
///
/// The call becomes a Lua coroutine on the agent's own config VM
/// ([`agent::lua::ToolRun`]) and the loop drives it to completion — so there is
/// no executor thread, no second VM, and state a tool writes (a path trusted
/// with `[a]lways`, a mode it switched) is still there on the next call. The
/// round's panel sink is installed on the VM for the duration, so a tool's
/// panels land in this round's transcript; panel ops buffer as the tool works
/// and the loop drains the sink every frame, which is what makes a long bash
/// command's output appear *live* instead of hanging until it completes.
///
/// Returns the call's first step, or the outcome of a call that never started —
/// a tool the model was not offered is refused here rather than looked up.
fn start_next_tool<'lua>(
    vm: &'lua mlua::Lua,
    tool_queue: &mut VecDeque<(String, String, String)>,
    round_sink: Option<&agent::panels::PanelSink>,
    offered: std::collections::HashSet<String>,
) -> Result<(Option<ToolFlight<'lua>>, Option<ToolOutcome>), String> {
    let Some((id, name, arguments)) = tool_queue.pop_front() else {
        return Ok((None, None));
    };
    let refused = |why: String| {
        (
            None,
            Some(ToolOutcome {
                id: id.clone(),
                result: Err(why),
            }),
        )
    };
    // Only what the model was actually offered may run. The registry the tool
    // is looked up in is the live one, reloaded by `/reload` — but a tool the
    // model was not shown (a mode replaced the registry, an old tool call
    // replayed out of the history) must not become runnable by naming itself.
    // The offered set is the request's own tool list, captured before the call
    // was queued.
    if let Err(why) = may_run(&name, &offered) {
        return Ok(refused(why));
    }
    if let Some(s) = round_sink {
        agent::lua::install_sink(vm, s).map_err(|e| format!("panel sink: {e}"))?;
    }
    match agent::lua::ToolRun::start(vm, &name, &arguments) {
        Ok(Some((run, step))) => Ok((Some(ToolFlight { id, run, step }), None)),
        // The registry holds no such tool. It is the only place a tool can come
        // from, so there is nothing to fall back to.
        Ok(None) => Ok(refused(format!(
            "no tool named '{name}' is registered in agent.mcps"
        ))),
        Err(e) => Ok(refused(e)),
    }
}

/// Advance the tool in flight by at most one step and report whether the call is
/// over.
///
/// `verdict` answers the question currently on screen (the user pressed a key
/// that decides it). With no verdict, a call suspended on a reactor wait takes
/// its next step — that is the 50ms pulse's job, and it is what keeps a long
/// sandbox run from blocking the loop: the run yields between idle steps rather
/// than sleeping in `agent.api.step`. A call suspended on a *question* with no
/// verdict is left alone, because the user has not decided yet.
///
/// A question becomes [`PendingQuestion`], which the loop draws; the ask's own
/// `always` rides along as the name of the third answer, so a grant with a
/// narrower life than "always" keeps it and the dialog says so.
fn advance_tool(
    flight: &mut ToolFlight<'_>,
    verdict: Option<mlua::Value>,
) -> Result<(Option<ToolOutcome>, Option<PendingQuestion>), String> {
    use agent::lua::ToolStep;
    if let Some(v) = verdict {
        flight.step = flight.run.answer(v).map_err(|e| e.to_string())?;
    } else if matches!(flight.step, ToolStep::Waiting { .. }) {
        flight.step = flight.run.wait().map_err(|e| e.to_string())?;
    }
    Ok(match &flight.step {
        ToolStep::Returned(body) => (
            Some(ToolOutcome {
                id: flight.id.clone(),
                result: Ok((body.clone(), body.clone())),
            }),
            None,
        ),
        ToolStep::Ask { text, remember } => (
            None,
            Some(PendingQuestion {
                text: text.clone(),
                remember: remember.clone(),
            }),
        ),
        // Waiting: nothing to show, and the pulse brings us back.
        ToolStep::Waiting { .. } => (None, None),
    })
}

/// Fold a finished tool call into the conversation: the `tool` message the
/// model reads back, and whatever the tool drew, drained here so it all lands at
/// once.
///
/// **A tool call puts nothing in the transcript.** Not its arguments, not its
/// result, not an error. There was a box per call for exactly that, and it was
/// the wrong shape twice over: it repeated the output of any tool that already
/// had a panel, and for the ones that did not it was a wall of raw JSON
/// arguments and result envelopes — the loudest thing on screen, and the least
/// informative.
///
/// A tool is therefore **responsible for its own reporting**, which is also the
/// only arrangement that can be formatted properly. `agent.panel` is the
/// mechanism, and the shell is the worked example: it opens a panel titled with
/// the command and appends stdout as it arrives. A tool that wants to be seen
/// draws itself; a tool that wants to be quiet is quiet.
///
/// That includes failure. A tool that fails says so, in whatever form suits it.
/// If a tool fails silently, so be it — the model reads the error in `history`
/// either way, and the transcript is the model's account rather than a duplicate
/// of the wire format.
///
/// The consequence to be aware of: a tool that draws nothing is invisible, and
/// nothing in the loop will draw for it.
/// What a finished tool call says, as the `(id, content)` pair the suspended
/// `turn` handler gets back from its `agent.await_tools` yield.
///
/// The loop does *not* put the result in the conversation: the handler does,
/// from this same pair, through `agent.api.history_append` — which archives it as
/// it appends. What leaves the loop is the content alone.
fn tool_result(outcome: ToolOutcome) -> (String, String) {
    let ToolOutcome { id, result, .. } = outcome;
    let content = match result {
        Ok((_body, content)) => content,
        Err(msg) => json!({"error": msg}).to_string(),
    };
    (id, content)
}

/// Archive the panel ops a round has drawn, as they drain.
///
/// Straight to the log, with no buffer and no splice position: a panel is
/// written where it happens, and the messages around it are written where
/// *they* happen — the handler appends the round's text and calls before it hands
/// the round over, and the results when they come back. So the log order is the
/// transcript's own order: the words, then the panels, then the results.
///
/// The splice that used to place panels *before* the request that started them
/// existed because Rust buffered panels and messages separately and drained both
/// at the end of a frame; nothing buffers now.
///
/// A failure to write is reported and dropped: the panels are on screen, and the
/// transcript is rebuilt from reasoning records and assistant messages either
/// way, so an I/O error must not take the loop down with it.
fn archive_panel_ops(ops: Vec<agent::panels::PanelOp>) {
    if ops.is_empty() {
        return;
    }
    let records: Vec<serde_json::Value> = ops.iter().map(agent::panels::panel_record).collect();
    if let Err(e) = agent::lua::memory_append_many(&records) {
        eprintln!("[agent] save to disk failed (panels): {e}");
    }
}

struct PendingQuestion {
    text: String,
    remember: agent::panels::Remember,
}

/// The per-request tool catalog: exactly what the user's `agent.mcps` registry
/// holds, and nothing else — the sandboxed shell included (`lua/bash_tool.lua`
/// is a connection like any other, so a mode that lists no connections offers
/// the model no tools at all). `vm` is the config VM — the live Lua table is
/// reindexed on every call and **never cached in Rust**, so a config edit
/// (picked up by `/reload`) is advertised on the very next request (see
/// `agent::lua`'s config section).
fn tool_defs(vm: &mlua::Lua) -> Result<Vec<agent::api::ToolDef>> {
    Ok(agent::tools::adopt_mcp_tools(
        agent::lua::mcps_tool_defs(vm).map_err(anyhow::Error::msg)?,
    ))
}

#[derive(Default)]
struct GrammarQueue {
    pending: VecDeque<String>,
    asked: std::collections::HashSet<String>,
    fetching: bool,
}

impl GrammarQueue {
    /// Note that something on screen asked for `lang`. `false` if already asked
    /// for, in which case it is not queued again.
    fn request(&mut self, lang: String) -> bool {
        if self.asked.insert(lang.clone()) {
            self.pending.push_back(lang);
            true
        } else {
            false
        }
    }

    /// The next language to fetch, or `None` if none is waiting or one is already
    /// in flight. Marking it in flight is what serialises them: two concurrent
    /// `cc` runs would fight for the CPU the frame is trying to draw on.
    fn take_next(&mut self) -> Option<String> {
        if self.fetching {
            return None;
        }
        let lang = self.pending.pop_front()?;
        self.fetching = true;
        Some(lang)
    }

    /// A fetch reported back. Returns whether it succeeded.
    ///
    /// The unconditional `fetching = false` is the whole point: a task that only
    /// reported success would leave this `true` and everything behind it stuck.
    fn finish(&mut self, ok: bool) -> bool {
        self.fetching = false;
        ok
    }
}

enum GrammarOutcome {
    Ready(String),
    Failed(String, String),
}

/// Whether a tool call may run: only a name this request actually offered.
///
/// A tool is called by name against the *live* registry, so "not advertised"
/// is not by itself "not callable" — a mode that replaced `agent.mcps`, an
/// unregistered tool, or an old tool call replayed out of the history would
/// each find a working tool by name. The request's own tool list is the gate,
/// so what the model was shown is exactly what it can run.
fn may_run(name: &str, offered: &std::collections::HashSet<String>) -> Result<(), String> {
    if offered.contains(name) {
        Ok(())
    } else {
        Err(format!(
            "`{name}` is not one of the tools offered for this request"
        ))
    }
}

/// Re-derive the advertised tool list from the live registry, at the start of
/// every turn.
///
/// This is the dispatch gate (`may_run`): a call the model invented — or one the
/// registry no longer offers after a `/reload` — never runs. Reindexing per turn
/// is what keeps a config edit immediate, and it is why the loop needs no cached
/// copy of anything `agent.mcps` says.
fn refresh_offered(vm: &mlua::Lua) -> Result<std::collections::HashSet<String>> {
    Ok(tool_defs(vm)?
        .into_iter()
        .map(|t| t.function.name)
        .collect())
}

/// Start the `turn_completed` event after a full user turn: hands the
/// conversation (the read side of compaction) to any
/// `agent.on_event("turn_completed", ...)` handler — driven **cooperatively
/// on the loop's own thread** as a coroutine (see `agent::lua::EventRun`),
/// strictly single-threaded.
///
/// The handler runs on `vm` — the *config* VM, the one this loop reads the
/// system prompt and the tool registry from — so what it configures is what the
/// next turn uses: a mode it switches, a setting it writes, a flag it arms to
/// carry state to the next event. Each `agent.on_timeout(...)` wait suspends the
/// coroutine and arms a reactor timer instead of freezing the loop, and its
/// `agent.trigger(...)` command arrives back here through the trigger channel.
fn start_turn_completed<'a>(
    vm: &'a mlua::Lua,
    event: &mut Option<agent::lua::EventRun<'a>>,
    event_rx: &mut Option<mpsc::UnboundedReceiver<()>>,
) {
    // No payload: the conversation is `agent.history`, which a handler reads
    // directly. There is nothing to hand it that it cannot already see.
    match agent::lua::EventRun::start(vm, "turn_completed", &json!({})) {
        Ok(Some((run, step))) => match step {
            // The handler suspended on a timer (pump cadence, a sleep, ...):
            // keep the coroutine alive and arm the reactor timer; the loop
            // resumes it when the timer fires.
            agent::lua::EventStep::Waiting { ms } => {
                *event = Some(run);
                *event_rx = Some(start_event_timer(ms));
            }
            // No wait: the handler already ran to completion inside `start`.
            agent::lua::EventStep::Returned => {}
            // `agent.await_tools` suspends only the `turn` handler — the round
            // is driven by the turn's machinery, and a `turn_completed`
            // handler has none to drive it with.
            agent::lua::EventStep::Tools { .. } => {
                eprintln!(
                    "[agent] event turn_completed: agent.await_tools can only suspend the turn handler"
                );
            }
        },
        Ok(None) => {} // no turn_completed handler registered: events are opt-in
        Err(e) => eprintln!("[agent] event turn_completed: {e}"),
    }
}

/// Arm a one-shot reactor timer that pokes the loop's event channel after
/// `ms` milliseconds. The timer task itself is spawned (it is plain Send
/// work); the handler coroutine — and its `Lua` state — never leave the main
/// thread.
fn start_event_timer(ms: u64) -> mpsc::UnboundedReceiver<()> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        let _ = tx.send(());
    });
    rx
}

/// Start a turn as a Lua `turn` event: the handler (`agent.on_event("turn", …)`
/// — `agent.main_turn` in the shipped tree) runs the whole turn on
/// `agent.history`, drawing each request's stream into the transcript as it
/// arrives and appending every message to the conversation and to the log.
///
/// `text` is the user's line, or `None` for a turn nobody asked for — an
/// `agent.trigger()` with no argument. The handler records it as a user message;
/// the loop's part was echoing it to the transcript, which has already happened
/// by the time this fires.
///
/// There is no built-in fallback: the loop no longer knows how to hold a
/// conversation, so a turn with no handler registered is reported and dropped.
/// The shipped tree registers one (`lua/lib/main_turn.lua`), and a config that
/// replaces it with nothing is told so in as many words.
///
/// Same cooperative-coroutine shape as `turn_completed` (the handler suspends on
/// `agent.on_timeout` waits while the loop keeps rendering), but its own pair of
/// slots: a suspended `turn_completed` handler may legitimately span into the
/// turn that follows it, and one slot would have each clobber the other.
fn start_lua_turn<'a>(
    vm: &'a mlua::Lua,
    text: Option<&str>,
    app: &mut App,
    turn_event: &mut Option<agent::lua::EventRun<'a>>,
    turn_sink: &mut Option<agent::panels::PanelSink>,
    pending_turn_step: &mut Option<agent::lua::EventStep>,
    next_panel_id: u64,
) {
    let payload = json!({ "text": text });
    // The sink goes on before the first resume: the handler can draw before its
    // first wait (a fast server, a large first chunk), and an op emitted with no
    // sink to catch it goes nowhere.
    let sink = agent::panels::PanelSink::continuing_from(next_panel_id);
    if let Err(e) = agent::lua::install_sink(vm, &sink) {
        app.push_boxed(Role::Assistant, format!("panel sink: {e}"), "error".into());
        return;
    }
    match agent::lua::EventRun::start(vm, "turn", &payload) {
        Ok(Some((run, step))) => {
            *turn_sink = Some(sink);
            // The bar is the only place that says a request is live — the first
            // chunk can take a while, with the last frame still up.
            app.set_status_text("streaming...", StatusKind::Info);
            *turn_event = Some(run);
            // The first step is handled where every later step is — at the top of
            // the next pass — so a handler that suspends on its tools *immediately*
            // (a replay, a canned round) starts the same round a streamed answer
            // would.
            *pending_turn_step = Some(step);
        }
        Ok(None) => {
            let _ = agent::lua::clear_sink(vm);
            app.push_boxed(
                Role::Assistant,
                "no `turn` event handler: nothing can run a turn — see \
                 lua/lib/main_turn.lua (agent.main_turn is the shipped one)"
                    .into(),
                "error".into(),
            );
        }
        Err(e) => {
            let _ = agent::lua::clear_sink(vm);
            app.push_boxed(Role::Assistant, format!("turn failed: {e}"), "error".into());
        }
    }
}

/// Take down the Lua turn's drawing state: the sink comes off the VM (a panel
/// opened with no round in flight must reach no panel), its last ops drain to
/// the transcript, and its id counter carries forward so the next round's
/// first panel never reuses an id this turn handed out.
///
/// The drained ops are *not* archived — unlike a tool round's. The reasoning
/// and response blocks the handler draws are reconstructed on resume from the
/// archived reasoning records and the assistant message, and logging the ops
/// too would draw every streamed block twice.
fn teardown_turn_sink(
    vm: &mlua::Lua,
    app: &mut App,
    turn_sink: &mut Option<agent::panels::PanelSink>,
    next_panel_id: &mut u64,
) {
    let _ = agent::lua::clear_sink(vm);
    if let Some(s) = turn_sink.take() {
        app.drain_panel_ops(&s);
        *next_panel_id = s.next_id();
    }
}

/// What a finished request cost and how fast it answered, in the two places
/// that read it: `agent.llm.usage` (so a `turn_completed` handler reads the
/// request that just finished) and the summary line. Per round for a
/// Lua-driven turn, per request for a built-in one.
fn note_turn_meta(vm: &mlua::Lua, app: &mut App, turn: &agent::api::Turn) {
    agent::lua::record_usage(vm, turn.tokens());
    // The answer content was already streamed live into its block; do not
    // push it again. The summary line (tokens, tok/s) is not part of it.
    if let Some(summary) = turn.summary() {
        app.push(Role::Assistant, summary);
    }
}

#[allow(clippy::too_many_arguments)]
fn begin_tool_calls<'a>(
    vm: &'a mlua::Lua,
    turn: &agent::api::Turn,
    offered: &std::collections::HashSet<String>,
    tool_queue: &mut VecDeque<(String, String, String)>,
    tool_flight: &mut Option<ToolFlight<'a>>,
    pending_outcome: &mut Option<ToolOutcome>,
    round_sink: &mut Option<agent::panels::PanelSink>,
    next_panel_id: &mut u64,
) -> Result<()> {
    *tool_queue = turn
        .tool_calls
        .iter()
        .map(|c| (c.id.clone(), c.name.clone(), c.arguments.clone()))
        .collect();
    // `continuing_from`, not a fresh sink: a panel id is scoped to the
    // transcript's id→message map, which outlives the round, so a counter that
    // restarted here would hand round two's first panel an id round one had
    // already used — and it would be appended to *that* panel, putting a write's
    // content and its dialog in the read box above it.
    *round_sink = Some(agent::panels::PanelSink::continuing_from(*next_panel_id));
    // A call that never started (refused by the dispatch gate, or not in the
    // registry) lands in `pending_outcome` and takes the same finish path a
    // completed call does.
    let (started, refused) = start_next_tool(vm, tool_queue, round_sink.as_ref(), offered.clone())
        .map_err(anyhow::Error::msg)?;
    *tool_flight = started;
    *pending_outcome = refused;
    Ok(())
}

struct TurnDrive<'a, 'lua> {
    vm: &'lua mlua::Lua,
    app: &'a mut App,
    offered: &'a std::collections::HashSet<String>,
    stop_turn: &'a mut bool,
    tool_queue: &'a mut VecDeque<(String, String, String)>,
    tool_flight: &'a mut Option<ToolFlight<'lua>>,
    pending_outcome: &'a mut Option<ToolOutcome>,
    round_sink: &'a mut Option<agent::panels::PanelSink>,
    next_panel_id: &'a mut u64,
    event: &'a mut Option<agent::lua::EventRun<'lua>>,
    event_rx: &'a mut Option<mpsc::UnboundedReceiver<()>>,
    turn_event: &'a mut Option<agent::lua::EventRun<'lua>>,
    turn_event_rx: &'a mut Option<mpsc::UnboundedReceiver<()>>,
    turn_sink: &'a mut Option<agent::panels::PanelSink>,
    round_results: &'a mut Option<Vec<(String, String)>>,
}

/// Report a turn that failed before it produced anything to fold, and take
/// its drawing state down — the same close the normal return path runs, with
/// nothing to show for the request but the message.
fn fail_turn<'a, 'lua: 'a>(d: &mut TurnDrive<'a, 'lua>, msg: String) {
    *d.turn_event = None;
    *d.turn_event_rx = None;
    teardown_turn_sink(d.vm, d.app, d.turn_sink, d.next_panel_id);
    d.app.clear_status();
    d.app.push_boxed(Role::Assistant, msg, "error".into());
    close_turn(d);
}

/// The user turn is over: fire `turn_completed` so a Lua handler can inspect the
/// conversation and compact it (see `lua/init.lua` §7). Every path that ends a
/// turn comes through here — a returned answer, a stopped round, a failure — so
/// it fires exactly once whatever the turn ended as.
fn close_turn<'a, 'lua: 'a>(d: &mut TurnDrive<'a, 'lua>) {
    start_turn_completed(d.vm, d.event, d.event_rx);
}

/// Advance the Lua-driven turn by one handler step, looping while the handler's
/// own answer immediately produces the next step (a malformed yield's report, a
/// stopped round's resume). Returns when the handler is parked — on a timer, or
/// on the tool round now in flight — or finished.
///
/// This is the *whole* contract between the loop and the `turn` handler:
///
/// - `Waiting` — arm the reactor timer; the tick resumes the pump.
/// - `Tools` — the answer wanted tools: note what the round cost, run it, and
///   park the handler until the last outcome lands. Handler and tool coroutines
///   never run nested — the loop alternates them, which is the re-entrancy
///   answer for a tool loop written in Lua.
/// - `Returned` — the assembled final turn (or the stopped sentinel) closes the
///   user turn out.
fn drive_lua_turn<'a, 'lua: 'a>(
    d: &mut TurnDrive<'a, 'lua>,
    mut step: Option<Result<agent::lua::EventStep, String>>,
) -> Result<()> {
    loop {
        match step {
            Some(Ok(agent::lua::EventStep::Waiting { ms })) => {
                *d.turn_event_rx = Some(start_event_timer(ms));
                return Ok(());
            }
            Some(Ok(agent::lua::EventStep::Tools { turn: table })) => {
                // The handler parks on the round — its last timer is spent.
                // Clearing the receiver is not hygiene: a spent unbounded
                // receiver's sender is gone (the timer task drops it after
                // firing), so `recv` answers `None` *immediately* rather than
                // pending — and the select arm maps any completed recv to
                // `Tick::LuaTurn`, which would resume the parked handler with
                // `true` (a busy loop of spurious ticks, the first of which
                // crashes the handler on its boolean `round`). The select may
                // only ever see a live timer. The round's own machinery —
                // pulses, keys, the outcome fold — wakes the loop from here.
                *d.turn_event_rx = None;
                let (turn, _reasoning) = match agent::lua::turn_from_lua(mlua::Value::Table(table))
                {
                    Ok(pair) => pair,
                    Err(e) => {
                        fail_turn(d, format!("turn failed: {e}"));
                        return Ok(());
                    }
                };
                // What the round cost, and `agent.llm.usage` showing the request
                // that just finished — which is what the compaction policy reads to
                // know the conversation is near the window's edge. Reasoning is not
                // recorded here: the handler is the code that received it, and it
                // archived it.
                note_turn_meta(d.vm, d.app, &turn);
                if *d.stop_turn {
                    // Stopped before the round began: tell the handler, and it ends
                    // the turn by returning the sentinel back. Nothing is answered —
                    // the calls were never run.
                    let reply = agent::lua::stopped_reply(d.vm).map_err(anyhow::Error::msg)?;
                    step = d.turn_event.as_mut().map(|run| run.resume_value(reply));
                    continue;
                }
                *d.round_results = Some(Vec::new());
                begin_tool_calls(
                    d.vm,
                    &turn,
                    d.offered,
                    d.tool_queue,
                    d.tool_flight,
                    d.pending_outcome,
                    d.round_sink,
                    d.next_panel_id,
                )?;
                // The handler parks until the round's last outcome lands — the
                // resume comes from the loop's tool-finish path.
                return Ok(());
            }
            Some(Ok(agent::lua::EventStep::Returned)) => {
                let mut run = d.turn_event.take().expect("stepped Some");
                *d.turn_event_rx = None;
                let returned = run.take_returned();
                teardown_turn_sink(d.vm, d.app, d.turn_sink, d.next_panel_id);
                d.app.clear_status();
                match returned.map(agent::lua::turn_reply_from_lua) {
                    Some(Ok(agent::lua::TurnReply::Stopped)) => {
                        // The round ran and was interrupted; the handler closed the
                        // turn out by returning the sentinel. Say so and end it.
                        d.app.push(
                            Role::Assistant,
                            "stopped: you interrupted this turn.".to_string(),
                        );
                        d.app.set_status_text("turn stopped", StatusKind::Warn);
                    }
                    Some(Ok(agent::lua::TurnReply::Turn(turn, _reasoning))) => {
                        // What the turn cost and how fast it answered. The handler
                        // has already appended it to the conversation and the log.
                        note_turn_meta(d.vm, d.app, &turn);
                    }
                    Some(Err(e)) => d.app.push_boxed(Role::Assistant, e, "error".into()),
                    // A handler that answered nil drove nothing: say so, because a
                    // turn that silently did not happen looks like a lost message.
                    None => d.app.push_boxed(
                        Role::Assistant,
                        "turn failed: the `turn` handler returned nothing \
                         (agent.on_event(\"turn\", …) must return the \
                         assembled turn — see lua/lib/main_turn.lua)"
                            .into(),
                        "error".into(),
                    ),
                }
                close_turn(d);
                return Ok(());
            }
            Some(Err(e)) => {
                fail_turn(d, format!("turn failed: {e}"));
                return Ok(());
            }
            None => {
                *d.turn_event_rx = None;
                return Ok(());
            }
        }
    }
}

/// Rebuild the transcript from archived records, oldest first.
///
/// Tool panels come back with it. They are archived in transcript order (see
/// [`splice_panel_records`]), so one pass rebuilds what the user was looking at —
/// the before/after of every past patch, every command's output — rather than a
/// session that shows the model's words with the tools that produced them
/// silently missing, which is what this used to do.
///
/// A log written before panels were archived has no panel records and resumes as
/// it always did. There is deliberately no second reconstruction from the call's
/// arguments and result: a panel rebuilt from those would be a plausible
/// impostor of one that was archived, and a drawing that is not the drawing is
/// worse than an absent one.
///
/// A free function so a test can drive the same path `main` does — the loop
/// inside `main` is otherwise untestable, and untestable is how this stayed
/// broken for so long.
fn replay_transcript(app: &mut App, records: &[Value]) {
    for msg in records {
        if let Some(op) = agent::panels::panel_record_op(msg) {
            app.panel.apply_op(op);
            continue;
        }
        if msg["kind"].as_str() == Some(agent::panels::REASONING_RECORD) {
            if let Some(text) = msg["text"].as_str() {
                app.stream_append_boxed(text, "reasoning".into());
            }
            continue;
        }
        let Some(role) = msg["role"].as_str() else {
            continue;
        };
        let Some(content) = msg["content"].as_str() else {
            continue;
        };
        match role {
            "user" => app.push(Role::User, content.to_string()),
            // No summary box, deliberately: there was one here once —
            // `invoked tools: read_file, bash` — and a tool round now brings its
            // own panel back, so a summary would be a second, vaguer copy of
            // what the transcript already shows.
            "assistant" => app.push(Role::Assistant, content.to_string()),
            _ => {} // tool results: invisible, as they are live
        }
    }
    // Collapsed, because they are history: a session with a tool per turn has a
    // panel per turn, and expanding them all buries the conversation being
    // resumed under screens of old output. Each is a title and a `[+]`, and the
    // transcript reads as the outline it is. Live panels stay expanded — this
    // runs only on the replay path.
    app.panel.collapse_all_boxes();
}

/// Cold start: the archived records, split into the two things that want them.
///
/// `(transcript, request)` — the first is every record, in log order, so
/// [`replay_transcript`] can rebuild the panels as well as the words; the second
/// is the messages alone, rebuilt for sending.
///
/// **One call, one split, on purpose.** These were two independent reads once,
/// and the panel half was quietly lost: startup read the *messages-only* half for
/// both purposes, so every archived panel was filtered out before the transcript
/// could apply it. Nothing failed — the tests all drove the pieces directly, and
/// the pieces were each correct. It is the one defect that only a test of the
/// *wiring* can catch, so the wiring is the thing that is a function.
fn cold_start(path: &std::path::Path, n: usize) -> Replayed {
    replay_records(path, n)
}

/// The request half of a replay: the messages, with each tool result reduced to
/// one line.
///
/// Two things are dropped or rewritten here, and both matter for what gets
/// *sent*. Panel records are not conversation and must never reach the model; and
/// [`rebuild_tool_results`] replaces each tool result with a one-line record of
/// the call, because a tool result is the bulkiest thing in the log by a wide
/// margin and replaying it verbatim would spend the context on output the model
/// can read again more cheaply.
fn replayed_request_history(records: &[Value]) -> Vec<Value> {
    let messages: Vec<Value> = records
        .iter()
        .filter(|r| !is_transcript_record(r))
        .cloned()
        .collect();
    rebuild_tool_results(messages)
}

/// Whether a record is something the transcript *draws* and the request must not
/// carry: a panel op, or a chunk of streamed reasoning.
///
/// Both are archived so a resumed session looks like the one that ended, and
/// neither belongs in a request. Reasoning is the sharper case — it was never in
/// the conversation history either ("observed only; not kept in history"), so
/// there is no risk of sending it twice; archiving it is purely so the thinking
/// can be read back.
fn is_transcript_record(record: &Value) -> bool {
    matches!(
        record["kind"].as_str(),
        Some(agent::panels::PANEL_RECORD) | Some(agent::panels::REASONING_RECORD)
    )
}

/// Every record of the newest `n` **messages**, in log order, panels included.
///
/// The window is counted in messages and not in lines, because the two no longer
/// agree: a tool round contributes one assistant message, one `tool` message per
/// call, and now a run of panel records between them. Counting lines would make
/// the resumed window shrink as panels were added — the same code, less context
/// each time — so the tail is read generously and then trimmed back to `n`
/// messages from the newest end, which is what the window has always meant.
///
/// Corrupt lines are skipped, never fatal. A panel record this build cannot
/// decode is dropped by [`agent::panels::panel_record_op`], so an op variant
/// added after the log was written costs that one panel and nothing else.
fn replay_records(path: &std::path::Path, blocks: usize) -> Replayed {
    match agent::memory::read_before(path, u64::MAX, blocks) {
        Ok(page) => Replayed {
            records: page
                .records
                .iter()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect(),
            // From the same read as the records, not from a second read asking the
            // log again: the two would disagree about where the window ends, and the
            // disagreement is invisible — the transcript shows a record twice or
            // skips one, and either looks like a rendering fault.
            cursor: page.next,
        },
        Err(e) => {
            eprintln!("[agent] memory replay failed: {e}");
            Replayed::empty()
        }
    }
}

struct Replayed {
    records: Vec<Value>,
    cursor: u64,
}

impl Replayed {
    /// Nothing to show, and nothing older to page in.
    ///
    /// The cursor says so rather than pointing at the end of the log: that offset is
    /// the *start* of a backward walk, and from there a pager with somewhere to read
    /// would walk the entire file looking for a window that does not exist.
    fn empty() -> Self {
        Replayed {
            records: Vec::new(),
            cursor: 0,
        }
    }
}

/// Replace every replayed tool result with a one-line record of the call.
///
/// A tool result is the bulkiest thing in the log by a wide margin — a
/// `fs.read` is a whole file, a `bash` is whatever the command printed — and the
/// replay window is a *count* of messages (20), not a budget of bytes. So the
/// window is really "the last twenty messages, however large", and one archived
/// `cat` of a source file can be most of a cold start's context while telling the
/// model nothing it can use: the bytes are about a repository state that has
/// since moved, and the model is being asked to continue a conversation, not to
/// re-derive a file it can simply read again.
///
/// What is kept is the fact and its cost: which tool ran, and how much output
/// was dropped. That is enough for the model to know the call happened and to
/// re-read if it wants the contents, and it keeps the elision honest rather than
/// silent — a replay that quietly showed nothing at all would be
/// indistinguishable from one where no tool had run.
///
/// The `role` and `tool_call_id` are **not** touched. A `tool` message is only
/// legal immediately after the assistant message that requested it, matched by
/// id, so rewriting it into a `user` message or dropping the id would make the
/// request invalid rather than merely terse. The arguments in that assistant
/// message still name the tool and its target, which is why the summary does not
/// repeat them.
fn rebuild_tool_results(mut msgs: Vec<Value>) -> Vec<Value> {
    // `tool_call_id` -> the tool's name, harvested from the assistant messages as
    // the list is walked. A result with no entry here is one whose requesting
    // assistant message fell outside the replay window, which the ordinary case
    // rather than a rare one: the window is the newest 20 *messages*, so it
    // starts mid-turn whenever the last session ended on a tool round.
    let mut names: HashMap<String, String> = HashMap::new();
    for msg in &msgs {
        if msg["role"].as_str() != Some("assistant") {
            continue;
        }
        for call in msg["tool_calls"].as_array().into_iter().flatten() {
            if let (Some(id), Some(name)) = (call["id"].as_str(), call["function"]["name"].as_str())
            {
                names.insert(id.to_string(), name.to_string());
            }
        }
    }

    // **Both halves of the pairing, in this order.** First drop the results whose
    // requesting assistant message fell outside the window, then — the half this
    // used to be missing — trim the assistant messages that survive down to the
    // calls that actually have a result in the window.
    //
    // Without the second half the request can claim two calls and carry one
    // answer, which a server rejects outright: HuggingFace's router says
    // `incomplete_parallel_tool_calls: every tool call in a parallel group must
    // be answered before the next turn`, and OpenAI is no more forgiving. It only
    // arises when the window starts *inside* a round — the newest-N window does
    // that whenever the previous session ended mid-tool — and with one call per
    // turn it takes a session that ended between an assistant message and its
    // single result, which is why it went unseen against a local llama.
    // A model that asks for two at once makes it ordinary.
    let answered: std::collections::HashSet<String> = msgs
        .iter()
        .filter(|m| m["role"].as_str() == Some("tool"))
        .filter_map(|m| m["tool_call_id"].as_str().map(str::to_string))
        .collect();
    for msg in &mut msgs {
        if msg["role"].as_str() != Some("assistant") {
            continue;
        }
        let Some(calls) = msg["tool_calls"].as_array_mut() else {
            continue;
        };
        calls.retain(|c| c["id"].as_str().is_some_and(|id| answered.contains(id)));
        // Nothing left to answer: the message is just what the model said. The
        // field goes rather than becoming an empty array, because an empty
        // `tool_calls` is itself something some routers read as a request for
        // zero calls and reject.
        if calls.is_empty() {
            msg.as_object_mut()
                .expect("a message is an object")
                .remove("tool_calls");
        }
    }

    // Drop the parentless results *before* rewriting, so the loop below can rely
    // on every survivor having a name.
    //
    // This is not a tidy-up: a `tool` message is only legal immediately after the
    // assistant message that requested it, matched by id, so a parentless one
    // makes the whole request invalid. llama-server is lenient about it (checked:
    // a request whose first message is a `tool` one comes back 200), but the
    // shipped default endpoint is `https://api.openai.com/v1`, where that is a
    // 400 — so a cold start would fail outright, on the default configuration,
    // for anyone whose previous session ended inside a tool round. Which is most
    // sessions, given the agent uses tools to do anything.
    msgs.retain(|msg| {
        msg["role"].as_str() != Some("tool")
            || msg["tool_call_id"]
                .as_str()
                .is_some_and(|id| names.contains_key(id))
    });

    for msg in &mut msgs {
        if msg["role"].as_str() != Some("tool") {
            continue;
        }
        let bytes = msg["content"].as_str().map_or(0, str::len);
        let who = msg["tool_call_id"]
            .as_str()
            .and_then(|id| names.get(id).map(String::as_str))
            .unwrap_or("a tool");
        let content = elided_line(who, bytes);
        msg["content"] = Value::String(content);
    }
    msgs
}

/// `[used fs.read; 12.4 kB of output not replayed]`, in one line.
fn elided_line(who: &str, bytes: usize) -> String {
    if bytes == 0 {
        return format!("[used {who}; no output]");
    }
    let (value, unit) = if bytes >= 1024 * 1024 {
        (bytes as f64 / (1024.0 * 1024.0), "MB")
    } else if bytes >= 1024 {
        (bytes as f64 / 1024.0, "kB")
    } else {
        (bytes as f64, "B")
    };
    format!("[used {who}; {value:.1} {unit} of output not replayed]")
}

#[allow(clippy::too_many_arguments)]
async fn run<W: Write>(
    terminal: &mut Terminal<CrosstermBackend<W>>,
    rx: &mut mpsc::UnboundedReceiver<CrosstermEvent>,
    lua_rx: &mut mpsc::UnboundedReceiver<agent::lua::AgentCommand>,
    app: &mut App,
    vm: &mlua::Lua,
    catalog: &mut Catalog,
    pager: &mut paging::Pager,
) -> Result<()> {
    // What the model was offered this turn: the dispatch gate every call that
    // comes back has to pass (`may_run`), read fresh from Lua at the start of
    // each turn so a `/reload` is effective immediately.
    let mut offered: std::collections::HashSet<String> = refresh_offered(vm)?;
    // Tool-round state: queued calls (id, name, arguments) still waiting to
    // run, the in-flight call's completion channel, the same call's
    // permission-ask channel (both live while a tool runs), the round's
    // shared panel sink (drained every frame so streamed ops render live),
    // and the ask currently awaiting the user's y/n verdict.
    let mut tool_queue: VecDeque<(String, String, String)> = VecDeque::new();
    // The tool in flight, driven by this loop on the config VM: no executor
    // thread and no second VM (see `start_next_tool`).
    let mut tool_flight: Option<ToolFlight<'_>> = None;
    // The question the tool is waiting on, and the answer the user has given
    // for it (handed to the coroutine on the next step).
    let mut pending_question: Option<PendingQuestion> = None;
    let mut pending_verdict: Option<mlua::Value> = None;
    // A call that finished (or never started) and is waiting to be answered —
    // handed to the parked `turn` handler — at the top of the next iteration.
    let mut pending_outcome: Option<ToolOutcome> = None;
    // The user asked to stop the *turn*, not just the tool it was watching.
    // There is no round cap any more, so this is the only thing standing between
    // a model that keeps asking for tools and a session that never ends: cleared
    // at every new user turn, and checked wherever a turn would otherwise chain
    // into another round.
    //
    // Killing the tool alone is deliberately not enough: that only answers the
    // run, and a model that ignores an `interrupted` result asks again with
    // nothing left to stop it but `Ctrl+d`. There used to be a cap
    // (`MAX_TOOL_ROUNDS`, 8) and it was the wrong shape of limit — a count says
    // nothing about how long the work is, so it truncated real tasks (a diff to
    // read, an edit to verify, a build to run) at a number chosen without knowing
    // any of that, and stopped with the model's calls unanswered. Time or round
    // counts both misprice "enough"; the user watching the turn is the one who
    // knows.
    let mut stop_turn = false;
    // A tool round's panel sink, and the highest panel id handed out so far: an
    // id has to outlive its sink (see `PanelSink::continuing_from`), which is why
    // the round's sink continues the turn's numbering rather than restarting it.
    let mut round_sink: Option<agent::panels::PanelSink> = None;
    let mut next_panel_id: u64 = 1;
    // The pager is armed by the caller, against the same window the replayed
    // transcript came from; see `paging::Pager::resume_after`.
    // Grammars the transcript has asked for, and the ones already asked for.
    // A fetch is seconds of network and `cc`, so it cannot run here — it runs in
    // a task and writes to the cache, and the loop picks the result up by polling
    // `grammar_rx` rather than by selecting on it, because nothing about a
    // finished fetch should be able to delay a key press.
    let mut grammars = GrammarQueue::default();
    // Completion only. Progress goes straight to the status line from the task —
    // it is a process-global mutex-backed line, so it is safe from any thread and
    // needs no channel, and keeping the two apart means this channel only ever
    // carries one thing: a language that is ready.
    let (grammar_tx, mut grammar_rx) = mpsc::unbounded_channel::<GrammarOutcome>();
    // The `turn_completed` event handler, driven **cooperatively on this
    // thread**: a coroutine that suspends at each `agent.on_timeout` wait
    // (the loop keeps rendering) and is resumed when its reactor timer fires.
    let mut event: Option<agent::lua::EventRun<'_>> = None;
    let mut event_rx: Option<mpsc::UnboundedReceiver<()>> = None;
    // The `turn` event handler — the main conversation's requests, driven by
    // Lua (`lua/lib/main_turn.lua`) when a handler is registered. Same
    // cooperative shape as `turn_completed`, but a *request*: the coroutine's
    // return value is the assembled turn. Separate slots, because a suspended
    // `turn_completed` handler may legitimately span into the turn that
    // follows it, and one slot would have each clobber the other.
    let mut turn_event: Option<agent::lua::EventRun<'_>> = None;
    let mut turn_event_rx: Option<mpsc::UnboundedReceiver<()>> = None;
    // The sink the turn handler's panels draw into while it runs. Drained
    // every frame like a tool round's — but *not* archived (see
    // `teardown_turn_sink` for why).
    let mut turn_sink: Option<agent::panels::PanelSink> = None;
    // The handler's first step, queued by `start_lua_turn` and driven at the
    // top of the next pass so every step runs one code path.
    let mut pending_turn_step: Option<agent::lua::EventStep> = None;
    // The tool round a suspended `turn` handler is waiting on: the results to
    // resume it with, collected as each call lands. `Some` for the whole round —
    // the handler's coroutine is parked in `turn_event` for the duration.
    let mut round_results: Option<Vec<(String, String)>> = None;

    // Draw once before the loop: without it the (bare) alternate screen is
    // blank until the first event arrives, so the app looks dead on startup.
    // Flush explicitly afterwards — ratatui's draw flushes the backend, but
    // an explicit `Stderr::flush()` forces the frame out even if the runtime
    // or a wrapper buffers the fd (e.g. a log-capturing pipe).
    terminal.autoresize()?;
    terminal.draw(|frame| app.render(frame))?;
    stderr().flush()?;

    loop {
        // A tool in flight is stepped *here*, on this thread, before anything
        // else: the call is a Lua coroutine on the config VM, so advancing it is
        // an ordinary synchronous call, and the loop is the only thing that can
        // decide a question it raises.
        //
        // A call that has finished — or never started — goes through the one
        // finish path below: fold its result into the conversation, then start
        // the next queued call or hand the turn back to the model.
        // The `turn` handler's first step, queued by `start_lua_turn` on the
        // previous pass: driven here so every step — first, timer-ticked, and
        // round-resumed — runs the one `drive_lua_turn` path.
        // The `turn` handler's first step, queued by `start_lua_turn` on the
        // previous pass: driven here so every step — first, timer-ticked, and
        // round-resumed — runs the one `drive_lua_turn` path.
        if let Some(first) = pending_turn_step.take() {
            let mut d = TurnDrive {
                vm,
                app,
                offered: &offered,
                stop_turn: &mut stop_turn,
                tool_queue: &mut tool_queue,
                tool_flight: &mut tool_flight,
                pending_outcome: &mut pending_outcome,
                round_sink: &mut round_sink,
                next_panel_id: &mut next_panel_id,
                event: &mut event,
                event_rx: &mut event_rx,
                turn_event: &mut turn_event,
                turn_event_rx: &mut turn_event_rx,
                turn_sink: &mut turn_sink,
                round_results: &mut round_results,
            };
            drive_lua_turn(&mut d, Some(Ok(first)))?;
        }

        if let Some(outcome) = pending_outcome.take() {
            // The call is over: no question can be outstanding, and the VM's panel
            // sink goes with it, so a panel opened outside a round reaches no panel
            // at all — as it did when every call had a VM of its own.
            pending_question = None;
            let _ = agent::lua::clear_sink(vm);
            // What the call said, and whatever it drew on the way — archived here,
            // in the order both happened.
            let (id, content) = tool_result(outcome);
            if let Some(s) = round_sink.as_ref() {
                archive_panel_ops(app.drain_panel_ops(s));
            }
            if let Some(results) = &mut round_results {
                // A suspended `turn` handler collects every result; the resume hands
                // it exactly what the call said, and it appends them itself.
                results.push((id, content));
            }
            if !tool_queue.is_empty() {
                let (started, refused) =
                    start_next_tool(vm, &mut tool_queue, round_sink.as_ref(), offered.clone())
                        .map_err(anyhow::Error::msg)?;
                tool_flight = started;
                pending_outcome = refused;
                continue;
            }
            tool_flight = None;
            // The round is over, so the next one restarts the sink — but not the
            // numbering. Carried here, where the sink is still in hand.
            next_panel_id = round_sink.as_ref().map_or(next_panel_id, |s| s.next_id());
            round_sink = None;
            let Some(results) = round_results.take() else {
                // A round only ever starts from a `turn` handler's await, so a round
                // finishing with none parked is a bug in the loop rather than a case:
                // say so instead of dropping the results in silence.
                eprintln!("[agent] tool round finished with no turn handler waiting");
                continue;
            };
            // The round belonged to a suspended `turn` handler: resume it with the
            // results, and *it* decides the next request. The turn sink goes back on
            // first — re-created at the carried panel counter, so a panel the handler
            // opens next never reuses an id the round handed out.
            let sink = agent::panels::PanelSink::continuing_from(next_panel_id);
            if let Err(e) = agent::lua::install_sink(vm, &sink) {
                eprintln!("[agent] turn sink reinstall: {e}");
            }
            turn_sink = Some(sink);
            let reply = match agent::lua::round_results_reply(vm, &results, stop_turn) {
                Ok(reply) => reply,
                Err(e) => {
                    eprintln!("[agent] round results reply: {e}");
                    continue;
                }
            };
            let step = turn_event.as_mut().map(|run| run.resume_value(reply));
            let mut d = TurnDrive {
                vm,
                app,
                offered: &offered,
                stop_turn: &mut stop_turn,
                tool_queue: &mut tool_queue,
                tool_flight: &mut tool_flight,
                pending_outcome: &mut pending_outcome,
                round_sink: &mut round_sink,
                next_panel_id: &mut next_panel_id,
                event: &mut event,
                event_rx: &mut event_rx,
                turn_event: &mut turn_event,
                turn_event_rx: &mut turn_event_rx,
                turn_sink: &mut turn_sink,
                round_results: &mut round_results,
            };
            drive_lua_turn(&mut d, step)?;
            continue;
        }

        if let Some(flight) = tool_flight.as_mut() {
            let (outcome, question) = match advance_tool(flight, pending_verdict.take()) {
                Ok(pair) => pair,
                // A tool that raised is a failed call, not a dead agent: it
                // becomes the call's error, so the model reads what happened and
                // the conversation carries on.
                Err(why) => (Some(flight.failed(why)), None),
            };
            if let Some(o) = outcome {
                pending_outcome = Some(o);
                // Fold it on this same pass rather than after another wake: the
                // call is over and there is nothing to wait for.
                continue;
            }
            // A question the tool is waiting on. The tool already put it on
            // screen — `panel:ask` is a member function, so the dialog is on the
            // panel that raised the question and there is nothing here to place.
            //
            // All the loop does is remember that a question is outstanding, so a
            // key press can be read as a verdict. It is told about the same
            // question on every tick until it is answered, which is why the
            // re-report is ignored rather than acted on.
            if let Some(q) = question.filter(|q| !q.text.is_empty()) {
                pending_question = Some(q);
            }
        }

        let busy = tool_flight.is_some() || turn_event.is_some();
        let tick = if busy {
            if tool_flight.is_some() {
                // A tool is executing: also wake on a short pulse so the loop
                // drains streamed ops and redraws while it runs — that's what
                // makes a long command's output appear live in its panel — and
                // gives a suspended sandbox run its next step.
                tokio::select! {
                    ev = rx.recv() => ev.map(Tick::Key),
                    cmd = lua_rx.recv() => cmd.map(Tick::Lua),
                    _eev = next_event(&mut event_rx) => Some(Tick::Event(())),
                    _tev = next_event(&mut turn_event_rx) => Some(Tick::LuaTurn),
                    _ = tokio::time::sleep(Duration::from_millis(20)) => Some(Tick::Pulse),
                }
            } else {
                tokio::select! {
                    ev = rx.recv() => ev.map(Tick::Key),
                    cmd = lua_rx.recv() => cmd.map(Tick::Lua),
                    _eev = next_event(&mut event_rx) => Some(Tick::Event(())),
                    _tev = next_event(&mut turn_event_rx) => Some(Tick::LuaTurn),
                }
            }
        } else {
            // Idle: wait for terminal input or a Lua-forced inference
            // (agent.trigger). A *forced inference* sent while the loop is busy
            // stays queued until the next idle moment — right after the current
            // turn finishes, which is when compaction handlers want to run
            // anyway, and starting a second turn mid-stream would interleave two
            // conversations. An input edit is not in that category: it is a
            // keystroke the user is watching for, so the busy arms above poll
            // this channel too and it lands on the same tick as the key press
            // that asked for it. A suspended `turn_completed` handler is resumed
            // here too, on its timer pokes.
            tokio::select! {
                ev = rx.recv() => ev.map(Tick::Key),
                cmd = lua_rx.recv() => cmd.map(Tick::Lua),
                _eev = next_event(&mut event_rx) => Some(Tick::Event(())),
                _tev = next_event(&mut turn_event_rx) => Some(Tick::LuaTurn),
            }
        };
        let Some(tick) = tick else {
            break; // stdin closed / producer task ended
        };

        match tick {
            Tick::Key(CrosstermEvent::Key(key)) => {
                if let Some(question) = pending_question.take() {
                    // A permission question is on screen (and, for the shell,
                    // also as the panel overlay): only a verdict answers it —
                    // everything else is ignored until the user decides.
                    // `a` is a verdict only when the question offered "always".
                    if key.kind == KeyEventKind::Press {
                        match ask_choice(key.code, &question.remember) {
                            Some(choice) => {
                                let answer = record_verdict(app, choice);
                                pending_verdict = Some(agent::lua::verdict_to_lua(vm, &answer));
                            }
                            None => match key.code {
                                // The command asking is the one thing worth
                                // interrupting here: its whole tree is frozen
                                // on this very question, so this is the moment a
                                // user is most likely to want it gone — and the
                                // ask it is blocked on will never be answered.
                                // The question is dropped, not restored.
                                KeyCode::Char('c')
                                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                                {
                                    agent::seccomp::request_interrupt();
                                    // Same as the idle path: killing the tool is
                                    // not the same as ending the turn, and with
                                    // no round cap the difference is the whole
                                    // escape hatch.
                                    stop_turn = true;
                                    app.set_status_text("interrupting…", StatusKind::Warn);
                                }
                                // Ctrl+d leaves even mid-question: the one way out
                                // that has to work while a verdict is pending,
                                // which is exactly when a user may want it.
                                KeyCode::Char('d')
                                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                                {
                                    break;
                                }
                                _ => {
                                    // Not an answer: put the question back.
                                    pending_question = Some(question);
                                }
                            },
                        }
                    } else {
                        // A key release or repeat: still the same question.
                        pending_question = Some(question);
                    }
                } else {
                    // A Lua `key` handler gets first refusal (see `resolve_key`).
                    // It is asked only here — never on the pending-question path
                    // above — because `y`/`n`/`a` are verdicts, and a binding
                    // table that could redirect one would be able to answer a
                    // permission question by accident.
                    let bound = match key.kind {
                        KeyEventKind::Press => resolve_key(vm, &key),
                        _ => None,
                    };
                    let effect = match bound {
                        // A binding that names an action still has to pass the
                        // letter gate, or `BIND["q"] = "quit"` quits the app
                        // mid-word. Refusing falls through to the text path, so
                        // the letter types rather than vanishing.
                        Some(Ok(_)) if !app.key_may_act(&key) => default_key(app, key, busy),
                        Some(Ok(action)) => app.perform(action),
                        Some(Err(why)) => {
                            // Loud, and not fatal: the key still does whatever it
                            // did before, so a typo in a binding table costs a
                            // message on the bar rather than the key.
                            app.set_status_text(format!("key binding: {why}"), StatusKind::Warn);
                            default_key(app, key, busy)
                        }
                        None => default_key(app, key, busy),
                    };
                    match effect {
                        Effect::Continue => {}
                        Effect::Quit => break,
                        Effect::Interrupt => {
                            // A latch, not a signal from here: the sandbox is
                            // inside the tool's coroutine and this thread has no
                            // handle on it. The driver picks the request up at
                            // the top of its next step, kills the whole captured
                            // tree, and the run finishes the ordinary way — so
                            // there is nothing to unwind, and the tool result
                            // comes back marked interrupted.
                            agent::seccomp::request_interrupt();
                            // …and the *turn* stops too. Killing the tool alone
                            // only answered the run: the model reads
                            // `interrupted` as a result and may ask again, which
                            // with no round cap means a loop the user cannot
                            // leave. This is the stop that ends it.
                            stop_turn = true;
                            app.set_status_text("interrupting…", StatusKind::Warn);
                        }
                    }
                    if let Some(text) = app.take_submitted() {
                        if text.strip_prefix("/save").is_some() {
                            // Saving is continuous (the loop archives messages
                            // as they land and flushes at turn boundaries);
                            // /save is the explicit "flush now, and tell me
                            // where it went".
                            if !agent::lua::memory_is_bound() {
                                app.push_boxed(
                                    Role::Assistant,
                                    "no conversation log open (agent.llm.memory.enabled = false)"
                                        .into(),
                                    "error".into(),
                                );
                            } else {
                                match agent::lua::memory_flush() {
                                    Ok(()) => {
                                        let where_ = agent::lua::memory_path()
                                            .map(|p| format!(" — {}", p.display()))
                                            .unwrap_or_default();
                                        app.push_boxed(
                                            Role::Assistant,
                                            format!("conversation saved to disk{where_}."),
                                            "config".into(),
                                        );
                                    }
                                    Err(e) => app.push_boxed(
                                        Role::Assistant,
                                        format!("save failed: {e}"),
                                        "error".into(),
                                    ),
                                }
                            }
                        } else if text.strip_prefix("/reload").is_some() {
                            // A local command: reload the user config (picks
                            // up config edits), then re-derive the tool
                            // catalog from its fresh `agent.mcps` — nothing
                            // cached in Rust — so the next request already
                            // advertises the new tool set and the new system
                            // prompt.
                            match agent::lua::load_config_file(vm) {
                                Err(e) => app.push_boxed(
                                    Role::Assistant,
                                    format!("config reload failed: {e:#}"),
                                    "error".into(),
                                ),
                                Ok(loaded) => match tool_defs(vm) {
                                    Ok(tools) => {
                                        // The gate reads the registry per turn, so
                                        // reloading needs no Rust-side refresh — only
                                        // the notice that says what changed.
                                        let names: Vec<&str> = tools
                                            .iter()
                                            .map(|t| t.function.name.as_str())
                                            .collect();
                                        let prompt = match agent::lua::system_prompt(vm) {
                                            Ok(p) if !p.trim().is_empty() => "system prompt set",
                                            Ok(_) => "no system prompt",
                                            Err(_) => "system prompt unreadable",
                                        };
                                        app.push_boxed(
                                            Role::Assistant,
                                            format!(
                                                "config {} — tools: {} · {prompt}",
                                                if loaded {
                                                    "reloaded (~/.config/agent/init.lua)"
                                                } else {
                                                    "reloaded (built-in defaults: no \
                                                     ~/.config/agent/init.lua)"
                                                },
                                                names.join(", ")
                                            ),
                                            "config".into(),
                                        );
                                    }
                                    Err(e) => app.push_boxed(
                                        Role::Assistant,
                                        format!("tool list failed: {e:#}"),
                                        "error".into(),
                                    ),
                                },
                            }
                        } else {
                            stop_turn = false;
                            // Reindex the dispatch gate for this turn (never cached
                            // across one, so a `/reload` is effective immediately).
                            match refresh_offered(vm) {
                                Ok(names) => {
                                    offered = names;
                                    start_lua_turn(
                                        vm,
                                        Some(&text),
                                        app,
                                        &mut turn_event,
                                        &mut turn_sink,
                                        &mut pending_turn_step,
                                        next_panel_id,
                                    );
                                }
                                Err(e) => app.push_boxed(
                                    Role::Assistant,
                                    format!("tools refresh failed: {e:#}"),
                                    "error".into(),
                                ),
                            }
                        }
                    }
                }
            }
            // A paste is not a key, so it is handled here and not through the
            // binding table or `handle_key`: there is no single chord to bind, no
            // action to name, and — the point of the exercise — no `Enter` in it.
            //
            // It respects the two states a key respects. With a permission
            // question on screen, a paste is ignored: the question is modal, and
            // text arriving underneath it would be typed at a dialog. While a
            // turn is running, a paste is *inserted* rather than sent, because
            // `Enter` mid-turn is ignored and a pasted newline must be ignored
            // the same way rather than submitting a message the user is still
            // writing.
            Tick::Key(CrosstermEvent::Paste(text)) => {
                if pending_question.is_none() {
                    let had = app.input.len();
                    app.paste(&text);
                    if app.input.len() != had {
                        let added = app.input.len() - had;
                        app.set_status_text(
                            format!("pasted {added} char{}", if added == 1 { "" } else { "s" }),
                            StatusKind::Info,
                        );
                    }
                }
            }
            Tick::Key(CrosstermEvent::Mouse(ev)) => match app.handle_mouse(ev) {
                // A click on one of the dialog's answers. The panel reports only
                // the letter inside the brackets, and it goes through the same
                // `ask_choice` the keyboard does, so a pointer and a key cannot
                // come to mean different things — the one thing worth being
                // careful about when a *permission* can be granted by either.
                Click::Answer(letter) => {
                    if let Some(question) = pending_question.take() {
                        match ask_choice(KeyCode::Char(letter), &question.remember) {
                            Some(choice) => {
                                let answer = record_verdict(app, choice);
                                pending_verdict = Some(agent::lua::verdict_to_lua(vm, &answer));
                            }
                            None => {
                                // `a` answers only a question that offered
                                // "always", and the dialog is not offering it —
                                // so the click landed on an answer that does not
                                // exist, and the question stays.
                                pending_question = Some(question);
                            }
                        }
                    }
                }
                // Box collapse is the panel's own business, handled inside
                // `handle_mouse`; it decides nothing and so reports nothing.
                Click::Toggled | Click::Nothing => {}
            },
            Tick::Key(_) => {} // resize and friends: just redraw below

            Tick::Lua(cmd) => match cmd {
                // A Lua handler changed the input line (`agent.api.input_*`).
                // Its own arm rather than something done where the key was
                // pressed, because this is the only place the loop owns the
                // input, and the channel is the only thing a `key` handler can
                // reach it through. It falls through to the redraw below like
                // every other tick, which is what makes the change visible.
                agent::lua::AgentCommand::Input(op) => app.apply_input_op(op),
                // A Lua handler forced a new inference (`agent.trigger`),
                // optionally with a user line. There is no replacement history
                // here: the conversation is `agent.history`, so a compaction has
                // already assigned it and the turn reads it as it stands. Only
                // the idle select polls the channel, so the loop is between
                // turns here.
                agent::lua::AgentCommand::RunTurn { user } => {
                    if let Some(text) = user {
                        // Mirror a normal submission: the transcript records the
                        // line too, and the `turn` handler appends it to the
                        // conversation.
                        app.push(Role::User, text);
                    }
                    stop_turn = false;
                    match refresh_offered(vm) {
                        Ok(names) => {
                            offered = names;
                            start_lua_turn(
                                vm,
                                None,
                                app,
                                &mut turn_event,
                                &mut turn_sink,
                                &mut pending_turn_step,
                                next_panel_id,
                            );
                        }
                        Err(e) => app.push_boxed(
                            Role::Assistant,
                            format!("tools refresh failed: {e:#}"),
                            "error".into(),
                        ),
                    }
                }
            },

            Tick::Event(()) => {
                // The reactor's timer fired for a suspended `turn_completed`
                // handler: resume its coroutine where it yielded. A returned
                // (or errored) handler is done; a fresh wait arms the next
                // timer.
                let step = event.as_mut().map(|run| run.step());
                match step {
                    Some(Ok(agent::lua::EventStep::Waiting { ms })) => {
                        event_rx = Some(start_event_timer(ms));
                    }
                    Some(Ok(agent::lua::EventStep::Returned)) | None => {
                        event = None;
                        event_rx = None;
                    }
                    Some(Ok(agent::lua::EventStep::Tools { .. })) => {
                        eprintln!(
                            "[agent] event turn_completed: agent.await_tools can only suspend the turn handler"
                        );
                        event = None;
                        event_rx = None;
                    }
                    Some(Err(e)) => {
                        eprintln!("[agent] event turn_completed: {e}");
                        event = None;
                        event_rx = None;
                    }
                }
            }

            Tick::LuaTurn => {
                // The reactor's timer fired for the Lua-driven turn: resume the
                // handler where it yielded. It polls its request's queue
                // between `agent.on_timeout` waits, and those waits are what
                // the timers pace — so this arm *is* the stream pump.
                let step = turn_event.as_mut().map(|run| run.step());
                let mut d = TurnDrive {
                    vm,
                    app,
                    offered: &offered,
                    stop_turn: &mut stop_turn,
                    tool_queue: &mut tool_queue,
                    tool_flight: &mut tool_flight,
                    pending_outcome: &mut pending_outcome,
                    round_sink: &mut round_sink,
                    next_panel_id: &mut next_panel_id,
                    event: &mut event,
                    event_rx: &mut event_rx,
                    turn_event: &mut turn_event,
                    turn_event_rx: &mut turn_event_rx,
                    turn_sink: &mut turn_sink,
                    round_results: &mut round_results,
                };
                drive_lua_turn(&mut d, step)?;
            }
            Tick::Pulse => {} // periodic wake while a tool runs: drained + redrawn below
        }

        // Apply any panel ops that streamed in since the last frame — a
        // running bash command appends its stdout chunks to the round's sink
        // as the loop steps it, so the box fills live.
        if let Some(s) = &round_sink {
            archive_panel_ops(app.drain_panel_ops(s));
        }
        // The Lua turn handler's drawing, drained the same way — but not
        // archived: resume reconstructs those blocks from the reasoning
        // records and the assistant message (see `teardown_turn_sink`).
        if let Some(s) = &turn_sink {
            app.drain_panel_ops(s);
        }

        // Grammars, in three steps: notice what the transcript asked for, start
        // at most one fetch, and apply whatever finished. Applying means a cache
        // hit on the foreground catalog (milliseconds) followed by a re-highlight
        // of the transcript, which changes no row count and so does not move the
        // viewport — the whole reason this can happen mid-conversation.
        for lang in app.take_wanted_grammars() {
            grammars.request(lang);
        }
        if let Some(lang) = grammars.take_next() {
            let dir = agent::grammars::cache_root();
            let tx = grammar_tx.clone();
            tokio::spawn(async move {
                let named = lang.clone();
                let mut worker = agent::grammars::Catalog::new()
                    .with_cache_dir(dir)
                    .with_progress(move |m| agent::status::info(format!("{m} ({named})")));
                let outcome = match worker.ensure(&lang).await {
                    Ok(_) => GrammarOutcome::Ready(lang.clone()),
                    // Not retried, deliberately: `GrammarQueue::asked` keeps the
                    // language, so a registry that is down, or a fence naming a
                    // language that was never published, costs one attempt rather
                    // than one per frame for the rest of the session.
                    Err(e) => GrammarOutcome::Failed(lang.clone(), format!("{e:#}")),
                };
                let _ = tx.send(outcome);
            });
        }
        while let Ok(outcome) = grammar_rx.try_recv() {
            // Unconditional and first: a failure has to clear this too, or the
            // queue is wedged for the rest of the session.
            let lang = match outcome {
                GrammarOutcome::Ready(lang) => {
                    grammars.finish(true);
                    lang
                }
                GrammarOutcome::Failed(lang, why) => {
                    grammars.finish(false);
                    app.set_status_text(
                        format!("{lang} highlighting unavailable ({why})"),
                        StatusKind::Warn,
                    );
                    continue;
                }
            };
            // A cache hit, so this is a `dlopen` and a read — no network on the
            // thread that draws frames. (If the cached object turned out to be
            // unloadable, `ensure` falls through to a rebuild *here*, which would
            // stall the UI for as long as that takes. The worker having just built
            // it is the reason that is not a real risk rather than a handled one.)
            match catalog.ensure(&lang).await {
                Ok(g) => {
                    let n = app.add_grammar(&lang, g);
                    app.set_status_text(
                        format!("{lang} highlighting ready ({n} messages)"),
                        StatusKind::Done,
                    );
                }
                Err(e) => {
                    app.set_status_text(
                        format!("{lang} highlighting unavailable ({e:#})"),
                        StatusKind::Warn,
                    );
                }
            }
        }

        // Seal the log when the turn is fully over — no tool in flight, no handler
        // running — so every finished turn is durably on disk (group commit;
        // `/save` flushes early).
        //
        // The *contents* are not the loop's business any more: the handler
        // appends each message as it produces it (`agent.api.history_append`,
        // which archives as it appends), and a round's panels were archived as
        // they drained. All this decides is when buffered bytes reach the file.
        if tool_flight.is_none()
            && pending_outcome.is_none()
            && turn_event.is_none()
            && let Err(e) = agent::lua::memory_flush()
        {
            eprintln!("[agent] save to disk failed (flush): {e}");
        }

        terminal.autoresize()?;
        terminal.draw(|frame| app.render(frame))?;
        // After the draw: that is when the panel knows where the view actually is,
        // since `at_loaded_top` reads the scroll offset the render just resolved.
        // Paging before it would ask on the previous frame's position.
        paging::page_if_wanted(app, pager);
        // Force the frame to the terminal fd (belt and braces on top of
        // ratatui's own backend flush).
        stderr().flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent::testutil::unique_path;

    /// The whole app as a user would see it.
    ///
    /// This goes through [`App::render`], which is what gives the transcript the
    /// area it measures and wraps at — so a test that needs the app to know its
    /// own width has to read it this way; drawing the bare panel would leave
    /// `panel_area` unset and every
    /// width-dependent path untested.
    fn app_screen(app: &mut App, w: u16, h: u16) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).expect("terminal");
        terminal.draw(|frame| app.render(frame)).expect("draw");
        let buf = terminal.backend().buffer();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "))
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn a_lua_binding_table_turns_a_key_press_into_an_action() {
        let vm = agent::lua::new_vm().expect("VM");
        vm.load(
            r#"
            local BIND = { ["ctrl+q"] = "quit", ["alt+j"] = "newline" }
            SEEN = nil
            agent.on_event("key", function(k)
              SEEN = { spec = k.spec, char = k.char, alt = k.alt, ctrl = k.ctrl }
              return BIND[k.spec]
            end)
        "#,
        )
        .exec()
        .expect("register");
        let key = |code, mods| KeyEvent::new(code, mods);

        assert_eq!(
            resolve_key(&vm, &key(KeyCode::Char('q'), KeyModifiers::CONTROL)),
            Some(Ok(Action::Quit)),
            "a bound chord performs what it was bound to"
        );
        assert_eq!(
            resolve_key(&vm, &key(KeyCode::Char('j'), KeyModifiers::ALT)),
            Some(Ok(Action::Newline)),
            "and another"
        );
        assert_eq!(
            resolve_key(&vm, &key(KeyCode::Char('x'), KeyModifiers::NONE)),
            None,
            "an unbound key is no answer at all, so the default stands"
        );

        // The payload is the contract, so it is worth seeing what the handler
        // was actually told.
        let seen = |vm: &mlua::Lua| -> Value {
            let v: mlua::Value = vm.load("return SEEN").eval().expect("read back");
            agent::mcp::lua_to_json(&v).expect("to json")
        };
        let payload = seen(&vm);
        assert_eq!(payload["spec"], "x");
        assert_eq!(payload["char"], "x");
        assert_eq!(payload["alt"], false);
        assert_eq!(payload["ctrl"], false);

        // A named key has no character, and says so rather than sending "".
        resolve_key(&vm, &key(KeyCode::Enter, KeyModifiers::ALT));
        let payload = seen(&vm);
        assert_eq!(payload["spec"], "alt+enter");
        assert!(
            payload["char"].is_null(),
            "a named key has no char: {payload}"
        );

        // A typo is an error the loop can report, not a silently dead binding.
        vm.load("agent.on_event('key', function() return 'conceall' end)")
            .exec()
            .expect("re-register");
        let got = resolve_key(&vm, &key(KeyCode::Char('c'), KeyModifiers::ALT))
            .expect("the key was asked about");
        let why = got.expect_err("a typo is not an action");
        assert!(why.contains("conceall"), "{why}");
        assert!(why.contains("conceal"), "and lists the real names: {why}");
    }

    /// A Lua binding *replaces* the Rust default for that key, rather than
    /// deferring to it.
    ///
    /// This is the load-bearing detail of the whole arrangement, and the reason
    /// the keys Rust keeps are a fallback rather than a floor: the loop asks Lua
    /// first and falls through to the default table only when Lua returns
    /// nothing, so a table entry for a key Rust also holds makes the Rust row
    /// unreachable. Pinned because the alternative — Rust consulting its defaults
    /// first — would silently make every binding unreachable for exactly the keys
    /// a user is most likely to want to move, which is the opposite of what a
    /// configurable key is for.
    ///
    #[test]
    fn a_lua_binding_replaces_the_rust_default_for_that_key() {
        let vm = agent::lua::new_vm().expect("VM");
        let ctrl_d = KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL);

        // The shipped config binds nothing for `ctrl+d`, so it falls through to
        // the Rust default.
        assert_eq!(
            resolve_key(&vm, &ctrl_d),
            None,
            "unbound in Lua, so Rust's default stands"
        );
        let mut app = App::default();
        assert_eq!(
            app.handle_key(ctrl_d),
            Effect::Quit,
            "and Rust's default is to leave"
        );

        // Bind it in Lua and the same key now means something else entirely.
        vm.load(
            r#"
            agent.on_event("key", function(k)
              if k.spec == "ctrl+d" then return "conceal" end
            end)
        "#,
        )
        .exec()
        .expect("re-register");
        assert_eq!(
            resolve_key(&vm, &ctrl_d),
            Some(Ok(Action::Conceal)),
            "a table entry takes the key over"
        );
    }

    /// The input primitives report honestly when nothing is listening.
    ///
    #[test]
    fn the_input_primitives_report_false_with_no_loop_attached() {
        let vm = agent::lua::new_vm().expect("VM");
        for call in [
            "return agent.api.input_insert('x')",
            "return agent.api.input_backspace()",
            "return agent.api.input_clear()",
        ] {
            let got: bool = vm.load(call).eval().expect("eval");
            assert!(!got, "{call} reports that nothing was queued");
        }
    }

    /// A unique temp log path for one test; parallel tests never collide,
    /// because [`unique_path`] carries a per-process counter.
    fn unique_log(name: &str) -> std::path::PathBuf {
        unique_path(&format!("agent-mem-{name}"))
    }

    /// A replayed tool result becomes a one-line record of the call.
    ///
    /// Four things are pinned, and the last two are the ones that would be easy
    /// to break while making the transcript shorter: the summary must name the
    /// tool (resolved through the parent assistant message, since a result does
    /// not carry the name itself), and the `role`/`tool_call_id` pair must survive
    /// untouched — a `tool` message is only legal after the assistant message
    /// that requested it, so rewriting it into a `user` message would make the
    /// request invalid rather than merely terse.
    /// Panel records round-trip through the log and come back as a panel.
    ///
    #[test]
    fn a_panel_is_archived_and_replayed_as_a_panel() {
        // What `apply_patch` emits, in order.
        let ops = vec![
            agent::panels::PanelOp::Split {
                id: 7,
                title: "apply_patch: /tmp/x.lua".into(),
                panes: vec![
                    agent::panels::PaneInit {
                        caption: "before".into(),
                        lang: Some("lua".into()),
                    },
                    agent::panels::PaneInit {
                        caption: "after".into(),
                        lang: Some("lua".into()),
                    },
                ],
            },
            agent::panels::PanelOp::SetPane {
                id: 7,
                pane: 1,
                text: "\tlocal a = 1\n".into(),
            },
            agent::panels::PanelOp::SetPane {
                id: 7,
                pane: 2,
                text: "  local a = 2\n".into(),
            },
            agent::panels::PanelOp::HighlightPane {
                id: 7,
                pane: 2,
                start: 2,
                end: 9,
                style: "bold.green".into(),
            },
        ];

        // Archived: each op becomes one log record.
        let archived: Vec<serde_json::Value> =
            ops.iter().map(agent::panels::panel_record).collect();
        assert!(
            archived.iter().all(agent::panels::is_panel_record),
            "every record identifies itself as a panel"
        );

        // Read back: the ops come back exactly, which is what "the drawing is
        // archived" has to mean for it to be worth anything.
        let decoded: Vec<agent::panels::PanelOp> = archived
            .iter()
            .filter_map(agent::panels::panel_record_op)
            .collect();
        assert_eq!(decoded, ops, "the drawing survives the round trip");
    }

    /// The whole chain against a real log *file*, written the way the loop
    /// actually writes it: frame by frame, through [`splice_panel_records`].
    ///
    /// The frames matter. A round's `Create` is written in the same frame as the
    /// request that started it, so it can be spliced in beside it; a *streamed*
    /// tool's chunks arrive over the frames after, when that request is already
    /// on disk and the recorded position is behind the watermark. Writing the log
    /// directly would skip exactly the step that lost every `bash` panel.
    /// The whole chain against a real log *file*, written the way the loop
    /// actually writes it: frame by frame, through [`splice_panel_records`].
    ///
    /// The frames matter. A round's `Create` is written in the same frame as the
    /// request that started it, so it can be spliced in beside it; a *streamed*
    /// tool's chunks arrive over the frames after, when that request is already
    /// on disk and the recorded position is behind the watermark. Writing the log
    /// The archive step, and the rule that keeps an empty stream from leaving a mark
    /// anywhere.
    ///
    /// Reasoning comes back on resume, in its own block and in the right order.
    ///
    /// `PageUp` moves a screen, not a line.
    ///
    /// Both were bound to the one-row scroll, so every key that scrolled moved one
    /// row and going back through a transcript took one press per line — which reads
    /// as scrolling not working at all.
    ///
    #[test]
    fn a_screen_scroll_moves_the_viewport_less_one_row() {
        let mut app = App::default();
        for i in 0..60 {
            app.push(Role::Assistant, format!("line {i:02}"));
        }
        // Rendered first: the viewport comes from the area the panel was last given, so
        // an unrendered app would scroll by the fallback and the assertion would be
        // about nothing.
        app_screen(&mut app, 60, 10);
        let viewport = app.panel_viewport_h();
        // The transcript's first visible line, by number. The number is taken as a
        // whitespace-delimited word because the row ends in the scrollbar lane, whose
        // glyph is not whitespace and so survives `trim`.
        let first_row = |app: &mut App| -> usize {
            let screen = app_screen(app, 60, 10);
            screen
                .lines()
                .find_map(|l| {
                    l.trim_start()
                        .strip_prefix("assistant line ")?
                        .split_whitespace()
                        .next()?
                        .parse()
                        .ok()
                })
                .unwrap_or_else(|| panic!("no transcript line on screen:\n{screen}"))
        };
        let before = first_row(&mut app);
        app.perform(Action::PageUp);
        let after = first_row(&mut app);
        assert_eq!(
            before - after,
            viewport - 1,
            "one screen less the row they share, so no line is skipped at the seam"
        );
        // …and back down a screen, symmetrically — measured before the one-row check
        // moves the view, or it would be a screen up from the wrong place.
        app.perform(Action::PageDown);
        assert_eq!(
            first_row(&mut app),
            before,
            "one screen back down returns to where it was"
        );
        // A single row still moves a single row: the two are different quantities and
        // one must not have been quietly made a synonym for the other.
        app.perform(Action::ScrollUp);
        assert_eq!(
            first_row(&mut app),
            before - 1,
            "one arrow is still one line"
        );
    }

    /// Reasoning in the paged-in range comes back, folded, in its turn's position.
    ///
    /// The defect this covers was asymmetry, not absence: a cold start reconstructs
    /// reasoning (see `reasoning_is_archived_and_replayed_in_its_own_block`), so the
    /// turns in the window showed their thinking and the turns reached by scrolling
    /// showed none. One log, two reconstructions, one lossy — and the lossy one is
    /// whichever the reader had to scroll to reach.
    ///
    #[test]
    fn reasoning_behind_the_reload_point_is_reconstructed_when_paged_in() {
        let path = unique_log("paging-reasoning");
        let _ = std::fs::remove_file(&path);
        let think = "the stat syscall runs per keystroke.";
        let answer = "because it re-reads it.";
        let mut written = Vec::new();
        for i in 0..40 {
            if i == 4 {
                // Reasoning is archived first within a turn, then the words.
                written.push(agent::panels::reasoning_record(&format!("{think}\n")));
                written.push(json!({"role": "assistant", "content": answer}));
                continue;
            }
            written.push(json!({
                "role": if i % 2 == 0 { "user" } else { "assistant" },
                "content": format!("line {i:02}"),
            }));
        }
        {
            let mut mem = agent::memory::Memory::with_options(
                &path,
                agent::memory::Options {
                    block_target: 256,
                    working_set: 1,
                },
            )
            .expect("log opens");
            for line in &written {
                mem.append(&serde_json::to_string(line).unwrap())
                    .expect("append");
            }
            mem.flush().expect("flush");
        }

        // A one-block window against a log of many: the thinking has to be *behind* the
        // reload point, or this only re-tests the cold start.
        let replayed = cold_start(&path, 1);
        let mut app = App::default();
        replay_transcript(&mut app, &replayed.records);
        // Rendered before paging, as the loop always is: the page wraps to the width
        // the panel was last given, and with no frame drawn there is no width.
        let before = app_screen(&mut app, 80, 60);
        assert!(
            !before.contains("[+] reasoning"),
            "the thinking is older than the window, so there is nothing to \
             reconstruct yet:\n{before}"
        );

        let mut pager = paging::Pager::new();
        pager.resume_at(&path, replayed.cursor);
        let mut guard = 0;
        loop {
            app.perform(Action::Top);
            if pager.page(&mut app) == 0 {
                break;
            }
            guard += 1;
            assert!(guard < 64, "the pager is making progress");
        }

        app.panel.jump_top();
        let all = app_screen(&mut app, 80, 60);
        assert!(
            all.contains("[+] reasoning"),
            "the paged-in turn brought its thinking back, folded like every \
             reconstructed block:\n{all}"
        );
        assert!(
            !all.contains(think),
            "and folded — the thinking is behind the click, not filling the view:\n{all}"
        );
        let at = |needle: &str| {
            all.find(needle)
                .unwrap_or_else(|| panic!("{needle:?} is not on screen at all:\n{all}"))
        };
        assert!(
            at("[+] reasoning") < at(answer),
            "reasoning sits where the turn had it — before the answer, not after it:\n{all}"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// A panel whose opening and whose body are in different blocks still comes back.
    ///
    /// A panel is two records — the `Create` that names it and the `Append` that fills
    /// it — and a page is one block, so a boundary can fall between them. It is worse
    /// than a cosmetic split: reading backwards, the content is met first and its
    /// `Create` is in the next older block, so the two halves land in different
    /// per-page id ranges and neither draws. The panel silently disappears from a turn
    /// that has it.
    ///
    #[test]
    fn a_panel_split_across_a_block_boundary_still_reconstructs() {
        let path = unique_log("paging-split");
        let _ = std::fs::remove_file(&path);
        {
            let mut mem = agent::memory::Memory::open(&path).expect("log opens");
            // Block A: the opening, and nothing else.
            mem.append(
                &serde_json::to_string(&agent::panels::panel_record(
                    &agent::panels::PanelOp::Create {
                        id: 1,
                        title: "split-tool".into(),
                        boxed: true,
                        conceal_box: false,
                    },
                ))
                .unwrap(),
            )
            .expect("append");
            mem.flush().expect("seal the opening into its own block");
            // Block B: the body, with no opening in sight.
            mem.append(
                &serde_json::to_string(&agent::panels::panel_record(
                    &agent::panels::PanelOp::Append {
                        id: 1,
                        text: "split-output\n".into(),
                    },
                ))
                .unwrap(),
            )
            .expect("append");
            mem.flush().expect("seal the body into the next block");
            // Blocks after it, so the window has something to be a window *of*.
            for i in 0..8 {
                mem.append(
                    &serde_json::to_string(&json!({
                        "role": "assistant",
                        "content": format!("line {i:02}"),
                    }))
                    .unwrap(),
                )
                .expect("append");
            }
            mem.flush().expect("flush");
        }

        let replayed = cold_start(&path, 1);
        let mut app = App::default();
        replay_transcript(&mut app, &replayed.records);
        let before = app_screen(&mut app, 80, 40);
        assert!(
            !before.contains("split-tool"),
            "the panel is older than the window, so there is nothing to reconstruct \
             yet:\n{before}"
        );

        let mut pager = paging::Pager::new();
        pager.resume_at(&path, replayed.cursor);
        let mut guard = 0;
        loop {
            app.perform(Action::Top);
            if pager.page(&mut app) == 0 {
                break;
            }
            guard += 1;
            assert!(guard < 32, "the pager is making progress");
        }

        app.panel.jump_top();
        let all = app_screen(&mut app, 80, 40);
        assert!(
            all.contains("split-tool [+]"),
            "the panel is reconstructed, under its own title and folded — the page \
             reached back for the opening that the boundary separated from the \
             body:\n{all}"
        );
        assert!(
            !all.contains("split-output"),
            "and folded, so its body is behind the click:\n{all}"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Scrolling past the loaded window brings older history in — in order, once,
    /// without moving what the user was reading, and as panels that still belong to
    /// their own tools.
    ///
    /// Each of those is a separate thing that can be got wrong in a way a row count
    /// cannot see, and each has bitten:
    ///
    /// * **The boundary.** The window is trimmed by *messages* (the newest `n`, plus
    ///   the panel records interleaved among them), and the log is addressed by
    ///   *block*. Getting that wrong shows a record twice or skips one, and either
    ///   looks like a rendering fault rather than a paging one.
    /// * **The view.** Rows are counted from the top, so history arriving at the top
    ///   pushes the content down. Without the matching scroll shift the view jumps
    ///   away from the line being read.
    /// * **The panel ids.** They are per tool round and continue across rounds, so
    ///   every chunk of a long session has a panel numbered 1. Merged unchecked, the
    ///   older chunk's `Create` retitles the newer chunk's box and its output appends
    ///   into it — and every click on either box then opens the wrong thing.
    ///
    #[test]
    fn a_page_arrives_when_the_view_reaches_the_top_of_what_is_loaded() {
        let path = unique_log("paging");
        let _ = std::fs::remove_file(&path);
        // Two tool panels, one inside the window and one *older* than it, both with
        // id 1 — which is what a real session has. Each carries output that is
        // recognisably its own, so a merge reads as one box wearing the other's name.
        let panel = |id: u64, title: &str, text: &str| {
            vec![
                agent::panels::panel_record(&agent::panels::PanelOp::Create {
                    id,
                    title: title.into(),
                    boxed: true,
                    conceal_box: false,
                }),
                agent::panels::panel_record(&agent::panels::PanelOp::Append {
                    id,
                    text: format!("{text}\n"),
                }),
            ]
        };
        let mut written = Vec::new();
        for i in 0..24 {
            match i {
                12 => written.extend(panel(1, "old-tool", "old-output")),
                20 => written.extend(panel(1, "new-tool", "new-output")),
                _ => written.push(json!({
                    "role": if i % 2 == 0 { "user" } else { "assistant" },
                    "content": format!("message {i:02}"),
                })),
            }
        }
        {
            let mut mem = agent::memory::Memory::with_options(
                &path,
                agent::memory::Options {
                    // Big enough that a block holds a dozen records, so the window's
                    // trim boundary lands mid-block and the resume cursor has to
                    // carry a skip count as well as an offset.
                    block_target: 256,
                    working_set: 1,
                },
            )
            .expect("log opens");
            for line in &written {
                mem.append(&serde_json::to_string(line).unwrap())
                    .expect("append");
            }
            mem.flush().expect("flush");
        }

        // Two blocks out of many: the window has to leave something behind it or
        // there is nothing to page, and that is the whole point.
        const WINDOW: usize = 2;
        let replayed = cold_start(&path, WINDOW);
        let mut app = App::default();
        replay_transcript(&mut app, &replayed.records);
        // Armed from the same read, at the same boundary.
        let mut pager = paging::Pager::new();
        pager.resume_at(&path, replayed.cursor);

        // Rendered first, and through the app: the top of the view is only a
        // position once a draw has resolved the offset, and the width a page wraps to
        // is the area the panel was last given. A test that jumped straight to the
        // top would be asking for a page at no width at all.
        //
        // Narrow, so the transcript is taller than the screen and the scroll offset
        // has somewhere to be wrong. At a height that fits the whole window, every
        // screen shows every message and the "the view did not move" assertion below
        // passes whether or not the offset was adjusted at all.
        let before = app_screen(&mut app, 80, 12);
        assert!(
            before.contains("new-tool [+]") && !before.contains("old-tool"),
            "the window holds the newest records, panel and all, and none of the \
             older chunk:\n{before}"
        );

        // Asking for nothing reads nothing: the pager answers a scroll request it
        // could not satisfy, and a frame that asks for nothing is not a request. Keyed
        // off the view sitting at the top instead, the first idle frame would read the
        // whole log in a block at a time.
        let mut idle = paging::Pager::new();
        idle.resume_at(&path, replayed.cursor);
        assert_eq!(
            idle.page(&mut app),
            0,
            "a frame that asks for nothing reads no history"
        );

        // `home` is a request for the beginning, which is behind the window.
        app.perform(Action::Top);
        let rows = pager.page(&mut app);
        assert!(rows > 0, "a page arrived: {rows} rows");

        // The older history is *on screen*. Not restored to where the view was — the
        // user scrolled to the end of what existed because they wanted what was behind
        // it, so putting the offset back would mean the gesture that fetched the
        // history shows none of it, and they would have to scroll up through the whole
        // page again to reach what they just asked for.
        //
        // Compared by *age*, not by a particular record: a page is one block, and where
        // the block boundaries fall is `block_target`'s business. What has to hold is
        // that the top of the view now shows something older than the window did.
        // The number off a `message NN` row. `position` consumes up to and including
        // the match, so the number is simply the next token.
        let oldest_visible = |screen: &str| -> i64 {
            screen
                .lines()
                .filter_map(|l| {
                    let mut w = l.split_whitespace();
                    w.position(|t| t == "message")?;
                    w.next()?.parse::<i64>().ok()
                })
                .min()
                .unwrap_or_else(|| panic!("no numbered message on screen:\n{screen}"))
        };
        let after = app_screen(&mut app, 80, 12);
        assert!(
            oldest_visible(&after) < oldest_visible(&before),
            "the page is on screen, not pushed back above the viewport — something \
             older than the window's oldest ({}) is showing:\n{after}",
            oldest_visible(&before)
        );

        // Asking again fetches again. The offset is still at the top of what is loaded
        // — the page went in above it — so this is the same gesture as the one before,
        // and treating it as "already paged" would stop the scroll dead one page in.
        app.perform(Action::Top);
        assert!(
            pager.page(&mut app) > 0,
            "asking again at the top fetches the next page"
        );
        assert_eq!(
            pager.page(&mut app),
            0,
            "and a frame that asks for nothing still reads nothing"
        );

        // Paged all the way back. Guarded, because an exhausted cursor that never
        // says so shows up here as a test that never finishes rather than as a
        // failure.
        let mut guard = 0;
        loop {
            // Through the action, not `jump_top`: paging answers a scroll request the
            // app could not satisfy, and `jump_top` on the panel is not one.
            app.perform(Action::Top);
            if pager.page(&mut app) == 0 {
                break;
            }
            guard += 1;
            assert!(guard < 32, "the pager is making progress");
        }

        // Now the content, read off one tall screen rather than a walk down
        // overlapping ones: consecutive screens share rows, so a count of "how many
        // times does this message appear" across them counts a message once per
        // screen it stayed on screen, which says nothing about the transcript. One
        // screen tall enough to hold the lot has no overlap and no such ambiguity.
        app.panel.jump_top();
        let all = app_screen(&mut app, 80, 40);
        for i in 0..24 {
            if matches!(i, 12 | 20) {
                continue; // those two are the panels, not messages
            }
            let needle = format!("message {i:02}");
            assert_eq!(
                all.matches(&needle).count(),
                1,
                "`{needle}` appears {} times — the pager's boundary and the \
                 window's do not agree:\n{all}",
                all.matches(&needle).count()
            );
        }
        // Folded, exactly as the panels reconstructed at startup are folded, and
        // titled for their own tool — which is also how the two chunks' panels are
        // shown not to have merged.
        for title in ["old-tool", "new-tool"] {
            assert!(
                all.contains(&format!("{title} [+]")),
                "`{title}` is on screen, folded and titled for its own tool, so the \
                 two chunks' panels did not merge into one:\n{all}"
            );
        }
        assert!(
            !all.contains("old-output") && !all.contains("new-output"),
            "and folded, so neither one's output fills the view:\n{all}"
        );

        // Clicking the window's panel still opens the window's panel. This is where
        // the two index maps earn their keep: a panel id is only meaningful together
        // with the message index it points at, and prepending history shifts every
        // message index there is. Resolve the wrong message and the box opens with
        // somebody else's output — or, landing on a plain message, not at all.
        let row = all
            .lines()
            .position(|l| l.contains("new-tool"))
            .expect("the window's panel is on screen") as u16;
        let click = crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: 6,
            row,
            modifiers: crossterm::event::KeyModifiers::NONE,
        };
        assert!(
            matches!(app.handle_mouse(click), Click::Toggled),
            "a click on the window's panel toggles a panel"
        );
        let opened = app_screen(&mut app, 80, 40);
        assert!(
            opened.contains("new-output") && !opened.contains("old-output"),
            "and opens the window's own output, not the older chunk's — the click \
             resolved the right panel:\n{opened}"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// round's drawings among them.
    ///
    /// A result whose parent assistant message fell outside the replay window is
    /// **dropped**, not kept and not renamed.
    ///
    #[test]
    fn a_parentless_tool_result_is_dropped_not_repaired() {
        let out = rebuild_tool_results(vec![
            serde_json::json!({
                "role": "tool", "tool_call_id": "call_9", "content": "orphaned output",
            }),
            serde_json::json!({"role": "user", "content": "hi"}),
        ]);
        assert_eq!(out.len(), 1, "only the user turn survives");
        assert_eq!(out[0]["content"], "hi");
        assert!(
            !out.iter().any(|m| m["role"] == "tool"),
            "and no orphan is left to invalidate the request"
        );
    }

    /// The window is a message *count*, so it can also start mid-round in the
    /// other direction — and must not, or a `tool` result loses its request.
    ///
    #[test]
    fn a_result_is_matched_to_its_own_call_not_its_position() {
        let out = rebuild_tool_results(vec![
            serde_json::json!({
                "role": "assistant", "content": null,
                "tool_calls": [
                    {"id": "c1", "type": "function",
                     "function": {"name": "fs.read", "arguments": "{}"}},
                    {"id": "c2", "type": "function",
                     "function": {"name": "bash.bash", "arguments": "{}"}},
                ],
            }),
            serde_json::json!({"role": "tool", "tool_call_id": "c2", "content": "out2"}),
            serde_json::json!({"role": "tool", "tool_call_id": "c1", "content": "out1"}),
        ]);
        let named: Vec<&str> = out
            .iter()
            .filter(|m| m["role"] == "tool")
            .map(|m| m["content"].as_str().expect("a string"))
            .collect();
        assert_eq!(named.len(), 2, "both results are kept");
        assert!(
            named[0].contains("bash.bash") && named[1].contains("fs.read"),
            "each names its own tool, by id rather than by order: {named:?}"
        );
    }

    /// The byte reduction, on a log that looks like a real turn.
    ///
    #[test]
    fn rebuilding_shrinks_a_realistic_turn_by_an_order_of_magnitude() {
        let file = "fn main() {}\n".repeat(2000); // ~30 kB, a source file
        let raw = vec![
            serde_json::json!({"role": "user", "content": "read main.rs"}),
            serde_json::json!({
                "role": "assistant", "content": null,
                "tool_calls": [{"id": "c1", "type": "function",
                    "function": {"name": "fs.read", "arguments": "{\"path\":\"main.rs\"}"}}],
            }),
            serde_json::json!({"role": "tool", "tool_call_id": "c1", "content": file}),
            serde_json::json!({
                "role": "assistant",
                "content": "It prints a newline and nothing else.",
            }),
        ];
        let before: usize = raw.iter().map(|m| m.to_string().len()).sum();
        let after: usize = rebuild_tool_results(raw.clone())
            .iter()
            .map(|m| m.to_string().len())
            .sum();
        assert!(
            after * 8 < before,
            "expected a large reduction, got {before} -> {after}"
        );
        // And it is a reduction in the tool result, not a truncation of the answer.
        let rebuilt = rebuild_tool_results(raw);
        assert_eq!(
            rebuilt[3]["content"], "It prints a newline and nothing else.",
            "the assistant's own words are not the thing being elided"
        );
    }

    #[test]
    fn replay_history_returns_empty_for_a_missing_or_empty_log() {
        let gone = unique_log("replay-gone");
        assert!(
            cold_start(&gone, 5).records.is_empty(),
            "a missing log replays nothing"
        );
        let path = unique_log("replay-empty");
        {
            let _mem = agent::memory::Memory::open(&path).unwrap(); // header only
        }
        assert!(
            cold_start(&path, 5).records.is_empty(),
            "an empty log replays nothing"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A failed fetch must not wedge the queue.
    ///
    #[test]
    fn a_failed_fetch_still_releases_the_queue() {
        let mut q = GrammarQueue::default();
        for lang in ["rust", "python"] {
            assert!(q.request(lang.to_string()));
        }
        assert_eq!(q.take_next().as_deref(), Some("rust"), "first goes first");

        // In flight: nothing else starts, however long it takes.
        assert_eq!(q.take_next(), None, "one at a time");

        // The failure, and the queue is usable again.
        assert!(!q.finish(false), "reported as a failure");
        assert_eq!(
            q.take_next().as_deref(),
            Some("python"),
            "so the one behind it is not stranded"
        );
    }

    /// A language is fetched at most once per session, however often it is asked
    /// for and however badly it goes.
    ///
    /// The transcript asks again on every re-highlight and a message with forty
    /// `rust` blocks asks forty times, so the dedup is the difference between one
    /// fetch and one per block. And on failure it is what stops the loop retrying a
    /// language the registry does not have, once per frame, until the session ends.
    /// The loop's grammar pump, end to end, in the shape it actually runs.
    ///
    /// The ignored test in `tui` proves the *chain* — notice, acquire, add, apply —
    /// but it drives those halves by hand. What is left untested is the wiring
    /// between them: that a request reaches a spawned task, that the task's
    /// completion reaches the loop, and that the loop then re-enters its own
    /// catalog and applies the result. That is thirty lines of glue around a
    /// six-hundred-line loop body, and glue is where the silent failures live.
    ///
    /// So this runs the real [`GrammarQueue`], a real spawned [`Catalog`]
    /// acquisition, the real channel, and the real [`App`] apply — the loop body
    /// with the terminal and the model taken out. `ignored` because it needs the
    /// network and a C compiler to obtain a grammar the app does not ship with;
    /// everything it asserts about *policy* is covered hermetically above.
    #[tokio::test]
    #[ignore = "needs the network and a C compiler; run with --ignored"]
    async fn a_wanted_grammar_is_fetched_in_the_background_and_applied() {
        use agent::tui::{App, Role};
        use std::fs;

        let dir = unique_path("agent-pump");
        let _ = fs::remove_dir_all(&dir);

        let mut catalog = agent::grammars::Catalog::new().with_cache_dir(&dir);
        for lang in ["markdown", "markdown_inline", "bash", "json"] {
            catalog
                .ensure(lang)
                .await
                .unwrap_or_else(|e| panic!("{lang} is required: {e:#}"));
        }
        let mut app = App::default();
        app.set_highlight(agent::tui::MarkdownHighlighter::from_catalog(&catalog));
        app.push(
            Role::Assistant,
            "# Fix\n\n```rust\nfn main() {\n    let x: u32 = 7;\n}\n```\n".to_string(),
        );

        // The transcript asks, and the queue takes the request.
        let mut q = GrammarQueue::default();
        for lang in app.take_wanted_grammars() {
            q.request(lang);
        }
        let lang = q
            .take_next()
            .expect("rust is wanted and nothing is in flight");

        // A worker, spawned the way the loop spawns it, pointed at the same cache
        // directory the foreground catalog reads — which is the part that makes the
        // foreground `ensure` below a cache hit rather than a second download.
        let (tx, mut rx) = mpsc::unbounded_channel::<GrammarOutcome>();
        let worker_dir = dir.clone();
        tokio::spawn(async move {
            let mut worker = agent::grammars::Catalog::new().with_cache_dir(worker_dir);
            let outcome = match worker.ensure(&lang).await {
                Ok(_) => GrammarOutcome::Ready(lang.clone()),
                Err(e) => GrammarOutcome::Failed(lang.clone(), format!("{e:#}")),
            };
            let _ = tx.send(outcome);
        });

        // Meanwhile the loop carries on: nothing is blocked, and nothing else is
        // started while that one is in flight.
        assert_eq!(q.take_next(), None, "one at a time, even while we wait");

        // The loop polls this between frames rather than awaiting it, so the test
        // drains the channel the same way — a plain `recv` here, because blocking on
        // it is exactly the difference being tested elsewhere and would hide a
        // completion that is never sent.
        let mut lang = None;
        while lang.is_none() {
            while let Ok(outcome) = rx.try_recv() {
                match outcome {
                    GrammarOutcome::Ready(l) => {
                        assert!(q.finish(true));
                        lang = Some(l);
                    }
                    GrammarOutcome::Failed(l, why) => {
                        assert!(!q.finish(false));
                        panic!("{l} should be obtainable: {why}");
                    }
                }
            }
            if lang.is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let lang = lang.expect("the worker reported back");

        // The foreground catalog now has it as a cache hit — no network here, which
        // is the property that keeps this off the frame-drawing path.
        let g = catalog.ensure(&lang).await.expect("a cache hit");
        let changed = app.add_grammar(&lang, g);
        assert_eq!(changed, 1, "the one message that was missing it");
        assert!(
            app.take_wanted_grammars().is_empty(),
            "and the gap is closed, so nothing queues for it again"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_grammar_is_asked_for_once_however_many_times_it_turns_up() {
        let mut q = GrammarQueue::default();
        for _ in 0..40 {
            q.request("rust".to_string());
        }
        assert_eq!(q.take_next().as_deref(), Some("rust"));
        assert!(!q.finish(false), "and it never arrived");
        assert_eq!(
            q.take_next(),
            None,
            "no retry: a language that cannot be fetched is not fetched again"
        );

        // A different language still gets its turn, which is the property the
        // dedup has to have without also being a block.
        q.request("python".to_string());
        assert_eq!(q.take_next().as_deref(), Some("python"));
    }

    #[test]
    fn only_the_tools_a_request_offered_may_run() {
        let offered: std::collections::HashSet<String> =
            ["bash.bash".to_string(), "fs.read".to_string()]
                .into_iter()
                .collect();
        // Names are qualified by their connection, so the gate is checked
        // against the names a request actually carries.
        assert!(may_run("bash.bash", &offered).is_ok());
        assert!(may_run("fs.read", &offered).is_ok());

        // A mode's dropped tool: well-formed, registered in the config the
        // tool call would run on, and still refused.
        let e = may_run("fs.write_file", &offered).unwrap_err();
        assert!(e.contains("fs.write_file"), "{e}");
        assert!(e.contains("not one of the tools offered"), "{e}");

        // The empty catalog of a no-tools mode refuses everything.
        let none = std::collections::HashSet::new();
        assert!(may_run("bash", &none).is_err());
        // An empty name cannot sneak through either.
        assert!(may_run("", &offered).is_err());
    }

    /// An assistant message that asks for calls must only ask for calls that have
    /// answers in the same request. The replay window can break that pairing —
    /// this is the case, seen from HuggingFace's router as
    /// `400 incomplete_parallel_tool_calls: every tool call in a parallel group
    /// must be answered before the next turn`.
    ///
    /// The window is the newest N messages, so it starts mid-round whenever the
    /// previous session ended inside one. `rebuild_tool_results` already drops a
    /// result whose *requesting* assistant message fell outside — but not the
    /// other half: an assistant message that fell *in* while some of its results
    /// fell out. That leaves the request claiming two calls and carrying one
    /// answer, which is precisely what the server rejects.
    ///
    #[test]
    fn a_parallel_group_is_trimmed_to_the_calls_that_were_answered() {
        // The window starts at the assistant message: both calls requested, only
        // the first answered.
        let out = rebuild_tool_results(vec![
            json!({"role": "assistant", "content": "on it", "tool_calls": [
                {"id": "call_a", "type": "function",
                 "function": {"name": "fs.read", "arguments": "{}"}},
                {"id": "call_b", "type": "function",
                 "function": {"name": "bash.bash", "arguments": "{}"}},
            ]}),
            json!({"role": "tool", "tool_call_id": "call_a", "content": "ok"}),
            json!({"role": "user", "content": "next question"}),
        ]);

        let calls = out[0]["tool_calls"]
            .as_array()
            .expect("still an assistant turn");
        assert_eq!(
            calls.len(),
            1,
            "the un-answered call is gone, or the server rejects the whole request: \
             {out:?}"
        );
        assert_eq!(calls[0]["id"], "call_a", "and the answered one is kept");
        assert_eq!(
            out[1]["tool_call_id"], "call_a",
            "its result survives to match it"
        );
    }

    #[test]
    fn an_assistant_message_with_no_answers_left_stops_claiming_calls() {
        let out = rebuild_tool_results(vec![
            json!({"role": "assistant", "content": "here is the answer", "tool_calls": [
                {"id": "call_a", "type": "function",
                 "function": {"name": "fs.read", "arguments": "{}"}},
                {"id": "call_b", "type": "function",
                 "function": {"name": "bash.bash", "arguments": "{}"}},
            ]}),
            json!({"role": "user", "content": "next question"}),
        ]);
        assert!(
            out[0]["tool_calls"].is_null(),
            "no answers in the window, so no calls claimed: {out:?}"
        );
        assert_eq!(
            out[0]["role"], "assistant",
            "and it stays an assistant turn, content and all"
        );
        assert_eq!(
            out[0]["content"], "here is the answer",
            "with the text the model actually produced, which is the point of \\
             keeping it"
        );
    }

    #[test]
    fn a_fully_answered_group_is_left_exactly_as_it_was() {
        let msgs = vec![
            json!({"role": "assistant", "content": "checking", "tool_calls": [
                {"id": "call_a", "type": "function",
                 "function": {"name": "fs.read", "arguments": "{}"}},
                {"id": "call_b", "type": "function",
                 "function": {"name": "bash.bash", "arguments": "{}"}},
            ]}),
            json!({"role": "tool", "tool_call_id": "call_a", "content": "one"}),
            json!({"role": "tool", "tool_call_id": "call_b", "content": "two"}),
        ];
        let out = rebuild_tool_results(msgs.clone());
        assert_eq!(out.len(), 3, "nothing dropped: {out:?}");
        assert_eq!(
            out[0]["tool_calls"].as_array().map(Vec::len),
            Some(2),
            "both calls still claimed, in the order the model asked"
        );
        for (i, id) in ["call_a", "call_b"].iter().enumerate() {
            assert_eq!(out[1 + i]["tool_call_id"], *id, "results still matched");
        }
    }

    /// A turn that said *and* asked gets two assistant messages, and they must be
    /// in the order the protocol requires: the text first, then the calls.
    ///
    /// This is the live half of `incomplete_parallel_tool_calls`. The loop used
    /// to push the calls message and the text message in separate places, and the
    /// text landed *after* it — so the history read
    ///
    /// ```text
    /// assistant: tool_calls=[read(A), read(B)]
    /// assistant: "I'll start by looking at the README."   <- the next turn
    /// tool: …
    /// tool: …
    /// ```
    ///
    /// The stopped turn must leave the history *valid*, which is the subtle half.
    ///
    #[test]
    fn the_ask_keys_offer_a_third_answer_only_when_the_question_had_one() {
        use agent::panels::{ALWAYS_LABEL, Remember};
        use crossterm::event::KeyCode;
        let offered: Remember = Some(ALWAYS_LABEL.to_string());
        // Offered: all three. What the third one is *called* is the panel's
        // business, so a run-scoped `lways this run` answers exactly as a plain
        // `lways` does.
        assert_eq!(
            ask_choice(KeyCode::Char('y'), &offered),
            Some(AskChoice::Yes)
        );
        assert_eq!(
            ask_choice(KeyCode::Char('n'), &offered),
            Some(AskChoice::No)
        );
        assert_eq!(
            ask_choice(KeyCode::Char('a'), &offered),
            Some(AskChoice::Always)
        );
        assert_eq!(
            ask_choice(KeyCode::Char('a'), &Some("lways this run".into())),
            Some(AskChoice::Always),
            "a narrower grant is still a grant"
        );
        // Uppercase too — the answer is not case-sensitive.
        assert_eq!(
            ask_choice(KeyCode::Char('A'), &offered),
            Some(AskChoice::Always)
        );
        assert_eq!(ask_choice(KeyCode::Char('Y'), &None), Some(AskChoice::Yes));
        // Not offered: `a` answers nothing, and neither does anything else —
        // a question on screen must not eat the user's typing.
        assert_eq!(ask_choice(KeyCode::Char('a'), &None), None);
        assert_eq!(ask_choice(KeyCode::Char('A'), &None), None);
        for code in [
            KeyCode::Char('x'),
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Up,
            KeyCode::Char('c'),
        ] {
            assert_eq!(
                ask_choice(code, &offered),
                None,
                "{code:?} is not an answer"
            );
        }
    }
}
