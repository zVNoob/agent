//! The agent binary: chat TUI front end + LLM client + a test tool executor.
//!
//! This milestone wires the LLM client into the TUI:
//!   - type a message, press Enter, and the model's streamed answer renders
//!     live in the turn panel inside its own borderless "response" block;
//!     reasoning streams live into a separate borderless "reasoning" block
//!     above it, dimmed so the thinking reads darker than the answer (tool
//!     calls keep their framed, click-collapsible boxes; both streamed
//!     blocks follow the markup-conceal toggle like plain messages, so Alt+c
//!     hides markers inside them too),
//!   - when the model requests a tool, the agent runs it (the `bash` tool
//!     executes through the seccomp sandbox under a Lua syscall policy in
//!     `tools`; the sandbox becomes interruptible in the next milestone) and
//!     renders the call + result in a click-collapsible box,
//!   - the result is fed back as a `tool` message and the continuation is
//!     streamed, up to [`MAX_TOOL_ROUNDS`] chained rounds per user turn.
//!
//! Key semantics: Enter mid-turn is ignored (the typed text stays in the
//! input and submits once the current turn ends); Ctrl+C / q / Esc quit.
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
//! [`MEMORY_REPLAY_LATEST`] messages are replayed into the transcript and the
//! request history (the watermark starts past them, so nothing is
//! re-archived).
//! All server-communicating logic lives in `api`; rendering and interaction
//! state live in `agent::tui`; the terminal setup mirrors `bin/chat.rs`.

use agent::api::{Chat, TurnBuilder, TurnEvent, assistant_tool_message};
use agent::grammars::Catalog;
use agent::status::StatusKind;
use agent::tui::{Action, App, Click, Effect, MarkdownHighlighter, Role};
use anyhow::Result;
use crossterm::event::{
    Event as CrosstermEvent, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
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

/// Safety cap on chained tool rounds within a single user turn.
const MAX_TOOL_ROUNDS: usize = 8;

/// How many of the newest archived messages a fresh session replays into the
/// transcript and request history (cold-start context, chronological).
const MEMORY_REPLAY_LATEST: usize = 20;

/// Mouse capture: press/release + SGR coordinates only. crossterm's
/// `EnableMouseCapture` also enables the `?1002`/`?1003` *motion* modes, which
/// make every pointer wiggle over the terminal wake the event loop and redraw;
/// the agent only needs deliberate clicks and wheel notches.
const MOUSE_ON: &str = "\x1b[?1000h\x1b[?1006h";
const MOUSE_OFF: &str = "\x1b[?1000l\x1b[?1006l";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
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
        ConfigOrigin::Tree => println!(
            "config: no writable ~/.config/agent — using the built-in defaults"
        ),
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
    let mut chat = Chat::connect(&config, tool_defs(&config_vm)?);
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
    // off — the newest MEMORY_REPLAY_LATEST archived messages become the
    // starting transcript/request history. The loop's save watermark starts
    // past them (see `run`), so the replayed prefix is never re-archived.
    let replayed: Vec<Value> = match agent::lua::memory_path() {
        Some(p) => replay_history(&p, MEMORY_REPLAY_LATEST),
        None => Vec::new(),
    };
    if !replayed.is_empty() {
        println!("memory: resumed {} archived messages", replayed.len());
    }

    enable_raw_mode()?;
    execute!(stderr(), EnterAlternateScreen)?;
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
    for msg in &replayed {
        let Some(role) = msg["role"].as_str() else {
            continue;
        };
        match role {
            "user" => {
                if let Some(content) = msg["content"].as_str() {
                    app.push(Role::User, content.to_string());
                }
            }
            "assistant" => {
                if let Some(content) = msg["content"].as_str() {
                    app.push(Role::Assistant, content.to_string());
                }
                // A tool round is silent on resume, exactly as it is live. There
                // was a summary box here — `invoked tools: read_file, bash` —
                // reconstructed from the archive's call names, and it was the
                // last thing in the loop that admitted a tool had run. Live
                // turns say nothing, so a resumed turn that said something would
                // be describing history the user cannot otherwise see. Keeping
                // it would have made a tool's visibility depend on whether the
                // session was fresh.
                //
                // The gap this leaves is real and worth naming: panels are not
                // archived, so a resumed session shows neither the summary nor
                // the tool's own drawing. Tools that report themselves will
                // report themselves again on the next turn; what is lost is
                // only the *visual* of what a past turn did.
            }
            _ => {} // tool results: invisible, as they are live
        }
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
        &mut chat,
        &config,
        &config_vm,
        &mut catalog,
        replayed,
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
    execute!(stderr(), LeaveAlternateScreen)?;
    let _ = stderr().flush();
    outcome
}

/// One unit of work the agent loop multiplexes: a terminal event, the next
/// turn event (`None` = the current turn's stream ended), a step of the tool
/// call in flight (which finishes on its own, not on a thread of its own), a
/// pending user-permission ask from the running tool (`None` = the ask channel
/// closed), the reactor's timer poke for a suspended `turn_completed` handler,
/// or a periodic pulse while a tool runs.
enum Tick {
    Key(CrosstermEvent),
    Turn(Option<Result<TurnEvent, anyhow::Error>>),
    /// A forced inference queued by Lua (`agent.trigger`), possibly with a
    /// replaced history — drained on the idle select.
    Lua(agent::lua::AgentCommand),
    /// The reactor's timer fired: resume the suspended `turn_completed`
    /// handler coroutine (see `start_turn_completed`).
    Event(()),
    Pulse,
}

/// Whether pressing `key` submits the input (Enter without Alt).
fn is_submit_key(key: &KeyEvent) -> bool {
    key.code == KeyCode::Enter && !key.modifiers.contains(KeyModifiers::ALT)
}

/// Await the in-flight turn's next event (parks forever when no turn is
/// active — the branch is only polled while `stream.is_some()`).
async fn next_turn_event(
    stream: &mut Option<agent::api::TurnStream>,
) -> Option<Result<TurnEvent, anyhow::Error>> {
    match stream {
        Some(s) => s.next().await,
        None => futures_util::future::pending().await,
    }
}

/// A finished tool call: the identity the `tool` message must quote, and the
/// outcome — `Ok((body, content))` or an executor error message. Produced by
/// the flight below, whether it finished normally, was refused by the dispatch
/// gate, or raised.
///
/// The name and the arguments are deliberately **not** here. They were, until
/// this stopped putting a box in the transcript: the box was the only reader.
/// What a call was, and how it went, is now either something the tool drew or
/// something it did not.
struct ToolOutcome {
    id: String,
    result: Result<(String, String), String>,
}

/// A tool call in flight, driven by the event loop **on the agent's own config
/// VM** — no thread, no second VM.
///
/// The call is a Lua coroutine ([`agent::lua::ToolRun`]) and `step` is where it
/// is suspended: on a question ([`agent::lua::ToolStep::Ask`]), on a reactor wait
/// (the sandbox's own cooperative cadence, or an `agent.on_timeout` inside the
/// tool), or finished. The loop resumes it — see `advance_tool`.
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

/// The three answers a permission question can take, as the *user* gives them.
///
/// `Always` is only reachable when the question offered it: Lua passes that flag
/// to `agent.api.ask_user`, and only a question with a path to remember offers
/// it (see `agent.ask.for_syscall`). It arrives at the asking side as
/// [`agent::lua::AskAnswer::AllowAndTrust`], which makes `agent.ask` record the
/// path — so the same question is not asked again in this run.
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
/// offered "always" — otherwise a stray `a` is not an answer to anything, and
/// treating it as one would remember a path the asking side never offered.
///
/// Returns `None` for any other key: while a question is on screen it is the
/// only thing that responds (Ctrl+C and Esc still quit), so a keystroke is never
/// mistaken for input text.
fn ask_choice(code: KeyCode, always: bool) -> Option<AskChoice> {
    match code {
        KeyCode::Char('y') | KeyCode::Char('Y') => Some(AskChoice::Yes),
        KeyCode::Char('n') | KeyCode::Char('N') => Some(AskChoice::No),
        KeyCode::Char('a') | KeyCode::Char('A') if always => Some(AskChoice::Always),
        _ => None,
    }
}

/// Await the suspended `turn_completed` handler's timer poke (parks forever
/// when no handler is waiting — the branch is only polled while the event
/// coroutine is suspended).
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
        Ok(Some((run, step))) => Ok((
            Some(ToolFlight { id, run, step }),
            None,
        )),
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
/// `always` flag rides along, and it is what decides whether `[a]lways` is one
/// of the offered keys.
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
        ToolStep::Ask { text, always } => (
            None,
            Some(PendingQuestion {
                text: text.clone(),
                always: *always,
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
fn fold_tool_outcome(
    app: &mut App,
    history: &mut Vec<serde_json::Value>,
    outcome: ToolOutcome,
    round_sink: Option<&agent::panels::PanelSink>,
) {
    let ToolOutcome { id, result, .. } = outcome;
    let content = match result {
        Ok((_body, content)) => content,
        Err(msg) => json!({"error": msg}).to_string(),
    };
    history.push(json!({
        "role": "tool",
        "tool_call_id": id,
        "content": content,
    }));
    if let Some(s) = round_sink {
        app.drain_panel_ops(s);
    }
}

/// A question the tool is waiting on, as the loop holds it: the wording to show
/// and whether `[a]lways` is one of the answers.
struct PendingQuestion {
    text: String,
    always: bool,
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

/// Whether a tool call may run: only a name this request actually offered.
///
/// A tool is called by name against the *live* registry, so "not advertised"
/// is not by itself "not callable" — a mode that replaced `agent.mcps`, an
/// unregistered tool, or an old tool call replayed out of the history would
/// each find a working tool by name. The request's own tool list is the gate,
/// so what the model was shown is exactly what it can run.
/// What the loop knows about grammars it has been asked for.
///
/// Its own type because the rules are the interesting part and the loop body is a
/// poor place to find them: the loop is six hundred lines, and the failure this
/// exists to prevent — a fetch that reported nothing leaving the queue wedged for
/// the session — is invisible there and obvious here.
///
/// Two rules, both of which cost something to learn:
/// * a language is fetched at most once per session, so a registry that is down or
///   a fence naming a language nobody published costs one attempt rather than one
///   per frame until the session ends;
/// * a fetch is only started when the previous one has reported back, *including
///   when it failed*. Forgetting the second half is a silent, session-long wedge.
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

/// How a background grammar acquisition ended.
///
/// The distinction is not cosmetic: the loop's "one fetch at a time" flag is only
/// cleared by receiving one of these, so a task that failed *silently* would leave
/// the flag set and every later grammar queued behind it would never be fetched —
/// one unknown fence language permanently disabling highlighting for the session.
/// A failure therefore has to travel the same path as a success.
enum GrammarOutcome {
    /// The worker wrote it to the cache. The loop can now `ensure` it, which is a
    /// `dlopen` and nothing else.
    Ready(String),
    /// It could not be obtained. `why` is for the status line; the language stays
    /// un-inlined, which is the degradation it already had.
    Failed(String, String),
}

fn may_run(name: &str, offered: &std::collections::HashSet<String>) -> Result<(), String> {
    if offered.contains(name) {
        Ok(())
    } else {
        Err(format!("`{name}` is not one of the tools offered for this request"))
    }
}

/// The names the current request offered the model: the gate a tool call has to
/// pass before it runs (see `start_next_tool`). Read off the chat, which holds
/// the tool list this turn was sent with.
fn offered_tools(chat: &Chat) -> std::collections::HashSet<String> {
    chat.tools()
        .iter()
        .map(|t| t.function.name.clone())
        .collect()
}

/// Re-derive the advertised tool list from the live registry before a request
/// and swap the chat only when the set actually changed (reindexing every
/// request is what keeps a config edit immediate; the swap is the minimal step
/// that surfaces the change to the frozen [`Chat`], which fixes its tools at
/// connect time).
fn refresh_chat_tools(chat: &mut Chat, config: &agent::api::ChatConfig, vm: &mlua::Lua) -> Result<()> {
    let tools = tool_defs(vm)?;
    if serde_json::to_string(&tools)? != serde_json::to_string(chat.tools())? {
        *chat = Chat::connect(config, tools);
    }
    Ok(())
}

/// The request's messages: the user's system prompt (read fresh from the
/// config VM, so `/reload` picks up an edit) as the leading message, then the
/// conversation. An empty prompt contributes nothing, leaving the history as
/// it stands.
fn request_history(vm: &mlua::Lua, history: &[Value]) -> Vec<Value> {
    let mut messages = Vec::with_capacity(history.len() + 1);
    if let Some(prompt) = agent::lua::system_prompt(vm)
        .ok()
        .filter(|p| !p.trim().is_empty())
    {
        messages.push(json!({"role": "system", "content": prompt}));
    }
    messages.extend_from_slice(history);
    messages
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
    history: &[Value],
    event: &mut Option<agent::lua::EventRun<'a>>,
    event_rx: &mut Option<mpsc::UnboundedReceiver<()>>,
) {
    let payload = json!({ "history": history });
    match agent::lua::EventRun::start(vm, "turn_completed", &payload) {
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

/// Archive newly-landed history messages to the conversation log (the
/// save-to-disk side). A watermark tracks how far the log has seen: every
/// message is appended exactly once, in order — the log is an append-only raw
/// transcript, so compaction that *replaces* the history with a shorter one
/// just clamps the watermark down to the new end (messages already logged stay
/// logged; the compacted summary is never re-archived). `turn_over` (no stream
/// or tool in flight) triggers the group-commit flush so each finished turn is
/// durably on disk. No log open (disabled, or a failed open) → no-op.
fn save_history(history: &[Value], saved_upto: &mut usize, turn_over: bool) {
    if !agent::lua::memory_is_bound() {
        return;
    }
    // Compaction shrank the history below the watermark: don't point past the
    // end, and don't re-archive what the log already has.
    *saved_upto = (*saved_upto).min(history.len());
    if *saved_upto < history.len() {
        match agent::lua::memory_append_many(&history[*saved_upto..]) {
            Ok(_) => *saved_upto = history.len(),
            // A persistent I/O error must not stall the loop: advance past the
            // failing block (it would only fail again next frame) and report.
            Err(e) => {
                eprintln!("[agent] save to disk failed: {e}");
                *saved_upto = history.len();
            }
        }
    }
    if turn_over && let Err(e) = agent::lua::memory_flush() {
        eprintln!("[agent] save to disk failed (flush): {e}");
    }
}

/// Cold-start replay: the newest `n` archived messages of the conversation
/// log (chronological order), parsed into request-history messages. Corrupt
/// lines are skipped, never fatal — a torn record simply shortens the
/// resumed context.
///
/// Tool results come back as a one-line record of *what ran* rather than what
/// it printed. See [`rebuild_tool_results`] for why, and for what is kept.
fn replay_history(path: &std::path::Path, n: usize) -> Vec<Value> {
    match agent::memory::read_tail(path, n) {
        Ok(lines) => {
            let msgs: Vec<Value> = lines
                .into_iter()
                .filter_map(|line| serde_json::from_str::<Value>(&line).ok())
                .collect();
            rebuild_tool_results(msgs)
        }
        Err(e) => {
            eprintln!("[agent] memory replay failed: {e}");
            Vec::new()
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
            if let (Some(id), Some(name)) =
                (call["id"].as_str(), call["function"]["name"].as_str())
            {
                names.insert(id.to_string(), name.to_string());
            }
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

/// The agent loop: multiplex crossterm events with the LLM turn stream, keep
/// conversation history, and drive the tool-call round-trip through `tools`.
/// The extra parameters (config, vm, initial history) are all loop state that
/// does not merit a struct yet.
#[allow(clippy::too_many_arguments)]
async fn run<W: Write>(
    terminal: &mut Terminal<CrosstermBackend<W>>,
    rx: &mut mpsc::UnboundedReceiver<CrosstermEvent>,
    lua_rx: &mut mpsc::UnboundedReceiver<agent::lua::AgentCommand>,
    app: &mut App,
    chat: &mut Chat,
    config: &agent::api::ChatConfig,
    vm: &mlua::Lua,
    catalog: &mut Catalog,
    initial_history: Vec<Value>,
) -> Result<()> {
    // The starting conversation: whatever earlier sessions archived and this
    // startup replayed (see `main`), else empty.
    let mut history = initial_history;
    // How much of `history` the conversation log has already seen (save-to-disk
    // watermark; see `save_history`). The replayed prefix already lives in the
    // log, so the watermark starts past it: only *new* messages get archived.
    let mut saved_upto: usize = history.len();
    let mut stream: Option<agent::api::TurnStream> = None;
    let mut builder = TurnBuilder::new();
    let mut tool_rounds: usize = 0;
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
    // A call that finished (or never started) and is waiting to be folded into
    // the conversation at the top of the next iteration.
    let mut pending_outcome: Option<ToolOutcome> = None;
    let mut round_sink: Option<agent::panels::PanelSink> = None;
    // The highest panel id handed out so far, carried across tool rounds: see
    // `PanelSink::continuing_from` for why an id has to outlive its sink.
    let mut next_panel_id: u64 = 0;
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
        if let Some(outcome) = pending_outcome.take() {
            // The call is over: no question can be outstanding, and the VM's
            // panel sink goes with it, so a panel opened outside a round reaches
            // no panel at all — as it did when every call had a VM of its own.
            pending_question = None;
            let _ = agent::lua::clear_sink(vm);
            fold_tool_outcome(app, &mut history, outcome, round_sink.as_ref());
            if !tool_queue.is_empty() {
                let (started, refused) = start_next_tool(
                    vm,
                    &mut tool_queue,
                    round_sink.as_ref(),
                    offered_tools(chat),
                )
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
            // The continuation is another request: re-index the registry again so
            // the tools stay current even between rounds of one turn.
            if let Err(e) = refresh_chat_tools(chat, config, vm) {
                app.push_boxed(
                    Role::Assistant,
                    format!("tools refresh failed: {e:#}"),
                    "error".into(),
                );
            } else {
                match chat.stream_turn(&request_history(vm, &history)).await {
                    Ok(s) => stream = Some(s),
                    Err(e) => {
                        app.push_boxed(
                            Role::Assistant,
                            format!("request failed: {e:#}"),
                            "error".into(),
                        );
                    }
                }
            }
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

        let busy = stream.is_some() || tool_flight.is_some();
        let tick = if busy {
            if tool_flight.is_some() {
                // A tool is executing: also wake on a short pulse so the loop
                // drains streamed ops and redraws while it runs — that's what
                // makes a long command's output appear live in its panel — and
                // gives a suspended sandbox run its next step.
                tokio::select! {
                    ev = rx.recv() => ev.map(Tick::Key),
                    tev = next_turn_event(&mut stream) => Some(Tick::Turn(tev)),
                    cmd = lua_rx.recv() => cmd.map(Tick::Lua),
                    _eev = next_event(&mut event_rx) => Some(Tick::Event(())),
                    _ = tokio::time::sleep(Duration::from_millis(20)) => Some(Tick::Pulse),
                }
            } else {
                tokio::select! {
                    ev = rx.recv() => ev.map(Tick::Key),
                    tev = next_turn_event(&mut stream) => Some(Tick::Turn(tev)),
                    cmd = lua_rx.recv() => cmd.map(Tick::Lua),
                    _eev = next_event(&mut event_rx) => Some(Tick::Event(())),
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
                        match ask_choice(key.code, question.always) {
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
                        Some(Ok(_)) if !app.key_may_act(&key) => {
                            default_key(app, key, busy)
                        }
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
                                        *chat = Chat::connect(config, tools.clone());
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
                            history.push(json!({"role": "user", "content": text}));
                            tool_rounds = 0;
                            // Reindex `agent.mcps` for this request (never
                            // cached) so the registry is already current in
                            // the tools offered to the model.
                            if let Err(e) = refresh_chat_tools(chat, config, vm) {
                                app.push_boxed(
                                    Role::Assistant,
                                    format!("tools refresh failed: {e:#}"),
                                    "error".into(),
                                );
                            } else {
                                match chat.stream_turn(&request_history(vm, &history)).await {
                                    Ok(s) => stream = Some(s),
                                    Err(e) => {
                                        app.push_boxed(
                                            Role::Assistant,
                                            format!("request failed: {e:#}"),
                                            "error".into(),
                                        );
                                    }
                                }
                            }
                        }
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
                        match ask_choice(KeyCode::Char(letter), question.always) {
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
                // A Lua handler forced a new inference (agent.trigger): it may
                // have replaced the in-memory history (a compacted history
                // handed back — the write side of compaction) and/or supplied
                // a user message. Only the idle select polls the channel, so
                // the loop is between turns here.
                agent::lua::AgentCommand::RunTurn {
                    history: replacement,
                    user,
                } => {
                    if let Some(replacement) = replacement {
                        let n = replacement.len();
                        history = replacement;
                        app.push_boxed(
                            Role::Assistant,
                            format!("history replaced by Lua ({n} messages); continuing."),
                            "config".into(),
                        );
                    }
                    if let Some(text) = user {
                        // Mirror a normal submission: `App::send` also records the
                        // user line in the transcript.
                        app.push(Role::User, text.clone());
                        history.push(json!({"role": "user", "content": text}));
                    }
                    tool_rounds = 0;
                    if let Err(e) = refresh_chat_tools(chat, config, vm) {
                        app.push_boxed(
                            Role::Assistant,
                            format!("tools refresh failed: {e:#}"),
                            "error".into(),
                        );
                    } else {
                        match chat.stream_turn(&request_history(vm, &history)).await {
                            Ok(s) => stream = Some(s),
                            Err(e) => {
                                app.push_boxed(
                                    Role::Assistant,
                                    format!("request failed: {e:#}"),
                                    "error".into(),
                                );
                            }
                        }
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
                    Some(Err(e)) => {
                        eprintln!("[agent] event turn_completed: {e}");
                        event = None;
                        event_rx = None;
                    }
                }
            }

            Tick::Turn(Some(Err(e))) => {
                stream = None;
                builder = TurnBuilder::new();
                app.clear_status();
                app.push_boxed(
                    Role::Assistant,
                    format!("turn failed: {e:#}"),
                    "error".into(),
                );
            }
            Tick::Turn(Some(Ok(ev))) => {
                // The turn is live. The bar is the only place that says so —
                // a streamed answer can take a while to say anything, and the
                // request's own latency is spent *before* this first event,
                // with the last frame still up.
                app.set_status_text_if_changed("streaming...", StatusKind::Info);
                match &ev {
                    TurnEvent::Reasoning(d) => {
                        // Streamed live into its own borderless "reasoning"
                        // block (never enters conversation history); the
                        // reasoning text renders dimmed, darker than the
                        // answer. Empty deltas are skipped so an all-empty
                        // reasoning stream never draws an empty block.
                        if !d.is_empty() {
                            app.stream_append_boxed(d, "reasoning".into());
                        }
                    }
                    TurnEvent::Content(d) => {
                        // The answer streams into its own "response" block;
                        // the seamless title switch breaks the reasoning block.
                        app.stream_append_boxed(d, "response".into());
                    }
                    TurnEvent::ToolCallDelta(_) | TurnEvent::Usage(_) | TurnEvent::Timings(_) => {}
                }
                builder.apply(ev);
            }
            Tick::Turn(None) => {
                // Turn over: surface everything, then run the tool round.
                // Reasoning and answer content were already streamed live into
                // their "reasoning"/"response" blocks; nothing to flush.
                stream = None;
                // "streaming..." described a turn that has now ended, and a
                // tool round is not streaming — so the bar goes empty rather
                // than stale. Anything a tool reports sets it again.
                app.clear_status();
                let turn = builder.finish();
                // What this request cost, for `agent.llm.usage` (read-only, and
                // written here so a `turn_completed` handler reads the turn that
                // just finished).
                agent::lua::record_usage(vm, turn.tokens());
                // The answer content was already streamed live into the panel's
                // "response" block (content events -> stream_append_boxed); do
                // not push it again.
                if let Some(summary) = turn.summary() {
                    app.push(Role::Assistant, summary);
                }

                // A turn *continues* into another tool round while the model
                // still wants tools and the round budget remains; otherwise
                // the user turn is complete (final answer, or the budget ran
                // out — the model's unanswered calls stay in the transcript
                // and a note names the cap).
                let continuing = turn.wants_tools() && tool_rounds < MAX_TOOL_ROUNDS;
                if continuing {
                    tool_rounds += 1;
                    history.push(assistant_tool_message(&turn.tool_calls));
                    // Queue the round's calls and start the first one. A tool
                    // is a coroutine on the config VM that the loop steps (see
                    // `start_next_tool`), so it only runs between frames; panel
                    // ops from policy Lua and the bash stream panel buffer in
                    // the round's shared sink, drained every frame while the
                    // tools run.
                    tool_queue = turn
                        .tool_calls
                        .iter()
                        .map(|c| (c.id.clone(), c.name.clone(), c.arguments.clone()))
                        .collect();
                    // `continuing_from`, not a fresh sink: a panel id is scoped
                    // to the transcript's id→message map, which outlives the
                    // round, so a counter that restarted here would hand round
                    // two's first panel an id round one had already used — and it
                    // would be appended to *that* panel, putting a write's
                    // content and its dialog in the read box above it.
                    round_sink = Some(agent::panels::PanelSink::continuing_from(next_panel_id));
                    // A call that never started (refused by the dispatch gate,
                    // or not in the registry) lands in `pending_outcome` and
                    // takes the same finish path a completed call does.
                    let (started, refused) = start_next_tool(
                        vm,
                        &mut tool_queue,
                        round_sink.as_ref(),
                        offered_tools(chat),
                    )
                    .map_err(anyhow::Error::msg)?;
                    tool_flight = started;
                    pending_outcome = refused;
                } else if turn.wants_tools() {
                    // The tool-round budget ran out while the model still
                    // wanted tools: keep whatever it said and name the cap.
                    app.push(
                        Role::Assistant,
                        format!(
                            "tool round limit ({MAX_TOOL_ROUNDS}) reached; giving up on this turn."
                        ),
                    );
                }
                // Text the model said alongside (or instead of) tool calls is
                // its own assistant message — assistant_tool_message carries
                // content: null, so it is not baked into the calls message.
                if !turn.content.is_empty() {
                    history.push(json!({"role": "assistant", "content": turn.content}));
                }
                if !continuing {
                    // The user turn is over: start `turn_completed` so a Lua
                    // handler can inspect the conversation (and compact it —
                    // see `agent::lua`'s config section). It runs as a
                    // coroutine on this thread, suspended by its
                    // `agent.on_timeout` waits rather than blocking the loop.
                    start_turn_completed(vm, &history, &mut event, &mut event_rx);
                }
                builder = TurnBuilder::new();
            }
            Tick::Pulse => {} // periodic wake while a tool runs: drained + redrawn below
        }

        // Apply any panel ops that streamed in since the last frame — a
        // running bash command appends its stdout chunks to the round's sink
        // as the loop steps it, so the box fills live.
        if let Some(s) = &round_sink {
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

        // Archive this iteration's new history messages (watermark-backed, so
        // each message is logged exactly once). Flush when the turn is fully
        // over — no stream and no tool in flight — so every finished turn is
        // durably on disk (group commit; `/save` flushes early).
        save_history(
            &history,
            &mut saved_upto,
            stream.is_none() && tool_flight.is_none() && pending_outcome.is_none(),
        );

        terminal.autoresize()?;
        terminal.draw(|frame| app.render(frame))?;
        // Force the frame to the terminal fd (belt and braces on top of
        // ratatui's own backend flush).
        stderr().flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use agent::testutil::unique_path;
    use super::*;

    /// The `key` event end to end, from a `KeyEvent` to the action the loop will
    /// perform: the spec the table matches on, the parsing, and the two ways it
    /// can come back empty.
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
    /// `Ctrl+d` is the example because the override is *observable* there: bound
    /// to `conceal` it does something visibly different from the default `quit`.
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
        assert_eq!(app.handle_key(ctrl_d), Effect::Quit, "and Rust's default is to leave");

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
    /// `false`, not a silent success: a binding whose edit went nowhere would look
    /// like a key that does nothing, which is the one failure a keybinding feature
    /// must not have. Same contract as `agent.trigger`, and for the same reason —
    /// headless runs and the probe have no loop to drain the command.
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

    #[test]
    fn replay_history_parses_the_newest_n_chronologically() {
        let path = unique_log("replay");
        let messages = [
            r#"{"role":"user","content":"m0"}"#,
            r#"{"role":"assistant","content":"a0"}"#,
            r#"{"role":"user","content":"m1"}"#,
            r#"{"role":"assistant","content":"a1"}"#,
            r#"{"role":"user","content":"m2"}"#,
        ];
        {
            // Fresh log, five small messages: `flush` seals the pending block
            // (there is no per-message fsync / auto seal below block_target).
            let mut mem = agent::memory::Memory::open(&path).unwrap();
            for m in &messages {
                mem.append(m).unwrap();
            }
            mem.flush().unwrap();
        }
        let replayed = replay_history(&path, 2);
        assert_eq!(replayed.len(), 2);
        assert_eq!(replayed[0]["content"], "a1", "oldest-to-newest of the tail");
        assert_eq!(replayed[0]["role"], "assistant");
        assert_eq!(replayed[1]["content"], "m2");
        let _ = std::fs::remove_file(&path);
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
    #[test]
    fn a_replayed_tool_result_becomes_one_line_about_the_call() {
        let bulky = "x".repeat(40_000);
        let path = unique_log("replay-tool");
        {
            let mut mem = agent::memory::Memory::open(&path).unwrap();
            for m in [
                r#"{"role":"user","content":"read the file"}"#,
                r#"{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"fs.read","arguments":"{\"path\":\"a.rs\"}"}}]}"#,
                &format!(
                    r#"{{"role":"tool","tool_call_id":"call_1","content":"{bulky}"}}"#
                ),
            ] {
                mem.append(m).unwrap();
            }
            mem.flush().unwrap();
        }
        let replayed = replay_history(&path, 10);
        let tool = replayed
            .iter()
            .find(|m| m["role"] == "tool")
            .expect("the result is still a message");

        assert_eq!(tool["role"], "tool", "still a tool message");
        assert_eq!(tool["tool_call_id"], "call_1", "and still paired by id");
        let content = tool["content"].as_str().expect("a string");
        assert!(
            content.contains("fs.read"),
            "it names the tool, resolved from the parent: {content}"
        );
        assert!(
            content.contains("not replayed"),
            "and says the output is gone rather than pretending it was empty: {content}"
        );
        assert!(
            content.len() < 120,
            "one line, not 40 kB: {} bytes",
            content.len()
        );
        // The user turn is untouched: only results are rebuilt.
        assert_eq!(replayed[0]["content"], "read the file");
        let _ = std::fs::remove_file(&path);
    }

    /// A result whose parent assistant message fell outside the replay window is
    /// **dropped**, not kept and not renamed.
    ///
    /// This is the ordinary case, not an edge: the window is the newest 20
    /// messages, so it starts mid-turn whenever the last session ended on a tool
    /// round. Keeping the orphan would make the first request of the session
    /// invalid on a strict server — `tool` with no matching `tool_calls` is a 400
    /// on OpenAI, which is the endpoint the shipped config names. Measured
    /// llama-server accepts it (200 either way), so this only bites the default
    /// configuration, which is the wrong place for a landmine.
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
    /// One paired round in the middle proves the mapping is by id and not by
    /// position: the rebuild must survive unrelated `tool_calls` elsewhere.
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
    /// Measured rather than asserted by eye, because "much smaller" is the whole
    /// claim and it is worth knowing the ratio. It is also the number to watch if
    /// the replay window is ever changed: this is what the window is spending.
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
            replay_history(&gone, 5).is_empty(),
            "a missing log replays nothing"
        );
        let path = unique_log("replay-empty");
        {
            let _mem = agent::memory::Memory::open(&path).unwrap(); // header only
        }
        assert!(
            replay_history(&path, 5).is_empty(),
            "an empty log replays nothing"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The dispatch gate: a tool call runs only if this request offered that
    /// name. A mode that swapped the registry, a tool nobody registered, and an
    /// old call replayed out of the history all land here.
    #[test]
    /// A failed fetch must not wedge the queue.
    ///
    /// This is a regression test, and the bug it pins was in the wiring rather
    /// than in any logic: the task reported *successes* down the channel and
    /// logged failures to the status line instead, while the loop's "one at a
    /// time" flag was cleared only by receiving something. So a single fence naming
    /// a language that could not be fetched — offline, or a name nobody published —
    /// left the flag set and every grammar behind it unfetched for the rest of the
    /// session. Nothing crashed and nothing was logged as an error; highlighting
    /// just silently stopped improving.
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
        let lang = q.take_next().expect("rust is wanted and nothing is in flight");

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
            ["bash.bash".to_string(), "fs.read".to_string()].into_iter().collect();
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

    /// The three answers, and the rule that makes "always" conditional: `a` is
    /// an answer only when the question offered it. Without that, a stray `a`
    /// would be read as "yes, and remember" for a question that has nothing to
    /// remember.
    #[test]
    fn the_ask_keys_offer_always_only_when_the_question_did() {
        use crossterm::event::KeyCode;
        // Offered: all three.
        assert_eq!(ask_choice(KeyCode::Char('y'), true), Some(AskChoice::Yes));
        assert_eq!(ask_choice(KeyCode::Char('n'), true), Some(AskChoice::No));
        assert_eq!(ask_choice(KeyCode::Char('a'), true), Some(AskChoice::Always));
        // Uppercase too — the answer is not case-sensitive.
        assert_eq!(ask_choice(KeyCode::Char('A'), true), Some(AskChoice::Always));
        assert_eq!(ask_choice(KeyCode::Char('Y'), false), Some(AskChoice::Yes));
        // Not offered: `a` answers nothing, and neither does anything else —
        // a question on screen must not eat the user's typing.
        assert_eq!(ask_choice(KeyCode::Char('a'), false), None);
        assert_eq!(ask_choice(KeyCode::Char('A'), false), None);
        for code in [
            KeyCode::Char('x'),
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Up,
            KeyCode::Char('c'),
        ] {
            assert_eq!(ask_choice(code, true), None, "{code:?} is not an answer");
        }
    }
    /// A tool call is invisible in the transcript: not its arguments, not its
    /// result, not an error. A tool reports itself, or does not.
    ///
    /// This inverts the rule that was here an hour ago, and the inversion is
    /// deliberate. The box existed to make a silent call checkable, and it did
    /// the opposite: raw JSON arguments above a raw result envelope, the
    /// loudest thing on screen for a tool that had said nothing. And a tool that
    /// *had* spoken — the shell, `apply_patch` — got its output printed twice.
    ///
    /// The model is unaffected, which is the part that must not break: the
    /// result is still archived as a `tool` message, so a failure the user
    /// cannot see is still a failure the model can see and act on.
    #[test]
    fn a_tool_call_leaves_nothing_in_the_transcript_but_still_reaches_the_model() {
        let render = |app: &mut App| {
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(60, 12))
                    .expect("terminal");
            terminal.draw(|frame| app.render(frame)).expect("draw");
            let buf = terminal.backend().buffer();
            (0..12)
                .flat_map(|y| {
                    (0..60)
                        .map(move |x| {
                            buf.cell((x, y))
                                .map(|c| c.symbol())
                                .unwrap_or(" ")
                                .to_string()
                        })
                })
                .collect::<String>()
        };

        // A success, with a panel in the sink and without. Neither prints.
        for drew in [true, false] {
            let mut app = App::default();
            let mut history = Vec::new();
            let sink = agent::panels::PanelSink::default();
            if drew {
                // `Create` only registers the panel; the message appears on the
                // first `Append`, so a sink holding a bare `Create` renders as
                // an empty panel and would make this test pass for the wrong
                // reason.
                sink.push(agent::panels::PanelOp::Create {
                    id: 1,
                    title: "cat /etc/hostname".into(),
                    boxed: true,
                    conceal_box: false,
                });
                sink.push(agent::panels::PanelOp::Append {
                    id: 1,
                    text: "may-Legion-R9000P-AFR10H\n".into(),
                });
            }
            fold_tool_outcome(
                &mut app,
                &mut history,
                ToolOutcome {
                    id: "call_1".into(),
                    result: Ok((r#"{"ok":true,"result":{"n":3}}"#.into(), "{}".into())),
                },
                Some(&sink),
            );
            assert_eq!(
                history.len(),
                1,
                "the model reads the result back: {history:?}"
            );
            assert_eq!(history[0]["role"], "tool");
            assert_eq!(history[0]["tool_call_id"], "call_1");
            // The only thing on screen is what the tool drew — nothing else.
            let screen = render(&mut app);
            assert!(
                !screen.contains("ok\":true") && !screen.contains("tool_call_id"),
                "the result is not printed (drew={drew}):\n{screen}"
            );
            assert_eq!(
                screen.contains("cat /etc/hostname"),
                drew,
                "the tool's own panel is the whole visual (drew={drew}):\n{screen}"
            );
        }

        // A failure is silent too. The tool is in charge of saying so; this one
        // chose not to, and the transcript honours that.
        let mut app = App::default();
        let mut history = Vec::new();
        let sink = agent::panels::PanelSink::default();
        fold_tool_outcome(
            &mut app,
            &mut history,
            ToolOutcome {
                id: "call_2".into(),
                result: Err("the sandbox refused to start".into()),
            },
            Some(&sink),
        );
        assert_eq!(history.len(), 1);
        assert!(
            history[0]["content"]
                .as_str()
                .is_some_and(|c| c.contains("the sandbox refused to start")),
            "the model still learns it failed: {:?}",
            history[0]
        );
        let screen = render(&mut app);
        assert!(
            !screen.contains("refused to start"),
            "and the user is told nothing by the loop:\n{screen}"
        );
    }


}
