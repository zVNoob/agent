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

// api.rs is shared, frozen, and included per-binary; from_env is now unused
// here because the endpoint comes from Lua config (see `main`), so allow it.
#[allow(dead_code)]
mod api;
mod tools;

use agent::grammars::Catalog;
use agent::status::StatusKind;
use agent::tui::{App, MarkdownHighlighter, Role};
use anyhow::Result;
use api::{Chat, TurnBuilder, TurnEvent, assistant_tool_message};
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
use std::collections::VecDeque;
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
    let config = api::ChatConfig {
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
    stream: &mut Option<api::TurnStream>,
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
fn tool_defs(vm: &mlua::Lua) -> Result<Vec<api::ToolDef>> {
    Ok(tools::adopt_mcp_tools(
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
/// that surfaces the change to the frozen `api::Chat`, which fixes its tools at
/// connect time).
fn refresh_chat_tools(chat: &mut Chat, config: &api::ChatConfig, vm: &mlua::Lua) -> Result<()> {
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
fn replay_history(path: &std::path::Path, n: usize) -> Vec<Value> {
    match agent::memory::read_tail(path, n) {
        Ok(lines) => lines
            .into_iter()
            .filter_map(|line| serde_json::from_str::<Value>(&line).ok())
            .collect(),
        Err(e) => {
            eprintln!("[agent] memory replay failed: {e}");
            Vec::new()
        }
    }
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
    config: &api::ChatConfig,
    vm: &mlua::Lua,
    initial_history: Vec<Value>,
) -> Result<()> {
    // The starting conversation: whatever earlier sessions archived and this
    // startup replayed (see `main`), else empty.
    let mut history = initial_history;
    // How much of `history` the conversation log has already seen (save-to-disk
    // watermark; see `save_history`). The replayed prefix already lives in the
    // log, so the watermark starts past it: only *new* messages get archived.
    let mut saved_upto: usize = history.len();
    let mut stream: Option<api::TurnStream> = None;
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
                    _eev = next_event(&mut event_rx) => Some(Tick::Event(())),
                    _ = tokio::time::sleep(Duration::from_millis(20)) => Some(Tick::Pulse),
                }
            } else {
                tokio::select! {
                    ev = rx.recv() => ev.map(Tick::Key),
                    tev = next_turn_event(&mut stream) => Some(Tick::Turn(tev)),
                    _eev = next_event(&mut event_rx) => Some(Tick::Event(())),
                }
            }
        } else {
            // Idle: wait for terminal input or a Lua-forced inference
            // (agent.trigger). Commands sent while the loop is busy stay
            // queued and are picked up at the next idle moment — right after
            // the current turn finishes, which is when compaction handlers
            // want to run anyway. A suspended `turn_completed` handler is
            // resumed here too, on its timer pokes.
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
                    // everything else is ignored until the user decides
                    // (Ctrl+C / Esc still quit). `a` is a verdict only when the
                    // question offered "always".
                    if key.kind == KeyEventKind::Press {
                        match ask_choice(key.code, question.always) {
                            Some(choice) => {
                                // The answer is handed to the tool's coroutine on
                                // the next step (the top of the loop), as the
                                // value its question yielded for.
                                let answer = match choice {
                                    AskChoice::Yes => agent::lua::AskAnswer::Allow,
                                    AskChoice::Always => agent::lua::AskAnswer::AllowAndTrust,
                                    AskChoice::No => agent::lua::AskAnswer::Deny(Some(
                                        "denied by user".to_string(),
                                    )),
                                };
                                pending_verdict = Some(agent::lua::verdict_to_lua(vm, &answer));
                                // The decision goes on the status bar, not into
                                // the transcript. A cold command asks dozens of
                                // times, and a message per answer buried the run
                                // it was reporting on; the bar is one line and
                                // holds exactly the latest.
                                let outcome = match choice {
                                    AskChoice::Yes => "allowed",
                                    AskChoice::Always => "allowed, and remembered",
                                    AskChoice::No => "denied",
                                };
                                let kind = if choice == AskChoice::No {
                                    agent::status::StatusKind::Warn
                                } else {
                                    agent::status::StatusKind::Done
                                };
                                app.set_status_text(outcome, kind);
                            }
                            None => match key.code {
                                KeyCode::Char('c')
                                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                                {
                                    break;
                                }
                                KeyCode::Esc => break,
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
                    // Mid-turn Enter is ignored: the typed text stays in the
                    // input and submits once the current turn ends.
                    let quit = if busy && is_submit_key(&key) {
                        false
                    } else {
                        app.handle_key(key)
                    };
                    if quit {
                        break;
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
            Tick::Key(CrosstermEvent::Mouse(ev)) => {
                app.handle_mouse(ev);
            }
            Tick::Key(_) => {} // resize and friends: just redraw below

            Tick::Lua(cmd) => {
                // A Lua handler forced a new inference (agent.trigger): it may
                // have replaced the in-memory history (a compacted history
                // handed back — the write side of compaction) and/or supplied
                // a user message. Only the idle select polls the channel, so
                // the loop is between turns here.
                let agent::lua::AgentCommand::RunTurn {
                    history: replacement,
                    user,
                } = cmd;
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
                    round_sink = Some(agent::panels::PanelSink::default());
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
    use super::*;

    /// Sequence for [`unique_log`]: distinct paths across parallel tests.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A unique temp log path for one test (pid + sequence): parallel tests
    /// never collide.
    fn unique_log(name: &str) -> std::path::PathBuf {
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("agent-mem-{name}-{}-{seq}", std::process::id()))
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
