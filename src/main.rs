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
//! `/reload` re-reads ./agent.lua — endpoint, system prompt, `agent.mcps`
//! tools — without restarting; `/save` flushes the conversation log to disk
//! and reports where it went. Nothing else is a local command.
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
    // Configuration lives in Lua (./agent.lua, else ~/.config/agent/agent.lua):
    // the LLM endpoint (base_url / model / api_key — formerly AGENT_BASE_URL /
    // AGENT_MODEL / AGENT_API_KEY), the system prompt, and the tools
    // registered in `agent.mcps`. `config_vm` stays on the main thread: every
    // request reindexes that live table and re-reads the prompt, while
    // per-call MCP tool invocations build their own VM on the tool thread.
    let config_vm =
        agent::lua::new_vm_with_sink(None).map_err(|e| anyhow::anyhow!("config vm: {e}"))?;
    let loaded = agent::lua::load_config_file(&config_vm).map_err(anyhow::Error::msg)?;
    match agent::lua::config_path() {
        Some(p) => println!(
            "config: {} ({})",
            p.display(),
            if loaded {
                "user Lua config loaded"
            } else {
                "no user config"
            }
        ),
        None => {
            println!(
                "config: no agent.lua in cwd or ~/.config/agent — using the defaults \
                 (and so, no tools)"
            )
        }
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
    // is a startup decision: `/reload` re-reads agent.lua but cannot rebind
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
    let mut catalog = Catalog::new();
    let results = catalog
        .ensure_many(&["markdown", "markdown_inline", "bash", "json"])
        .await;
    for (lang, r) in &results {
        if let Err(e) = r {
            eprintln!("[agent] grammar {lang} unavailable ({e}); that content stays plain");
        }
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
                } else if let Some(names) = tool_call_names(msg) {
                    // The archive stores the calls, not the rendered boxes:
                    // a resumed tool round collapses to one named box.
                    app.push_boxed(
                        Role::Assistant,
                        format!("invoked tools: {names}"),
                        "tools".into(),
                    );
                }
            }
            _ => {} // tool results: their call's box already tells the story
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
             (/reload re-reads agent.lua; /save flushes the log to disk).",
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
/// turn event (`None` = the current turn's stream ended), a finished tool
/// call from its background thread, a pending user-permission ask from the
/// running tool (`None` = the ask channel closed), the reactor's timer poke
/// for a suspended `turn_completed` handler, or a periodic pulse while a
/// tool runs.
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

/// A finished tool call: the call identity (for the transcript) plus the
/// outcome — `Ok((body, content))` or an executor error message. Produced by
/// the flight below, whether it finished normally, was refused by the dispatch
/// gate, or raised.
struct ToolOutcome {
    id: String,
    name: String,
    arguments: String,
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
    name: String,
    arguments: String,
    run: agent::lua::ToolRun<'lua>,
    step: agent::lua::ToolStep,
}

impl ToolFlight<'_> {
    /// The call ended in an executor error rather than a result.
    fn failed(&self, why: String) -> ToolOutcome {
        ToolOutcome {
            id: self.id.clone(),
            name: self.name.clone(),
            arguments: self.arguments.clone(),
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
                name: name.clone(),
                arguments: arguments.clone(),
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
            Some(ToolFlight {
                id,
                name,
                arguments,
                run,
                step,
            }),
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
                name: flight.name.clone(),
                arguments: flight.arguments.clone(),
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

/// Fold a finished tool call into the conversation: the result (or the error) in
/// the transcript, and the `tool` message the model reads back. The round's
/// panel ops are drained here too, so everything the tool drew lands at once.
fn fold_tool_outcome(
    app: &mut App,
    history: &mut Vec<serde_json::Value>,
    outcome: ToolOutcome,
    round_sink: Option<&agent::panels::PanelSink>,
) {
    let ToolOutcome {
        id,
        name,
        arguments,
        result,
    } = outcome;
    match result {
        Ok((body, content)) => {
            // bash's visual is its streamed stdout panel — created and fed by
            // the Lua driver while the sandbox ran, so no JSON result box here;
            // the other tools keep their plain call + result box.
            if name != "bash" {
                app.push_boxed(
                    Role::Assistant,
                    format!("{name} {arguments}\n\n{body}"),
                    name.clone(),
                );
            }
            history.push(json!({
                "role": "tool",
                "tool_call_id": id,
                "content": content,
            }));
        }
        Err(msg) => {
            app.push_boxed(
                Role::Assistant,
                format!("{name} {arguments}\n\n{msg}"),
                "error".into(),
            );
            history.push(json!({
                "role": "tool",
                "tool_call_id": id,
                "content": json!({"error": msg}).to_string(),
            }));
        }
    }
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
/// the model no tools at all). `vm` is the main-thread config VM — the live Lua
/// table is reindexed on every call and **never cached in Rust**, so an
/// agent.lua edit (picked up by `/reload`) is advertised on the very next
/// request (see `agent::lua`'s config section).
fn tool_defs(vm: &mlua::Lua) -> Result<Vec<api::ToolDef>> {
    Ok(tools::adopt_mcp_tools(
        agent::lua::mcps_tool_defs(vm).map_err(anyhow::Error::msg)?,
    ))
}

/// Whether a tool call may run: only a name this request actually offered.
///
/// The tool VM loads a *fresh* registry (it re-runs `agent.lua`), so "not
/// advertised" is not by itself "not callable" — a mode that replaced
/// `agent.mcps`, an unregistered tool, or an old tool call replayed out of the
/// history would each find a working tool by name. The request's own tool list
/// is the gate, so what the model was shown is exactly what it can run.
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
/// request is what keeps an agent.lua edit immediate; the swap is the minimal
/// step that surfaces the change to the frozen `api::Chat`, which fixes its
/// tools at connect time).
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
/// coroutine and arms a reactor timer instead of freezing the loop; the old
/// `spawn_blocking` background thread is gone. Its `agent.trigger(...)` command
/// arrives back here through the loop's trigger channel.
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

/// The tool names in an archived assistant tool-call message, joined for the
/// resumed-history transcript (the log stores the calls, not the rendered
/// per-call boxes). `None` when the message carries no tool calls.
fn tool_call_names(msg: &Value) -> Option<String> {
    let names: Vec<&str> = msg["tool_calls"]
        .as_array()?
        .iter()
        .filter_map(|c| c["function"]["name"].as_str())
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names.join(", "))
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
            // A question the tool is waiting on. Its wording is drawn here rather
            // than only as a panel overlay, so a tool with no panel (every file
            // operation) still shows the user what it is asking.
            if let Some(q) = question {
                if !q.text.is_empty() {
                    app.push_boxed(
                        Role::Assistant,
                        format!(
                            "{}\n\n{}",
                            q.text,
                            if q.always {
                                "[y]es  [n]o  [a]lways"
                            } else {
                                "[y]es  [n]o"
                            }
                        ),
                        "ask".into(),
                    );
                }
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
                                app.push_boxed(
                                    Role::Assistant,
                                    format!(
                                        "{}",
                                        match choice {
                                            AskChoice::Yes => "allowed",
                                            AskChoice::Always => "allowed, and remembered",
                                            AskChoice::No => "denied",
                                        }
                                    ),
                                    "ask".into(),
                                );
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
                            // up agent.lua edits), then re-derive the tool
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
                                                    "reloaded (./agent.lua)"
                                                } else {
                                                    "reloaded (defaults: no agent.lua)"
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
                let step = match event.as_mut() {
                    Some(run) => Some(run.step()),
                    None => None,
                };
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
                app.push_boxed(
                    Role::Assistant,
                    format!("turn failed: {e:#}"),
                    "error".into(),
                );
            }
            Tick::Turn(Some(Ok(ev))) => {
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
                let turn = builder.finish();
                // What this request cost, for `agent.llm.usage` (read-only, and
                // seeded into every later VM).
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
                    // Queue the round's calls and start the first one. Tools
                    // run on background threads (see `start_next_tool`) so the
                    // loop keeps rendering; panel ops from policy Lua and the
                    // bash stream panel buffer in the round's shared sink,
                    // drained every frame while the tools run.
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
        // on its own thread, so the box fills live.
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
            ["bash".to_string(), "read_file".to_string()].into_iter().collect();
        assert!(may_run("bash", &offered).is_ok());
        assert!(may_run("read_file", &offered).is_ok());

        // A mode's dropped tool: well-formed, registered in the fresh VM the
        // tool call would load, and still refused.
        let e = may_run("write_file", &offered).unwrap_err();
        assert!(e.contains("write_file"), "{e}");
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

    #[test]
    fn tool_call_names_lists_calls_from_an_archived_message() {
        // The shape the loop archives: assistant, content null, calls array.
        let msg = serde_json::json!({
            "role": "assistant",
            "content": null,
            "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "bash", "arguments": "{}"}},
                {"id": "call_2", "type": "function", "function": {"name": "probe_tool", "arguments": "{}"}},
            ],
        });
        assert_eq!(tool_call_names(&msg).unwrap(), "bash, probe_tool");
        assert!(tool_call_names(&serde_json::json!({"role": "user"})).is_none());
        assert!(tool_call_names(&serde_json::json!({"tool_calls": []})).is_none());
    }
}
