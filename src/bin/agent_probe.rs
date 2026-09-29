//! Headless agent probe: drive a real chat-completions server (e.g. a local
//! llama.cpp `llama serve` running Gemma 4 E2B) through the **same tool
//! round-trip the TUI's `run` loop performs** — the model requests a tool →
//! the agent executes it from the Lua registry (`agent.mcps` on the probe's
//! own config VM; the `bash` tool runs through the seccomp sandbox + Lua
//! policy) → the result is fed back → the model continues.
//!
//! The catalog is the registry too, so a tool the model calls that the
//! configuration does not register is an error here exactly as it is in the
//! TUI. Asks auto-deny: the probe has no user, so the shell stays read-only.
//!
//! Each argv argument after the program name is one user turn (shared
//! history). Output is machine-labeled so a script can tell model content,
//! tool calls, and tool results apart:
//!
//! ```text
//! [user] <prompt>
//! [reasoning] <streamed reasoning>          (stderr; only if the model has any)
//! <streamed model content>
//! [tool-call] bash {"cmdline":"..."}
//! [tool-result] {"stdout":"...","exit_code":0,...}
//! [done]
//! ```
//!
//! The labels are once per item, never inside one: reasoning in particular
//! streams a token at a time, and a label repeated per token is a label a script
//! has to strip out of the middle of a field. Reasoning goes to stderr, so
//! stdout stays exactly "the model, its tool calls, and their results" and can be
//! piped somewhere on its own.
//!
//! Config: `~/.config/agent/init.lua` (the LLM endpoint and the system prompt,
//! the same Lua configuration the TUI reads); the `AGENT_BASE_URL` / `AGENT_MODEL` /
//! `AGENT_API_KEY` env vars remain a dev-harness override of the endpoint when
//! *any* is set.
//!
//! Events: after `[done]`, the probe fires the same `turn_completed` event the
//! TUI fires — the conversation as `{ history = {...} }` — on that same config
//! VM, whose panel sink is what prints a handler's `agent.panel` ops as
//! `[event-op]`.
//! Unlike the TUI, the probe has no idle loop, so `agent.trigger` is not bound
//! (it returns `false` inside handlers): check it if your compaction handler
//! depends on the write side.

use agent::api;
use anyhow::Result;
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::io::Write;

const MAX_TOOL_ROUNDS: usize = 8;

/// The agent's configuration lives in Lua (`~/.config/agent/init.lua` — the LLM endpoint,
/// system prompt, and conversation-log settings, read via `agent::lua`); the
/// `AGENT_*` env vars still override the *endpoint* here when set, so an
/// existing headless invocation keeps working unchanged. The system prompt has
/// no env override: it is pure Lua configuration, sent as the leading `system`
/// message of every request. The conversation-log config comes along so main
/// can open the same store the TUI does (path + on/off from
/// `agent.llm.memory`).
fn config_from_lua_or_env() -> (api::ChatConfig, String, agent::lua::MemoryConfig) {
    // The user's own `~/.config/agent/init.lua`, seeded on first run — the same
    // configuration the TUI reads, not a second opinion.
    let vm = agent::lua::new_agent_vm(None)
        .map(|(vm, _)| vm)
        .map_err(|e| e.to_string());
    // The prompt is pure Lua config: unlike the endpoint, it has no env
    // override, so a Lua failure just means "no system prompt".
    let prompt = vm
        .as_ref()
        .ok()
        .and_then(|vm| agent::lua::system_prompt(vm).ok())
        .unwrap_or_default();
    let memcfg = vm
        .as_ref()
        .ok()
        .and_then(|vm| agent::lua::memory_config(vm).ok())
        .unwrap_or_default();
    if std::env::var_os("AGENT_BASE_URL").is_some()
        || std::env::var_os("AGENT_API_KEY").is_some()
        || std::env::var_os("AGENT_MODEL").is_some()
    {
        return (api::ChatConfig::from_env(), prompt, memcfg);
    }
    match vm {
        Ok(vm) => match agent::lua::llm_config(&vm) {
            Ok(llm) => (
                api::ChatConfig {
                    base_url: llm.base_url,
                    api_key: llm.api_key,
                    model: llm.model,
                },
                prompt,
                memcfg,
            ),
            Err(e) => {
                eprintln!("[probe] warning: Lua config unavailable ({e}); falling back to env");
                (api::ChatConfig::from_env(), prompt, memcfg)
            }
        },
        Err(e) => {
            eprintln!("[probe] warning: Lua config unavailable ({e}); falling back to env");
            (api::ChatConfig::from_env(), prompt, memcfg)
        }
    }
}

/// Put SIGPIPE back to its default disposition.
///
/// Rust ignores it, which turns the most ordinary thing anyone does with a
/// command-line tool — `agent_probe | head` — into a panic on the way out:
/// `head` exits, our next `println!` gets EPIPE, and the process dies with
/// "failed printing to stdout: Broken pipe" instead of finishing the work it was
/// asked to do. The default disposition is a silent exit, which is what every
/// other tool in a pipeline does and what a script reading our exit status
/// expects.
///
/// `unsafe` because `signal` is `signal`; this is the documented idiom and there
/// is no safe wrapper, since the whole point is to change a process-global the
/// runtime set on our behalf.
fn restore_sigpipe() {
    // SAFETY: `signal` with SIG_DFL is async-signal-safe and is called here,
    // before any other thread this binary starts exists.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    restore_sigpipe();
    let (config, system_prompt, memcfg) = config_from_lua_or_env();
    // The config VM the tool registry and the `turn_completed` handlers share —
    // mlua VMs cannot cross threads, so it is created here on this thread. Its
    // sink is where a handler's `agent.panel` ops land, exactly as the TUI's
    // round sink collects them; the probe prints them at `[done]`.
    let event_sink = agent::panels::PanelSink::default();
    let vm = match agent::lua::new_agent_vm(Some(&event_sink)) {
        Ok((vm, _)) => vm,
        Err(e) => {
            // The user config is *optional* — the probe is a dev harness and the
            // endpoint can come from the environment instead — so a config that
            // will not load is a warning, not the end. A tree that will not load
            // is not optional at all: there is no tool registry without it and
            // nothing this binary does would work, so it propagates and `main`
            // prints it. Reported rather than panicked, because the difference
            // between "your Lua tree is missing, here are the four places we
            // looked" and "thread 'main' panicked" is the whole value of a good
            // error message.
            eprintln!("[probe] warning: Lua config unavailable ({e}); no tools advertised");
            agent::lua::new_vm().map_err(|e| anyhow::anyhow!("{e}"))?
        }
    };

    // Open the conversation log exactly like the TUI (path + on/off from
    // `agent.llm.memory`) so the probe archives each finished turn and any
    // Lua `agent.memory` handler persists against the same store. A failed
    // open degrades to "no persistence" rather than failing the probe.
    if memcfg.enabled {
        match agent::memory::Memory::open(&memcfg.path) {
            Ok(mem) => {
                agent::lua::bind_memory(std::sync::Arc::new(std::sync::Mutex::new(mem)))
                    .expect("memory log bound once");
                println!("[probe] memory={}", memcfg.path.display());
            }
            Err(e) => eprintln!(
                "[probe] warning: conversation log {} failed to open: {e:#}",
                memcfg.path.display()
            ),
        }
    } else {
        println!("[probe] memory=disabled");
    }
    // How much of `messages` the conversation log has already seen
    // (save-to-disk watermark; see the archive at [done] below).
    let mut saved_upto: usize = 0;

    // The tool catalog is the Lua registry, reindexed exactly as the TUI does
    // per request: whatever the configuration registered.
    let tool_defs = agent::lua::mcps_tool_defs(&vm)
        .map(agent::tools::adopt_mcp_tools)
        .unwrap_or_default();
    let chat = api::Chat::connect(&config, tool_defs);
    let offered: std::collections::HashSet<String> = chat
        .tools()
        .iter()
        .map(|t| t.function.name.clone())
        .collect();
    let names: Vec<String> = chat
        .tools()
        .iter()
        .map(|t| t.function.name.clone())
        .collect();
    println!(
        "[probe] endpoint={} model={} system_prompt={} tools={}",
        chat.endpoint(),
        chat.model(),
        if system_prompt.trim().is_empty() {
            "none"
        } else {
            "set"
        },
        names.join(",")
    );
    let _ = std::io::stdout().flush();

    let prompts: Vec<String> = std::env::args().skip(1).collect();
    let prompts: Vec<String> = if prompts.is_empty() {
        vec!["Use the bash tool to run: echo hello-from-sandbox".to_string()]
    } else {
        prompts
    };

    // The conversation, prefixed with the configured system prompt (empty ->
    // no system message, exactly as in the TUI).
    let mut messages: Vec<Value> = Vec::new();
    if !system_prompt.trim().is_empty() {
        messages.push(json!({"role": "system", "content": system_prompt}));
    }
    for prompt in prompts {
        println!("[user] {prompt}");
        messages.push(json!({"role": "user", "content": prompt}));
        let mut tool_rounds: usize = 0;
        loop {
            let mut stream = match chat.stream_turn(&messages).await {
                Ok(s) => s,
                Err(e) => {
                    println!("[error] request failed: {e:#}");
                    break;
                }
            };
            let mut builder = api::TurnBuilder::new();
            let mut failed: Option<String> = None;
            // One label per *block*, not per delta. Reasoning arrives a token at
            // a time, so printing the label with each one turned a readable line
            // into `[reasoning] The[reasoning]  user[reasoning]  wants[reasoning] `,
            // which is the opposite of what this output is for: the file header
            // promises a machine-readable stream, and a label repeated inside the
            // payload is a label a script has to strip from the middle of a
            // field.
            let mut reasoning_open = false;
            while let Some(ev) = stream.next().await {
                let ev = match ev {
                    Ok(e) => e,
                    Err(e) => {
                        failed = Some(format!("{e:#}"));
                        break;
                    }
                };
                match &ev {
                    api::TurnEvent::Content(d) => {
                        if reasoning_open {
                            reasoning_open = false;
                            eprintln!();
                        }
                        print!("{d}");
                        let _ = std::io::stdout().flush();
                    }
                    api::TurnEvent::Reasoning(d) => {
                        if !reasoning_open {
                            reasoning_open = true;
                            eprint!("[reasoning] ");
                        }
                        eprint!("{d}");
                        let _ = std::io::stderr().flush();
                    }
                    _ => {}
                }
                builder.apply(ev);
            }
            if reasoning_open {
                eprintln!();
            }
            println!();
            let _ = std::io::stdout().flush();
            if let Some(e) = failed {
                println!("[error] turn failed: {e}");
                break;
            }
            let turn = builder.finish();
            // What this request cost, for `agent.llm.usage` (read-only, and seeded
            // into every later VM).
            agent::lua::record_usage(&vm, turn.tokens());
            if let Some(summary) = turn.summary() {
                println!("[usage] {summary}");
            }
            if turn.wants_tools() && tool_rounds < MAX_TOOL_ROUNDS {
                tool_rounds += 1;
                messages.push(api::assistant_tool_message(&turn.tool_calls));
                for c in &turn.tool_calls {
                    println!("[tool-call] {} {}", c.name, c.arguments);
                    // The same gate the TUI applies: only a name this request
                    // offered may run. A tool is called by name against the
                    // live registry, so "registered" alone would let a dropped
                    // tool back in.
                    if !offered.contains(&c.name) {
                        let msg = format!("`{}` is not one of the tools offered", c.name);
                        println!("[tool-result] {{\"error\": {msg:?}}}");
                        messages.push(json!({
                            "role": "tool",
                            "tool_call_id": c.id,
                            "content": json!({"error": msg}).to_string(),
                        }));
                        continue;
                    }
                    // The round's panel sink: the bash tool emits its
                    // JSON-highlighted result panel here — print the ops so a
                    // headless run demonstrates the panel API live.
                    let sink = agent::panels::PanelSink::default();
                    let (body, content) =
                        match agent::lua::invoke_mcp_tool(&c.name, &c.arguments, Some(&sink)) {
                            Ok(Some((body, content))) => (body.clone(), content),
                            Ok(None) => (
                                format!("no tool named '{}' is registered in agent.mcps", c.name),
                                json!({"error": format!("no tool named '{}'", c.name)}).to_string(),
                            ),
                            Err(e) => (e.clone(), json!({"error": e}).to_string()),
                        };
                    println!("[tool-result] {body}");
                    for op in sink.drain() {
                        println!("[panel-op] {op:?}");
                    }
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": c.id,
                        "content": content,
                    }));
                }
                continue; // the model answers after seeing the results
            }
            if !turn.content.is_empty() {
                messages.push(json!({"role": "assistant", "content": turn.content}));
            }
            println!("[done]");
            // Fire `turn_completed` exactly like the TUI's loop: same payload
            // shape — `{ history = {...} }`, the conversation without the
            // leading system message — on the probe's own config VM, whose
            // sink makes a handler's agent.panel ops visible headless.
            // agent.trigger is NOT bound here (no idle loop to drive), so it
            // returns false.
            let start = messages
                .first()
                .and_then(|m| m["role"].as_str())
                .map_or(0, |r| usize::from(r == "system"));
            let payload = json!({ "history": &messages[start..] });
            // On the probe's own config VM, like the TUI: what a handler
            // configures is what the next turn would use, and its panel ops
            // land in the VM's sink.
            match agent::lua::fire_event_on_vm(&vm, "turn_completed", &payload) {
                Ok(true) => {
                    for op in event_sink.drain() {
                        println!("[event-op] {op:?}");
                    }
                }
                Ok(false) => println!("[event] no turn_completed handler registered"),
                Err(e) => println!("[event-error] {e}"),
            }
            // Archive the finished turn to the conversation log exactly like
            // the TUI loop: anything past the watermark (never the leading
            // system message), flushed at this turn boundary. Weak: a broken
            // store must not fail the probe.
            let water = saved_upto.max(start);
            if water < messages.len() && agent::lua::memory_is_bound() {
                if let Err(e) = agent::lua::memory_append_many(&messages[water..]) {
                    eprintln!("[probe] save to disk failed: {e}");
                }
                saved_upto = messages.len();
            }
            if let Err(e) = agent::lua::memory_flush() {
                eprintln!("[probe] save to disk failed (flush): {e}");
            }
            break;
        }
    }
    // Group-commit anything still buffered before the process exits.
    if let Err(e) = agent::lua::memory_flush() {
        eprintln!("[probe] final save to disk failed: {e}");
    }
    Ok(())
}
