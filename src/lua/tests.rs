//! Tests for the `agent` namespace.
//!
//! Split by the *shipped Lua surface* each group exercises rather than by the
//! Rust module that implements it: almost every one of these builds a real VM,
//! loads the real `lua/` tree, and drives it end to end, so the module boundary
//! is not the seam the tests have.
//!
//! This file holds what they all need — the imports, and the handful of
//! helpers (`vm`, `tree`, `run_bash`, `call_tool_asking`, `tool_allowed`,
//! `shipped_vm`, …) that a test reaches for whichever surface it is on. A
//! group file gets them with `use super::*;`.

use crate::mcp::{FakeHttpServer, FakeRequest, FakeResponse, FakeServerReply};
use serde_json::json;

/// Call one of the shipped tools the way the TUI does — on the shipped VM,
/// with the round's sink and an ask handler — and return the tool's JSON
/// body plus every question it asked.
///
/// The `fs` tools ask before touching anything, so a test *has* to answer:
/// `verdict` is what the user would press.
use crate::testutil::unique_path;
fn call_tool_asking(
    name: &str,
    args: &str,
    verdict: AskAnswer,
) -> (serde_json::Value, Vec<String>) {
    let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let seen = asked.clone();
    let sink = PanelSink::default();
    let (body, _) = invoke_mcp_tool_with_asks(
        name,
        args,
        Some(&sink),
        Some(Rc::new(move |text: &str, _always: bool| {
            seen.borrow_mut().push(text.to_string());
            verdict.clone()
        })),
        &ConfigSource::Tree,
    )
    .expect("invoke")
    .unwrap_or_else(|| panic!("the shipped config registers {name}"));
    let json = serde_json::from_str(&body).expect("tool json");
    let questions = asked.borrow().clone();
    (json, questions)
}

/// `call_tool_asking` with the user pressing `[y]es` every time.
fn tool_allowed(name: &str, args: &str) -> (serde_json::Value, Vec<String>) {
    call_tool_asking(name, args, AskAnswer::Allow)
}

/// One sandboxed run's outcome, as a test sees it: the result table
/// `agent.bash` returns, decoded. The tool layer (`lua/bash_tool.lua`)
/// shapes this into the MCP reply the model reads; the tests using this are
/// about the protocol underneath — masking, asks, denial reasons — so they
/// talk to `agent.bash` itself.
#[derive(Debug)]
struct Run {
    stdout: String,
    /// Decoded for completeness; the tool's reply is where a test that cares
    /// about stderr asserts on it.
    #[allow(dead_code)]
    stderr: String,
    exit_code: Option<i64>,
    exit_signal: Option<i64>,
    syscalls: u64,
    denied: u64,
    denied_reason: Option<String>,
}

impl Run {
    /// The run did not exit cleanly: killed by a signal (e.g. a denied
    /// syscall) or a non-zero exit code.
    fn failed(&self) -> bool {
        self.exit_signal.is_some() || self.exit_code.map(|c| c != 0).unwrap_or(false)
    }
}

/// Drive one sandboxed `bash -c` run through `agent.bash`, on a fresh VM of
/// its own, with the policy given as Lua source and, optionally, a
/// user-permission ask handler. A fresh VM here is the test's own isolation
/// — the shipped tool does the same call, on the config VM.
///
/// The ask wiring is the shipped tool's, minus the panel: the run is driven
/// with `s:run(handler)` and the handler hands each question to
/// `agent.api.ask_user`, which is the primitive the VM's handler (or the
/// auto-deny, when there is none) answers. Passing a policy *source* rather
/// than the shipped policy is the point: these tests pin the engine's
/// contract, which a fixed tool policy could not exercise.
fn run_bash(
    cmdline: &str,
    policy_src: &str,
    sink: Option<&PanelSink>,
    on_ask: Option<AskHandler>,
) -> Result<Run, String> {
    let lua = new_vm_with_ask(sink, on_ask).map_err(|e| format!("lua bash: vm: {e}"))?;
    let chunk = format!(
        r#"
        local policy = (function()
        {policy_src}
        end)()
        local s = agent.bash({cmdline:?}, policy, nil)
        return s:run(function(a)
          return agent.api.ask_user((type(a) == "table" and a.description) or tostring(a))
        end)
        "#
    );
    let r: Table = lua
        .load(&chunk)
        .eval()
        .map_err(|e| format!("lua bash: {e}"))?;
    let text = |key: &str| -> String {
        r.get::<mlua::LuaString>(key)
            .map(|s| String::from_utf8_lossy(s.as_bytes().as_ref()).to_string())
            .unwrap_or_default()
    };
    let exit: Table = r
        .get("exit")
        .map_err(|e| format!("lua bash: no exit: {e}"))?;
    Ok(Run {
        stdout: text("stdout"),
        stderr: text("stderr"),
        exit_code: exit.get("code").map_err(|e| format!("lua bash: {e}"))?,
        exit_signal: exit.get("signal").map_err(|e| format!("lua bash: {e}"))?,
        syscalls: r.get("syscalls").unwrap_or(0),
        denied: r.get("denied").unwrap_or(0),
        denied_reason: r.get("denied_reason").ok().flatten(),
    })
}

/// A fresh LuaJIT VM with the `agent` namespace installed.
fn vm() -> mlua::Lua {
    new_vm().expect("agent VM")
}

// -- the `lua/` tree: lib modules, the entry script, and require ---------

/// The tree every VM loads (the repo's own `lua/`, like the shipped one).
fn tree() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("lua")
}

/// Build an in-process fake MCP transport for the `agent.mcp` tests: a
/// function(request_json, on_streaming_response_json) that decodes each
/// request, looks up `handlers[req.method]`, and streams every message the
/// handler returns (JSON-encoded) through the callback in order. Request
/// handlers receive the decoded request and must return response messages
/// carrying `id = req.id`; unknown notifications are accepted silently;
/// unknown requests raise ("no handler"). Lua-only — it proves the client
/// talks to *any* transport func, not just spawned processes. Inserted as
/// a `format!` value, so the Lua braces inside are literal.
const FAKE_MCP_FUNC: &str = r#"
    local function fake_mcp_func(handlers)
      local encode, decode = agent.api.json_encode, agent.api.json_decode
      return function(request_json, on_streaming_response_json)
        local req = decode(request_json)
        local h = handlers[req.method]
        if h == nil then
          if req.id == nil then return end
          error("fake func: no handler for '" .. tostring(req.method) .. "'", 0)
        end
        local msgs = h(req)
        if msgs ~= nil then
          for _, m in ipairs(msgs) do
            on_streaming_response_json(encode(m))
          end
        end
      end
    end
    "#;

/// Standard fake-server handlers for `fake_mcp_func`: initialize,
/// tools/list (tools `probe` and `sum`), and tools/call (probe text back
/// or sum two numbers). Close to the reference `mcp_fake` server's shape,
/// but in-process. See `FAKE_MCP_FUNC` for the transport contract.
const FAKE_MCP_HANDLERS: &str = r#"
    local handlers = {
      initialize = function(req)
        return {
          { jsonrpc = "2.0", id = req.id,
            result = { protocolVersion = "2025-03-26", capabilities = { tools = {} },
                       serverInfo = { name = "lua-fake", version = "1.0.0" } } },
        }
      end,
      ["tools/list"] = function(req)
        return {
          { jsonrpc = "2.0", id = req.id,
            result = { tools = {
              { name = "probe", description = "probe text back",
                inputSchema = { type = "object",
                                properties = { text = { type = "string" } },
                                required = { "text" } } },
              { name = "sum", description = "add two numbers",
                inputSchema = { type = "object",
                                properties = { a = { type = "number" }, b = { type = "number" } },
                                required = { "a", "b" } } },
            } } },
        }
      end,
      ["tools/call"] = function(req)
        local args = req.params.arguments
        local text
        if args.text ~= nil then
          text = args.text
        else
          text = tostring(args.a + args.b)
        end
        return {
          { jsonrpc = "2.0", id = req.id,
            result = { content = { { type = "text", text = text } }, isError = false } },
        }
      end,
    }
    "#;

/// Collect pushed output chunks into tables (1-based, so the entry count
/// is the chunk count) and stamp them onto `opts`; returns `opts, out,
/// err`. The pump reads the callback fields off the object at drive time,
/// so collectors work whether installed before or after `run`.
const COLLECT: &str = r#"
    local function collect(opts)
      opts = opts or {}
      local out, err = {}, {}
      opts.on_stdout = function(c) out[#out + 1] = c end
      opts.on_stderr = function(c) err[#err + 1] = c end
      return opts, out, err
    end
    "#;

/// Allow every syscall: a policy with no own keys, so the interception mask
/// is empty and nothing is intercepted at all. (Its `__index` is never
/// consulted for masked syscalls — the mask is the policy's own string
/// keys — so it is vestigial here; tests that want a syscall decided
/// explicitly assign a key, e.g. `allowall.execve = ...`.)
const ALLOW_ALL: &str =
    r#"setmetatable({}, { __index = function() return function() return true end end })"#;

/// A VM with the built-in configuration taken back off: no connections, no
/// mode in force, no prompt — a neutral `agent` for the tests that need one.
///
/// The built-ins are real (the entry script registers the file tools, the
/// shell and the `coding` mode, so a fresh checkout is usable), which means a
/// plain `vm()` is no longer neutral. This is the way to ask for the old
/// starting point rather than working around it in each test.
fn neutral_vm() -> mlua::Lua {
    let lua = vm();
    lua.load(
        r#"
        agent.mode.set()             -- off the built-in default, back to the baseline
        agent.mcps = {}              -- …and the baseline registry itself
        agent.llm.system_prompt = ""
        agent.mode.forget_all()      -- no modes registered at all
    "#,
    )
    .exec()
    .expect("strip the built-in configuration");
    lua
}

/// A VM with the agent's built-in configuration — the connections and the
/// modes, which `lua/init.lua` registers as the defaults — so the tests
/// exercise the real Lua tools.
///
/// No user config is in play in the test environment, so this is just
/// `vm()`. It stays a named function because "the agent as it is actually
/// configured" is a thing the tests mean, and because if a user config were
/// present it is this line that has to apply it.
fn shipped_vm() -> mlua::Lua {
    vm()
}

/// Drive a tool call the way the event loop does — start it on the config
/// VM, answer whatever it asks, step it to its result — and collect the
/// questions it asked. This *is* the tool path now (there is no executor
/// thread), so pinning it here pins the loop's half of the contract.
fn drive_on_vm(
    lua: &mlua::Lua,
    name: &str,
    args: &str,
    mut on_ask: impl FnMut(&str, bool) -> AskAnswer,
) -> (serde_json::Value, Vec<String>) {
    use ToolStep;
    let Some((mut run, mut step)) = ToolRun::start(lua, name, args).expect("start") else {
        panic!("the registry holds {name}");
    };
    let mut asked = Vec::new();
    // Bounded: a driver that never finishes is a bug, not a test to hang on.
    for _ in 0..1000 {
        match step {
            ToolStep::Returned(body) => {
                return (serde_json::from_str(&body).expect("tool json"), asked);
            }
            ToolStep::Ask { text, remember } => {
                asked.push(text.clone());
                let answer = on_ask(&text, remember.is_some());
                step = run.answer(verdict_to_lua(lua, &answer)).expect("answer");
            }
            ToolStep::Waiting { .. } => step = run.wait().expect("wait"),
        }
    }
    panic!("{name} never finished");
}

/// One command through the permissive mode's shell, on `lua`, with the
/// questions it asked. `answers` is what the user presses every time.
///
/// Driven the way the probe drives a tool (to completion on this thread), not
/// the way the TUI does: a sandbox run needs either a reactor giving it
/// slices or a blocking step, and this is the second.
fn run_policy_bash(
    lua: &mlua::Lua,
    cmdline: &str,
    answers: AskAnswer,
) -> (serde_json::Value, Vec<String>) {
    let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let seen = asked.clone();
    let handler: AskHandler = Rc::new(move |text: &str, _always: bool| {
        seen.borrow_mut().push(text.to_string());
        answers.clone()
    });
    let args = serde_json::json!({ "cmdline": cmdline }).to_string();
    let Some((body, _)) =
        invoke_tool_asking(lua, "bash.bash", &args, Some(handler)).expect("invoke")
    else {
        panic!("the permissive mode registers bash")
    };
    let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
    let questions = asked.borrow().clone();
    (v, questions)
}

/// `bash`'s own startup reads — its binary, libc, the NSS files — are asked
/// like any other read now that every open is gated. A test that cares about
/// one particular file would otherwise drown in a dozen library questions, and
/// so would a user's first command, which is why the working directory trust
/// in `lua/init.lua` is not the whole answer.
///
/// This is what a user does after the first run: answer "always" once for
/// the libraries, and stop being asked about them. Leaving those grants in
/// place is the point — the next command's question is then about the work.
fn prime_the_sandbox(lua: &mlua::Lua) {
    assert_default_shell(lua);
    // Real binaries, not the `true` builtin: what is expensive to answer is
    // each *program's* own shared libraries, and they differ per program.
    for warm in ["/bin/true", "/bin/cat /dev/null", "/bin/ls /dev/null"] {
        let (v, _) = run_policy_bash(lua, warm, AskAnswer::AllowAndTrust);
        assert_eq!(v["ok"], true, "the warm-up {warm:?} ran: {v}");
    }
}

/// Did any of the questions ask to `verb` this `subject`?
///
/// Matching the question's *subject* rather than a substring anywhere in it, and
/// that is a change this helper exists to make. A command's own reads are not the
/// only ones — `bash` also opens locale and NSS data, and it does some of that
/// lazily, an error message being what triggers the locale load — so a count is
/// fragile where "was this asked" is not. But since every question now names the
/// asker's command line, a bare substring for a path is satisfied by *any*
/// question the run raised, because the command line is the command the test ran.
/// A positive assertion written that way passes even if the gate stopped asking,
/// which is the one thing it must never do.
///
/// So the match is on the part before the asker's `(pid N)`, and takes the verb
/// with the subject: "read /x" is a different question from "overwrite /x", and
/// only the first is evidence that the read was asked about.
fn asked_subject(asked: &[String], verb: &str, subject: &str) -> bool {
    asked.iter().any(|q| {
        let question = q.split(" (pid ").next().unwrap_or(q);
        question.contains(&format!("{verb} {subject}"))
    })
}

/// Whether a question names `port` as its endpoint, in the part before the
/// asker's command line. The command an endpoint test runs is
/// `exec 3<>/dev/tcp/127.0.0.1/<port>`, so the port appears in *every* question
/// that run raises — including the ones a test asserts did not happen.
fn asked_port(asked: &[String], port: u16) -> bool {
    asked.iter().any(|q| {
        let question = q.split(" (pid ").next().unwrap_or(q);
        question.contains(&format!("port {port}"))
    })
}

/// An ask handler that says yes to everything. The default policy asks about
/// every open and every endpoint, so a test that is about the *tool* — its
/// result shape, its panels, an exit status — needs a user who answers, or it
/// measures the policy instead. A test about the policy itself passes `None`
/// and gets the headless auto-deny.
fn allow_all() -> Option<AskHandler> {
    Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow))
}

/// Call the shipped `bash` tool the way the TUI does: on the shipped
/// config VM, with the round's panel sink and the call's ask handler.
/// Returns the tool's JSON body.
fn call_bash(args: &str, sink: &PanelSink, on_ask: Option<AskHandler>) -> serde_json::Value {
    let (body, _) =
        invoke_mcp_tool_with_asks("bash.bash", args, Some(sink), on_ask, &ConfigSource::Tree)
            .expect("invoke bash")
            .expect("the shipped config registers agent.mcps.bash");
    serde_json::from_str(&body).expect("tool json")
}

/// A tool already suspended on `first`, answering whatever it asks, driven
/// to its return. Every ask is allowed, so this is the "press yes to
/// everything" driver the loop's auto-yes would be.
fn drive_to_end(run: &mut ToolRun<'_>, first: ToolStep) -> String {
    use ToolStep;
    let mut step = first;
    let mut asks = 0usize;
    let mut waits = 0usize;
    for _ in 0..100000 {
        match step {
            ToolStep::Returned(body) => return body,
            ToolStep::Ask { .. } => {
                asks += 1;
                let v = verdict_to_lua(run.lua(), &AskAnswer::Allow);
                step = run.answer(v).expect("answer");
            }
            ToolStep::Waiting { ms } => {
                waits += 1;
                // As in `drive_to_ask`: the cadence is wall time, and a
                // driver that ignores it races the notification it is
                // waiting for.
                std::thread::sleep(std::time::Duration::from_millis(ms));
                step = run.wait().expect("wait");
            }
        }
    }
    panic!("the tool never finished after {asks} asks and {waits} waits");
}

/// A shell run whose handler answers `deny` to questions mentioning
/// `marker` and `allow` to everything else.
///
/// Needed because a cold `python3` reads a handful of unrelated files on the
/// way to running anything, and a handler that denies everything kills the run
/// before it reaches the call under test. Denying one question by its text is
/// the only way to say "this is the gate" without also enumerating
/// everything the interpreter happens to want.
fn run_policy_bash_except(
    lua: &mlua::Lua,
    cmdline: &str,
    marker: &str,
) -> (serde_json::Value, Vec<String>) {
    let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let seen = asked.clone();
    let mark = marker.to_string();
    let handler: AskHandler = Rc::new(move |text: &str, _always: bool| {
        seen.borrow_mut().push(text.to_string());
        if text.contains(&mark) {
            AskAnswer::Deny(Some("refused by the test".into()))
        } else {
            AskAnswer::Allow
        }
    });
    let args = serde_json::json!({ "cmdline": cmdline }).to_string();
    let Some((body, _)) =
        invoke_tool_asking(lua, "bash.bash", &args, Some(handler)).expect("invoke")
    else {
        panic!("the permissive mode registers bash")
    };
    let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
    (v, asked.borrow().clone())
}

/// The shell the tests below drive *is* the shipped one: `lua/policy.lua` is
/// the default sandbox policy, so `require("bash_tool")` already runs under
/// every syscall `MASK` names and there is nothing to install. Asserted here so
/// a change to the default fails loudly at the point the tests start rather
/// than as a baffling "asked nothing".
fn assert_default_shell(lua: &mlua::Lua) {
    // The real table, not the source: this used to grep
    // `policy.<name> = function` out of `lua/policy.lua`, which cannot see a
    // gate assigned from a named local — and `renameat` is exactly that,
    // because it and `renameat2` are one callback. The grep would have
    // reported five gates while the sandbox trapped seven.
    let gates: String = lua
        .load(
            r#"
        local policy = require("policy").new()
        local names = {}
        for name in pairs(policy) do names[#names + 1] = name end
        table.sort(names)
        return table.concat(names, ",")
    "#,
        )
        .eval()
        .expect("mask");
    assert_eq!(gates, MASK, "the default policy's mask is exactly this set");
}

/// What the drawing path puts in the transcript, read back off the sink as
/// one string — `Create` contributes its title, everything else its text.
fn drawn(sink: &crate::panels::PanelSink) -> String {
    sink.ops()
        .iter()
        .map(|op| match op {
            PanelOp::Create { title, .. } => format!("┌─ {title}\n"),
            PanelOp::Append { text, .. } => text.clone(),
            _ => String::new(),
        })
        .collect()
}

/// Read `agent.mode.current()`.
fn mode_current(lua: &mlua::Lua) -> Option<String> {
    lua.load("return agent.mode.current()")
        .eval()
        .expect("current mode")
}

/// A registered mode's system prompt.
fn mode_prompt(lua: &mlua::Lua, name: &str) -> String {
    lua.load(format!("return agent.mode.get({name:?}).system_prompt"))
        .eval()
        .expect("mode prompt")
}

/// A unique temp dir for a fixture tree — the tests that build a `lua/` tree on
/// disk, so they all share one naming convention and never collide.
fn fixture(name: &str) -> PathBuf {
    unique_path(&format!("agent-lua-{name}"))
}

/// The shipped policy's mask, spelled out. A policy that named fewer would
/// silently let a connect — or an `rm`, or a `chmod`, or an `io_uring_enter`
/// that walks past all three — through, so the set is pinned exactly; and it is
/// a list rather than a count, so that adding a gate is a visible edit here and
/// not a silent one.
const MASK: &str = "bind,bpf,chmod,connect,fchmodat,io_uring_enter,io_uring_register,io_uring_setup,lremovexattr,lsetxattr,memfd_create,name_to_handle_at,open_by_handle_at,openat,pidfd_getfd,pkey_alloc,pkey_free,pkey_mprotect,process_vm_readv,process_vm_writev,removexattr,renameat,renameat2,sendto,setxattr,unlinkat,userfaultfd";

/// Drive an `EventRun` to completion by answering every wait the way the
/// reactor would (its timer fired), counting the cooperative suspensions.
/// Returns `(run, waits)`.
fn drive_event_to_completion(mut run: EventRun, mut step: EventStep) -> (EventRun, u64) {
    let mut waits = 0;
    loop {
        match step {
            EventStep::Waiting { .. } => {
                waits += 1;
                step = run.step().expect("event timer fired");
            }
            EventStep::Returned => return (run, waits),
        }
    }
}

/// Read a table the handler stamped onto the event VM's `agent` global.
fn event_agent_field(run: &EventRun, key: &str) -> mlua::Table {
    run.lua()
        .globals()
        .get::<Table>("agent")
        .expect("agent table")
        .get(key)
        .expect("handler field")
}

// The namespace's own internals, for the tests that reach past the public
// surface: the loader's path resolution, the syscall decoders, the event
// machinery. A group file gets all of this with one `use super::*;`.
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use mlua::{Lua, Table};

pub use crate::lua::config::SEED_MARKER;
use crate::memory::Memory;
use crate::panels::{ALWAYS_LABEL, PaneInit, PanelOp, PanelSink, Remember};
use crate::seccomp::{self, FdSlot, Step, Verdict};

use super::config::{
    ConfigOrigin, ConfigSource, apply_config_source, ensure_config, invoke_mcp_tool_with_asks,
    invoke_tool, invoke_tool_asking, llm_config, mcps_tool_defs, system_prompt, verdict_to_lua,
};
use super::memory::{
    bind_memory, memory_append_many, memory_config, memory_is_bound, memory_latest,
};
use super::run::{
    AgentCommand, EventRun, EventStep, InputOp, ToolRun, ToolStep, claim_trigger_channel,
    fire_event_on_vm, fire_event_returning, release_trigger_channel,
};
use super::sandbox::{
    CSTRING_CAP, cstring_positions, cwd_resolution_ok, dirfd_slot_for, proc_cmdline, read_cstr,
    resolve_path,
};
use super::tree::{load_init, lua_dir_candidates, lua_dir_in, missing_tree_message};
use super::usage::{Usage, record_usage, usage_guard};
use super::vm::{
    AskAnswer, AskHandler, STDLIB, eval_reactor, install_sink, new_vm, new_vm_with_ask,
    new_vm_with_sink, setup_tree,
};

mod config;
mod events;
mod fs;
mod http;
mod keys;
mod loader;
mod mcp;
mod memory;
mod modes;
mod namespace;
mod panels;
mod policy;
mod registry;
mod sandbox;
mod syscalls;
mod tools;
mod tree;
mod trust;
