//! `agent` — an AI agent whose policy is syscall-tracing-based.
//!
//! Library crate root. The seccomp sandbox substrate (the future supervisor)
//! lives in [`seccomp`]; the tokio readiness adapter that drives a sandbox
//! (and its isolated stdin) from the agent's single poll loop lives in
//! [`async_sandbox`]; the chat TUI (screen shell in [`tui`], conversation
//! component in [`tui::TurnPanel`]) lives in [`tui`]'s module tree; runtime
//! grammar acquisition lives in [`grammars`]; the chat-completions client
//! lives in the `agent` binary's own module tree. Block-compressed,
//! tail-readable conversation memory lives in [`memory`], which the loop
//! archives to and Lua reads and writes as `agent.memory.*`. The Lua→TUI panel
//! op stream (what `agent.api.panel_*` emits for the transcript to apply) lives
//! in [`panels`], and the one-line status bar the TUI draws at the bottom — what
//! `print` and grammar progress report through — lives in [`status`].

pub mod async_sandbox;
pub mod grammars;
pub mod lua;
pub mod mcp;
pub mod memory;
pub mod panels;
pub mod seccomp;
pub mod status;
pub mod tui;
