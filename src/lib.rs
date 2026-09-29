//! `agent` — an AI agent whose policy is syscall-tracing-based.
//!
//! Library crate root. The seccomp sandbox substrate (the future supervisor)
//! lives in [`seccomp`]; the chat-completions client — tool definitions,
//! connection config, request plumbing, SSE parsing and turn accounting — lives
//! in [`api`], with the translation from the Lua tool registry into the
//! request's tool catalog in [`tools`]; the chat TUI (screen shell in [`tui`],
//! conversation component in [`tui::TurnPanel`]) lives in [`tui`]'s module
//! tree; runtime grammar acquisition lives in [`grammars`]. Block-compressed,
//! tail-readable conversation memory lives in [`memory`], which the loop
//! archives to and Lua reads and writes as `agent.memory.*`. The Lua→TUI panel
//! op stream (what `agent.api.panel_*` emits for the transcript to apply) lives
//! in [`panels`], and the one-line status bar the TUI draws at the bottom — what
//! `print` and grammar progress report through — lives in [`status`]. The Lua
//! namespace itself, plus everything the loop drives it with, lives in [`lua`].

pub mod api;
pub mod grammars;
pub mod lua;
pub mod mcp;
pub mod memory;
pub mod panels;
pub mod seccomp;
pub mod status;
pub mod tools;
pub mod tui;
