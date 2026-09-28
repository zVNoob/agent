# State of AI Coding-Agent Extensibility, Sandboxing, and User-Scriptable Policy (2026)

Research brief. Compiled 2026-09-26. Method: primary vendor documentation fetched directly
(avoiding blogs), plus GitHub READMEs for the smaller projects. Where a claim rests on a
secondary source or my own inference, it is flagged inline.

Confidence legend: **[V]** verified from primary docs in this session · **[V-]** verified in
the earlier research pass of this same brief · **[?]** uncertain, flagging why.

> **Scope, and how it ages.** Everything about *other* projects is a snapshot of
> 2026-09-26 and is only as good as that date — vendors ship, links rot, and the
> confidence flags say how solid each claim was. Nothing here was re-verified
> since. The passages about *this* repo (Part 0, §2.2, §2.3, Part 3) describe the
> tree as it stood when this was compiled; where the design has since moved, the
> passage is marked. The current design is documented in `README.md` and in the
> module docs, and those are the authority — this brief is why the design looks
> the way it does, not what it currently is.

---

## Part 0 — TL;DR for this project

This repo (`agent`) is a Rust coding agent where **Lua is the entire user-facing control
plane**: `mlua`/LuaJIT is embedded, Lua defines the LLM endpoint, system prompt, tools
(MCP-shaped), and seccomp sandbox policies (a syscall name -> callback table passed per call
to `agent.bash`, stated by each tool in its own closure), plus event hooks
(`agent.on_event`), history rewriting (`agent.trigger`), and memory (`agent.memory.*`).
`/reload` hot-reloads the config with nothing cached on the Rust side.

*Since this was compiled, the built-in configuration moved out of a config file and into
`lua/init.lua` (a user's `~/.config/agent/init.lua` is now an optional overlay on top of
it, at that one path), the process became strictly single-threaded — tools, event handlers and HTTP all run as coroutines one
event loop steps — and the sandbox policy became a policy module (`lua/policy.lua`) rather
than a table each tool spelled out. The shape of the design is the one described here; the
placement moved.*

The three headline findings that bear on that design:

1. **The design is essentially unprecedented in a mainstream product, and there is exactly
   one public precedent: [Capstan](https://github.com/theStrangeAdventurer/capstan)**
   (C99 + embedded Lua). It puts *more* in Lua than this repo does — config, permissions,
   profiles, plugins, providers, observability — but it is a solo project with **16 GitHub
   stars**, no release traction, and a self-described "exploratory" benchmark. It is a
   precedent, not validation. Details in §2.3.
2. **The industry converged on the opposite trade-off: a narrow, non-embeddable scripting
   surface.** Claude Code ships JavaScript *workflows* but deliberately hobbles the JS
   runtime (no `import()`, `Date.now()`/`Math.random()` throw, no filesystem or shell from
   the script body). Cline, pi, and Capstan all embed a full language runtime
   (TypeScript/TypeScript/Lua) but gate it as "trusted, in-process, same OS permissions as
   the agent." Nobody ships a sandboxed embedded DSL for *policy* specifically.
3. **The one place a real policy language reached production is Rego/OPA, and it runs as
   WASM in-process**, not as an interpreted scripting language — Vercel's
   `@ai-sdk/policy-opa` `wasmPolicyClient`. That is arguably a better answer to "user-
   scriptable policy" than an embedded Lua interpreter, and it is the design axis worth
   weighing. Details in §2.1.

---

## Part 1 — Per-target breakdown

### 1. Claude Code

- **(a) Language/runtime** — Node/TypeScript CLI, shipped as a native binary bundling
  `ripgrep`. **[V-]**
- **(b) Extensibility model — how a user adds a tool** — Six distinct surfaces, none of
  which is an embedded scripting language:
  - **MCP servers** — `.mcp.json` (project) / `~/.claude.json` (user). stdio, http, sse, ws;
    `headersHelper` for dynamic auth; `.mcpb`/`.dxt` bundles. **[V]**
  - **Plugins** — `.claude-plugin/plugin.json` manifest. Components: `skills/`
    (`<name>/SKILL.md`), `commands/` (flat `.md`), `agents/` (`.md`), `hooks/hooks.json`,
    `.mcp.json`, `.lsp.json`, `output-styles/`, **`workflows/`** (JS), `evals/`, plus
    `experimental.monitors` (long-running background shell processes started at
    `session_start` or `on-skill-invoke:<name>`) and `experimental.themes`. Manifest supports
    `userConfig` (prompted at enable time; `sensitive: true` → platform secure store, not
    `settings.json`), `channels` (message channels bound to an MCP server), `dependencies`
    (other plugins), `defaultEnabled`, `version` pinning. Env vars: `${CLAUDE_PLUGIN_ROOT}`,
    `${CLAUDE_PLUGIN_DATA}`, `${CLAUDE_PROJECT_DIR}`. Validate with
    `claude plugin validate [--strict]`. Installed via `/plugin`. **[V]**
    https://code.claude.com/docs/en/plugins-reference
  - **Skills** — `.claude/skills/<name>/SKILL.md`, model-invoked. **[V-]**
  - **Subagents** — `.claude/agents/*.md`. **[V-]**
  - **Slash commands** — `.claude/commands/*.md`. **[V-]**
  - **Hooks** — 5 handler types: `command`, `http`, `mcp_tool`, `prompt`, `agent`. Events
    include `PreToolUse`, `PostToolUse`, `PermissionRequest`, `SessionStart`/`End`,
    `Stop`, `SubagentStop`, `PreCompact`. A `PreToolUse` hook returning `allow` **approves**
    a call; `deny` blocks; `ask` defers. Exec form (`command` + `args`) vs shell form.
    **[V-]**
  - **Workflows (JavaScript)** — see §2.1. `.claude/workflows/*.js` and
    `~/.claude/workflows/*.js`; runs as `/<name>`; plugin-distributable via `workflows/`.
    **[V]**
- **(c) Permission/sandbox model** — Permission rules are `allow`/`ask`/`deny` lists in
  `settings.json`, matched on tool name + argument patterns. Four permission modes
  (including an `auto` mode with a classifier that eliminates prompts). **Sandbox**:
  macOS Seatbelt (`sandbox-exec`) / Linux+WSL2 bubblewrap + `socat`, plus an optional
  seccomp filter from `@anthropic-ai/sandbox-runtime` restricting Unix-socket paths.
  Network is enforced by a `socat` proxy against `sandbox.network.allowedDomains`.
  Credential masking uses a sentinel value plus a TLS-terminating proxy so secrets are
  never handed to sandboxed processes in the clear. **[V-]**
- **(d) MCP** — Yes, first-class, including plugin-bundled servers and bundle format. **[V]**
- **(e) Config format** — JSON at `~/.claude/settings.json`, `.claude/settings.json`,
  `.claude/settings.local.json`, `managed-settings.json`; plus `~/.claude.json`. YAML
  front-matter in `SKILL.md`/agent/command markdown. JS in `workflows/`. **[V-]**
- **(f) Strengths/weaknesses** — Strongest OS-level sandbox + most mature hook system of
  the set. Weaknesses: permission rule syntax is bespoke and non-compositional (no
  "allow if X and Y" beyond pattern matching); five overlapping extension surfaces with
  overlapping semantics; **no user-facing scripting language**; the one JS surface
  (workflows) is deliberately restricted.

### 2. OpenAI Codex CLI

- **(a)** — Rust (`codex-rs/`). **[V-]**
- **(b) Extensibility** — MCP servers (`mcp_servers.*`, OAuth, `enabled_tools` /
  `disabled_tools`, per-tool `approval_mode`); subagents (`agents.*`); rules; skills
  (`skills.config`); plugins/marketplaces (`.agents/plugins/marketplace.json`);
  `AGENTS.md`; hooks (`features.hooks`, `hooks.json` or inline `[hooks]`) — **command and
  MCP-tool hooks only**; and a **code mode** (`features.code_mode.*`). **[V-]**
  - **Permission profiles** are the notable part: named `[permissions.<name>]` tables with
    `extends`, `filesystem` (`:read-only` / `:workspace` / `:workspace_roots`, globs,
    read/write/deny), `network` (domains, `unix_sockets`, `socks5`), `workspace_roots`.
    **[V-]**
  - **`approvals_reviewer = "auto_review"`** routes approvals to a reviewer subagent whose
    policy is a **Markdown file**: `codex-rs/core/src/guardian/policy.md`. This is the
    closest thing in the industry to "policy as a text DSL" and is a useful precedent
    pointer. **[V-]**
  - **Code mode** (`features.code_mode.enabled`, plus `direct_only_tool_namespaces` and
    `excluded_tool_namespaces`) is documented as **"under development and off by
    default."** **[V]** — this is the JS/Python-as-agent direction, and it is not shipped on.
- **(c)** — Three sandbox levels: `read-only` / `workspace-write` / `danger-full-access`.
  macOS = Seatbelt via `sandbox-exec -p`; Linux = `bwrap` + seccomp; native Windows sandbox;
  WSL2 uses the Linux implementation (WSL1 support dropped in 0.115). Approval modes
  `on-request` / `never` / `granular` (`sandbox_approval`, `rules`, `mcp_elicitations`,
  `request_permissions`, `skill_approval`); `untrusted` is retired. Optional
  `features.network_proxy` (off by default) at `127.0.0.1:3128` HTTP / `:8081` SOCKS5.
  `codex sandbox macos|linux|windows` debug subcommand. **[V-]**
- **(d)** — MCP yes, with per-tool approval. **[V-]**
- **(e)** — TOML (`~/.codex/config.toml`). **[V-]**
- **(f)** — Best-in-class declarative, composable permission model (named profiles with
  inheritance — nothing else here has this). Weakness: hooks are limited to two handler
  types, and the scripting story is stalled at an off-by-default feature.

### 3. Aider

- **(a)** — Python + Rust. **[V-]**
- **(b)** — Slash commands; edit formats (`diff` / `search-replace` / `whole` / `editor` /
  `architect`); repo map via tree-sitter; `--lint-cmd` / `--test-cmd` / `--auto-test` loop
  that re-prompts the model on non-zero exit. Python scripting API is **explicitly
  undocumented and unsupported**. `https://aider.chat/docs/usage/custom-commands.html`
  **now 404s**; `.aider/commands/*.md` and `--load` are still referenced by third-party
  cheat sheets. **[?]** Treat `.aider/commands` as uncertain/stale — the vendor doc appears
  removed or relocated.
- **(c)** — **No sandboxing.** Approval is limited to interactive confirmations on edits /
  `/run` / `/ask`. **[V]**
- **(d)** — **No MCP support.** **[V]**
- **(e)** — YAML: `.aider.conf.yml`, plus env vars and CLI flags. **[V]**
- **(f)** — Strength: the lint/test auto-fix loop is the best "verify your own work"
  primitive of the group, and the repo map keeps context small. Weakness: no sandbox, no
  MCP, no supported extension surface at all. The weakest extensibility story in the set.

### 4. OpenHands

- **(a)** — Python. Packages: `openhands-sdk`, `openhands-tools`, `openhands-workspace`,
  `openhands-agent-server`. **[V-]**
- **(b)** — **Custom tools are Python code you write and register.** Subclass
  `ToolDefinition[Action, Observation]`, implement a `ToolExecutor`, call
  `register_tool("Name", ToolCls)`, then reference `Tool(name="LogDataTool")`. Registering
  against a *remote* agent server additionally requires a custom base image and a
  Dockerfile. **[V]** — This is the "author in Python, rebuild the image" model: the
  heaviest tool-extension path in the set, but also the only one where the tool has full
  Python.
- **Skills** — Agent Skills spec at `.agents/skills/<name>/SKILL.md`, plus `AGENTS.md`, and
  keyword `triggers` / path `paths` in front-matter. Legacy `.openhands/microagents/` and
  `.openhands/skills/`. **[V]**
- **(c)** — **Docker sandbox is the default** ("sandbox"; the `RUNTIME` env var is legacy).
  An Action Execution Server (FastAPI) runs inside the container. **[V]**
- **(d)** — MCP via `mcp_config` (`sse_servers`, `shttp_servers`, `stdio_servers`, OAuth). **[V]**
- **(e)** — Python config objects + `mcp_config`; markdown for skills/`AGENTS.md`. **[V]**
- **(f)** — Strength: the only entry here with a container sandbox as the *default* rather
  than an opt-in. Weakness: tool extension requires Python + image rebuild; heavy.

### 5. Goose

- **(a)** — Rust core (~72%), TypeScript desktop frontend. Moved to the Agentic AI
  Foundation (`aaif-goose/goose`), Apache-2.0. **[V-]**
- **(b) — the cleanest "MCP-only" story in the set, and the most interesting code-as-agent
  story.** Extensions *are* MCP servers; the built-ins (Developer, Computer Controller,
  Memory, Apps, Summon, Todo, Top of Mind, Chat Recall, Extension Manager, **Code Mode**,
  Skills) are themselves MCP servers. Configured in `~/.config/goose/config.yaml` /
  `profiles.yaml`, via `goose configure`, or by deeplink `goose://extension?cmd=...`. **[V]**
  - **Code Mode**: the LLM writes **JavaScript**, executed in a Deno-based runtime
    ("Port of Context", `github.com/Adriancole/pctx`), which exposes three meta-tools for
    tool discovery and invocation instead of dumping every tool schema into context. **[V]**
    **[?]** I did not confirm from the docs whether the Code Mode extension is enabled by
    default in shipped builds; treat "off by default" as unverified.
- **(c)** — Four permission modes: **Completely Autonomous (default)**, Manual Approval,
  Smart Approval (an LLM classifies read vs. write), Chat Only; plus per-tool permissions.
  `--container` runs extensions in Docker. Integrates CLI-provider permissions (Claude Code
  / Codex via `GOOSE_MODE`). **[V]**
- **(d)** — MCP is the *only* extension mechanism. **[V]**
- **(e)** — YAML (`config.yaml`, `profiles.yaml`, recipes) + `.goosehints` / `AGENT.md`. **[V]**
- **(f)** — Strength: one uniform extension model (everything is an MCP server), and
  Code Mode is a genuinely thoughtful answer to tool-schema bloat. Weakness: the default
  permission mode is fully autonomous; recipes are YAML, not code.

### 6. Cline / Roo Code

The most-changed entry since last year's consensus, and the one most relevant to
"scriptable extension."

- **(a)** — Cline: TypeScript VS Code extension, now **also** a CLI, TUI, Desktop app,
  Kanban (parallel agents in isolated git worktrees), ACP client-integration, a TypeScript
  **SDK** (`@cline/sdk`), and an OpenAI-compatible API. Roo: VS Code extension. **[V]**
- **(b) — Cline now has a real first-class plugin system (TypeScript).** An `AgentPlugin`
  object with `manifest.capabilities`, a synchronous `setup(api, ctx)` that calls
  `api.registerTool(createTool({name, description, inputSchema, execute}))`, and a `hooks`
  object with `beforeRun`, `afterRun`, `beforeModel`, `afterModel`, `beforeTool`,
  `afterTool`, `onEvent`. **[V]**
  - **Hook stages**: `input`, `runtime_event`, `session_start`, `run_start`,
    `iteration_start`, `turn_start`, `before_agent_start`, `tool_call_before`,
    `tool_call_after`, `turn_end`, `stop_error`, `iteration_end`, `run_end`,
    `session_shutdown`, `error`. **[V]**
  - **Hook policies** — `mode: "blocking" | "async"`, `timeoutMs`, `retries`,
    `retryDelayMs`, `failureMode: "fail_open" | "fail_closed"`, `maxConcurrency`,
    `queueLimit`. The docs explicitly recommend `fail_closed` for policy-enforcement hooks
    where bypassing the hook is unsafe. **[V]** — This is the most directly comparable
    thing in the set to a policy hook, and it is *in-process TypeScript*, not a DSL.
  - **Distribution**: `pluginPaths` in session config, or `cline plugin install` from a
    file URL, npm, git, or local path. Single-file plugins may import only Node builtins and
    `@cline/*`; anything needing an npm dep must ship as a package with a `cline` field in
    `package.json`. Packages can bundle a top-level `skills/` dir. **[V]**
  - MCP: `~/.cline/mcp.json`, `cline mcp` wizard, `cline config mcp --json`; stdio
    (`command`+`args`) and remote (`type: "streamableHttp"` recommended; `sse` is the
    legacy default if `type` is omitted), `headers`, `env`, `disabled`, `autoApprove[]`.
    **[V-]**
  - Modes: Plan / Act, plus subagents, skills, rules, checkpoints. **[V]**
  - **Cline has no sandbox.** Auto Approve is per-tool-call categorical: Read project
    files / Read all files / Edit project files / Edit all files / Execute safe commands /
    Execute all commands / Use the browser / Use MCP servers. "Read all" and "Edit all" only
    extend the base toggle. Crucially, **there is no fixed command allowlist** — *the model*
    sets a `requires_approval` flag per command. YOLO mode auto-approves everything. **[V]**
    → That model-assessed flag is a soft, spoofable signal, not an enforcement boundary.
- **Roo Code — declarative mode-as-policy.** Custom modes in YAML (`.roomodes` in-repo, or
  global `custom_modes.yaml`) with `slug`, `name`, `description`, `roleDefinition`,
  `whenToUse`, `customInstructions`, and **`groups`** — an allowlist of tool groups
  (`read`, `edit`, `command`, `mcp`) where `edit` can be narrowed by a **`fileRegex`**
  (e.g. `["edit", {fileRegex: "\\.md$"}]`), enforced with a `FileRestrictionError`.
  Mode instructions load from `.roo/rules-{slug}/` (preferred, recursive, alphabetical),
  falling back to `.roorules-{slug}` then `.clinerules-{slug}`. Project modes **completely
  override** global modes with the same slug — no merging. Built-in modes (Code, Debug,
  Ask, Architect, Orchestrator) are overridable by slug. Also `.rooignore`, skills, a
  marketplace. **[V]**
- **(c)** — Neither has an OS sandbox. They rely on the auto-approve list plus VS Code
  workspace trust. Kanban adds isolated git worktrees (not a security boundary). **[V]**
- **(e)** — JSON for MCP; YAML (preferred) or JSON for Roo modes; TypeScript for Cline
  plugins. **[V]**
- **(f)** — Strength: Cline's plugin system is the most complete *scriptable* extension
  story of any mainstream product, and its `fail_closed` hook policy is a real
  enforcement primitive. Weakness: extension code is in-process TypeScript with the same OS
  permissions as the agent — a plugin can bypass any policy it also enforces. Roo's
  `fileRegex` is a genuinely nice declarative capability boundary, but it is
  path-based only and does nothing about commands or network.

### 7. smolagents / Pydantic AI / OpenAI Agents SDK

Grouped because they are libraries, not end-user products — but their tool and approval
models are what a custom Rust agent would most plausibly be compared against.

#### smolagents **[V]**
- Python. `CodeAgent` = the LLM writes **Python**; `ToolCallingAgent` = JSON tool calls.
- **Tools**: subclass `Tool` with class attrs `name`, `description`, `inputs` (dict of
  `type`/`description`), `output_type` (Pydantic JSON-schema types), and `forward()`; or the
  `@tool` decorator for simple functions. Share via `push_to_hub()` (requires
  `trust_remote_code=True` to load). Adapters: `ToolCollection.from_mcp()`,
  `Tool.from_langchain()`, `Tool.from_space()` (Gradio). `agent.tools` is a plain dict you
  can mutate. `MCPClient` (stdio + streamable-http, `structured_output=True` for
  `outputSchema`).
- **Sandbox — the most interesting in the group.** `CodeAgent` runs LLM code in a
  **purpose-built AST interpreter**, `LocalPythonExecutor`, not CPython: it walks the AST
  and enforces an **authorized-imports allowlist** (submodules disabled by default;
  `random._os` explicitly blocked), caps elementary operations (1,000,000-iteration limit)
  to stop infinite loops, and errors on any undefined operation. The docs are explicit
  that **no local Python sandbox is ever secure** and recommend E2B/Docker for
  high-security cases. Remote executors: `executor_type = "e2b" | "modal" | "blaxel" |
  "docker"`.
- **No permission/approval model, no MCP-native policy.** Strength: the AST interpreter is
  the only *language-level* enforcement in the whole comparison. Weakness: not a security
  boundary against a determined attacker, by the authors' own admission.

#### Pydantic AI **[V]**
- Python. `@agent.tool` (gets `RunContext`), `@agent.tool_plain`, `tools=` kwarg (plain
  functions or `Tool` instances), `toolsets=` kwarg (MCP or third-party). Docstrings parsed
  with `griffe` (google/numpy/sphinx) into tool + parameter descriptions.
- **Approval is the most sophisticated of the three** — and notably honest about its
  limits. Deferred tools come in two flavours: `requires_approval=True` on the decorator
  (always ask) or `raise ApprovalRequired` from the body / `args_validator` (conditional on
  arguments or deps, with `RunContext.tool_call_approved` to check). `CallDeferred` /
  `ExternalToolset` for tools executed outside the process. Two resolution flows: inline via
  a `HandleDeferredToolCalls` capability, or stop-the-world with `DeferredToolRequests` as
  the run's `output_type`, then resume with `DeferredToolResults`. `ApprovalRequiredToolset`
  wraps any toolset (including MCP). Denials return `ToolDenied(message)` to the model with
  `outcome='denied'`.
  → The docs carry an explicit warning worth quoting: **"Approval is not an authorization
  boundary against an untrusted client"** — over a UI adapter the client submits its own
  approval, so you must still authenticate the endpoint and enforce authorization inside the
  tool. This is the clearest statement of the trust boundary in any of these docs.
- **No sandbox.** Pydantic AI is a library; isolation is the caller's problem.

#### OpenAI Agents SDK **[V]**
- Python. Notable because it has **moved furthest** — it now ships a first-class sandbox
  abstraction, which the other two do not.
- **Tools (5 categories)**: hosted (`WebSearchTool`, `FileSearchTool`,
  `CodeInterpreterTool`, `HostedMCPTool`, `ImageGenerationTool`, `ToolSearchTool`,
  `ProgrammaticToolCallingTool`); local runtime (`ComputerTool`, `ShellTool`,
  `LocalShellTool`, `ApplyPatchTool` — you supply the `Computer` / `ApplyPatchEditor`
  implementations); `FunctionTool` (`@function_tool` or hand-built with
  `on_invoke_tool`); agents-as-tools (`agent.as_tool(...)`); experimental Codex tool.
- **Code-as-agent**: `ProgrammaticToolCallingTool` — the model generates **JavaScript** that
  orchestrates several tool calls in a **fresh hosted V8 environment**. Explicitly *no*
  Node.js APIs, no filesystem, no network, no persistent process; it may only touch tools
  the developer marks `allowed_callers=["programmatic"]`. It composes with
  `ToolSearchTool` + `tool_namespace()` + `defer_loading=True` so you can defer large tool
  surfaces until runtime. This is the most careful "code as agent" implementation in the
  set — the sandbox is defined by an explicit allowlist, not by hoping the model behaves.
- **Approval**: `needs_approval` / `on_approval` on `ShellTool` and `ApplyPatchTool`
  (default `needs_approval=False`); the run pauses and returns `result.interruptions`,
  resolved through `RunState` (`state.approve(...)` / `state.reject(...)`). The docs state
  plainly that **"SDK approval does not provide a sandbox"** — your executor must enforce
  isolation. Guardrails (`input_guardrail`, `output_guardrail`, `ToolGuardrail`),
  `failure_error_function`, `timeout_behavior` (`error_as_result` | `raise_exception`).
- **Sandbox agents** — `SandboxAgent` + `Manifest` (files, `LocalDir`/`LocalFile`,
  `GitRepo`, S3/GCS/R2/Azure/Box mounts) + `Capabilities` (`Shell`, `Filesystem`, `Skills`,
  `Memory`, `Compaction`) + `Permissions` (owner/group/other `FileMode` bits) + `User`/
  `Group` + `run_as` (execute-as identity) + `extra_path_grants` (absolute paths, with
  `read_only`) + `SnapshotSpec` (local/remote snapshot restore).
  - `UnixLocalSandboxClient`: **macOS applies filesystem restrictions through
    `sandbox-exec`**; **on Linux it runs commands as host processes with no OS-level
    confinement**; **no network isolation on either**. The docs say outright: "Separate
    sessions do not guarantee OS-level isolation" and "a session does not itself guarantee
    OS-level confinement."
  - `DockerSandboxClient` / hosted providers for untrusted commands. On Windows, Docker or
    hosted only.
  - Hosted `ShellTool` environments: `container_auto` / `container_reference`, with
    `network_policy: "disabled" | "allowlist"` and `domain_secrets`.
  → Verdict: the SDK *models* Unix-style file permissions declaratively, which is
  genuinely novel, but its local backend is a prompt, not a jail.

### 8. MCP (the protocol, not an agent)

- **(a)** — Spec, not an implementation. Current version **`2026-07-28`** (RC 2026-05-21;
  this release promotes `2025-11-25` to Final). Sequence: 2024-11-05, 2025-03-26,
  2025-06-18, 2025-11-25, 2026-07-28. **[V]**
- **(b) How a tool is added** — A server implements `tools/list` + `tools/call`; clients
  discover and invoke. Nothing more.
- **(c) — There is no core notion of per-tool-call policy or permission.** This is the
  single most important fact for anyone building on MCP. The closest things:
  - **Tool Annotations** — `readOnlyHint`, `destructiveHint`, `openWorldHint`. Advisory
    hints only, set by the *server*, about the server's own tool.
  - **Enterprise-Managed Authorization** (extension) — the IdP is the authoritative
    decision-maker, but for *whether the client may reach the server at all*, not for
    individual tool calls.
  - **Interceptors Working Group** — charter only; no shipped spec.
  **[V]**
- **(d)** — stdio + Streamable HTTP; clients SHOULD support stdio; custom transports allowed.
  HTTP+SSE is now formally **Deprecated**. **[V]**
- **2026-07-28 changes worth knowing** (these invalidate several circulating blog posts):
  - **Stateless operation** — no `Mcp-Session-Id`, no `initialize`/`initialized` handshake;
    new `server/discover`.
  - **Multi Round-Trip Requests (SEP-2322)** — `InputRequiredResult` replaces
    server-initiated roots / sampling / elicitation. Results now require a `resultType` of
    `"complete"` or `"input_required"`.
  - `subscriptions/listen` replaces the GET endpoint and `resources/subscribe`; SSE
    resumability removed.
  - Tasks moved to extension `io.modelcontextprotocol/tasks` (SEP-2663).
  - **Deprecated**: Roots, Sampling, Logging (SEP-2577, 12-month minimum window), HTTP+SSE,
    and RFC 7591 DCR (→ Client ID Metadata Documents).
  - Extensions framework with reverse-DNS IDs. Apps extension `io.modelcontextprotocol/ui`
  live since 2026-01-26. **[V]**
  https://modelcontextprotocol.io/llms.txt

---

## Part 2 — The three cross-cutting questions

### 2.1 Does ANY of these let the *end user* define tools/policies in a scripting language at runtime?

**Short answer: no mainstream product ships a sandboxed embedded scripting language for
this. But the gap is narrower than it was a year ago, and Claude Code now ships
JavaScript — just not where you'd want it.**

The honest taxonomy, in descending order of how close each gets:

**(1) Real policy DSL, compiled, in-process — closest to the actual ask.**
Vercel AI SDK's [`@ai-sdk/policy-opa`](https://ai-sdk.dev/docs/ai-sdk-ui/policy-opa)
gates **every** tool call with **Rego/OPA** policies, fail-closed, via either
`wasmPolicyClient` (in-process WASM — no subprocess, no interpreter dependency) or
`httpPolicyClient` (live OPA server, hot-reloads policies without a restart). Also
`optionalOpaPolicy`, `shadow()` for staged rollout, `opaCapabilityMiddleware` (drops tools
*before the model ever sees them*), `wrapMcpTools` (default-wraps uncovered tools), and
`toInput` for transitive enforcement of coarse dispatchers. Policies are testable with
`opa test` in CI — i.e. policy gets a real test story, which no scripting hook has. The docs
are also honest that the policy gates **the model's call boundary, not side effects**, so a
sandbox is still required. **[V]**
> Why this matters for the design: this is the pattern that gets you "user-writes-policy in
> a real language" *without* shipping an interpreter or trusting in-process code, because
> Rego compiles to WASM and runs under resource limits. It is the one design in this brief
> that is both a genuine policy language and a containment story.

**(2) JavaScript orchestration, deliberately hobbled — Claude Code Workflows.** **[V]**
A workflow is a `.js` file with an `export const meta = {name, description}` block and a
body using top-level `await` plus four injected globals: `agent(prompt, {schema, label})`
spawns one subagent, `pipeline(items, fn)`, `parallel(tasks)`, `phase(title)`, `log(msg)`,
and an `args` global for invocation input. The runtime constraints are the interesting part
— they read as a deliberate threat model:
- **No module loading**: a script containing `import()` fails before the run starts. *"The
  script body is plain JavaScript. Put work that needs a library in an agent's task."*
- **No direct filesystem or shell access from the workflow itself** — agents do that; the
  script only coordinates.
- `Date.now()`, `Math.random()`, and `new Date()` **throw**, so a relaunched run repeats the
  same `agent()` calls. Determinism is enforced at the language level, not by convention.
- No mid-run user input (pauses only for permission prompts / usage-limit waits).
- Caps: 16 concurrent agents by default (`CLAUDE_CODE_WORKFLOW_MAX_CONCURRENT_AGENTS`,
  1–256), 4,096 items per `parallel()`/`pipeline()` call, 1,000 agents per run. Advisory
  `Large workflow` warning above 25 agents or a projected 1.5M tokens.
- Runs in an isolated environment separate from the conversation; intermediate results stay
  in script variables so context holds only the final answer. Results are checkpointed per
  agent, making runs **resumable** (completed agents replay from cache; the first changed
  agent and everything after it re-run).
- Entry points: `ultracode` keyword in a human-typed prompt, `/effort ultracode`, or
  `/<name>` for a saved workflow. Toggle: `disableWorkflows` in settings,
  `CLAUDE_CODE_DISABLE_WORKFLOWS=1`, or the `/config` row.
→ **The lesson: Claude Code got JS-as-orchestration and then removed every capability that
would make it a policy language.** No I/O, no modules, no nondeterminism. A workflow can
*ask* for things; it cannot *decide* or *inspect* whether they're allowed. If your goal is
policy, this surface deliberately won't serve.

**(3) In-process TypeScript extensions — full power, no containment.**
Cline's `AgentPlugin` and pi's `ExtensionAPI` both hand the extension the *same OS
permissions as the agent*. pi is explicit: *"An extension runs inside the Pi process with the
same operating-system permissions. It can inspect prompts, tool calls, files, credentials,
and session history, so load extensions only from sources you trust."* **[V]** This is the
industry's actual answer to "end-user-scriptable extension": **trusted-code plugins, not a
sandbox.** Compare:
- **Cline** (TS): `api.registerTool(createTool({name, description, inputSchema, execute}))`;
  hooks `beforeRun`/`afterRun`/`beforeModel`/`afterModel`/`beforeTool`/`afterTool`/`onEvent`
  with policy `{mode: blocking|async, timeoutMs, retries, retryDelayMs, failureMode:
  fail_open|fail_closed, maxConcurrency, queueLimit}`. **[V]**
- **pi** (TS, `@earendil-works/pi-coding-agent`, MIT): `pi.on(event)` for lifecycle
  (events can **transform data, replace results, or cancel an operation** — `tool_call` can
  mutate input or **block execution**; a handler failure blocks the tool as a fail-safe),
  `pi.registerTool()`, `pi.registerCommand()`, `pi.registerShortcut()`, `pi.registerFlag()`,
  `pi.sendUserMessage()`, `pi.appendEntry()`, `pi.registerProvider()`, `pi.events` for
  inter-extension messaging, `pi.setActiveTools()` for dynamic tool gating. Loaded via
  `jiti` so local TS needs no build step; distributed as a `pi-package` with
  `{"keywords":["pi-package"], "pi": {"extensions":[…], "skills":[…], "prompts":[…],
  "themes":[…]}}` and `pi install npm:@foo/pi-tools | git:… | https://…`. **[V]**
  https://github.com/earendil-works/pi

**(4) Subprocess hooks — the universal fallback, and still the most-used.**
Claude Code (5 handler types incl. `http`, `mcp_tool`, `prompt`, `agent`), Codex (command +
MCP-tool hooks), Cline, VS Code. Arbitrary shell/Python/JS/PowerShell with JSON on stdin.
Universally available, and the only model where the hook is a *separate trust domain* — at
the cost of a process per call, no shared state, and no typed API. Note the
`PreToolUse`-returns-`allow` pattern (Claude Code) and `fail_closed` (Cline): both let a
hook act as an *approval authority*, which is more than most people use them for.

**(5) Code-as-agent.** goose Code Mode (JS in a Deno "Port of Context" runtime with three
tool-discovery meta-tools) **[V-]**; smolagents `CodeAgent` (Python) **[V]**; OpenAI Agents
SDK `ProgrammaticToolCallingTool` (JS in a hosted V8, no fs/network, explicit
`allowed_callers` allowlist) **[V]**. The OpenAI implementation is the best-engineered of
the three and the clearest model of what a *bounded* code surface looks like.

**(6) Declarative, not code.** Claude Code permissions (JSON), Codex permission profiles
(TOML, with `extends` inheritance), Roo Code modes (YAML `groups` + `fileRegex`), Cline
auto-approve categories, goose permission modes, OpenHands `mcp_config`. Composable,
testable, no code execution — but limited to what the schema anticipated.

**The gap nobody has filled:** an embedded scripting language that is *safe to run
untrusted code in* and is *specifically the policy language*. Every product that embeds a
language (Cline, pi, Capstan) says "only load trusted extensions." Every product with real
policy is declarative JSON/YAML/TOML. That gap is the opportunity — and it is also the gap
that makes the WASM/Rego approach interesting, since WASM is the only in-process option that
isn't "trust the code."

### 2.2 State of syscall-interception / seccomp sandboxing in agent products

Sorting by *actual enforcement mechanism*:

**Syscall/OS-kernel level (real isolation):**
- **Claude Code** — macOS **Seatbelt** (`sandbox-exec`, MACF policy subsystem) / Linux+WSL2
  **bubblewrap** (namespaces + seccomp) + an optional **seccomp filter** from
  `@anthropic-ai/sandbox-runtime` that restricts which Unix sockets can be connected.
  Layered on top: a `socat` network proxy enforcing `sandbox.network.allowedDomains`, and
  credential masking via a sentinel value plus a TLS-terminating proxy. **[V-]**
  → The most complete enforcement stack in the industry: kernel confinement + path policy +
  network egress allowlist + secret redaction. The two layers are complementary and both are
  needed — path rules alone don't stop exfiltration.
- **Codex CLI** — macOS **Seatbelt** via `sandbox-exec -p`; Linux **`bwrap` + seccomp**;
  a **native Windows sandbox**; WSL2 uses the Linux path (WSL1 dropped in 0.115). Three
  levels `read-only` / `workspace-write` / `danger-full-access`. Optional
  `features.network_proxy` (off by default) at `127.0.0.1:3128` HTTP / `:8081` SOCKS5.
  `codex sandbox macos|linux|windows` to debug. **[V-]**
- **OpenAI Agents SDK (partial)** — `UnixLocalSandboxClient` applies **filesystem
  restrictions via `sandbox-exec` on macOS**, but **on Linux runs commands as host
  processes with no OS-level confinement**, and provides **no network isolation** on either
  platform. The docs state this plainly. `DockerSandboxClient` / hosted providers are the
  real boundary. **[V]**
  → Useful precedent for *declaring* Unix permission bits in a manifest
  (`Permissions(owner/group/other FileMode)`, `User`/`Group`, `run_as`,
  `extra_path_grants`) — but note the SDK's own docs warn that on Linux, path grants
  "do not constrain arbitrary shell commands."

**Container / microVM level (coarse but robust):**
- **OpenHands** — **Docker sandbox is the default**, with a FastAPI Action Execution Server
  inside the container. **[V]**
- **smolagents** — `executor_type="e2b" | "modal" | "blaxel" | "docker"`, plus local Docker
  via the `docker` Python SDK with `cap_drop=["ALL"]`, `security_opt=["no-new-privileges"]`,
  `pids_limit`, `mem_limit`, `cpu_quota`, `user="nobody"`. **[V]**
- **goose** — `--container`. **[V-]**
- **pi** — four documented patterns: plain Docker; **Docker Sandboxes** (`sbx`, whose proxy
  keeps the real provider credential on the host and substitutes it at egress);
  **NVIDIA OpenShell** (filesystem / process / network / credential / inference policies
  through a gateway); and a **Gondolin** extension routing built-in tools + `!` commands
  into a local **QEMU micro-VM** while `pi` and credentials stay on the host. pi is explicit
  that it has **no built-in permission system** for filesystem, process, network, or
  credential access. **[V]**
  https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/containerization.md
- **OpenAI Agents SDK hosted** — `ShellTool` with `environment: {type: "container_auto" |
  "container_reference"}`, `network_policy: "disabled" | "allowlist"`,
  `network_policy.domain_secrets`, `memory_limit`, `file_ids`. **[V]**

**Language-interpreter level (not a security boundary):**
- **smolagents `LocalPythonExecutor`** — a purpose-built AST interpreter with an
  authorized-imports allowlist, submodule denial, and an operation cap. The authors state
  plainly that no local Python sandbox is ever secure and recommend E2B/Docker for
  high-security cases. **[V]**
→ Worth noting as a *UX* pattern (safe by default, good error messages) but it is not
syscall interception and must not be confused with it.

**No sandbox at all:**
- **Aider** — none. **[V]**
- **Cline / Roo Code** — none; auto-approve lists + VS Code workspace trust. Cline's
  command safety is a `requires_approval` flag **set by the model itself**, which is a
  prompt to the model, not an enforcement boundary. Kanban's git worktrees are isolation
  for parallel edits, not for security. **[V]**
- **pi** — none built in, by explicit design. **[V]**

**Summary of the state of the art:** exactly **two** shipping products (Claude Code, Codex)
do real kernel-level confinement on all three major platforms, and both pair it with a
separate network-egress allowlist and a seccomp/bwrap layer. Everyone else is either
container-only, interpreter-level, or trusting the model. Notably, **nobody ships seccomp as
a user-facing policy primitive** — it appears only as an implementation detail inside Claude
Code's and Codex's own sandboxes. That is precisely the gap this repo's
`agent.bash(cmd, policy)` occupies, where `policy` is a Lua table of syscall name ->
callback the tool wrote itself.

### 2.3 Is there a known project doing Lua-as-policy for agent sandboxing?

**Yes — exactly one, and it is small: [Capstan](https://github.com/theStrangeAdventurer/capstan).**
Confidence: **high that it exists and does this; low that it constitutes prior art worth
citing.** It appeared in exactly one search result (a Reddit post) and was then confirmed
directly against its README and GitHub search.

- **What it is** — "A lightweight, extensible terminal coding agent built in **C with an
  embedded Lua runtime**." C99 with `-Wall -Wextra -Werror`; **Lua and ncurses are vendored
  and statically linked**; `libcurl` is the only system-linked runtime library. Apache-2.0.
  Single binary for macOS arm64, Linux x86_64/arm64. **[V]**
- **Scale** — **16 GitHub stars**, solo author (`theStrangeAdventurer`), updated ~16 days
  before this research. Its own benchmark section labels its results "exploratory" and
  "research evidence rather than a publishable release result" because the worktree was
  dirty. **[V]**
- **How far Lua goes — further than this repo.** One language for the whole control plane:
  - `~/.config/capstan/config.lua` — provider, model, permissions, MCP, observability
  - `permissions = { {tool="file_read", pattern="~/code/project/*", allow=true}, … }` —
    **durable allow/deny rules in Lua tables**, later matching rules win, and explicit
    denies beat `--yolo`
  - `~/.config/capstan/profiles/*.lua` — profiles with `allowed_tools = { file_read=true,
    file_write=true, … }`, `readonly`, `reasoning_effort`, `prompt`. **Profile tool
    restrictions are enforced before plugin and permission handling: tools absent from
    `allowed_tools` are never sent to the model** — a capability-filtering design, not just
    a call-time check. Built-in profiles are themselves embedded Lua.
  - `~/.config/capstan/plugins/*.lua` — a plugin may be a slash command, a model tool, an
    autocomplete source, an OAuth provider, a lifecycle hook, or any combination.
    **Hot-reloaded in the TUI.**
  - `hooks.after_agent_turn` with `hooks_scope = "orchestrator"`, receiving a `ctx` and
    returning it
  - A gated `capabilities.self_improvement` flag that lets **the agent write its own Lua
    plugins** (the README's demo: ask it to create a `/hello` command; it writes the file and
    hot-reloads it, no restart). Spec at `specs/self-improvement.md`.
  - Debug introspection from inside the agent: a `logs` tool reading
    `$XDG_STATE_HOME/capstan/logs/`.
- **Its sandbox is *not* syscall-level.** Permissions are pattern-matched **in Lua** against
  tool + path, plus a `--yolo` escape hatch. There is no seccomp, no bwrap, no Seatbelt.
  Tools are `file_read`, `file_write`, `file_edit`, `shell`, `fetch`, `logs`, `subagents`,
  Wiki tools, and MCP tools. **`--yolo` is process-local** and "should only be used in a
  trusted workspace." **[V]**
- Also ships MCP (stdio + Streamable HTTP), **ACP** (`capstan acp`, so it plugs into
  ACP-compatible editors), skills at `.agents/skills/<name>/SKILL.md`, layered `AGENTS.md`
  (`~/.config/capstan/AGENTS.md` → `~/.agents/AGENTS.md` → `<workspace>/AGENTS.md`),
  OpenTelemetry OTLP export, ncurses TUI + headless `capstan run`, and per-workspace
  sessions.

**The comparison that matters for this repo:**

| | **this repo (`agent`)** | **Capstan** |
|---|---|---|
| Host language | Rust | C99 |
| Embedded runtime | mlua / **LuaJIT**, `vendored` | **Lua**, vendored + statically linked |
| Lua owns | config, system prompt, tools, policies, event hooks, history, memory | config, **permissions**, profiles, plugins, hooks, providers, observability |
| Enforcement mechanism | **seccomp, exposed to Lua** | **Lua pattern-matching, in-process** |
| Who decides | **the user, asked per syscall** | the policy table, silently |
| Hot reload | `/reload`, nothing cached Rust-side | TUI hot-reload of plugins |
| Agent can write its own Lua | not present | **yes**, gated `self_improvement` |
| Transport surface | MCP-shaped tools | MCP + **ACP** |
| Scale | this project | **16 stars**, solo, pre-release |

The `Enforcement mechanism` row flatters this repo and the `Who decides` row is the correction.
Both halves use a language-written policy; only one of them *enforces* it without a human in
the loop. A seccomp user-notify filter is a real kernel-level decision point, and it is still
a **question**, answered in the moment by whoever is watching — a denied syscall kills the
tracee, but nothing is refused that the user has not had the chance to allow. Capstan's
pattern-matching decides on its own and says no. So on "does an untrusted command get to do
the thing", the smaller project is the stricter one, and the row order above is not a quality
ranking. What the seccomp substrate buys is a floor under the *decision* — real arguments, read
out of a frozen process, instead of a pattern someone wrote — not autonomy from the user.

**The honest read:** Capstan proves the *ergonomics* — that a single embedded language can
own config, tools, policy, and hooks without the user learning a second surface — and it is
ahead on one axis that matters: it decides without asking. Its
`allowed_tools`-as-pre-send-filter is a better enforcement point than a call-time check. But
it does **not** attempt kernel-level isolation, so it is not a precedent for the part of this
design that is actually novel. There is **no established project doing Lua-as-policy over a
syscall-interception sandbox.** The nearest mature analogues are non-Lua:
**Rego/OPA** (WASM, in-process, fail-closed, `opa test`-able — the strongest) and **Cedar**
(AWS, with formal analysis tooling).

**Also worth naming as adjacent prior art:** NVIDIA **OpenShell** — a "policy-controlled
sandbox" for agents with filesystem, process, network, credential, and inference policies
behind a gateway. It is the productization of the idea that an agent sandbox should be
policy-driven rather than container-shaped, and pi documents integrating with it. **[V]**
https://docs.nvidia.com/openshell/about/overview

---

## Part 3 — Implications for this project

Framed against the findings, not as recommendations.

**The design has no direct precedent, and that cuts both ways.** The closest public project
(Capstan) matches on "embedded Lua as the control plane" but not on "seccomp exposed to
Lua." Since Claude Code and Codex both ship seccomp/bwrap as *undocumented implementation
detail* and never as a user-facing policy surface, and since nobody ships a sandboxed
embedded DSL for policy, the combination is genuinely unclaimed. **[?]** Treat "unclaimed" as
an observation about a fast-moving field, not a moat — the `?` is that I surveyed docs, not
source code, and a small project could exist that I did not surface in search.

**The strongest external validation available is Rego/OPA, not Lua.** `@ai-sdk/policy-opa`
demonstrates that a real policy language is worth having — and demonstrates the properties
worth copying: fail-closed by default, in-process WASM with resource limits (so untrusted
policy is containable), hot-reload without restart, `shadow()` for staged rollout,
capability middleware that drops tools *before the model sees them*, and `opa test` in CI.
None of the scripting-hook approaches (Claude Code hooks, Cline hooks, pi extensions) offer
that test story. If the project's policy surface grows past a couple of tables, the
WASM-compiled-language route is the one with a track record — and it composes: Rego for
*policy*, Lua for *glue*.

**Two concrete design patterns from the competitors are worth stealing on their merits.**
(1) **Capability filtering over call-time checks** — Capstan's `allowed_tools` is applied
"before plugin and permission handling: tools absent from `allowed_tools` are not sent to
the model," and Cline's `opaCapabilityMiddleware` / pi's `pi.setActiveTools()` do the same.
Reducing the tool surface is strictly stronger than denying a call after the model has
already committed to it, and it saves context. (2) **Determinism enforced at the language
level** — Claude Code makes `Date.now()` and `Math.random()` *throw* inside workflow scripts
so a resumed run replays identically. If any of this repo's Lua is ever involved in
replayable or resumable execution, that is the pattern.

**The "policy in a Markdown file" precedent is worth knowing about, in both directions.**
Codex routes approvals to a reviewer subagent governed by
`codex-rs/core/src/guardian/policy.md`. It is the cheapest "policy as prose" design in the
industry and it is genuinely effective — but it is enforced by an *LLM reading prose*, not
by a deterministic interpreter. That is the trade this repo's seccomp policy explicitly
declines to make, which is the right call: prose policies are undecidable and unauditable.

**Where the competitive risk actually sits.** The realistic threats are not other agents
shipping Lua-as-policy. They are: (a) **Claude Code closing the gap** — it already has JS
workflows, plugins, hooks, and a real seccomp sandbox, and adding a policy hook that runs
*inside* the sandbox is a small step; (b) **NVIDIA OpenShell** productizing policy-driven
agent sandboxes at the infrastructure layer, which would make "policy" a platform concern
rather than an application one; (c) **the declarative route getting good enough** — Codex's
named permission profiles with `extends` inheritance, and Roo's `fileRegex` groups, are
composable and auditable, and a Rust agent that only offers a scripting language will look
*less* safe than one that offers a schema.

**Where the project's approach is already ahead.** Three things none of the competitors do
in combination: policy expressed in a language a non-programmer can plausibly write;
enforcement at the syscall layer rather than in a hook that the tool could bypass; and
hot-reload with nothing cached on the Rust side (Claude Code needs `/reload-skills` and
discards the extension runtime on reload; Cline plugins need reinstall). Capstan matches the
third and part of the first; nothing matches the second.

---

## Appendix — Primary sources

| Topic | URL |
|---|---|
| Claude Code plugin manifest | https://code.claude.com/docs/en/plugins-reference |
| Claude Code workflows (JS) | https://code.claude.com/docs/en/workflows |
| Claude Code doc index | https://code.claude.com/docs/llms.txt |
| Codex `config.toml` reference | https://developers.openai.com/codex/config-reference (append `.md`) |
| Codex auto-review policy | https://github.com/openai/codex/blob/main/codex-rs/core/src/guardian/policy.md |
| Aider config | https://aider.chat/docs/config/ |
| OpenHands custom tools | https://docs.openhands.dev/sdk/guides/custom-tools |
| Goose extensions | https://block.github.io/goose/docs/guides/developer/goose-extensions |
| Cline SDK plugins | https://docs.cline.bot/sdk/plugins |
| Cline writing plugins | https://docs.cline.bot/sdk/guides/writing-plugins |
| Cline auto-approve | https://docs.cline.bot/features/auto-approve |
| Cline doc index | https://docs.cline.bot/llms.txt |
| Roo Code custom modes | https://docs.roocode.com/features/custom-modes |
| smolagents tools | https://huggingface.co/docs/smolagents/en/tutorials/tools |
| smolagents secure execution | https://huggingface.co/docs/smolagents/en/tutorials/secure_code_execution |
| Pydantic AI tools | https://pydantic.dev/docs/ai/tools-toolsets/tools/ |
| Pydantic AI deferred tools / approval | https://pydantic.dev/docs/ai/tools-toolsets/deferred-tools/ |
| OpenAI Agents SDK tools | https://openai.github.io/openai-agents-python/tools/ |
| OpenAI Agents SDK sandbox concepts | https://openai.github.io/openai-agents-python/sandbox/guide/ |
| Vercel `@ai-sdk/policy-opa` (Rego) | https://ai-sdk.dev/docs/ai-sdk-ui/policy-opa |
| pi extensions | https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md |
| pi containerization | https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/containerization.md |
| **Capstan (Lua agent)** | https://github.com/theStrangeAdventurer/capstan |
| MCP spec index | https://modelcontextprotocol.io/llms.txt |
| NVIDIA OpenShell | https://docs.nvidia.com/openshell/about/overview |

## Open uncertainties (carry these forward)

1. **Aider `.aider/commands`** — vendor doc 404s; support status unverified. Treat as stale.
2. **goose Code Mode default-on?** — the extension exists and is documented; I did not
   confirm whether shipped builds enable it.
3. **"No project does Lua-as-policy over seccomp"** — this is a negative claim from
   documentation search, not from source-code or package-registry search. Reasonable but not
   provable; a small project could exist.
4. **Capstan's benchmark claims** — self-published, self-labeled exploratory, dirty
   worktree. Not usable as evidence.
5. **Aider's Python scripting API** — documented as unsupported; I did not verify whether it
   has since been formalized.
