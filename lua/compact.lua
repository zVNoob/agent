-- compact.lua — the `compact` mode: no tools, and a prompt that asks the model
-- to write the conversation down instead of doing more work.
--
--   agent.mode.new("compact", require("compact"))
--
-- Registering it changes nothing until you switch to it (`agent.mode.set("compact")`),
-- and switching back with `agent.mode.set()` restores your prompt and registry.
--
-- ## What the mode is for
--
-- A long conversation is expensive to resend and hard for the model to hold, so
-- compaction is the standard fix: replace the history with a summary plus the
-- recent tail. The usual way to build one is a `turn_completed` handler that
-- summarizes the old part off to the side (`agent.http`) and hands the loop a
-- replacement history via `agent.trigger({ ... })`. This mode is the other half
-- of that trade: instead of a *side* model summarizing a window, the agent
-- itself reads the whole conversation and writes the summary — which is the only
-- thing here that can be worth its own turn, because it is the only actor that
-- has seen all of it.
--
-- The mode is therefore deliberately austere:
--
--   mcps = {}  — no tools at all, so a compaction turn cannot touch the
--     filesystem, run a command, or reach the network. It can only answer.
--     (The shell included: `bash` is a registered connection like any other, so
--     an empty registry is an empty toolset — see `lua/lib/mode.lua`.)
--
--   the prompt — the whole job: write a handoff summary of the conversation so
--     far, in a fixed shape, with no preamble and nothing invented.
--
-- ## What it does *not* do
--
-- It does not rewrite the history. A mode is a prompt and a tool set; the
-- history lives in the agent loop, and only `agent.trigger` can replace it. So
-- the compaction turn ends with a summary *in the transcript*, and something
-- has to carry that summary forward — a `turn_completed` handler that pulls it
-- out and calls
--
--   agent.trigger({ { role = "system", content = summary }, unpack(keep) })
--
-- The handler is deliberately not written here: which messages to keep, how to
-- pull the summary back out of the last assistant turn, and when a compaction is
-- due at all are policy decisions, and the wiring point for them is the entry
-- script (`lua/init.lua`) where the other loop-level hooks live. Switch to the
-- mode, ask for a compaction, and let that handler land the result.
--
-- For a mode that needs no rewriting at all, point `agent.mode.set` at this one
-- and read the summary yourself.

return {
  description = "compact the conversation: no tools, write a handoff summary",

  -- The empty registry is the point: `set` overwrites `agent.mcps` with exactly
  -- this, so the next request advertises no tools whatsoever and a tool call is
  -- not even invokable.
  mcps = {},

  system_prompt = [[
You are compacting this conversation. You have no tools: do not try to read
files, run commands, or search — your only job is to write the conversation down
so it can continue without you.

Write a handoff summary, using exactly these sections:

## Task
What the user is ultimately trying to accomplish, in one or two sentences. If
the request is still ambiguous, say which reading you assumed.

## Done
What has already been completed, and the decisions made along the way (approach
chosen, alternatives rejected and why). One line per item, most recent last.

## State
The current working context: which files, functions, or services matter now, and
the concrete facts discovered while working — error messages, test results,
values, paths. Include the exact text of anything that will be needed verbatim
(a failing assertion, a schema, a command that works). Omit what is obvious from
the file names.

## Next
What remains, in order, with the first step spelled out enough to start from
without re-reading the whole conversation.

Rules:

- Report only what is in the conversation. Never invent a file path, a symbol, a
  command, or a result; if something was not established, leave it out.
- No preamble, no closing remarks, no offers to continue — the summary is the
  whole reply.
- Prefer specifics over prose. "read errors on a missing path, returns
  `{ ok = false, error = ... }`" beats "there were some issues with reading".
- Keep the user's own words for requirements and constraints; they are the part
  most easily lost.
]],
}
