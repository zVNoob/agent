-- coding.lua — the `coding` mode: all the tools, and a prompt that says the job
-- is working in this repository.
--
--   agent.mode.new("coding", require("coding"))
--   agent.mode.set("coding")   -- all tools, coding prompt
--   agent.mode.set()           -- back to the state captured before the first switch
--
-- Registering it changes nothing until you switch to it. It is the mode the
-- shipped config starts in, and it is the mode you actually work
-- in, as against `compact` — which is a *restriction*: an empty connection set,
-- so a compaction turn has no tools at all and can only answer.
--
-- ## Why it lists its connections instead of saying "all"
--
-- The tool set is `require("mcps")` — the shipped registry, by name. The
-- alternative is the string `"all"`, which leaves whatever registry is in force
-- alone and swaps only the prompt (see `agent.mode.new` in `lua/lib/mode.lua`).
-- That is the more robust of the two — a connection registered after this module
-- was written is still in it — and the reason to prefer it is that a list has to
-- be kept in step by hand.
--
-- This uses the list because it *names* what the mode can reach: the whole
-- shipped set, stated where a reader can see it, rather than "whatever this
-- session happens to have registered". `agent.mode.set()` still restores
-- everything the config had, so nothing is lost by naming it.
--
-- ## What the tools do when you get here
--
-- Whatever `mcps` names — the file tools (`lua/fs.lua`) and the sandboxed shell
-- (`lua/bash_tool.lua`). Two rules hold regardless of mode, because they are the
-- engine's and not the mode's:
--
--   * A file operation asks before it touches anything, and "always" remembers
--     the path. The working directory is trusted outright (`lua/init.lua`), so
--     work inside this repository asks nothing and everything outside it does.
--   * The shell runs under seccomp with the default policy (`lua/policy.lua`):
--     every open and every endpoint is asked about. A mode is not a sandbox, so
--     switching into this one changes what you can reach no further than the
--     tools it lists.

return {
  description = "work in this repository: all the tools, a coding prompt",

  mcps = require("mcps"),

  system_prompt = [[You are a coding agent working in this repository.

Start by reading before you write: inspect the code you are asked to change,
then make the smallest edit that does the job, and say what you changed and
why. Prefer the tools you have over guessing; if a tool is not enough, say so
instead of improvising a workaround.
]],
}
