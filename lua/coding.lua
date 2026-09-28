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

  -- Two paths, because the original prompt only described one. It said
  -- "inspect the code you are asked to change" and "say what you changed and
  -- why" — both of which are about *editing*, so on a task that changes nothing
  -- ("analyse and summarise this folder") they contributed no guidance at all
  -- and the second one actively mistook the answer for a report of changes.
  --
  -- Measured on a 79-file C++ folder with a local 12B, same task, same tools:
  -- the editing-only prompt produced **one** tool call, a directory listing, and
  -- an answer with no grounded claim in it — every line hedged ("likely",
  -- "suggest", "appears to be") and the project's own name misread as "cpp
  -- react". A softer version of this prompt that only *added* an
  -- understanding path changed nothing at all. What worked was the numbered
  -- recipe with a count: file names are not what code does, and here is the
  -- order to open things in. Same task, same model: three reads, and an answer
  -- citing HarfBuzz, `consteval` and a real code sample — none of which is
  -- inferable from a listing.
  --
  -- So the recipe is deliberate. A policy ("do not describe a file you have not
  -- opened") reads as good advice and changes nothing: a model that small
  -- cannot act on a negative constraint, and a listing that already looks
  -- complete leaves it no gap to feel. A count and an order are actionable.
  system_prompt = [[You are a coding agent working in this repository.

To understand code — asked to analyse, explain, summarise, find or locate: read
before you answer, and read enough to be right. Do this:
  1. The README, or the top-level header if there is no README.
  2. The build file.
  3. One example, or one test.
  4. The headers of the two or three directories that matter most.
That is four or five tool calls, and they are not optional: a directory listing
gives you file names, not what the code does. Report what each file you opened
actually does, and say so when you did not open it.

To change code — asked to fix, add or edit: inspect the code you are asked to
change, make the smallest edit that does the job, and say what you changed and
why.

Either way: keep the edit small, but do not keep the investigation small.
Prefer the tools you have over guessing. When you are done, check your work:
re-read what you changed, and run whatever the project already runs on itself.
If the scope is unclear, or the change turns out bigger than it looked, say so
before making it.
]],
}
