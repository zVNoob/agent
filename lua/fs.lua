-- fs.lua — the filesystem tool connection.
--
-- Everything the agent can do to files, as one MCP-shaped connection:
--
--   agent.mcps.fs = require("fs")
--
-- Registering it is that one line: the returned value is a connection
-- (`{ name = "fs", tools = { ... } }`), exactly what `agent.mcp` produces and
-- what Rust reindexes per request. Drop the line and the tools are gone; delete
-- a `tools.<name>` line and that one tool is gone.
--
--   read_file    read a file with line numbers              (asks to read)
--   list_dir     list a directory                           (asks to read)
--   write_file   create/overwrite a file verbatim           (asks to write)
--   apply_patch  apply a unified diff, show before/after    (asks to write)
--
-- ## Every operation asks
--
-- A read is `io.open`, a write is `io.open` for writing, and the only two things
-- the standard library cannot do — create a parent directory, and list a
-- directory — are the only two shell calls in the file (`os.execute` and
-- `io.popen`, both with the path quoted by `agent.shq`). No command line ever
-- carries a file's *contents*, so nothing to be got wrong by quoting them.
--
-- Each operation resolves the path the model gave it, then asks about *that*
-- path, in the words the user sees:
--
--   Allow read /home/may/notes.md
--   Allow write /home/may/notes.md, which is the symlink of notes.md
--
-- "always" is on offer, because a path is exactly what `agent.ask`'s trust
-- tables remember — so the answer is asked through the same `[y]es / [n]o /
-- [a]lways` prompt as the shell tool. See `lua/lib/ask.lua`. What the tables
-- buy *these* tools today is nothing across calls: each tool call gets a fresh
-- VM, so there is exactly one ask per operation, and it is asked every time.
-- That is a limitation of where the tables live, not of the tools.
--
-- What this gives up, plainly: the seccomp sandbox. These operations used to run
-- under a policy that denied a write from a read tool, and the kernel was the
-- floor. The ask is now the only gate for them, which is fine as long as the ask
-- is answered by a human (and headless, where there is no one, `agent.ask`
-- denies and the tool does nothing). The sandbox still guards the `bash` tool,
-- which is where a command line can do something a file operation cannot.
--
-- The module also publishes itself as `agent.fs` (the `lua/lib/` convention, so
-- a tool can reach a sibling without requiring it again) and exposes the pure
-- diff engine as `agent.fs.patch` — parse and apply with no sandbox and no I/O:
--
--   local res = agent.fs.patch.apply(old_text, diff)   -- { content, added, removed, ... }
--   local lines = agent.fs.patch.split(text)           -- text -> lines, round-trips

local M = { name = "fs", tools = {} }

-- ==========================================================================
-- The pure-Lua unified-diff engine: parse and apply. No sandbox, no I/O — the
-- tools below do the file read/write. Exposed as `M.patch` so callers (and the
-- Rust tests) can drive it directly.
-- ==========================================================================

--- Split `text` into lines, keeping the trailing empty line after a final
--- newline, so joining with "\n" reproduces the input byte for byte: a patch
--- never eats a file's last newline and untouched regions round-trip exactly.
local function patch_split(text)
  if text == "" then return {} end
  local t, pos, n = {}, 1, #text
  while true do
    local nl = text:find("\n", pos)
    if nl == nil then
      t[#t + 1] = text:sub(pos)
      return t
    end
    t[#t + 1] = text:sub(pos, nl - 1)
    pos = nl + 1
    if pos > n then
      t[#t + 1] = ""
      return t
    end
  end
end

local function patch_normalize(line)
  return line:gsub("\r$", "") -- CRLF and LF are the same line for matching
end

-- "@@ -s[,c] +s[,c] @"-style header -> { old_start, old_count, new_start,
-- new_count, known } (bare "@@" -> counts unknown, zeros). nil = malformed.
-- " -2,2 +3" parses as start=2/count=2, start=3/count=1; " -2," is count 0.
local function patch_counts(spec)
  local start_s, comma, count_s = spec:match("^(%d+)(,?)(%d*)$")
  if not start_s then return nil end
  local count = 1
  if comma == "," then
    count = (count_s ~= "") and tonumber(count_s) or 0
  end
  return tonumber(start_s), count
end

local function patch_header(line)
  local rest = line:match("^@@(.*)$")
  if not rest then return nil end
  rest = (rest:gsub("@@.*$", "")):gsub("^%s+", ""):gsub("%s*$", "")
  if rest == "" then
    return { old_start = 0, old_count = 0, new_start = 0, new_count = 0, known = false }
  end
  local o, n = rest:match("^%-(%S*)%s*%+(%S*)$")
  if not o then return nil end
  local os, oc = patch_counts(o)
  local ns, nc = patch_counts(n)
  if not (os and ns) then return nil end
  return {
    old_start = os,
    old_count = oc,
    new_start = ns,
    new_count = nc,
    known = true,
  }
end

-- One hunk-body line: "kind", "text" (leading prefix stripped). Unprefixed
-- trivia — "\ No newline at end of file" markers and stray blank separators —
-- is "mark" (skipped): a real empty context line is written " " (a space).
local function patch_classify(line)
  local c = line:sub(1, 1)
  if c == " " then return "ctx", line:sub(2) end
  if c == "-" then return "old", line:sub(2) end
  if c == "+" then return "new", line:sub(2) end
  if c == "\\" or line == "" then return "mark", nil end
  return nil, nil
end

local function patch_parse(diff)
  local lines = patch_split(diff)
  local idx = 1
  -- Skip leading noise ("--- a/x", "+++ b/x", "diff --git", blank lines)
  -- until the first hunk header.
  while idx <= #lines and lines[idx]:sub(1, 2) ~= "@@" do
    idx = idx + 1
  end
  local hunks = {}
  while idx <= #lines do
    local hdr = patch_header(lines[idx])
    if not hdr then
      error("hunk " .. (#hunks + 1) .. ": expected an '@@' header, got '" ..
            lines[idx] .. "'")
    end
    idx = idx + 1
    local body = {} -- { { kind = "ctx"|"old"|"new", text = ... }, ... } in order
    while idx <= #lines and lines[idx]:sub(1, 2) ~= "@@" do
      local kind, text = patch_classify(lines[idx])
      if not kind then
        error("hunk " .. (#hunks + 1) .. ": unexpected line '" .. lines[idx] ..
              "' (the body wants ' ', '-', '+' or '\\' prefixed lines)")
      end
      if kind ~= "mark" then
        body[#body + 1] = { kind = kind, text = patch_normalize(text) }
      end
      idx = idx + 1
    end
    local old_side, new_side, removed_n, added_n = {}, {}, 0, 0
    for _, e in ipairs(body) do
      if e.kind ~= "new" then old_side[#old_side + 1] = e.text end
      if e.kind ~= "old" then new_side[#new_side + 1] = e.text end
      if e.kind == "old" then removed_n = removed_n + 1 end
      if e.kind == "new" then added_n = added_n + 1 end
    end
    hunks[#hunks + 1] = {
      body = body, old_side = old_side, new_side = new_side,
      removed_n = removed_n, added_n = added_n,
      old_start = hdr.old_start, new_start = hdr.new_start,
    }
  end
  return hunks
end

-- First index in `lines` (>= from) where the whole sequence `seq` matches
-- contiguously; nil when nowhere. Application is purely content-based, so
-- the model's line numbers never have to be right — drift is harmless.
local function patch_locate(seq, lines, from)
  local first = seq[1]
  for p = from, #lines - #seq + 1 do
    if lines[p] == first then
      local ok = true
      for q = 2, #seq do
        if lines[p + q - 1] ~= seq[q] then ok = false break end
      end
      if ok then return p end
    end
  end
  return nil
end

-- `seq` matches *exactly* at position `pos` in `lines` (anchored, unlike
-- patch_locate which scans forward). Used for the already-applied checks.
local function patch_match_at(seq, lines, pos)
  if pos < 1 or pos + #seq - 1 > #lines then return false end
  for q = 1, #seq do
    if lines[pos + q - 1] ~= seq[q] then return false end
  end
  return true
end

-- Apply `diff` to `old_text`. Returns { content, added, removed,
-- before_changed, after_changed } — the last two are 1-based line spans in
-- the old / new texts respectively (for the split panel's red/green tint).
-- Raises on a malformed patch or a hunk that does not match (nothing is
-- ever partially applied: the new content is built fully before any write).
local function patch_apply(old_text, diff)
  local hunks = patch_parse(diff)
  if #hunks == 0 then
    error("the patch has no @@ hunks")
  end
  local old_lines = {}
  -- CRLF and LF are the same line for matching (patches are matched as LF;
  -- the new content is written LF, so a CRLF file is rewritten as LF).
  for _, l in ipairs(patch_split(old_text)) do
    old_lines[#old_lines + 1] = patch_normalize(l)
  end
  local new_lines, cursor, added, removed = {}, 1, 0, 0
  local before_changed, after_changed = {}, {}
  for i, h in ipairs(hunks) do
    if #h.old_side == 0 then
      error("hunk " .. i .. " inserts without context: anchor it with " ..
            "surrounding unchanged lines")
    end
    local at = patch_locate(h.old_side, old_lines, cursor)
    if not at then
      -- Already-applied replacement hunk: the old side is gone but the new
      -- side is present somewhere ahead — skip it (the file already has the
      -- change; keep it byte-for-byte instead of erroring).
      local an = patch_locate(h.new_side, old_lines, cursor)
      if an then
        for j = cursor, an + #h.new_side - 1 do
          new_lines[#new_lines + 1] = old_lines[j]
        end
        cursor = an + #h.new_side
      else
        error("hunk " .. i .. " (near old line " .. h.old_start .. ") does not " ..
              "match the file: its context lines were not found")
      end
    elseif h.removed_n == 0 and patch_match_at(h.new_side, old_lines, at) then
      -- Already-applied insertion hunk: the added lines already sit right
      -- after the context at the matched spot (a pure insertion's context
      -- would otherwise match again and duplicate the lines).
      for j = cursor, at + #h.new_side - 1 do
        new_lines[#new_lines + 1] = old_lines[j]
      end
      cursor = at + #h.new_side
    else
      for j = cursor, at - 1 do new_lines[#new_lines + 1] = old_lines[j] end
      local oldpos, rem_start, add_start = at, nil, nil
      for _, e in ipairs(h.body) do
        if e.kind == "ctx" then
          new_lines[#new_lines + 1] = e.text
          oldpos = oldpos + 1
          if rem_start then
            before_changed[#before_changed + 1] = { rem_start, oldpos - 1 }
            rem_start = nil
          end
        elseif e.kind == "old" then
          removed = removed + 1
          if not rem_start then rem_start = oldpos end
          oldpos = oldpos + 1
        else -- "new"
          added = added + 1
          if not add_start then add_start = #new_lines + 1 end
          new_lines[#new_lines + 1] = e.text
        end
      end
      if rem_start then
        before_changed[#before_changed + 1] = { rem_start, oldpos - 1 }
      end
      if add_start then
        after_changed[#after_changed + 1] = { add_start, #new_lines }
      end
      cursor = oldpos
    end
  end
  for j = cursor, #old_lines do new_lines[#new_lines + 1] = old_lines[j] end
  return {
    content = table.concat(new_lines, "\n"),
    added = added, removed = removed,
    before_changed = before_changed, after_changed = after_changed,
  }
end

M.patch = { split = patch_split, apply = patch_apply }

-- ==========================================================================
-- Shared helpers
-- ==========================================================================

-- Byte range (inclusive start, exclusive end) of lines `first..last` (1-based)
-- inside a pane text that is exactly the lines joined with "\n".
local function line_bytes(lines, first, last)
  local off = 0
  for i = 1, first - 1 do off = off + #lines[i] + 1 end
  local start = off
  for i = first, last do off = off + #lines[i] + 1 end
  return start, off - 1
end

-- Best-effort pane language by file extension; panes render plain when the
-- extension is not known (or there is none).
local FILE_LANGS = {
  rs = "rust", go = "go", py = "python", lua = "lua", sh = "bash", bash = "bash",
  zsh = "bash", js = "javascript", mjs = "javascript", cjs = "javascript",
  ts = "typescript", tsx = "typescriptreact", jsx = "javascriptreact",
  json = "json", toml = "toml", yaml = "yaml", yml = "yaml", md = "markdown",
  html = "html", htm = "html", css = "css", c = "c", h = "c", cpp = "cpp",
  cc = "cpp", cxx = "cpp", hpp = "cpp", hh = "cpp", java = "java", rb = "ruby",
  php = "php", sql = "sql", xml = "xml", svg = "svg", ini = "ini",
}
local function lang_for(path)
  local ext = path:match("%.([%a%d]+)$")
  if not ext then return nil end
  return FILE_LANGS[ext:lower()]
end

-- The ask, and the two helpers every tool below goes through. `kind` is "read"
-- or "write": the two differ only in which trust table answers, which is what
-- makes "you may read here" and "you may write here" separate decisions.
--
-- The question names the path the agent is really about, and says where that
-- came from when it is not the path the model wrote — a tilde or a relative path
-- resolved to an absolute one. (A symlink is *not* followed: the standard
-- library cannot resolve one, so a symlinked path is asked about, and trusted,
-- under its own name.)
local ask = require("ask")

local function permit(kind, given)
  local resolved = ask.resolve(given)
  local question = "Allow " .. kind .. " " .. resolved
  if resolved ~= given then
    question = question .. ", which is the symlink of " .. given
  end
  local verdict
  if kind == "write" then
    verdict = ask.ask_trust_write(resolved, question)
  else
    verdict = ask.ask_trust_read(resolved, question)
  end
  local allowed, reason = ask.of(verdict)
  return resolved, allowed, reason
end

-- What a refused operation reports: the same shape the sandbox's denials used to
-- produce, so a caller (or a policy) sees one kind of refusal either way.
local function refused(tool, path, reason)
  return { ok = false, denied = true,
           error = tool .. ": '" .. path .. "' was not allowed" ..
                   (reason and (": " .. reason) or "") }
end

-- A non-empty string argument, or a failure result naming what was wrong.
local function want_path(tool, args)
  if type(args.path) ~= "string" or args.path == "" then
    return nil, { ok = false, error = tool .. ": a non-empty 'path' string is required" }
  end
  return args.path
end

-- ==========================================================================
-- The tools
-- ==========================================================================

local function read_file(args)
  local given, bad = want_path("read_file", args)
  if not given then return bad end
  local path, allowed, reason = permit("read", given)
  if not allowed then return refused("read_file", path, reason) end
  local handle, err = io.open(path, "rb")
  if not handle then
    return { ok = false, error = "read_file: cannot read '" .. path .. "': " .. tostring(err) }
  end
  local body = handle:read("*a")
  handle:close()
  -- Numbered here rather than by `cat -n`, so the model gets the same shape with
  -- one less process: every line numbered, tab-separated, a trailing newline
  -- (a file that has none still ends its last line cleanly, and a `\r` stays on
  -- its line, as it did under `cat`).
  local numbered, n, pos = {}, 0, 1
  while pos <= #body do
    local stop = body:find("\n", pos, true)
    n = n + 1
    numbered[n] = n .. "\t" .. (stop and body:sub(pos, stop - 1) or body:sub(pos))
    if not stop then break end
    pos = stop + 1
  end
  local content = table.concat(numbered, "\n")
  if content ~= "" then content = content .. "\n" end
  return { ok = true, result = { content = content } }
end

-- The stdlib cannot list a directory (no readdir in Lua 5.1), so this is the
-- one read that shells out — after the ask, with the path quoted.
--
-- The trailing slash is deliberate: `ls` happily describes a *file* it is given,
-- which is not what this tool is for, but `ls <file>/` fails with "not a
-- directory" and prints nothing. So the listing is empty exactly when the path
-- is not a directory, and that is the failure we report.
local function list_dir(args)
  local given, bad = want_path("list_dir", args)
  if not given then return bad end
  local path, allowed, reason = permit("read", given)
  if not allowed then return refused("list_dir", path, reason) end
  local handle = io.popen("ls -la -- " .. agent.shq(path) .. "/")
  if not handle then
    return { ok = false, error = "list_dir: cannot list '" .. path .. "'" }
  end
  local listing = handle:read("*a")
  handle:close()
  if listing == "" then
    return { ok = false, error = "list_dir: '" .. path .. "' is not a readable directory" }
  end
  return { ok = true, result = { content = listing } }
end

-- Create or overwrite `path` verbatim (bit-for-bit; nothing is appended).
-- The body never touches a shell: it is written straight to the file, so there
-- is no quoting of the content anywhere. Parent directories are still created —
-- the one thing stdlib cannot do — after the ask, never before.
local function write_file(args)
  local given, bad = want_path("write_file", args)
  if not given then return bad end
  local content = args.content
  if type(content) ~= "string" then
    return { ok = false, error = "write_file: 'content' must be a string, got " .. type(content) }
  end
  local path, allowed, reason = permit("write", given)
  if not allowed then return refused("write_file", path, reason) end
  local parent = path:match("^(.*)/[^/]+$")
  if parent and parent ~= "" and not io.open(parent, "r") then
    -- LuaJIT follows 5.1 here: `os.execute` returns the exit status as a plain
    -- number (0 = made), not the 5.2+ `(ok, "exit", code)` triple. Either way a
    -- nil, or anything non-zero, means the directory is not there.
    local made = os.execute("mkdir -p -- " .. agent.shq(parent))
    if made == nil or (type(made) == "number" and made ~= 0) then
      return { ok = false, error = "write_file: cannot create '" .. parent .. "'" }
    end
  end
  local handle, err = io.open(path, "wb")
  if not handle then
    return { ok = false, error = "write_file: cannot write '" .. path .. "': " .. tostring(err) }
  end
  handle:write(content)
  handle:close()
  local lines = 0
  for _ in content:gmatch("\n") do lines = lines + 1 end
  if content ~= "" and content:sub(-1) ~= "\n" then lines = lines + 1 end
  return { ok = true, result = { path = path, bytes = #content, lines = lines } }
end

-- Apply a unified diff to an existing file and show the before/after in a
-- split panel: each pane runs its own tree-sitter grammar
-- (`agent.split_panel`), added lines green, removed lines red.
--
-- The patch format the model should emit:
--
--   @@ -3,2 +3,3 @@ an optional heading
--    context line (one leading space)
--   -removed line (one leading dash)
--   +added line (one leading plus)
--
-- Hunks are matched by *exact context content*, not by line numbers or the
-- +/- counts, so those may be approximate. An insertion/deletion hunk must
-- carry surrounding unchanged context to anchor itself. The file's trailing
-- newline is preserved; CRLF files are rewritten as LF. Re-applying a patch
-- that already matches the file is a no-op.
local function apply_patch(args)
  local given, bad = want_path("apply_patch", args)
  if not given then return bad end
  local patch = args.patch
  if type(patch) ~= "string" then
    return { ok = false, error = "apply_patch: 'patch' must be a string, got " .. type(patch) }
  end
  -- One ask for the whole operation: a patch is a write to this path, and the
  -- read it needs to compute the diff is part of the same decision.
  local path, allowed, reason = permit("write", given)
  if not allowed then return refused("apply_patch", path, reason) end
  local prev = io.open(path, "rb")
  if not prev then
    return { ok = false, error = "apply_patch: '" .. path .. "' does not exist to patch" }
  end
  local before_text = prev:read("*a")
  prev:close()
  local ok, res = pcall(patch_apply, before_text, patch)
  if not ok then
    return { ok = false, error = "apply_patch: " .. tostring(res) }
  end
  local new_text = res.content
  local changed = new_text ~= before_text
  if changed then
    local handle, err = io.open(path, "wb")
    if not handle then
      return { ok = false, error = "apply_patch: cannot write '" .. path .. "': " .. tostring(err) }
    end
    handle:write(new_text)
    handle:close()
  end
  -- The before/after view: one split panel, each pane run through its own
  -- grammar, changed lines tinted red (removed) / green (added).
  local lang = lang_for(path)
  local before_lines = patch_split(before_text)
  local after_lines = patch_split(new_text)
  local p = agent.split_panel("apply_patch: " .. path, {
    { caption = "before " .. #before_lines .. " lines", lang = lang },
    { caption = "after " .. #after_lines .. " lines", lang = lang },
  })
  p:set(1, before_text)
  p:set(2, new_text)
  for _, span in ipairs(res.before_changed) do
    local a, b = line_bytes(before_lines, span[1], span[2])
    if b > a then p:highlight(1, a, b, "bold.red") end
  end
  for _, span in ipairs(res.after_changed) do
    local a, b = line_bytes(after_lines, span[1], span[2])
    if b > a then p:highlight(2, a, b, "bold.green") end
  end
  return { ok = true, result = { path = path, changed = changed,
                                 added = res.added, removed = res.removed } }
end

-- ==========================================================================
-- Registration
-- ==========================================================================

M.tools.read_file = agent.utils.tool(
  "Read a file with line numbers. The user is asked before the file is read, and \"always\" makes it stop asking.",
  {
    type = "object",
    properties = { path = { type = "string" } },
    required = { "path" },
  },
  read_file)

M.tools.list_dir = agent.utils.tool(
  "List a directory. The user is asked before the directory is read, and \"always\" makes it stop asking.",
  {
    type = "object",
    properties = { path = { type = "string" } },
    required = { "path" },
  },
  list_dir)

M.tools.write_file = agent.utils.tool(
  "Write a file verbatim, creating parent directories as needed; overwrites an existing file. The user is asked before the file is written, and \"always\" makes it stop asking. Read the file first when editing.",
  {
    type = "object",
    properties = {
      path = { type = "string", description = "File to write (directories are created)." },
      content = { type = "string", description = "Exact bytes to write; nothing is appended." },
    },
    required = { "path", "content" },
  },
  write_file)

M.tools.apply_patch = agent.utils.tool(
  "Apply a unified diff to an existing file. The user is asked before the file is written, and \"always\" makes it stop asking. patch must contain one or more hunks:\n\n  @@ -3,2 +3,3 @@ optional heading\n   context line (one leading space)\n  -removed line (one leading dash)\n  +added line (one leading plus)\n\nHunks are matched by exact context content, never by line numbers or counts, so those may be approximate. Insertion/deletion hunks must carry surrounding unchanged context to anchor themselves. The file's trailing newline is preserved; CRLF files are rewritten with LF. Re-applying a patch that already matches the file is a no-op.",
  {
    type = "object",
    properties = {
      path = { type = "string", description = "Existing file to patch." },
      patch = { type = "string", description = "Unified diff (one or more @@ hunks)." },
    },
    required = { "path", "patch" },
  },
  apply_patch)

-- The lib-module convention: a module publishes itself on the `agent` table
-- under its own name, so a sibling can reach it without requiring it again —
-- `agent.fs.tools.read_file` above, and `agent.fs.patch` for the pure diff
-- engine. (`lua/lib/` modules are auto-required by the loader; a root module
-- like this one is required by the config, so it says so itself.)
agent.fs = M

return M
