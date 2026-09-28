-- utils.lua — pure-Lua string/table transformation helpers.
--
-- A support library shipped in `lua/lib/`, auto-required by the loader, so it
-- registers itself as `agent.utils` on every VM — no require needed at the use
-- site:
--
--   agent.utils.string.snake_case("HTTPServer2")   --> "http_server2"
--   agent.utils.table.get(args, "properties.path")
--
-- It is also a normal module, so `local utils = require("utils")` gives the
-- same table (and `package.loaded.utils` is that table too):
--
--   local str, tbl = require("utils").string, require("utils").table
--
--   str.snake_case("HTTPServer2")      --> "http_server2"
--   str.wrap(long_text, 72)            --> array of wrapped lines
--   tbl.group_by(users, u.role)        --> { admin = {...}, dev = {...} }
--
-- The library itself is otherwise dependency-free: no I/O, no `agent.*` use
-- beyond the one registration below — every function either returns a new
-- value or (where noted) mutates its argument by design.
--
-- Design rules:
--   * pure: inputs are never mutated. The one deliberate exception is
--     `utils.table.set` / `utils.table.unset`, which write through a path.
--   * 1-based, like Lua. Byte-oriented unless a function says "chars"
--     (`char_count`, `chars`, `truncate` are UTF-8 aware).
--   * LuaJIT / Lua 5.1 compatible: no `goto`, no `//`, no `table.unpack`
--     (the `unpack` global is used when present).
--   * `string` arguments accept numbers (coerced); anything else raises a
--     `utils.*: expected a string or number, got <type>` error. `nil`-safe
--     variants exist where the name implies one (`is_empty`, `is_blank`).
--
-- Section layout:
--   utils.string   text transformations        (below)
--   utils.table    table/list transformations  (bottom of the file)
--   utils.tool     the callable tool object    (just above the self-test)

local M = {}
M.version = "0.1.0"

-- --------------------------------------------------------------------------
-- Internals
-- --------------------------------------------------------------------------

local unpack = unpack or table.unpack

-- Coerce strings/numbers to text; anything else is an error naming the
-- caller's type. Level 3 so the trace points at the user's call site.
local function text(s)
  local t = type(s)
  if t == "string" then return s end
  if t == "number" then return tostring(s) end
  error("utils: expected a string or number, got " .. t, 3)
end

local function require_table(t, name)
  if type(t) ~= "table" then
    error("utils.table." .. name .. ": expected a table, got " .. type(t), 3)
  end
  return t
end

local function require_fn(fn, name)
  if type(fn) ~= "function" then
    error("utils.table." .. name .. ": expected a function, got " .. type(fn), 3)
  end
  return fn
end

-- Escape a string so it is a case-sensitive literal pattern for any
-- `string.find/gsub/match` (the `plain` mode many helpers take uses this).
local function escape_pattern(s)
  return (s:gsub("([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1"))
end

-- Byte length of the UTF-8 code point whose lead byte is `cc`; degenerate
-- bytes are treated as one byte so malformed input never stalls the walker.
local function utf8_byte_len(cc)
  if cc == nil then return 0 end
  if cc < 0x80 then return 1 end
  if cc < 0xE0 then return 2 end
  if cc < 0xF0 then return 3 end
  if cc < 0xF8 then return 4 end
  return 1
end

-- Walk `s` UTF-8 code point by code point, calling `fn(c)` with each char.
local function utf8_walk(s, fn)
  local i, n = 1, #s
  while i <= n do
    local len = utf8_byte_len(s:byte(i))
    fn(s:sub(i, i + len - 1))
    i = i + len
  end
end

-- Split on "\n", keeping lines intact: `"a\nb\n"` -> {"a","b"} (a single
-- trailing newline is not a trailing empty line), `""` -> {""}.
local function split_lines(s)
  if s == "" then return { "" } end
  local out, from = {}, 1
  while true do
    local nl = s:find("\n", from, true)
    if not nl then
      out[#out + 1] = s:sub(from)
      return out
    end
    out[#out + 1] = s:sub(from, nl - 1)
    from = nl + 1
    if from > #s then return out end -- trailing newline: no empty tail line
  end
end

-- Split on a literal separator (plain) or a pattern. `keep_empty` controls
-- whether empties produced by leading/trailing/consecutive separators are
-- kept.
local function split_plain(s, sep, keep_empty)
  local out, from = {}, 1
  while true do
    local a, b = s:find(sep, from, true)
    if not a then break end
    if keep_empty or a > from then out[#out + 1] = s:sub(from, a - 1) end
    from = b + 1
  end
  local tail = s:sub(from)
  if keep_empty or tail ~= "" then out[#out + 1] = tail end
  return out
end

local function split_pattern(s, sep, keep_empty)
  local out, from = {}, 1
  while true do
    local a, b = s:find(sep, from)
    if not a then break end
    if keep_empty or a > from then out[#out + 1] = s:sub(from, a - 1) end
    from = b + 1
  end
  local tail = s:sub(from)
  if keep_empty or tail ~= "" then out[#out + 1] = tail end
  return out
end

-- ==========================================================================
-- utils.string
-- ==========================================================================

local str = {}

-- Strip leading whitespace (default) — or any characters given as a plain
-- set, e.g. `trim(s, "\t,;")`.
function str.trim(s, chars)
  s = text(s)
  if chars == nil then
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
  end
  chars = escape_pattern(text(chars))
  return (s:gsub("^[" .. chars .. "]*", ""):gsub("[" .. chars .. "]*$", ""))
end

function str.trim_left(s, chars)
  s = text(s)
  if chars == nil then return (s:gsub("^%s+", "")) end
  chars = escape_pattern(text(chars))
  return (s:gsub("^[" .. chars .. "]*", ""))
end

function str.trim_right(s, chars)
  s = text(s)
  if chars == nil then return (s:gsub("%s+$", "")) end
  chars = escape_pattern(text(chars))
  return (s:gsub("[" .. chars .. "]*$", ""))
end

-- nil-safe; numbers count as non-empty.
function str.is_empty(s)
  return s == nil or s == ""
end

-- nil, "", or whitespace-only.
function str.is_blank(s)
  if s == nil then return true end
  s = text(s)
  return not s:find("%S")
end

-- Split `s` into an array.
--   split("a,b,c", ",")                -- pattern separator
--   split("a,b,c", ",", { plain = true }) -- literal separator
--   split("a,,b",  ",", { keep_empty = true }) -- keeps the middle ""
--   split("  a  b ", nil)              -- nil sep: runs of whitespace
--   split("héllo", "")                 -- "" sep: UTF-8 code points
-- Pattern captures in `sep` are ignored; avoid zero-width patterns other
-- than "" (they would slice per byte).
function str.split(s, sep, opts)
  s = text(s)
  opts = opts or {}
  if sep == nil then
    local out = {}
    for w in s:gmatch("%S+") do out[#out + 1] = w end
    return out
  end
  sep = text(sep)
  if sep == "" then return str.chars(s) end
  if opts.plain then return split_plain(s, sep, opts.keep_empty) end
  return split_pattern(s, sep, opts.keep_empty)
end

-- Split into lines. Default strips a trailing "\r" (CRLF-friendly); pass
-- `{ strip_cr = false }` to keep bytes intact.
function str.lines(s, opts)
  s = text(s)
  opts = opts or {}
  local out = split_lines(s)
  if opts.strip_cr ~= false then
    for i, l in ipairs(out) do out[i] = (l:gsub("\r$", "")) end
  end
  return out
end

-- Join an array of strings/numbers with `sep` (default "").
function str.join(parts, sep)
  if type(parts) ~= "table" then
    error("utils.string.join: expected an array, got " .. type(parts), 2)
  end
  sep = sep or ""
  local out, n = {}, #parts
  for i = 1, n do
    local v, t = parts[i], type(parts[i])
    if t ~= "string" and t ~= "number" then
      error("utils.string.join: element " .. i .. " is a " .. t ..
            ", expected string/number", 2)
    end
    out[i] = tostring(v)
  end
  return table.concat(out, sep)
end

function str.contains(s, needle, plain)
  s = text(s)
  needle = text(needle)
  if plain then return s:find(needle, 1, true) ~= nil end
  return s:find(needle) ~= nil
end

function str.starts_with(s, prefix)
  s = text(s)
  prefix = text(prefix)
  return s:sub(1, #prefix) == prefix
end

function str.ends_with(s, suffix)
  s = text(s)
  suffix = text(suffix)
  if #suffix > #s then return false end
  return s:sub(#s - #suffix + 1) == suffix
end

-- Number of non-overlapping matches of `pattern` (or of the literal
-- `pattern` when `plain` is true).
function str.count(s, pattern, plain)
  s = text(s)
  pattern = text(pattern)
  if plain then pattern = escape_pattern(pattern) end
  local _, n = s:gsub(pattern, "")
  return n
end

-- Same as string.find: start, finish (byte offsets, 1-based), or nil.
function str.find(s, pattern, plain)
  s = text(s)
  pattern = text(pattern)
  if plain then return s:find(pattern, 1, true) end
  return s:find(pattern)
end

-- The text of the first match, or nil (unlike `find` which returns offsets).
function str.first(s, pattern, plain)
  local a, b = str.find(s, pattern, plain)
  if not a then return nil end
  return text(s):sub(a, b)
end

-- Replace *every* occurrence of `from`. `plain` treats `from` literally
-- (and escapes `to`); otherwise both are Lua patterns, with gsub's usual
-- `%1`-style captures available in `to`.
function str.replace(s, from, to, plain)
  s = text(s)
  from = text(from)
  to = tostring(to)
  if plain then
    from = escape_pattern(from)
    to = to:gsub("%%", "%%%%")
  end
  return (s:gsub(from, to))
end

function str.lower(s)
  return text(s):lower()
end

function str.upper(s)
  return text(s):upper()
end

-- Alias: expose the escape helper for building your own patterns.
function str.escape(pattern)
  return escape_pattern(text(pattern))
end

-- The string as an array of UTF-8 code points.
function str.chars(s)
  s = text(s)
  local out = {}
  utf8_walk(s, function(c) out[#out + 1] = c end)
  return out
end

-- Number of UTF-8 code points (best-effort; malformed bytes count as one).
function str.char_count(s)
  s = text(s)
  local n = 0
  utf8_walk(s, function() n = n + 1 end)
  return n
end

function str.byte_length(s)
  return #text(s)
end

-- Byte substring, 1-based; negative indices count from the end
-- (slice(s, -3) = last 3 bytes), nil `to` = to the end.
function str.slice(s, from, to)
  s = text(s)
  if from < 0 then from = #s + from + 1 end
  if to == nil then to = #s elseif to < 0 then to = #s + to + 1 end
  if from > to or from > #s then return "" end
  return s:sub(from, math.min(to, #s))
end

-- Pad to `n` bytes with `ch` (default " ") on the right / left / both
-- (center; extra space goes right).
function str.pad_right(s, n, ch)
  s = text(s)
  ch = ch or " "
  local add = n - #s
  if add <= 0 then return s end
  return s .. string.rep(ch, add)
end

function str.pad_left(s, n, ch)
  s = text(s)
  ch = ch or " "
  local add = n - #s
  if add <= 0 then return s end
  return string.rep(ch, add) .. s
end

function str.pad(s, n, ch)
  s = text(s)
  ch = ch or " "
  local add = n - #s
  if add <= 0 then return s end
  local left = math.floor(add / 2)
  return string.rep(ch, left) .. s .. string.rep(ch, add - left)
end

-- Cut `s` to the first `n` UTF-8 chars, appending `suffix` ("…") only when
-- it was truncated.
function str.truncate(s, n, suffix)
  s = text(s)
  n = n or 80
  if n < 0 then n = 0 end
  suffix = suffix or "…"
  if str.char_count(s) <= n then return s end
  local cut = n - str.char_count(suffix)
  if cut < 0 then cut = 0 end
  local out, i, got = {}, 1, 0
  while i <= #s and got < cut do
    local len = utf8_byte_len(s:byte(i))
    out[#out + 1] = s:sub(i, i + len - 1)
    i = i + len
    got = got + 1
  end
  return table.concat(out) .. suffix
end

-- Prefix every line with `n` copies of `ch` (default " "). Blank lines are
-- indented too, so the shape is preserved.
function str.indent(s, n, ch)
  s = text(s)
  n = n or 2
  ch = ch or " "
  local pad = string.rep(ch, n)
  local out = {}
  for _, l in ipairs(split_lines(s)) do out[#out + 1] = pad .. l end
  return table.concat(out, "\n")
end

-- Remove the common leading whitespace across non-blank lines (a
-- "strip-margin" style helper for heredocs written at a deeper indent).
function str.dedent(s)
  s = text(s)
  local lines = split_lines(s)
  local min = math.huge
  for _, l in ipairs(lines) do
    if l:match("%S") then
      min = math.min(min, #(l:match("^%s*")))
    end
  end
  if min == math.huge then min = 0 end
  local out = {}
  for _, l in ipairs(lines) do out[#out + 1] = l:sub(min + 1) end
  return table.concat(out, "\n")
end

-- Word-wrap `s` to `width` columns (default 80). Existing newlines are hard
-- breaks; overlong words are split. Returns an array of lines.
function str.wrap(s, width)
  s = text(s)
  width = width or 80
  if width < 1 then width = 1 end
  local out = {}
  for _, raw in ipairs(split_lines(s)) do
    local cur = ""
    for word in raw:gmatch("%S+") do
      local sep = (cur == "") and "" or " "
      if #cur + #sep + #word > width then
        if cur ~= "" then out[#out + 1] = cur end
        local rest = word
        while #rest > width do
          out[#out + 1] = rest:sub(1, width)
          rest = rest:sub(width + 1)
        end
        cur = rest
      else
        cur = cur .. sep .. word
      end
    end
    out[#out + 1] = cur
  end
  return out
end

-- Strip one trailing newline ("\n" or "\r\n").
function str.chomp(s)
  return (text(s):gsub("\r?\n$", ""))
end

-- Collapse every run of whitespace (including newlines) into a single
-- space, trimmed at both ends.
function str.normalize_ws(s)
  s = text(s):gsub("%s+", " ")
  return (s:gsub("^ ", ""):gsub(" $", ""))
end

-- --------------------------------------------------------------------------
-- Word / case conversions. Words are alpha-numeric runs; boundaries split on
-- non-alphanumerics and on camel/acronym edges:
--   "HTTPServer2" -> {"http","server2"}     "camelCase" -> {"camel","case"}
--   "kebab-case"  -> {"kebab","case"}       "v2.4"      -> {"v2","4"}
-- --------------------------------------------------------------------------

local function case_words(s)
  local words, buf = {}, {}
  local function flush()
    if #buf > 0 then words[#words + 1] = table.concat(buf):lower() end
    buf = {}
  end
  local n = #s
  for i = 1, n do
    local c = s:sub(i, i)
    if c:match("%a") or c:match("%d") then
      if #buf > 0 then
        local last = buf[#buf]
        local last_up = last:match("%u") ~= nil
        local up = c:match("%u") ~= nil
        if not last_up and up then
          flush() -- camelCase: lower/digit followed by Upper
        elseif last_up and not up and c:match("%a") and #buf >= 2 then
          -- Acronym run dissolving into a word ("HTTPServer" -> "HTTP"
          -- "Server"): keep the run's *last* upper with the lower tail.
          local prev = buf[#buf - 1]
          if prev:match("%u") then
            local last_c = table.remove(buf)
            flush()
            buf[#buf + 1] = last_c
          end
        end
      end
      buf[#buf + 1] = c
    else
      flush()
    end
  end
  flush()
  return words
end

local function capitalize(w)
  return w:sub(1, 1):upper() .. w:sub(2)
end

function str.words(s)
  return case_words(text(s))
end

function str.snake_case(s)
  return table.concat(case_words(text(s)), "_")
end

function str.kebab_case(s)
  return table.concat(case_words(text(s)), "-")
end

function str.screaming_snake(s)
  return table.concat(case_words(text(s)), "_"):upper()
end

function str.camel_case(s)
  local w = case_words(text(s))
  for i = 2, #w do w[i] = capitalize(w[i]) end
  return table.concat(w)
end

function str.pascal_case(s)
  local w = case_words(text(s))
  for i = 1, #w do w[i] = capitalize(w[i]) end
  return table.concat(w)
end

function str.title_case(s)
  local w = case_words(text(s))
  for i = 1, #w do w[i] = capitalize(w[i]) end
  return table.concat(w, " ")
end

-- Alphanumerics joined with "-" (identical to kebab_case; kept as a
-- dedicated name for url/path slugs).
function str.slugify(s)
  return table.concat(case_words(text(s)), "-")
end

-- ==========================================================================
-- utils.table
-- ==========================================================================

local tbl = {}

function tbl.is_empty(t)
  return type(t) ~= "table" or next(t) == nil
end

-- True when `t` is a contiguous 1..n array (holes and stray keys make it
-- false).
function tbl.is_array(t)
  if type(t) ~= "table" then return false end
  local n = #t
  for i = 1, n do if t[i] == nil then return false end end
  for k in pairs(t) do
    if type(k) ~= "number" or k % 1 ~= 0 or k < 1 or k > n then return false end
  end
  return true
end

-- `pairs`-driven; order is unspecified for dictionaries.
function tbl.keys(t)
  require_table(t, "keys")
  local out = {}
  for k in pairs(t) do out[#out + 1] = k end
  return out
end

function tbl.values(t)
  require_table(t, "values")
  local out = {}
  for _, v in pairs(t) do out[#out + 1] = v end
  return out
end

function tbl.each(t, fn)
  require_table(t, "each")
  require_fn(fn, "each")
  for k, v in pairs(t) do fn(v, k) end
  return t
end

-- Array transforms below operate on the contiguous 1..n part (ipairs).

-- Map fn(v, i) over an array, preserving positions.
function tbl.map(t, fn)
  require_table(t, "map")
  require_fn(fn, "map")
  local out = {}
  for i, v in ipairs(t) do out[i] = fn(v, i) end
  return out
end

-- Map over a dictionary, keeping keys: fn(v, k) -> new value.
function tbl.map_values(t, fn)
  require_table(t, "map_values")
  require_fn(fn, "map_values")
  local out = {}
  for k, v in pairs(t) do out[k] = fn(v, k) end
  return out
end

function tbl.filter(t, fn)
  require_table(t, "filter")
  require_fn(fn, "filter")
  local out = {}
  for i, v in ipairs(t) do if fn(v, i) then out[#out + 1] = v end end
  return out
end

-- Keep entries whose value passes fn(v, k).
function tbl.filter_values(t, fn)
  require_table(t, "filter_values")
  require_fn(fn, "filter_values")
  local out = {}
  for k, v in pairs(t) do if fn(v, k) then out[k] = v end end
  return out
end

-- foldl: `reduce(t, fn, init)` starts from init; without an init the first
-- element seeds the accumulator.
function tbl.reduce(t, fn, init)
  require_table(t, "reduce")
  require_fn(fn, "reduce")
  local acc, started = init, init ~= nil
  for i, v in ipairs(t) do
    if started then acc = fn(acc, v, i) else acc, started = v, true end
  end
  return acc
end

function tbl.some(t, fn)
  require_table(t, "some")
  require_fn(fn, "some")
  for i, v in ipairs(t) do if fn(v, i) then return true end end
  return false
end

function tbl.every(t, fn)
  require_table(t, "every")
  require_fn(fn, "every")
  for i, v in ipairs(t) do if not fn(v, i) then return false end end
  return true
end

function tbl.none(t, fn)
  return not tbl.some(t, fn)
end

-- First element passing fn(v, i) (or nil).
function tbl.find(t, fn)
  require_table(t, "find")
  require_fn(fn, "find")
  for i, v in ipairs(t) do if fn(v, i) then return v end end
  return nil
end

-- Index of the first element passing fn (or nil).
function tbl.find_index(t, fn)
  require_table(t, "find_index")
  require_fn(fn, "find_index")
  for i, v in ipairs(t) do if fn(v, i) then return i end end
  return nil
end

-- First index whose value is exactly `value` (raw equality), or nil.
function tbl.index_of(t, value)
  require_table(t, "index_of")
  for i, v in ipairs(t) do if v == value then return i end end
  return nil
end

function tbl.contains(t, value)
  return tbl.index_of(t, value) ~= nil
end

-- Alias for `utils.string.join` over the array's values.
function tbl.join(t, sep)
  return str.join(t, sep)
end

function tbl.first(t)
  return t[1]
end

function tbl.last(t)
  return t[#t]
end

function tbl.take(t, n)
  require_table(t, "take")
  n = n or 1
  local out = {}
  for i = 1, math.min(n, #t) do out[i] = t[i] end
  return out
end

function tbl.drop(t, n)
  require_table(t, "drop")
  n = n or 1
  local out = {}
  for i = n + 1, #t do out[#out + 1] = t[i] end
  return out
end

-- New array, first element's index after `from` (1-based; negative from the
-- end), inclusive `to` (nil = end).
function tbl.slice(t, from, to)
  require_table(t, "slice")
  local n = #t
  if from < 0 then from = n + from + 1 end
  if to == nil then to = n elseif to < 0 then to = n + to + 1 end
  local out = {}
  if from > to then return out end
  for i = from, math.min(to, n) do out[#out + 1] = t[i] end
  return out
end

function tbl.reverse(t)
  require_table(t, "reverse")
  local out = {}
  for i = #t, 1, -1 do out[#out + 1] = t[i] end
  return out
end

-- First-occurrence dedupe (raw equality).
function tbl.unique(t)
  require_table(t, "unique")
  local seen, out = {}, {}
  for _, v in ipairs(t) do
    if seen[v] == nil then seen[v] = true out[#out + 1] = v end
  end
  return out
end

-- Dedupe by a key function: fn(v, i) -> key.
function tbl.uniq_by(t, fn)
  require_table(t, "uniq_by")
  require_fn(fn, "uniq_by")
  local seen, out = {}, {}
  for i, v in ipairs(t) do
    local k = fn(v, i)
    if seen[k] == nil then seen[k] = true out[#out + 1] = v end
  end
  return out
end

-- A *new* array sorted by fn(v, i) (stable — equal keys keep input order;
-- keys must all be comparable, e.g. numbers or strings). opts.desc = true
-- reverses. The input is never mutated.
function tbl.sort_by(t, key_fn, opts)
  require_table(t, "sort_by")
  key_fn = key_fn or function(v) return v end
  require_fn(key_fn, "sort_by")
  local items = {}
  for i, v in ipairs(t) do items[#items + 1] = { i = i, v = v, k = key_fn(v, i) } end
  table.sort(items, function(a, b)
    if a.k ~= b.k then
      if opts and opts.desc then return a.k > b.k end
      return a.k < b.k
    end
    return a.i < b.i
  end)
  local out = {}
  for i, it in ipairs(items) do out[i] = it.v end
  return out
end

-- The element maximizing / minimizing fn(v, i) (first wins ties).
function tbl.max_by(t, fn)
  require_table(t, "max_by")
  require_fn(fn, "max_by")
  local best, best_k
  for i, v in ipairs(t) do
    local k = fn(v, i)
    if best_k == nil or k > best_k then best, best_k = v, k end
  end
  return best
end

function tbl.min_by(t, fn)
  require_table(t, "min_by")
  require_fn(fn, "min_by")
  local best, best_k
  for i, v in ipairs(t) do
    local k = fn(v, i)
    if best_k == nil or k < best_k then best, best_k = v, k end
  end
  return best
end

function tbl.sum(t)
  require_table(t, "sum")
  local acc = 0
  for _, v in ipairs(t) do acc = acc + v end
  return acc
end

-- { key = { elements in order } }.
function tbl.group_by(t, fn)
  require_table(t, "group_by")
  require_fn(fn, "group_by")
  local out = {}
  for i, v in ipairs(t) do
    local k = fn(v, i)
    local g = out[k]
    if g == nil then g = {} out[k] = g end
    g[#g + 1] = v
  end
  return out
end

-- { key = element } (later wins).
function tbl.index_by(t, fn)
  require_table(t, "index_by")
  require_fn(fn, "index_by")
  local out = {}
  for i, v in ipairs(t) do out[fn(v, i)] = v end
  return out
end

-- { key = count }.
function tbl.count_by(t, fn)
  require_table(t, "count_by")
  require_fn(fn, "count_by")
  local out = {}
  for i, v in ipairs(t) do
    local k = fn(v, i)
    out[k] = (out[k] or 0) + 1
  end
  return out
end

-- Flatten one level (nested arrays spliced; non-tables passed through).
function tbl.flatten(t)
  require_table(t, "flatten")
  local out = {}
  for _, v in ipairs(t) do
    if type(v) == "table" then
      for _, x in ipairs(v) do out[#out + 1] = x end
    else
      out[#out + 1] = v
    end
  end
  return out
end

function tbl.flatten_deep(t)
  require_table(t, "flatten_deep")
  local out = {}
  local function walk(x, depth)
    if depth > 64 then error("utils.table.flatten_deep: deeper than 64 levels", 2) end
    if type(x) == "table" then
      for _, v in ipairs(x) do walk(v, depth + 1) end
    else
      out[#out + 1] = x
    end
  end
  walk(t, 0)
  return out
end

-- Zip arrays into rows: zip(a, b) -> { {a1,b1}, {a2,b2}, … } (shortest
-- length wins).
function tbl.zip(...)
  local n = select("#", ...)
  local lists = {}
  for i = 1, n do lists[i] = select(i, ...) end
  local len = math.huge
  for i = 1, n do
    if type(lists[i]) ~= "table" then
      error("utils.table.zip: argument " .. i .. " is not a table", 2)
    end
    len = math.min(len, #lists[i])
  end
  local out = {}
  for i = 1, len do
    local row = {}
    for j = 1, n do row[j] = lists[j][i] end
    out[i] = row
  end
  return out
end

-- Split an array into chunks of at most `n`.
function tbl.chunk(t, n)
  require_table(t, "chunk")
  n = n or 1
  local out = {}
  for i = 1, #t, n do
    local c = {}
    for j = i, math.min(i + n - 1, #t) do c[#c + 1] = t[j] end
    out[#out + 1] = c
  end
  return out
end

-- Shallow copy (keys preserved).
function tbl.copy(t)
  require_table(t, "copy")
  local out = {}
  for k, v in pairs(t) do out[k] = v end
  return out
end

-- Recursive copy; arrays stay arrays. Cycles are not supported (a depth cap
-- bounds runaway instead of hanging).
function tbl.deep_copy(t)
  require_table(t, "deep_copy")
  local function dc(x, depth)
    if type(x) ~= "table" then return x end
    if depth > 64 then error("utils.table.deep_copy: deeper than 64 levels", 2) end
    local out = {}
    for k, v in pairs(x) do
      out[dc(k, depth + 1)] = dc(v, depth + 1)
    end
    return out
  end
  return dc(t, 0)
end

-- Recursive structural equality (no metatables, no cycles — depth capped).
function tbl.deep_equal(a, b)
  local function de(x, y, depth)
    if x == y then return true end
    if type(x) ~= "table" or type(y) ~= "table" then return false end
    if depth > 64 then return false end
    for k, v in pairs(x) do
      if y[k] == nil or not de(v, y[k], depth + 1) then return false end
    end
    for k in pairs(y) do
      if x[k] == nil then return false end
    end
    return true
  end
  return de(a, b, 0)
end

-- Shallow merge of any number of tables (later wins); returns a new table.
function tbl.merge(...)
  local out = {}
  for i = 1, select("#", ...) do
    local t = select(i, ...)
    if type(t) ~= "table" then
      error("utils.table.merge: argument " .. i .. " is not a table", 2)
    end
    for k, v in pairs(t) do out[k] = v end
  end
  return out
end

-- Recursive merge: nested tables merge recursively; everything else is
-- replaced (later wins).
function tbl.deep_merge(...)
  local out = {}
  local function merge_into(dst, src)
    for k, v in pairs(src) do
      local dv = dst[k]
      if type(v) == "table" and type(dv) == "table" then
        merge_into(dv, v)
      else
        dst[k] = v
      end
    end
  end
  for i = 1, select("#", ...) do
    local t = select(i, ...)
    if type(t) ~= "table" then
      error("utils.table.deep_merge: argument " .. i .. " is not a table", 2)
    end
    merge_into(out, t)
  end
  return out
end

-- Fill gaps from `fallback` (a new table; `t` wins where present).
function tbl.defaults(t, fallback)
  require_table(t, "defaults")
  require_table(fallback, "defaults")
  local out = {}
  for k, v in pairs(fallback) do out[k] = v end
  for k, v in pairs(t) do out[k] = v end
  return out
end

-- --------------------------------------------------------------------------
-- Path access. A path is an array of keys or a dotted string that also
-- accepts numeric bracket suffixes: "a.b[2].name" == {"a","b",2,"name"}.
-- --------------------------------------------------------------------------

local function path_parts(path)
  if type(path) == "table" then return path end
  if type(path) ~= "string" then
    error("utils.table: path must be an array or a dotted string, got " ..
          type(path), 3)
  end
  local parts = {}
  for p in (path:gsub("%[(%d+)%]", ".%1")):gmatch("[^%.]+") do
    local num = tonumber(p)
    parts[#parts + 1] = num or p
  end
  return parts
end

local MISSING = {} -- sentinel: distinguishes "nil value" from "absent"

local function resolve(t, path)
  local node = t
  for _, p in ipairs(path_parts(path)) do
    if type(node) ~= "table" then return MISSING end
    node = node[p]
    if node == nil then return MISSING end
  end
  return node
end

-- The value at `path`, or nil when absent (or explicitly nil).
function tbl.get(t, path)
  require_table(t, "get")
  local v = resolve(t, path)
  if v == MISSING then return nil end
  return v
end

-- The value at `path`, or `default` when absent.
function tbl.get_or(t, path, default)
  require_table(t, "get_or")
  local v = resolve(t, path)
  if v == MISSING then return default end
  return v
end

function tbl.has(t, path)
  require_table(t, "has")
  return resolve(t, path) ~= MISSING
end

-- Write `value` at `path`, creating intermediate tables as needed. Mutates
-- and returns `t` (the one deliberate mutation, so it chains).
function tbl.set(t, path, value)
  require_table(t, "set")
  local parts = path_parts(path)
  local node = t
  for i = 1, #parts - 1 do
    local p = parts[i]
    local child = node[p]
    if type(child) ~= "table" then child = {} node[p] = child end
    node = child
  end
  node[parts[#parts]] = value
  return t
end

-- Remove the key at `path` (no-op when absent). Mutates and returns `t`.
function tbl.unset(t, path)
  require_table(t, "unset")
  local parts = path_parts(path)
  local node = t
  for i = 1, #parts - 1 do
    if type(node) ~= "table" then return t end
    node = node[parts[i]]
  end
  if type(node) == "table" then node[parts[#parts]] = nil end
  return t
end

-- --------------------------------------------------------------------------
-- Selection / reshaping
-- --------------------------------------------------------------------------

-- Pick listed keys (an array, or varargs) into a new table. nil-valued keys
-- are dropped.
function tbl.pick(t, ...)
  require_table(t, "pick")
  local n = select("#", ...)
  local first = ...
  local keys = (n == 1 and type(first) == "table") and first or { ... }
  local out = {}
  for _, k in ipairs(keys) do if t[k] ~= nil then out[k] = t[k] end end
  return out
end

-- Everything except the listed keys (an array, or varargs).
function tbl.omit(t, ...)
  require_table(t, "omit")
  local n = select("#", ...)
  local first = ...
  local drop = {}
  if n == 1 and type(first) == "table" then
    for _, k in ipairs(first) do drop[k] = true end
  else
    for i = 1, n do drop[select(i, ...)] = true end
  end
  local out = {}
  for k, v in pairs(t) do if not drop[k] then out[k] = v end end
  return out
end

-- Copy with key `old` moved to `new` (old is dropped).
function tbl.rename(t, old, new)
  require_table(t, "rename")
  local out = {}
  for k, v in pairs(t) do
    if k == old then out[new] = v else out[k] = v end
  end
  return out
end

-- The entries as an array of { key, value } pairs (a `pairs`-ordered list).
function tbl.to_list(t)
  require_table(t, "to_list")
  local out = {}
  for k, v in pairs(t) do out[#out + 1] = { k, v } end
  return out
end

-- Inverse of `to_list`: array of { key, value } pairs back into a table.
function tbl.from_pairs(list)
  require_table(list, "from_pairs")
  local out = {}
  for _, p in ipairs(list) do
    if type(p) ~= "table" or p[1] == nil then
      error("utils.table.from_pairs: entry " .. _ .. " is not a { key, value } pair", 2)
    end
    out[p[1]] = p[2]
  end
  return out
end

-- Pack varargs into a 1-based array (a `table.pack` stand-in that keeps
-- nils).
function tbl.array(...)
  local out = {}
  for i = 1, select("#", ...) do out[i] = select(i, ...) end
  return out
end

-- The `unpack` global (or table.unpack, when it exists) behind one name.
function tbl.unpack_items(t, i, j)
  return unpack(t, i, j)
end

M.string = str
M.table = tbl

-- ==========================================================================
-- `utils.tool` — the callable tool object
-- ==========================================================================
--
-- The one thing in this file that is not a string or table transformation, and
-- the reason it lives here anyway: it is the smallest, most dependency-free piece
-- of the tool system — a constructor that wraps a description, a schema and a
-- callback into the shape `agent.mcp` produces and Rust reindexes. It belongs to
-- no other module (there is no tool registry, no policy, no transport in it), and
-- every connection needs it, so it sits with the other general-purpose helpers.

-- A callable tool object in the shape `agent.mcp` produces: a table with
-- description / signature / callback. `callback(args)` returns the
-- MCP-shaped `{ ok, result, error, denied }` (or `false` to deny).
--
-- Register one by putting it in a connection's `tools` table — that is the
-- whole registry Rust reindexes per request:
--
--   local conn = { name = "my-tools", tools = {} }
--   conn.tools.read = agent.utils.tool("Read a file.", schema, function(args) ... end)
--   agent.mcps["my-tools"] = conn
function M.tool(description, inputSchema, callback)
  local tool = {
    description = description,
    signature = inputSchema,
    callback = callback,
  }
  setmetatable(tool, {
    __call = function(_, args)
      local r = tool.callback(args)
      if r == false then
        return { ok = false, denied = true,
                 error = "tool denied by its callback" }
      end
      return r
    end,
  })
  return tool
end

-- The lib-module convention: a module in `lua/lib/` publishes itself on the
-- `agent` table under its own name. The loader auto-requires every lib module
-- on every VM, so this line alone makes `agent.utils` available everywhere —
-- and `lib/<name>.lua` -> `agent.<name>` is the shape every other module here
-- --------------------------------------------------------------------------
-- Self-test: `utils._selftest()` returns true, raising on any failure.
-- Kept tiny on purpose — the interesting edges (case splitting, paths,
-- deep copy) are the ones most likely to rot.
-- --------------------------------------------------------------------------

function M._selftest()
  local str, tbl = M.string, M.table
  local eq = tbl.deep_equal

  assert(str.trim("  hi  ") == "hi")
  assert(str.trim(";;hi;;", ";") == "hi")
  assert(str.is_blank(" \n\t ") and str.is_empty(nil))
  assert(eq(str.split("a,b,c", ","), { "a", "b", "c" }))
  assert(eq(str.split("a,b,c", ",", { plain = true }), { "a", "b", "c" }))
  assert(eq(str.split("a,,b", ",", { keep_empty = true }), { "a", "", "b" }))
  assert(eq(str.split("  a  b ", nil), { "a", "b" }))
  assert(eq(str.split("héllo", ""), { "h", "é", "l", "l", "o" }))
  assert(eq(str.lines("a\r\nb\n"), { "a", "b" }))
  assert(str.join({ "a", 1, "b" }, "-") == "a-1-b")
  assert(str.starts_with("fetch", "fe") and str.ends_with("fetch", "ch"))
  assert(str.count("aaabaaa", "a+") == 2)
  assert(str.replace("a.b.c", ".", "/", true) == "a/b/c")
  assert(str.char_count("héllo") == 5)
  assert(str.truncate("abcdef", 4) == "abc…")
  assert(str.dedent("  a\n  b\n") == "a\nb")
  assert(eq(str.wrap("aaa bbb ccc", 7), { "aaa bbb", "ccc" }))
  assert(str.chomp("hi\n") == "hi" and str.chomp("hi") == "hi")
  assert(str.normalize_ws("  a  \n  b ") == "a b")

  assert(str.snake_case("HTTPServer2") == "http_server2", "acronym + digit")
  assert(str.snake_case("camelCase") == "camel_case")
  assert(str.snake_case("kebab-case") == "kebab_case")
  assert(str.pascal_case("hello world") == "HelloWorld")
  assert(str.camel_case("hello_world") == "helloWorld")

  local t = { 1, 2, 3, 4 }
  assert(eq(tbl.map(t, function(v) return v * 2 end), { 2, 4, 6, 8 }))
  assert(eq(tbl.filter(t, function(v) return v % 2 == 0 end), { 2, 4 }))
  assert(tbl.reduce(t, function(a, v) return a + v end) == 10)
  assert(tbl.some(t, function(v) return v > 3 end))
  assert(not tbl.every(t, function(v) return v < 4 end))
  assert(tbl.find(t, function(v) return v == 3 end) == 3)
  assert(tbl.index_of(t, 3) == 3 and tbl.contains(t, 3))
  assert(eq(tbl.reverse(t), { 4, 3, 2, 1 }))
  assert(eq(tbl.unique({ 1, 2, 1, 3 }), { 1, 2, 3 }))
  assert(eq(tbl.sort_by({ "ccc", "a", "bb" }, function(v) return #v end),
            { "a", "bb", "ccc" }))
  assert(eq(tbl.group_by({ 1, 2, 3, 4 }, function(v) return v % 2 end),
            { [0] = { 2, 4 }, [1] = { 1, 3 } }))
  assert(eq(tbl.chunk({ 1, 2, 3, 4, 5 }, 2), { { 1, 2 }, { 3, 4 }, { 5 } }))
  assert(eq(tbl.zip({ 1, 2 }, { "a", "b" }), { { 1, "a" }, { 2, "b" } }))
  assert(tbl.deep_equal(tbl.deep_copy(t), t))
  assert(eq(tbl.merge({ a = 1 }, { a = 2, b = 3 }), { a = 2, b = 3 }))
  assert(tbl.deep_equal(tbl.deep_merge({ a = { x = 1 } }, { a = { y = 2 } }),
                        { a = { x = 1, y = 2 } }))

  local cfg = { server = { host = "h", port = 8080, tags = { "x", "y" } } }
  assert(tbl.get(cfg, "server.port") == 8080)
  assert(tbl.get(cfg, "server.tags[2]") == "y")
  assert(tbl.get(cfg, "server.missing") == nil)
  assert(tbl.get_or(cfg, "server.x", 5) == 5)
  assert(tbl.has(cfg, "server.host"))
  local p = tbl.set({}, "a.b.c", 42)
  assert(p.a.b.c == 42 and tbl.get(p, "a.b.c") == 42)
  tbl.unset(p, "a.b.c")
  assert(tbl.get(p, "a.b.c") == nil)
  assert(eq(tbl.pick(cfg, { "server" }), { server = cfg.server }))
  assert(eq(tbl.omit(cfg, "server"), {}))
  assert(eq(tbl.rename({ a = 1 }, "a", "b"), { b = 1 }))
  assert(eq(tbl.array(1, nil, 3), { 1, nil, 3 }))

  -- The registrations below are in place by the time the loader runs us.
  assert(agent.utils == M, "agent.utils is not this module")
  assert(agent.utils.tool == M.tool, "agent.utils.tool is not this module's field")
  -- And the tool object it builds is the MCP shape: callable, with the
  -- description and signature the registry reindexes.
  local probe = M.tool("a description", { type = "object" }, function() return { ok = true } end)
  assert(probe.description == "a description" and probe.signature.type == "object",
         "the tool carries its description and schema")
  assert(getmetatable(probe).__call ~= nil, "and is callable")
  assert(probe({}).ok == true, "calling it runs the callback")
  local refusing = M.tool("d", {}, function() return false end)
  assert(refusing({}).denied == true, "and a callback that returns false is a denial")

  return true
end

-- The lib-module convention: a module in `lua/lib/` publishes itself on the
-- `agent` table under its own name. The loader auto-requires every lib module
-- on every VM, so this line alone makes `agent.utils` available everywhere —
-- and `lib/<name>.lua` -> `agent.<name>` is the shape every other module here
-- follows.
agent.utils = M

return M