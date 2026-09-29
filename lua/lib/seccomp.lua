-- seccomp.lua — flag checking for sandbox policies.
--
-- A policy callback receives the intercepted syscall as `sys`
-- (`{ name, nr, pid, cmdline, args, str }`) and has to answer one question:
-- *do the flags in this argument permit what the caller is trying to do?* That
-- used to mean reading an argument by a magic index and doing bit arithmetic
-- by hand — `sys.args[3]`, `flags % 4 ~= 0`, and a `2050` nobody can explain.
-- This module does that work:
--
--   local sc = agent.seccomp
--
--   policy.openat = function(sys)
--     local flags = sc.arg(sys, "openat")        -- the right arg, by name
--     if sc.is_tty_probe(flags) then return true end
--     if sc.check_sys(sys, "openat", "WRITE") then  -- O_WRONLY or O_RDWR?
--       return agent.deny("write open denied: " .. sc.describes("openat", flags))
--     end
--     return true
--   end
--
-- Note the argument order: `check` takes the flags *value*, not the syscall
-- table, so it can be called on a number that came from anywhere. `check_sys`
-- is the wrapper that pulls the argument out for you.
--
--   sc.arg(sys, "openat")                 -> the flags argument of that syscall
--   sc.check("openat", flags, "WRITE")    -> are all the named flags set?
--   sc.check("openat", flags, {"TRUNCATE", "APPEND"})
--   sc.check("access", mode, "W")         -> a W_OK access check
--   sc.check("mmap.prot", prot, "EXEC")   -> PROT_EXEC (mmap has two flag
--                                          arguments, hence the qualified
--                                          name — "mmap" alone is an error)
--
--   sc.check_any("openat", flags, {"TRUNCATE", "APPEND"})  -- any of them?
--   sc.check_sys(sys, "openat", "WRITE")  -- the same, reading the arg for you
--   sc.describes("openat", flags)         -> "O_RDWR|O_CREAT|O_TRUNC"
--
-- On the path side, for the `*at` family:
--
--   sc.dirfd(sys)        -> the dirfd an `*at` call is relative to, or nil
--   sc.paths(sys)        -> the C-string arguments, resolved (see below)
--
-- The flag vocabularies are plain tables of name -> value (Linux, x86-64
-- values), so anything this module does not cover is still reachable:
-- `sc.O.O_TMPFILE`, `sc.PROT`, `sc.MAP`, `sc.MS`, `sc.MAY`, `sc.AT`. A
-- `flags` value of 0 is tested as "the whole value is 0" (how O_RDONLY and
-- PROT_NONE read), and any bits left over by `describes` are appended in hex
-- rather than silently dropped.
--
-- Like every module in `lua/lib/`, this one publishes itself as `agent.seccomp`
-- — the loader auto-requires it, so the table is live on every VM.

local M = {}
M.version = "0.1.0"

-- --------------------------------------------------------------------------
-- Flag vocabularies (name -> value). Names are the short kernel spellings;
-- friendly aliases (CREATE, TRUNCATE, W, X, ...) live in the registry below.
-- --------------------------------------------------------------------------

-- open(2)/openat(2) flags. The low two bits are the access mode.
M.O = {
  RDONLY = 0,       -- 0: the access mode
  WRONLY = 1,       -- 1
  RDWR = 2,         -- 2
  CREAT = 64,       -- 0o100
  EXCL = 128,       -- 0o200
  NOCTTY = 256,     -- 0o400
  TRUNC = 512,      -- 0o1000
  APPEND = 1024,    -- 0o2000
  NONBLOCK = 2048,  -- 0o4000
  DSYNC = 4096,     -- 0o10000
  DIRECT = 16384,   -- 0o40000
  LARGEFILE = 32768,-- 0o100000
  DIRECTORY = 65536,-- 0o200000
  NOFOLLOW = 131072,-- 0o400000
  NOATIME = 262144, -- 0o1000000
  CLOEXEC = 524288, -- 0o2000000
  SYNC = 1052672,   -- 0o4010000
  PATH = 2097152,   -- 0o10000000
  TMPFILE = 4259840,-- 0o20200000
}

-- mmap(2)/mprotect(2) protection bits.
M.PROT = { NONE = 0, READ = 1, WRITE = 2, EXEC = 4 }

-- mmap(2) mapping flags.
M.MAP = {
  SHARED = 1, PRIVATE = 2, FIXED = 16, ANONYMOUS = 32,
  GROWSDOWN = 256, DENYWRITE = 2048,
}

-- access(2)/faccessat(2) mode. F_OK (0) is a mode test, not a bit: see the
-- EXISTS entry in the registry below.
M.MAY = { EXECUTE = 1, WRITE = 2, READ = 4 }

-- *at(2) flag arguments.
M.AT = { REMOVEDIR = 512, SYMLINK_FOLLOW = 1024, EMPTY_PATH = 4096 }

-- mount(2)/umount2(2) flags.
M.MS = {
  RDONLY = 1, NOSUID = 2, NODEV = 4, NOEXEC = 8, REMOUNT = 32, BIND = 4096,
  REC = 16384, PRIVATE = 262144, SLAVE = 524288, SHARED = 1048576,
}

-- AT_FDCWD: not a flag, but the dirfd value that means "relative to the
-- caller's cwd" — a mode test, so a policy can ask for it by name.
M.AT_FDCWD = -100

-- --------------------------------------------------------------------------
-- The registry: which argument of which syscall holds flags, and the
-- vocabulary (plus any modes and friendly aliases) its bits are read in.
--
-- The key is what you pass to `arg` / `check` / `describes`. It is the plain
-- syscall name whenever the syscall has one flags argument, and a qualified
-- name when it has more than one (`mmap.prot`, `mmap.flags`) so the question
-- being asked is never ambiguous.
-- --------------------------------------------------------------------------

local REGISTRY = {
  open = {
    index = 2, flags = "O",
    modes = {
      -- The access mode is not one bit but the low two: "write" means either
      -- O_WRONLY or O_RDWR, which a plain bit test cannot express.
      WRITE = function(f) return (f % 4) ~= 0 end,
      READONLY = function(f) return (f % 4) == 0 end,
    },
    aliases = {
      CREATE = "CREAT", EXCLUSIVE = "EXCL", TRUNCATE = "TRUNC",
      NONBLOCK = "NONBLOCK", DIRECTORY = "DIRECTORY", NOFOLLOW = "NOFOLLOW",
      CLOEXEC = "CLOEXEC", SYNC = "SYNC", PATH = "PATH", TMPFILE = "TMPFILE",
    },
  },
  openat = {
    index = 3, flags = "O",
    modes = {
      WRITE = function(f) return (f % 4) ~= 0 end,
      READONLY = function(f) return (f % 4) == 0 end,
    },
    aliases = {
      CREATE = "CREAT", EXCLUSIVE = "EXCL", TRUNCATE = "TRUNC",
      NONBLOCK = "NONBLOCK", DIRECTORY = "DIRECTORY", NOFOLLOW = "NOFOLLOW",
      CLOEXEC = "CLOEXEC", SYNC = "SYNC", PATH = "PATH", TMPFILE = "TMPFILE",
    },
  },
  openat2 = {
    index = 3, flags = "O",
    modes = {
      WRITE = function(f) return (f % 4) ~= 0 end,
      READONLY = function(f) return (f % 4) == 0 end,
    },
    aliases = {
      CREATE = "CREAT", EXCLUSIVE = "EXCL", TRUNCATE = "TRUNC",
      NONBLOCK = "NONBLOCK", DIRECTORY = "DIRECTORY", NOFOLLOW = "NOFOLLOW",
      CLOEXEC = "CLOEXEC", SYNC = "SYNC", PATH = "PATH", TMPFILE = "TMPFILE",
    },
  },
  ["mmap.prot"] = {
    index = 3, flags = "PROT",
    aliases = { R = "READ", W = "WRITE", X = "EXEC", NONE = "NONE" },
  },
  ["mmap.flags"] = {
    index = 4, flags = "MAP",
    aliases = { ANON = "ANONYMOUS", SHARED = "SHARED", PRIVATE = "PRIVATE" },
  },
  mprotect = {
    index = 3, flags = "PROT",
    aliases = { R = "READ", W = "WRITE", X = "EXEC", NONE = "NONE" },
  },
  mount = {
    index = 4, flags = "MS",
    aliases = { BINDMOUNT = "BIND", RECURSIVE = "REC" },
  },
  umount2 = { index = 2, flags = "MS" },
  access = {
    index = 2, flags = "MAY",
    -- F_OK: the value is 0, which is not a bit.
    modes = { EXISTS = function(f) return f == 0 end },
    aliases = { X = "EXECUTE", W = "WRITE", R = "READ" },
  },
  faccessat = {
    index = 3, flags = "MAY",
    modes = { EXISTS = function(f) return f == 0 end },
    aliases = { X = "EXECUTE", W = "WRITE", R = "READ" },
  },
  faccessat2 = {
    index = 3, flags = "MAY",
    modes = { EXISTS = function(f) return f == 0 end },
    aliases = { X = "EXECUTE", W = "WRITE", R = "READ" },
  },
  unlinkat = {
    index = 3, flags = "AT",
    modes = { CWD = function(f) return f == M.AT_FDCWD end },
    aliases = {
      REMOVE_DIR = "REMOVEDIR", FOLLOW = "SYMLINK_FOLLOW", EMPTY = "EMPTY_PATH",
    },
  },
  mkdirat = {
    index = 2, flags = "AT",
    modes = { CWD = function(f) return f == M.AT_FDCWD end },
    aliases = {
      REMOVE_DIR = "REMOVEDIR", FOLLOW = "SYMLINK_FOLLOW", EMPTY = "EMPTY_PATH",
    },
  },
  fchmodat = {
    index = 3, flags = "AT",
    modes = { CWD = function(f) return f == M.AT_FDCWD end },
    aliases = {
      REMOVE_DIR = "REMOVEDIR", FOLLOW = "SYMLINK_FOLLOW", EMPTY = "EMPTY_PATH",
    },
  },
  fchownat = {
    index = 4, flags = "AT",
    modes = { CWD = function(f) return f == M.AT_FDCWD end },
    aliases = {
      REMOVE_DIR = "REMOVEDIR", FOLLOW = "SYMLINK_FOLLOW", EMPTY = "EMPTY_PATH",
    },
  },
  renameat2 = {
    index = 4, flags = "AT",
    modes = { CWD = function(f) return f == M.AT_FDCWD end },
    aliases = {
      REMOVE_DIR = "REMOVEDIR", FOLLOW = "SYMLINK_FOLLOW", EMPTY = "EMPTY_PATH",
    },
  },
  newfstatat = {
    index = 4, flags = "AT",
    modes = { CWD = function(f) return f == M.AT_FDCWD end },
    aliases = {
      REMOVE_DIR = "REMOVEDIR", FOLLOW = "SYMLINK_FOLLOW", EMPTY = "EMPTY_PATH",
    },
  },
}

-- The registry, exposed for callers that want to walk it (and for tests).
M.FLAGS = REGISTRY

-- --------------------------------------------------------------------------
-- Internals
-- --------------------------------------------------------------------------

-- Is `bit` set in `value`? A zero-valued flag is "the value is zero" (that is
-- how O_RDONLY and PROT_NONE read); a non-zero one is a plain bit test.
local function bit_set(value, bit)
  if bit == 0 then return value == 0 end
  return math.floor(value / bit) % 2 == 1
end

-- The registry entry for a syscall name, or a loud error listing what is known.
local function resolve(syscall)
  if type(syscall) ~= "string" then
    error("agent.seccomp: syscall name must be a string, got " .. type(syscall), 3)
  end
  local entry = REGISTRY[syscall]
  if entry == nil then
    local known = {}
    for name in pairs(REGISTRY) do known[#known + 1] = name end
    table.sort(known)
    error("agent.seccomp: no flags known for '" .. syscall .. "' (known: " ..
          table.concat(known, ", ") .. ")", 3)
  end
  return entry
end

-- "WRITE" or {"WRITE", "TRUNCATE"} -> an array of names.
local function to_list(flags_to_check)
  local t = type(flags_to_check)
  if t == "string" then return { flags_to_check } end
  if t ~= "table" then
    error("agent.seccomp: flags to check must be a name or an array of names, got " .. t, 3)
  end
  return flags_to_check
end

local function to_number(value, syscall)
  if type(value) ~= "number" then
    error("agent.seccomp: the '" .. syscall .. "' flags value must be a number, got " ..
          type(value), 3)
  end
  return value
end

-- Does one named flag/mode hold for `value` under this entry's vocabulary?
-- A name resolves in three steps: as a mode, as an alias (CREATE -> CREAT),
-- or as a family-prefixed spelling (O_CREAT -> CREAT, so the output of
-- `describes` can be fed straight back in).
local function holds(entry, name, value)
  if type(name) ~= "string" then
    error("agent.seccomp: flag names must be strings, got " .. type(name), 3)
  end
  local vocabulary = M[entry.flags]
  local function lookup(n)
    local mode = entry.modes and entry.modes[n]
    if mode ~= nil then return true, mode(value) and true or false end
    local bit = vocabulary[n]
    if bit ~= nil then return true, bit_set(value, bit) end
    return false
  end
  local found, holds_ = lookup(name)
  if not found and entry.aliases and entry.aliases[name] ~= nil then
    found, holds_ = lookup(entry.aliases[name])
  end
  if not found then
    local prefix = entry.flags .. "_"
    if name:sub(1, #prefix) == prefix then
      found, holds_ = lookup(name:sub(#prefix + 1))
    end
  end
  if not found then
    error("agent.seccomp: '" .. name .. "' is not an " .. entry.flags .. " flag or mode", 3)
  end
  return holds_
end

-- --------------------------------------------------------------------------
-- The API
-- --------------------------------------------------------------------------

-- The flags argument of `syscall` in the syscall table `sys` (or nil when it
-- is not a table). This is the piece that removes the `sys.args[3]` index from
-- policy code: the registry knows where each syscall keeps its flags.
function M.arg(sys, syscall)
  local entry = resolve(syscall)
  if type(sys) ~= "table" or type(sys.args) ~= "table" then
    return nil
  end
  return sys.args[entry.index]
end

-- Are *all* of `flags_to_check` set in `value`? `syscall` picks the argument's
-- vocabulary; `value` is the flags value itself (a number — `M.arg` reads it
-- out of a syscall table). An empty list is vacuously true.
function M.check(syscall, value, flags_to_check)
  local entry = resolve(syscall)
  value = to_number(value, syscall)
  for _, name in ipairs(to_list(flags_to_check)) do
    if not holds(entry, name, value) then return false end
  end
  return true
end

-- Is *any* of `flags_to_check` set in `value`? An empty list is false.
function M.check_any(syscall, value, flags_to_check)
  local entry = resolve(syscall)
  value = to_number(value, syscall)
  for _, name in ipairs(to_list(flags_to_check)) do
    if holds(entry, name, value) then return true end
  end
  return false
end

-- `check` against a syscall table, reading the flags argument by name:
-- `check_sys(sys, "openat", "WRITE")`.
function M.check_sys(sys, syscall, flags_to_check)
  resolve(syscall)
  if type(sys) ~= "table" or type(sys.args) ~= "table" then
    error("agent.seccomp: expected a syscall table with .args, got " .. type(sys), 2)
  end
  return M.check(syscall, M.arg(sys, syscall), flags_to_check)
end

-- ==========================================================================
-- The *other* half of a syscall's arguments: the paths.
--
-- `arg` finds the flags; the pathnames live in `sys.str`, which the engine
-- fills only at the argument positions that really are C strings (so a
-- numeric argument never shows up there, and no out-buffer is read). The paths
-- are already resolved against the caller's working directory where that is
-- possible; a name relative to a dirfd the engine cannot see is passed through
-- unresolved rather than mis-resolved.
-- ==========================================================================

-- Syscalls whose first argument is a directory fd: `sys.args[1]` is the dirfd
-- and the paths start after it. Read from the kernel's shape, not guessed.
local AT_SYSCALLS = {
  openat = true, openat2 = true, unlinkat = true, mkdirat = true,
  fchmodat = true, fchownat = true, newfstatat = true, faccessat = true,
  faccessat2 = true, readlinkat = true, linkat = true, symlinkat = true,
  utimensat = true, execveat = true, renameat = true, renameat2 = true,
}

local function args_of(sys, what)
  if type(sys) ~= "table" then
    error("agent.seccomp." .. what .. ": expected the syscall table, got " ..
          type(sys), 3)
  end
  if type(sys.args) ~= "table" then
    error("agent.seccomp." .. what .. ": the syscall table has no .args", 3)
  end
  if type(sys.name) ~= "string" then
    error("agent.seccomp." .. what .. ": the syscall table has no .name", 3)
  end
  return sys
end

--- Every path the syscall names, in argument order (usually one; `rename` and
--- friends have two). Empty when it names none.
function M.paths(sys)
  args_of(sys, "paths")
  local str = type(sys.str) == "table" and sys.str or {}
  -- `str` is sparse (only the real C-string positions are filled, e.g. [2] for
  -- openat), so collect by key and sort by position — `#` and `ipairs` both
  -- lie about a table like this.
  local by_pos = {}
  for pos, text in pairs(str) do
    if type(pos) == "number" and type(text) == "string" then
      by_pos[#by_pos + 1] = { pos = pos, text = text }
    end
  end
  table.sort(by_pos, function(a, b) return a.pos < b.pos end)
  local out = {}
  for i, item in ipairs(by_pos) do out[i] = item.text end
  return out
end

--- The nth path (1-based; the default is the first) or nil. Most syscalls
--- touch exactly one file, so `sc.path(sys)` is the common case; `rename` and
--- friends take `sc.path(sys, 2)` for the destination.
function M.path(sys, n)
  n = n or 1
  if type(n) ~= "number" or n < 1 or n % 1 ~= 0 then
    error("agent.seccomp.path: n must be a positive integer, got " .. tostring(n), 2)
  end
  return M.paths(sys)[n]
end

--- The path an open descriptor names, for the syscalls that identify a file only
--- by descriptor: `sc.fd_path(sys, 1)` is the file `fchmod` is about, read back
--- through `/proc/<pid>/fd/<n>` by the engine.
---
--- `nil` for everything that is not a path — a pipe, a socket, an already-closed
--- slot — and `nil` for a syscall with no descriptor argument at all. That is a
--- real answer rather than a missing one: `fchmod` on a pipe is `EBADF`, there is
--- no file, and a policy that wants to ask about the call has to ask about the
--- *call* rather than about a path that does not exist.
function M.fd_path(sys, n)
  n = n or 1
  if type(n) ~= "number" or n < 1 or n % 1 ~= 0 then
    error("agent.seccomp.fd_path: n must be a positive integer, got " ..
          tostring(n), 2)
  end
  if type(sys) ~= "table" then
    error("agent.seccomp.fd_path: expected the syscall table, got " ..
          type(sys), 2)
  end
  local fds = sys.fd
  if type(fds) ~= "table" then return nil end
  local text = fds[n]
  if type(text) ~= "string" or text == "" then return nil end
  return text
end

--- The endpoint the syscall names, decoded out of the caller's memory by the
--- engine: `{ family = "inet"|"inet6"|"unix"|"other", ip = string|nil,
--- port = number|nil, path = string|nil }`. `nil` when the syscall names no
--- address (`sc.path`'s counterpart for the network) or when the address could
--- not be read — a policy then asks about a call it cannot describe rather than
--- waving it through.
---
--- `connect` and `bind` are the two that matter, and they mean opposite things:
--- `connect` names a target the process wants to *reach*, `bind` the address it
--- wants to *listen* on. (`listen()` itself names nothing — it only marks an
--- already-bound socket as accepting — so there is no address to ask about.)
function M.addr(sys)
  if type(sys) ~= "table" then
    error("agent.seccomp.addr: expected the syscall table, got " .. type(sys), 2)
  end
  if type(sys.addr) ~= "table" then return nil end
  -- 1-based and aligned with `sys.args`, like `sys.str` — so the sockaddr in
  -- `connect(fd, addr, len)` is at slot **2**, not slot 1. These calls have one
  -- endpoint each, so this is the lowest-numbered entry.
  local first
  for slot, endpoint in pairs(sys.addr) do
    if type(slot) == "number" and (first == nil or slot < first) then
      first = slot
    end
  end
  return first and sys.addr[first] or nil
end

--- The name for the endpoint's address, for a question a user can act on:
--- `sc.host_of(sys)` is `"api.github.com"` when the address reverse-resolves and
--- the bare address when it does not. Reverse DNS misses are normal (a
--- container's internal address usually has no PTR), so this never raises and
--- never blocks on anything but a short resolver timeout.
function M.host_of(sys, addr)
  addr = addr or M.addr(sys)
  if type(addr) ~= "table" or type(addr.ip) ~= "string" then return nil end
  local name = agent.api.reverse_dns(addr.ip)
  if type(name) == "string" and name ~= "" then return name end
  return nil
end

--- The endpoint's *address*, as one line of text: `api.github.com
--- (140.82.121.6)`, or the bare address when it has no name, or the path for a
--- unix socket. This is the shape a question reads best in.
---
--- The port is deliberately not part of it: a question about reaching something
--- wants to say the port in its own words ("at port 443"), and a question about
--- listening wants it first ("open port 443 on ..."), so folding it into the
--- address would make both read as a doubled port. `sc.port_of(sys)` is the other
--- half.
function M.describes_addr(addr)
  if type(addr) ~= "table" then return "an unknown address" end
  if addr.family == "unix" then
    return "the unix socket " .. tostring(addr.path or "(unnamed)")
  end
  if type(addr.ip) ~= "string" then
    return "an address this agent cannot describe"
  end
  local name = M.host_of(nil, addr)
  return name and (name .. " (" .. addr.ip .. ")") or addr.ip
end

--- The endpoint's port, or `nil` when the family has none (a unix socket) or
--- the address could not be read.
function M.port_of(sys, addr)
  addr = addr or M.addr(sys)
  if type(addr) ~= "table" or type(addr.port) ~= "number" then return nil end
  return addr.port
end

--- The directory fd an `*at` syscall is relative to, or nil when the syscall
--- has none. `-100` (`AT_FDCWD`) means the caller's working directory — ask
--- with `sc.check(syscall, flags, "CWD")` when the flags are the thing being
--- tested, or compare with `sc.AT_FDCWD` here.
function M.dirfd(sys)
  args_of(sys, "dirfd")
  if not AT_SYSCALLS[sys.name] then return nil end
  return sys.args[1]
end

-- Human-readable flag decoding: "O_RDWR|O_CREAT|O_TRUNC". Bits the vocabulary
-- does not name are appended in hex, so nothing is silently dropped.
function M.describes(syscall, value)
  local entry = resolve(syscall)
  value = to_number(value, syscall)
  local vocabulary = M[entry.flags]
  local names = {}
  for name, bit in pairs(vocabulary) do
    if bit_set(value, bit) then names[#names + 1] = { name = name, bit = bit } end
  end
  -- Ascending bit order: the access mode (low bits) reads first.
  table.sort(names, function(a, b)
    if a.bit ~= b.bit then return a.bit < b.bit end
    return a.name < b.name
  end)
  local parts = {}
  for _, item in ipairs(names) do parts[#parts + 1] = entry.flags .. "_" .. item.name end
  -- Whatever the vocabulary could not name: the value minus the named bits.
  local leftover = value
  for name, bit in pairs(vocabulary) do
    if bit_set(value, bit) then leftover = leftover - bit end
  end
  if leftover ~= 0 then parts[#parts + 1] = string.format("0x%x", leftover) end
  if #parts == 0 then return entry.flags .. "_NONE" end
  return table.concat(parts, "|")
end

-- bash opens /dev/tty with exactly O_RDWR|O_NONBLOCK at startup to probe for a
-- controlling terminal (the open fails ENXIO off a tty and is ignored). Asking
-- on that probe would interrupt the first syscall of *every* command, so
-- policies exempt it — hence the named constant instead of a literal 2050.
M.TTY_PROBE_FLAGS = M.O.RDWR + M.O.NONBLOCK

-- Is this the controlling-tty probe? Pass either a flags value or a syscall
-- table: `is_tty_probe(sys)` or `is_tty_probe(2050)`.
function M.is_tty_probe(value)
  if type(value) == "table" then
    local flags = M.arg(value, value.name or "openat")
    return flags == M.TTY_PROBE_FLAGS
  end
  return value == M.TTY_PROBE_FLAGS
end

-- The `lua/lib/` convention: publish on `agent`, so the loader's auto-require
-- makes `agent.seccomp` live on every VM.
agent.seccomp = M

-- --------------------------------------------------------------------------
-- Self-test: `agent.seccomp._selftest()` raises on any failure.
-- --------------------------------------------------------------------------

function M._selftest()
  -- The open family: the access mode, the tty probe, decode-and-ask in one
  -- line each — the checks a read-only policy is made of.
  assert(M.check("openat", 2050, "WRITE"), "tty probe is a write open")
  assert(M.is_tty_probe(2050))
  assert(not M.is_tty_probe(1))
  assert(M.is_tty_probe({ name = "openat", args = { -100, "/dev/tty", 2050 } }))
  assert(M.arg({ name = "openat", args = { -100, "/dev/tty", 2050 } }, "openat") == 2050)
  assert(M.arg({ name = "open", args = { "/etc/hosts", 0 } }, "open") == 0)
  assert(M.check("openat", 0, "READONLY") and not M.check("openat", 0, "WRITE"))
  assert(M.check("openat", 1, "WRONLY") and M.check("openat", 1, "WRITE"))
  assert(M.check("openat", 2, "RDWR") and M.check("openat", 2, "WRITE"))
  assert(not M.check("openat", 2, "WRONLY"), "O_RDWR is not O_WRONLY")
  assert(M.check("openat", 1089, { "CREATE", "APPEND" }))
  assert(not M.check("openat", 1089, { "CREATE", "TRUNCATE" }))
  assert(M.check_any("openat", 1089, { "TRUNCATE", "APPEND" }))
  assert(not M.check_any("openat", 1089, { "TRUNCATE", "EXCLUSIVE" }))
  assert(M.check("openat", 1089, "O_CREAT"), "the kernel spelling works too")
  assert(not M.check("openat", 1089, "O_TRUNC"), "O_TRUNC is not set")
  -- describes output round-trips back into check.
  for _, name in ipairs({ "O_WRONLY", "O_CREAT", "O_APPEND" }) do
    assert(M.check("openat", 1089, name), "round-trip " .. name)
  end
  assert(M.describes("openat", 2050) == "O_RDWR|O_NONBLOCK")
  assert(M.describes("openat", 1089) == "O_WRONLY|O_CREAT|O_APPEND")
  assert(M.describes("openat", 0) == "O_RDONLY")

  -- Other families: the qualified names, and the mode-style tokens.
  assert(M.check("mmap.prot", 5, { "R", "X" }))
  assert(not M.check("mmap.prot", 5, "W"))
  assert(M.check("access", 6, { "R", "W" }))
  assert(M.check("access", 0, "EXISTS"))
  assert(not M.check("access", 2, "EXISTS"))
  assert(M.check("unlinkat", -100, "CWD"))
  assert(M.check("unlinkat", 512, "REMOVE_DIR"))
  assert(M.check("mount", 4096, "BINDMOUNT"))

  -- Paths: the engine fills sys.str only at real C-string positions, so the
  -- paths are just its non-nil entries, in argument order.
  local openat_sys = { name = "openat", args = { -100, "/tmp/x", 65 },
                       str = { [2] = "/tmp/x" } }
  assert(M.path(openat_sys) == "/tmp/x")
  assert(M.paths(openat_sys)[1] == "/tmp/x" and #M.paths(openat_sys) == 1)
  assert(M.path(openat_sys, 2) == nil)
  assert(M.dirfd(openat_sys) == -100, "openat is relative to a dirfd")
  -- rename carries both sides.
  local rename_sys = { name = "rename", args = { 1, 2, 3, 4 },
                       str = { [1] = "old", [2] = "new" } }
  assert(M.path(rename_sys) == "old" and M.path(rename_sys, 2) == "new")
  assert(M.dirfd(rename_sys) == nil, "rename has no dirfd")
  -- A non-*at syscall starts its path at args[1].
  local open_sys = { name = "open", args = { "/etc/hosts", 0 },
                     str = { [1] = "/etc/hosts" } }
  assert(M.path(open_sys) == "/etc/hosts" and M.dirfd(open_sys) == nil)
  -- A syscall with no path arguments.
  local getpid_sys = { name = "getpid", args = {}, str = {} }
  assert(M.path(getpid_sys) == nil and #M.paths(getpid_sys) == 0)
  assert(not pcall(M.path, openat_sys, 0), "a bad path index is refused")
  assert(not pcall(M.paths, { name = "x" }), "a table with no .args is refused")

  -- The empty list is vacuously true for check, false for check_any.
  assert(M.check("openat", 0, {}))
  assert(not M.check_any("openat", 0, {}))

  -- Unknown names are loud, not silently false.
  local ok = pcall(M.check, "openat", 0, "CRETA")
  assert(not ok, "a misspelled flag must not be silently false")
  local ok2 = pcall(M.check, "nosuchsyscall", 0, "WRITE")
  assert(not ok2, "an unknown syscall must not be silently false")

  return true
end

return M
