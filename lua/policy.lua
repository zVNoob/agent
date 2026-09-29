-- policy.lua — the default sandbox policy behind the shipped `bash` tool.
--
-- `require("policy").new()` returns a policy: a table of `syscall name ->
-- callback`, and the whole reason a shell run is something the user agreed to
-- rather than something it just did. **Every** file it opens and **every**
-- endpoint it reaches is **asked** first.
--
-- **A policy is built per run, not per process, and that is what makes its
-- memory per run.** `.new()` is called once for each `agent.bash` invocation and
-- hands back a fresh table of fresh closures; the previous run's table is
-- dropped when it returns. A gate that remembers therefore needs nothing to
-- scope its memory — no run id, no pid, no key it could get wrong. Its memory is
-- an upvalue, and an upvalue is unreachable from the next run because the next
-- run never sees this table again. There is no identifier anywhere in the design
-- for a stale grant to be confused with a live one, which is also why a recycled
-- pid cannot inherit anything.
--
-- The syscall-name keys are the interception mask, so the mask here is exactly
-- what this file names and nothing more:
--
--   openat   the process want to read/write {path} ({flags})
--            A read and a write are two questions, not one: a read asks
--            `ask_trust_read` and a write asks `ask_trust_write`, so trusting a
--            file *to read it* never silently grants writing it. What keeps this
--            usable is the working directory, which `lua/init.lua` trusts at
--            startup — so work inside this repository asks nothing, and
--            everything outside it asks.
--
--            …except a write to a name **nothing holds yet**. Creating is not
--            asking: there is nothing to disturb and nothing to lose, and a
--            prompt per created file trains the user to stop reading prompts.
--            The new name is then write-trusted, so the create and its follow-up
--            edits are one decision. An *overwrite* still asks, and the test is
--            `os.rename(p, p)` on the resolved path — which succeeds on a file
--            the process cannot even read, so a name that exists cannot be
--            mistaken for one that does not.
--
--   connect  the process want to access {hostname} ({IP}) at port {port}
--            The target it wants to *reach*. The hostname is a reverse lookup and
--            is dropped when there is none; the address is the ground truth.
--
--   bind     the process want to open port {port} on {address}
--            The address it wants to *listen* on. (`listen()` is not gated: it
--            names no address, it only marks an already-bound socket as
--            accepting, so there is nothing to ask about.)
--
--   chmod    the process want to change the mode of {path}
--   fchmodat the same, for the path form
--            Metadata, not content, and still a permission change: `chmod +x` is
--            how a payload becomes runnable. Write trust, the same table an
--            overwrite asks on. (`fchmod` is not in the mask — it names no path,
--            and holding a descriptor on a file already cost a grant.)
--
--   setxattr the process want to set the {attribute} of {path}
--   lsetxattr the same, without following a final symlink
--   removexattr / lremovexattr the same, removing
--            `security.*` is what file capabilities are, and setting one can make
--            a file run with privileges the agent was never given — `setcap`, and
--            `setcap -r` through the remove calls. The attribute name is in the
--            question, so `security.capability` reads differently from `user.*`.
--            The getters are not gated; a read of one says little and asking
--            about it would be noise.
--
--   sendto   the process want to send to {hostname} ({IP}) at port {port}
--            UDP egress, which is `connect` without a handshake: a datagram
--            leaves and the peer never replies, so nothing downstream would ever
--            notice. It is in the mask for exactly that reason.
--
--   unlinkat  the process want to delete {path}
--            Removing a name, asked on **write** trust: unlinking is not reading
--            the file, it is the removal of the name. This is the gate that makes
--            `rm` ask, and the file's contents are never read to answer it.
--
--   renameat  the process want to move {from} to {to}
--   renameat2 the same, with flags
--            Two questions, because a rename is two things. The source is asked
--            first — without it the move does not happen. The target is asked
--            **only when it already exists**, which is the difference between
--            creating a name (already covered by the source) and destroying
--            somebody else's.
--
--            Both names are gated because only one of them is ever called:
--            glibc's `rename()` is `renameat2` now, so `mv` never reaches
--            `renameat`. One without the other would look right and do nothing.
--
--   io_uring_setup    the process want to create an io_uring event loop
--   io_uring_enter    the process want to submit work to one
--   io_uring_register the process want to register files or buffers with one
--            The most consequential entries in this file, and the only ones
--            added for what they *defeat* rather than for what they allow.
--            `IORING_OP_OPENAT` and its siblings are submission-queue
--            opcodes, not syscalls: a program that speaks the ring protocol can
--            open, stat, unlink, rename, link and symlink without `openat`,
--            `unlinkat` or `renameat` ever being called. So while
--            `io_uring_enter` is ungated, every question this file asks about a
--            file can be walked around by a program that cares to walk around
--            it.
--
--            What is asked, and why it repeats, is in `ask_capability` below.
--            Briefly: nothing is decoded, and there is no `always`.
--
--   open_by_handle_at the process want to open a file by an opaque handle
--   name_to_handle_at the process want to take such a handle for {path}
--            A second way to name a file that is not a path, so a second way
--            past every table above. `open_by_handle_at` picks the file with an
--            opaque `file_handle`; its `path` argument is a component hint of at
--            most 64 bytes that decides nothing, which is why it is deliberately
--            absent from the engine's pathname table — reading it would put a
--            plausible and *wrong* name in the question. Its partner does name a
--            real path, so it is asked on read trust like any other read; but a
--            handle carries no path back, so trusting the taking does not
--            silence the spending. See the two callbacks for why that asymmetry
--            is the point rather than an oversight.
--
--   memfd_create / pidfd_getfd / process_vm_readv / process_vm_writev / bpf /
--   userfaultfd / pkey_alloc / pkey_mprotect / pkey_free
--            The same shape, one step further out: each is a way of reaching
--            something the path tables cannot see at all — a file with no name, a
--            descriptor owned by somebody else, another address space's memory,
--            the kernel itself. None of them has an argument worth reading, so
--            they are one table of one-liners at the bottom.
--
--            One deliberate omission: `memfd_secret` is **not** gated, because
--            glibc uses it for the per-thread guard pages behind
--            `MALLOC_TUNABLE_*`. A gate that fires on libc's own housekeeping is
--            a gate that teaches the user to press `a`.
--
-- Note what is *not* in the mask on the filesystem side: `mkdirat` and `rmdir`.
-- A new directory is therefore created without a question (which is what the
-- rule above would conclude anyway), and `rm -r` reaches the gate through
-- `unlinkat` on each name, one question per name. `linkat` and `symlinkat` are
-- absent too, and are a real gap rather than a decision: a sandboxed command can
-- hard-link or symlink inside a directory you have trusted. They are the next
-- thing to add if you want them, and the shape is the `unlinkat` callback above.
--
-- Everything *not* named above is not intercepted at all — it runs straight
-- through the kernel under its default (allow). So read this as what it is: a
-- filter that asks about files and endpoints, not a jail. The sandbox is a bare
-- `fork()` with no `unshare`, so a command keeps the host's filesystem view and
-- the host's network namespace; `ss` or `/proc/net/tcp` will list every listener
-- on the machine, and anything bound to 127.0.0.1 that a command can guess is
-- reachable. Asking is not confining.
--
-- That is the design, not a gap in it. The decision belongs to the user at the
-- moment it matters, so the job here is to make the question answerable — name
-- the path, or the host and the port, and offer `always` when there is something
-- to remember — and then get out of the way. A policy that decided on its own
-- what a command may do would be a different product with a different failure
-- mode, so this one does not do that.
--
-- What it does provide is a floor under every decision it *does* make: a denied
-- syscall is refused by the kernel, not by this table's opinion.
--
-- ## Two kinds of question
--
-- Everything above except the last two groups is a question about a **thing** —
-- a path, a host, a port — so it can be matched against a trust table, and an
-- `always` has something to record. Those records outlive the run, because the
-- file or the host does: trusting `/srv/app` today is still true tomorrow.
--
-- The rest ask about a **capability**: the syscall is itself what is being
-- vouched for, and there is no path, host or port in it for a table to hold. So
-- `always` is not a flag there but a *string* — `lways this run` — and it is
-- exactly what it says. The grant is an upvalue of that gate's closure, which
-- every worker in the tree shares and no other command can reach.
--
-- That lifetime is the design rather than a limitation, and the wider
-- alternative was the obvious first cut: a capability table that outlived the
-- run would answer the *next* command's `io_uring_enter` with no question at
-- all, and "this program may reach any file" is not a decision anyone makes
-- about a *program* — the next `bash` is a different program that would inherit
-- it invisibly. A closure costs one question per command rather than one per
-- syscall, and carries no key that could go stale.
--
-- Where a capability names *another process* — `pidfd_getfd`,
-- `process_vm_readv`, `process_vm_writev` — its pid is deliberately left out of
-- the question. The tracee's own command line is already in it, and a second
-- bare pid is a number nobody has vouched for: there is no table of trusted
-- processes, so printing one would make the question look decidable when it is
-- not. The capability is what is being asked about, and it is the whole of it.
--
-- ## What "always" remembers
--
-- A file question is remembered by the path tables in `agent.ask`
-- (`ask_trust_read` / `ask_trust_write`); a network question by the
-- trustworthy-server table (`ask_server`): a host, or one `host:port`. Separate
-- tables on purpose — a trusted file is not a trusted peer, and forgetting one
-- must never forget the other. A plain `yes` is for that one operation; only
-- the third answer is recorded, and both tables live on the agent's own VM, so
-- such a grant outlives the call that made it.
--
-- A **capability** question is remembered by neither, and this is the one answer
-- here that does not outlive the question. It has no path or host to put in a
-- table, so the gate brings its own `remember` closure and the recording happens
-- there. The gate is a closure of a table this file builds per run, so the grant
-- dies with the policy — and since nothing else holds a reference to that table,
-- "dies with" is not a rule anyone has to enforce.
--
-- ## The other two seams
--
-- `agent.seccomp` (`sc`) is the flag and address reading — the flags argument by
-- name, the read/write test, the human-readable decode, and the sockaddr decode
-- the endpoint questions are worded from. `agent.ask` raises the question; the
-- tool (`lua/bash_tool.lua`) shows the description as an overlay on the
-- bash-result panel and hands back the verdict. A run with no ask handler —
-- headless, the tests, the probe — auto-denies, so a sandboxed run there touches
-- nothing it was not already trusted for.
--
-- A policy is a plain table passed per call to `agent.bash`, so this file
-- *returns* one and registers nothing: `require("bash_tool")` is what puts the
-- shell in `agent.mcps`, and that is what lets a mode drop it. Both modules are
-- read at call time, not load time, so the `require`s here are order-independent.
local sc, ask = require("seccomp"), require("ask")

-- The module table. It exports exactly one thing, `new`, and it exports the
-- *constructor* rather than a policy — see its doc below for why that is the
-- whole scoping mechanism.
local M = {}

--- The trust key for an endpoint: the name the user was shown, or the address
--- when it has none. An endpoint the engine could not read at all is keyed by a
--- fixed string, so every such call is one remembered decision rather than an
--- endless stream of questions with nothing in them.
local function server_key(addr)
  if type(addr) ~= "table" then return "unreadable-endpoint", nil end
  local host = sc.host_of(nil, addr) or addr.ip
  if type(host) ~= "string" or host == "" then return "unreadable-endpoint", nil end
  return host, addr.port
end

--- The question a *reach* raises, worded for the syscall doing it: "access" for
--- `connect`, "send to" for `sendto`. The address and the port are named
--- separately, so neither is printed twice.
local function reach_question(what, addr)
  return "The process want to " .. what .. " " .. sc.describes_addr(addr) ..
         " at port " .. tostring(sc.port_of(nil, addr) or "?")
end


--- A fresh policy table: one closure per gate, per run.
---
--- Everything below is inside this function, and that placement is the design
--- rather than an accident of style. A `local` at module level would be created
--- once per *process* and shared by every command, so any state a gate closed
--- over would belong to every run and not to the one that asked — the exact
--- failure this refactor exists to remove. As it stands, a gate's memory is born
--- with the run and dies with it.
---
--- The gates are returned rather than registered on `agent`, because this file
--- is a module and not a lib-module (see the `lib/` convention): it is passed
--- per call to `agent.bash`, which is what lets a mode drop the shell entirely.
function M.new()
local policy = {}

-- Every open is asked, read or write — with one exception, below. The tty probe
-- is bash checking whether it has a terminal, not a file the user means, and
-- asking about it would interrupt the first syscall of every command.
policy.openat = function(sys)
  local flags = sc.arg(sys, "openat")
  if sc.is_tty_probe(flags) then return true end
  local path = sc.path(sys)
  if sc.check("openat", flags, "WRITE") then
    -- **Creating** something new is not a question. Nothing is there to disturb
    -- and nothing can be lost, so the alternative is a prompt before every file
    -- the agent ever makes — and the cost of that is not a pause, it is a user
    -- who stops reading the questions and starts pressing `a`.
    --
    -- The name is then recorded as write-trusted, so the create and the edits
    -- that follow it are one decision rather than one per write. That also
    -- silences *reads* of it, because `trust_write` records both tables — which
    -- is right for a file the agent just made and is not true in general.
    --
    -- What this does not do is make an overwrite silent. The existence probe is
    -- the whole difference, and it is asked of the *resolved* path: a symlink to
    -- an existing file resolves to that file, which is taken, so it asks. The same
    -- resolution runs on every later write, so swapping a created file for a
    -- symlink makes the next write ask about the symlink's target rather than
    -- quietly following it.
    --
    -- …unless the name is inside a **read-only** grant, which is where the
    -- system tree lives. "You may look here" is not "you may make things here",
    -- and `/usr` is the case that proves it: without this the create rule would
    -- let the agent drop a file into the system tree without a word, which is
    -- the opposite of what granting it read-only meant. A working directory is
    -- granted with `trust` and so is unaffected — work there still creates
    -- quietly, as it must.
    if not ask.taken(path) and not ask.is_readonly(path)
       and not ask.is_blocked(path) then
      ask.trust_write(path)
      return true
    end
    return ask.ask_trust_write(
      path,
      "The process want to write " .. tostring(path) .. " (" ..
      sc.describes("openat", flags) .. ")")
  end
  return ask.ask_trust_read(path, "The process want to read " .. tostring(path))
end

-- Reaching for an endpoint. The ask records the host (and port) in the
-- trustworthy-server table, so an "always" makes the next connection silent.
policy.connect = function(sys)
  local addr = sc.addr(sys)
  local host, port = server_key(addr)
  return ask.ask_server(host, port, reach_question("access", addr))
end

-- Opening a port. Same table, same reasoning: a port vouched for once is a port
-- the next command need not ask about again.
policy.bind = function(sys)
  local addr = sc.addr(sys)
  local host, port = server_key(addr)
  return ask.ask_server(
    host, port,
    "The process want to open port " .. tostring(sc.port_of(nil, addr) or "?") ..
    " on " .. sc.describes_addr(addr))
end

-- Changing a file's mode. Metadata rather than content, but it is a permission
-- change, and `chmod +x` is how a payload becomes runnable — so it asks on
-- **write** trust, the same table an overwrite asks on.
--
-- `fchmod` is deliberately *not* in the mask. It takes a descriptor and no path,
-- so there is nothing to name in a question, and reaching it means the process
-- already holds an open descriptor on the file — which cost it read or write
-- trust when it opened it. The path-based pair is what can be asked about, and
-- the descriptor-based one is the narrow remainder of that same grant.
local function ask_change_mode(sys)
  local path = sc.path(sys)
  return ask.ask_trust_write(
    path, "The process want to change the mode of " .. tostring(path))
end

policy.chmod = ask_change_mode
policy.fchmodat = ask_change_mode

-- An extended attribute is metadata the filesystem does not otherwise expose,
-- and `security.*` on it is what file capabilities are: setting one can turn an
-- ordinary file into one that runs with privileges the agent was never given.
-- That is `setcap`, and it is a permission change wearing a different hat.
--
-- The attribute's name is the second path, so the question names it — being told
-- a `security.capability` is going onto a file is a different thing from being
-- told an app is tidying up its own `user.*` metadata. `removexattr` is gated for
-- the same reason: `setcap -r` goes through it.
--
-- The *getters* are not gated. Reading `security.capability` says whether a file
-- has capabilities and nothing more, and gating reads would add a question to
-- every program that inspects its own metadata for reasons of its own.
local function ask_xattr(sys, verb)
  local path, name = sc.path(sys, 1), sc.path(sys, 2)
  return ask.ask_trust_write(
    path,
    "The process want to " .. verb .. " the " ..
    (type(name) == "string" and name or "extended attributes") ..
    " of " .. tostring(path))
end

policy.setxattr = function(sys) return ask_xattr(sys, "set") end
policy.lsetxattr = function(sys) return ask_xattr(sys, "set") end
policy.removexattr = function(sys) return ask_xattr(sys, "remove") end
policy.lremovexattr = function(sys) return ask_xattr(sys, "remove") end

-- UDP egress: the same question, and the same gate, for a datagram.
policy.sendto = function(sys)
  local addr = sc.addr(sys)
  local host, port = server_key(addr)
  return ask.ask_server(host, port, reach_question("send to", addr))
end

-- Deleting a name. Gated on **write** trust in the path, not read: unlinking is
-- not a read of the file, it is the removal of the name, and a path trusted for
-- reading is trusted for nothing else. The same table `openat`'s write branch
-- uses, so a directory trusted to be written to does not need a second grant for
-- its files to be deletable.
--
-- This is what makes `rm` ask. It is also the only gate on the name itself: the
-- file's *contents* are never read to answer it, so the question is about the
-- path and nothing leaks about what is in it.
policy.unlinkat = function(sys)
  local path = sc.path(sys)
  return ask.ask_trust_write(
    path, "The process want to delete " .. tostring(path))
end

-- Moving a name. Two questions, because a rename is two things at once: the
-- source stops existing under its own name, and — only when something is already
-- there — the target's contents are destroyed by the arrival. The source is
-- asked first, since without it the move does not happen at all.
--
-- The target is asked *only if it exists*, and that is not a shortcut: a rename
-- onto a name nobody holds creates it, which is the source's permission already
-- spoken for, whereas a rename onto a name somebody holds overwrites them. The
-- existence test is `io.open` on the target, which follows symlinks — so a
-- *dangling* symlink reads as absent and its replacement is not asked about.
-- Lua 5.1 has no `lstat`, and a second process to ask the question properly
-- would be a worse trade than naming the gap.
local function ask_rename(sys)
  local from, to = sc.path(sys, 1), sc.path(sys, 2)
  if type(from) ~= "string" or from == "" then
    return ask.deny("the move named no source path")
  end
  local moved = ask.of(
    ask.ask_trust_write(
      from, "The process want to move " .. from .. " to " .. tostring(to)))
  if not moved then
    return ask.deny("the move of " .. from .. " was not allowed")
  end
  if type(to) == "string" and to ~= "" then
    local existing = io.open(to, "rb")
    if existing then
      existing:close()
      local overwrote = ask.of(
        ask.ask_trust_write(
          to, "The process want to overwrite " .. to .. " by moving " .. from))
      if not overwrote then
        return ask.deny("overwriting " .. to .. " was not allowed")
      end
    end
  end
  return true
end

-- `renameat2` is the *same* operation with a flags argument, and it is the one
-- that actually gets issued: glibc's `rename()` maps onto it, so `mv` on this
-- machine never reaches `renameat` at all. Gating only `renameat` would have
-- looked correct and left every real `mv` ungated, so both are in the mask.
--
-- The cost is a second round of questions for `mv -f` onto a name that already
-- exists: coreutils first tries `RENAME_NOREPLACE`, the kernel answers EEXIST,
-- and it retries as a plain `renameat`. The retry asks again, because a plain
-- `yes` is remembered for one operation by design. `always` records both paths
-- and the retry is silent.
policy.renameat = ask_rename
policy.renameat2 = ask_rename

-- One gate per capability, curried rather than called: `capability_gate(name,
-- what)` closes over `name` and over its own `accepted` flag, and returns the
-- callback the mask ends up holding. Currying is what scopes the memory. The
-- closure is created inside `M.new`, so it belongs to one run: `accepted` is an
-- upvalue of a function the next run has no reference to.
--
-- Nothing identifies a run anywhere in this, which is the point. The earlier
-- shape keyed the accepted set on a sandbox id and needed the id to be unique
-- and unrecyclable — a property of the *engine* that the policy had to trust.
-- Here there is no key at all, so there is no way for one run's grant to be read
-- as another's, whether the run is the next command or a different process
-- entirely. The memory is not scoped; it is simply unreachable.
--
-- The loop, and why each step is there:
--
--   1. already accepted in this run? Then the gate answers itself, which is the
--      whole of what the grant is for: a program that opens one ring should be
--      asked once about it, not once per `io_uring_enter` for the rest of the
--      command — and every worker in the tree shares this one closure, so a
--      server's workers do not each bring their own question.
--   2. otherwise build the question. `for_syscall` fills the description; `path`
--      is *dropped*, because `ask` short-circuits to `true` on a trusted path and
--      a grant about a file must not answer a question about a capability (set
--      here rather than left to the engine's pathname table staying right).
--   3. `always` is a string rather than a flag, and the string is what the dialog
--      draws after the `[a]`. "always" would be a lie: this grant cannot outlive
--      the run, so it says `lways this run` and the user reads the limit at the
--      moment they choose it.
local function capability_gate(name, what)
  local accepted = false
  return function(sys)
    if accepted then return true end
    local q = ask.for_syscall(sys, what)
    q.path = nil
    q.always = "lways this run"
    -- The memory, and the only copy of it: `ask` calls this when — and only
    -- when — the user pressed the third answer, so a plain `y` still asks again.
    -- `name` is not read here, which is deliberate: the closure is one per gate,
    -- so it cannot record another gate's answer by construction.
    q.remember = function() accepted = true end
    return ask.ask(q)
  end
end

-- The ring. All three are asked, and none of them is decoded: the work is in
-- the ring's own memory, not in the arguments, and reading a live ring on every
-- `io_uring_enter` would put a cross-process memory read on the hot path of
-- precisely the programs most likely to be driving one.
--
-- The wording carries the warning on purpose. Allowing a ring is not permission
-- to do one thing — it is permission to do every file and endpoint operation in
-- this file *without asking again*, which is the whole thing the rest of the
-- policy is for. So the second clause is in the sentence rather than in a note
-- below it: a user who read only the first words would not know what they had
-- agreed to.
policy.io_uring_setup = capability_gate(
  "io_uring_setup",
  "to create an io_uring event loop, which can then reach any file or endpoint " ..
  "without asking about it")
policy.io_uring_enter = capability_gate(
  "io_uring_enter",
  "to submit work to an io_uring event loop, which can reach any file or " ..
  "endpoint without asking about it")
policy.io_uring_register = capability_gate(
  "io_uring_register",
  "to register files or buffers with an io_uring event loop, which can then " ..
  "read and write them without asking about it")

-- Opening by handle. No path, so nothing for the tables above to hold; and its
-- `path` argument is not read on purpose, because it is a hint that decides
-- nothing and naming it would be worse than naming nothing.
policy.open_by_handle_at = capability_gate(
  "open_by_handle_at",
  "to open a file by an opaque handle, naming no path at all")

-- Taking the handle. This one *does* name a real path, so it is an ordinary
-- read-trust question: the user is vouching for this file being read, the same
-- promise `openat`'s read branch makes.
--
-- What that grant buys is narrower than it looks, and worth being plain about.
-- Remembering the path silences *taking* handles for it and nothing more:
-- spending one still asks, every time, because a `file_handle` carries no path
-- back to check against the table above. So the two halves are deliberately not
-- symmetrical — one is matchable and is matched, the other is not and is not.
policy.name_to_handle_at = function(sys)
  local path = sc.path(sys)
  return ask.ask_trust_read(
    path,
    "The process want to take an opaque handle for " .. tostring(path) ..
    ", which can then be opened without naming it again")
end

-- Everything else that reaches past the filesystem: no arguments worth reading,
-- and no use in a shell. One table because the only thing that differs between
-- them is the verb — which is also the honest summary of why each is here.
for name, what in pairs({
  memfd_create =
    "to create a file in memory, which has no path and so sits outside every " ..
    "trust table above",
  pidfd_getfd =
    "to take a file descriptor out of another process, and read whatever that " ..
    "process can read",
  process_vm_readv = "to read another process's memory",
  process_vm_writev = "to write another process's memory",
  bpf = "to load a program into the kernel",
  userfaultfd = "to watch another process's page faults",
  pkey_alloc = "to allocate a memory protection key",
  pkey_mprotect = "to change the protection key on a mapping",
  pkey_free = "to free a memory protection key",
}) do
  policy[name] = capability_gate(name, what)
end

return policy
end

return M
