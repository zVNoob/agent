-- policy.lua — the default sandbox policy behind the shipped `bash` tool.
--
-- Returned by `require("policy")`, and the whole reason a shell run is something
-- the user agreed to rather than something it just did: **every** file it opens
-- and **every** endpoint it reaches is **asked** first.
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
--   connect  the process want to access {hostname} ({IP}) at port {port}
--            The target it wants to *reach*. The hostname is a reverse lookup and
--            is dropped when there is none; the address is the ground truth.
--
--   bind     the process want to open port {port} on {address}
--            The address it wants to *listen* on. (`listen()` is not gated: it
--            names no address, it only marks an already-bound socket as
--            accepting, so there is nothing to ask about.)
--
--   sendto   the process want to send to {hostname} ({IP}) at port {port}
--            UDP egress, which is `connect` without a handshake: a datagram
--            leaves and the peer never replies, so nothing downstream would ever
--            notice. It is in the mask for exactly that reason.
--
-- Everything *not* named above is not intercepted at all — it runs straight
-- through the kernel under its default (allow). So read this as what it is: a
-- filter that asks about files and endpoints, not a jail. The sandbox is a bare
-- `fork()` with no `unshare`, so a command keeps the host's filesystem view and
-- the host's network namespace; `ss` or `/proc/net/tcp` will list every listener
-- on the machine, and anything bound to 127.0.0.1 that a command can guess is
-- reachable. Asking is not confining.
--
-- ## What "always" remembers
--
-- A file question is remembered by the path tables in `agent.ask`
-- (`ask_trust_read` / `ask_trust_write`); a network question by the
-- trustworthy-server table (`ask_server`): a host, or one `host:port`. Separate
-- tables on purpose — a trusted file is not a trusted peer, and forgetting one
-- must never forget the other. A plain `yes` is for that one operation; only
-- `always` is recorded, and both tables live on the agent's own VM, so a grant
-- outlives the call that made it.
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

local policy = {}

-- Every open is asked, read or write. The tty probe is bash checking whether it
-- has a terminal, not a file the user means, and asking about it would interrupt
-- the first syscall of every command.
policy.openat = function(sys)
  local flags = sc.arg(sys, "openat")
  if sc.is_tty_probe(flags) then return true end
  local path = sc.path(sys)
  if sc.check("openat", flags, "WRITE") then
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

-- UDP egress: the same question, and the same gate, for a datagram.
policy.sendto = function(sys)
  local addr = sc.addr(sys)
  local host, port = server_key(addr)
  return ask.ask_server(host, port, reach_question("send to", addr))
end

return policy
