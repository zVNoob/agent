//! The sandbox primitives `lua/lib/bash.lua` drives, and the introspection
//! they report through.
//!
//! `agent.bash` itself is Lua; what is left on this side is the substrate it
//! drives — `spawn`, `step`, `decide`, `kill`, `write`, `close_stdin` — plus the
//! work that makes a policy decision *checkable*: reading the tracee's `/proc`
//! (argv, cwd, C strings, socket addresses) and resolving a path the way the
//! kernel will, so a Lua policy can ask about the actual file rather than an
//! opaque pointer. None of these yield; the cadence lives in the Lua driver.
//!
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use mlua::{AnyUserData, Lua, Table, UserData};

use crate::seccomp::{self, CoroutineEvent, FdSlot, Step, Verdict};

use super::vm::err_to_mlua;

// ---------------------------------------------------------------------------
// Rust primitives called from Lua (never yield — see module docs)
// ---------------------------------------------------------------------------

/// `agent.api.spawn(cmdline, mask?) -> handle`.
///
/// Every *masked* syscall surfaces as a frozen [`Step::Blocked`] — the
/// decider always returns `Ask` — so decisions land entirely in Lua policy.
///
/// `mask` is the list of syscall names whose syscalls the filter traps:
/// anything not listed is not intercepted at all and runs straight through
/// the kernel under its default (allow). The engine always additionally
/// traps the fork family and auto-allows those it did not name (pid
/// bookkeeping). `nil`/absent = an **empty** mask — nothing is intercepted
/// except the engine's always-on fork family, which runs free: a raw
/// `agent.api.spawn(cmdline)` driver observes a plain run, not an ask loop.
/// An unknown name is a runtime error, so a policy typo cannot silently
/// trace nothing.
pub(super) fn lua_spawn(
    _: &Lua,
    (cmdline, mask): (String, Option<Vec<String>>),
) -> mlua::Result<SandboxHandle> {
    let mut nrs: Vec<i32> = Vec::new();
    if let Some(names) = mask {
        nrs.reserve(names.len());
        for name in names {
            let Some(nr) = seccomp::syscall_nr(&name) else {
                return Err(mlua::Error::RuntimeError(format!(
                    "agent.api.spawn: unknown syscall name in mask: {name:?}"
                )));
            };
            nrs.push(nr);
        }
    }
    let sb = seccomp::Sandbox::spawn("bash", &["-c", &cmdline], |_| Verdict::Ask, &nrs);
    let sb = sb.map_err(err_to_mlua)?;
    Ok(SandboxHandle(Rc::new(RefCell::new(sb))))
}

/// `agent.api.step(handle) -> step table` — one poll round + one non-blocking
/// engine step (mirrors `Sandbox::pump`'s poll loop, stopping at `Blocked`).
///
/// The poll is non-blocking (timeout 0) on a reactor-driven VM — an event
/// handler, where a blocking poll would freeze the loop; the pump suspends
/// between idle steps instead. Plain VMs keep the blocking poll.
///
/// Returns `{kind="blocked", syscall={..}}` (the asking thread is parked in
/// the kernel's notification wait), `{kind="output", stream, data}`,
/// `{kind="idle"}` (poll timed out; caller just loops), or
/// `{kind="finished", result={..}}`.
pub(super) fn lua_step(lua: &Lua, handle: AnyUserData) -> mlua::Result<Table> {
    let h = handle.borrow::<SandboxHandle>()?;
    let mut sb = h.0.borrow_mut();
    let slots = sb.poll_slots();
    if slots.is_empty() {
        // Nothing left to wait on: only the completion path remains.
        return match sb.step(0).map_err(err_to_mlua)? {
            Step::Finished(r) => finished_table(lua, r),
            other => Err(mlua::Error::RuntimeError(format!(
                "agent.api.step: tree gone but step returned {other:?}"
            ))),
        };
    }
    let mut pfds: Vec<libc::pollfd> = slots.iter().map(|(_, p)| *p).collect();
    // On a reactor-driven VM (an event handler, see [`EventRun`]) every step
    // must stay non-blocking: the pump's `drive` yields a cooperative cadence
    // between idle steps, so a poll(0) keeps each slice microsecond-sized and
    // the event loop live. Tool threads and headless runs keep the blocking
    // poll — there the poll *is* the wait.
    let timeout = if lua
        .globals()
        .get::<Table>("agent")
        .and_then(|a| a.get::<bool>("__on_reactor"))
        .unwrap_or(false)
    {
        0
    } else {
        seccomp::DEFAULT_POLL_TIMEOUT_MS
    };
    let pr = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, timeout) };
    if pr == -1 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR) {
            return idle_table(lua);
        }
        return Err(mlua::Error::RuntimeError(format!("agent.api.step: poll: {e}")));
    }
    if pr == 0 {
        return idle_table(lua);
    }
    let mut listener_revents = 0i16;
    for (k, p) in pfds.iter().enumerate() {
        if p.revents != 0 && slots[k].0 == FdSlot::Listener {
            listener_revents = p.revents;
        }
    }
    let step_res = sb.step(listener_revents).map_err(err_to_mlua)?;
    match step_res {
        Step::Blocked { syscall, .. } => {
            // Freeze every tree process *except* the asker before the string
            // deref + path resolution below: with the siblings SIGSTOP'd,
            // nothing can rewrite a symlink or the tracee's memory between
            // the policy's check and the kernel's own resolution of the
            // syscall — the TOCTOU gate. The asker is deliberately left to
            // the kernel's own park (a full-tree freeze would interrupt its
            // notification wait, discard the notification, and re-ask
            // forever). Thaw happens in `agent.api.decide` →
            // `Sandbox::resolve_ask_frozen`, once the allowed syscall has
            // executed; a raw `_step` consumer that never decides is released
            // by the resume() at the top of the next blocked step.
            sb.resume();
            sb.freeze_others(syscall.pid);
            let t = lua.create_table()?;
            t.set("kind", "blocked")?;
            t.set("syscall", syscall_into_table(lua, &syscall)?)?;
            Ok(t)
        }
        Step::Event(CoroutineEvent::Output { stream, data }) => {
            let t = lua.create_table()?;
            t.set("kind", "output")?;
            t.set(
                "stream",
                match stream {
                    seccomp::Stream::Stdout => "stdout",
                    seccomp::Stream::Stderr => "stderr",
                },
            )?;
            t.set("data", lua.create_string(&data)?)?;
            Ok(t)
        }
        // A decided syscall is only emitted for direct Allow/Deny decider
        // verdicts; the always-Ask decider never produces one.
        Step::Event(CoroutineEvent::Decided { .. }) => idle_table(lua),
        Step::Idle => idle_table(lua),
        Step::Finished(r) => finished_table(lua, r),
    }
}

/// `agent.api.decide(handle, verdict)` — resolve the pending syscall ask.
/// `true` → Allow (CONTINUE), `false` → Deny (final: tree is SIGKILLed).
pub(super) fn lua_decide(_: &Lua, (handle, verdict): (AnyUserData, bool)) -> mlua::Result<()> {
    let h = handle.borrow::<SandboxHandle>()?;
    let mut sb = h.0.borrow_mut();
    // The tree is frozen from `lua_step`'s Blocked arm (siblings SIGSTOP'd,
    // asker parked on its notification). `resolve_ask_frozen` answers the
    // ask and — for an Allow — holds the siblings until the allowed syscall
    // has executed before thawing, so the filesystem the policy resolved
    // against is still the one the kernel resolves. A Deny SIGKILLs the whole
    // tree inside resolve_ask; nothing is thawed.
    let verdict = if verdict {
        Verdict::Allow
    } else {
        Verdict::Deny(libc::EPERM)
    };
    sb.resolve_ask_frozen(verdict).map_err(err_to_mlua)?;
    Ok(())
}

/// `agent.api.kill(handle)` — SIGKILL the whole tree (idempotent; used for
/// interrupt/cancel and by the Lua driver's error paths).
pub(super) fn lua_kill(_: &Lua, handle: AnyUserData) -> mlua::Result<()> {
    let h = handle.borrow::<SandboxHandle>()?;
    h.0.borrow_mut().kill_tree();
    Ok(())
}

/// `agent.api.write(handle, data)` — feed bytes to the tracee's stdin pipe.
/// Non-blocking: what the pipe can take is written immediately, the rest is
/// queued and flushed by the engine once it reports `POLLOUT`; input after
/// EOF is dropped (see `Sandbox::queue_stdin`).
pub(super) fn lua_write_stdin(_: &Lua, (handle, data): (AnyUserData, mlua::LuaString)) -> mlua::Result<()> {
    let h = handle.borrow::<SandboxHandle>()?;
    let bytes = data.as_bytes();
    h.0.borrow_mut().queue_stdin(&bytes).map_err(err_to_mlua)
}

/// `agent.api.close_stdin(handle)` — close the tracee's stdin write end; its next
/// `read(0)` sees EOF once all copies are gone.
pub(super) fn lua_close_stdin(_: &Lua, handle: AnyUserData) -> mlua::Result<()> {
    let h = handle.borrow::<SandboxHandle>()?;
    h.0.borrow_mut().close_stdin();
    Ok(())
}

// ---------------------------------------------------------------------------
// Lua value helpers
// ---------------------------------------------------------------------------

pub(super) fn idle_table(lua: &Lua) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    t.set("kind", "idle")?;
    Ok(t)
}

pub(super) fn proc_cmdline(pid: i32) -> String {
    let raw = match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let mut args = Vec::new();
    for part in raw.split(|b| *b == 0) {
        if !part.is_empty() {
            args.push(String::from_utf8_lossy(part).into_owned());
        }
    }
    args.join(" ")
}

pub(super) fn syscall_into_table(lua: &Lua, s: &seccomp::Syscall) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    let name = s.name();
    t.set("name", name.as_str())?;
    t.set("nr", s.nr as i64)?;
    t.set("pid", s.pid as i64)?;
    // Which sandbox this call arrived in — the identity a policy scopes
    // per-run state to. See `Syscall::run`.
    t.set("run", s.run as i64)?;
    t.set("cmdline", proc_cmdline(s.pid))?;
    let args = lua.create_table()?;
    // u64 -> f64 is lossy for pointer-sized args; documented in module docs.
    for (i, arg) in s.args.iter().enumerate() {
        args.raw_set((i as i64) + 1, *arg as f64)?;
    }
    t.set("args", args)?;
    // `sys.addr`: the endpoint each naming syscall wants, decoded out of the
    // caller's memory (see `read_sockaddr`). 1-based, aligned with `args`.
    let addrs = lua.create_table()?;
    if let Some(positions) = sockaddr_positions(&name) {
        for &p in positions {
            // The sockaddr's own length is the next argument: `connect(fd, addr,
            // addrlen)`. Read it when the syscall has one, and fall back to the
            // family's own size when it does not (so a bogus 0 cannot shrink the
            // read below the family header).
            let len = s.args.get(p + 1).copied().unwrap_or(28);
            if let Some(t) = endpoint_into_lua(lua, s.pid, s.args[p], len)? {
                addrs.raw_set((p as i64) + 1, t)?;
            }
        }
    }
    t.set("addr", addrs)?;
    let strs = lua.create_table()?;
    if let Some(positions) = cstring_positions(&name) {
        let cwd = tracee_cwd(s.pid);
        for &p in positions {
            if let Some(text) = read_cstr(s.pid, s.args[p], CSTRING_CAP) {
                let text = if cwd_resolution_ok(&name, p, s.args) {
                    resolve_path(cwd.as_deref(), &text)
                } else {
                    // Relative to a caller-held dirfd we cannot see: the name
                    // passes through unresolved rather than mis-resolved.
                    text
                };
                strs.raw_set((p as i64) + 1, text)?;
            }
        }
    }
    t.set("str", strs)?;
    Ok(t)
}

pub(super) const CSTRING_CAP: usize = 4096;

pub(super) const CSTRING_ARGS: &[(&str, &[usize])] = &[
    ("execve", &[0]),
    ("execveat", &[1]),
    ("open", &[0]),
    ("creat", &[0]),
    ("openat", &[1]),
    ("openat2", &[1]),
    ("stat", &[0]),
    ("lstat", &[0]),
    ("newfstatat", &[1]),
    ("access", &[0]),
    ("faccessat", &[1]),
    ("readlink", &[0]),
    ("readlinkat", &[1]),
    ("unlink", &[0]),
    ("unlinkat", &[1]),
    ("rmdir", &[0]),
    ("mkdir", &[0]),
    ("mkdirat", &[1]),
    ("rename", &[0, 1]),
    // renameat(olddirfd, oldpath, newdirfd, newpath): the strings are 1 and 3.
    // Slot 2 is *newdirfd* — a small integer, not a pointer — and reading it as
    // a C string is how the second path came back nil for every rename, which
    // is why nothing had ever asked about one.
    ("renameat", &[1, 3]),
    ("renameat2", &[1, 3]),
    ("chdir", &[0]),
    ("chroot", &[0]),
    ("chmod", &[0]),
    ("fchmodat", &[1]),
    ("chown", &[0]),
    ("fchownat", &[1]),
    ("lchown", &[0]),
    ("truncate", &[0]),
    ("statfs", &[0]),
    ("link", &[0, 1]),
    // linkat(olddirfd, oldpath, newdirfd, newpath, flags): the same shape.
    ("linkat", &[1, 3]),
    ("symlink", &[0, 1]),
    // symlinkat(target, newdirfd, linkpath): the strings are 0 and 2.
    ("symlinkat", &[0, 2]),
    ("mount", &[0, 1, 2, 3]),
    ("umount2", &[0]),
    ("utime", &[0]),
    ("utimensat", &[1]),
    ("getxattr", &[0, 1]),
    ("lgetxattr", &[0, 1]),
    ("setxattr", &[0, 1]),
    ("lsetxattr", &[0, 1]),
    // removexattr(path, name): the name is a string argument too, and without
    // it a policy gating the call cannot say *which* attribute was removed —
    // which is the whole difference between `setcap -r` and an app tidying up
    // its own `user.*` metadata.
    ("removexattr", &[0, 1]),
    ("lremovexattr", &[0, 1]),
    ("inotify_add_watch", &[1]),
    ("name_to_handle_at", &[1]),
    // `open_by_handle_at(dirfd, mount_fd, flags, path, handle, …)` is the one
    // deliberate absence, and it is load-bearing: its `path` argument is a
    // component hint of at most 64 bytes used to make errors readable, and the
    // file actually opened is chosen by the opaque `file_handle`. Putting it in
    // this table would make `sc.path(sys)` return the last component of the
    // target's real path, so a policy asking about "the process want to read
    // `/shadow`" would be confidently wrong — a name the user can check, for a
    // decision about a different file. `lua/policy.lua` gates the call and asks
    // with no path at all, which is the truth. Pinned by
    // `open_by_handle_at_names_no_path_in_the_default_policy`.
];

/// The `sys.addr` positions for a syscall name: the `struct sockaddr *` each one
/// takes, 0-based, mirroring [`CSTRING_ARGS`].
///
pub(super) const SOCKADDR_ARGS: &[(&str, &[usize])] = &[
    ("connect", &[1]),
    ("bind", &[1]),
    ("sendto", &[1]),
];

pub(super) fn sockaddr_positions(name: &str) -> Option<&'static [usize]> {
    SOCKADDR_ARGS
        .iter()
        .find(|&&(n, _)| n == name)
        .map(|&(_, p)| p)
}

/// A named endpoint, read out of a `struct sockaddr` in the caller's memory.
///
pub(super) struct Endpoint {
    family: &'static str,
    ip: Option<String>,
    port: Option<u16>,
    /// `AF_UNIX` has a NUL-terminated path where an address would be.
    path: Option<String>,
}

pub(super) fn read_sockaddr(pid: i32, addr: u64, len: u64) -> Option<Endpoint> {
    if addr == 0 {
        return None;
    }
    // The family is the first 2 bytes; the rest is family-specific. Read the
    // largest body any family we handle needs (AF_INET6), bounded by the
    // caller's own `len` so a short buffer is not over-read.
    let want = len.clamp(2, 28) as usize;
    let mut buf = vec![0u8; want];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: want,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: want,
    };
    // SAFETY: `buf` is valid for `want` bytes; `addr` is a best-effort userland
    // pointer into the frozen target, which the kernel validates.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    match family {
        // AF_INET: sa_data[0..2] is sin_port (big-endian), [2..6] is sin_addr.
        2 if buf.len() >= 8 => Some(Endpoint {
            family: "inet",
            ip: Some(format!(
                "{}.{}.{}.{}",
                buf[4], buf[5], buf[6], buf[7]
            )),
            port: Some(u16::from_be_bytes([buf[2], buf[3]])),
            path: None,
        }),
        // AF_INET6: sin6_port then a 16-byte address plus a scope id.
        10 if buf.len() >= 24 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let scope = u32::from_ne_bytes([buf[20], buf[21], buf[22], buf[23]]);
            Some(Endpoint {
                family: "inet6",
                ip: Some(render_ipv6(&octets, scope)),
                port: Some(u16::from_be_bytes([buf[2], buf[3]])),
                path: None,
            })
        }
        // AF_UNIX: a NUL-terminated path in the same place an address would be.
        1 => {
            let body = &buf[2..];
            let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
            Some(Endpoint {
                family: "unix",
                ip: None,
                port: None,
                path: Some(String::from_utf8_lossy(&body[..end]).into_owned()),
            })
        }
        // A family we do not decode: report the number rather than guessing.
        other => Some(Endpoint {
            family: "other",
            ip: None,
            port: None,
            path: Some(format!("af{}", other)),
        }),
    }
}

pub(super) fn render_ipv6(octets: &[u8; 16], scope: u32) -> String {
    let mut out = String::with_capacity(45);
    for (i, pair) in octets.chunks(2).enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{:x}", u16::from_be_bytes([pair[0], pair[1]])));
    }
    if scope != 0 {
        out.push_str(&format!("%{scope}"));
    }
    out
}

pub(super) fn endpoint_into_lua(lua: &Lua, pid: i32, ptr: u64, len: u64) -> mlua::Result<Option<Table>> {
    let Some(e) = read_sockaddr(pid, ptr, len) else {
        return Ok(None);
    };
    let t = lua.create_table()?;
    t.set("family", e.family)?;
    if let Some(ip) = e.ip {
        t.set("ip", ip)?;
    }
    if let Some(port) = e.port {
        t.set("port", port as i64)?;
    }
    if let Some(path) = e.path {
        t.set("path", path)?;
    }
    Ok(Some(t))
}

pub(super) fn cstring_positions(name: &str) -> Option<&'static [usize]> {
    CSTRING_ARGS
        .iter()
        .find(|&&(n, _)| n == name)
        .map(|&(_, p)| p)
}

pub(super) fn read_cstr(pid: i32, addr: u64, cap: usize) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(cap.min(4096));
    let mut cur = addr;
    while out.len() < cap {
        let want = (cap - out.len()).min(4096);
        let mut buf = vec![0u8; want];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: want,
        };
        let remote = libc::iovec {
            iov_base: cur as *mut libc::c_void,
            iov_len: want,
        };
        // SAFETY: `buf` is valid for `want` bytes; `cur` is a best-effort
        // userland pointer into the frozen target; the kernel validates it.
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            return None;
        }
        let n = n as usize;
        if n == 0 {
            return None;
        }
        if let Some(z) = buf[..n].iter().position(|&b| b == 0) {
            out.extend_from_slice(&buf[..z]);
            break;
        }
        out.extend_from_slice(&buf[..n]);
        cur += n as u64;
    }
    if out.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

pub(super) fn tracee_cwd(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

/// The `args` slot holding the *directory fd* each path argument of a syscall
/// resolves against, as `(path slot, dirfd slot)` pairs, 0-based — the dirfd
/// family: the syscalls whose relative pathnames resolve against a
/// caller-supplied fd instead of the cwd (`openat`, `newfstatat`, `renameat`,
/// `execveat`, ...).
///
/// **Per path, not per syscall.** The two-path `*at` calls have *two* dirfds,
/// and one slot for the syscall resolves a rename's target against the
/// *source's* directory — which is a wrong answer rather than a missing one, and
/// the kind that only shows up once a command bothers to open a directory and
/// rename into it.
///
pub(super) const DIRFD_FOR_PATH: &[(&str, &[(usize, usize)])] = &[
    ("execveat", &[(1, 0)]),
    ("openat", &[(1, 0)]),
    ("openat2", &[(1, 0)]),
    ("newfstatat", &[(1, 0)]),
    ("faccessat", &[(1, 0)]),
    ("readlinkat", &[(1, 0)]),
    ("unlinkat", &[(1, 0)]),
    ("mkdirat", &[(1, 0)]),
    ("renameat", &[(1, 0), (3, 2)]),
    ("renameat2", &[(1, 0), (3, 2)]),
    ("linkat", &[(1, 0), (3, 2)]),
    ("symlinkat", &[(2, 1)]),
    ("utimensat", &[(1, 0)]),
    ("fchmodat", &[(1, 0)]),
    ("fchownat", &[(1, 0)]),
    ("inotify_add_watch", &[(1, 0)]),
    ("name_to_handle_at", &[(1, 0)]),
];

pub(super) fn dirfd_slot_for(sys_name: &str, path_slot: usize) -> Option<usize> {
    DIRFD_FOR_PATH
        .iter()
        .find(|&&(n, _)| n == sys_name)
        .and_then(|&(_, pairs)| {
            pairs
                .iter()
                .find(|&&(p, _)| p == path_slot)
                .map(|&(_, fd)| fd)
        })
}

pub(super) fn cwd_resolution_ok(sys_name: &str, p: usize, args: [u64; 6]) -> bool {
    match dirfd_slot_for(sys_name, p) {
        None => true,                                // plain pathname syscall
        Some(f) => args[f] == libc::AT_FDCWD as u64, // the fd slot says "cwd"?
    }
}

/// Resolve `name` (a pathname syscall arg) to the *actual* file or directory
/// it names on disk, from the tracee's filesystem context (`cwd` is the
/// tracee's cwd, see [`tracee_cwd`]):
///
/// 1. relative names are joined to the tracee's cwd (the supervisor's cwd as
///    a last resort);
/// 2. a resolvable path is canonicalized — symlinks chased, `..` collapsed —
///    producing the actual path (this settles an existing file's real identity);
/// 3. when the tail does not exist yet (open-for-create, `unlink`, rename
///    targets, ...) the existing prefix is still chased, but only refinements
///    *over the input* are handed back: a symlinked or `..`-carrying path
///    becomes its actual directory plus the literal tail, and anything that
///    already names that directory (plain absolute paths, plain cwd-relative
///    names) passes the original name through — per the contract, an
///    unresolvable file is reported as the name it was asked by. A *dangling*
///    symlink (target does not exist yet) is followed to where it points, so
///    the intended location still lands, capped like the kernel (40 hops:
///    chains unwind, cycles give up and stay literal);
/// 4. when even the prefix cannot be established the name passes through
///    unchanged — Lua still gets a string it can ask-and-remember on.
///
pub(super) fn resolve_path(cwd: Option<&Path>, name: &str) -> String {
    if name.is_empty() {
        return name.to_string();
    }
    if name.starts_with('/') {
        return resolve_joined(Path::new(name), name);
    }
    let Some(base) = cwd
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())
    else {
        return name.to_string();
    };
    let joined = base.join(name);
    resolve_joined(&joined, name)
}

pub(super) const MAX_SYMLINK_HOPS: usize = 40;

pub(super) fn dangling_target(cand: &Path) -> Option<PathBuf> {
    let meta = std::fs::symlink_metadata(cand).ok()?;
    if !meta.file_type().is_symlink() {
        return None;
    }
    let link = std::fs::read_link(cand).ok()?;
    Some(if link.is_absolute() {
        link
    } else {
        cand.parent()?.join(link)
    })
}

pub(super) fn resolve_joined(joined: &Path, fallback: &str) -> String {
    // Full resolution first: the file exists, chase everything.
    if let Ok(real) = std::fs::canonicalize(joined) {
        return real.to_string_lossy().into_owned();
    }
    // The tail is missing: chase the existing prefix component by component
    // and keep the rest literal, so symlink/`..` chases still apply where
    // they can. A component that is itself a dangling symlink is followed to
    // where it points, so the walk keeps going against the intended target.
    let mut out = PathBuf::from("/");
    let mut pending: std::collections::VecDeque<std::ffi::OsString> = joined
        .components()
        .map(|c| c.as_os_str().to_os_string())
        .collect();
    let mut hops = 0usize;
    let mut literal = false;
    while let Some(seg) = pending.pop_front() {
        let text = seg.to_string_lossy();
        if literal {
            match text.as_ref() {
                ".." => {
                    out.pop();
                }
                "." | "/" => {}
                _ => out.push(&seg),
            }
            continue;
        }
        match text.as_ref() {
            // joined is absolute here (resolve_path made it so) and "." is a
            // no-op — both collapse to nothing.
            "/" | "." => {}
            ".." => {
                out.pop();
            }
            _ => {
                let cand = out.join(&seg);
                match std::fs::canonicalize(&cand) {
                    Ok(p) => out = p,
                    Err(_) => {
                        // Unresolvable so far: within the hop budget, a
                        // dangling symlink rebases the whole walk onto where
                        // it points (its target is absolute, so the pending
                        // walk restarts there and the still-waiting components
                        // follow it).
                        if hops < MAX_SYMLINK_HOPS
                            && let Some(target) = dangling_target(&cand)
                        {
                            hops += 1;
                            let rest: Vec<_> = pending.drain(..).collect();
                            let mut rebase: Vec<_> = target
                                .components()
                                .map(|c| c.as_os_str().to_os_string())
                                .collect();
                            rebase.extend(rest);
                            pending = rebase.into();
                            out = PathBuf::from("/");
                            continue;
                        }
                        // Over budget (cycles) or genuinely missing: keep the
                        // form and go literal from here.
                        out.push(&seg);
                        literal = true;
                    }
                }
            }
        }
    }
    let resolved = out.to_string_lossy().into_owned();
    // Hand the refined form back only when it reflects the actual filesystem
    // (a symlink or `..` chased, or a relative name made concrete); otherwise
    // pass the original name along unchanged.
    if resolved != joined.to_string_lossy() {
        resolved
    } else {
        fallback.to_string()
    }
}

pub(super) fn finished_table(lua: &Lua, r: seccomp::SandboxResult) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    t.set("kind", "finished")?;
    let result = lua.create_table()?;
    result.set("stdout", lua.create_string(&r.stdout)?)?;
    result.set("stderr", lua.create_string(&r.stderr)?)?;
    let exit = lua.create_table()?;
    if let Some(code) = r.exit.code {
        exit.set("code", code as i64)?;
    }
    if let Some(sig) = r.exit.signal {
        exit.set("signal", sig as i64)?;
    }
    result.set("exit", exit)?;
    result.set("syscalls", r.syscalls as i64)?;
    result.set("denied", r.denied as i64)?;
    // Always present, so `bash` can read it without a nil check, and true only
    // when the user stopped the run. A killed tree and a command that failed on
    // its own look identical without it — same signal, same exit — and the
    // model reads "you interrupted this" very differently from "this broke".
    result.set("interrupted", r.interrupted)?;
    t.set("result", result)?;
    Ok(t)
}

// `agent.bash` itself is Lua (`lua/lib/bash.lua`); what is left on this side is
// the substrate it drives: `spawn`, `step`, `decide`, `kill`, `write` and
// `close_stdin`, over `seccomp::Sandbox`.

/// The sandbox handle handed to Lua. A single-owner wrapper around the live
/// [`seccomp::Sandbox`]; dropping the userdata (GC, coroutine unwind,
/// `agent.api.kill`) runs the engine's destructor, which SIGKILLs the whole tree
/// (see `src/seccomp/`).
pub(super) struct SandboxHandle(pub(super) Rc<RefCell<seccomp::Sandbox>>);

impl UserData for SandboxHandle {}
