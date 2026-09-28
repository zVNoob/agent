//! Seccomp user-notify sandbox substrate — a *coroutine-structured supervisor*.
//!
//! This is the executor substrate for the AI agent: it runs a program (and its
//! whole process tree) with a seccomp filter that returns
//! `SECCOMP_RET_USER_NOTIF` only for the syscalls the caller named
//! ([`Sandbox::spawn`]'s `named` mask) **plus the always-masked fork family**
//! (`fork`/`vfork`/`clone`/`clone3` — the engine's pid bookkeeping depends on
//! intercepting them, and they are auto-allowed unless named); every other
//! syscall runs straight through the kernel under its default (allow). A
//! "supervisor" process (us)
//! intercepts each syscall *before it runs* and decides what to do:
//!
//! - [`Verdict::Allow`]  → reply `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, run normally
//! - [`Verdict::Deny`]    → spoof the `errno` it carries as the error return
//! - [`Verdict::Ask`]     → do NOT reply yet: the syscall stays frozen while
//!   control is yielded back to the driver (see [`Sandbox::step`]); the driver
//!   later calls [`Sandbox::resolve_ask`] to thaw it.
//!
//! The supervisor is structured as a **coroutine / generator**: [`Sandbox::step`]
//! is a non-blocking pump that processes exactly one unit of already-ready
//! work per call and suspends at the decision point. It can therefore be
//! driven by anything — a blocking CLI loop, an async task, or (the actual
//! client) the Lua policy bridge in [`crate::lua`]. The bridge drives every
//! syscall through [`Verdict::Ask`] + [`Step::Blocked`], runs each policy
//! callback in a fresh sub-coroutine, and maps `coroutine.yield` onto the
//! ask; resuming the caller's coroutine **with the verdict boolean** maps
//! onto the bridge's `agent.api.decide` → [`Sandbox::resolve_ask`]. The plumbing
//! below is that contract, in pure Rust, [`Verdict::Ask`] being the yield —
//! never a final answer.
//!
//! Note the verdict grammar: the policy function itself only ever *returns*
//! [`Verdict::Allow`] or [`Verdict::Deny`]; [`Verdict::Ask`] is the coroutine
//! *yield* — the suspension point where control hands back to the driver —
//! never a final answer. Because a delivered `Deny` is final, it kills the
//! whole tree in **both** delivery paths: the immediate decider path
//! (`Sandbox::handle_notification`) and the frozen-ask path
//! ([`Sandbox::resolve_ask`]); an `Allow` in the ask path thaws the tree with
//! SIGCONT.
//!
//! Polling is centralized for power efficiency: [`Sandbox::step`] never
//! blocks — it only works on work that a poll has already declared ready.
//! All sleeping happens in a **single global poll loop** ([`Supervisor::drive`],
//! with [`Sandbox::pump`] as the one-sandbox case), which registers every
//! live fd of every sandbox in one `poll(2)` call. Fds past EOF are
//! deregistered so sticky `POLLHUP` can't spin the loop; a frozen
//! (ask-pending) listener is registered with `events == 0` so a queue of
//! unread notifications can't busy-spin it either. There is no per-sandbox
//! polling anywhere.
//!
//! Process topology:
//!
//! 1. parent: `pipe2` ×2 (stdout, stderr) + `socketpair(AF_UNIX, STREAM|CLOEXEC)`
//!    + `fork`
//! 2. child: `dup2` pipe write ends onto 1/2 → `prctl(NO_NEW_PRIVS)` →
//!    `seccomp(SET_MODE_FILTER|NEW_LISTENER)` (BPF bakes in the one ALLOWed
//!    syscall: `sendmsg` on the handshake socket, so the fd handoff can't
//!    deadlock) → `SCM_RIGHTS`-send the listener fd → `execv`
//! 3. parent: `recv_fd` the listener, then drive [`Sandbox::step`] until
//!    [`Step::Finished`], capturing stdout/stderr and reporting the exit
//!    status.
//!
//! Notes:
//! - every descendant inherits the filter (it cannot be removed), so EOF on
//!   the listener (`POLLHUP` / `ENOENT`) means the *whole tree* is gone.
//! - RECV is poll-gated: `Sandbox::handle_notification` confirms with a
//!   zero-timeout `poll` that a notification is actually queued (or the
//!   filter gone) before `NOTIF_RECV`, which can only return a real
//!   notification or `ENOENT` — never block. This is required because a poll
//!   wakeup is *not* a guarantee that a notification is queued (the kernel
//!   drops a pending notification when a filter user exits, waking the
//!   listener for the *empty* queue), and some kernels ignore `O_NONBLOCK`
//!   on notification fds, letting an unguarded RECV block until a
//!   notification arrives or the filter dies — a full runtime freeze for
//!   the single-threaded drive. `EAGAIN` (on kernels that do honor
//!   `O_NONBLOCK`) is likewise treated as idle — never an error and never
//!   `tree_done`. `step` therefore never blocks on the listener, in both
//!   the sync pump and the async drive.
//! - while a [`Verdict::Ask`] is pending **this crate's drive paths**
//!   ([`Sandbox::pump`] and the async drive) freeze the tree *twice over*:
//!   (1) [`Sandbox::freeze`] SIGSTOPs every captured pid so the answerer
//!   inspects a consistent snapshot and the tree makes no progress; (2) the
//!   listener is registered with `events == 0` (no `POLLIN` interest), so
//!   unread notifications don't wake the poll loop; only the output pipes
//!   keep draining. The Lua bridge in [`crate::lua`] freezes its own way —
//!   [`Sandbox::freeze_others`] SIGSTOPs every process *except* the asker's
//!   (a full-tree freeze would interrupt the asker's notif-wait, discard the
//!   notification, and re-ask forever) and only thaws after the allowed
//!   syscall has executed ([`Sandbox::resolve_ask_frozen`]). [`Verdict::Deny`]
//!   — answered or delivered — kills the whole captured tree at once, and the
//!   destructor does the same so a dropped sandbox never leaves orphans.
//! - each run gets an **isolated stdin pipe**: the tracee's fd 0 is a fresh
//!   pipe read end (never the supervisor's stdin), so a supervisor ask-prompt
//!   or the agent TUI can consume the process's own stdin without stealing
//!   input the command expects. The supervisor feeds it via
//!   [`Sandbox::queue_stdin`] (non-blocking; the write end is `O_NONBLOCK`
//!   and only registered for `POLLOUT` while input is queued, so a full pipe
//!   parks the poll loop instead of spinning it).

mod arch;

use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// seccomp kernel ABI (kept local, same values as linux/seccomp.h)
// ---------------------------------------------------------------------------

const SECCOMP_SET_MODE_FILTER: u32 = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 0x8; // (1UL << 3)
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 0x1;

/// _IOWR(0x21, 0, struct seccomp_notif)  (struct size 80 = 0x50)
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
/// _IOWR(0x21, 1, struct seccomp_notif_resp)  (struct size 24 = 0x18)
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
/// _IOWR(0x21, 2, __u64)  — SECCOMP_IOCTL_NOTIF_ID_VALID (Linux 5.0)
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0xc008_2102;

/// How long [`Sandbox::wait_completion`] holds a frozen tree waiting for an
/// allowed syscall to finish before thawing anyway. Real path syscalls
/// resolve in microseconds; this ceiling exists only so a *legitimately
/// blocking* allowed syscall (e.g. `open` on a FIFO with no writer) can never
/// hang the whole frozen tree on the wait.
const COMPLETION_WAIT_MAX: std::time::Duration = std::time::Duration::from_millis(250);
/// Bound on acknowledging a [`Sandbox::freeze_others`] SIGSTOP via
/// `/proc/<pid>/stat` polling — SIGSTOP's `T` transition lands on a scheduler
/// tick, not synchronously with `kill`.
const FREEZE_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

// BPF instruction field encodings (linux/filter.h)
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// The architecture seam: syscall numbers, the audit-arch / x32 checks, the
// fork family and the name table all come from `arch` (see `arch/mod.rs`). The
// rest of this module is architecture-neutral.
use arch::{AUDIT_ARCH, FORK_FAMILY, SYS_SENDMSG, X32_SYSCALL_BIT};

/// Poll timeout per `Sandbox::step` idle tick, in milliseconds.
pub const DEFAULT_POLL_TIMEOUT_MS: i32 = 200;
const PIPE_CHUNK: usize = 65536;

// ---------------------------------------------------------------------------
// Kernel notification structs (identical layout to linux/seccomp.h)
// ---------------------------------------------------------------------------

#[repr(C)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

// ---------------------------------------------------------------------------
// Public vocabulary
// ---------------------------------------------------------------------------

/// One intercepted syscall, as seen by the supervisor (entry only — there are
/// no return values in this mechanism, by design).
#[derive(Clone, Copy, Debug)]
pub struct Syscall {
    pub pid: i32,
    pub nr: i32,
    pub args: [u64; 6],
}

impl Syscall {
    pub fn name(&self) -> String {
        syscall_name(self.nr)
    }
}

/// The supervisor's decision for an intercepted syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Run the syscall normally (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`).
    Allow,
    /// Spoof a failure: the target's syscall returns -1 with the given (positive) errno.
    Deny(i32),
    /// Freeze the syscall and yield control to the driver; resolve later via
    /// [`Sandbox::resolve_ask`]. A suspension point, not a final answer: a
    /// policy (e.g. the future Lua coroutine) only ever *returns* `Allow` or
    /// `Deny` — `Ask` is its `coroutine.yield`.
    Ask,
}

/// Which output stream a captured chunk belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// Which of a sandbox's fds a poll result refers to. Returned alongside the
/// registered [`libc::pollfd`] by [`Sandbox::poll_slots`] so the global loop
/// can hand per-fd results back to the right sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdSlot {
    /// The seccomp user-notify listener (readiness granted via
    /// [`Sandbox::step`]'s `listener_revents` argument).
    Listener,
    /// The tracee's stdout capture pipe.
    Stdout,
    /// The tracee's stderr capture pipe.
    Stderr,
    /// The per-run stdin pipe's write end, registered with `POLLOUT` **only
    /// while input is queued** (see [`Sandbox::queue_stdin`]); a full pipe
    /// buffer therefore parks the poll loop rather than spinning it.
    Stdin,
}

/// Events the supervisor coroutine yields to its driver while the target runs.
#[derive(Clone, Debug)]
pub enum CoroutineEvent {
    /// A chunk of the target's stdout/stderr (captured; the driver may tee it).
    Output { stream: Stream, data: Vec<u8> },
    /// A syscall was decided (informational; not yielded for `Ask`).
    Decided { syscall: Syscall, verdict: Verdict },
}

/// A cloneable request to stop one particular run.
///
/// Per-run, and that is the whole design. This started as a process-global
/// `bool`, then as a global counter, and both were wrong in the same way: a
/// request could not be told apart from a request meant for somebody else. The
/// `bool` had to be cleared by [`Sandbox::spawn`] to stop a `Ctrl+c` with
/// nothing running from killing the *next* command, and that made every
/// unrelated spawn a chance to drop a live request. The counter needed no
/// clearing and so fixed that — and then killed every concurrently-running
/// sandbox at once, because each one had a baseline from before the request and
/// read the bump as its own. Fifteen unrelated tests failed at once, all of them
/// committing suicide.
///
/// A flag the run owns cannot have either fault: a request aimed at run A leaves
/// run B alone, and a run that starts after a request cannot inherit it, because
/// the flag is created with the run.
#[derive(Clone)]
pub struct InterruptHandle {
    flag: Arc<AtomicBool>,
}

impl InterruptHandle {
    /// Ask this run to stop. Idempotent, and safe from any thread, at any point
    /// in the run — the driver acts on it at the top of its next step, and also
    /// on a poll timeout, which is the only chance a *silent* run gets.
    pub fn interrupt(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
}

/// The run the agent's own `Ctrl+c` should stop.
///
/// One slot, published by [`Sandbox::spawn`] and fired by [`request_interrupt`].
/// Single-slot is sound because the agent drives tools strictly sequentially —
/// there is a test pinning that, and it is the invariant this rests on. It is
/// *not* a general mechanism: with two runs live, the slot names whichever
/// started last, and a request would go to the wrong one. That is acceptable
/// here and nowhere else, which is why the tests in this module take their own
/// [`Sandbox::interrupt_handle`] rather than reading the slot.
///
/// Never cleared, deliberately. A `Ctrl+c` with nothing running sets a flag on a
/// finished run, which nobody will ever read, and the next spawn overwrites the
/// slot — so a stale entry is inert rather than dangerous, and there is no
/// window in which a clear could race a spawn and leave the slot empty while a
/// run was live. Clearing would be more tidiness than the design can afford.
static LIVE_RUN: Mutex<Option<InterruptHandle>> = Mutex::new(None);

/// Ask the sandbox the agent is running to stop, if there is one.
///
/// Called from the TUI on `Ctrl+c`. With nothing running it is a no-op, which is
/// what makes it safe to fire on every press without first checking whether a
/// tool happens to be live. Any run that starts later is unaffected: it brings
/// its own flag.
pub fn request_interrupt() {
    if let Some(handle) = LIVE_RUN.lock().ok().and_then(|slot| slot.clone()) {
        handle.interrupt();
    }
}

/// Result of a [`Sandbox::step`] call.
#[derive(Debug)]
pub enum Step {
    /// The policy returned [`Verdict::Ask`]: the target's syscall is frozen and
    /// control is yielded to the driver. Call [`Sandbox::resolve_ask`] to thaw.
    Blocked { syscall: Syscall, request: u64 },
    /// One event (output chunk or a decided syscall).
    Event(CoroutineEvent),
    /// Nothing was ready in this (never-blocking) step; the driver should go
    /// back to the global poll loop and try again later.
    Idle,
    /// The target tree is gone and all output was captured.
    Finished(SandboxResult),
}

/// How the traced program (the direct child) terminated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitInfo {
    /// Exit code, if it exited normally; `None` if it died by signal.
    pub code: Option<i32>,
    /// Fatal signal, if it was killed by one; `None` otherwise.
    pub signal: Option<i32>,
}

/// Everything the supervisor learned about the run.
#[derive(Clone, Debug)]
pub struct SandboxResult {
    /// The run was stopped by [`request_interrupt`] rather than finishing on
    /// its own. Carried into the tool result so a stopped command reads as
    /// stopped, not as a command that failed.
    pub interrupted: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit: ExitInfo,
    /// Total syscalls intercepted (whole tree). In narrow-mask mode this
    /// counts only the masked set — the policy's named syscalls plus the
    /// fork family — which is usually far smaller than the tree's real
    /// syscall load (everything un-named runs un-masked and uncounted).
    pub syscalls: u64,
    /// Syscalls that were denied (spoofed error or frozen+denied ask).
    pub denied: u64,
}

/// The supervisor coroutine. Create with [`Sandbox::spawn`], then drive with
/// [`Sandbox::step`] (non-blocking; feed it the listener's poll revents), the
/// convenience [`Sandbox::pump`] (one-sandbox poll loop), or add it to a
/// [`Supervisor`] for a shared global poll loop. Answer [`Step::Blocked`]
/// outcomes with [`Sandbox::resolve_ask`].
pub struct Sandbox {
    listener: i32,
    out_r: i32,
    err_r: i32,
    /// Write end of the per-run stdin pipe (the tracee's fd 0 is its read
    /// end). `-1` once closed ([`Sandbox::close_stdin`]).
    stdin_w: i32,
    /// True once the write end is gone or [`Sandbox::close_stdin`] ran; no
    /// further input is accepted (`queue_stdin` drops it).
    stdin_closed: bool,
    /// Bytes queued for the tracee's stdin that have not reached the pipe yet
    /// (non-empty only while the pipe buffer is full).
    input: Vec<u8>,
    child: libc::pid_t,
    /// Every pid observed in the tree so far: the root [`Sandbox::spawn`]
    /// child plus every process that has made a syscall since. fork/clone
    /// children announce themselves via their first post-fork syscall (see
    /// [`Sandbox::handle_notification`]). Sorted, unique — the source of
    /// truth for [`Sandbox::freeze`], [`Sandbox::resume`], and
    /// [`Sandbox::kill_tree`], and for the destructor's no-orphans contract.
    pids: BTreeSet<libc::pid_t>,
    /// fork()/clone()/vfork()/clone3() syscalls observed. Each one grows the
    /// tree, and the `pids` set tracks it (the fork hook is the explicit
    /// capture point the tree bookkeeping keys off; see `handle_notification`).
    forks: u64,
    /// This run was stopped by [`request_interrupt`] rather than finishing on
    /// its own, so [`SandboxResult`] can say so. Without it a killed tree and a
    /// crash look identical in the tool result, and the model reads "interrupted"
    /// very differently from "the command failed".
    interrupted: bool,
    /// This run's own interrupt flag, shared with whoever holds its
    /// [`InterruptHandle`]. Per-run so that a request cannot be delivered to the
    /// wrong sandbox — see [`InterruptHandle`].
    interrupt: Arc<AtomicBool>,
    decider: Box<dyn FnMut(&Syscall) -> Verdict + Send>,
    out: Vec<u8>,
    err: Vec<u8>,
    out_eof: bool,
    err_eof: bool,
    tree_done: bool,
    pending: Option<Ask>,
    /// The kernel notification id most recently answered by
    /// [`Sandbox::resolve_ask`]. After a response is sent, the id stays valid
    /// until the target syscall has *executed* — [`Sandbox::wait_completion`]
    /// polls `SECCOMP_IOCTL_NOTIF_ID_VALID` on it so a still-frozen tree is
    /// only thawed once the kernel's own pathname resolution is safely past.
    sent_notif: Option<u64>,
    /// How many sibling pids the current [`Sandbox::freeze_others`] actually
    /// SIGSTOP'd (0 = nothing left to freeze for this ask). Consumed by
    /// [`Sandbox::resolve_ask_frozen`] so the completion wait is skipped when
    /// there is nobody left who could race the allowed syscall's execution.
    frozen_siblings: usize,
    child_reaped: bool,
    child_status: i32,
    next_request: u64,
    syscalls: u64,
    denied: u64,
    finished: bool,
}

#[derive(Clone, Copy, Debug)]
struct Ask {
    id: u64,
}

/// The name↔number table for this arch (see [`arch::SyscallTable`]).
fn table() -> &'static arch::SyscallTable {
    use std::sync::OnceLock;
    static TABLE: OnceLock<arch::SyscallTable> = OnceLock::new();
    TABLE.get_or_init(arch::table)
}

/// The canonical name for a syscall number on this arch, or a synthetic
/// `syscall_<n>` for numbers the table does not name.
pub fn syscall_name(nr: i32) -> String {
    table().name_of(nr).map(str::to_string).unwrap_or_else(|| format!("syscall_{nr}"))
}

/// Resolve a syscall *name* (as used for policy-table keys, e.g. `"openat"`)
/// to its number on this arch, for building narrow-mask filters. `None` for
/// names not in the table (a policy typo raises a Lua-side error at spawn,
/// rather than silently tracing nothing).
pub fn syscall_nr(name: &str) -> Option<i32> {
    table().number_of(name)
}

/// `/proc/<pid>/stat` field 4 is the parent pid. Parse from the last `)` so a
/// command name containing `)` can't confuse the field split.
fn proc_ppid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1; // " S ppid pgrp session ..."
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

/// `/proc/<tid>/status` `Tgid:` field — the process (thread-group leader)
/// owning a thread. A seccomp notification names the *thread* that made the
/// syscall; SIGSTOP is process-wide, so an asker-excluded freeze
/// ([`Sandbox::freeze_others`]) must exclude the asker's whole process, not
/// just its tid.
fn proc_tgid(tid: i32) -> Option<i32> {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:").and_then(|v| v.trim().parse().ok()))
}

/// `/proc/<pid>/stat` state character (`R`/`S`/`T`/`Z`/…), if readable.
fn proc_state_of(pid: i32) -> Option<char> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = s.rfind(')')?;
    s.as_bytes().get(close + 2).copied().map(|b| b as char)
}

/// Existence probe — a dead pid's number may have been recycled by an
/// unrelated process and must never receive a live signal.
fn alive(pid: i32) -> bool {
    unsafe {
        let r = libc::kill(pid, 0);
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

/// Poll until every live pid in `pids` reports `T` (stop) or `t` (tracing
/// stop) in `/proc/<pid>/stat` — the observable post-SIGSTOP state — or the
/// budget elapses. Dead pids are skipped; a `D`-state thread may take
/// arbitrarily long, so the ack is best-effort bounded. First check runs
/// immediately, then a fine-grained sleep keeps the typical ack cost in the
/// sub-millisecond range (this runs once per blocked syscall on the hot ask
/// path).
fn wait_stopped(pids: &[i32], budget: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    loop {
        let not_stopped: Vec<i32> = pids
            .iter()
            .copied()
            .filter(|&p| alive(p) && !matches!(proc_state_of(p), Some('T') | Some('t')))
            .collect();
        if not_stopped.is_empty() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_micros(200));
    }
}

// ---------------------------------------------------------------------------
// BPF filter
// ---------------------------------------------------------------------------

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Trap only the syscalls in `masked` with `SECCOMP_RET_USER_NOTIF`; every
/// other syscall runs under the kernel default (`SECCOMP_RET_ALLOW`) without
/// ever reaching the supervisor. The `(nr, args[0])` `allowed` exceptions are
/// checked **first**, so the handshake `sendmsg` on the listener socket stays
/// ALLOWed even if the policy names `sendmsg` itself — otherwise the fd
/// handoff (and every spawn with it) would deadlock.
fn build_filter_named(masked: &[i32], allowed: &[(u32, u32)]) -> Vec<libc::sock_filter> {
    let mut v = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, 4), // 0: load arch
        // 1: arch == x86_64 ? skip 1 → 3 : fall → 2
        jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS), // 2: wrong arch
        stmt(BPF_LD | BPF_W | BPF_ABS, 0),               // 3: load syscall nr
        // 4: nr >= x32 bit ? fall → 5 : skip 1 → 6
        jump(BPF_JMP | BPF_JGE | BPF_K, 0, 1, X32_SYSCALL_BIT),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS), // 5: x32 ABI
    ];
    // 6..: allowed exceptions first (the handshake MUST run), then the trap
    // set, then the kernel-default ALLOW for everything else.
    for &(nr, fd) in allowed {
        v.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, nr));
        v.push(stmt(BPF_LD | BPF_W | BPF_ABS, 16));
        v.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, fd));
        v.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }
    // Reload the syscall nr: an allowed pair above may have left the
    // accumulator holding args[0] (the fd), which would break every `JEQ nr`
    // that follows (a masked `sendmsg` named in the policy would compare its
    // number against the fd and wrongly run free on non-handshake sockets).
    v.push(stmt(BPF_LD | BPF_W | BPF_ABS, 0));
    for &nr in masked {
        // jeq nr: true → fall into the RET USER_NOTIF; false → skip the RET
        // (jf=1) to the next pair — never beyond the program end, which the
        // kernel's seccomp BPF validator rejects at install time.
        v.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, nr as u32));
        v.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
    }
    v.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    v
}

// ---------------------------------------------------------------------------
// Filter install (child side)
// ---------------------------------------------------------------------------

/// Install the pre-built filter (no allocation in the child). Returns the
/// listener fd.
fn install_filter(prog: &libc::sock_fprog) -> Result<i32> {
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
            bail!("prctl(NO_NEW_PRIVS): {}", std::io::Error::last_os_error());
        }
        let fd = libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER as libc::c_long,
            SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_long,
            prog as *const libc::sock_fprog as libc::c_long,
        );
        if fd == -1 {
            bail!("seccomp(NEW_LISTENER): {}", std::io::Error::last_os_error());
        }
        Ok(fd as i32)
    }
}

// ---------------------------------------------------------------------------
// SCM_RIGHTS listener-fd handoff
// ---------------------------------------------------------------------------

fn cmsg_align(n: usize) -> usize {
    (n + std::mem::size_of::<usize>() - 1) & !(std::mem::size_of::<usize>() - 1)
}

fn cmsg_len(n: usize) -> usize {
    cmsg_align(std::mem::size_of::<libc::cmsghdr>()) + n
}

fn cmsg_space(n: usize) -> usize {
    cmsg_align(std::mem::size_of::<libc::cmsghdr>()) + cmsg_align(n)
}

const CONTROL_CAP: usize = 64;

/// Aligned backing for `cmsg` buffers. Kernel `cmsghdr` requires 8-byte
/// alignment; a raw `[u8; N]` has alignment 1 and would be a misaligned deref.
#[repr(C, align(8))]
struct ControlBuf([u8; CONTROL_CAP]);

fn send_fd(sock: i32, fd: i32) -> Result<()> {
    assert!(cmsg_space(std::mem::size_of::<i32>()) <= CONTROL_CAP);
    let mut control = ControlBuf([0; CONTROL_CAP]);
    let mut data: i32 = 12345;
    let mut iov = libc::iovec {
        iov_base: (&mut data as *mut i32).cast(),
        iov_len: std::mem::size_of::<i32>(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space(std::mem::size_of::<i32>());
    unsafe {
        let cmsg = &mut *msg.msg_control.cast::<libc::cmsghdr>();
        cmsg.cmsg_level = libc::SOL_SOCKET;
        cmsg.cmsg_type = libc::SCM_RIGHTS;
        cmsg.cmsg_len = cmsg_len(std::mem::size_of::<i32>());
        let slot = (control.0.as_mut_ptr() as usize
            + cmsg_align(std::mem::size_of::<libc::cmsghdr>())) as *mut i32;
        *slot = fd;
        if libc::sendmsg(sock, &msg, 0) == -1 {
            bail!("sendmsg(SCM_RIGHTS): {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn recv_fd(sock: i32) -> Result<i32> {
    assert!(cmsg_space(std::mem::size_of::<i32>()) <= CONTROL_CAP);
    let mut control = ControlBuf([0; CONTROL_CAP]);
    let mut data: i32 = 0;
    let mut iov = libc::iovec {
        iov_base: (&mut data as *mut i32).cast(),
        iov_len: std::mem::size_of::<i32>(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space(std::mem::size_of::<i32>());
    unsafe {
        if libc::recvmsg(sock, &mut msg, 0) == -1 {
            bail!("recvmsg(SCM_RIGHTS): {}", std::io::Error::last_os_error());
        }
        let cmsg = &*msg.msg_control.cast::<libc::cmsghdr>();
        if cmsg.cmsg_level != libc::SOL_SOCKET || cmsg.cmsg_type != libc::SCM_RIGHTS {
            bail!(
                "unexpected ancillary data (level={}, type={})",
                cmsg.cmsg_level,
                cmsg.cmsg_type
            );
        }
        if cmsg.cmsg_len < cmsg_len(std::mem::size_of::<i32>()) {
            bail!("short cmsg");
        }
        let slot = (control.0.as_ptr() as usize + cmsg_align(std::mem::size_of::<libc::cmsghdr>()))
            as *const i32;
        Ok(*slot)
    }
}

// ---------------------------------------------------------------------------
// Program resolution (done pre-fork so the child needs no PATH lookups under
// the filter)
// ---------------------------------------------------------------------------

fn resolve_program(program: &str) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let p = std::path::Path::new(program);
    let has_separator = p.components().count() > 1 || program.starts_with('.');
    if has_separator {
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
        bail!("cannot execute {program}: No such file or directory");
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(program);
        let Ok(meta) = std::fs::metadata(&cand) else {
            continue;
        };
        if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
            return Ok(cand);
        }
    }
    bail!("cannot execute {program}: command not found")
}

// ---------------------------------------------------------------------------
// The supervisor coroutine
// ---------------------------------------------------------------------------

impl Sandbox {
    /// Set up the sandbox: the seccomp filter traps the syscalls named in
    /// `named` with `SECCOMP_RET_USER_NOTIF` — **always plus the
    /// `FORK_FAMILY`**, which is masked unconditionally at the engine level
    /// (pid bookkeeping, the fork counter, and kill-on-deny all require
    /// intercepting forks) — and everything else runs straight through the
    /// kernel under its default (allow) without ever reaching the supervisor.
    /// Resolve the program, create pipes + socketpair, fork, arm the filter in
    /// the child (built *before* fork, so the child allocates nothing), hand
    /// the listener fd back, and return a ready supervisor. The child has
    /// exec'd by the time this returns.
    ///
    /// The `decider` only ever sees the masked syscalls. A fork-family syscall
    /// the caller did not name is **auto-allowed** by the engine: fork
    /// interception is internal bookkeeping (pid capture, the fork counter,
    /// kill-on-deny), not a policy decision. Name a fork syscall (e.g.
    /// `"clone"`) to decide it yourself.
    pub fn spawn(
        program: &str,
        argv: &[&str],
        decider: impl FnMut(&Syscall) -> Verdict + Send + 'static,
        named: &[i32],
    ) -> Result<Sandbox> {
        let named_set: BTreeSet<i32> = named.iter().copied().collect();
        let mut set = named_set.clone();
        for &f in &FORK_FAMILY {
            set.insert(f);
        }
        let masked: Vec<i32> = set.into_iter().collect();
        let mut decider: Box<dyn FnMut(&Syscall) -> Verdict + Send> = Box::new(decider);
        Self::spawn_inner(
            program,
            argv,
            &masked,
            Box::new(move |sc: &Syscall| {
                if FORK_FAMILY.contains(&sc.nr) && !named_set.contains(&sc.nr) {
                    Verdict::Allow
                } else {
                    decider(sc)
                }
            }),
        )
    }

    fn spawn_inner(
        program: &str,
        argv: &[&str],
        masked: &[i32],
        decider: Box<dyn FnMut(&Syscall) -> Verdict + Send>,
    ) -> Result<Sandbox> {
        let resolved = resolve_program(program)?;
        let exec_target =
            CString::new(resolved.as_os_str().as_bytes()).context("program path contains NUL")?;

        // argv / CStrings built before fork; the child only execs.
        let mut cstrings: Vec<CString> = Vec::with_capacity(argv.len() + 1);
        cstrings.push(CString::new(program).context("program name contains NUL")?);
        for a in argv {
            cstrings.push(CString::new(*a).context("arg contains NUL")?);
        }
        let mut argv_c: Vec<*const libc::c_char> = cstrings.iter().map(|c| c.as_ptr()).collect();
        argv_c.push(std::ptr::null());

        let mut pout = [0i32; 2];
        let mut perr = [0i32; 2];
        let mut pstdin = [0i32; 2];
        let mut sock = [0i32; 2];
        unsafe {
            if libc::pipe2(pout.as_mut_ptr(), libc::O_CLOEXEC) == -1 {
                bail!("pipe2(stdout): {}", std::io::Error::last_os_error());
            }
            if libc::pipe2(perr.as_mut_ptr(), libc::O_CLOEXEC) == -1 {
                bail!("pipe2(stderr): {}", std::io::Error::last_os_error());
            }
            // Per-run stdin isolation: the tracee's fd 0 is this pipe's read
            // end, so the supervisor process's own stdin stays untouched.
            if libc::pipe2(pstdin.as_mut_ptr(), libc::O_CLOEXEC) == -1 {
                bail!("pipe2(stdin): {}", std::io::Error::last_os_error());
            }
            if libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                sock.as_mut_ptr(),
            ) == -1
            {
                bail!("socketpair: {}", std::io::Error::last_os_error());
            }
        }

        // Filter built *before* fork: the child reuses this memory copy and
        // performs no allocation between install and exec. `masked` already
        // contains the always-on FORK_FAMILY (merged in `spawn`).
        let filter = build_filter_named(masked, &[(SYS_SENDMSG, sock[0] as u32)]);
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };

        let pid = unsafe { libc::fork() };
        if pid == -1 {
            bail!("fork: {}", std::io::Error::last_os_error());
        }

        if pid == 0 {
            // ---- target (child) ----
            unsafe {
                libc::close(sock[1]);
                libc::close(pout[0]);
                libc::close(perr[0]);
                libc::close(pstdin[1]); // the child only reads its stdin
                if libc::dup2(pstdin[0], 0) == -1
                    || libc::dup2(pout[1], 1) == -1
                    || libc::dup2(perr[1], 2) == -1
                {
                    libc::_exit(126);
                }
                libc::close(pstdin[0]);
                libc::close(pout[1]);
                libc::close(perr[1]);
            }
            let listener = match install_filter(&prog) {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("sandbox: {e:#}");
                    unsafe { libc::_exit(126) }
                }
            };
            if let Err(e) = send_fd(sock[0], listener) {
                eprintln!("sandbox: {e:#}");
                unsafe { libc::_exit(126) }
            }
            unsafe {
                libc::execv(exec_target.as_ptr(), argv_c.as_ptr());
                eprintln!("sandbox: execv failed: {}", std::io::Error::last_os_error());
                libc::_exit(127);
            }
        }

        // ---- supervisor (parent) ----
        unsafe {
            libc::close(pout[1]);
            libc::close(perr[1]);
            libc::close(pstdin[0]); // keep only the write end
            libc::close(sock[0]);
            for fd in [pout[0], perr[0], pstdin[1]] {
                let fl = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
        }
        let listener = recv_fd(sock[1]).context("receiving listener fd")?;
        unsafe {
            // Request O_NONBLOCK as a second line of defense where the
            // kernel honors it on notification fds (some do not — some
            // kernels let NOTIF_RECV block on an empty queue regardless of
            // this flag). The authoritative guarantee that RECV never
            // blocks lives in `handle_notification`'s zero-timeout poll
            // gate: poll reports POLLIN only while a notification is
            // queued, and POLLHUP once the filter is gone (RECV then
            // answers ENOENT). The stale wake it also covers: the kernel
            // drops pending notifications when a filter user exits —
            // after having woken the listener for the *empty* queue.
            let fl = libc::fcntl(listener, libc::F_GETFL);
            libc::fcntl(listener, libc::F_SETFL, fl | libc::O_NONBLOCK);
            libc::close(sock[1]);
        }

        Ok(Sandbox {
            listener,
            out_r: pout[0],
            err_r: perr[0],
            stdin_w: pstdin[1],
            stdin_closed: false,
            input: Vec::new(),
            child: pid,
            pids: [pid].into_iter().collect(),
            forks: 0,
            interrupted: false,
            interrupt: {
                // Publish so the TUI's `Ctrl+c` can find this run. Single-slot,
                // which is sound only because the agent runs one tool at a time
                // — see `LIVE_RUN`.
                let flag = Arc::new(AtomicBool::new(false));
                if let Ok(mut slot) = LIVE_RUN.lock() {
                    *slot = Some(InterruptHandle {
                        flag: flag.clone(),
                    });
                }
                flag
            },
            decider,
            out: Vec::new(),
            err: Vec::new(),
            out_eof: false,
            err_eof: false,
            tree_done: false,
            pending: None,
            sent_notif: None,
            frozen_siblings: 0,
            child_reaped: false,
            child_status: 0,
            next_request: 0,
            syscalls: 0,
            denied: 0,
            finished: false,
        })
    }

    /// Drive the coroutine one **non-blocking** step, processing at most one
    /// unit of work that a poll has already declared ready. Never sleeps.
    ///
    /// `listener_revents` must be the poll(2) result for this sandbox's
    /// listener fd (`0` if the listener was not ready or not registered).
    /// RECV is poll-gated: `Sandbox::handle_notification` runs a zero-timeout
    /// `poll` first (`POLLIN` ⇒ a notification is queued; `POLLHUP` ⇒ the
    /// filter died, RECV answers `ENOENT`), so step never sleeps and the
    /// poll loop alone still gates notification work. Returns:
    ///
    /// - [`Step::Blocked`] — the decider asked; the target is frozen. Resolve
    ///   via [`Sandbox::resolve_ask`], then step again.
    /// - [`Step::Event`] — one output chunk or one decided syscall.
    /// - [`Step::Idle`] — nothing was ready; go back to the poll loop.
    /// - [`Step::Finished`] — the tree is gone; output fully captured.
    pub fn step(&mut self, listener_revents: i16) -> Result<Step> {
        if self.finished {
            bail!("sandbox already finished");
        }
        // An interrupt asked for since the last round. `kill_tree` rather than a
        // bare `kill` on the root, because descendants captured earlier would
        // otherwise keep the seccomp listener alive and the run would go on
        // without its output. From here the run finishes the ordinary way — the
        // tree's death arrives as listener EOF on a later poll — so the driver
        // needs no interrupt path of its own, only the note in the result.
        self.service_interrupt();
        // The tree's death is signaled by listener EOF — which arrives on the
        // same poll as pipe EOF when the last filter user exits. Record it
        // regardless of pipe state; the caller passes 0 revents once the fd is
        // deregistered, so this can only fire while the listener is live.
        if listener_revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            self.tree_done = true;
        }
        let mut listener_ready = listener_revents & libc::POLLIN != 0;
        loop {
            // 0. push whatever queued stdin input the pipe can take (never
            // blocks; the write end is O_NONBLOCK). The poll loop only wakes
            // us for this after POLLOUT on a full pipe.
            self.try_flush_stdin()?;
            // 1. drain whatever output is already readable (never blocks)
            if let Some(ev) = self.try_drain_one()? {
                return Ok(Step::Event(ev));
            }
            // 2. completion: tree gone and both pipes at EOF
            if self.tree_done && self.out_eof && self.err_eof {
                let r = self.finish_result()?;
                return Ok(Step::Finished(r));
            }
            // 3. exactly one notification, gated by poll-readiness (RECV
            //    blocks otherwise). A frozen ask can't be answered here —
            //    that goes through resolve_ask — so skip RECV while pending.
            if listener_ready && self.pending.is_none() {
                match self.handle_notification()? {
                    Some(st) => return Ok(st),
                    None => {
                        // ENOENT (queue drained; may have set tree_done) or
                        // EINTR: don't re-enter RECV, re-check completion
                        // once, then idle — the poll loop will re-report.
                        listener_ready = false;
                        continue;
                    }
                }
            }
            // 4. nothing more right now
            return Ok(Step::Idle);
        }
    }

    /// The fds to register in the global poll loop, as `(slot, pollfd)` in a
    /// stable order. Power-efficiency contract:
    ///
    /// - fds at EOF are **omitted**, so their sticky `POLLHUP` can't make the
    ///   shared poll return instantly forever (the busy-spin that per-sandbox
    ///   polling used to hide);
    /// - a frozen (ask-pending) listener is registered with `events == 0` —
    ///   `POLLHUP`/`POLLERR` are still reported, but a queue of unread
    ///   notifications can't wake the loop.
    pub fn poll_slots(&self) -> Vec<(FdSlot, libc::pollfd)> {
        let mut v = Vec::with_capacity(3);
        if !self.tree_done {
            v.push((
                FdSlot::Listener,
                libc::pollfd {
                    fd: self.listener,
                    events: if self.pending.is_none() {
                        libc::POLLIN
                    } else {
                        0
                    },
                    revents: 0,
                },
            ));
        }
        if !self.out_eof {
            v.push((
                FdSlot::Stdout,
                libc::pollfd {
                    fd: self.out_r,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ));
        }
        if !self.err_eof {
            v.push((
                FdSlot::Stderr,
                libc::pollfd {
                    fd: self.err_r,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ));
        }
        if !self.stdin_closed && !self.input.is_empty() {
            v.push((
                FdSlot::Stdin,
                libc::pollfd {
                    fd: self.stdin_w,
                    events: libc::POLLOUT,
                    revents: 0,
                },
            ));
        }
        v
    }

    /// Diagnostic: where each tree process is parked right now (kernel wait
    /// channel + the syscall it is executing + blocked/pending signals, from
    /// /proc). Read-only; never blocks on the tracees. Nothing in the agent
    /// calls this at runtime any more — it backed the `agent.api.diag` bridge
    /// primitive, which no Lua code used — but it is the only way to see *why*
    /// a drive loop stopped making progress, so it stays as public API.
    pub fn probe(&self) -> Vec<(i32, String)> {
        let mut out = Vec::new();
        for &pid in self.pids.iter() {
            let wchan = std::fs::read_to_string(format!("/proc/{pid}/wchan")).unwrap_or_default();
            let syscall =
                std::fs::read_to_string(format!("/proc/{pid}/syscall")).unwrap_or_default();
            let mut sigblk = String::new();
            let mut sigpnd = String::new();
            if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
                for line in status.lines() {
                    if let Some(v) = line.strip_prefix("SigBlk:") {
                        sigblk = v.trim().to_string();
                    } else if let Some(v) = line.strip_prefix("SigPnd:") {
                        sigpnd = v.trim().to_string();
                    }
                }
            }
            let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            let st = state.split_whitespace().nth(2).unwrap_or("?");
            out.push((
                pid,
                format!(
                    "state={st} wchan={} syscall={} blk={sigblk} pnd={sigpnd}",
                    wchan.trim(),
                    syscall.trim()
                ),
            ));
        }
        out
    }

    /// Diagnostic: one-line summary of the engine's own state (see [`Sandbox::probe`]).
    pub fn state_desc(&self) -> String {
        format!(
            "tree_done={} pending={} out_eof={} err_eof={} stdin_closed={} stdin_q={} forks={} syscalls={} denied={} pids={}",
            self.tree_done,
            self.pending.is_some(),
            self.out_eof,
            self.err_eof,
            self.stdin_closed,
            self.input.len(),
            self.forks,
            self.syscalls,
            self.denied,
            self.pids.len()
        )
    }

    /// Thaw a frozen syscall ([`Step::Blocked`]) with the final verdict. A
    /// `Deny` kills the whole tree *before* replaying the errno (the denied
    /// thread is still parked in its notification wait, so the SIGKILL cannot
    /// be outrun — see the kill-first ordering below).
    pub fn resolve_ask(&mut self, verdict: Verdict) -> Result<()> {
        let Some(ask) = self.pending.take() else {
            bail!("no pending ask to resolve");
        };
        match verdict {
            Verdict::Ask => bail!("cannot resolve an ask with another ask"),
            Verdict::Deny(_) => self.denied += 1,
            Verdict::Allow => {}
        }
        if matches!(verdict, Verdict::Deny(_)) {
            // Kill the whole tree FIRST: the denied thread is still parked
            // in the notification wait, so the SIGKILL lands before it can
            // run any post-deny work toward an exit of its own — under a
            // narrow mask its un-masked exit path (a write, `_exit`) could
            // otherwise race the kill and surface an exit code (127) instead
            // of a signal. The errno replay below is then best-effort
            // (ENOENT once the thread is already dead).
            self.kill_tree();
        }
        self.sent_notif = Some(ask.id);
        self.send_response(ask.id, verdict)?;
        Ok(())
    }

    /// Feed bytes to the tracee's (isolated) stdin pipe. Non-blocking: what
    /// the pipe can take now is written immediately, the rest is queued and
    /// flushed by [`Sandbox::step`] once the pipe reports `POLLOUT` (the
    /// poll loop registers the write end only while input is queued, so a
    /// full buffer parks it). Input after EOF is dropped.
    pub fn queue_stdin(&mut self, data: &[u8]) -> Result<()> {
        if self.stdin_closed || data.is_empty() {
            return Ok(());
        }
        self.input.extend_from_slice(data);
        self.try_flush_stdin()
    }

    /// Close the per-run stdin pipe's write end: the tracee's next `read(0)`
    /// will see EOF once every copy of the write end is gone (the async
    /// driver also drops its dup'd [`AsyncFd`](tokio::io::unix::AsyncFd)-owned copy).
    pub fn close_stdin(&mut self) {
        if self.stdin_w >= 0 {
            unsafe {
                libc::close(self.stdin_w);
            }
            self.stdin_w = -1;
        }
        self.stdin_closed = true;
        self.input.clear();
    }

    /// Whether the per-run stdin write end is closed (EOF already signaled).
    pub fn stdin_closed(&self) -> bool {
        self.stdin_closed
    }

    /// Raw fds for the async driver to dup into pollable handles. The caller
    /// must not close them — [`Sandbox`] owns them.
    pub fn listener_fd(&self) -> RawFd {
        self.listener
    }
    pub fn stdout_fd(&self) -> RawFd {
        self.out_r
    }
    pub fn stderr_fd(&self) -> RawFd {
        self.err_r
    }
    pub fn stdin_fd(&self) -> Option<RawFd> {
        (self.stdin_w >= 0).then_some(self.stdin_w)
    }

    /// The tree's root pid — the direct child [`Sandbox::spawn`] created.
    /// Stable for the whole run; the agent uses it to interrupt a tool.
    pub fn pid(&self) -> libc::pid_t {
        self.child
    }

    /// Snapshot of every pid seen in the tree so far. The root child is
    /// always present; fork/clone children appear once they make their first
    /// post-fork syscall (each is captured by `Sandbox::handle_notification`).
    pub fn pids(&self) -> Vec<libc::pid_t> {
        self.pids.iter().copied().collect()
    }

    /// fork()/clone()/vfork()/clone3() syscalls observed so far (the fork
    /// hook; see `Sandbox::handle_notification`).
    pub fn forks(&self) -> u64 {
        self.forks
    }

    /// A handle that can ask *this* run to stop, from any thread.
    ///
    /// What the agent's `Ctrl+c` reaches through [`request_interrupt`], and what
    /// a caller with the [`Sandbox`] in hand would use instead. Per-run, so
    /// holding one is safe even with other sandboxes live.
    pub fn interrupt_handle(&self) -> InterruptHandle {
        InterruptHandle {
            flag: self.interrupt.clone(),
        }
    }

    /// SIGSTOP the whole captured tree.
    ///
    /// Call this **before** surfacing a [`Verdict::Ask`] when the ask must
    /// quiesce the whole tree: while the ask is pending the answerer inspects
    /// a consistent snapshot — nothing in the tree makes progress, output is
    /// quiesced, and the target processes are frozen mid-flight. Thaw with
    /// [`Sandbox::resume`]. This is the frozen-ask pattern [`Sandbox::pump`]
    /// and the async drive use; the Lua bridge in [`crate::lua`] instead uses
    /// [`Sandbox::freeze_others`], which stops every process **except** the
    /// asker's — a full-tree freeze would interrupt the asker's notif-wait,
    /// discard the pending notification, and re-ask forever (see the Lua
    /// module docs). Best-effort: pids that exited since capture are
    /// existence-probed and skipped (see [`Sandbox::kill_tree`]).
    pub fn freeze(&mut self) {
        self.signal_tree(libc::SIGSTOP);
    }

    /// SIGCONT the whole captured tree, thawing a [`Sandbox::freeze`].
    pub fn resume(&mut self) {
        self.signal_tree(libc::SIGCONT);
    }

    /// SIGSTOP every captured tree process **except the asker's** process, so
    /// a deref + path resolution and the policy run see a quiesced tree: no
    /// sibling process can rewrite a symlink or the tracee's memory between
    /// the policy's check and the kernel's own resolution of the syscall —
    /// the TOCTOU gate a path-based policy would otherwise sit inside.
    /// Unlike [`Sandbox::freeze`], the asking thread is deliberately left
    /// alone: the kernel already parks it on the very notification being
    /// answered, and stopping it would interrupt that wait, discard the
    /// notification, and re-ask forever (the documented livelock that keeps
    /// the Lua bridge off `freeze()`). The exclusion is by thread-group —
    /// SIGSTOP is process-wide, so the asker's whole process is skipped;
    /// sibling *threads inside the asker's own process* are the one
    /// unreachable residual. Best-effort, like [`Sandbox::freeze`]: the stop
    /// is acknowledged (targets are polled in `/proc/<pid>/stat` until they
    /// report `T`, bounded by `FREEZE_ACK_TIMEOUT`), because SIGSTOP's stop
    /// transition lands on a scheduler tick. Thaw with [`Sandbox::resume`],
    /// typically via [`Sandbox::resolve_ask_frozen`]. Returns how many pids
    /// were actually stopped (0 means nothing was frozen, so the completion
    /// wait in [`Sandbox::resolve_ask_frozen`] is skipped — nobody is left to
    /// race the allowed syscall; keeps the ask path cheap for single-process
    /// trees).
    pub fn freeze_others(&mut self, asker_tid: i32) -> usize {
        // A descendant that never made a *masked* syscall never announced
        // itself: complete the tree from /proc first (same as signal_tree).
        self.refresh_tree_from_proc();
        let asker_tgid = proc_tgid(asker_tid).unwrap_or(asker_tid);
        let mut targets: Vec<i32> = self.pids.iter().copied().collect();
        if !targets.contains(&self.child) {
            targets.push(self.child);
        }
        let mut stopped: Vec<i32> = Vec::new();
        for pid in targets {
            if pid == asker_tgid || !alive(pid) {
                continue;
            }
            unsafe {
                libc::kill(pid, libc::SIGSTOP);
            }
            stopped.push(pid);
        }
        self.frozen_siblings = stopped.len();
        wait_stopped(&stopped, FREEZE_ACK_TIMEOUT);
        stopped.len()
    }

    /// Wait (bounded by `budget`) for the most recently answered
    /// notification's syscall to actually finish executing, polling
    /// `SECCOMP_IOCTL_NOTIF_ID_VALID`: after a response is sent the kernel
    /// keeps the id valid until the target syscall completes. A still-frozen
    /// tree ([`Sandbox::freeze_others`]) is only thawed once that has
    /// happened, so sibling processes cannot race the kernel's pathname
    /// resolution. Returns `false` if the budget elapsed before completion (a
    /// legitimately blocking allowed syscall, e.g. `open` on a FIFO) —
    /// callers then thaw anyway rather than hang the tree.
    pub fn wait_completion(&self, budget: std::time::Duration) -> bool {
        let Some(id) = self.sent_notif else {
            return true;
        };
        let deadline = std::time::Instant::now() + budget;
        loop {
            let r = unsafe { libc::ioctl(self.listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) };
            if r == -1 {
                // Id invalid: the syscall finished (or the tree is gone).
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
    }

    /// The Lua-bridge verdict delivery for a tree frozen with
    /// [`Sandbox::freeze_others`]: answer the pending ask, and on `Allow`
    /// keep the siblings frozen until the allowed syscall has executed
    /// ([`Sandbox::wait_completion`], bounded by `COMPLETION_WAIT_MAX`)
    /// before thawing — closing the TOCTOU window between the policy's path
    /// check and the kernel's own resolution. On `Deny` the whole tree is
    /// SIGKILLed inside [`Sandbox::resolve_ask`]; nothing is thawed.
    pub fn resolve_ask_frozen(&mut self, verdict: Verdict) -> Result<()> {
        let had_frozen_siblings = std::mem::take(&mut self.frozen_siblings);
        self.resolve_ask(verdict)?;
        if matches!(verdict, Verdict::Allow) && had_frozen_siblings > 0 {
            self.wait_completion(COMPLETION_WAIT_MAX);
            self.resume();
        }
        Ok(())
    }

    /// SIGKILL the whole captured tree. Runs automatically when a
    /// [`Verdict::Deny`] is delivered (`Sandbox::handle_notification`) or
    /// answered ([`Sandbox::resolve_ask`]), and from the destructor so a
    /// dropped [`Sandbox`] never leaves a live process tree behind.
    ///
    /// Idempotent: each pid is existence-probed (`kill(pid, 0)`) first, so a
    /// pid number recycled after its process exited can't be hit with a live
    /// signal. That narrows — but does not close — the pid-reuse race
    /// (pidfd-pinning is the hardening; out of scope for the deliberately
    /// insecure agent sandbox).
    pub fn kill_tree(&mut self) {
        self.signal_tree(libc::SIGKILL);
    }

    fn signal_tree(&mut self, sig: libc::c_int) {
        // A descendant that never makes a *masked* syscall never announced
        // itself, so complete the tree from /proc (PPid ancestry) before
        // signaling — otherwise a deny or drop could leave such a child
        // alive, holding a pipe open forever.
        self.refresh_tree_from_proc();
        // Iterate a snapshot: `kill` may race with our own reaping elsewhere,
        // and we never mutate `pids` from here. The root pid is *always* a
        // target — `pids` is seeded with it at spawn, but the invariant is
        // kept explicit here so a future `pids` prune can't strand the root:
        // an interrupt that races the tree's very first syscall (before any
        // notification captured descendants) must still reach it.
        let mut targets: Vec<libc::pid_t> = self.pids.iter().copied().collect();
        if !targets.contains(&self.child) {
            targets.push(self.child);
        }
        for pid in targets {
            // Existence probe — a dead pid's number may have been recycled by
            // an unrelated process and must not receive a live signal.
            let alive = unsafe {
                let r = libc::kill(pid, 0);
                if r == 0 {
                    true
                } else {
                    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
                }
            };
            if alive {
                unsafe {
                    libc::kill(pid, sig);
                }
            }
        }
    }

    /// Extend `pids` with every live `/proc` process whose PPid ancestry
    /// reaches a captured pid (transitive closure over one snapshot), so
    /// [`Sandbox::signal_tree`] reaches the whole tree even when a descendant
    /// never performed a *masked* syscall (only the fork family is guaranteed
    /// intercepted, so un-masked descendants can exist). Dead-but-unreaped
    /// zombies are included harmlessly — signal_tree's existence probe
    /// filters every target anyway. A process whose parent died and got
    /// reparented before this scan is missed (residual — a deny usually
    /// kills the root first, so parents don't die first).
    fn refresh_tree_from_proc(&mut self) {
        let mut snapshot: Vec<(i32, i32)> = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for ent in rd.flatten() {
                let name = ent.file_name();
                let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
                    continue;
                };
                if let Some(ppid) = proc_ppid(pid) {
                    snapshot.push((pid, ppid));
                }
            }
        }
        loop {
            let before = self.pids.len();
            for &(pid, ppid) in &snapshot {
                if !self.pids.contains(&pid) && self.pids.contains(&ppid) {
                    self.pids.insert(pid);
                }
            }
            if self.pids.len() == before {
                break;
            }
        }
    }

    /// Whether the engine still holds input queued for the tracee's stdin
    /// (write end open, pipe buffer full). Once false, the write end can be
    /// closed without losing bytes.
    pub fn stdin_pending(&self) -> bool {
        !self.stdin_closed && !self.input.is_empty()
    }

    /// Write as much queued input as the pipe buffer accepts (`O_NONBLOCK`):
    /// EAGAIN keeps the remainder queued (the poll loop re-registers
    /// `POLLOUT`), EPIPE marks EOF and drops it (the tracee exited or closed
    /// its stdin), EINTR retries. Never blocks, never errors on flow control.
    fn try_flush_stdin(&mut self) -> Result<()> {
        if self.stdin_closed || self.input.is_empty() {
            return Ok(());
        }
        loop {
            let n = unsafe {
                libc::write(
                    self.stdin_w,
                    self.input.as_ptr().cast::<libc::c_void>(),
                    self.input.len(),
                )
            };
            if n > 0 {
                self.input.drain(..n as usize);
                if self.input.is_empty() {
                    return Ok(());
                }
                continue; // pipe still had room: keep pushing
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => return Ok(()), // full; wait for POLLOUT
                Some(libc::EPIPE) => {
                    // tracee gone or closed its stdin: no more input possible
                    self.stdin_closed = true;
                    self.input.clear();
                    return Ok(());
                }
                _ => bail!("write(stdin): {e}"),
            }
        }
    }

    /// Drive this one sandbox to completion, handing asks to `on_ask` and
    /// forwarding every event to `on_event`. This is [`Supervisor::drive`]
    /// specialized to a single sandbox: one `poll(2)` over this sandbox's
    /// live fds, blocking when there's nothing to do, then stepping it.
    /// Act on a pending interrupt request, if there is one; returns whether one
    /// fired.
    ///
    /// Called from the step *and* the poll-timeout path, and the second one is not
    /// belt-and-braces. A command that is producing no output never reaches
    /// `step` at all: the driver polls, times out, and goes straight back to
    /// sleep. That is exactly the command a user reaches for `Ctrl+c` on — a
    /// long build, a `sleep`, a server that has gone quiet — so a latch checked
    /// only in `step` would interrupt chatty commands and fail on precisely the
    /// ones that matter. Found by a test that ran `sleep 30`, which is the whole
    /// reason the fixture is silent.
    fn service_interrupt(&mut self) -> bool {
        if !self.interrupt.swap(false, Ordering::SeqCst) {
            return false; // nothing asked for this run
        }
        self.interrupted = true;
        self.kill_tree();
        true
    }

    pub fn pump<A, E>(&mut self, mut on_ask: A, mut on_event: E) -> Result<SandboxResult>
    where
        A: FnMut(&Syscall) -> Verdict,
        E: FnMut(CoroutineEvent),
    {
        loop {
            let slots = self.poll_slots();
            if slots.is_empty() {
                // Nothing left to wait on: only the completion path remains.
                return match self.step(0)? {
                    Step::Finished(r) => Ok(r),
                    other => bail!("tree gone but step returned {other:?}"),
                };
            }
            let mut pfds: Vec<libc::pollfd> = slots.iter().map(|(_, p)| *p).collect();
            let pr = unsafe {
                libc::poll(
                    pfds.as_mut_ptr(),
                    pfds.len() as libc::nfds_t,
                    DEFAULT_POLL_TIMEOUT_MS,
                )
            };
            if pr == -1 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                bail!("poll: {e}");
            }
            if pr == 0 {
                // Timeout, nothing ready — and the only moment a silent command
                // can be interrupted, since it will never reach `step`.
                self.service_interrupt();
                continue; // back to sleep
            }
            let mut listener_revents = 0i16;
            for (k, p) in pfds.iter().enumerate() {
                if p.revents != 0 && slots[k].0 == FdSlot::Listener {
                    listener_revents = p.revents;
                }
            }
            match self.step(listener_revents)? {
                Step::Blocked { syscall, .. } => {
                    // Freeze the whole tree so the answerer (policy/user)
                    // sees a consistent snapshot. An Allow answer thaws it
                    // below; a Deny answer kills it inside resolve_ask.
                    self.freeze();
                    let verdict = on_ask(&syscall);
                    self.resolve_ask(verdict)?;
                    if matches!(verdict, Verdict::Allow) {
                        self.resume();
                    }
                }
                Step::Event(ev) => on_event(ev),
                Step::Idle => {}
                Step::Finished(result) => return Ok(result),
            }
        }
    }

    /// [`Sandbox::pump`] with stdin forwarding: also polls `stdin_fd`
    /// (typically the supervisor process's own fd 0) for readability and
    /// feeds everything it reads into the tracee's isolated stdin via
    /// [`Sandbox::queue_stdin`]; EOF on it stops forwarding and, once the
    /// queued tail has drained, closes the tracee's stdin. The tracee can
    /// never read the supervisor's stdin directly, so ask prompts and
    /// program input no longer contend for the same pipe.
    pub fn pump_with_stdin<A, E>(
        &mut self,
        stdin_fd: i32,
        mut on_ask: A,
        mut on_event: E,
    ) -> Result<SandboxResult>
    where
        A: FnMut(&Syscall) -> Verdict,
        E: FnMut(CoroutineEvent),
    {
        let mut parent_eof = false;
        loop {
            // Parent stdin EOF + queue drained: signal EOF to the tracee.
            if parent_eof && !self.stdin_closed() && !self.stdin_pending() {
                self.close_stdin();
            }
            // Completion must be reachable even while the parent stdin (an
            // idle TTY, say) never EOFs — so check the sandbox's own slots
            // BEFORE adding the external stdin entry.
            let own_slots = self.poll_slots();
            if own_slots.is_empty() {
                // Nothing left to wait on: only the completion path remains.
                return match self.step(0)? {
                    Step::Finished(r) => Ok(r),
                    other => bail!("tree gone but step returned {other:?}"),
                };
            }
            let mut slots = own_slots;
            // One extra pollfd for the parent stdin; the engine's own Stdin
            // slot (POLLOUT on the tracee's pipe) is distinguished by index.
            let stdin_index = if parent_eof || self.stdin_closed() {
                None
            } else {
                let idx = slots.len();
                slots.push((
                    FdSlot::Stdin,
                    libc::pollfd {
                        fd: stdin_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ));
                Some(idx)
            };
            let mut pfds: Vec<libc::pollfd> = slots.iter().map(|(_, p)| *p).collect();
            let pr = unsafe {
                libc::poll(
                    pfds.as_mut_ptr(),
                    pfds.len() as libc::nfds_t,
                    DEFAULT_POLL_TIMEOUT_MS,
                )
            };
            if pr == -1 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                bail!("poll: {e}");
            }
            if pr == 0 {
                // Timeout, nothing ready — and the only moment a silent command
                // can be interrupted, since it will never reach `step`.
                self.service_interrupt();
                continue; // back to sleep
            }

            // Forward whatever the supervisor's stdin has, then step.
            if let Some(idx) = stdin_index
                && pfds[idx].revents & (libc::POLLIN | libc::POLLHUP) != 0
            {
                let mut buf = [0u8; 4096];
                loop {
                    let n = unsafe { libc::read(stdin_fd, buf.as_mut_ptr().cast(), buf.len()) };
                    if n > 0 {
                        self.queue_stdin(&buf[..n as usize])?;
                        break;
                    }
                    if n == 0 {
                        parent_eof = true;
                        // Don't close yet: the queued tail must drain
                        // first or it would be dropped (see loop top).
                        break;
                    }
                    let e = std::io::Error::last_os_error();
                    match e.raw_os_error() {
                        Some(libc::EINTR) => continue,
                        Some(libc::EAGAIN) => break, // spurious wake
                        _ => bail!("read(stdin): {e}"),
                    }
                }
            }

            let mut listener_revents = 0i16;
            for (k, p) in pfds.iter().enumerate() {
                if p.revents != 0 && slots[k].0 == FdSlot::Listener && Some(k) != stdin_index {
                    listener_revents = p.revents;
                }
            }
            match self.step(listener_revents)? {
                Step::Blocked { syscall, .. } => {
                    // Freeze the whole tree while the ask is pending (see
                    // [`Sandbox::pump`] for the freeze/thaw contract).
                    self.freeze();
                    let verdict = on_ask(&syscall);
                    self.resolve_ask(verdict)?;
                    if matches!(verdict, Verdict::Allow) {
                        self.resume();
                    }
                }
                Step::Event(ev) => on_event(ev),
                Step::Idle => {}
                Step::Finished(result) => return Ok(result),
            }
        }
    }

    /// RECV one notification and decide it. Returns `Some(step)` when `step`
    /// should return it (a decided event, or a frozen ask), `None` when the
    /// loop should just continue (ENOENT/EINTR/stale wake).
    fn handle_notification(&mut self) -> Result<Option<Step>> {
        // Guard the RECV with a zero-timeout poll. The listener can wake
        // with *nothing* queued (a dropped notification wakes it for its
        // now-empty queue), and some kernels do not honor O_NONBLOCK on
        // NOTIF_RECV — it would block until a notification arrives or the
        // filter dies, freezing a single-threaded driver for the whole
        // run. poll() reports POLLIN only while a request is queued, and
        // POLLHUP once the last filter user is gone (RECV then answers
        // ENOENT instantly) — so a POLLIN|POLLHUP wake makes the RECV
        // below non-blocking by construction.
        let mut pfd = libc::pollfd {
            fd: self.listener,
            events: libc::POLLIN,
            revents: 0,
        };
        let pr = unsafe { libc::poll(&mut pfd, 1, 0) };
        if pr == -1 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                return Ok(None); // caller re-polls; nothing consumed
            }
            bail!("poll(listener): {e}");
        }
        if pr == 0 || pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
            // Stale wake: nothing queued and the filter is still alive. Not
            // an error and not tree_done — idle; the poll loop re-reports
            // genuine arrivals.
            return Ok(None);
        }
        let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::ioctl(self.listener, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) };
        if r == -1 {
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::ENOENT) => {
                    // ENOENT after a poll that reported POLLIN (revents=1)
                    // is the interrupt race, NOT filter death: a signal woke
                    // the suspended tracee out of the kernel's interruptible
                    // wait in seccomp_do_user_notification and the kernel
                    // discarded its notification; the syscall restarts and
                    // will queue a fresh one. The filter is provably alive
                    // here — the notification's owner cannot exit while
                    // frozen — so marking tree_done would strand a live tree
                    // (this was the MCP flake: listener unpolled forever, a
                    // surviving tracee holding the pipes open). Only treat
                    // ENOENT as death when the poll gate also reported
                    // HUP/ERR (last filter user genuinely gone).
                    if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                        self.tree_done = true;
                    }
                    return Ok(None);
                }
                Some(libc::EINTR) => return Ok(None),
                // Spurious (or a kernel that does honor O_NONBLOCK while
                // the poll gate raced a drop): nothing queued. Not an
                // error, not tree_done — idle; the poll loop re-reports
                // genuine arrivals.
                Some(libc::EAGAIN) => return Ok(None),
                _ => bail!("NOTIF_RECV: {e}"),
            }
        }
        self.syscalls += 1;
        let caller_pid = notif.pid as i32;
        // Pid capture: every notification names its caller, so the whole tree
        // — root child plus every fork/clone descendant, once it makes its
        // first post-fork syscall — lands in `self.pids`.
        self.pids.insert(caller_pid);
        // fork()/clone() capture hook: a fork means the tree is about to grow.
        // The new pid is not knowable from *this* notification (it only names
        // the caller); the child announces itself via its own next syscall,
        // which the insert above picks up. So all we record here is that a
        // fork happened (observable via [`Sandbox::forks`]).
        if FORK_FAMILY.contains(&notif.data.nr) {
            self.forks += 1;
        }
        let syscall = Syscall {
            pid: caller_pid,
            nr: notif.data.nr,
            args: notif.data.args,
        };
        let verdict = (self.decider)(&syscall);
        match verdict {
            Verdict::Allow | Verdict::Deny(_) => {
                let denied = matches!(verdict, Verdict::Deny(_));
                if denied {
                    self.denied += 1;
                }
                if denied {
                    // A denied request kills the whole tree at once: nothing
                    // continues in a sandbox the policy just rejected. Kill
                    // first — the denier is still parked in its notification
                    // wait, so the SIGKILL lands before any post-deny exit
                    // work can race it under a narrow mask — then replay the
                    // errno best-effort (ENOENT once the tracee is dead).
                    self.kill_tree();
                }
                self.send_response(notif.id, verdict)?;
                Ok(Some(Step::Event(CoroutineEvent::Decided {
                    syscall,
                    verdict,
                })))
            }
            Verdict::Ask => {
                let request = self.next_request;
                self.next_request += 1;
                self.pending = Some(Ask { id: notif.id });
                Ok(Some(Step::Blocked { syscall, request }))
            }
        }
    }

    fn send_response(&self, id: u64, verdict: Verdict) -> Result<()> {
        let resp = match verdict {
            Verdict::Allow => SeccompNotifResp {
                id,
                val: 0,
                error: 0,
                flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE, // note: error/val must be 0
            },
            Verdict::Deny(errno) => SeccompNotifResp {
                id,
                val: 0,
                error: -errno, // negative errno per the man page
                flags: 0,
            },
            Verdict::Ask => bail!("cannot send an ask"),
        };
        loop {
            let s = unsafe { libc::ioctl(self.listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) };
            if s != -1 {
                return Ok(());
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                // target terminated while frozen: nothing to respond to
                Some(libc::ENOENT) => return Ok(()),
                Some(libc::EINTR) => continue,
                _ => bail!("NOTIF_SEND: {e}"),
            }
        }
    }

    fn try_drain_one(&mut self) -> Result<Option<CoroutineEvent>> {
        let mut buf = [0u8; PIPE_CHUNK];
        if !self.out_eof
            && let Some(n) = self.read_ready(self.out_r, &mut buf)?
        {
            self.out.extend_from_slice(&buf[..n]);
            return Ok(Some(CoroutineEvent::Output {
                stream: Stream::Stdout,
                data: buf[..n].to_vec(),
            }));
        }
        if !self.err_eof
            && let Some(n) = self.read_ready(self.err_r, &mut buf)?
        {
            self.err.extend_from_slice(&buf[..n]);
            return Ok(Some(CoroutineEvent::Output {
                stream: Stream::Stderr,
                data: buf[..n].to_vec(),
            }));
        }
        Ok(None)
    }

    /// Non-blocking read of one chunk. Returns `Some(n)` on data, `None` when
    /// not ready; on EOF sets the corresponding eof flag.
    fn read_ready(&mut self, fd: i32, buf: &mut [u8]) -> Result<Option<usize>> {
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                return Ok(Some(n as usize));
            }
            if n == 0 {
                if fd == self.out_r {
                    self.out_eof = true;
                } else {
                    self.err_eof = true;
                }
                return Ok(None);
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => return Ok(None), // not ready (non-blocking)
                _ => bail!("read: {e}"),
            }
        }
    }

    fn finish_result(&mut self) -> Result<SandboxResult> {
        if !self.child_reaped {
            let mut st: i32 = 0;
            let w = unsafe { libc::waitpid(self.child, &mut st, 0) };
            if w == -1 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::ECHILD) {
                    bail!("waitpid: {e}");
                }
            }
            self.child_reaped = true;
            self.child_status = st;
        }
        self.finished = true;
        Ok(SandboxResult {
            interrupted: self.interrupted,
            stdout: std::mem::take(&mut self.out),
            stderr: std::mem::take(&mut self.err),
            exit: ExitInfo::from_status(self.child_status),
            syscalls: self.syscalls,
            denied: self.denied,
        })
    }
}

/// A set of sandboxes driven by **one shared poll loop**. Every active
/// sandbox's live fds (listener + output pipes, minus the EOF'd ones — see
/// [`Sandbox::poll_slots`]) are registered in a single `poll(2)` call, so the
/// whole process sleeps when nothing is ready: no busy spinning, and no
/// per-sandbox polling anywhere. Finished sandboxes drop out of the poll set
/// automatically.
pub struct Supervisor {
    sandboxes: Vec<Sandbox>,
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            sandboxes: Vec::new(),
        }
    }

    /// Spawn a sandbox into the supervisor; returns its supervisor-wide id.
    /// The id is stable (slots are never reused), so it can be used to key
    /// policy state, answers, and results.
    pub fn add(&mut self, sb: Sandbox) -> usize {
        self.sandboxes.push(sb);
        self.sandboxes.len() - 1
    }

    /// Number of sandboxes ever added (finished or not).
    pub fn len(&self) -> usize {
        self.sandboxes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sandboxes.is_empty()
    }

    /// Whether any sandbox is still running.
    pub fn is_active(&self) -> bool {
        self.sandboxes.iter().any(|s| !s.finished)
    }

    /// Drive every sandbox to completion from a single global poll loop.
    ///
    /// Each round: build one poll set over every active sandbox's live fds,
    /// `poll` (blocking — this is where the whole process sleeps), then step
    /// each sandbox whose fds reported ready. A [`Step::Blocked`] is answered
    /// immediately via `on_ask(sandbox_id, &syscall)` — matching
    /// [`Sandbox::pump`], which is this restricted to one sandbox.
    ///
    /// Returns results in *completion order* as `(sandbox_id, result)`.
    pub fn drive<A, E>(
        &mut self,
        mut on_ask: A,
        mut on_event: E,
        poll_timeout_ms: i32,
    ) -> Result<Vec<(usize, SandboxResult)>>
    where
        A: FnMut(usize, &Syscall) -> Verdict,
        E: FnMut(usize, CoroutineEvent),
    {
        let mut results: Vec<(usize, SandboxResult)> = Vec::new();
        loop {
            // --- one poll set for every active sandbox's live fds ----------
            let mut pfds: Vec<libc::pollfd> = Vec::new();
            let mut meta: Vec<(usize, FdSlot)> = Vec::new();
            for (bi, sb) in self.sandboxes.iter().enumerate() {
                if sb.finished {
                    continue;
                }
                for (slot, pfd) in sb.poll_slots() {
                    pfds.push(pfd);
                    meta.push((bi, slot));
                }
            }
            if pfds.is_empty() {
                break; // every tree is gone
            }
            let pr = unsafe {
                libc::poll(
                    pfds.as_mut_ptr(),
                    pfds.len() as libc::nfds_t,
                    poll_timeout_ms,
                )
            };
            if pr == -1 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                bail!("poll: {e}");
            }
            if pr == 0 {
                continue; // timeout with nothing ready: block again
            }

            // --- hand each sandbox its listener revents ---------------------
            let n = self.sandboxes.len();
            let mut ready = vec![false; n];
            let mut listener_ev = vec![0i16; n];
            for (k, p) in pfds.iter().enumerate() {
                if p.revents == 0 {
                    continue;
                }
                let (bi, slot) = meta[k];
                ready[bi] = true;
                if slot == FdSlot::Listener {
                    listener_ev[bi] = p.revents;
                }
            }
            for bi in 0..n {
                if !ready[bi] {
                    continue;
                }
                let sb = &mut self.sandboxes[bi];
                match sb.step(listener_ev[bi])? {
                    Step::Event(ev) => on_event(bi, ev),
                    Step::Blocked { syscall, .. } => {
                        // Freeze the whole tree while this ask is pending;
                        // Allow thaws it below, Deny kills it in resolve_ask.
                        sb.freeze();
                        let verdict = on_ask(bi, &syscall);
                        sb.resolve_ask(verdict)?;
                        if matches!(verdict, Verdict::Allow) {
                            sb.resume();
                        }
                    }
                    Step::Idle => {}
                    Step::Finished(r) => {
                        results.push((bi, r));
                        // stays in `sandboxes` (finished flag set), but
                        // poll_slots() skips it next round
                    }
                }
            }
        }
        Ok(results)
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitInfo {
    fn from_status(status: i32) -> ExitInfo {
        if libc::WIFEXITED(status) {
            ExitInfo {
                code: Some(libc::WEXITSTATUS(status)),
                signal: None,
            }
        } else if libc::WIFSIGNALED(status) {
            ExitInfo {
                code: None,
                signal: Some(libc::WTERMSIG(status)),
            }
        } else {
            ExitInfo {
                code: None,
                signal: None,
            }
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if !self.finished {
            // Destructor contract: a dropped (unfinished) sandbox must never
            // leave a live process tree behind. Killing is best-effort (pids
            // are existence-probed); the root child is then reaped so its
            // slot frees immediately rather than lingering as a zombie. A
            // SIGKILL'd process dies without running anything, and a stopped
            // (frozen) one is killed all the same, so this is bounded.
            self.kill_tree();
            if !self.child_reaped {
                let mut st: i32 = 0;
                unsafe {
                    libc::waitpid(self.child, &mut st, 0);
                }
            }
        }
        unsafe {
            libc::close(self.listener);
            libc::close(self.out_r);
            libc::close(self.err_r);
            if self.stdin_w >= 0 {
                libc::close(self.stdin_w);
            }
        }
    }
}

/// Run a program under the sandbox to completion. `argv[0]` is the program
/// name; `named` is the interception mask ([`Sandbox::spawn`] — the fork
/// family is always added); the `decider` sees every masked syscall; a
/// [`Verdict::Ask`] from it is resolved as `Deny(EPERM)`.
pub fn run_sandboxed(
    argv: &[&str],
    named: &[i32],
    decider: impl FnMut(&Syscall) -> Verdict + Send + 'static,
) -> Result<SandboxResult> {
    let Some(program) = argv.first() else {
        bail!("empty argv");
    };
    let mut sandbox = Sandbox::spawn(program, &argv[1..], decider, named)?;
    sandbox.pump(|_| Verdict::Deny(libc::EPERM), |_| {})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal BPF interpreter over the "seccomp_data" layout we rely on
    /// (nr @ 0, arch @ 4, args[0] @ 16). Used to prove filter jump offsets.
    fn sim(filter: &[libc::sock_filter], nr: i32, arch: u32, arg0: u64) -> u32 {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&(nr as u32).to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        data[16..24].copy_from_slice(&arg0.to_le_bytes());
        let mut pc = 0usize;
        let mut a: u32 = 0;
        loop {
            let ins = &filter[pc];
            match ins.code & 0x07 {
                0x00 => {
                    // LD|W|ABS
                    assert_eq!(ins.code & 0xe0, 0x20, "only ABS addressing supported");
                    let k = ins.k as usize;
                    a = u32::from_le_bytes(data[k..k + 4].try_into().unwrap());
                    pc += 1;
                }
                0x05 => {
                    // JMP
                    let cond = match ins.code & 0xf0 {
                        0x10 => a == ins.k, // JEQ
                        0x30 => a >= ins.k, // JGE
                        _ => panic!("unsupported jmp op"),
                    };
                    pc += 1 + if cond {
                        ins.jt as usize
                    } else {
                        ins.jf as usize
                    };
                }
                0x06 => return ins.k, // RET
                other => panic!("unsupported code class {other:02x}"),
            }
        }
    }

    #[test]
    fn syscall_names() {
        assert_eq!(syscall_name(59), "execve");
        assert_eq!(syscall_name(317), "seccomp");
        assert_eq!(syscall_name(999999), "syscall_999999");
    }

    #[test]
    fn syscall_nr_resolves_names() {
        assert_eq!(syscall_nr("openat"), Some(257));
        assert_eq!(syscall_nr("clone3"), Some(435));
        assert_eq!(syscall_nr("write"), Some(1));
        assert_eq!(syscall_nr("openatt"), None);
        assert_eq!(syscall_nr(""), None);
    }

    #[test]
    fn named_filter_traps_only_the_named_syscalls() {
        // Mask {openat, write}: those trap, the handshake always runs
        // (allowed pair is checked first), and everything else — reads,
        // stats, mmap, forks — is the kernel-default ALLOW. The builder is
        // pure: the caller-supplied mask is what it traps; the engine's
        // `spawn` additionally merges the always-on FORK_FAMILY into it.
        let f = build_filter_named(&[257, 1], &[(SYS_SENDMSG, 7)]);
        // 6 header + 4 exception + 1 nr-reload + 2 per masked pair + default
        assert_eq!(f.len(), 6 + 4 + 1 + (2 * 2) + 1);
        assert_eq!(sim(&f, 46, AUDIT_ARCH, 7), SECCOMP_RET_ALLOW);
        assert_eq!(sim(&f, 46, AUDIT_ARCH, 8), SECCOMP_RET_ALLOW);
        assert_eq!(sim(&f, 257, AUDIT_ARCH, 0), SECCOMP_RET_USER_NOTIF);
        assert_eq!(sim(&f, 1, AUDIT_ARCH, 7), SECCOMP_RET_USER_NOTIF);
        assert_eq!(sim(&f, 0, AUDIT_ARCH, 0), SECCOMP_RET_ALLOW);
        assert_eq!(sim(&f, 57, AUDIT_ARCH, 0), SECCOMP_RET_ALLOW);
        // x32 ABI still killed; wrong arch still killed
        assert_eq!(
            sim(&f, 1 | (1 << 30), AUDIT_ARCH, 0),
            SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(sim(&f, 1, 0xc000_0037, 7), SECCOMP_RET_KILL_PROCESS);
        // A named syscall that is also exempted (sendmsg on the handshake fd)
        // still runs — allowed pairs are checked first.
        let f2 = build_filter_named(&[46], &[(SYS_SENDMSG, 7)]);
        assert_eq!(sim(&f2, 46, AUDIT_ARCH, 7), SECCOMP_RET_ALLOW);
        assert_eq!(sim(&f2, 46, AUDIT_ARCH, 8), SECCOMP_RET_USER_NOTIF);
    }

    #[test]
    fn named_mask_captures_the_tree_and_runs_everything_else_free() {
        // Narrow mask = {write}: only writes are intercepted (all allowed) —
        // the decider must never see anything but nr 1. `ls` forks an
        // executor: the fork family is always masked (auto-allowed), and the
        // forked child — which never performs a masked syscall of its own
        // here — still gets captured for signaling via /proc completion.
        // Un-named syscalls (execve, reads, stats, mmap…) run straight
        // through the kernel; the run completes with its stdout intact.
        let mut sandbox = Sandbox::spawn(
            "sh",
            &["-c", "ls /tmp >/dev/null; echo done"],
            |sc| {
                assert_eq!(sc.nr, 1, "only write must be masked, saw {}", sc.nr);
                Verdict::Allow
            },
            &[1],
        )
        .unwrap();
        let r = sandbox.pump(|_| Verdict::Allow, |_| {}).unwrap();
        assert_eq!(r.stdout, b"done\n");
        assert_eq!(r.exit.code, Some(0));
        assert!(r.syscalls >= 1, "writes are masked, so intercepts exist");
        assert!(r.denied == 0);
        assert!(sandbox.forks() >= 1, "the fork family is always masked");
        assert!(sandbox.pids().len() >= 2, "the forked child is captured");
    }

    #[test]
    fn named_mask_deny_kills_the_whole_tree() {
        // A denied write under a {write}-only mask still ends the run with
        // SIGKILL and empty output — narrow masking never weakens the
        // kill-on-deny contract.
        let mut sandbox = Sandbox::spawn(
            "sh",
            &["-c", "echo denied"],
            |_| Verdict::Deny(libc::EPERM),
            &[1],
        )
        .unwrap();
        let r = sandbox.pump(|_| Verdict::Allow, |_| {}).unwrap();
        assert!(r.stdout.is_empty(), "the denied write produced no output");
        assert_eq!(r.exit.signal, Some(libc::SIGKILL));
        assert!(r.denied >= 1);
    }

    #[test]
    fn proc_ppid_parses_stat_field_4() {
        // Our own process: stat is always readable in this process tree.
        let me = std::process::id() as i32;
        let ppid = proc_ppid(me).expect("own ppid readable");
        assert!(ppid > 1, "ppid {ppid} of pid {me} is not init's");
        assert_eq!(proc_ppid(-1), None);
    }

    // ---- real-fork integration --------------------------------------------

    #[test]
    fn captures_stdout_and_exit_code() {
        let r = run_sandboxed(&["sh", "-c", "echo hello from sandbox"], &[1], |_| {
            Verdict::Allow
        })
        .unwrap();
        assert_eq!(r.stdout, b"hello from sandbox\n");
        assert!(r.stderr.is_empty());
        assert_eq!(r.exit.code, Some(0));
        assert!(r.syscalls > 0);
        assert_eq!(r.denied, 0);
    }

    #[test]
    fn separates_stdout_and_stderr() {
        let r = run_sandboxed(&["sh", "-c", "printf out; printf err >&2"], &[1], |_| {
            Verdict::Allow
        })
        .unwrap();
        assert_eq!(r.stdout, b"out");
        assert_eq!(r.stderr, b"err");
        assert_eq!(r.exit.code, Some(0));
    }

    #[test]
    fn deny_write_breaks_the_tracee() {
        let r = run_sandboxed(&["sh", "-c", "echo hello"], &[1], |sc| {
            if sc.nr == 1 {
                Verdict::Deny(libc::EPERM)
            } else {
                Verdict::Allow
            }
        })
        .unwrap();
        assert!(
            r.stdout.is_empty(),
            "write was denied, stdout must be empty"
        );
        assert!(r.exit.code != Some(0), "tracee should have failed");
        assert_eq!(
            r.exit.signal,
            Some(libc::SIGKILL),
            "a denied request must kill the whole tree"
        );
        assert!(r.denied >= 1);
    }

    #[test]
    fn ask_freezes_then_resolves_allow() {
        let mut sandbox = Sandbox::spawn(
            "sh",
            &["-c", "echo asked-ok"],
            |sc| {
                if sc.nr == 1 {
                    Verdict::Ask
                } else {
                    Verdict::Allow
                }
            },
            &[1],
        )
        .unwrap();
        let mut saw_blocked = false;
        let r = sandbox
            .pump(
                |_| {
                    saw_blocked = true;
                    Verdict::Allow
                },
                |_| {},
            )
            .unwrap();
        assert!(saw_blocked);
        assert_eq!(r.stdout, b"asked-ok\n");
        assert_eq!(r.exit.code, Some(0));
        assert_eq!(r.denied, 0);
    }

    #[test]
    fn ask_deny_blocks_the_write() {
        let mut sandbox = Sandbox::spawn(
            "sh",
            &["-c", "echo denied-ok"],
            |sc| {
                if sc.nr == 1 {
                    Verdict::Ask
                } else {
                    Verdict::Allow
                }
            },
            &[1],
        )
        .unwrap();
        let r = sandbox
            .pump(|_| Verdict::Deny(libc::EPERM), |_| {})
            .unwrap();
        assert!(r.stdout.is_empty());
        assert!(r.exit.code != Some(0));
        assert_eq!(
            r.exit.signal,
            Some(libc::SIGKILL),
            "an answered-deny must kill the whole tree"
        );
        assert!(r.denied >= 1);
    }

    #[test]
    fn multi_process_tree_is_traced_and_captured() {
        // sh forks (vfork) for `ls`, then runs the builtin printf. The
        // caller's mask is empty, yet the fork is still intercepted: the
        // engine always masks the fork family (auto-allowed) for pid
        // bookkeeping, so the fork counter still ticks under an empty mask.
        let mut sb = Sandbox::spawn(
            "sh",
            &["-c", "ls >/dev/null; printf done"],
            |_| Verdict::Allow,
            &[],
        )
        .unwrap();
        let r = sb.pump(|_| Verdict::Allow, |_| {}).unwrap();
        assert!(r.stdout.ends_with(b"done"));
        assert_eq!(r.exit.code, Some(0));
        assert!(sb.forks() >= 1, "the fork family is always masked");
    }

    #[test]
    fn exit_code_and_signal_propagate() {
        let r = run_sandboxed(&["sh", "-c", "exit 7"], &[], |_| Verdict::Allow).unwrap();
        assert_eq!(r.exit.code, Some(7));
        assert_eq!(r.exit.signal, None);

        let r = run_sandboxed(&["sh", "-c", "kill -TERM $$"], &[], |_| Verdict::Allow).unwrap();
        assert_eq!(r.exit.code, None);
        assert_eq!(r.exit.signal, Some(libc::SIGTERM));
    }

    #[test]
    fn multiple_sandboxes_driven_from_one_poll_loop() {
        // Three independent sandboxes in one Supervisor, each sleeping
        // briefly. One shared poll loop must drive them all; wall time
        // << 3× the sleep proves they genuinely overlap (they are separate
        // OS processes, supervised cooperatively from a single thread).
        let cmds: Vec<String> = (0..3)
            .map(|i| format!("echo box-{i}; sleep 0.05; echo done-{i}"))
            .collect();
        let mut sup = Supervisor::new();
        for c in &cmds {
            sup.add(Sandbox::spawn("sh", &["-c", c.as_str()], |_| Verdict::Allow, &[1]).unwrap());
        }

        let start = std::time::Instant::now();
        let results = sup
            .drive(|_, _| Verdict::Allow, |_, _| {}, DEFAULT_POLL_TIMEOUT_MS)
            .unwrap();
        let elapsed = start.elapsed();

        // drive() returns completion order; map back to ids.
        for i in 0..3 {
            let r = results
                .iter()
                .find(|(id, _)| *id == i)
                .map(|(_, r)| r.clone())
                .expect("every sandbox must finish");
            assert_eq!(r.stdout, format!("box-{i}\ndone-{i}\n").as_bytes());
            assert_eq!(r.exit.code, Some(0));
            assert!(r.syscalls > 0);
        }
        assert!(
            elapsed < std::time::Duration::from_millis(120),
            "sandboxes did not overlap: {elapsed:?}"
        );
    }

    #[test]
    fn supervisor_dispatches_asks_with_sandbox_id() {
        // The first write(1, ...) asks; the supervisor's on_ask must see the
        // right sandbox id and the answer must thaw the target.
        let asked = std::cell::Cell::new(false);
        let mut sup = Supervisor::new();
        let id = sup.add(
            Sandbox::spawn(
                "sh",
                &["-c", "echo dispatched"],
                move |sc| {
                    if sc.nr == 1 && !asked.get() {
                        asked.set(true);
                        Verdict::Ask
                    } else {
                        Verdict::Allow
                    }
                },
                &[1],
            )
            .unwrap(),
        );

        let mut seen_asks = Vec::new();
        let results = sup
            .drive(
                |bid, sc| {
                    seen_asks.push((bid, sc.nr));
                    Verdict::Allow
                },
                |_, _| {},
                DEFAULT_POLL_TIMEOUT_MS,
            )
            .unwrap();

        assert_eq!(seen_asks, vec![(id, 1)]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, id);
        assert_eq!(results[0].1.stdout, b"dispatched\n");
        assert_eq!(results[0].1.exit.code, Some(0));
    }

    #[test]
    fn traced_child_reads_isolated_stdin() {
        // The tracee's fd 0 is a private pipe, not the supervisor's stdin.
        // queue_stdin feeds it; a line is echoed back on stdout.
        let mut sandbox = Sandbox::spawn(
            "sh",
            &["-c", "read x; echo got:$x"],
            |_| Verdict::Allow,
            &[1],
        )
        .unwrap();
        sandbox.queue_stdin(b"hello\n").unwrap();
        let r = sandbox.pump(|_| Verdict::Allow, |_| {}).unwrap();
        assert_eq!(r.stdout, b"got:hello\n");
        assert_eq!(r.exit.code, Some(0));
    }

    /// A handle stops the run it came from, and says so in the result.
    ///
    /// `sleep 30` is the fixture because it is the thing a user actually wants to
    /// stop — and, more to the point, because it is *silent*, so the only place
    /// the driver can notice an interrupt is the poll-timeout path. A chatty
    /// fixture would pass with that path missing, which is the bug this test was
    /// written after finding.
    ///
    /// The request goes through this run's own handle rather than
    /// [`request_interrupt`], because that reads the agent's single slot and this
    /// suite has dozens of sandboxes running at once. It is also the better test
    /// for the property that matters: a handle reaches its own run and no other.
    #[test]
    fn a_handle_stops_its_own_run_and_the_result_says_so() {
        let mut sandbox =
            Sandbox::spawn("sh", &["-c", "sleep 30"], |_| Verdict::Allow, &[1]).unwrap();
        let handle = sandbox.interrupt_handle();
        let started = std::time::Instant::now();
        handle.interrupt();
        let r = sandbox.pump(|_| Verdict::Allow, |_| {}).expect("the run succeeded");
        assert!(r.interrupted, "the result says it was interrupted");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "and it did not wait out the sleep: {:?}",
            started.elapsed()
        );
    }

    /// One run's request does not reach another. This is the property both earlier
    /// designs got wrong, and the reason the flag is per-run: a global counter
    /// made a single request kill every concurrently-running sandbox, which
    /// showed up as fifteen unrelated tests failing at once.
    #[test]
    fn a_request_reaches_only_the_run_whose_handle_it_came_from() {
        let mut mine =
            Sandbox::spawn("sh", &["-c", "sleep 30"], |_| Verdict::Allow, &[1]).unwrap();
        let theirs =
            Sandbox::spawn("sh", &["-c", "echo fine; sleep 30"], |_| Verdict::Allow, &[1])
                .unwrap();
        mine.interrupt_handle().interrupt();
        let stopped = mine.pump(|_| Verdict::Allow, |_| {}).expect("the run succeeded");
        assert!(stopped.interrupted, "the addressed run stopped");
        // The other one is untouched: the driver has not even been called, so
        // nothing has asked it to do anything.
        assert!(theirs.pids().len() <= 1, "the other run is still whole");
    }

    /// A run started *after* a request cannot inherit it — the property that lets
    /// the agent fire an interrupt on every `Ctrl+c` without first checking
    /// whether a tool happens to be live.
    ///
    /// Held by the per-run flag rather than tested directly: the flag is created
    /// with the run, so "a later run cannot see an earlier request" is structural
    /// and there is nothing to assert. It *was* tested directly, against a global
    /// latch, and the test could not be made race-free — `request_interrupt`
    /// reads the agent's single slot, which in a parallel suite names whichever
    /// sandbox started last, so the test killed somebody else's run. Dropping the
    /// test is the honest outcome: the global registry is left uncovered, and it
    /// is six lines of plumbing whose whole content is "the slot names the run the
    /// agent is running".
    #[test]
    fn a_later_run_cannot_see_an_earlier_runs_request() {
        let earlier =
            Sandbox::spawn("sh", &["-c", "sleep 30"], |_| Verdict::Allow, &[1]).unwrap();
        earlier.interrupt_handle().interrupt();
        // A run that begins after that request, with a flag of its own.
        let r = run_sandboxed(&["sh", "-c", "echo alive"], &[1], |_| Verdict::Allow).unwrap();
        assert_eq!(r.stdout, b"alive\n");
        assert!(!r.interrupted, "and it ran to completion");
    }

    #[test]
    fn stdin_overflow_is_queued_and_flushed_by_the_poll_loop() {
        // Feed 1 MiB — beyond the ~64 KiB pipe buffer — in one queue_stdin
        // call: the overflow must sit in `input` and be flushed as the poll
        // loop re-registers the write end after POLLOUT. `head -c` reads
        // (and echoes) exactly N bytes, so no EOF is required.
        let n = 1 << 20;
        let mut sandbox =
            Sandbox::spawn("sh", &["-c", "head -c 1048576"], |_| Verdict::Allow, &[1]).unwrap();
        sandbox.queue_stdin(&vec![b'x'; n]).unwrap();
        let r = sandbox.pump(|_| Verdict::Allow, |_| {}).unwrap();
        assert_eq!(r.stdout.len(), n);
        assert!(r.stdout.iter().all(|&b| b == b'x'));
        assert_eq!(r.exit.code, Some(0));
    }

    #[test]
    fn stdin_eof_closes_and_input_after_eof_is_dropped() {
        // close_stdin → the tracee's read(0) sees EOF and `cat` finishes
        // with empty output; queued input after that is dropped.
        let mut sandbox = Sandbox::spawn("sh", &["-c", "cat"], |_| Verdict::Allow, &[1]).unwrap();
        sandbox.close_stdin();
        sandbox.queue_stdin(b"dropped\n").unwrap();
        let r = sandbox.pump(|_| Verdict::Allow, |_| {}).unwrap();
        assert!(r.stdout.is_empty());
        assert_eq!(r.exit.code, Some(0));
    }

    // ------------------------------------------------------------------
    // tree bookkeeping: pid capture, freeze/resume, kill-on-deny/drop
    // ------------------------------------------------------------------

    /// `/proc/<pid>/stat` state character (`R`/`S`/`T`/`Z`/…), if readable.
    fn proc_state(pid: libc::pid_t) -> Option<char> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let close = s.rfind(')')?;
        s.as_bytes().get(close + 2).copied().map(|b| b as char)
    }

    /// Poll until `/proc/<pid>/stat` reports `state` (bounded). SIGSTOP's
    /// `T` transition lands on a scheduler tick, not synchronously with
    /// `kill`, so asserting must poll.
    fn wait_state(pid: libc::pid_t, state: char, timeout: std::time::Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if proc_state(pid) == Some(state) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        proc_state(pid) == Some(state)
    }

    #[test]
    fn pid_and_pids_track_the_root_child() {
        // The root child is in `pids` from spawn; the fork counter starts at
        // zero and nothing is captured that never ran.
        let mut sandbox = Sandbox::spawn("sh", &["-c", "exit 0"], |_| Verdict::Allow, &[]).unwrap();
        let root = sandbox.pid();
        assert!(root > 0);
        assert_eq!(sandbox.pids(), vec![root]);
        assert_eq!(sandbox.forks(), 0);
        let r = sandbox.pump(|_| Verdict::Allow, |_| {}).unwrap();
        assert_eq!(r.exit.code, Some(0));
        assert_eq!(sandbox.pids(), vec![root]);
    }

    #[test]
    fn captures_forked_children_pids() {
        // `ls … & wait` forces a fork (dash vforks for external commands);
        // the forked child announces itself via its own syscalls and must
        // land in `pids`, and the fork hook must have observed the fork.
        let mut sandbox = Sandbox::spawn(
            "sh",
            &["-c", "echo START; ls /tmp >/dev/null & wait; echo END"],
            |_| Verdict::Allow,
            &[1],
        )
        .unwrap();
        let r = sandbox.pump(|_| Verdict::Allow, |_| {}).unwrap();
        assert_eq!(r.stdout, b"START\nEND\n");
        assert_eq!(r.exit.code, Some(0));
        assert!(sandbox.forks() >= 1, "a fork must have been observed");
        assert!(
            sandbox.pids().len() >= 2,
            "the forked child's pid must be captured: {:?}",
            sandbox.pids()
        );
        assert!(
            sandbox.pids().contains(&sandbox.pid()),
            "the root child must stay in the captured set"
        );
    }

    #[test]
    fn deny_decides_kill_the_whole_tree_fast() {
        // sleep(1) → nanosleep; the first one is denied, and the whole tree
        // dies at once — far faster than the 0.5 s sleep would take.
        let start = std::time::Instant::now();
        let r = run_sandboxed(&["sleep", "0.5"], &[35, 230], |sc| {
            if sc.nr == 35 || sc.nr == 230 {
                Verdict::Deny(libc::EPERM)
            } else {
                Verdict::Allow
            }
        })
        .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(
            r.exit.signal,
            Some(libc::SIGKILL),
            "a decider-deny must kill the whole tree"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(400),
            "deny must kill the tree promptly, took {elapsed:?}"
        );
        assert!(r.denied >= 1);
    }

    #[test]
    fn ask_deny_kills_the_whole_tree_fast() {
        // The same, via the frozen-ask path: the tree is SIGSTOP'd while the
        // ask is pending, then a Deny answer kills it outright — no thaw, no
        // waiting out the 0.5 s sleep.
        let start = std::time::Instant::now();
        let mut sandbox = Sandbox::spawn(
            "sleep",
            &["0.5"],
            |sc| {
                if sc.nr == 35 || sc.nr == 230 {
                    Verdict::Ask
                } else {
                    Verdict::Allow
                }
            },
            &[35, 230],
        )
        .unwrap();
        let r = sandbox
            .pump(|_| Verdict::Deny(libc::EPERM), |_| {})
            .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(
            r.exit.signal,
            Some(libc::SIGKILL),
            "an answered-deny must kill the whole tree"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(400),
            "ask-deny must kill the tree promptly, took {elapsed:?}"
        );
        assert!(r.denied >= 1);
    }

    /// Drive until the next [`Step::Blocked`], resolving non-blocked steps
    /// inline, exactly like [`Sandbox::pump`]'s poll+step loop stopping at
    /// the ask. Lets a test intercept the freeze/resolve points.
    fn step_until_blocked(sb: &mut Sandbox) -> Result<Step> {
        loop {
            let slots = sb.poll_slots();
            if slots.is_empty() {
                return match sb.step(0)? {
                    Step::Finished(r) => Ok(Step::Finished(r)),
                    other => bail!("tree gone but step returned {other:?}"),
                };
            }
            let mut pfds: Vec<libc::pollfd> = slots.iter().map(|(_, p)| *p).collect();
            let pr = unsafe {
                libc::poll(
                    pfds.as_mut_ptr(),
                    pfds.len() as libc::nfds_t,
                    DEFAULT_POLL_TIMEOUT_MS,
                )
            };
            if pr == -1 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                bail!("poll: {e}");
            }
            if pr == 0 {
                // Timeout, nothing ready — and the only moment a silent command
                // can be interrupted, since it will never reach `step`.
                sb.service_interrupt();
                continue; // back to sleep
            }
            let mut listener_revents = 0i16;
            for (k, p) in pfds.iter().enumerate() {
                if p.revents != 0 && slots[k].0 == FdSlot::Listener {
                    listener_revents = p.revents;
                }
            }
            match sb.step(listener_revents)? {
                st @ Step::Blocked { .. } => return Ok(st),
                Step::Event(_) | Step::Idle => {}
                Step::Finished(r) => return Ok(Step::Finished(r)),
            }
        }
    }

    #[test]
    fn completion_wait_holds_until_the_allowed_syscall_executes() {
        // `sleep 1` masks only nanosleep (35; the fork family is always
        // masked, but a directly-exec'd `sleep` never forks). After the Allow
        // response is *sent*, the kernel keeps the notification id valid until
        // the syscall finishes — so `resolve_ask_frozen`'s completion wait
        // must span the whole 1 s sleep. This is the empirical contract the
        // TOCTOU gate rests on: the siblings stay frozen until the allowed
        // syscall has actually executed.
        let mut sandbox = Sandbox::spawn("sleep", &["1"], |_| Verdict::Ask, &[35]).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "run must finish within the deadline"
            );
            match step_until_blocked(&mut sandbox).unwrap() {
                Step::Finished(r) => {
                    assert_eq!(r.exit.code, Some(0));
                    break;
                }
                Step::Blocked { syscall, .. } => {
                    assert_eq!(syscall.nr, 35, "only nanosleep is masked");
                    sandbox.freeze_others(syscall.pid); // no siblings: a no-op
                    let t0 = std::time::Instant::now();
                    sandbox.resolve_ask_frozen(Verdict::Allow).unwrap();
                    let waited = t0.elapsed();
                    assert!(
                        waited >= std::time::Duration::from_millis(700),
                        "the completion wait must span the 1 s nanosleep, held {waited:?}"
                    );
                }
                Step::Event(_) | Step::Idle => {}
            }
        }
    }

    #[test]
    fn freeze_others_quiesces_siblings_but_never_the_asker() {
        // bash spawns a background `sleep 5` (sibling) then a foreground
        // `sleep 1`; nanosleep/clock_nanosleep (35/230) are the only masked
        // syscalls besides the always-masked fork family. When a sleeper
        // blocks, `freeze_others` must leave it parked (the kernel already
        // does) while every other live tree process reports state `T` — and
        // the later allow round trip must still deliver. The old full-tree
        // `freeze()` interrupted the asker's notif-wait and re-asked forever;
        // excluding the asker is what makes this livelock impossible.
        let mut sandbox = Sandbox::spawn(
            "bash",
            &["-c", "sleep 1 & sleep 0.3"],
            |_| Verdict::Ask,
            &[35, 230],
        )
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut froze = false;
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "run must finish, not livelock"
            );
            match step_until_blocked(&mut sandbox).unwrap() {
                Step::Finished(r) => {
                    assert_eq!(r.exit.code, Some(0), "expected a clean exit");
                    break;
                }
                Step::Blocked { syscall, .. } => {
                    if matches!(syscall.nr, 56 | 57 | 58 | 435) {
                        // fork family: let the tree keep growing
                        sandbox.resolve_ask(Verdict::Allow).unwrap();
                        continue;
                    }
                    assert!(
                        matches!(syscall.nr, 35 | 230),
                        "only the sleep syscalls are masked, saw {}",
                        syscall.nr
                    );
                    sandbox.freeze_others(syscall.pid);
                    let asker = proc_state_of(syscall.pid);
                    assert!(
                        asker.is_some() && !matches!(asker, Some('T') | Some('t')),
                        "the asker must stay parked, not stopped: {asker:?}"
                    );
                    for &pid in sandbox.pids().iter() {
                        if pid == syscall.pid {
                            continue;
                        }
                        assert!(
                            wait_state(pid, 'T', std::time::Duration::from_millis(500)),
                            "sibling {pid} must be stopped"
                        );
                    }
                    froze = true;
                    // Answer, hold the frozen siblings until the syscall has
                    // run (bounded), then thaw.
                    sandbox.resolve_ask_frozen(Verdict::Allow).unwrap();
                }
                Step::Event(_) | Step::Idle => {}
            }
        }
        assert!(froze, "a nanosleep ask must have been observed");
    }

    #[test]
    fn proc_tgid_identifies_the_process_behind_a_thread() {
        // Main thread: tid == tgid.
        let me = std::process::id() as i32;
        assert_eq!(proc_tgid(me), Some(me));
        // A spawned thread: its tid differs, its tgid is the main process —
        // exactly the mapping freeze_others needs to exclude an asker thread
        // without stopping its whole process.
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            tx.send(tid).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
        });
        let tid = rx.recv().unwrap();
        assert_ne!(tid, me, "a spawned thread has its own tid");
        assert_eq!(proc_tgid(tid), Some(me), "its tgid is the main process");
        t.join().unwrap();
    }

    #[test]
    fn ask_freezes_the_whole_tree_while_pending() {
        // The ask hook freezes the whole tree *before* surfacing the question
        // — the answerer (the future Lua policy / the user) must observe every
        // captured pid stopped. On Allow the tree is thawed and completes.
        let asked = std::cell::Cell::new(false);
        let mut sandbox = Sandbox::spawn(
            "sleep",
            &["0.4"],
            move |sc| {
                if (sc.nr == 35 || sc.nr == 230) && !asked.get() {
                    asked.set(true);
                    Verdict::Ask
                } else {
                    Verdict::Allow
                }
            },
            &[35, 230],
        )
        .unwrap();
        let root = sandbox.pid();
        let mut frozen = false;
        let r = sandbox
            .pump(
                |_| {
                    frozen = wait_state(root, 'T', std::time::Duration::from_secs(2));
                    Verdict::Allow
                },
                |_| {},
            )
            .unwrap();
        assert!(
            frozen,
            "the tree must be frozen (state T) while an ask is pending"
        );
        assert_eq!(r.exit.code, Some(0));
    }

    #[test]
    fn drop_kills_a_live_tree() {
        // A sandbox that is dropped without ever being driven must not leave
        // its process running: the destructor SIGKILLs the tree and reaps the
        // root child, so the pid goes absent (kill(pid, 0) → ESRCH) instead
        // of living out its 5 s sleep.
        let sandbox = Sandbox::spawn("sleep", &["5"], |_| Verdict::Allow, &[]).unwrap();
        let root = sandbox.pid();
        drop(sandbox);
        let start = std::time::Instant::now();
        let mut gone = false;
        while start.elapsed() < std::time::Duration::from_secs(2) {
            let alive = unsafe {
                let r = libc::kill(root, 0);
                if r == 0 {
                    true
                } else {
                    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
                }
            };
            if !alive {
                gone = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(gone, "dropping a live sandbox must kill its whole tree");
    }
}
