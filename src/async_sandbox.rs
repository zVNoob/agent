//! Tokio readiness adapter — drives a [`seccomp::Sandbox`] from the agent's
//! **single** reactor, so sandbox fds, the HTTP client, and the TUI stdin all
//! share one `epoll_wait`: one power-efficient poll loop, nothing busy-spins.
//!
//! [`AsyncSandbox`] owns a spawned [`seccomp::Sandbox`] (the non-blocking
//! coroutine substrate) plus dup'd [`AsyncFd`]s for its four live fds
//! (listener, stdout, stderr, and the per-run stdin write end). [`drive`]
//! maps the engine's [`seccomp::Sandbox::poll_slots`] — the single source of
//! truth for which fd is worth awaiting — onto `select!`, then hands each
//! readiness token to the existing non-blocking [`seccomp::Sandbox::step`].
//!
//! The suspend/resume contract travels over channels instead of callbacks:
//!
//! - a [`Verdict::Ask`] freezes the tracee; [`Ask`] is sent on `ask_tx` and
//!   [`drive`] **awaits** the verdict on `answer_rx`, so the reactor stays
//!   free while the policy engine (or the user, or a Lua coroutine) decides.
//!   While frozen, buffered output keeps draining before the await.
//! - tracee stdin is fed through `input_rx` into [`seccomp::Sandbox`]'s
//!   non-blocking queue; a full pipe parks on `POLLOUT` (`EAGAIN`) instead
//!   of blocking the reactor. Dropping the input sender signals EOF: once
//!   the queue has drained, the dup'd write end is closed so the tracee's
//!   `read(0)` sees EOF.
//!
//! Listener death needs no special handling: tokio's fd readiness maps
//! `POLLHUP` onto "readable", so the guarded `NOTIF_RECV` probe the engine
//! runs on readiness returns `ENOENT`, [`seccomp::Sandbox`] records
//! `tree_done`, and the normal completion path finishes the result.
//!
//! Seccomp's notification fd (and the output pipes) can wake an `AsyncFd`
//! with *no* work behind it: a notification that was consumed elsewhere wakes
//! the listener for its now-empty queue, and a burst drains the pipes between
//! polls. An `AsyncFd` guard dropped without [`AsyncFdReadyGuard::clear_ready`]
//! latches that stale readiness — [`AsyncSandbox::drive_live`]'s `select!` then
//! re-fires instantly and the current_thread reactor parks on a dead event,
//! freezing its timer wheel (kills, timeouts) until a real event lands.
//! [`AsyncSandbox::drive_live`] therefore holds each fired guard until the
//! engine's non-blocking [`seccomp::Sandbox::step`] confirms the fire carried
//! no work, then consumes the edge with `clear_ready()` — the drain-then-clear
//! cadence keeps timers live, while level-triggered epoll re-reports genuinely
//! pending work with a fresh guard.
//!
//! Interrupts travel on a separate `watch` channel: [`AsyncSandbox::kill_handle`]
//! hands out a cloneable [`KillHandle`] whose `kill()` requests the prompt
//! termination of the whole captured tree ([`seccomp::Sandbox::kill_tree`] —
//! every pid, not just the root, so descendants can't outlive the run). The
//! driver notices the signal in its `select!` even while parked on a verdict,
//! so a kill during a frozen ask terminates the run without waiting for the
//! policy's answer. [`AsyncSandbox::drive_live`] additionally forwards every
//! output chunk to a callback as it arrives (also while frozen), while the
//! final [`seccomp::SandboxResult`] still carries the full captured output.

use anyhow::{Context, Result, anyhow, bail};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::sync::{mpsc, watch};

use crate::seccomp::{self, Step, Verdict};

/// An intercepted syscall that the engine froze with [`Verdict::Ask`], handed
/// to the policy engine for a verdict. Send the verdict back via
/// [`Channels`]'s `answer_tx`.
#[derive(Debug)]
pub struct Ask {
    pub sandbox_id: usize,
    pub syscall: seccomp::Syscall,
    pub request: u64,
}

/// Channel ends the driver's caller holds while [`drive`] runs: the asks it
/// must answer, the verdicts it feeds back, and the stdin it may stream into
/// the tracee's isolated stdin pipe.
pub struct Channels(
    pub mpsc::UnboundedReceiver<Ask>,
    pub mpsc::UnboundedSender<Verdict>,
    pub mpsc::UnboundedSender<Vec<u8>>,
);

impl Channels {
    pub fn ask_rx(&mut self) -> &mut mpsc::UnboundedReceiver<Ask> {
        &mut self.0
    }
    pub fn answer_tx(&self) -> mpsc::UnboundedSender<Verdict> {
        self.1.clone()
    }
    pub fn input_tx(&self) -> mpsc::UnboundedSender<Vec<u8>> {
        self.2.clone()
    }
}

/// A cloneable interrupt handle: [`KillHandle::kill`] requests the prompt
/// termination of the **whole** captured tree — every pid, via
/// [`seccomp::Sandbox::kill_tree`] — not just the root, so already-spawned
/// descendants can't outlive the run. It works at any point, *including*
/// while the sandbox is frozen on an ask: the driver parks on this channel
/// alongside the verdict channel, so a kill terminates the run without
/// waiting for the policy's answer.
#[derive(Clone)]
pub struct KillHandle {
    tx: watch::Sender<bool>,
}

impl KillHandle {
    /// Request the tree's prompt termination. Idempotent, and safe to call
    /// from any thread, before or during [`AsyncSandbox::drive`] (or with
    /// several cloned handles from different callers).
    pub fn kill(&self) {
        let _ = self.tx.send(true);
    }
}

/// A [`seccomp::Sandbox`] with its fds registered with the tokio reactor.
pub struct AsyncSandbox {
    sandbox: seccomp::Sandbox,
    listener: AsyncFd<OwnedFd>,
    out: AsyncFd<OwnedFd>,
    err: AsyncFd<OwnedFd>,
    stdin: Option<AsyncFd<OwnedFd>>,
    sandbox_id: usize,
    input_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ask_tx: mpsc::UnboundedSender<Ask>,
    answer_rx: mpsc::UnboundedReceiver<Verdict>,
    /// Interrupt latch: [`KillHandle`]es clone the sender; the driver holds
    /// the receiver and notices the signal in its `select!`s (see
    /// [`AsyncSandbox::drive_live`]).
    kill_tx: watch::Sender<bool>,
    kill_rx: watch::Receiver<bool>,
}

/// Dup a sandbox-owned raw fd into an [`AsyncFd`] (the dup, not the original:
/// the sandbox keeps owning its fds). The dup shares the file description,
/// so the listener dup polls the same notification queue the engine ioctls.
fn dup_async(fd: RawFd) -> Result<AsyncFd<OwnedFd>> {
    let dup = unsafe { libc::dup(fd) };
    if dup == -1 {
        bail!("dup({fd}): {}", std::io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(dup) };
    AsyncFd::new(owned).context("AsyncFd")
}

impl AsyncSandbox {
    /// Spawn a sandbox and wrap it, returning the driver and the caller-held
    /// channel ends. `argv[0]` is the program name; the syscalls named in
    /// `named` (plus the engine's always-masked fork family) go through
    /// `decider` (see [`seccomp::Sandbox::spawn`]).
    pub fn spawn(
        program: &str,
        argv: &[&str],
        decider: impl FnMut(&seccomp::Syscall) -> Verdict + Send + 'static,
        named: &[i32],
    ) -> Result<(AsyncSandbox, Channels)> {
        let sandbox = seccomp::Sandbox::spawn(program, argv, decider, named)?;
        Self::wrap(sandbox)
    }

    /// Wrap an already-spawned sandbox (e.g. one from a `Supervisor`),
    /// creating fresh channels.
    pub fn wrap(sandbox: seccomp::Sandbox) -> Result<(AsyncSandbox, Channels)> {
        let (ask_tx, ask_rx) = mpsc::unbounded_channel();
        let (answer_tx, answer_rx) = mpsc::unbounded_channel();
        let (input_tx, input_rx) = mpsc::unbounded_channel();
        let (kill_tx, kill_rx) = watch::channel(false);
        // Dup before moving `sandbox` (the fds live on it; the dups are what
        // the reactor polls — the sandbox keeps owning the originals).
        let listener = dup_async(sandbox.listener_fd())?;
        let out = dup_async(sandbox.stdout_fd())?;
        let err = dup_async(sandbox.stderr_fd())?;
        let stdin = match sandbox.stdin_fd() {
            Some(fd) => Some(dup_async(fd)?),
            None => None,
        };
        let driver = AsyncSandbox {
            sandbox,
            listener,
            out,
            err,
            stdin,
            sandbox_id: 0,
            input_rx,
            ask_tx,
            answer_rx,
            kill_tx,
            kill_rx,
        };
        // Note: the listener's dup shares the open file description with the
        // engine's fd, so it inherits O_NONBLOCK. The engine additionally
        // poll-gates NOTIF_RECV (a zero-timeout poll confirms a notification
        // is queued before the ioctl, see
        // `seccomp::Sandbox::handle_notification`), so a wake that carries no
        // queued notification simply idles instead of blocking the reactor.
        Ok((driver, Channels(ask_rx, answer_tx, input_tx)))
    }

    /// Tag asks with a supervisor-wide sandbox id (future multi-sandbox use).
    pub fn with_id(mut self, id: usize) -> Self {
        self.sandbox_id = id;
        self
    }

    /// A cloneable handle that interrupts the run — kills the **whole**
    /// captured tree promptly, at any point (see [`KillHandle`]). Take it
    /// before handing the driver to [`AsyncSandbox::drive`] /
    /// [`AsyncSandbox::drive_live`].
    pub fn kill_handle(&self) -> KillHandle {
        KillHandle {
            tx: self.kill_tx.clone(),
        }
    }

    /// The sandbox tree's root pid — the direct child of the underlying
    /// [`seccomp::Sandbox`] — useful for diagnostics and external monitoring.
    ///
    /// To *interrupt* a run, use [`AsyncSandbox::kill_handle`] instead: a
    /// bare SIGKILL on the root would leave already-spawned descendants
    /// running until they exit on their own (the seccomp listener only EOFs
    /// once the last filter user is gone), whereas [`KillHandle::kill`]
    /// SIGKILLs every captured pid and the tree is reaped when the drive
    /// future resolves.
    pub fn pid(&self) -> libc::pid_t {
        self.sandbox.pid()
    }

    /// Drive the sandbox to completion from the shared reactor, buffering all
    /// output internally: the returned [`seccomp::SandboxResult`] carries the
    /// full captured stdout/stderr. Use [`AsyncSandbox::drive_live`] when
    /// output chunks must be observed as they arrive. A [`KillHandle`] taken
    /// from [`AsyncSandbox::kill_handle`] interrupts the run at any point —
    /// including while it is parked on a verdict.
    ///
    /// Steals no thread: the only blocking parts are the `select!` polls, and
    /// the engine's `step` is never called without a readiness token that
    /// makes its RECV safe.
    pub async fn drive(self) -> Result<seccomp::SandboxResult> {
        self.drive_live(|_, _| {}).await
    }

    /// [`AsyncSandbox::drive`] with live output: every captured stdout/stderr
    /// chunk is forwarded to `on_output(stream, data)` the moment it arrives
    /// (also while the tree is frozen on an ask), so a consumer can stream it
    /// before the run completes. The final [`seccomp::SandboxResult`] still
    /// carries the full captured output.
    pub async fn drive_live<F>(self, mut on_output: F) -> Result<seccomp::SandboxResult>
    where
        F: FnMut(seccomp::Stream, Vec<u8>),
    {
        let AsyncSandbox {
            mut sandbox,
            listener,
            out,
            err,
            mut stdin,
            sandbox_id,
            mut input_rx,
            ask_tx,
            mut answer_rx,
            mut kill_rx,
            ..
        } = self;
        let mut listener_ready = false;
        let mut input_eof = false;
        // Interrupt state: `killed` latches the first kill so a second signal
        // is a no-op; `kill_alive` drops to false once the last KillHandle is
        // gone, so the arm can never spin on a senderless watch receiver.
        let mut killed = false;
        let mut kill_alive = true;
        // Readiness edges from the last `select!` fire, held until the engine
        // confirms they carried no work. An `AsyncFd` guard dropped un-cleared
        // latches that fd's readiness: the next `select!` re-fires instantly
        // and the current_thread reactor parks on a stale event, freezing its
        // timer wheel until a real event lands. The drain-then-clear cadence
        // below consumes each stale edge, while level-triggered epoll
        // re-reports genuinely pending work with a fresh guard. (The stdin
        // flush clears its edge inline instead: it only ever has the one
        // pipe to drain.)
        let mut listener_guard: Option<AsyncFdReadyGuard<'_, OwnedFd>> = None;
        let mut out_guard: Option<AsyncFdReadyGuard<'_, OwnedFd>> = None;
        let mut err_guard: Option<AsyncFdReadyGuard<'_, OwnedFd>> = None;

        loop {
            // --- progress: step once on already-ready work (never blocks) --
            let revents = if listener_ready { libc::POLLIN } else { 0 };
            let step_out = sandbox.step(revents)?;
            // Consume a stale edge when the fire produced no work (the
            // engine's non-blocking probe hit EAGAIN/ENOENT — the queue is
            // confirmed empty); a genuinely pending notification re-reports
            // level-triggered and re-fires with a fresh guard.
            if matches!(step_out, Step::Idle) {
                if let Some(mut g) = listener_guard.take() {
                    g.clear_ready();
                }
                if let Some(mut g) = out_guard.take() {
                    g.clear_ready();
                }
                if let Some(mut g) = err_guard.take() {
                    g.clear_ready();
                }
            }
            match step_out {
                Step::Blocked { syscall, request } => {
                    // Freeze the whole tree so the answerer (the policy
                    // engine, the user, or a future Lua coroutine) inspects a
                    // consistent snapshot — see `seccomp::Sandbox::freeze`.
                    // A Deny answer kills the tree inside resolve_ask; an
                    // Allow answer is thawed with SIGCONT below.
                    sandbox.freeze();
                    ask_tx
                        .send(Ask {
                            sandbox_id,
                            syscall,
                            request,
                        })
                        .map_err(|_| anyhow!("ask channel closed"))?;
                    // The target is frozen; drain whatever output was already
                    // buffered before parking on the answer — keep streaming.
                    loop {
                        match sandbox.step(0)? {
                            Step::Event(seccomp::CoroutineEvent::Output { stream, data }) => {
                                on_output(stream, data)
                            }
                            Step::Event(_) => {}
                            Step::Idle => break,
                            Step::Blocked { .. } => {
                                unreachable!("cannot re-block while frozen")
                            }
                            Step::Finished(r) => return Ok(r),
                        }
                    }
                    // Park on a verdict. A kill while frozen must still
                    // terminate the run without waiting for the answer —
                    // Deny is a safe stand-in: the tree is already dying,
                    // so resolve_ask's response hits ENOENT and its kill_tree
                    // is idempotent. If the last KillHandle is dropped
                    // (`changed()` Err), fall back to waiting for the real
                    // answer: dropping a handle is not a kill and must not
                    // deny anything.
                    let verdict = loop {
                        let v: Option<Verdict> = tokio::select! {
                            v = answer_rx.recv() => match v {
                                Some(v) => Some(v),
                                None => {
                                    return Err(anyhow!("answer channel closed"));
                                }
                            },
                            res = kill_rx.changed(), if !killed && kill_alive => match res {
                                Ok(()) if *kill_rx.borrow_and_update() => {
                                    killed = true;
                                    sandbox.kill_tree();
                                    Some(Verdict::Deny(libc::EPERM))
                                }
                                Ok(()) => None, // signal already consumed
                                Err(_) => {
                                    kill_alive = false; // wait for the answer
                                    None
                                }
                            },
                        };
                        if let Some(v) = v {
                            break v;
                        }
                    };
                    sandbox.resolve_ask(verdict)?;
                    if matches!(verdict, Verdict::Allow) {
                        sandbox.resume();
                    }
                    // The notification that fired the select was consumed
                    // into the ask above: drop its (now stale) readiness edge.
                    if let Some(mut g) = listener_guard.take() {
                        g.clear_ready();
                    }
                    listener_ready = false;
                    continue;
                }
                Step::Event(seccomp::CoroutineEvent::Output { stream, data }) => {
                    on_output(stream, data)
                }
                Step::Event(_) => {}
                Step::Idle => {}
                Step::Finished(r) => return Ok(r),
            }
            listener_ready = false;

            // --- one-hand poll set from the engine (single source of truth)
            let slots = sandbox.poll_slots();
            if slots.is_empty() {
                // Nothing left to wait on: only the completion path remains.
                return match sandbox.step(0)? {
                    Step::Finished(r) => Ok(r),
                    other => bail!("tree gone but step returned {other:?}"),
                };
            }
            let mut want_listener = false;
            let mut want_stdin = false;
            let mut want_out = false;
            let mut want_err = false;
            for (slot, p) in &slots {
                match slot {
                    seccomp::FdSlot::Listener => {
                        // while an ask is pending the engine registers the
                        // listener with events == 0: don't await it
                        want_listener |= p.events & libc::POLLIN != 0;
                    }
                    seccomp::FdSlot::Stdout => want_out = true,
                    seccomp::FdSlot::Stderr => want_err = true,
                    seccomp::FdSlot::Stdin => want_stdin = true,
                }
            }

            // --- park in the shared reactor until something is ready -------
            // Every arm yields that fd's readiness guard (all but the fired
            // one are None), so the loop can consume the edge with
            // `clear_ready()` once the engine confirms the fire carried no
            // work — see the drain-then-clear comment at the loop head.
            let (new_lg, new_og, new_eg) = tokio::select! {
                guard = listener.readable(), if want_listener => {
                    listener_ready = true;
                    (Some(guard?), None, None)
                }
                guard = out.readable(), if want_out => {
                    (None, Some(guard?), None)
                }
                guard = err.readable(), if want_err => {
                    (None, None, Some(guard?))
                }
                guard = stdin_writable(stdin.as_ref()), if want_stdin => {
                    // Consume the POLLOUT edge immediately: a flush that
                    // still EAGAINs must park on a *fresh* edge rather than
                    // re-fire on the latched one (that would spin the flush
                    // and freeze the reactor's timer wheel).
                    let g = guard.map_err(|e| anyhow!("stdin writable: {e}"))?;
                    if let Some(mut g) = g {
                        g.clear_ready();
                    }
                    (None, None, None)
                }
                msg = input_rx.recv(), if !input_eof => {
                    match msg {
                        Some(chunk) => { sandbox.queue_stdin(&chunk)?; }
                        None => { input_eof = true; /* EOF: drain queue, then close */ }
                    }
                    (None, None, None)
                },
                res = kill_rx.changed(), if !killed && kill_alive => {
                    match res {
                        Ok(()) if *kill_rx.borrow_and_update() => {
                            killed = true;
                            sandbox.kill_tree();
                        }
                        Ok(()) => {} // signal already consumed
                        Err(_) => kill_alive = false, // last handle dropped
                    }
                    (None, None, None)
                }
            };
            listener_guard = new_lg;
            out_guard = new_og;
            err_guard = new_eg;

            // Input exhausted: once the engine's queue has drained (no Stdin
            // slot registered), close the write end so the tracee's read(0)
            // sees EOF. Closing early would drop queued bytes.
            if input_eof && !want_stdin && !sandbox.stdin_closed() {
                stdin.take();
                sandbox.close_stdin();
            }
        }
    }
}

/// Await `POLLOUT` on the stdin pipe (a full pipe parked on `EAGAIN`),
/// yielding the readiness guard so [`AsyncSandbox::drive_live`] can consume
/// the edge once the engine confirms the flush is parked on EAGAIN.
async fn stdin_writable(
    stdin: Option<&AsyncFd<OwnedFd>>,
) -> std::io::Result<Option<AsyncFdReadyGuard<'_, OwnedFd>>> {
    match stdin {
        Some(fd) => fd.writable().await.map(Some),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// TUI stdin seam (Stage 3 prep: the agent's own stdin, polled by this loop)
// ---------------------------------------------------------------------------

/// An [`AsyncFd`] over the agent process's own stdin (default fd 0), so the
/// TUI shares the one reactor instead of blocking it with `read_line`.
/// `dup()`'d, so the real fd is never taken over; `O_NONBLOCK` guarantees a
/// read past a complete line/EOF returns `EAGAIN` instead of parking the
/// only thread.
pub struct TuiStdin {
    fd: AsyncFd<OwnedFd>,
}

impl TuiStdin {
    pub fn new() -> Result<Self> {
        Self::from_fd(0)
    }

    /// Wrap a dup of `fd` (a pipe read end in tests).
    pub fn from_fd(fd: RawFd) -> Result<Self> {
        let dup = unsafe { libc::dup(fd) };
        if dup == -1 {
            bail!("dup(stdin): {}", std::io::Error::last_os_error());
        }
        let fl = unsafe { libc::fcntl(dup, libc::F_GETFL) };
        if fl != -1 {
            unsafe { libc::fcntl(dup, libc::F_SETFL, fl | libc::O_NONBLOCK) };
        }
        let owned = unsafe { OwnedFd::from_raw_fd(dup) };
        Ok(Self {
            fd: AsyncFd::new(owned).context("AsyncFd(stdin)")?,
        })
    }

    /// Read one line (through the first `\n`). Returns `Ok(false)` on EOF
    /// with no buffered bytes. Parks in the reactor when no complete line is
    /// buffered (canonical TTY mode delivers a full line per readiness);
    /// never blocks the runtime.
    pub async fn read_line(&self, out: &mut Vec<u8>) -> Result<bool> {
        loop {
            let mut guard = self.fd.readable().await?;
            loop {
                let mut tmp = [0u8; 256];
                let n = unsafe {
                    libc::read(
                        guard.get_ref().as_raw_fd(),
                        tmp.as_mut_ptr().cast(),
                        tmp.len(),
                    )
                };
                if n > 0 {
                    let chunk = &tmp[..n as usize];
                    out.extend_from_slice(chunk);
                    if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
                        // keep through the newline, drop any bytes after it
                        out.truncate(out.len() - (chunk.len() - pos - 1));
                        return Ok(true);
                    }
                    continue; // more of the line is buffered: keep reading
                }
                if n == 0 {
                    // EOF: deliver a buffered partial line, then EOF below
                    return Ok(!out.is_empty());
                }
                let e = std::io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EAGAIN) => {
                        // No complete line buffered: consume the readiness
                        // edge so the next park waits for a *fresh* edge —
                        // a dropped guard leaves the fd latched, which would
                        // spin here and freeze the reactor's timer wheel.
                        guard.clear_ready();
                        break;
                    }
                    _ => bail!("read(tui stdin): {e}"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::{Stream, Verdict};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn async_drive_captures_like_sync() {
        let (driver, _ch) = AsyncSandbox::spawn(
            "sh",
            &["-c", "echo async-hi; echo err 1>&2; sleep 0.05; echo more"],
            |_| Verdict::Allow,
            &[1],
        )
        .unwrap();
        let r = driver.drive().await.unwrap();
        assert_eq!(r.stdout, b"async-hi\nmore\n");
        assert_eq!(r.stderr, b"err\n");
        assert_eq!(r.exit.code, Some(0));
        assert!(r.syscalls > 0);
    }

    #[tokio::test]
    async fn async_ask_awaits_answer_without_blocking_reactor() {
        // The first write(1) asks. The driver must hand the Ask out and park
        // in the reactor; a concurrently spawned answerer (sitting on the
        // same current-thread runtime) must be able to run — if drive()
        // blocked the reactor, it never would, and the timeout would fire.
        let asked = std::cell::Cell::new(false);
        let (driver, ch) = AsyncSandbox::spawn(
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
        .unwrap();
        let Channels(ask_rx, answer_tx, _input_tx) = ch;
        let server_answer = tokio::spawn(async move {
            let mut ask_rx = ask_rx;
            let ask = ask_rx.recv().await.expect("ask must arrive");
            tokio::time::sleep(Duration::from_millis(20)).await;
            answer_tx
                .send(Verdict::Allow)
                .expect("answer channel closed");
            ask
        });
        let r = tokio::time::timeout(Duration::from_secs(10), driver.drive())
            .await
            .expect("driver stalled: it blocked the reactor")
            .unwrap();
        let ask = server_answer.await.unwrap();
        assert_eq!(ask.request, 0);
        assert_eq!(ask.syscall.nr, 1);
        assert_eq!(ask.sandbox_id, 0);
        assert_eq!(r.stdout, b"dispatched\n");
        assert_eq!(r.exit.code, Some(0));
    }

    #[tokio::test]
    async fn two_async_sandboxes_interleave_on_one_reactor() {
        // Two independent sandboxes, one shared reactor; wall time much less
        // than 2 × 50 ms proves they genuinely overlap.
        let (a, _) =
            AsyncSandbox::spawn("sh", &["-c", "sleep 0.05; echo a"], |_| Verdict::Allow, &[])
                .unwrap();
        let (b, _) =
            AsyncSandbox::spawn("sh", &["-c", "sleep 0.05; echo b"], |_| Verdict::Allow, &[])
                .unwrap();
        let start = Instant::now();
        let (ra, rb) = tokio::join!(a.drive(), b.drive());
        let elapsed = start.elapsed();
        assert_eq!(ra.unwrap().stdout, b"a\n");
        assert_eq!(rb.unwrap().stdout, b"b\n");
        assert!(
            elapsed < Duration::from_millis(120),
            "sandboxes did not overlap: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn async_stdin_feeds_the_tracee() {
        let (driver, ch) = AsyncSandbox::spawn(
            "sh",
            &["-c", "read x; echo got:$x"],
            |_| Verdict::Allow,
            &[],
        )
        .unwrap();
        let Channels(_ask_rx, _answer_tx, input_tx) = ch;
        input_tx.send(b"hello\n".to_vec()).unwrap();
        drop(input_tx); // EOF: the driver closes the tracee's stdin pipe
        let r = driver.drive().await.unwrap();
        assert_eq!(r.stdout, b"got:hello\n");
        assert_eq!(r.exit.code, Some(0));
    }

    #[tokio::test]
    async fn stdin_backpressure_keeps_the_reactor_responsive() {
        // Feed 1 MiB while the child sleeps: the pipe (~64 KiB) fills, and
        // the driver must park on POLLOUT (EAGAIN) instead of blocking the
        // reactor. A ticking task proves the reactor stayed free.
        let n = 1 << 20;
        let (driver, ch) = AsyncSandbox::spawn(
            "sh",
            &["-c", "sleep 0.4; head -c 1048576"],
            |_| Verdict::Allow,
            &[],
        )
        .unwrap();
        let Channels(_ask_rx, _answer_tx, input_tx) = ch;
        for chunk in vec![b'q'; n].chunks(64 * 1024) {
            input_tx.send(chunk.to_vec()).unwrap();
        }
        drop(input_tx);

        let ticks = Arc::new(AtomicUsize::new(0));
        let t = ticks.clone();
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                t.fetch_add(1, Ordering::SeqCst);
            }
        });

        let r = driver.drive().await.unwrap();
        ticker.abort();
        assert_eq!(r.stdout.len(), n, "queued input must not be dropped");
        assert!(r.stdout.iter().all(|&b| b == b'q'));
        assert_eq!(r.exit.code, Some(0));
        assert!(
            ticks.load(Ordering::SeqCst) > 0,
            "the reactor was blocked during stdin backpressure"
        );
    }

    #[tokio::test]
    async fn tui_stdin_is_polled_not_blocking() {
        // A pipe stands in for the TTY: a writer emits a line late, so the
        // TUI reader must park in the reactor (proved by the ticker) rather
        // than blocking it with a synchronous read.
        let mut pipes = [0i32; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipes.as_mut_ptr(), libc::O_NONBLOCK) },
            0
        );
        let (r, w) = (pipes[0], pipes[1]);

        let ticks = Arc::new(AtomicUsize::new(0));
        let t = ticks.clone();
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                t.fetch_add(1, Ordering::SeqCst);
            }
        });
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let data = b"hi\n";
            let n = unsafe { libc::write(w, data.as_ptr().cast(), data.len()) };
            assert_eq!(n, data.len() as isize);
            unsafe { libc::close(w) };
        });

        let tui = TuiStdin::from_fd(r).unwrap();
        let mut line = Vec::new();
        assert!(tui.read_line(&mut line).await.unwrap(), "first line");
        assert_eq!(line, b"hi\n");
        assert!(
            !tui.read_line(&mut Vec::new()).await.unwrap(),
            "EOF after the line"
        );
        writer.await.unwrap();
        ticker.abort();
        unsafe { libc::close(r) };
        assert!(
            ticks.load(Ordering::SeqCst) > 0,
            "the reactor was blocked during TUI stdin polling"
        );
    }

    #[tokio::test]
    async fn drive_live_forwards_output_chunks_before_completion() {
        // A slow command: chunks must be forwarded as they arrive (≥ 2 stdout
        // chunks — one per echo, separated by a 50 ms sleep), not coalesced
        // into the final result.
        let (driver, ch) = AsyncSandbox::spawn(
            "sh",
            &["-c", "echo one; sleep 0.05; echo two; echo err 1>&2"],
            |_| Verdict::Allow,
            &[],
        )
        .unwrap();
        let Channels(_ask_rx, _answer_tx, _input_tx) = ch;
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<(Stream, Vec<u8>)>();
        let r = driver
            .drive_live(move |stream, data| {
                let _ = out_tx.send((stream, data));
            })
            .await
            .unwrap();
        let mut chunks = Vec::new();
        while let Ok((s, d)) = out_rx.try_recv() {
            chunks.push((s, d));
        }
        // The final result still carries the full captured output…
        assert_eq!(r.stdout, b"one\ntwo\n");
        assert_eq!(r.stderr, b"err\n");
        assert_eq!(r.exit.code, Some(0));
        // …and the forwarding was genuinely per-chunk and interleaved live.
        let stdout_chunks: usize = chunks.iter().filter(|(s, _)| *s == Stream::Stdout).count();
        let stderr_chunks: usize = chunks.iter().filter(|(s, _)| *s == Stream::Stderr).count();
        assert!(
            stdout_chunks >= 2,
            "stdout must arrive in ≥ 2 chunks: {chunks:?}"
        );
        assert_eq!(stderr_chunks, 1, "one stderr chunk: {chunks:?}");
        let mut joined = Vec::new();
        for (_s, d) in chunks.iter().filter(|(s, _)| *s == Stream::Stdout) {
            joined.extend_from_slice(d);
        }
        assert_eq!(joined, b"one\ntwo\n");
    }

    #[tokio::test]
    async fn kill_handle_interrupts_a_running_tree_promptly() {
        // Interrupt a `sh -c "sleep 5; echo done"` almost immediately: the
        // whole tree must die well under wall time, the root must report
        // SIGKILL, the never-reached "done" must not appear, and no orphan
        // may be left behind.
        let (driver, _ch) =
            AsyncSandbox::spawn("sh", &["-c", "sleep 5; echo done"], |_| Verdict::Allow, &[])
                .unwrap();
        let root = driver.pid();
        let kill_handle = driver.kill_handle();
        let killer2 = kill_handle.clone(); // handles are cloneable; both may fire
        let start = Instant::now();
        let handle = tokio::spawn(driver.drive());
        let timer_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            kill_handle.kill();
            killer2.kill(); // idempotent: the second must be a no-op
        });
        let r = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("kill did not terminate the tree in time")
            .unwrap()
            .unwrap();
        timer_task.await.unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "tree outlived the interrupt"
        );
        assert_eq!(r.exit.signal, Some(libc::SIGKILL));
        assert!(
            !r.stdout.windows(4).any(|w| w == b"done"),
            "run continued past the kill"
        );
        // No orphan: the root (reaped by finish_result) is gone.
        let probe = unsafe { libc::kill(root, 0) };
        assert_eq!(probe, -1, "root pid {root} still alive after the kill");
    }

    #[tokio::test]
    async fn kill_during_a_frozen_ask_terminates_promptly() {
        // The first write(1) is frozen into an ask. We never answer it —
        // instead we interrupt. The driver must terminate the run without
        // waiting for the verdict, and the root must still be sanitized.
        let (driver, ch) = AsyncSandbox::spawn(
            "sh",
            &["-c", "echo needs-answer; sleep 5"],
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
        let Channels(mut ask_rx, _answer_tx, _input_tx) = ch;
        let killer = driver.kill_handle();
        let handle = tokio::spawn(driver.drive());
        let ask = tokio::time::timeout(Duration::from_secs(5), ask_rx.recv())
            .await
            .expect("the ask must arrive")
            .expect("ask channel closed");
        assert_eq!(ask.syscall.nr, 1, "the frozen syscall must be write(1)");
        killer.kill(); // no answer is ever sent
        let r = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("kill during a frozen ask did not terminate the run")
            .unwrap()
            .unwrap();
        assert_eq!(r.exit.signal, Some(libc::SIGKILL));
    }
}
