//! `sandbox` — CLI facade over the seccomp supervisor substrate.
//!
//! Runs a command inside the sandbox, streams its stdout/stderr live, and
//! exits with its status. Only the syscalls the CLI is told to decide are
//! intercepted (mask = the union of `--deny-nr`/`--ask-nr` targets); the
//! engine's always-masked fork family is auto-allowed. With no flags the
//! mask is empty and the command runs freely through the kernel. The decision
//! point is exercisable without any policy engine:
//!
//! ```text
//! sandbox <cmd> [args...]              # allow everything (empty mask)
//! sandbox --deny-nr N <cmd> [args...]  # deny syscall N with EPERM
//! sandbox --ask-nr  N <cmd> [args...]  # freeze syscall N and ask on stdin
//! ```
//!
//! `--ask-nr` demonstrates the coroutine suspend/resume: the syscall is frozen,
//! the supervisor yields a `Step::Blocked`, and answering allows it to resume.

use agent::seccomp::{CoroutineEvent, Sandbox, Stream, Syscall, Verdict};
use anyhow::{Result, bail};
use std::io::Write;

fn usage() -> ! {
    eprintln!("usage: sandbox [--deny-nr N] [--ask-nr N] <program> [args...]");
    std::process::exit(2);
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut deny_nr: Option<i32> = None;
    let mut ask_nr: Option<i32> = None;
    let mut rest: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--deny-nr" | "--ask-nr" => {
                let Some(nr_str) = args.get(i + 1) else {
                    usage()
                };
                let nr: i32 = nr_str.parse().unwrap_or_else(|_| usage());
                if args[i] == "--deny-nr" {
                    deny_nr = Some(nr);
                } else {
                    ask_nr = Some(nr);
                }
                i += 2;
            }
            "--help" | "-h" => usage(),
            "--" => {
                rest.extend(args[i + 1..].iter().cloned());
                break;
            }
            s if s.starts_with('-') => bail!("unknown option: {s}"),
            _ => {
                rest.extend(args[i..].iter().cloned());
                break;
            }
        }
    }
    if rest.is_empty() {
        usage();
    }

    let program = rest[0].clone();
    let argv: Vec<&str> = rest[1..].iter().map(String::as_str).collect();

    let decider = move |sc: &Syscall| -> Verdict {
        if deny_nr == Some(sc.nr) {
            Verdict::Deny(libc::EPERM)
        } else if ask_nr == Some(sc.nr) {
            Verdict::Ask
        } else {
            Verdict::Allow
        }
    };
    // The interception mask: only the syscalls the CLI decides are trapped.
    let mut mask: Vec<i32> = Vec::new();
    if let Some(n) = deny_nr {
        mask.push(n);
    }
    if let Some(n) = ask_nr {
        mask.push(n);
    }

    let mut sandbox = Sandbox::spawn(&program, &argv, decider, &mask)?;

    let result = sandbox.pump_with_stdin(
        0, // the CLI's own stdin, forwarded into the tracee's private stdin pipe
        |sc| {
            // Ask reached: the tracee is frozen. Prompt on our own stderr
            // (the tracee's stderr is captured, not shown) and read stdin.
            eprint!("ask: pid {} {}(", sc.pid, sc.name());
            for (k, a) in sc.args.iter().enumerate() {
                if k > 0 {
                    eprint!(", ");
                }
                eprint!("0x{a:x}");
            }
            eprint!(") -> allow/deny [y/N]: ");
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            let read = std::io::stdin().read_line(&mut line).is_ok();
            let t = line.trim();
            if read
                && (t.eq_ignore_ascii_case("y")
                    || t.eq_ignore_ascii_case("yes")
                    || t.eq_ignore_ascii_case("allow"))
            {
                Verdict::Allow
            } else {
                Verdict::Deny(libc::EPERM)
            }
        },
        |ev| match ev {
            CoroutineEvent::Output {
                stream: Stream::Stdout,
                data,
            } => {
                let _ = std::io::stdout().write_all(&data);
            }
            CoroutineEvent::Output {
                stream: Stream::Stderr,
                data,
            } => {
                let _ = std::io::stderr().write_all(&data);
            }
            _ => {}
        },
    )?;

    let _ = std::io::stdout().flush();
    match result.exit {
        agent::seccomp::ExitInfo {
            code: Some(code),
            signal: None,
        } => std::process::exit(code),
        agent::seccomp::ExitInfo {
            code: None,
            signal: Some(sig),
        } => std::process::exit(128 + sig),
        _ => std::process::exit(1),
    }
}
