//! The syscall tables themselves: that the pathname/dirfd slot tables match
//! the kernel's signatures, that the default mask is exactly thirteen entries,
//! and that a rename target resolves against its own dirfd.
use super::*;

    /// Every pathname a syscall names, checked against the kernel's own
    /// signatures — the tables that decide which `args` slots get dereferenced
    /// as C strings, and which of them resolve against a dirfd.
    ///
    /// There was no test here, which is how `renameat` kept `&[1, 2]` for years:
    /// slot 2 is *newdirfd*, so the second path was read out of a small integer
    /// instead of a pointer and came back nil. Nothing had ever asked a question
    /// about a rename's target, so nothing noticed. The signatures are spelled
    /// out here rather than derived, because a typo in a table is invisible until
    /// something reads the slot it mistyped.
    #[test]
    fn the_pathname_and_dirfd_tables_match_the_kernel_signatures() {
        // (syscall, its 0-based string slots) straight from the man pages.
        let signatures: &[(&str, &[usize])] = &[
            ("open", &[0]),
            ("openat", &[1]),
            ("openat2", &[1]),
            ("unlinkat", &[1]),
            ("mkdirat", &[1]),
            ("renameat", &[1, 3]),
            ("renameat2", &[1, 3]),
            ("linkat", &[1, 3]),
            ("symlinkat", &[0, 2]),
            ("execveat", &[1]),
            ("newfstatat", &[1]),
            ("readlinkat", &[1]),
            ("fchmodat", &[1]),
            ("fchownat", &[1]),
            ("utimensat", &[1]),
            ("name_to_handle_at", &[1]),
            ("chmod", &[0]),
            ("fchmodat", &[1]),
            ("setxattr", &[0, 1]),
            ("lsetxattr", &[0, 1]),
            ("removexattr", &[0, 1]),
            ("lremovexattr", &[0, 1]),
        ];
        for (name, want) in signatures {
            assert_eq!(
                cstring_positions(name),
                Some(*want),
                "{name}: which args hold a C string"
            );
        }

        // And the dirfd each of those paths resolves against. A two-path call
        // has two dirfds, and resolving the target against the source's
        // directory is a wrong answer rather than a missing one.
        let cases: &[(&str, usize, Option<usize>)] = &[
            ("openat", 1, Some(0)),
            ("chmod", 0, None),
            ("fchmodat", 1, Some(0)),
            ("unlinkat", 1, Some(0)),
            ("renameat", 1, Some(0)),
            ("renameat", 3, Some(2)),
            ("renameat2", 1, Some(0)),
            ("renameat2", 3, Some(2)),
            ("linkat", 1, Some(0)),
            ("linkat", 3, Some(2)),
            // symlinkat's target is cwd-relative; only its linkpath is behind
            // the fd.
            ("symlinkat", 0, None),
            ("symlinkat", 2, Some(1)),
            ("open", 0, None),
            ("unlink", 0, None),
        ];
        for (name, path, want) in cases {
            assert_eq!(
                dirfd_slot_for(name, *path),
                *want,
                "{name} path slot {path}: which dirfd it resolves against"
            );
        }
    }

    /// The dirfd decision is per *path*, so a rename's target resolves against
    /// the cwd only when the caller said `AT_FDCWD` in the slot that governs
    /// it — the target's own slot, not the source's.
    #[test]
    fn a_rename_target_resolves_against_its_own_dirfd() {
        let cwd = libc::AT_FDCWD as u64;
        let other_fd = 7u64;
        // renameat(olddirfd, oldpath, newdirfd, newpath): the target is slot 3
        // and its dirfd is slot 2.
        // olddirfd, oldpath, newdirfd, newpath — slots 0 and 2 govern slots 1
        // and 3 respectively.
        let both_cwd = [cwd, 0, cwd, 0, 0, 0];
        let new_only = [cwd, 0, other_fd, 0, 0, 0];
        let both_fds = [other_fd, 0, other_fd, 0, 0, 0];

        // Both slots say the cwd: both paths resolve.
        assert!(cwd_resolution_ok("renameat", 1, both_cwd), "source, both AT_FDCWD");
        assert!(cwd_resolution_ok("renameat", 3, both_cwd), "target, both AT_FDCWD");

        // Only the target names a real dirfd: the source still resolves and the
        // target must not. The old table had one slot for the whole syscall —
        // slot 0 — so it read "AT_FDCWD" here and resolved the target against
        // the cwd, which is a wrong answer rather than a missing one.
        assert!(cwd_resolution_ok("renameat", 1, new_only), "source, its own slot");
        assert!(
            !cwd_resolution_ok("renameat", 3, new_only),
            "target, behind a caller-held dirfd"
        );

        // Neither does: neither resolves.
        assert!(!cwd_resolution_ok("renameat", 1, both_fds), "source, behind an fd");
        assert!(!cwd_resolution_ok("renameat", 3, both_fds), "target, behind an fd");
    }

    /// let a connect — or a `rm` — through, so the set is pinned exactly.
    #[test]
    fn the_default_policy_traps_exactly_thirteen_syscalls() {
        assert_default_shell(&shipped_vm());
    }

    /// A remembered endpoint goes quiet, and only for the endpoint that was
    /// remembered: a plain yes asks again, an "always" does not, and a different
    /// port still does. This is the trustworthy-server table doing its job.
    #[test]
    fn the_permissive_mode_remembers_a_server_on_always_only() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let cmd = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");

        // A plain yes is for that one call: the endpoint is asked again.
        let (v, asked) = run_policy_bash(&lua, &cmd, AskAnswer::Allow);
        assert!(asked_about(&asked, &port.to_string()), "asked: {asked:?} {v}");
        let (v, asked) = run_policy_bash(&lua, &cmd, AskAnswer::Allow);
        assert!(
            asked_about(&asked, &port.to_string()),
            "a plain yes is not remembered: {asked:?} {v}"
        );

        // "always" records host:port, and the next call does not ask about it at
        // all — even though the answer it would have got is a denial.
        let (v, asked) = run_policy_bash(&lua, &cmd, AskAnswer::AllowAndTrust);
        assert!(asked_about(&asked, &port.to_string()), "asked once: {asked:?} {v}");
        let (v, asked) = run_policy_bash(&lua, &cmd, AskAnswer::Deny(None));
        assert!(
            !asked_about(&asked, &port.to_string()),
            "the remembered endpoint is silent: {asked:?} {v}"
        );

        // A different port on the same host is a different question.
        let other = {
            let p = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = p.local_addr().expect("addr").port();
            drop(p);
            port
        };
        let (v, asked) = run_policy_bash(
            &lua,
            &format!("exec 3<>/dev/tcp/127.0.0.1/{other}"),
            AskAnswer::Allow,
        );
        assert!(
            asked_about(&asked, &other.to_string()),
            "another port still asks: {asked:?} {v}"
        );

        // And forgetting it puts the question back. The key is the *name* the
        // question showed — `localhost`, since 127.0.0.1 reverse-resolves
        // without a network — which is the whole point of keying on what the user
        // read.
        let trusted: i64 = lua
            .load("return #agent.ask.trusted_servers()")
            .eval()
            .expect("listed");
        assert_eq!(trusted, 1, "exactly one server was remembered: {trusted}");
        let forgotten: bool = lua
            .load(format!("return agent.ask.forget_server('localhost', {port})"))
            .eval()
            .expect("forget");
        assert!(forgotten, "the endpoint was trusted");
        let (v, asked) = run_policy_bash(&lua, &cmd, AskAnswer::Allow);
        assert!(
            asked_about(&asked, &port.to_string()),
            "a forgotten endpoint asks again: {asked:?} {v}"
        );
    }

    /// `lua/init.lua` trusts the working directory at startup, so the mode's
    /// every-read gate is silent inside the project and asks about everything
    /// else. That is a *full config load* (the entry script plus any user
    /// config), which is why this is not just another `shipped_vm()` assertion.
    #[test]
    fn the_working_directory_is_trusted_at_startup() {
        let lua = new_vm_with_sink(None).expect("vm");
        let cwd = std::env::var("PWD").expect("PWD");

        // The grant is a *directory* entry, so it covers the whole subtree — a
        // file that does not exist yet is inside it too.
        let trusted: bool = lua
            .load(format!("return agent.ask.is_trusted({cwd:?})"))
            .eval()
            .expect("is_trusted");
        assert!(trusted, "the working directory is trusted: {cwd}");
        let inside: bool = lua
            .load(format!("return agent.ask.is_trusted({:?})", format!("{cwd}/lua/init.lua")))
            .eval()
            .expect("a file inside it");
        assert!(inside, "and so is a file in it");
        let outside: bool = lua
            .load("return agent.ask.is_trusted('/etc')")
            .eval()
            .expect("is_trusted");
        assert!(!outside, "but nothing outside it is — that is the point");

        // And the effect the grant exists for: inside the cwd nothing asks, and
        // the same read outside it does.
        // Read a file that is really there, so the grant is what made it quiet
        // rather than the file being absent.
        let (v, asked) =
            run_policy_bash(&lua, &format!("cat {cwd}/lua/init.lua"), AskAnswer::Allow);
        assert_eq!(v["ok"], true, "the read ran: {v}");
        assert!(
            !asked_about(&asked, "init.lua"),
            "a read inside the trusted cwd asks nothing: {asked:?}"
        );
        let outside_path = std::env::temp_dir().join("agent-cwd-trust-probe.txt");
        std::fs::write(&outside_path, "x\n").expect("seed outside the cwd");
        let (v, asked) = run_policy_bash(
            &lua,
            &format!("cat {}", outside_path.to_string_lossy()),
            AskAnswer::Allow,
        );
        assert_eq!(v["ok"], true, "the outside read ran: {v}");
        assert!(
            asked_about(&asked, &outside_path.to_string_lossy()),
            "and the same read outside the cwd is asked: {asked:?}"
        );
        let _ = std::fs::remove_file(&outside_path);
    }
