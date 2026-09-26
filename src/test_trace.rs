//! strace(1)-like syscall tracer built on the seccomp user-space notification
//! mechanism (SECCOMP_RET_USER_NOTIF + SECCOMP_FILTER_FLAG_NEW_LISTENER).
//!
//! This is the foundation of the planned supervisor: the tracing supervisor
//! (us) and the traced program (the target) are separate processes, and every
//! target syscall is *intercepted* (not just observed), giving the supervisor
//! a decision point per syscall. For now the supervisor is a pure pass-through:
//! it prints each syscall like strace and answers every notification with
//! SECCOMP_USER_NOTIF_FLAG_CONTINUE so the syscall runs normally.
//!
//! Unlike strace (which is ptrace-based), we only ever see the syscall *entry*:
//! the notification carries the syscall number and its six arguments. There are
//! no exit notifications, so return values are never captured -- by design.
//!
//! Protocol between supervisor and target:
//!   1. parent creates an AF_UNIX socketpair, then forks
//!   2. child:  prctl(NO_NEW_PRIVS) -> seccomp(NEW_LISTENER) -> listener fd
//!   3. child:  passes the listener fd to the parent via SCM_RIGHTS, then execv
//!   4. parent: loops SECCOMP_IOCTL_NOTIF_RECV -> print -> NOTIF_SEND(CONTINUE)
//!
//! Deadlock note: a filter that traps *everything* would also trap the child's
//! fd-passing sendmsg (which can't deliver the fd since the syscall never runs).
//! The BPF therefore ALLOWs exactly one syscall: sendmsg() on the handshake
//! socket, identified by baking that fd number into the program. The socket is
//! SOCK_CLOEXEC, so the child needs no close() between filter install and exec.
//! The program path is resolved to an absolute path *before* fork, so with the
//! handshake allowed, the only syscalls after filter-install are the allowed
//! sendmsg and the (trapped, then continued) execv.

use anyhow::{Context, Result, bail};
use std::ffi::CString;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// seccomp constants (kernel ABI; kept local so we don't depend on libc having
// the newest definitions)
// ---------------------------------------------------------------------------

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
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

// BPF instruction field encodings (linux/filter.h)
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// The x32 ABI sets bit 30 of the syscall number; reject it.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const SYS_SENDMSG: u32 = 46;

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
// x86_64 syscall table (generated from /usr/include/asm/unistd_64.h)
// ---------------------------------------------------------------------------

const SYSCALLS: &[(i32, &str)] = &[
    (0, "read"),
    (1, "write"),
    (2, "open"),
    (3, "close"),
    (4, "stat"),
    (5, "fstat"),
    (6, "lstat"),
    (7, "poll"),
    (8, "lseek"),
    (9, "mmap"),
    (10, "mprotect"),
    (11, "munmap"),
    (12, "brk"),
    (13, "rt_sigaction"),
    (14, "rt_sigprocmask"),
    (15, "rt_sigreturn"),
    (16, "ioctl"),
    (17, "pread64"),
    (18, "pwrite64"),
    (19, "readv"),
    (20, "writev"),
    (21, "access"),
    (22, "pipe"),
    (23, "select"),
    (24, "sched_yield"),
    (25, "mremap"),
    (26, "msync"),
    (27, "mincore"),
    (28, "madvise"),
    (29, "shmget"),
    (30, "shmat"),
    (31, "shmctl"),
    (32, "dup"),
    (33, "dup2"),
    (34, "pause"),
    (35, "nanosleep"),
    (36, "getitimer"),
    (37, "alarm"),
    (38, "setitimer"),
    (39, "getpid"),
    (40, "sendfile"),
    (41, "socket"),
    (42, "connect"),
    (43, "accept"),
    (44, "sendto"),
    (45, "recvfrom"),
    (46, "sendmsg"),
    (47, "recvmsg"),
    (48, "shutdown"),
    (49, "bind"),
    (50, "listen"),
    (51, "getsockname"),
    (52, "getpeername"),
    (53, "socketpair"),
    (54, "setsockopt"),
    (55, "getsockopt"),
    (56, "clone"),
    (57, "fork"),
    (58, "vfork"),
    (59, "execve"),
    (60, "exit"),
    (61, "wait4"),
    (62, "kill"),
    (63, "uname"),
    (64, "semget"),
    (65, "semop"),
    (66, "semctl"),
    (67, "shmdt"),
    (68, "msgget"),
    (69, "msgsnd"),
    (70, "msgrcv"),
    (71, "msgctl"),
    (72, "fcntl"),
    (73, "flock"),
    (74, "fsync"),
    (75, "fdatasync"),
    (76, "truncate"),
    (77, "ftruncate"),
    (78, "getdents"),
    (79, "getcwd"),
    (80, "chdir"),
    (81, "fchdir"),
    (82, "rename"),
    (83, "mkdir"),
    (84, "rmdir"),
    (85, "creat"),
    (86, "link"),
    (87, "unlink"),
    (88, "symlink"),
    (89, "readlink"),
    (90, "chmod"),
    (91, "fchmod"),
    (92, "chown"),
    (93, "fchown"),
    (94, "lchown"),
    (95, "umask"),
    (96, "gettimeofday"),
    (97, "getrlimit"),
    (98, "getrusage"),
    (99, "sysinfo"),
    (100, "times"),
    (101, "ptrace"),
    (102, "getuid"),
    (103, "syslog"),
    (104, "getgid"),
    (105, "setuid"),
    (106, "setgid"),
    (107, "geteuid"),
    (108, "getegid"),
    (109, "setpgid"),
    (110, "getppid"),
    (111, "getpgrp"),
    (112, "setsid"),
    (113, "setreuid"),
    (114, "setregid"),
    (115, "getgroups"),
    (116, "setgroups"),
    (117, "setresuid"),
    (118, "getresuid"),
    (119, "setresgid"),
    (120, "getresgid"),
    (121, "getpgid"),
    (122, "setfsuid"),
    (123, "setfsgid"),
    (124, "getsid"),
    (125, "capget"),
    (126, "capset"),
    (127, "rt_sigpending"),
    (128, "rt_sigtimedwait"),
    (129, "rt_sigqueueinfo"),
    (130, "rt_sigsuspend"),
    (131, "sigaltstack"),
    (132, "utime"),
    (133, "mknod"),
    (134, "uselib"),
    (135, "personality"),
    (136, "ustat"),
    (137, "statfs"),
    (138, "fstatfs"),
    (139, "sysfs"),
    (140, "getpriority"),
    (141, "setpriority"),
    (142, "sched_setparam"),
    (143, "sched_getparam"),
    (144, "sched_setscheduler"),
    (145, "sched_getscheduler"),
    (146, "sched_get_priority_max"),
    (147, "sched_get_priority_min"),
    (148, "sched_rr_get_interval"),
    (149, "mlock"),
    (150, "munlock"),
    (151, "mlockall"),
    (152, "munlockall"),
    (153, "vhangup"),
    (154, "modify_ldt"),
    (155, "pivot_root"),
    (156, "_sysctl"),
    (157, "prctl"),
    (158, "arch_prctl"),
    (159, "adjtimex"),
    (160, "setrlimit"),
    (161, "chroot"),
    (162, "sync"),
    (163, "acct"),
    (164, "settimeofday"),
    (165, "mount"),
    (166, "umount2"),
    (167, "swapon"),
    (168, "swapoff"),
    (169, "reboot"),
    (170, "sethostname"),
    (171, "setdomainname"),
    (172, "iopl"),
    (173, "ioperm"),
    (174, "create_module"),
    (175, "init_module"),
    (176, "delete_module"),
    (177, "get_kernel_syms"),
    (178, "query_module"),
    (179, "quotactl"),
    (180, "nfsservctl"),
    (181, "getpmsg"),
    (182, "putpmsg"),
    (183, "afs_syscall"),
    (184, "tuxcall"),
    (185, "security"),
    (186, "gettid"),
    (187, "readahead"),
    (188, "setxattr"),
    (189, "lsetxattr"),
    (190, "fsetxattr"),
    (191, "getxattr"),
    (192, "lgetxattr"),
    (193, "fgetxattr"),
    (194, "listxattr"),
    (195, "llistxattr"),
    (196, "flistxattr"),
    (197, "removexattr"),
    (198, "lremovexattr"),
    (199, "fremovexattr"),
    (200, "tkill"),
    (201, "time"),
    (202, "futex"),
    (203, "sched_setaffinity"),
    (204, "sched_getaffinity"),
    (205, "set_thread_area"),
    (206, "io_setup"),
    (207, "io_destroy"),
    (208, "io_getevents"),
    (209, "io_submit"),
    (210, "io_cancel"),
    (211, "get_thread_area"),
    (212, "lookup_dcookie"),
    (213, "epoll_create"),
    (214, "epoll_ctl_old"),
    (215, "epoll_wait_old"),
    (216, "remap_file_pages"),
    (217, "getdents64"),
    (218, "set_tid_address"),
    (219, "restart_syscall"),
    (220, "semtimedop"),
    (221, "fadvise64"),
    (222, "timer_create"),
    (223, "timer_settime"),
    (224, "timer_gettime"),
    (225, "timer_getoverrun"),
    (226, "timer_delete"),
    (227, "clock_settime"),
    (228, "clock_gettime"),
    (229, "clock_getres"),
    (230, "clock_nanosleep"),
    (231, "exit_group"),
    (232, "epoll_wait"),
    (233, "epoll_ctl"),
    (234, "tgkill"),
    (235, "utimes"),
    (236, "vserver"),
    (237, "mbind"),
    (238, "set_mempolicy"),
    (239, "get_mempolicy"),
    (240, "mq_open"),
    (241, "mq_unlink"),
    (242, "mq_timedsend"),
    (243, "mq_timedreceive"),
    (244, "mq_notify"),
    (245, "mq_getsetattr"),
    (246, "kexec_load"),
    (247, "waitid"),
    (248, "add_key"),
    (249, "request_key"),
    (250, "keyctl"),
    (251, "ioprio_set"),
    (252, "ioprio_get"),
    (253, "inotify_init"),
    (254, "inotify_add_watch"),
    (255, "inotify_rm_watch"),
    (256, "migrate_pages"),
    (257, "openat"),
    (258, "mkdirat"),
    (259, "mknodat"),
    (260, "fchownat"),
    (261, "futimesat"),
    (262, "newfstatat"),
    (263, "unlinkat"),
    (264, "renameat"),
    (265, "linkat"),
    (266, "symlinkat"),
    (267, "readlinkat"),
    (268, "fchmodat"),
    (269, "faccessat"),
    (270, "pselect6"),
    (271, "ppoll"),
    (272, "unshare"),
    (273, "set_robust_list"),
    (274, "get_robust_list"),
    (275, "splice"),
    (276, "tee"),
    (277, "sync_file_range"),
    (278, "vmsplice"),
    (279, "move_pages"),
    (280, "utimensat"),
    (281, "epoll_pwait"),
    (282, "signalfd"),
    (283, "timerfd_create"),
    (284, "eventfd"),
    (285, "fallocate"),
    (286, "timerfd_settime"),
    (287, "timerfd_gettime"),
    (288, "accept4"),
    (289, "signalfd4"),
    (290, "eventfd2"),
    (291, "epoll_create1"),
    (292, "dup3"),
    (293, "pipe2"),
    (294, "inotify_init1"),
    (295, "preadv"),
    (296, "pwritev"),
    (297, "rt_tgsigqueueinfo"),
    (298, "perf_event_open"),
    (299, "recvmmsg"),
    (300, "fanotify_init"),
    (301, "fanotify_mark"),
    (302, "prlimit64"),
    (303, "name_to_handle_at"),
    (304, "open_by_handle_at"),
    (305, "clock_adjtime"),
    (306, "syncfs"),
    (307, "sendmmsg"),
    (308, "setns"),
    (309, "getcpu"),
    (310, "process_vm_readv"),
    (311, "process_vm_writev"),
    (312, "kcmp"),
    (313, "finit_module"),
    (314, "sched_setattr"),
    (315, "sched_getattr"),
    (316, "renameat2"),
    (317, "seccomp"),
    (318, "getrandom"),
    (319, "memfd_create"),
    (320, "kexec_file_load"),
    (321, "bpf"),
    (322, "execveat"),
    (323, "userfaultfd"),
    (324, "membarrier"),
    (325, "mlock2"),
    (326, "copy_file_range"),
    (327, "preadv2"),
    (328, "pwritev2"),
    (329, "pkey_mprotect"),
    (330, "pkey_alloc"),
    (331, "pkey_free"),
    (332, "statx"),
    (333, "io_pgetevents"),
    (334, "rseq"),
    (335, "uretprobe"),
    (336, "uprobe"),
    (424, "pidfd_send_signal"),
    (425, "io_uring_setup"),
    (426, "io_uring_enter"),
    (427, "io_uring_register"),
    (428, "open_tree"),
    (429, "move_mount"),
    (430, "fsopen"),
    (431, "fsconfig"),
    (432, "fsmount"),
    (433, "fspick"),
    (434, "pidfd_open"),
    (435, "clone3"),
    (436, "close_range"),
    (437, "openat2"),
    (438, "pidfd_getfd"),
    (439, "faccessat2"),
    (440, "process_madvise"),
    (441, "epoll_pwait2"),
    (442, "mount_setattr"),
    (443, "quotactl_fd"),
    (444, "landlock_create_ruleset"),
    (445, "landlock_add_rule"),
    (446, "landlock_restrict_self"),
    (447, "memfd_secret"),
    (448, "process_mrelease"),
    (449, "futex_waitv"),
    (450, "set_mempolicy_home_node"),
    (451, "cachestat"),
    (452, "fchmodat2"),
    (453, "map_shadow_stack"),
    (454, "futex_wake"),
    (455, "futex_wait"),
    (456, "futex_requeue"),
    (457, "statmount"),
    (458, "listmount"),
    (459, "lsm_get_self_attr"),
    (460, "lsm_set_self_attr"),
    (461, "lsm_list_modules"),
    (462, "mseal"),
    (463, "setxattrat"),
    (464, "getxattrat"),
    (465, "listxattrat"),
    (466, "removexattrat"),
    (467, "open_tree_attr"),
    (468, "file_getattr"),
    (469, "file_setattr"),
    (470, "listns"),
    (471, "rseq_slice_yield"),
];

fn syscall_name(nr: i32) -> String {
    match SYSCALLS.binary_search_by_key(&nr, |&(n, _)| n) {
        Ok(i) => SYSCALLS[i].1.to_string(),
        Err(_) => format!("syscall_{nr}"),
    }
}

/// Which argument slots of a syscall are C string pointers (best-effort
/// strace-style pathname decoding; everything else prints as hex).
fn path_slots(nr: i32) -> &'static [usize] {
    match nr {
        2 => &[0],         // open
        4 | 6 => &[0],     // stat, lstat
        21 => &[0],        // access
        59 => &[0],        // execve
        76 => &[0],        // truncate
        80 => &[0],        // chdir
        82 => &[0, 1],     // rename
        83 => &[0],        // mkdir
        84 => &[0],        // rmdir
        85 => &[0],        // creat
        86 => &[0, 1],     // link
        87 => &[0],        // unlink
        88 => &[0, 1],     // symlink
        89 => &[0],        // readlink
        90 => &[0],        // chmod
        92 | 94 => &[0],   // chown, lchown
        132 => &[0],       // utime
        133 => &[0],       // mknod
        161 => &[0],       // chroot
        163 => &[0],       // acct
        167 | 168 => &[0], // swapon, swapoff
        257 => &[1],       // openat
        258 => &[1],       // mkdirat
        259 => &[1],       // mknodat
        260 => &[1],       // fchownat
        262 => &[1],       // newfstatat
        263 => &[1],       // unlinkat
        264 => &[1, 2],    // renameat
        265 => &[1],       // linkat
        266 => &[1],       // symlinkat
        267 => &[1],       // readlinkat
        268 => &[1],       // fchmodat
        269 => &[1],       // faccessat
        280 => &[1],       // utimensat
        316 => &[1, 2],    // renameat2
        322 => &[1],       // execveat
        437 => &[1],       // openat2
        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// Argument decoding (read tracee memory via process_vm_readv)
// ---------------------------------------------------------------------------

fn read_c_string(pid: i32, addr: u64, max: usize) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let mut buf = vec![0u8; max];
    let mut n = 0usize;
    while n < max {
        let local = libc::iovec {
            iov_base: buf[n..].as_mut_ptr().cast(),
            iov_len: max - n,
        };
        let remote = libc::iovec {
            iov_base: (addr + n as u64) as *mut libc::c_void,
            iov_len: max - n,
        };
        let chunk = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if chunk <= 0 {
            break;
        }
        n += chunk as usize;
        if buf[n - chunk as usize..n].contains(&0) {
            break;
        }
    }
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    if end == 0 {
        // Empty string ("\0" at buf[0]) vs unreadable pointer.
        return if n > 0 { Some(String::new()) } else { None };
    }
    Some(escape_bytes(&buf[..end]))
}

fn escape_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\n' => s.push_str("\\n"),
            b'\t' => s.push_str("\\t"),
            b'\r' => s.push_str("\\r"),
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s
}

fn print_syscall(notif: &SeccompNotif) {
    let name = syscall_name(notif.data.nr);
    let slots = path_slots(notif.data.nr);
    let mut parts: Vec<String> = Vec::with_capacity(6);
    for i in 0..6 {
        let arg = notif.data.args[i];
        if slots.contains(&i) {
            if let Some(s) = read_c_string(notif.pid as i32, arg, 256) {
                parts.push(format!("\"{s}\""));
                continue;
            }
        }
        parts.push(format!("0x{arg:x}"));
    }
    eprintln!("{:>6} {}({})", notif.pid, name, parts.join(", "));
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

/// Trap every syscall with SECCOMP_RET_USER_NOTIF, except the single
/// sendmsg() on the handshake socket fd (which must run so it can carry the
/// listener fd to the supervisor).
fn build_filter(handshake_fd: i32) -> Vec<libc::sock_filter> {
    vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, 4), // 0: load arch
        // 1: arch == x86_64 ? jump to 3 : fall to 2
        jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_X86_64),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS), // 2: wrong arch
        stmt(BPF_LD | BPF_W | BPF_ABS, 0),               // 3: load syscall nr
        // 4: nr >= x32 bit ? fall to 5 (kill) : jump to 6
        jump(BPF_JMP | BPF_JGE | BPF_K, 0, 1, X32_SYSCALL_BIT),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS), // 5: x32 ABI
        // 6: nr == sendmsg ? fall to 7 : jump to 10
        jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, SYS_SENDMSG),
        stmt(BPF_LD | BPF_W | BPF_ABS, 16), // 7: load args[0] (socket fd)
        // 8: fd == handshake socket ? fall to 9 (allow) : jump to 10
        jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, handshake_fd as u32),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), // 9: handshake sendmsg
        stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF), // 10: everything else
    ]
}

// ---------------------------------------------------------------------------
// Filter install (child side)
// ---------------------------------------------------------------------------

fn install_filter(handshake_fd: i32) -> Result<i32> {
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
            bail!("prctl(NO_NEW_PRIVS): {}", std::io::Error::last_os_error());
        }
        let filter = build_filter(handshake_fd);
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        let fd = libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER as libc::c_long,
            SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_long,
            &prog as *const libc::sock_fprog as libc::c_long,
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
// Supervisor loop
// ---------------------------------------------------------------------------

fn signal_name(sig: i32) -> String {
    let name = match sig {
        libc::SIGHUP => "SIGHUP",
        libc::SIGINT => "SIGINT",
        libc::SIGQUIT => "SIGQUIT",
        libc::SIGILL => "SIGILL",
        libc::SIGABRT => "SIGABRT",
        libc::SIGFPE => "SIGFPE",
        libc::SIGKILL => "SIGKILL",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGALRM => "SIGALRM",
        libc::SIGTERM => "SIGTERM",
        libc::SIGUSR1 => "SIGUSR1",
        libc::SIGUSR2 => "SIGUSR2",
        libc::SIGCHLD => "SIGCHLD",
        libc::SIGCONT => "SIGCONT",
        libc::SIGSTOP => "SIGSTOP",
        libc::SIGTSTP => "SIGTSTP",
        libc::SIGTTIN => "SIGTTIN",
        libc::SIGTTOU => "SIGTTOU",
        libc::SIGBUS => "SIGBUS",
        _ => return format!("signal {sig}"),
    };
    name.to_string()
}

fn print_exit_status(status: i32) {
    if libc::WIFEXITED(status) {
        eprintln!("+++ exited with {} +++", libc::WEXITSTATUS(status));
    } else if libc::WIFSIGNALED(status) {
        eprintln!("+++ killed by {} +++", signal_name(libc::WTERMSIG(status)));
    }
}

fn supervise(listener: i32, child: libc::pid_t) -> Result<()> {
    let mut reaped = false;
    loop {
        // 1. Reap the direct child whenever it finishes (non-blocking).
        let mut status: i32 = 0;
        let w = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if w == child && !reaped {
            reaped = true;
            print_exit_status(status);
        }

        // 2. Wait for a notification, or EOF when every filter user is gone.
        let mut pfd = libc::pollfd {
            fd: listener,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let pr = unsafe { libc::poll(&mut pfd, 1, 200) };
        if pr == -1 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            bail!("poll: {e}");
        }
        if pfd.revents & libc::POLLHUP != 0 {
            break;
        }
        if pfd.revents & libc::POLLIN == 0 {
            continue; // timeout: target is blocked inside a syscall; keep watching
        }

        // 3. Receive one notification.
        let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) };
        if r == -1 {
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::ENOENT) => break, // targets are gone
                Some(libc::EINTR) => continue,
                _ => bail!("NOTIF_RECV: {e}"),
            }
        }

        // 4. Print the syscall (entries only; no return values, by design).
        print_syscall(&notif);

        // 5. Let it run normally.
        let resp = SeccompNotifResp {
            id: notif.id,
            val: 0,
            error: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        };
        let s = unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) };
        if s == -1 {
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::ENOENT) => continue, // syscall interrupted / target died
                Some(libc::EINTR) => continue,
                _ => bail!("NOTIF_SEND: {e}"),
            }
        }
    }

    if !reaped {
        let mut status: i32 = 0;
        unsafe {
            libc::waitpid(child, &mut status, 0);
        }
        print_exit_status(status);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Usage: test_trace <program> [args...]
///
/// Traces the program like strace(1) (output on stderr); unlike strace it
/// captures *only* syscall entries -- no return values.
fn main() -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: test_trace <program> [args...]");
        std::process::exit(2);
    }
    let program = &args[0];
    let prog_args = &args[1..];

    let resolved = resolve_program(program)?;
    let exec_target =
        CString::new(resolved.as_os_str().as_bytes()).context("program path contains NUL")?;

    // argv / CStrings are built *before* fork so the child does zero
    // allocation between filter install and execv.
    let mut cstrings: Vec<CString> = Vec::with_capacity(prog_args.len() + 1);
    cstrings.push(CString::new(program.as_str()).context("program name contains NUL")?);
    for a in prog_args {
        cstrings.push(CString::new(a.as_str()).context("arg contains NUL")?);
    }
    let mut argv: Vec<*const libc::c_char> = cstrings.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    let mut sock = [0i32; 2];
    let r = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sock.as_mut_ptr(),
        )
    };
    if r == -1 {
        bail!("socketpair: {}", std::io::Error::last_os_error());
    }

    let pid = unsafe { libc::fork() };
    if pid == -1 {
        bail!("fork: {}", std::io::Error::last_os_error());
    }

    if pid == 0 {
        // ---- target (child): arm the filter, hand off the listener, exec ----
        unsafe {
            libc::close(sock[1]);
            let listener = match install_filter(sock[0]) {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("test_trace: {e:#}");
                    libc::_exit(126);
                }
            };
            if let Err(e) = send_fd(sock[0], listener) {
                eprintln!("test_trace: {e:#}");
                libc::_exit(126);
            }
            libc::execv(exec_target.as_ptr(), argv.as_ptr());
            eprintln!(
                "test_trace: execv failed: {}",
                std::io::Error::last_os_error()
            );
            libc::_exit(127);
        }
    }

    // ---- supervisor (parent) ----
    unsafe {
        libc::close(sock[0]);
    }
    let listener = recv_fd(sock[1]).context("receiving listener fd")?;
    unsafe {
        libc::close(sock[1]);
    }
    supervise(listener, pid)
}

// ---------------------------------------------------------------------------
// Tests (pure logic only; the kernel machinery is exercised via cargo run)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_lookup() {
        assert_eq!(syscall_name(59), "execve");
        assert_eq!(syscall_name(1), "write");
        assert_eq!(syscall_name(317), "seccomp");
        assert_eq!(syscall_name(999999), "syscall_999999");
    }

    #[test]
    fn table_is_sorted() {
        let mut prev = -1;
        for &(nr, _) in SYSCALLS {
            assert!(nr > prev, "table out of order at nr {nr}");
            prev = nr;
        }
    }

    #[test]
    fn escapes_non_printables() {
        assert_eq!(escape_bytes(b"a\nb\"\\"), "a\\nb\\\"\\\\");
        assert_eq!(escape_bytes(b"\x01\x1f"), "\\x01\\x1f");
    }

    #[test]
    fn path_slots_by_syscall() {
        assert_eq!(path_slots(2), &[0]);
        assert_eq!(path_slots(257), &[1]);
        assert_eq!(path_slots(264), &[1, 2]);
        assert_eq!(path_slots(42), &[]);
    }

    #[test]
    fn filter_bakes_in_handshake_fd() {
        let f = build_filter(7);
        assert_eq!(f.len(), 11);
        // slot 8 compares args[0] against the handshake fd
        assert_eq!(f[7].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(f[7].k, 16);
        assert_eq!(f[8].k, 7);
        // everything else ends in USER_NOTIF
        assert_eq!(f[10].k, SECCOMP_RET_USER_NOTIF);
        assert_eq!(f[2].k, SECCOMP_RET_KILL_PROCESS);
    }
}
