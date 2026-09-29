// The architecture seam.
//
// Everything the supervisor knows about *this* machine's syscalls lives behind
// [`SyscallTable`] and a handful of per-arch constants. The engine
// (`super::`) is otherwise architecture-neutral: the BPF program shape, the
// user-notification ABI, the fork bookkeeping, the /proc parsing.
//
// Adding an architecture is one new module here (a `&[(i32, &str)]` number
// table plus four constants) and one arm in the two functions below. The
// syscall *names* are the portable contract — they are what a Lua policy names
// and what `syscall_name` hands back — so a new arch only has to map names to
// its own numbers.

mod x86_64;

/// A resolved, per-arch name↔number table: the engine's only view of "what is
/// a syscall number on this machine". Built once per sandbox spawn.
pub struct SyscallTable {
    /// number → canonical name, sorted by number for binary search.
    by_number: Vec<(i32, &'static str)>,
    /// name → number, for resolving a policy's mask.
    by_name: Vec<(&'static str, i32)>,
}

impl SyscallTable {
    /// Build a table from `(name, number)` pairs. Duplicate names or numbers
    /// would make lookups ambiguous, so they are rejected rather than silently
    /// taking the first.
    pub fn from_pairs<I>(pairs: I) -> Self
    where
        I: Iterator<Item = (&'static str, i32)>,
    {
        let mut by_name: Vec<(&'static str, i32)> = pairs.collect();
        by_name.sort_unstable_by_key(|&(name, _)| name);
        for w in by_name.windows(2) {
            if w[0].0 == w[1].0 {
                panic!(
                    "seccomp: duplicate syscall name '{}' in the arch table",
                    w[0].0
                );
            }
        }
        let mut by_number: Vec<(i32, &'static str)> =
            by_name.iter().map(|&(name, nr)| (nr, name)).collect();
        by_number.sort_unstable_by_key(|&(nr, _)| nr);
        for w in by_number.windows(2) {
            if w[0].0 == w[1].0 {
                panic!(
                    "seccomp: duplicate syscall number {} ({}/{}) in the arch table",
                    w[0].0, w[0].1, w[1].1
                );
            }
        }
        SyscallTable { by_number, by_name }
    }

    /// The number for a syscall name on this arch, or `None` when the name is
    /// not in the table (an unknown name is a policy error, not a silent 0).
    pub fn number_of(&self, name: &str) -> Option<i32> {
        self.by_name
            .binary_search_by_key(&name, |&(n, _)| n)
            .ok()
            .map(|i| self.by_name[i].1)
    }

    /// The canonical name for a syscall number, or `None` if the number is not
    /// in the table (the caller formats a synthetic name for unmapped numbers).
    pub fn name_of(&self, nr: i32) -> Option<&'static str> {
        self.by_number
            .binary_search_by_key(&nr, |&(n, _)| n)
            .ok()
            .map(|i| self.by_number[i].1)
    }
}

/// The `AUDIT_ARCH_*` value the BPF program checks to refuse a foreign ABI.
pub const AUDIT_ARCH: u32 = x86_64::AUDIT_ARCH;

/// The x32 marker bit, or 0 for an arch with no such ABI.
pub const X32_SYSCALL_BIT: u32 = x86_64::X32_SYSCALL_BIT;

/// The fork family the supervisor always intercepts.
pub const FORK_FAMILY: [i32; 4] = x86_64::FORK_FAMILY;

/// `sendmsg` on the listener fd, always allowed so the handshake cannot
/// deadlock.
pub const SYS_SENDMSG: u32 = x86_64::SYS_SENDMSG;

/// The name→number table for the architecture this binary was built for.
pub fn table() -> SyscallTable {
    x86_64::table()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is a real bijection on the names it covers: every name the
    /// engine resolves round-trips back to the same number, and the two index
    /// halves agree. (Duplicates are rejected at construction, so a name
    /// lookup can never silently disagree with a number lookup.)
    #[test]
    fn table_round_trips_and_indexes_agree() {
        let t = table();
        for &name in &[
            "read", "write", "openat", "execve", "clone", "fork", "seccomp",
        ] {
            let nr = t
                .number_of(name)
                .unwrap_or_else(|| panic!("{name} missing"));
            assert_eq!(t.name_of(nr), Some(name), "{name} -> {nr} round-trips");
        }
        assert_eq!(t.number_of("no_such_syscall"), None);
        assert_eq!(t.name_of(999_999), None);
    }

    /// The x86_64 numbers the engine and its tests hard-rely on (the fork
    /// family, sendmsg, and the classic syscall numbers) are the kernel's.
    #[test]
    fn x86_64_numbers_are_the_kernels() {
        let t = table();
        assert_eq!(t.number_of("read"), Some(0));
        assert_eq!(t.number_of("write"), Some(1));
        assert_eq!(t.number_of("open"), Some(2));
        assert_eq!(t.number_of("openat"), Some(257));
        assert_eq!(t.number_of("fork"), Some(57));
        assert_eq!(t.number_of("vfork"), Some(58));
        assert_eq!(t.number_of("clone"), Some(56));
        assert_eq!(t.number_of("clone3"), Some(435));
        assert_eq!(t.number_of("seccomp"), Some(317));
        assert_eq!(t.number_of("sendmsg"), Some(46));
        // The audit arch and the fork-family set agree with the table.
        assert_eq!(FORK_FAMILY, [57, 58, 56, 435]);
        assert_eq!(SYS_SENDMSG as i32, t.number_of("sendmsg").unwrap());
        assert_eq!(AUDIT_ARCH, 0xc000_003e);
        assert_eq!(X32_SYSCALL_BIT, 0x4000_0000);
    }

    /// A duplicate name or number is a table bug, caught at construction
    /// rather than becoming a lookup that answers the wrong thing.
    #[test]
    #[should_panic(expected = "duplicate syscall name")]
    fn duplicate_names_are_rejected() {
        SyscallTable::from_pairs([("read", 0), ("read", 1)].into_iter());
    }

    #[test]
    #[should_panic(expected = "duplicate syscall number")]
    fn duplicate_numbers_are_rejected() {
        SyscallTable::from_pairs([("read", 0), ("write", 0)].into_iter());
    }
}
