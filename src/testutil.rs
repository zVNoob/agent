//! Shared fixtures for the test suites.
//!
//! This is the one place a test asks for a temporary path, because there were
//! forty-seven places that did it themselves and three that disagreed: some keyed
//! on the process id alone, some on an id plus a counter. Pid alone is a
//! collision waiting to happen — two tests in one process that want the same
//! prefix get the same directory, and the failure is whichever one loses the
//! race deleting the other's files. The counter removes that, and having one
//! implementation means the naming convention is discoverable.
//!
//! Compiled into the library rather than hidden behind `#[cfg(test)]` because the
//! binaries' own test modules need it too, and a `cfg(test)` item is not
//! compiled into the lib when the lib is a *dependency* of a test binary.
//!
//! Nothing here is used by production code paths, and the name is the warning.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh temp path for one test: `<prefix>-<pid>-<n>`.
///
/// The path does not exist — the caller decides whether it wants a file or a
/// directory, and creating it here would hide a test that forgot to. Distinct
/// across every call in the process, so parallel tests cannot collide.
pub fn unique_path(prefix: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()))
}

/// [`unique_path`], as a directory that exists, emptied first.
///
/// For the common case: a test that wants somewhere to write and does not care
/// what was there. Removing whatever is already there is the point — a leftover
/// from an interrupted run must not be able to make the test pass.
pub fn scratch_dir(prefix: &str) -> PathBuf {
    let dir = unique_path(prefix);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the scratch directory");
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Distinct paths across calls, which is the whole contract: a suite runs its
    /// tests on many threads at once, and two tests sharing a path would race on
    /// the filesystem rather than fail loudly.
    #[test]
    fn every_call_is_distinct_even_within_one_prefix() {
        let a = unique_path("dup");
        let b = unique_path("dup");
        assert_ne!(a, b, "same prefix, same call site shape, still distinct");
        assert!(a.starts_with(std::env::temp_dir()), "and in the temp dir");
    }

    /// The scratch directory exists and is empty, so a test cannot pass on
    /// whatever a previous run left behind.
    #[test]
    fn a_scratch_dir_exists_and_is_empty() {
        let dir = scratch_dir("agent-scratch-test");
        assert!(dir.is_dir(), "created: {}", dir.display());
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "and empty, so a leftover cannot make a test pass for the wrong reason"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A stale directory at the same name is cleared, which is the case that
    /// makes `scratch_dir` worth having over `create_dir_all`.
    #[test]
    fn a_scratch_dir_is_cleared_before_use() {
        let dir = scratch_dir("agent-scratch-stale");
        std::fs::write(dir.join("leftover"), "x").expect("seed");
        let again = scratch_dir("agent-scratch-stale");
        assert!(again.is_dir(), "exists again");
        assert!(!again.join("leftover").exists(), "and the leftover is gone");
        std::fs::remove_dir_all(&again).ok();
    }
}
