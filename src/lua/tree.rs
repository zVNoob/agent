//! Assembling a VM's Lua from the shipped `lua/` tree: the module search path,
//! the auto-required `lib/*` modules, and the `init.lua` entry script.
//!
//! Kept apart from [`super::vm`] because this half is all *filesystem* — where
//! the tree is found, what order it loads in, and what a missing file is
//! called — where that half is all *runtime* (the stdlib, the `agent` table, the
//! ask handler).
//!
use std::path::{Path, PathBuf};

use mlua::{Lua, Table};

// The shipped `lua/` tree: how a VM's Lua is assembled.
//
// The tree ships alongside the binary:
//
//   lua/init.lua      the entry script — the only top-level script, run last
//   agent_api.meta.lua  the `agent.api` bridge: types for a language server,
//                       and the documentation the loader checks against the
//                       real bridge at startup
//   lua/fs.lua …      top-level modules, required on demand
//   lua/lib/**.lua    the module directory: every one is required (and cached)
//                     at VM setup, and any of them can require the others
//
// The tree is on the **module search path** ([`install_require`]), so `require`
// and `package.path` agree: `require("utils")` finds `lua/lib/utils.lua`,
// `require("fs")` finds `lua/fs.lua`, `require("net.http")` finds
// `lua/lib/net/http.lua` (dots are directories), and `require("net")` finds
// `lua/lib/net/init.lua`. Only `lib/` is auto-required at setup; a top-level
// module is pulled in by whoever wants it (the entry script requires what it
// registers — e.g. `agent.mcps.fs = require("fs")` — and so does a user config
// that adds a connection of its own).
//
// Because every lib module is auto-required, a lib module publishes itself by
// assigning to the `agent` table — `lua/lib/utils.lua` ends with
// `agent.utils = M`, so `agent.utils` is live on every VM with no require at
// the use site, while `require("utils")` still hands back the same table.
// That `lib/<name>.lua` -> `agent.<name>` convention is the whole mechanism;
// Rust stays out of it (a module that wants a different name just assigns a
// different field, or nothing at all).
//
// **Order matters for siblings, so use `require` for them.** The auto-scan
// requires lib modules in alphabetical order, so `lua/lib/aaa.lua` runs before
// `lua/lib/seccomp.lua` — a module that writes `local sc = agent.seccomp` at its
// top level gets `nil`, silently, because the sibling has not published itself
// yet. `local sc = require("seccomp")` is order-independent (it loads the
// sibling on demand, and the auto-scan's later require is a cache hit), and
// `agent.seccomp` then works for every caller *after* setup. Inside a function,
// at call time, `agent.seccomp` is fine.
// ---------------------------------------------------------------------------

/// The directory name this package installs under, in `share/`. Part of the
/// install layout rather than a constant that could drift from the `Makefile`.
pub(super) const PACKAGE: &str = "agent";

pub(super) fn lua_dir() -> PathBuf {
    lua_dir_in(
        std::env::var_os("AGENT_LUA_DIR").map(PathBuf::from),
        std::env::current_exe().ok(),
    )
}

/// Every place the tree is looked for, in order, as (what it is, the path).
///
/// Exposed so that a failure can *list what was tried*. The single most common
/// way to get this wrong is an incomplete install, and "lua lib: lua/lib: No
/// such file or directory (os error 2)" says nothing about which of four
/// directories was meant.
pub(super) fn lua_dir_candidates(
    explicit: Option<PathBuf>,
    exe: Option<PathBuf>,
) -> Vec<(&'static str, PathBuf)> {
    let mut out: Vec<(&'static str, PathBuf)> = Vec::new();
    if let Some(dir) = &explicit {
        out.push(("$AGENT_LUA_DIR", dir.clone()));
        return out;
    }
    if let Some(bin) = exe.as_deref().and_then(Path::parent) {
        // `<prefix>/share/agent/lua` — the install layout, found by walking
        // *up* from the executable, because the tree is not beside the binary
        // but beside the binary's sibling directory.
        if let Some(prefix) = bin.parent() {
            out.push((
                "installed (share)",
                prefix.join("share").join(PACKAGE).join("lua"),
            ));
        }
        // A tree laid *beside* the executable: what a hand-copied
        // `target/release/agent` sitting next to a `lua/` looks like.
        out.push(("beside the executable", bin.join("lua")));
    }
    // The tree this binary was built from — **debug builds only**, so that
    // `cargo run` and `cargo test` work from any directory without guessing at
    // the working directory.
    //
    // Not in release builds, and the reason is worth stating because the
    // unconditional version looked harmless and was not: a release binary built
    // on a machine that still has the checkout would fall back to it, so
    // `make install` followed by an edit to the checkout's `lua/` would change
    // the installed agent's behaviour — and a missing `share/` would be silently
    // papered over instead of reported. A release binary reads the tree it was
    // installed with, or nothing. `make run` sets `$AGENT_LUA_DIR` for the case
    // where you want a release build against the working tree anyway.
    if cfg!(debug_assertions) {
        out.push((
            "the tree it was built from (debug builds only)",
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("lua"),
        ));
    }
    out
}

/// The first candidate that holds an entry script, or the last one tried.
///
/// **There is deliberately no working-directory fallback.** A `lua/` directory
/// in the current directory used to be enough to load a policy, which for a tool
/// whose entire job is asking before it touches a file is a hole and not a
/// convenience: running the agent from a checkout of anything at all would have
/// silently replaced the shipped sandbox policy with whatever was in `./lua`.
pub(super) fn lua_dir_in(explicit: Option<PathBuf>, exe: Option<PathBuf>) -> PathBuf {
    if let Some(dir) = explicit {
        return dir;
    }
    let candidates = lua_dir_candidates(explicit, exe);
    for (_, dir) in &candidates {
        if dir.join("init.lua").is_file() {
            return dir.clone();
        }
    }
    candidates
        .into_iter()
        .last()
        .map(|(_, dir)| dir)
        .unwrap_or_else(|| PathBuf::from("lua"))
}

/// The message a missing tree produces, naming every location that was tried and
/// the one variable that overrides all of them.
pub(super) fn missing_tree_message(candidates: &[(&'static str, PathBuf)]) -> String {
    let mut msg = String::from(
        "the shipped Lua tree was not found. It installs to \
         <prefix>/share/agent/lua alongside the binary in <prefix>/bin; these \
         were tried, in order:",
    );
    for (what, dir) in candidates {
        msg.push_str(&format!("\n  {what}: {}", dir.display()));
    }
    msg.push_str(
        "\nSet $AGENT_LUA_DIR to the directory holding init.lua to override all \
         of them.",
    );
    // …and, if this is a machine that has the source tree, say so. A release
    // build run out of a checkout is a completely ordinary thing to do
    // (`cargo build --release && ./target/release/agent`) and the install paths
    // above will all be misses, which reads as a broken install rather than as
    // "you are in the wrong directory". Naming the checkout — as something to
    // point the variable at, not as something searched — is the difference
    // between a message someone can act on and one they have to reason about.
    let built_from = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("lua");
    if built_from.join("init.lua").is_file() {
        msg.push_str(&format!(
            "\nThis machine has the source tree; `AGENT_LUA_DIR={}` will use it, \
             and `make run` is that with the other arguments filled in.",
            built_from.display()
        ));
    }
    msg
}

/// Put the tree on the module search path, so `require` finds the modules a
/// VM loads.
///
/// The standard mechanism, so `require` and `package.path` agree: the tree's
/// `lib/` comes first (it is the module directory), then the tree root (where
/// the entry script and other top-level modules like `fs` live), each with both
/// the `?.lua` and the `?/init.lua` form:
///
pub(super) fn install_require(lua: &Lua, dir: &Path) -> mlua::Result<()> {
    let package: Table = lua
        .globals()
        .get("package")
        .map_err(|e| mlua::Error::RuntimeError(format!("lua: no package library: {e}")))?;
    let old: String = package.get("path")?;
    let lib = dir.join("lib");
    let path = [
        lib.join("?.lua").display().to_string(),
        lib.join("?").join("init.lua").display().to_string(),
        dir.join("?.lua").display().to_string(),
        dir.join("?").join("init.lua").display().to_string(),
        old,
    ]
    .join(";");
    package.set("path", path)?;
    Ok(())
}

/// Require every module under `lua/lib/`, recursively, in sorted order (so the
/// load order never follows directory order). Each lands in `package.loaded`, so
/// a module that requires a sibling sees it already loaded, and a later
/// `require` of the same name is a cache hit.
///
pub(super) fn load_lib_modules(lua: &Lua, dir: &Path) -> mlua::Result<()> {
    let mut names: Vec<String> = Vec::new();
    collect_modules(&dir.join("lib"), "", &mut names)?;
    names.sort();
    let require: mlua::Function = lua
        .globals()
        .get("require")
        .map_err(|e| mlua::Error::RuntimeError(format!("lua lib: no require: {e}")))?;
    for name in &names {
        require
            .call::<mlua::Value>(name.as_str())
            .map_err(|e| mlua::Error::RuntimeError(format!("lua lib: require(\"{name}\"): {e}")))?;
    }
    Ok(())
}

pub(super) fn collect_modules(dir: &Path, prefix: &str, out: &mut Vec<String>) -> mlua::Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| mlua::Error::RuntimeError(format!("lua lib: {}: {e}", dir.display())))?;
    let join = |base: &str, name: &str| {
        if base.is_empty() {
            name.to_string()
        } else {
            format!("{base}.{name}")
        }
    };
    for entry in entries {
        let entry = entry
            .map_err(|e| mlua::Error::RuntimeError(format!("lua lib: {}: {e}", dir.display())))?;
        let path = entry.path();
        let Some(file_name) = entry.file_name().to_str().map(str::to_string) else {
            continue; // not valid UTF-8: no Lua module can be named after it
        };
        if path.is_dir() {
            collect_modules(&path, &join(prefix, &file_name), out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("lua") {
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            out.push(join(prefix, stem));
        }
    }
    Ok(())
}

pub(super) fn load_init(lua: &Lua, dir: &Path) -> mlua::Result<()> {
    load_init_at(lua, &dir.join("init.lua"))
}

pub(super) fn load_init_at(lua: &Lua, path: &Path) -> mlua::Result<()> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| mlua::Error::RuntimeError(format!("lua config: {}: {e}", path.display())))?;
    lua.load(&source)
        .set_name(path.display().to_string())
        .exec()
}
