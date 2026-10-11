//! The `agent.api` table: every primitive Rust exposes to Lua, and the lock
//! that makes it read-only.
//!
//! One place, read-only, and annotated or it does not ship — the three
//! properties the banner below spells out. [`super::vm`] calls [`install_api`]
//! to build the table, and [`install_panel_primitives`] lives here too, because
//! the `agent.api.panel_*` entry points are bridge primitives like any other.
//!
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::Path;
use std::rc::Rc;

use mlua::{Lua, Table};

use crate::panels::{PaneInit, PanelOp, PanelSink, remember_label};

use super::history::lua_history_append;
use super::memory::{
    lua_memory_append, lua_memory_flush, lua_memory_latest, lua_memory_new, lua_memory_path,
};
use super::run::{InputOp, lua_ask_user, lua_input_op, lua_trigger};
use super::sandbox::{lua_close_stdin, lua_decide, lua_kill, lua_spawn, lua_step, lua_write_stdin};
use super::vm::{AskHandler, SinkSlot};

// ---------------------------------------------------------------------------
// `agent.api` — the Rust↔Lua bridge.
//
// Every primitive Rust exposes to Lua lives in one table, under its bare name
// (the namespace carries the "this is the substrate" signal, so there is no `_`
// prefix left to carry as well). Three properties:
//
//   * **one place**: `agent.api.<name>`, declared in
//     `lua/agent_api.meta.lua` — so the surface is discoverable instead of
//     folklore spread over the driver.
//   * **read-only**: `agent.api` is a proxy whose metatable raises on any
//     assignment and hides itself from `getmetatable`/`setmetatable`
//     ([`lock_table`]), so a policy cannot rewrite the bridge it is judged by.
//     (The `agent.api` slot itself is still an ordinary key on `agent`; the
//     sandbox's real security boundary is seccomp, not this table.)
//   * **annotated or it does not ship**: [`verify_api_annotations`] fails the
//     VM when a primitive has no declaration in `lua/agent_api.meta.lua`, or a
//     declaration names a function that does not exist.
//
// Lua-side fields deliberately stay on `agent` (they are not the bridge):
// `agent._events` (the hook registry), `agent.__on_reactor` (a flag Rust sets
// while a handler coroutine runs), and whatever the user's own config
// defines.
// ---------------------------------------------------------------------------

pub(super) fn install_api(
    lua: &Lua,
    sink: Option<&PanelSink>,
    on_ask: Option<AskHandler>,
) -> mlua::Result<Table> {
    // The panel sink is a *slot*, not a captured value: the panel primitives
    // read it when they are called, so the agent's long-lived config VM can be
    // given the current round's sink (or none) between tool calls instead of
    // being built per call to get one. See `install_sink`.
    let sink_slot = Rc::new(RefCell::new(sink.cloned()));
    lua.globals()
        .set("__agent_sink", SinkSlot(sink_slot.clone()))?;
    let api = lua.create_table()?;
    api.set("spawn", lua.create_function(lua_spawn)?)?;
    api.set("step", lua.create_function(lua_step)?)?;
    api.set("decide", lua.create_function(lua_decide)?)?;
    api.set("kill", lua.create_function(lua_kill)?)?;
    api.set("write", lua.create_function(lua_write_stdin)?)?;
    api.set("close_stdin", lua.create_function(lua_close_stdin)?)?;
    api.set("trigger", lua.create_function(lua_trigger)?)?;
    // The `&Lua` argument is required by `create_function` and unused: these
    // send on the same channel `agent.trigger` does, and the VM is not involved.
    api.set(
        "input_insert",
        lua.create_function(|_: &Lua, text: String| lua_input_op(InputOp::Append(text)))?,
    )?;
    api.set(
        "input_backspace",
        lua.create_function(|_: &Lua, ()| lua_input_op(InputOp::Backspace))?,
    )?;
    api.set(
        "input_clear",
        lua.create_function(|_: &Lua, ()| lua_input_op(InputOp::Clear))?,
    )?;
    api.set("ask_user", lua.create_function(lua_ask_user(on_ask))?)?;
    api.set("memory_path", lua.create_function(lua_memory_path)?)?;
    api.set("memory_append", lua.create_function(lua_memory_append)?)?;
    api.set("memory_latest", lua.create_function(lua_memory_latest)?)?;
    api.set("memory_flush", lua.create_function(lua_memory_flush)?)?;
    api.set("memory_new", lua.create_function(lua_memory_new)?)?;
    api.set("history_append", lua.create_function(lua_history_append)?)?;
    install_panel_primitives(lua, &api, &sink_slot)?;
    install_print(lua)?;
    crate::mcp::install_bridge(lua, &api)?;
    crate::lua::turn::install(lua, &api)?;
    Ok(api)
}

/// Replace the global `print` so it cannot land in the middle of the screen.
///
/// A TUI owns the terminal: a `print` from a tool callback or an event handler
/// would scribble over the alternate screen and leave the garbage there when it
/// exits. So `print` reports to [`crate::status`] instead — but only once a
/// screen has attached. Detached (the probe, the tests, `chat`) it writes to
/// real stdout exactly as before, which is what keeps a headless run debuggable.
///
pub(super) fn install_print(lua: &Lua) -> mlua::Result<()> {
    let sink = lua.create_function(|_: &Lua, line: String| {
        if crate::status::is_attached() {
            crate::status::print_line(&line);
        } else {
            println!("{line}");
        }
        Ok(())
    })?;
    lua.globals().set("__agent_print", sink)?;
    lua.load(PRINT_SHIM).exec()?;
    Ok(())
}

pub(super) const PRINT_SHIM: &str = r#"
local emit = __agent_print
function print(...)
  local n = select('#', ...)
  if n == 0 then return emit("") end
  local parts = {}
  for i = 1, n do parts[i] = tostring((select(i, ...))) end
  return emit(table.concat(parts, "\t"))
end
"#;

pub(super) fn lock_table(lua: &Lua, real: Table, name: &str) -> mlua::Result<Table> {
    let proxy = lua.create_table()?;
    let metatable = lua.create_table()?;
    metatable.set("__index", real)?;
    let name = name.to_string();
    metatable.set(
        "__newindex",
        lua.create_function(
            move |_, (first, second, _value): (mlua::Value, mlua::Value, mlua::Value)| {
                // Lua calls a `__newindex` metamethod as (table, key, value) —
                // the table itself arrives first, so the key is the *second*
                // argument. Name it when it is a string.
                let key = match (&first, &second) {
                    (mlua::Value::String(s), _) | (_, mlua::Value::String(s)) => {
                        s.to_string_lossy().to_string()
                    }
                    _ => "<non-string key>".to_string(),
                };
                Err::<(), _>(mlua::Error::RuntimeError(format!(
                    "agent.{name} is read-only: cannot set '{key}'"
                )))
            },
        )?,
    )?;
    metatable.set("__metatable", false)?;
    proxy.set_metatable(Some(metatable))?;
    Ok(proxy)
}

/// The primitives `lua/agent_api.meta.lua` declares, read as text.
///
/// A `---@meta` file is comments and must never be executed — `require`ing it would
/// run `function agent.api.x() end` against a *locked* table and raise — so the
/// declarations are read rather than loaded. `function agent.api.<name>(` is the
/// marker, required to start the line so a mention inside a comment is not mistaken
/// for a declaration.
///
/// That marker is a contract, and the file says so: the stubs look illustrative and
/// are not. `std::fs::read_to_string` failing is an error rather than an empty set,
/// because "this file declared no primitives" and "this file was not found" would
/// otherwise report the same way — as thirty-six undocumented primitives, which
/// sends the reader to the bridge instead of to the file that went missing.
pub(super) fn declared_primitives(meta: &Path) -> std::io::Result<BTreeSet<String>> {
    const MARKER: &str = "function agent.api.";
    let text = std::fs::read_to_string(meta)?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix(MARKER)?;
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect())
}

/// Fail the VM unless `lua/agent_api.meta.lua` and the real bridge name the same
/// primitives.
///
/// Both directions, because both are ways to be wrong: a primitive nobody wrote
/// down is folklore, and a declaration for a primitive that is gone is a
/// documentation promise the agent cannot keep.
///
/// Compared as two sets rather than by probing the table. Probing is what this used
/// to do — `api.get(name).is_err()` — and it does not work here: `api` is the plain
/// table [`install_api`] built, not the locked proxy, and on a plain table a missing
/// key reads as `Ok(Null)` rather than an error. So the stale direction silently
/// never fired, and a declaration for a renamed primitive passed. The proxy is the
/// thing that raises, and by then there is nothing left to check.
pub(super) fn verify_api_annotations(api: &Table, meta: &Path) -> mlua::Result<()> {
    let declared = declared_primitives(meta).map_err(|e| {
        mlua::Error::RuntimeError(format!("agent.api: cannot read {}: {e}", meta.display()))
    })?;

    let mut installed: BTreeSet<String> = BTreeSet::new();
    for pair in api.pairs::<String, mlua::Value>() {
        installed.insert(pair?.0);
    }

    let undocumented: Vec<&str> = installed
        .iter()
        .filter(|name| !declared.contains(*name))
        .map(String::as_str)
        .collect();
    if !undocumented.is_empty() {
        return Err(mlua::Error::RuntimeError(format!(
            "agent.api: no declaration in {} for: {}",
            meta.display(),
            undocumented.join(", ")
        )));
    }

    let stale: Vec<&str> = declared
        .iter()
        .filter(|name| !installed.contains(*name))
        .map(String::as_str)
        .collect();
    if !stale.is_empty() {
        return Err(mlua::Error::RuntimeError(format!(
            "agent.api: {} declares functions that do not exist: {}",
            meta.display(),
            stale.join(", ")
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------

/// Strict read of an optional `opts` boolean field: absent -> `None`, a real
/// boolean -> `Some(b)`, anything else -> error. (mlua's `FromLua for bool`
/// is *truthy* — a typo'd `boxed = "yes"` would silently become `true`.)
pub(super) fn opts_bool(t: &Table, key: &str) -> mlua::Result<Option<bool>> {
    if !t.contains_key(key)? {
        return Ok(None);
    }
    match t.get::<mlua::Value>(key)? {
        mlua::Value::Boolean(b) => Ok(Some(b)),
        v => Err(mlua::Error::FromLuaConversionError {
            from: v.type_name(),
            to: "boolean".to_string(),
            message: Some(format!("opts.{key} must be a boolean")),
        }),
    }
}

pub(super) fn install_panel_primitives(
    lua: &Lua,
    api: &Table,
    sink_slot: &Rc<RefCell<Option<PanelSink>>>,
) -> mlua::Result<()> {
    let panel_seq = Rc::new(RefCell::new(0u64));
    api.set("panel_create", {
        let seq = Rc::clone(&panel_seq);
        let sink = sink_slot.clone();
        lua.create_function(
            move |_: &Lua, (title, opts): (String, Option<Table>)| -> mlua::Result<u64> {
                // Ids come from the round's sink so Lua and Rust producers
                // in one round can never collide; headless falls back to a
                // per-VM counter (the ids still round-trip through the
                // handle's methods, they just don't reach any panel).
                let id = match &*sink.borrow() {
                    Some(s) => (*s).alloc_id(),
                    None => {
                        let mut n = seq.borrow_mut();
                        *n += 1;
                        *n
                    }
                };
                let (mut boxed, mut conceal_box) = (true, true);
                if let Some(t) = opts {
                    if let Some(b) = opts_bool(&t, "boxed")? {
                        boxed = b;
                    }
                    if let Some(c) = opts_bool(&t, "conceal_box")? {
                        conceal_box = c;
                    }
                }
                if let Some(s) = &*sink.borrow() {
                    s.push(PanelOp::Create {
                        id,
                        title,
                        boxed,
                        conceal_box,
                    });
                }
                Ok(id)
            },
        )?
    })?;
    api.set("panel_append", {
        let sink = sink_slot.clone();
        lua.create_function(move |_: &Lua, (id, text): (u64, String)| {
            if let Some(s) = &*sink.borrow() {
                s.push(PanelOp::Append { id, text });
            }
            Ok(())
        })?
    })?;
    api.set("panel_set", {
        let sink = sink_slot.clone();
        lua.create_function(move |_: &Lua, (id, text): (u64, String)| {
            if let Some(s) = &*sink.borrow() {
                s.push(PanelOp::Set { id, text });
            }
            Ok(())
        })?
    })?;
    api.set("panel_highlight", {
        let sink = sink_slot.clone();
        lua.create_function(
            move |_: &Lua, (id, start, finish, style): (u64, u64, u64, String)| {
                if let Some(s) = &*sink.borrow() {
                    s.push(PanelOp::Highlight {
                        id,
                        start: start as usize,
                        end: finish as usize,
                        style,
                    });
                }
                Ok(())
            },
        )?
    })?;
    api.set("panel_clear_regions", {
        let sink = sink_slot.clone();
        lua.create_function(move |_: &Lua, id: u64| {
            if let Some(s) = &*sink.borrow() {
                s.push(PanelOp::ClearRegions { id });
            }
            Ok(())
        })?
    })?;
    api.set("panel_overlay", {
        let sink = sink_slot.clone();
        lua.create_function(
            move |_: &Lua, (id, text, always): (u64, Option<String>, mlua::Value)| {
                if let Some(s) = &*sink.borrow() {
                    s.push(PanelOp::Overlay {
                        id,
                        text,
                        // `always` is widened from a bool to `true | string |
                        // nil` so a grant that lasts one run can be *called*
                        // that in the prompt. See `panels::Remember`.
                        remember: remember_label(&always),
                    });
                }
                Ok(())
            },
        )?
    })?;
    // Split panels: one titled box holding several regions, each with its own
    // caption, text, and declared grammar (the sibling of the single-body
    // panels above — `agent.split_panel` is the driver sugar). `panes` is an
    // array; each entry is either a caption string or a table with optional
    // `caption` and `lang` fields.
    api.set("panel_split", {
        let seq = Rc::clone(&panel_seq);
        let sink = sink_slot.clone();
        lua.create_function(
            move |_: &Lua, (title, panes): (String, mlua::Table)| -> mlua::Result<u64> {
                let mut inits: Vec<PaneInit> = Vec::new();
                for pair in panes.pairs::<mlua::Value, mlua::Value>() {
                    let (_, v) = pair?;
                    match v {
                        mlua::Value::String(s) => {
                            inits.push(PaneInit {
                                caption: s.to_str()?.to_string(),
                                lang: None,
                            });
                        }
                        mlua::Value::Table(t) => {
                            let caption = match t.get::<mlua::Value>("caption")? {
                                mlua::Value::String(s) => s.to_str()?.to_string(),
                                mlua::Value::Nil => String::new(),
                                _ => {
                                    return Err(mlua::Error::runtime(
                                        "split pane caption must be a string",
                                    ));
                                }
                            };
                            let lang = match t.get::<mlua::Value>("lang")? {
                                mlua::Value::String(s) => Some(s.to_str()?.to_string()),
                                mlua::Value::Nil => None,
                                _ => {
                                    return Err(mlua::Error::runtime(
                                        "split pane lang must be a string",
                                    ));
                                }
                            };
                            inits.push(PaneInit { caption, lang });
                        }
                        _ => {
                            return Err(mlua::Error::runtime(
                                "split panes: each entry is a caption string or a \
                                     { caption = …, lang = … } table",
                            ));
                        }
                    }
                }
                if inits.is_empty() {
                    return Err(mlua::Error::runtime("split panel needs at least one pane"));
                }
                let id = match &*sink.borrow() {
                    Some(s) => (*s).alloc_id(),
                    None => {
                        let mut n = seq.borrow_mut();
                        *n += 1;
                        *n
                    }
                };
                if let Some(s) = &*sink.borrow() {
                    s.push(PanelOp::Split {
                        id,
                        title,
                        panes: inits,
                    });
                }
                Ok(id)
            },
        )?
    })?;
    api.set("panel_pane_set", {
        let sink = sink_slot.clone();
        lua.create_function(move |_: &Lua, (id, pane, text): (u64, usize, String)| {
            if let Some(s) = &*sink.borrow() {
                s.push(PanelOp::SetPane { id, pane, text });
            }
            Ok(())
        })?
    })?;
    api.set("panel_pane_lang", {
        let sink = sink_slot.clone();
        lua.create_function(
            move |_: &Lua, (id, pane, lang): (u64, usize, Option<String>)| {
                if let Some(s) = &*sink.borrow() {
                    s.push(PanelOp::SetPaneLang { id, pane, lang });
                }
                Ok(())
            },
        )?
    })?;
    api.set("panel_pane_highlight", {
        let sink = sink_slot.clone();
        lua.create_function(
            move |_: &Lua, (id, pane, start, finish, style): (u64, usize, u64, u64, String)| {
                if let Some(s) = &*sink.borrow() {
                    s.push(PanelOp::HighlightPane {
                        id,
                        pane,
                        start: start as usize,
                        end: finish as usize,
                        style,
                    });
                }
                Ok(())
            },
        )?
    })?;
    api.set("panel_pane_clear_regions", {
        let sink = sink_slot.clone();
        lua.create_function(move |_: &Lua, (id, pane): (u64, usize)| {
            if let Some(s) = &*sink.borrow() {
                s.push(PanelOp::ClearPaneRegions { id, pane });
            }
            Ok(())
        })?
    })?;
    Ok(())
}
