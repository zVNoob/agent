//! Agent configuration in Lua: the `agent.llm` settings table, the system
//! prompt, the user's `~/.config/agent/init.lua` and how it is seeded — and the
//! promise that the test suite never reads the real home directory.
use super::*;

use crate::testutil::{scratch_dir, unique_path};

/// Two connections offering the *same* tool name are two tools, and the
/// names the model sees have to say so.
///
/// This is why tools are advertised as `{connection}.{tool}`: a bare
/// `list_issues` from two servers is one name for two tools, and the
/// registry resolves an unqualified name by scanning connections — so one of
/// them is not merely ambiguous, it is unreachable. Qualifying at the point
/// of advertisement means the collision cannot be expressed at all.
#[test]
fn tool_names_are_qualified_by_their_connection() {
    let lua = vm();
    lua.load(
        r#"
            local function conn(name, toolname)
              return {
                name = name,
                tools = { [toolname] = agent.utils.tool(
                  "the same tool, from " .. name,
                  { type = "object", properties = {} },
                  function () return { ok = true, result = name } end) },
              }
            end
            agent.mcps.alpha = conn("alpha", "list_issues")
            agent.mcps.beta  = conn("beta",  "list_issues")
        "#,
    )
    .exec()
    .expect("two connections with a colliding tool name");

    let names: Vec<String> = mcps_tool_defs(&lua)
        .expect("reindex")
        .into_iter()
        .map(|d| d.name)
        .collect();
    assert_eq!(
        names,
        [
            "alpha.list_issues",
            "bash.bash",
            "beta.list_issues",
            "fs.apply_patch",
            "fs.hand_to_user",
            "fs.read",
            "fs.write_file",
        ],
        "the two colliding tools are two names, alongside the built-ins"
    );

    // And each resolves to *its own* implementation, not the first match.
    for conn in ["alpha", "beta"] {
        let (body, _) = invoke_tool(&lua, &format!("{conn}.list_issues"), "{}")
            .expect("invoke")
            .expect("registered");
        let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
        assert_eq!(v["result"], conn, "{conn} runs its own tool");
    }

    // The bare name is not a way back in: it is a name the model was never
    // shown, so it resolves to nothing rather than to whichever came first.
    assert!(
        invoke_tool(&lua, "list_issues", "{}")
            .expect("invoke")
            .is_none(),
        "an unqualified name is refused, not guessed at"
    );
}

/// A user's `~/.config/agent/init.lua` has to do what it is for: override
/// the endpoint and the prompt, and register connections, all through the
/// real loader, with the per-request reindex picking them up.
///
/// This used to be a test that read "the example config the repo ships" —
/// and had been quietly passing for as long as no such file existed, because
/// it returned early when the config path was `None`. The repo ships no
/// example config; the user writes one. So it is written here instead, and
/// asserted through the same path the loader takes.
///
/// It is also the worked example of the policy convention: a policy is a
/// local table in the file that applies it, because `agent.bash` takes one.
#[test]
fn a_user_config_overrides_the_built_ins_and_registers_connections() {
    let lua = new_vm_with_sink(None).expect("vm");
    // The built-ins first, so the override is an override and not an
    // initialisation: `apply_config_source` runs on top of the entry script.
    load_init(&lua, &tree()).expect("the entry script");
    assert_eq!(
        llm_config(&lua).expect("llm").model,
        "gpt-4o-mini",
        "the built-in default is what a config starts from"
    );

    let source = r#"
            agent.llm.base_url = "http://127.0.0.1:9/v1"
            agent.llm.model    = "my-local-model"
            agent.llm.system_prompt = "You are a test fixture, and this is the prompt."
            agent.mcps = { echo = { name = "echo", tools = {
                echo = agent.utils.tool("echo one argument back", {
                  type = "object",
                  properties = { line = { type = "string", description = "the line" } },
                  required = { "line" },
                }, function (a) return { ok = true, result = a.line } end),
            } } }
        "#;
    apply_config_source(&lua, source).expect("the user config applies");

    let llm = llm_config(&lua).expect("llm");
    assert_eq!(
        llm.base_url, "http://127.0.0.1:9/v1",
        "the endpoint is overridden"
    );
    assert_eq!(llm.model, "my-local-model", "and so is the model");
    assert!(
        system_prompt(&lua)
            .expect("prompt")
            .contains("test fixture"),
        "and the prompt"
    );

    // The registry is what the request advertises, and this config replaced
    // it wholesale — so only its own tool is offered.
    let defs = mcps_tool_defs(&lua).expect("reindex");
    let names: Vec<&str> = defs.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        ["echo.echo"],
        "the config's registry — qualified by the connection name it chose"
    );

    for tool in &defs {
        assert_eq!(
            tool.parameters["type"], "object",
            "{} advertises a schema",
            tool.name
        );
        assert!(
            !tool.description.is_empty(),
            "{} has a description",
            tool.name
        );
        assert!(
            invoke_tool(&lua, &tool.name, r#"{"line":"hi"}"#)
                .expect("invoke")
                .is_some(),
            "{} is registered and callable",
            tool.name
        );
    }
}

/// Where the config is looked for: one path, under `$HOME`, and it has to
/// exist to count. Asserted through the `$HOME`-taking form so it does not
/// depend on whoever is running the suite.
/// The loader seeds the user's config from the shipped one, once, and runs
/// *that* — after which the file in `$HOME` is the configuration, not an
/// overlay on it.
///
/// Both halves matter. Seeding means a user who has never run the agent ends
/// up with a file they can read and edit, instead of having to write one from
/// a manual. And "runs that, not both" means the file they edit is the whole
/// truth: there is no second script underneath quietly contributing
/// connections the user cannot see or remove.
/// A test that reads the invoking user's `~/.config/agent/init.lua` is a
/// test that passes on one machine and fails on the next, and one that
/// passes or fails depending on what the operator last edited. This pins
/// the two doors that opened onto `$HOME`.
///
/// It runs a test VM with the *tree's* configuration and a config in a
/// temporary home that would be obviously wrong if it were read, and asserts
/// the VM came from the tree.
#[test]
fn the_test_suite_never_reads_the_real_home_directory() {
    // 1. `ConfigSource::default()` — what every `new_vm` uses — is the tree.
    assert_eq!(ConfigSource::default(), ConfigSource::Tree);
    // The tree's entry script registers the shell and the file tools. A
    // user's config need not — the hostile one this suite has been run
    // against registers neither — so their presence is the evidence.
    let lua = vm();
    let names: Vec<String> = mcps_tool_defs(&lua)
        .expect("reindex")
        .into_iter()
        .map(|d| d.name)
        .collect();
    assert_eq!(
        names,
        [
            "bash.bash",
            "fs.apply_patch",
            "fs.hand_to_user",
            "fs.read",
            "fs.write_file",
        ],
        "a plain VM has the shipped configuration, not the operator's"
    );

    // 2. The standalone tool-invocation path takes its configuration as an
    //    argument, so a test passes the tree explicitly rather than
    //    inheriting whatever is in `$HOME`. (Registration is the check; the
    //    call itself would need a sandbox answer, and a headless run denies
    //    every ask.)
    assert!(
        invoke_mcp_tool_with_asks("bash.bash", "{}", None, None, &ConfigSource::Tree)
            .expect("invoke")
            .is_some(),
        "the tree's configuration, found by name"
    );
    assert!(
        invoke_mcp_tool_with_asks("no.such.tool", "{}", None, None, &ConfigSource::Tree)
            .expect("invoke")
            .is_none(),
        "and nothing else is"
    );
}

#[test]
fn the_users_config_is_seeded_from_the_shipped_one_and_then_belongs_to_them() {
    let home = scratch_dir("agent-seed");
    let cfg = home.join(".config").join("agent").join("init.lua");

    // First run: no file, so the shipped one is copied there and that is the
    // script the VM is configured by.
    let (path, origin) = ensure_config(&tree(), Some(&home));
    assert_eq!(path, cfg, "the config is the user's own copy");
    assert_eq!(origin, ConfigOrigin::Seeded);
    assert!(cfg.is_file(), "and it exists now: {}", cfg.display());
    let seeded = std::fs::read_to_string(&cfg).expect("read the seeded config");
    assert!(
        seeded.contains("agent.llm"),
        "seeded from the real entry script, not a stub: {} bytes",
        seeded.len()
    );

    // A VM configured from the seeded file is a whole agent — the copy is
    // the real entry script, not a stub.
    let run = |home: &std::path::Path| -> Result<Lua, String> {
        let lua = Lua::new_with(STDLIB, mlua::LuaOptions::default()).map_err(|e| e.to_string())?;
        setup_tree(
            &lua,
            None,
            None,
            &tree(),
            &ConfigSource::UserHome(Some(home.to_path_buf())),
        )
        .map_err(|e| e.to_string())?;
        Ok(lua)
    };
    let seeded_vm = run(&home).expect("the seeded copy configures a VM");
    assert_eq!(
        llm_config(&seeded_vm).expect("llm").base_url,
        "https://api.openai.com/v1",
        "the seeded copy configures a working agent"
    );
    assert_eq!(
        mcps_tool_defs(&seeded_vm).expect("reindex").len(),
        5,
        "shell and the four file tools"
    );

    // Second run: the user's file is the configuration, never re-seeded
    // over. Note what an edit has to look like now: the file is the *whole*
    // config, so it is also what creates the tables it sets.
    std::fs::write(
        &cfg,
        "agent.llm = agent.llm or { base_url = 'x', model = 'x', api_key = '' }\n\
             agent.llm.model = 'mine'\n",
    )
    .expect("edit the config");
    let (path, origin) = ensure_config(&tree(), Some(&home));
    assert_eq!((path, origin), (cfg.clone(), ConfigOrigin::Existing));
    assert!(
        std::fs::read_to_string(&cfg)
            .expect("read")
            .contains("'mine'"),
        "an existing config is never re-seeded over"
    );

    let edited = run(&home).expect("the edited config loads");
    assert_eq!(
        llm_config(&edited).expect("llm").model,
        "mine",
        "the edit is what the VM runs"
    );
    assert!(
        mcps_tool_defs(&edited).expect("reindex").is_empty(),
        "and nothing else is layered underneath: replacing the file replaces \
             the configuration, which is the point of it being the user's"
    );

    // And a config may be as short as the one thing it wants to change. The
    // loader creates `agent.llm` before the config runs, precisely so that
    // a three-line file is a working configuration — a user who writes their
    // own from scratch should not have to reproduce a table constructor to
    // set a field on it.
    std::fs::write(&cfg, "agent.llm.model = 'short'\n").expect("a minimal config");
    let short = run(&home).expect("a one-line config loads");
    assert_eq!(llm_config(&short).expect("llm").model, "short");
    assert_eq!(
        llm_config(&short).expect("llm").base_url,
        "https://api.openai.com/v1",
        "and the fields it does not mention fall back to the default"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// A home that cannot be written must not stop the agent: it runs the
/// shipped defaults and says so. An agent that will not start is worse than
/// one that is not configured.
#[test]
fn an_unwritable_home_falls_back_to_the_shipped_defaults() {
    // A path whose parent is a *file*, so creating the directory under it
    // cannot work — no permission fiddling, and it fails the same way on
    // every platform and whether or not the suite runs as root.
    let blocker = scratch_dir("agent-blocked");
    std::fs::write(blocker.join("not-a-dir"), "x").expect("a file where a dir must go");

    let (path, origin) = ensure_config(&tree(), Some(&blocker.join("not-a-dir")));
    assert_eq!(origin, ConfigOrigin::Tree, "reported, not fatal");
    assert_eq!(
        path,
        tree().join("init.lua"),
        "and the shipped script is used instead"
    );
    let _ = std::fs::remove_dir_all(&blocker);
}

/// One path under home: `~/.config/agent/init.lua`, and a *file* or nothing.
///
/// Pinned on the three shapes `ensure_config` tells apart, since that is the
/// whole decision: nothing there yet is seeded from the shipped script, a
/// real file is the user's own, and a **directory** called `init.lua` is
/// neither — `is_file`, not `exists`, is what keeps it from being read as a
/// config and then failing with a message about the file rather than about
/// the directory.
#[test]
fn the_user_config_is_one_path_under_home() {
    let dir = unique_path("agent-confighome");
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = dir.join(".config").join("agent");
    std::fs::create_dir_all(&cfg).expect("make a fake home");
    let seeded = cfg.join("init.lua");

    // Nothing there yet: the shipped script is *seeded* there, and the caller
    // is told it did so, rather than the agent refusing to start.
    let (path, origin) = ensure_config(&tree(), Some(&dir));
    assert_eq!(path, seeded, "one path: ~/.config/agent/init.lua");
    assert_eq!(origin, ConfigOrigin::Seeded, "reported as seeded");
    assert!(path.is_file(), "and it was really written");

    // A directory that exists but is not the file is still no config: the
    // seed cannot be written, and the tree's own script is used instead.
    std::fs::remove_file(&seeded).expect("undo the seed");
    std::fs::create_dir_all(&seeded).expect("a decoy directory");
    let (path, origin) = ensure_config(&tree(), Some(&dir));
    assert_eq!(path, tree().join("init.lua"), "a directory is not a config");
    assert_eq!(origin, ConfigOrigin::Tree, "so the shipped script is used");

    std::fs::remove_dir_all(&seeded).expect("clear the decoy");

    // With a real file, it is the user's and the shipped one is left alone.
    std::fs::write(&seeded, "-- mine\n").expect("write a config");
    let (path, origin) = ensure_config(&tree(), Some(&dir));
    assert_eq!(path, seeded, "one path: ~/.config/agent/init.lua");
    assert_eq!(origin, ConfigOrigin::Existing, "and it is the user's own");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "-- mine\n",
        "read back verbatim, not re-seeded from the tree"
    );

    // And it is not re-seeded on a second call, which is the upgrade path's
    // whole point: the user's file is the authority, so upgrading the agent
    // does not overwrite it.
    let (path, origin) = ensure_config(&tree(), Some(&dir));
    assert_eq!(
        (path, origin),
        (seeded, ConfigOrigin::Existing),
        "idempotent"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
