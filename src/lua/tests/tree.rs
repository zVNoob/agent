//! Where the `lua/` tree is found and what `require` can see from it.
use super::*;

    /// A name that is in no searcher fails with a name-bearing error (the
    /// standard "module not found" shape), not a silent nil.
    #[test]
    fn require_of_a_missing_module_fails_by_name() {
        let lua = vm();
        let err = lua
            .load(r#"require("no_such_module_xyz")"#)
            .eval::<mlua::Value>()
            .expect_err("require of a missing module must fail");
        let text = err.to_string();
        assert!(
            text.contains("no_such_module_xyz"),
            "error should name the module, got: {text}"
        );
    }

    /// The tree is on the module search path, `lib/` first: `require` finds a
    /// lib module, a top-level module, and a nested one, and the path itself
    /// says so.
    #[test]
    fn the_tree_is_on_the_module_search_path() {
        let lua = vm();
        let (path, ok): (String, bool) = lua
            .load(
                r#"
            local head = {}
            for entry in package.path:gmatch("[^;]+") do head[#head + 1] = entry end
            -- The first four entries are ours: lib/?/?.lua, lib/?/init.lua,
            -- ?/?.lua, ?/init.lua — the original path follows.
            return table.concat(head, ";"), require("utils") == agent.utils
        "#,
            )
            .eval()
            .expect("search path eval");
        let entries: Vec<&str> = path.split(';').collect();
        assert!(
            entries[0].ends_with("lua/lib/?.lua"),
            "lib first in the search path: {path}"
        );
        assert!(
            entries[1].ends_with("lua/lib/?/init.lua"),
            "the ?/init.lua form for a directory module: {path}"
        );
        assert!(
            entries[2].ends_with("lua/?.lua"),
            "the tree root is in the path too: {path}"
        );
        assert!(ok, "require resolves a lib module to the same table");
    }
