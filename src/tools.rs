//! Tool plumbing shared by the binaries that embed the agent loop.
//!
//! There are **no built-in tools**: every tool the model may call is registered
//! in Lua, in `agent.mcps`, and advertised from there (see
//! [`adopt_mcp_tools`] and `crate::lua::mcps_tool_defs`). The sandboxed shell
//! that used to be a `ToolDef` assembled here is `lua/bash_tool.lua` — a
//! connection like any other, so the registry is the single place that decides
//! what the agent can do, and a mode that lists no connections has no shell.

use crate::api::ToolDef;

/// Translate lib-level tools registered in `agent.mcps`
/// ([`agent::lua::McpToolDef`], reindexed fresh per request — never cached)
/// into this binary's API [`ToolDef`]s. Dead-code allowed: only the TUI
/// consumes it.
#[allow(dead_code)]
pub fn adopt_mcp_tools(tools: Vec<agent::lua::McpToolDef>) -> Vec<ToolDef> {
    tools
        .into_iter()
        .map(|t| ToolDef {
            kind: "function".into(),
            function: crate::api::FunctionDef {
                name: t.name,
                description: t.description,
                parameters: t.parameters,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing is built in any more: the catalog is exactly the registry's
    /// contents, translated one-for-one. (`agent.mcps` reindexing itself is
    /// covered in `crate::lua`'s tests; this is the translation half.)
    #[test]
    fn registry_tools_translate_one_for_one() {
        let tools = adopt_mcp_tools(vec![
            agent::lua::McpToolDef {
                name: "bash".into(),
                description: "run a command".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": { "cmdline": { "type": "string" } },
                    "required": ["cmdline"],
                }),
            },
            agent::lua::McpToolDef {
                name: "read".into(),
                description: "read a file".into(),
                parameters: serde_json::json!({ "type": "object" }),
            },
        ]);
        let names: Vec<&str> = tools.iter().map(|t| t.function.name.as_str()).collect();
        assert_eq!(names, ["bash", "read"], "order is the registry's own");
        assert_eq!(tools[0].kind, "function");
        assert_eq!(tools[0].function.description, "run a command");
        assert_eq!(
            tools[0].function.parameters["required"][0], "cmdline",
            "the schema travels verbatim"
        );
    }
}
