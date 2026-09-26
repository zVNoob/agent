//! Grammar acquisition probe: proves the registry → compile → dlopen chain
//! end-to-end, without any grammar code in Cargo.
//!
//! Ensures `json`, `bash`, `markdown` and `markdown_inline` (the markdown
//! monorepo pair exercises the `parser_location` path), then parses a sample
//! with each and reports the resulting node trees and ABI versions.
//!
//! This is a demo binary, not library code: `grammars` itself stays stdio-free.

use agent::grammars::Catalog;
use anyhow::Result;
use tree_sitter::Parser;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut catalog = Catalog::new();
    let langs = ["json", "bash", "markdown", "markdown_inline"];
    let results = catalog.ensure_many(&langs).await;

    let mut failed = false;
    for (lang, r) in &results {
        match r {
            Ok(()) => println!("[grammars] {lang}: loaded"),
            Err(e) => {
                println!("[grammars] {lang}: FAILED — {e}");
                failed = true;
            }
        }
    }

    // Parse a sample per language (when available).
    for (lang, sample) in [
        ("json", r#"{"name": "agent", "tags": [1, 2, 3]}"#),
        ("bash", "for f in *.c; do echo \"$f\"; done"),
        ("markdown", "# Hi\n\nSome **bold** and `code`."),
    ] {
        let Some(g) = catalog.get(lang) else { continue };
        let mut parser = Parser::new();
        parser
            .set_language(&g.language)
            .unwrap_or_else(|e| panic!("{lang}: set_language failed: {e}"));
        let tree = parser.parse(sample, None).expect("parse");
        println!(
            "[{lang}] abi={} nodes={} root: {}",
            g.abi,
            tree.root_node().descendant_count(),
            tree.root_node().to_sexp()
        );
    }

    // End-to-end highlight: markdown with a bash fence, a json fence, and
    // inline formatting, all through the same pipeline the TUI uses.
    if let Some(mut hl) = agent::tui::MarkdownHighlighter::from_catalog(&catalog) {
        let sample = "# Hi\n\nSome **bold** and `code`.\n\n```bash\nfor f in *.c; do exit 1; done\n```\n\n```json\n{\"a\": [1, 2]}\n```";
        let segs = hl.highlight_message(sample);
        let covered: usize = segs.iter().map(|s| s.end - s.start).sum();
        let styled = segs
            .iter()
            .filter(|s| s.style != ratatui::style::Style::default())
            .count();
        assert_eq!(
            covered,
            sample.len(),
            "segments must cover the whole source"
        );
        println!(
            "[highlight] segments={} styled={} coverage={covered}/{}",
            segs.len(),
            styled,
            sample.len()
        );
        if styled == 0 {
            println!("[highlight] FAILED — no styled segments produced");
            failed = true;
        }

        // Markup conceal end-to-end: the pipeline the TUI pushes through. The
        // visible text (source minus the concealed ranges) must be exactly
        // the expected one — `#`/`**`/backticks/`*`/`~~` hidden, everything
        // else byte-for-byte.
        for (label, source, expected) in [
            (
                "inline",
                "# Plan\n\n**bold** and `code` and *it* and ~~gone~~",
                "Plan\n\nbold and code and it and gone",
            ),
            ("plain", "just words", "just words"),
            ("clamp", "**Hi**", "Hi"),
        ] {
            let h = hl.highlight_message_with_conceal(source);
            let conceal = &h.conceal;
            let mut prev = 0;
            let mut shown = String::with_capacity(source.len());
            for &(r0, r1) in conceal {
                shown.push_str(&source[prev..r0]);
                prev = r1;
            }
            shown.push_str(&source[prev..]);
            if shown != expected {
                println!(
                    "[conceal:{label}] FAILED — shown {shown:?} != {expected:?} ({conceal:?})"
                );
                failed = true;
            } else {
                println!("[conceal:{label}] ok — {shown:?} ({conceal:?})");
            }
        }

        // Fenced code: only the ``` delimiters vanish; the bash/json content
        // (and its language labels) render verbatim.
        let fence = "```bash\nfor f in *.c; do exit 1; done\n```\n\n```json\n{\"a\": [1, 2]}\n```";
        let h = hl.highlight_message_with_conceal(fence);
        // Both fences' `` ``` `` runs vanish; the blank line between them is
        // structural newlines and stays, and bash/json content is verbatim.
        let expect = "bash\nfor f in *.c; do exit 1; done\n\n\njson\n{\"a\": [1, 2]}\n";
        let mut prev = 0;
        let mut shown = String::new();
        for &(r0, r1) in &h.conceal {
            shown.push_str(&fence[prev..r0]);
            prev = r1;
        }
        shown.push_str(&fence[prev..]);
        let only_delimiters = h
            .conceal
            .iter()
            .all(|&(r0, r1)| r1 - r0 == 3 && &fence[r0..r1] == "```")
            && h.conceal.len() == 4;
        if shown != expect || !only_delimiters {
            println!(
                "[conceal:fence] FAILED — shown {shown:?} != {expect:?} ({:?})",
                h.conceal
            );
            failed = true;
        } else {
            println!("[conceal:fence] ok — delimiters hidden, content verbatim");
        }

        // No conceal range may touch fenced-code content.
        if h.conceal
            .iter()
            .any(|&(r0, _)| fence[r0..].starts_with("for f") || fence[r0..].starts_with("{\""))
        {
            println!("[conceal:fence] FAILED — a range lands inside the code content");
            failed = true;
        }
    } else {
        println!("[highlight] FAILED — markdown grammar not loaded");
        failed = true;
    }

    if failed {
        std::process::exit(1);
    }
    Ok(())
}
