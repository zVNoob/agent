//! Markdown syntax highlighting for the turn panel.
//!
//! Bridges the runtime-loaded grammars (`crate::grammars`) into
//! `tree-sitter-highlight` and maps capture names onto ratatui [`Style`]s.
//!
//! The loaded markdown grammar parses each message body; its injection query
//! pulls in `markdown_inline` (inline formatting), the fenced-block language
//! from the fence's info string (bash/json), and html/yaml/toml. Languages we
//! do not have loaded are simply skipped by the injection callback, so those
//! ranges render unhighlighted instead of breaking.
//!
//! Every [`HighlightConfiguration`] is `configure`d with the *same* ordered
//! capture-name list, so a [`Highlight`] index means the same capture in every
//! layer (markdown and its injections) and one theme table
//! ([`style_for_capture`]) serves the lot. Highlight indices are resolved
//! through that shared list in the event loop of
//! [`MarkdownHighlighter::highlight_message`].
//!
//! The result is a contiguous sequence of [`Segment`]s (byte range + style)
//! covering the whole source, so callers can wrap and clip them without
//! re-deriving style boundaries.

use std::collections::HashMap;

use ratatui::style::{Color, Modifier, Style};
use tree_sitter::Parser;
use tree_sitter_highlight::{
    Error as HighlightError, Highlight, HighlightConfiguration, HighlightEvent, Highlighter,
};

use crate::grammars::{Catalog, LoadedGrammar};

/// Inline-span captures whose delimiter runs are hidden from the rendered
/// text (markup conceal). These only ever fire from the `markdown_inline`
/// injection over paragraph/heading text — fenced-code *content* is injected
/// as bash/json (no `markup.*` names), so code blocks keep their original
/// rendering. `markup.raw` here is exactly the inline code span capture;
/// fences use `markup.raw.block`, which is deliberately not in this list.
const INLINE_CONCEAL: [&str; 5] = [
    "markup.strong",
    "markup.emphasis",
    "markup.italic",
    "markup.strikethrough",
    "markup.raw",
];

/// Languages the markdown grammar can inject. The fenced-block language is
/// the text of the fence's `(language)` node; inline formatting is injected
/// with `#set! injection.language "markdown_inline"`.
const INJECTED: &[&str] = &["markdown_inline", "bash", "json"];

/// nvim-treesitter markers that must never be rendered as a style.
fn is_meta_capture(name: &str) -> bool {
    name.starts_with('_') || matches!(name, "conceal" | "nospell" | "none" | "spell")
}

/// The `@capture` names used in a query file, in first-appearance order.
/// nvim queries also use `@` to prefix predicate capture args, which are
/// captures too, so a plain token scan collects them all.
fn capture_names(query: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = query.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            let mut j = i + 1;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || matches!(bytes[j], b'.' | b'_' | b'-'))
            {
                j += 1;
            }
            if j > i + 1 {
                let name = &query[i + 1..j];
                if !is_meta_capture(name) {
                    out.push(name.to_string());
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// Capture name -> style. `markup.*`/`text.*` refine by their second segment;
/// anything unknown stays plain (merges with the surrounding text).
pub fn style_for_capture(name: &str) -> Style {
    let base = Style::default();
    let mut parts = name.split('.');
    let first = parts.next().unwrap_or_default();
    let second = parts.next();
    match (first, second) {
        ("keyword", _) => base.fg(Color::Magenta).add_modifier(Modifier::BOLD),
        ("string", _) | ("escape", _) => base.fg(Color::LightGreen),
        ("comment", _) => base.fg(Color::DarkGray),
        ("number", _) => base.fg(Color::LightYellow),
        ("boolean", _) => base.fg(Color::LightRed),
        ("constant", _) => base.fg(Color::LightMagenta),
        ("function", _) | ("method", _) | ("constructor", _) => {
            base.fg(Color::LightBlue).add_modifier(Modifier::BOLD)
        }
        ("type", _) => base.fg(Color::LightYellow),
        ("variable", Some("builtin")) => base.fg(Color::LightCyan),
        ("operator", _) => base.fg(Color::Cyan),
        ("punctuation", _) => base.fg(Color::DarkGray),
        ("property", _) | ("field", _) | ("label", _) | ("tag", _) => base.fg(Color::LightCyan),
        ("attribute", _) => base.fg(Color::LightRed),
        ("namespace", _) | ("module", _) => base.fg(Color::LightCyan),
        ("title", _) => base.fg(Color::LightYellow).add_modifier(Modifier::BOLD),
        ("link", _) | ("uri", _) | ("url", _) => {
            base.fg(Color::LightBlue).add_modifier(Modifier::UNDERLINED)
        }
        ("warning", _) | ("todo", _) | ("note", _) | ("info", _) | ("hint", _) => {
            base.fg(Color::LightYellow)
        }
        ("danger", _) | ("error", _) => base.fg(Color::LightRed).add_modifier(Modifier::BOLD),
        ("markup", Some(m)) | ("text", Some(m)) => match m {
            "heading" => base.fg(Color::LightYellow).add_modifier(Modifier::BOLD),
            "strong" => base.add_modifier(Modifier::BOLD),
            "emphasis" | "italic" => base.add_modifier(Modifier::ITALIC),
            "strikethrough" => base.add_modifier(Modifier::CROSSED_OUT),
            "raw" | "literal" | "inline" => base.fg(Color::LightGreen),
            "link" | "uri" | "url" => base.fg(Color::LightBlue).add_modifier(Modifier::UNDERLINED),
            "label" => base.fg(Color::LightCyan),
            "quote" => base.fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
            "subscript" | "superscript" => base.add_modifier(Modifier::DIM),
            "underline" => base.add_modifier(Modifier::UNDERLINED),
            _ => base, // list markers, unchecked items, &c. stay plain
        },
        _ => base,
    }
}

/// A compact style spec → [`Style`] for Lua panel regions ([`PanelOp`]s):
/// dot-separated modifier/color names (`"bold"`, `"bold.cyan"`,
/// `"underlined.lightred"`). If nothing in the spec is recognized it falls
/// back to [`style_for_capture`] — which returns plain for unknown names —
/// so a spec that is really a capture name (`"number"`, `"markup.strong"`,
/// …) still works.
pub fn style_for_spec(spec: &str) -> Style {
    let mut st = Style::default();
    let mut any = false;
    for tok in spec.split('.') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(c) = color_for_name(t) {
            st = st.fg(c);
            any = true;
        } else if let Some(m) = modifier_for_name(t) {
            st = st.add_modifier(m);
            any = true;
        }
    }
    if any { st } else { style_for_capture(spec) }
}

fn color_for_name(name: &str) -> Option<Color> {
    Some(match name {
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" | "purple" => Color::Magenta,
        "cyan" => Color::Cyan,
        "gray" | "grey" => Color::Gray,
        "darkgray" | "darkgrey" => Color::DarkGray,
        "lightred" => Color::LightRed,
        "lightgreen" => Color::LightGreen,
        "lightyellow" => Color::LightYellow,
        "lightblue" => Color::LightBlue,
        "lightmagenta" => Color::LightMagenta,
        "lightcyan" => Color::LightCyan,
        "white" => Color::White,
        _ => return None,
    })
}

fn modifier_for_name(name: &str) -> Option<Modifier> {
    Some(match name {
        "bold" => Modifier::BOLD,
        "dim" => Modifier::DIM,
        "italic" => Modifier::ITALIC,
        "underlined" | "underline" => Modifier::UNDERLINED,
        "slowblink" => Modifier::SLOW_BLINK,
        "rapidblink" => Modifier::RAPID_BLINK,
        "reversed" | "reverse" => Modifier::REVERSED,
        "hidden" => Modifier::HIDDEN,
        "crossedout" | "strikethrough" => Modifier::CROSSED_OUT,
        _ => return None,
    })
}

/// One styled byte range of a highlighted message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub start: usize,
    pub end: usize,
    pub style: Style,
}

/// Highlighting of one message body: the styled [`Segment`]s covering the
/// whole text, plus the byte ranges whose characters are hidden from the
/// rendered output — ATX heading `#` markers (and the space after them),
/// delimiter runs of formed inline spans (`**`/`*`/`` ` ``/`~~`), and fenced
/// code `` ``` `` delimiters. Sorted, disjoint, and clamped to the text
/// length; never overlaps fenced-code content, which renders verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighlightedMessage {
    pub segments: Vec<Segment>,
    pub conceal: Vec<(usize, usize)>,
}

/// The ready-to-use markdown highlighter for one session. Constructed once
/// from the loaded grammars; `highlight_message` is reentrant per message.
pub struct MarkdownHighlighter {
    markdown: HighlightConfiguration,
    injected: HashMap<String, HighlightConfiguration>,
    /// The shared capture-name list; indexes into it are `Highlight` values.
    names: Vec<String>,
    /// Fence info-string spellings -> canonical language name.
    aliases: HashMap<String, String>,
    highlighter: Highlighter,
    /// The markdown block grammar itself, re-parsed at push time to locate
    /// heading markers and fenced-code delimiters for markup concealment.
    markdown_language: tree_sitter::Language,
}

/// nvim-treesitter queries carry directives that only apply inside nvim and
/// that `tree-sitter-highlight`'s predicate evaluator rejects — most notably
/// `(#set! @capture key @capture)` ("Unexpected second capture name"), used
/// to attach URL data to link nodes. Remove exactly those clauses (and the
/// whitespace after them) and return the result; `None` when there is
/// nothing to remove, in which case the caller keeps the query byte-for-byte
/// (the bash and json queries always hit this path). The scan is string-aware
/// so parentheses inside string literals can never throw off the balancing.
fn sanitize_query(query: &str) -> Option<String> {
    let bytes = query.as_bytes();
    let n = bytes.len();
    let mut removals: Vec<(usize, usize)> = Vec::new();
    let mut cursor = 0usize;
    loop {
        // Find the next `(#set!` whose first argument names a capture.
        let mut start = None;
        let mut j = cursor;
        while j + 1 < n {
            if bytes[j] == b'(' {
                let mut k = j + 1;
                while k < n && (bytes[k].is_ascii_whitespace()) {
                    k += 1;
                }
                if k + 5 <= n && &query[k..k + 5] == "#set!" {
                    let mut a = k + 6;
                    while a < n && bytes[a].is_ascii_whitespace() {
                        a += 1;
                    }
                    if a < n && bytes[a] == b'@' {
                        start = Some(j);
                        break;
                    }
                }
            }
            j += 1;
        }
        let Some(open) = start else {
            break;
        };
        // Find the matching close paren without misreading strings.
        let mut depth = 1usize;
        let mut p = open + 1;
        let mut in_str = false;
        while p < n && depth > 0 {
            let b = bytes[p];
            if in_str {
                if b == b'\\' {
                    p += 1;
                } else if b == b'"' {
                    in_str = false;
                }
            } else {
                match b {
                    b'"' => in_str = true,
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
            }
            p += 1;
        }
        // Swallow the trailing whitespace so successive removals merge.
        let mut end = p;
        while end < n && bytes[end].is_ascii_whitespace() {
            end += 1;
        }
        removals.push((open, end));
        cursor = end;
    }
    if removals.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(query.len());
    let mut prev = 0;
    for (s, e) in removals {
        out.push_str(&query[prev..s]);
        prev = e;
    }
    out.push_str(&query[prev..]);
    Some(out)
}

/// `tree-sitter-highlight` excludes an `injection.content` node's *children*
/// from the injected ranges unless `injection.include-children` is set.
/// nvim-treesitter's markdown injection query injects `(inline)` /
/// `(pipe_table_cell)` into `markdown_inline` without that flag — and the
/// markdown *block* grammar's `(inline)` node contains only the formatting
/// marker tokens (`*`, `` ` ``), so the injected ranges would collapse to the
/// plain text between markers and `**bold**`/`*italic*`/`\`code\`` would never
/// highlight (nvim's own engine treats injections differently, which is why
/// this works there). The same applies to fenced code: the block grammar
/// gives `code_fence_content` marker-token children (`;`, `{`, `"`, `:`, …),
/// which would leave only gaps for the injected bash/json tree. Add the flag
/// to every rule that injects markdown_inline and to the fenced-code rule.
/// `None` when nothing needed changing.
fn normalize_markdown_injections(injections: &str) -> Option<String> {
    let bytes = injections.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(injections.len() + 64);
    let mut i = 0;
    let mut changed = false;
    while i < n {
        if bytes[i] == b'(' {
            let mut depth = 1usize;
            let mut j = i + 1;
            let mut in_str = false;
            while j < n && depth > 0 {
                let b = bytes[j];
                if in_str {
                    if b == b'\\' {
                        j += 1;
                    } else if b == b'"' {
                        in_str = false;
                    }
                } else {
                    match b {
                        b'"' => in_str = true,
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                }
                j += 1;
            }
            let group = &injections[i..j.min(n)];
            let needs_injection_flag =
                group.contains("\"markdown_inline\"") || group.contains("code_fence_content");
            if needs_injection_flag {
                out.push_str(&group[..group.len() - 1]);
                out.push_str("\n  (#set! injection.include-children)");
                out.push(')');
                changed = true;
            } else {
                out.push_str(group);
            }
            i = j;
        } else {
            let start = i;
            while i < n && bytes[i] != b'(' {
                i += 1;
            }
            out.push_str(&injections[start..i]);
        }
    }
    changed.then_some(out)
}

/// Drop nvim-only spell/conceal meta captures from a *highlights* query.
///
/// `tree-sitter-highlight` resolves a node to its *last* same-node capture, so
/// a trailing `@nospell`/`@spell`/`@conceal` on an otherwise-styled node
/// (e.g. `(code_span) @markup.raw @nospell`) silently blanks the highlight.
/// Those captures mean nothing outside nvim, so:
/// - `@spell`/`@nospell`/`@conceal` capture tokens are removed everywhere, and
/// - any `(#predicate …)` clause that references one of them as an argument is
///   dropped whole, because its target capture is about to disappear (keeping
///   it would turn the query invalid: "capture not used in pattern").
///
/// Predicates with only literal/string arguments, e.g. `(#set! conceal "")`,
/// are kept verbatim (they are harmless no-ops for tree-sitter-highlight).
///
/// `None` when nothing was removed, in which case the caller keeps the
/// original byte-for-byte.
fn strip_meta_captures(query: &str) -> Option<String> {
    const META: [&str; 3] = ["spell", "nospell", "conceal"];
    let b = query.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(query.len());
    let mut i = 0;
    let mut changed = false;
    while i < n {
        match b[i] {
            b'"' => {
                let start = i;
                i += 1;
                while i < n {
                    if b[i] == b'\\' {
                        i = (i + 1).min(n);
                        if i < n {
                            i += 1;
                        }
                    } else if b[i] == b'"' {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
                out.push_str(&query[start..i]);
            }
            b'(' => {
                // A clause whose first token is `#…` is a predicate call.
                let mut j = i + 1;
                while j < n && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < n && b[j] == b'#' {
                    let end = clause_end(query, i).unwrap_or(n);
                    let args = clause_capture_args(query, i, end);
                    if args.iter().any(|name| META.contains(&name.as_str())) {
                        changed = true; // drop the whole predicate clause
                    } else {
                        out.push_str(&query[i..end]);
                    }
                    i = end;
                } else {
                    out.push('(');
                    i += 1;
                }
            }
            b'@' => {
                let start = i;
                i += 1;
                while i < n && is_capture_name_byte(b[i]) {
                    i += 1;
                }
                if META.iter().any(|m| *m == &query[start + 1..i]) {
                    changed = true; // drop the token, keep surrounding whitespace
                } else {
                    out.push_str(&query[start..i]);
                }
            }
            _ => {
                let ch = query[i..].chars().next().expect("i < n");
                out.push_str(&query[i..i + ch.len_utf8()]);
                i += ch.len_utf8();
            }
        }
    }
    changed.then_some(out)
}

/// Byte past the `)` closing the clause opened at `start` (`start` is a `(`).
/// String literals are skipped wholesale so `"` and `)` inside them (or quoted
/// backslashes) never disturb the paren balance. `None` if unbalanced.
fn clause_end(query: &str, start: usize) -> Option<usize> {
    let b = query.as_bytes();
    let n = b.len();
    let mut depth = 0usize;
    let mut i = start;
    while i < n {
        match b[i] {
            b'"' => {
                i += 1;
                while i < n {
                    if b[i] == b'\\' {
                        i = (i + 1).min(n);
                        if i < n {
                            i += 1;
                        }
                    } else if b[i] == b'"' {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
            }
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// Capture names referenced as predicate arguments inside `(start..end)`.
fn clause_capture_args(query: &str, start: usize, end: usize) -> Vec<String> {
    let b = query.as_bytes();
    let mut args = Vec::new();
    let mut i = start + 1; // skip the '('
    while i < end {
        match b[i] {
            b'#' => {
                // the predicate symbol itself, e.g. `eq?`, `set!`, `lua-match?`
                i += 1;
                while i < end && is_capture_name_byte(b[i]) {
                    i += 1;
                }
            }
            b'@' => {
                let t0 = i;
                i += 1;
                while i < end && is_capture_name_byte(b[i]) {
                    i += 1;
                }
                args.push(query[t0 + 1..i].to_string());
            }
            b'"' => {
                i += 1;
                while i < end {
                    if b[i] == b'\\' {
                        i = (i + 1).min(end);
                        if i < end {
                            i += 1;
                        }
                    } else if b[i] == b'"' {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
            }
            _ => i += 1,
        }
    }
    args
}

fn is_capture_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'?' | b'!')
}

fn build_config(g: &LoadedGrammar, name: &str, names: &[String]) -> Option<HighlightConfiguration> {
    let highlights_raw = g.highlights.as_deref()?;
    let highlights_san = sanitize_query(highlights_raw);
    let highlights_clean = strip_meta_captures(highlights_san.as_deref().unwrap_or(highlights_raw));
    let highlights = highlights_clean
        .as_deref()
        .unwrap_or(highlights_san.as_deref().unwrap_or(highlights_raw));
    let injections_raw = g.injections.as_deref().unwrap_or("");
    let injections_san = sanitize_query(injections_raw);
    let injections_sanned = injections_san.as_deref().unwrap_or(injections_raw);
    let injections_norm = if name == "markdown" {
        normalize_markdown_injections(injections_sanned)
    } else {
        None
    };
    let injections = injections_norm.as_deref().unwrap_or(injections_sanned);
    let mut config = HighlightConfiguration::new(
        g.language.clone(),
        name.to_string(),
        highlights,
        injections,
        "",
    )
    .ok()?;
    config.configure(names);
    Some(config)
}

impl MarkdownHighlighter {
    /// Build from the runtime catalogue. `None` when the markdown grammar
    /// itself is unavailable — callers fall back to plain text.
    pub fn from_catalog(catalog: &Catalog) -> Option<Self> {
        let md = catalog.get("markdown")?;
        let md_highlights = md.highlights.as_deref()?;

        // One capture-name list shared by every layer, so `Highlight` indexes
        // line up across the markdown tree and all injected trees.
        let mut names = capture_names(md_highlights);
        for lang in INJECTED {
            if let Some(g) = catalog.get(lang)
                && let Some(q) = g.highlights.as_deref()
            {
                names.extend(capture_names(q));
            }
        }
        names.sort();
        names.dedup();

        let markdown = build_config(md, "markdown", &names)?;
        let mut injected = HashMap::new();
        for lang in INJECTED {
            if let Some(g) = catalog.get(lang)
                && let Some(cfg) = build_config(g, lang, &names)
            {
                injected.insert(lang.to_string(), cfg);
            }
        }

        let mut aliases = HashMap::new();
        for alias in ["sh", "shell"] {
            aliases.insert(alias.to_string(), "bash".to_string());
        }

        Some(Self {
            markdown,
            injected,
            names,
            aliases,
            highlighter: Highlighter::new(),
            markdown_language: md.language.clone(),
        })
    }

    /// Highlight a message body into contiguous, full-coverage [`Segment`]s
    /// (first starts at 0, last ends at the text length). Returns empty on
    /// any failure — the caller renders plain text.
    ///
    /// The markdown block grammar requires a trailing newline after block
    /// constructs (an ATX heading, a fenced code block's closing fence, ...).
    /// A message body often has none, which made short messages like `# Plan`
    /// or `**Hello**` parse as an `ERROR` node and render unhighlighted.
    /// We append one newline for parsing — exactly how editors see markdown
    /// buffers — and clamp every emitted range back to the real text length.
    pub fn highlight_message(&mut self, text: &str) -> Vec<Segment> {
        self.highlight_message_with_conceal(text).segments
    }

    /// Highlight a message body into a `HighlightedMessage`: the styled
    /// segments (identical to [`Self::highlight_message`], which delegates
    /// here) plus the concealed marker ranges.
    ///
    /// Two sources feed the conceal map:
    /// - a second parse with the block grammar locates `atx_h*_marker` and
    ///   `fenced_code_block_delimiter` nodes *exactly* (a heading's `#` plus
    ///   the space after it; a fence's `` ``` `` runs), and
    /// - the highlight event stream hands back the byte range of every
    ///   formed inline span (`markup.strong`/`italic`/`strikethrough`/`raw`),
    ///   whose symmetric delimiter runs are hidden.
    ///
    /// Ranges are merged, clamped to the text length, and anything sitting
    /// inside `code_fence_content` is dropped so code blocks render verbatim
    /// (their syntax highlighting comes from the injected language, not from
    /// markdown markers).
    pub fn highlight_message_with_conceal(&mut self, text: &str) -> HighlightedMessage {
        let len = text.len();
        let mut augmented = String::with_capacity(len + 1);
        augmented.push_str(text);
        augmented.push('\n');
        let src = augmented.as_bytes();
        let highlighter = &mut self.highlighter;
        let injected = &self.injected;
        let aliases = &self.aliases;
        let events = match highlighter.highlight(&self.markdown, src, None, |name| {
            let canonical = aliases.get(name).map(String::as_str).unwrap_or(name);
            injected.get(canonical)
        }) {
            Ok(it) => it,
            Err(_) => {
                return HighlightedMessage {
                    segments: Vec::new(),
                    conceal: Vec::new(),
                };
            }
        };

        let (segments, spans) = consume_events(&self.names, events, len);

        // Conceal ranges: block-level markers from a re-parse, inline
        // delimiter runs from the collected spans.
        let (mut conceal, fence_content) = block_marker_ranges(&self.markdown_language, text, len);
        for (name, s, e) in &spans {
            if let Some((lead, trail)) = inline_delimiters(name, &text[*s..*e]) {
                conceal.push((*s, *s + lead));
                conceal.push((*e - trail, *e));
            }
        }
        merge_conceal(&mut conceal, &fence_content, len);

        HighlightedMessage { segments, conceal }
    }

    /// Highlight `text` directly with the grammar named by `lang` (e.g.
    /// `"json"`), bypassing the markdown pipeline — used by panels whose
    /// `SetLang` declares the language instead of carrying a ```lang fence.
    /// The named grammar's own `highlights.scm` themes the whole body with the
    /// shared capture table, and the ranges come back exact (no injected-tree
    /// offsets). An unloaded or unknown language degrades to plain text.
    pub fn highlight_lang(&mut self, lang: &str, text: &str) -> HighlightedMessage {
        // Disjoint field borrows so the config can stay live while the events
        // iterator mutably borrows the highlighter.
        let highlighter = &mut self.highlighter;
        let names = &self.names;
        let canonical = self.aliases.get(lang).map(String::as_str).unwrap_or(lang);
        let config = if canonical == "markdown" {
            Some(&self.markdown)
        } else {
            self.injected.get(canonical)
        };
        let Some(config) = config else {
            return HighlightedMessage {
                segments: Vec::new(),
                conceal: Vec::new(),
            };
        };
        let events = match highlighter.highlight(config, text.as_bytes(), None, |_| None) {
            Ok(it) => it,
            Err(_) => {
                return HighlightedMessage {
                    segments: Vec::new(),
                    conceal: Vec::new(),
                };
            }
        };
        let (segments, _) = consume_events(names, events, text.len());
        HighlightedMessage {
            segments,
            conceal: Vec::new(),
        }
    }
}

/// Consume a highlight event stream into (ordered, full-coverage segments
/// filling to `len`, completed inline spans). Shared by the markdown pipeline
/// (which conceals the inline-span delimiters) and the direct-language path
/// (which ignores the spans).
fn consume_events(
    names: &[String],
    events: impl Iterator<Item = Result<HighlightEvent, HighlightError>>,
    len: usize,
) -> (Vec<Segment>, Vec<(String, usize, usize)>) {
    let mut out: Vec<Segment> = Vec::new();
    let mut stack: Vec<Highlight> = Vec::new();
    // Mirror of `stack` for concealment: (capture name index for inline
    // spans, span start byte once its first Source range arrives). Pushed
    // for *every* highlight so HighlightEnd stays balanced.
    let mut span_stack: Vec<(Option<usize>, Option<usize>)> = Vec::new();
    // Completed inline spans: (capture name, start, end).
    let mut spans: Vec<(String, usize, usize)> = Vec::new();
    // End of the most recent Source range, to close a span on its End.
    let mut last_src_end = 0usize;
    let mut prev_end = 0;
    for event in events {
        match event {
            Ok(HighlightEvent::Source { start, end }) => {
                // Clamp the synthetic trailing newline out of every range.
                let start = start.min(len);
                let end = end.min(len);
                // Open spans get their start from the range that first
                // covers them; every span closes at the current range's
                // end (the last Source before its HighlightEnd).
                if end > start {
                    last_src_end = end;
                    for (_, s) in span_stack.iter_mut() {
                        if s.is_none() {
                            *s = Some(start);
                        }
                    }
                }
                let style = match stack.last() {
                    Some(h) => style_for_capture(&names[h.0]),
                    None => Style::default(),
                };
                if start > prev_end {
                    out.push(Segment {
                        start: prev_end,
                        end: start,
                        style: Style::default(),
                    });
                }
                if end > start {
                    if let Some(last) = out.last_mut()
                        && last.end == start
                        && last.style == style
                    {
                        last.end = end; // coalesce same-style neighbours
                    } else {
                        out.push(Segment { start, end, style });
                    }
                }
                prev_end = prev_end.max(end);
            }
            Ok(HighlightEvent::HighlightStart(h)) => {
                stack.push(h);
                let tracked = INLINE_CONCEAL.contains(&names[h.0].as_str());
                span_stack.push((tracked.then_some(h.0), None));
            }
            Ok(HighlightEvent::HighlightEnd) => {
                stack.pop();
                if let Some((Some(idx), Some(s))) = span_stack.pop()
                    && s < last_src_end
                {
                    spans.push((names[idx].clone(), s, last_src_end));
                }
            }
            Err(_) => break,
        }
    }
    if prev_end < len {
        out.push(Segment {
            start: prev_end,
            end: len,
            style: Style::default(),
        });
    }
    (out, spans)
}

/// True when `kind` is an ATX heading marker node (`atx_h1_marker` …
/// `atx_h6_marker`).
fn is_atx_marker(kind: &str) -> bool {
    matches!(
        kind,
        "atx_h1_marker"
            | "atx_h2_marker"
            | "atx_h3_marker"
            | "atx_h4_marker"
            | "atx_h5_marker"
            | "atx_h6_marker"
    )
}

/// The symmetric delimiter runs [(leading, trailing)] framing `span` when it
/// is a formed inline span of `kind`: `markup.raw` (code spans — backtick
/// runs, required equal on both sides by markdown), `markup.strikethrough`
/// (`~`), and strong/emphasis (`*` or `_`). `None` otherwise — so a span
/// merely carrying the name (an fenced code block, a quoted word) never loses
/// characters.
fn inline_delimiters(kind: &str, span: &str) -> Option<(usize, usize)> {
    let open = span.chars().next()?;
    let close = span.chars().last()?;
    let delim = match kind {
        "markup.raw" => '`',
        "markup.strikethrough" => '~',
        _ => match open {
            '*' | '_' => open,
            _ => return None,
        },
    };
    if open != delim || close != delim {
        return None;
    }
    let leading = span.chars().take_while(|&c| c == delim).count();
    let trailing = span.chars().rev().take_while(|&c| c == delim).count();
    if leading == 0 || trailing == 0 || leading != trailing {
        return None;
    }
    Some((leading, trailing))
}

/// Conceal ranges plus the `code_fence_content` ranges that must stay intact.
type ConcealAndGuards = (Vec<(usize, usize)>, Vec<(usize, usize)>);

/// From the markdown block tree, the byte ranges to conceal (ATX heading
/// `#` markers plus the space after them, and fenced code `` ``` ``
/// delimiters) and the `code_fence_content` ranges that must never be
/// concealed — code blocks keep their original rendering. Both clamped to
/// `len`; parses `text` with an appended newline like [`Self::highlight_message`].
fn block_marker_ranges(lang: &tree_sitter::Language, text: &str, len: usize) -> ConcealAndGuards {
    let mut conceal = Vec::new();
    let mut content = Vec::new();
    let mut parser = Parser::new();
    if parser.set_language(lang).is_err() {
        return (conceal, content);
    }
    let mut augmented = String::with_capacity(len + 1);
    augmented.push_str(text);
    augmented.push('\n');
    let Some(tree) = parser.parse(augmented.as_bytes(), None) else {
        return (conceal, content);
    };
    let bytes = text.as_bytes();
    let mut stack = vec![tree.root_node()];
    // Iterative DFS: long messages must not recurse.
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if is_atx_marker(kind) {
            let mut end = node.end_byte();
            if end < len && bytes[end] == b' ' {
                end += 1; // heading text sits flush-left, no stray space
            }
            conceal.push((node.start_byte().min(len), end));
        } else if kind == "fenced_code_block_delimiter" {
            conceal.push((node.start_byte().min(len), node.end_byte().min(len)));
        } else if kind == "code_fence_content" {
            content.push((node.start_byte().min(len), node.end_byte().min(len)));
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    (conceal, content)
}

/// Sort and merge `conceal` (overlaps collapse — nested spans contribute
/// duplicate marker runs), clamp to `len`, and drop ranges fully inside
/// `fence_content` so fenced code renders verbatim.
fn merge_conceal(conceal: &mut Vec<(usize, usize)>, fence_content: &[(usize, usize)], len: usize) {
    for r in conceal.iter_mut() {
        r.1 = r.1.min(len);
    }
    conceal.retain(|&(r0, r1)| r0 < r1);
    conceal.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(conceal.len());
    for range in conceal.drain(..) {
        match merged.last_mut() {
            Some(last) if range.0 <= last.1 => last.1 = last.1.max(range.1),
            _ => merged.push(range),
        }
    }
    merged.retain(|&(r0, r1)| !fence_content.iter().any(|&(c0, c1)| c0 <= r0 && r1 <= c1));
    *conceal = merged;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_names_collects_and_filters() {
        let q = "(x @keyword @keyword.conditional @string.special.symbol \
                 @_private @none @nospell @conceal @spell)";
        assert_eq!(
            capture_names(q),
            vec!["keyword", "keyword.conditional", "string.special.symbol"]
        );
    }

    #[test]
    fn sanitizer_drops_nvim_capture_set_but_keeps_supported_predicates() {
        // The markdown_inline query's URL-augmentation directives must go…
        let bad = "((uri_autolink) @_url (#offset! @_url 0 1 0 -1)\n\
                   (#set! @_url url @_url))";
        let out = sanitize_query(bad).unwrap();
        assert!(!out.contains("#set! @_url"));
        assert!(out.contains("#offset! @_url 0 1 0 -1"));

        // …while nvim-style literal #set! and value predicates stay.
        let good = "((entity_reference) @character.special\n\
                    (#eq? @character.special \"&amp;\")\n\
                    (#set! conceal \"&\"))";
        assert!(sanitize_query(good).is_none());

        // Parens inside string literals must not confuse the scanner.
        let parens = "(rule @x (#match? @x \"a(b)c\")) (#set! @y k @z)";
        assert_eq!(
            sanitize_query(parens).unwrap(),
            "(rule @x (#match? @x \"a(b)c\")) "
        );

        // Queries with nothing to remove pass through untouched.
        let plain = "(atx_heading (atx_h1_marker)) @markup.heading.1";
        assert!(sanitize_query(plain).is_none());
    }

    #[test]
    fn strip_meta_captures_drops_nvim_only_spell_captures() {
        // @nospell is dropped; the trailing whitespace stays harmlessly.
        let q = "(code_span) @markup.raw @nospell";
        let out = strip_meta_captures(q).unwrap();
        assert!(out.contains("@markup.raw"));
        assert!(!out.contains("nospell"));

        // @conceal inside an alternation pattern is dropped, and the
        // literal-only #set! clause that sits next to it survives.
        let q = "([ (code_span_delimiter) (emphasis_delimiter) ] @conceal (#set! conceal \"\"))";
        let out = strip_meta_captures(q).unwrap();
        assert!(!out.contains("@conceal"));
        assert!(out.contains("(#set! conceal \"\")"));
        assert!(out.contains("code_span_delimiter"));

        // Real capture names fully separate from the meta ones are kept.
        let q2 = "(x @keyword.spellcheck @nospell_extra @conceal.x)";
        assert!(strip_meta_captures(q2).is_none());

        // Queries without spell captures pass through unchanged.
        let q3 = "(file) @string.raw";
        assert!(strip_meta_captures(q3).is_none());
    }

    #[test]
    fn strip_meta_captures_resolves_dangling_predicate_args() {
        // `#eq?` references the now-dropped `@conceal`, so the whole clause
        // must go; the literal-only `(#set! conceal "X")` survives as a no-op.
        let q = "((escape_sequence) @conceal (#eq? @conceal \"x\") (#set! conceal \"X\"))";
        let out = strip_meta_captures(q).unwrap();
        assert!(!out.contains("@conceal"));
        assert!(!out.contains("#eq?"));
        assert!(out.contains("(#set! conceal \"X\")"));
        assert!(out.contains("escape_sequence"));

        // Predicates whose capture args are real (non-meta) captures are kept.
        let q2 = "((word) @x (#eq? @x \"trap\") (#set! priority 90))";
        assert!(strip_meta_captures(q2).is_none());

        // Anonymous captures used by #offset!/#lua-match? are untouched.
        let q3 = "((uri_autolink) @_url (#offset! @_url 0 1 0 -1))";
        assert!(strip_meta_captures(q3).is_none());
    }

    #[test]
    fn normalize_markdown_injections_adds_include_children() {
        let inj = "([\n  (inline)\n  (pipe_table_cell)\n] @injection.content\n\
                   (#set! injection.language \"markdown_inline\"))\n\
                   (fenced_code_block\n  (code_fence_content) @injection.content\n\
                   (info_string (language) @injection.language))";
        let out = normalize_markdown_injections(inj).unwrap();
        // include-children added to the markdown_inline rule only.
        assert!(out.contains("(#set! injection.include-children)"));
        // The language set and the fence rule survive untouched.
        assert!(out.contains("#set! injection.language \"markdown_inline\""));
        assert!(out.contains("(info_string (language) @injection.language)"));
        assert!(out.contains("(code_fence_content) @injection.content"));
        // The fence rule must get its own include-children, otherwise the
        // block grammar's marker children collapse the injected ranges.
        let fence_idx = out.find("fenced_code_block").unwrap();
        assert!(out[fence_idx..].contains("include-children"));

        // Queries without markdown_inline or fenced code pass through unchanged.
        let other = "((code) @injection.content (#set! injection.language \"bash\"))";
        assert!(normalize_markdown_injections(other).is_none());
    }

    #[test]
    fn theme_styles_common_captures() {
        let base = Style::default();
        assert_eq!(
            style_for_capture("keyword.conditional"),
            base.fg(Color::Magenta).add_modifier(Modifier::BOLD)
        );
        assert_eq!(
            style_for_capture("string.regexp"),
            base.fg(Color::LightGreen)
        );
        assert_eq!(
            style_for_capture("markup.heading"),
            base.fg(Color::LightYellow).add_modifier(Modifier::BOLD)
        );
        assert_eq!(
            style_for_capture("markup.strong"),
            base.add_modifier(Modifier::BOLD)
        );
        assert_eq!(style_for_capture("comment"), base.fg(Color::DarkGray));
        // surroundings / unknown stay plain
        assert_eq!(style_for_capture("variable"), base);
        assert_eq!(style_for_capture("markup.list"), base);
    }

    #[test]
    fn inline_delimiters_extracts_symmetric_marker_runs() {
        // Formed inline spans: strong via `**`, emphasis via `*`/`_`,
        // strikethrough via `~~`, code via equal backtick runs.
        assert_eq!(inline_delimiters("markup.strong", "**bold**"), Some((2, 2)));
        assert_eq!(inline_delimiters("markup.strong", "__bold__"), Some((2, 2)));
        assert_eq!(inline_delimiters("markup.italic", "*it*"), Some((1, 1)));
        assert_eq!(inline_delimiters("markup.italic", "_it_"), Some((1, 1)));
        assert_eq!(
            inline_delimiters("markup.strikethrough", "~~gone~~"),
            Some((2, 2))
        );
        assert_eq!(inline_delimiters("markup.raw", "`code`"), Some((1, 1)));
        assert_eq!(inline_delimiters("markup.raw", "``c``"), Some((2, 2)));
        // Triple-marker nesting: the outer strong span strips 3+3.
        assert_eq!(
            inline_delimiters("markup.strong", "***both***"),
            Some((3, 3))
        );
        // Inner backticks inside a code span survive (only the framing runs).
        assert_eq!(inline_delimiters("markup.raw", "``a`b``"), Some((2, 2)));

        // Code spans require equal runs.
        assert_eq!(inline_delimiters("markup.raw", "`x``"), None);
        // Spans that merely carry the name but are not delimited are safe.
        assert_eq!(inline_delimiters("markup.raw", "lorem"), None);
        assert_eq!(inline_delimiters("markup.strong", "plain text"), None);
        // Fence content is never stripped: it is `markup.raw.block`, which
        // is not an inline-conceal name (checked by the caller), and even if
        // it were, its text has no symmetric backtick framing.
        assert_eq!(inline_delimiters("markup.raw.block", "```bash"), None);
    }

    #[test]
    fn merge_conceal_clamps_merges_and_spares_fence_content() {
        // Overlapping/duplicate ranges (nested spans) collapse.
        let mut conceal = vec![(7, 10), (0, 2), (1, 3), (7, 9)];
        merge_conceal(&mut conceal, &[], 20);
        assert_eq!(conceal, vec![(0, 3), (7, 10)]);

        // Ranges are clamped to the text length (the parse sees an appended
        // newline; the message itself may be shorter).
        let mut conceal = vec![(3, 9)];
        merge_conceal(&mut conceal, &[], 5);
        assert_eq!(conceal, vec![(3, 5)]);

        let mut conceal = vec![(4, 6), (2, 4)];
        merge_conceal(&mut conceal, &[], 10);
        assert_eq!(conceal, vec![(2, 6)], "adjacent ranges merge");

        // Ranges inside fenced-code content are dropped: code renders verbatim.
        let mut conceal = vec![(5, 6), (10, 12)];
        merge_conceal(&mut conceal, &[(4, 8)], 20);
        assert_eq!(conceal, vec![(10, 12)]);

        // An empty conceal stays empty (plain messages).
        let mut conceal = Vec::new();
        merge_conceal(&mut conceal, &[(0, 4)], 10);
        assert!(conceal.is_empty());
    }

    #[test]
    fn atx_marker_kinds_cover_all_heading_levels() {
        assert!(is_atx_marker("atx_h1_marker"));
        assert!(is_atx_marker("atx_h6_marker"));
        assert!(!is_atx_marker("setext_h1_underline"));
        assert!(!is_atx_marker("fenced_code_block_delimiter"));
        assert!(
            !is_atx_marker("atx_h7_marker"),
            "markdown has only levels 1-6"
        );
    }
}
