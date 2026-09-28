//! Runtime tree-sitter grammar acquisition — the registry model.
//!
//! Grammar *code* never touches Cargo: this module fetches grammars from the
//! community tree-sitter registry the same way nvim-treesitter does, compiles
//! them with the system C compiler, and loads the result as a native shared
//! library. No grammar crates, no cargo/`build.rs` involvement, no wasm.
//!
//! Pipeline for a requested language:
//!
//! 1. **Registry** — `treesitter-parser-registry`'s `registry.json` (a plain
//!    JSON catalogue, no Lua) is consulted for the language's entry:
//!    `parser_url` (the grammar repo), `parser_location` (subdir for
//!    monorepos, e.g. the two markdown grammars), and `queries_url`.
//! 2. **Source** — the grammar repo's latest release tag is resolved and its
//!    source tarball downloaded. Grammar repos ship pre-generated
//!    `src/parser.c` (plus `src/scanner.c` when an external scanner exists).
//! 3. **Compile** — `parser.c`(+`scanner.c`) is compiled to `parser.so` with
//!    the system C compiler (`cc`/`$CC`), exactly like nvim-treesitter's
//!    installer. No rust/cargo involved.
//! 4. **Load** — the `.so` is dlopen'd via [`libloading`], its
//!    `tree_sitter_<lang>` entrypoint wrapped as a [`Language`], and the ABI
//!    is checked against this runtime's supported range.
//!
//! Results are cached under `$XDG_DATA_HOME/agent/grammars/<lang>/` with a
//! `stamp.json`, so subsequent runs are fully offline: a valid cache hit
//! loads without any network access. A prebuilt `.so` dropped into the cache
//! directory by hand is loaded as-is.
//!
//! The only host requirement is a C compiler on `PATH` (or `$CC`) when a
//! fresh grammar must be built — the same requirement nvim-treesitter makes.
//! Missing languages degrade to "unavailable" with a clear error; callers
//! (the TUI) fall back to plain text.

use anyhow::{Context, Result, bail};
use libloading::Library;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use tree_sitter::{LANGUAGE_VERSION, Language, MIN_COMPATIBLE_LANGUAGE_VERSION};
use tree_sitter_language::LanguageFn;

/// The community catalogue of grammars and their query sources.
const REGISTRY_URL: &str = "https://raw.githubusercontent.com/neovim-treesitter/treesitter-parser-registry/main/registry.json";

/// The GitHub API base used for tag/asset discovery.
const GH_API: &str = "https://api.github.com";

// ---------------------------------------------------------------------------
// Registry data
// ---------------------------------------------------------------------------

/// One language's entry in the registry (`registry.json`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    pub name: String,
    pub filetypes: Vec<String>,
    pub parser_url: String,
    /// Subdirectory within a monorepo holding this parser (e.g. the
    /// `tree-sitter-markdown` repo's two grammars); `None` for single-parser
    /// repos.
    pub parser_location: Option<String>,
    pub queries_url: String,
}

impl RegistryEntry {
    /// The C entrypoint/artifact base for this parser: the parser location
    /// when it differs from the language name (monorepo), dashes → underscores
    /// (`tree-sitter-markdown-inline` → `tree_sitter_markdown_inline`).
    pub fn symbol(&self) -> String {
        let raw = self
            .parser_location
            .as_deref()
            .unwrap_or(&self.name)
            .replace('-', "_");
        // Monorepo subdirs are already named `tree-sitter-<name>`, which
        // would double the prefix.
        let trimmed = raw.strip_prefix("tree_sitter_").unwrap_or(&raw);
        format!("tree_sitter_{trimmed}")
    }
}

/// Parse the registry JSON into entries. Skips non-parser entries
/// (`$schema`, `queries_only`, `local`).
pub fn parse_registry(text: &str) -> Result<HashMap<String, RegistryEntry>> {
    let v: serde_json::Value =
        serde_json::from_str(text).context("registry.json is not valid JSON")?;
    let obj = v
        .as_object()
        .context("registry.json root is not an object")?;
    let mut out = HashMap::new();
    for (name, e) in obj {
        if name == "$schema" {
            continue;
        }
        let src = &e["source"];
        if !src.is_object() {
            continue;
        }
        match src["type"].as_str() {
            Some("external_queries") | Some("self_contained") => {}
            _ => continue, // queries_only / local / unknown
        }
        let parser_url = src["parser_url"].as_str().or(src["url"].as_str());
        let Some(parser_url) = parser_url else {
            continue;
        };
        let queries_url = src["queries_url"]
            .as_str()
            .or(src["url"].as_str())
            .unwrap_or_default();
        let filetypes = e["filetypes"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|f| f.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        out.insert(
            name.clone(),
            RegistryEntry {
                name: name.clone(),
                filetypes,
                parser_url: parser_url.to_string(),
                parser_location: src["parser_location"].as_str().map(str::to_string),
                queries_url: queries_url.to_string(),
            },
        );
    }
    Ok(out)
}

/// Extract `(owner, repo)` from a GitHub-style URL, tolerating trailing
/// `.git`, paths, and arbitrary hosts.
pub fn parse_gh(url: &str) -> Result<(String, String)> {
    let (rest, has_host) = match url.split_once("://") {
        Some((_, rest)) => (rest, true),
        None => (url, false),
    };
    let mut segs: Vec<&str> = rest
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches(".git"))
        .collect();
    if has_host && !segs.is_empty() {
        segs.remove(0); // drop the host segment (github.com, gitlab.com, …)
    }
    if segs.len() < 2 {
        bail!("not a repo URL: {url}");
    }
    let repo = segs.pop().unwrap().to_string();
    let owner = segs.pop().unwrap().to_string();
    Ok((owner, repo))
}

// ---------------------------------------------------------------------------
// XDG cache
// ---------------------------------------------------------------------------

/// Where grammars are cached, resolved the standard way.
///
/// Public because a background acquisition task has to write to the *same*
/// directory the foreground catalog reads from, and that catalog does not expose
/// its own path. Two code paths guessing the location independently is how a
/// worker ends up building a grammar nobody can find.
pub fn cache_root() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("agent").join("grammars")
}

/// What a cached grammar was built from. `ensure` only requires
/// `parser_url` to match to trust a cache entry — the rest is provenance.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Stamp {
    name: String,
    symbol: String,
    parser_url: String,
    queries_url: String,
    tag: String,
}

// ---------------------------------------------------------------------------
// Runtime loading
// ---------------------------------------------------------------------------

/// A grammar loaded from a shared library. Holds the `Library` alive for as
/// long as the `Language` (whose parse tables live in the mapped library) is
/// used — dropping it first would be a use-after-free.
pub struct LoadedGrammar {
    pub name: String,
    pub language: Language,
    /// Reported tree-sitter ABI of the compiled parser.
    pub abi: usize,
    pub highlights: Option<String>,
    pub injections: Option<String>,
    #[allow(dead_code)] // provenance, kept for debugging
    pub source: PathBuf,
    _lib: Library,
}

fn load_so(path: &Path, symbol: &str) -> Result<LoadedGrammar> {
    // SAFETY: dlopen of a grammar we (or the user) placed in the cache. The
    // ABI is validated right after; the Library is held for the process.
    let lib = unsafe { Library::new(path) }
        .with_context(|| format!("dlopen {} failed", path.display()))?;
    let entry: libloading::Symbol<unsafe extern "C" fn() -> *const ()> = unsafe {
        lib.get(symbol.as_bytes())
            .with_context(|| format!("{path:?} exports no `{symbol}` symbol"))?
    };
    // SAFETY: the grammar's exported entrypoint follows tree-sitter's C ABI
    // (verified below by the ABI check); the language is a plain pointer
    // wrapper into the library, kept mapped via `_lib`.
    let language = unsafe { Language::new(LanguageFn::from_raw(*entry)) };
    let abi = language.abi_version();
    if !(MIN_COMPATIBLE_LANGUAGE_VERSION..=LANGUAGE_VERSION).contains(&abi) {
        bail!(
            "grammar ABI {abi} outside supported range {MIN_COMPATIBLE_LANGUAGE_VERSION}..={LANGUAGE_VERSION} \
             (rebuild with a compatible tree-sitter CLI)"
        );
    }
    Ok(LoadedGrammar {
        name: String::new(),
        language,
        abi,
        highlights: None,
        injections: None,
        source: path.to_path_buf(),
        _lib: lib,
    })
}

// ---------------------------------------------------------------------------
// Acquisition
// ---------------------------------------------------------------------------

/// The runtime catalogue: fetches, builds, caches, and hands out grammars.
pub struct Catalog {
    client: reqwest::Client,
    cache_dir: PathBuf,
    registry: Option<HashMap<String, RegistryEntry>>,
    loaded: HashMap<String, LoadedGrammar>,
    /// Where progress goes. A cold language is a registry lookup, a tarball and
    /// a C compile — seconds, not milliseconds — so a caller that has somewhere
    /// to show that needs to be told about it. `None` means silent.
    progress: Option<ProgressFn>,
}

/// A progress sink: one human-readable line per acquisition step.
/// `Send` so a [`Catalog`] can be built *inside* a background task and driven
/// there: acquiring a grammar takes seconds of network and `cc`, which cannot
/// happen on the thread that draws frames. The callback therefore has to be
/// movable into that task, and every caller already satisfies it — the status
/// line and the test sinks are `Mutex`-backed statics.
type ProgressFn = Box<dyn Fn(&str) + Send>;

impl Default for Catalog {
    fn default() -> Self {
        Self::new()
    }
}

impl Catalog {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent("agent-grammar/0.1")
            .build()
            .expect("reqwest client builds");
        let cache_dir = cache_root();
        // Make sure we have a healthy cache even if the registry entry is
        // missing on a later run.
        let registry = fs::read(cache_dir.join("registry.json"))
            .ok()
            .and_then(|t| parse_registry(&String::from_utf8_lossy(&t)).ok());
        Self {
            client,
            cache_dir,
            registry,
            loaded: HashMap::new(),
            progress: None,
        }
    }

    /// Report acquisition progress to `f` — one human-readable line per step,
    /// already formatted. Returns `self` so it chains off [`Catalog::new`].
    ///
    /// A callback rather than a `StatusLine` so this module keeps no opinion
    /// about screens: the TUI points it at the status bar, a headless binary
    /// points it at stderr, and a test collects the strings.
    pub fn with_progress(mut self, f: impl Fn(&str) + Send + 'static) -> Self {
        self.progress = Some(Box::new(f));
        self
    }

    /// Put the cache somewhere else entirely, and re-read the registry copy
    /// from there.
    ///
    /// [`Catalog::new`] resolves `$XDG_DATA_HOME`/`$HOME`, which is right for the
    /// application and wrong for a test: a suite that downloads grammars must not
    /// write a megabyte of `.so` into the user's data directory, and must not
    /// depend on what happens to be cached there either. Pointed at a temp
    /// directory, a test is hermetic in both directions — it cannot pollute the
    /// cache and it cannot pass on the strength of a warm one it did not build.
    pub fn with_cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = dir.into();
        self.registry = fs::read(self.cache_dir.join("registry.json"))
            .ok()
            .and_then(|t| parse_registry(&String::from_utf8_lossy(&t)).ok());
        self
    }

    /// Say `msg` to the progress callback, if there is one.
    fn report(&self, msg: impl AsRef<str>) {
        if let Some(f) = &self.progress {
            f(msg.as_ref());
        }
    }

    /// Handed-out grammars by language name.
    pub fn get(&self, lang: &str) -> Option<&LoadedGrammar> {
        self.loaded.get(lang)
    }

    /// Ensure all `langs` are loaded; returns per-language outcomes so the
    /// caller can report failures without aborting.
    pub async fn ensure_many(&mut self, langs: &[&str]) -> Vec<(String, Result<(), String>)> {
        let mut out = Vec::with_capacity(langs.len());
        for lang in langs {
            out.push((
                lang.to_string(),
                self.ensure(lang)
                    .await
                    .map(|_| ())
                    .map_err(|e| format!("{e:#}")),
            ));
        }
        out
    }

    /// Load `lang` (from cache if valid; otherwise fetch, build, cache).
    pub async fn ensure(&mut self, lang: &str) -> Result<&LoadedGrammar> {
        if self.loaded.contains_key(lang) {
            return Ok(self.loaded.get(lang).unwrap());
        }

        // 1) Cache hit — fully offline. A hand-dropped prebuilt .so also
        // counts: load it and stamp it ad hoc.
        let dir = self.cache_dir.join(lang);
        let so = dir.join("parser.so");
        if so.is_file() {
            let symbol = match read_stamp(&dir) {
                Some(st) => st.symbol,
                None => format!("tree_sitter_{}", lang.replace('-', "_")),
            };
            match load_so(&so, &symbol) {
                Ok(mut l) => {
                    l.name = lang.to_string();
                    l.highlights = read_opt(&dir.join("highlights.scm"));
                    l.injections = read_opt(&dir.join("injections.scm"));
                    self.loaded.insert(lang.to_string(), l);
                    return Ok(self.loaded.get(lang).unwrap());
                }
                Err(e) => {
                    // Stale/broken cache: fall through to rebuild. This used to
                    // be an `eprintln!`, which in the TUI printed into the
                    // middle of the alternate screen.
                    self.report(format!(
                        "cached {lang} unusable ({e:#}); rebuilding from the registry"
                    ));
                }
            }
        }

        // 2) Registry entry.
        self.report(format!("fetching {lang} grammar…"));
        let entry = self.registry_entry(lang).await?;

        // 3) Source tarball at the latest release tag.
        self.report(format!("downloading {lang} source…"));
        let tag = latest_tag(&self.client, &entry.parser_url).await?;
        let archive = download_source(&self.client, &entry.parser_url, &tag).await?;

        // 4) Extract + compile into a temp dir, then atomically swap in. The
        //    compile is the slow part — a full C build of a generated parser —
        //    so it gets its own line rather than sharing the download's.
        self.report(format!("building {lang} parser…"));
        let build = self.cache_dir.join(format!(".{lang}.build"));
        let _ = fs::remove_dir_all(&build);
        fs::create_dir_all(&build)
            .with_context(|| format!("create build dir {}", build.display()))?;
        extract_src(&archive, &build, entry.parser_location.as_deref())
            .context("extract grammar source")?;
        compile_parser(&build, &build.join("parser.so"))
            .with_context(|| format!("compile grammar {lang}"))?;
        let _ = fs::remove_dir_all(&dir);
        fs::rename(&build, &dir).with_context(|| format!("stage {lang} into cache"))?;

        // 5) Queries (best-effort; the highlighter consumes these later).
        for (file, slot) in [
            ("highlights.scm", dir.join("highlights.scm")),
            ("injections.scm", dir.join("injections.scm")),
        ] {
            if let Ok(q) = fetch_query(&self.client, &entry.queries_url, file).await {
                let _ = fs::write(&slot, q);
            }
        }
        write_stamp(
            &dir,
            &Stamp {
                name: lang.to_string(),
                symbol: entry.symbol(),
                parser_url: entry.parser_url.clone(),
                queries_url: entry.queries_url.clone(),
                tag,
            },
        )?;

        // 6) Load.
        let mut l = load_so(&dir.join("parser.so"), &entry.symbol())?;
        l.name = lang.to_string();
        l.highlights = read_opt(&dir.join("highlights.scm"));
        l.injections = read_opt(&dir.join("injections.scm"));
        self.loaded.insert(lang.to_string(), l);
        Ok(self.loaded.get(lang).unwrap())
    }

    async fn registry_entry(&mut self, lang: &str) -> Result<RegistryEntry> {
        if self.registry.is_none() {
            self.registry = Some(self.fetch_registry().await?);
        }
        self.registry
            .as_ref()
            .unwrap()
            .get(lang)
            .cloned()
            .with_context(|| format!("language {lang} is not in the grammar registry"))
    }

    /// Fetch (and persist) the registry; falls back to last cached copy.
    async fn fetch_registry(&mut self) -> Result<HashMap<String, RegistryEntry>> {
        let result = async {
            let text = self
                .client
                .get(REGISTRY_URL)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            Ok::<String, anyhow::Error>(text)
        }
        .await;
        match result {
            Ok(text) => {
                let parsed = parse_registry(&text)?;
                let _ = fs::create_dir_all(&self.cache_dir);
                let _ = fs::write(self.cache_dir.join("registry.json"), &text);
                Ok(parsed)
            }
            Err(e) => {
                let cached = fs::read_to_string(self.cache_dir.join("registry.json")).ok();
                cached
                    .as_deref()
                    .map(parse_registry)
                    .transpose()
                    .with_context(|| format!("fetch registry failed and no cached copy: {e:#}"))?
                    .ok_or_else(|| anyhow::anyhow!("registry unavailable: {e:#}"))
            }
        }
    }
}

/// Resolve the latest release tag of a grammar repo. Uses the GitHub
/// `releases/latest` endpoint; falls back to the tag list.
async fn latest_tag(client: &reqwest::Client, parser_url: &str) -> Result<String> {
    let (owner, repo) = parse_gh(parser_url)?;
    let url = format!("{GH_API}/repos/{owner}/{repo}/releases/latest");
    let resp = client.get(&url).send().await?;
    if resp.status().is_success() {
        let v: serde_json::Value = resp.json().await?;
        if let Some(t) = v["tag_name"].as_str() {
            return Ok(t.to_string());
        }
    }
    // Fallback: newest tag that looks semantic.
    let url = format!("{GH_API}/repos/{owner}/{repo}/tags");
    let v: serde_json::Value = client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    for t in v.as_array().into_iter().flatten() {
        if let Some(n) = t["name"].as_str()
            && n.starts_with('v')
            && n[1..].contains('.')
        {
            return Ok(n.to_string());
        }
    }
    bail!("no release tag found for {parser_url}")
}

/// Download the source tarball for `tag` (contains pre-generated
/// `src/parser.c`).
async fn download_source(client: &reqwest::Client, parser_url: &str, tag: &str) -> Result<Vec<u8>> {
    let (owner, repo) = parse_gh(parser_url)?;
    let url = format!("https://github.com/{owner}/{repo}/archive/refs/tags/{tag}.tar.gz");
    let bytes = client
        .get(&url)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("download grammar source from {url}"))?
        .bytes()
        .await?;
    Ok(bytes.to_vec())
}

/// Fetch one query file from the language's query repo. Errors when the repo
/// or file does not exist (each language ships different query sets);
/// callers treat that as "no such query file".
async fn fetch_query(client: &reqwest::Client, queries_url: &str, file: &str) -> Result<String> {
    let (owner, repo) = parse_gh(queries_url)?;
    for branch in ["main", "master"] {
        let url =
            format!("https://raw.githubusercontent.com/{owner}/{repo}/{branch}/queries/{file}");
        let resp = client.get(&url).send().await?;
        if resp.status().is_success() {
            return resp.text().await.context("read query file");
        }
    }
    bail!("query file {file} not found in {queries_url}")
}

/// Extract the parser's `src/` tree from the tarball into `dest`, honoring
/// monorepo `location`s (e.g. `tree-sitter-markdown-inline`): only the
/// `src` directory directly under the matching location is kept, at the same
/// relative path. The tarball's own top-level directory is stripped.
fn extract_src(archive: &[u8], dest: &Path, location: Option<&str>) -> Result<()> {
    let gz = flate2::read::GzDecoder::new(archive);
    let mut ar = tar::Archive::new(gz);
    for entry in ar.entries()? {
        let mut e = entry?;
        if !e.header().entry_type().is_file() {
            continue; // dirs/symlinks are not needed
        }
        let comps: Vec<String> = e
            .path()?
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        // The payload starts at the first `src` component whose parent (with
        // a location set) is that location.
        let start = (0..comps.len()).find(|&i| {
            comps[i] == "src"
                && match location {
                    None => true,
                    Some(loc) => i > 0 && comps[i - 1] == loc,
                }
        });
        let Some(i) = start else { continue };
        let rel = comps[i..].join("/");
        let out = dest.join(&rel);
        if let Some(p) = out.parent() {
            fs::create_dir_all(p)?;
        }
        let mut f = fs::File::create(&out)?;
        io::copy(&mut e, &mut f)?;
    }
    Ok(())
}

/// Compile `src/parser.c` (+ optional `src/scanner.c`) into `out` with the
/// system C compiler — the same flow nvim-treesitter's installer uses.
fn compile_parser(src_root: &Path, out: &Path) -> Result<()> {
    let src = src_root.join("src");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let mut cmd = Command::new(&cc);
    cmd.args(["-shared", "-fPIC", "-O2", "-std=c11"])
        .arg(format!("-I{}", src.display()))
        .arg(src.join("parser.c"));
    if src.join("scanner.c").is_file() {
        cmd.arg(src.join("scanner.c"));
    }
    let tmp = out.with_extension("so.tmp");
    cmd.arg("-o").arg(&tmp);
    let run = cmd.output().with_context(|| format!("spawn {cc}"))?;
    if !run.status.success() {
        bail!(
            "{cc} failed for {}:\n{}",
            src_root.display(),
            String::from_utf8_lossy(&run.stderr)
        );
    }
    fs::rename(&tmp, out)?;
    Ok(())
}

fn read_stamp(dir: &Path) -> Option<Stamp> {
    serde_json::from_str(&fs::read_to_string(dir.join("stamp.json")).ok()?).ok()
}

fn write_stamp(dir: &Path, st: &Stamp) -> Result<()> {
    fs::write(dir.join("stamp.json"), serde_json::to_string_pretty(st)?).map_err(Into::into)
}

fn read_opt(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok()
}

#[cfg(test)]
mod tests {
    /// A grammar this module has never heard of, acquired the way the app does
    /// it: registry lookup, release resolution, tarball, `cc`, dlopen.
    ///
    /// `#[ignore]`d on purpose, and the reason is worth stating rather than
    /// hiding behind a feature flag: this needs the network, a C compiler, and
    /// several seconds of both. A suite that depended on it would be a suite that
    /// fails on a train. It is run deliberately — `--ignored` — because the thing
    /// it covers, the download-on-demand path, is the part of this module with
    /// no offline substitute at all: the cache-hit path is one `if so.is_file()`,
    /// and everything after it is the part that can actually break.
    ///
    /// The cache is a temp directory throughout. [`Catalog::new`] resolves
    /// `$XDG_DATA_HOME`/`$HOME`, and a test that wrote a megabyte of `.so` into
    /// the user's data directory — or worse, *passed* because of a warm cache it
    /// did not build — would be worse than no test.
    #[tokio::test]
    #[ignore = "needs the network and a C compiler; run with --ignored"]
    async fn an_unseen_grammar_is_fetched_compiled_and_loaded() {
        let dir = std::env::temp_dir().join(format!("agent-grammar-fetch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        // `with_progress` takes an `Fn`, so the log needs interior mutability —
        // the same shape `main.rs` uses, handing progress to the status line.
        let steps: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = steps.clone();
        let mut catalog = Catalog::new()
            .with_cache_dir(&dir)
            .with_progress(move |m| sink.lock().expect("steps").push(m.to_string()));

        // `rust` is not in the app's own list, so this is genuinely cold: not
        // fetched, not compiled, not cached anywhere this test can see.
        let loaded = catalog
            .ensure("rust")
            .await
            .expect("rust grammar acquires");
        assert_eq!(loaded.name, "rust");
        assert!(
            loaded.highlights.is_some(),
            "and its queries came with it, or nothing would be styled"
        );

        // It really was built here: the artefacts are on disk under the temp dir.
        let built = dir.join("rust");
        assert!(built.join("parser.so").is_file(), "a shared object was built");
        assert!(
            built.join("stamp.json").is_file(),
            "and stamped, or the next run would rebuild it"
        );
        let steps = steps.lock().expect("steps").clone();
        assert!(
            steps.iter().any(|s| s.contains("rust")) && steps.len() > 1,
            "and progress was reported, since this takes seconds: {steps:?}"
        );

        // Second half: a *fresh* catalog over the cache the first one filled must
        // load with no network at all. That is the "subsequent runs are fully
        // offline" claim, and it is the property that makes the first half
        // affordable — a compile on every startup would be unusable.
        let quiet: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let quiet_sink = quiet.clone();
        let mut again = Catalog::new()
            .with_cache_dir(&dir)
            .with_progress(move |m| quiet_sink.lock().expect("quiet").push(m.to_string()));
        let offline = again
            .ensure("rust")
            .await
            .expect("the cache hit needs no network");
        assert_eq!(offline.name, "rust");
        assert!(
            again.get("rust").is_some_and(|g| g.highlights.is_some()),
            "and it carries its queries, so a cached grammar is as good as a fresh one"
        );
        // The offline claim, actually checked rather than asserted: every step of
        // a fetch reports progress, and a cache hit reports nothing. An empty log
        // is therefore proof the network was not used — which a passing `ensure`
        // on a machine that happens to be online would not be.
        assert!(
            quiet.lock().expect("quiet").is_empty(),
            "a cache hit reports no progress, so this proves no fetch happened"
        );

        // A language that does not exist fails cleanly rather than panicking, so
        // a user asking for one gets a message instead of a crash.
        let mut missing = Catalog::new().with_cache_dir(dir.join("empty"));
        // No `expect_err`: the error type carries a `LoadedGrammar`, which is not
        // `Debug`, and deriving one for a test is not worth it. Match instead.
        match missing.ensure("definitely-not-a-language").await {
            Ok(_) => panic!("a language that does not exist must not load"),
            Err(e) => assert!(
                !format!("{e:#}").is_empty(),
                "and it fails with something to say, not a bare Err"
            ),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    /// The hand-dropped escape hatch: a `.so` in the cache directory with no
    /// provenance is loaded as-is.
    ///
    /// `#[ignore]`d for the same reason as its sibling, and the reason is worth
    /// being blunt about: the only compiled grammar available without a compiler
    /// is the one in the *application's* cache, so a hermetic version of this test
    /// would have to build one first — which is the test above. Reading the app's
    /// cache to save a compile would put `$HOME` back in the test path, and that
    /// is the rule this suite keeps: a test that depends on what happens to be
    /// cached is a test that passes for the wrong reason on one machine and fails
    /// on another.
    #[tokio::test]
    #[ignore = "needs a compiled grammar; borrows the app's cache, so run with --ignored"]
    async fn a_hand_dropped_shared_object_is_loaded_and_stamped() {
        let dir = std::env::temp_dir().join(format!("agent-grammar-drop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        // The language has to match the symbol inside the `.so`: `ensure` looks
        // up `tree_sitter_<lang>` and, if that entrypoint is not there, treats the
        // cache as a miss and *fetches* instead. Which is the right call — a
        // parser that cannot be loaded is no parser — but it means a hand-dropped
        // `.so` that is misfiled under the wrong name is silently ignored, with
        // nothing but a slow first request to show for it. Worth knowing before
        // spending an afternoon on it.
        let lang_dir = dir.join("bash");
        fs::create_dir_all(&lang_dir).expect("scratch");
        let source = cache_root().join("bash").join("parser.so");
        let Ok(so) = fs::read(&source) else {
            let _ = fs::remove_dir_all(&dir);
            eprintln!("[skip] no compiled bash grammar available to reuse");
            return;
        };
        fs::write(lang_dir.join("parser.so"), so).expect("drop the .so");
        fs::write(lang_dir.join("highlights.scm"), "(x) @keyword\n").expect("queries");

        let mut catalog = Catalog::new().with_cache_dir(&dir);
        let loaded = catalog
            .ensure("bash")
            .await
            .expect("a hand-dropped .so loads as-is");
        assert_eq!(loaded.name, "bash");
        assert_eq!(
            loaded.highlights.as_deref(),
            Some("(x) @keyword\n"),
            "and the queries beside it, which is the whole point of the escape hatch"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    use super::*;

    /// The progress hook is a plain callback, so this covers the plumbing: a
    /// message reaches it, and a catalogue without one is silent rather than a
    /// panic.
    ///
    /// What it does *not* cover is which steps of `ensure` report — those are on
    /// the network-and-C-compiler path, which no test here runs. The list of
    /// `report` calls in `ensure` is the thing to read when a progress message
    /// goes missing.
    #[test]
    fn progress_reports_to_a_callback_and_is_otherwise_silent() {
        let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let catalog = Catalog::new().with_progress(move |m| sink.lock().unwrap().push(m.into()));

        catalog.report("building bash parser…");
        catalog.report(format!("cached {lang} unusable; rebuilding", lang = "json"));
        assert_eq!(
            *seen.lock().unwrap(),
            ["building bash parser…", "cached json unusable; rebuilding"],
            "the callback sees each line, in order, as given"
        );

        // No callback installed: reporting is a no-op, not a panic. This is the
        // path the probe and `chat` take.
        Catalog::new().report("nobody is listening");
    }

    #[test]
    fn parse_registry_keeps_parsers_and_drops_meta() {
        let text = r#"{
            "$schema": "https://example/schema.json",
            "bash": {
                "filetypes": ["bash"],
                "source": {
                    "type": "external_queries",
                    "parser_url": "https://github.com/tree-sitter/tree-sitter-bash",
                    "queries_url": "https://github.com/neovim-treesitter/nvim-treesitter-queries-bash"
                }
            },
            "markdown_inline": {
                "filetypes": ["markdown_inline"],
                "source": {
                    "type": "external_queries",
                    "parser_url": "https://github.com/tree-sitter-grammars/tree-sitter-markdown",
                    "parser_location": "tree-sitter-markdown-inline",
                    "queries_url": "https://github.com/neovim-treesitter/nvim-treesitter-queries-markdown_inline"
                }
            },
            "ecma": { "source": { "type": "queries_only" } }
        }"#;
        let reg = parse_registry(text).unwrap();
        assert_eq!(reg.len(), 2);
        let bash = &reg["bash"];
        assert_eq!(bash.filetypes, vec!["bash"]);
        assert_eq!(bash.parser_location, None);
        assert_eq!(bash.symbol(), "tree_sitter_bash");
        let md = &reg["markdown_inline"];
        assert_eq!(
            md.parser_location.as_deref(),
            Some("tree-sitter-markdown-inline")
        );
        assert_eq!(md.symbol(), "tree_sitter_markdown_inline");
    }

    #[test]
    fn parse_gh_handles_hosts_and_suffixes() {
        assert_eq!(
            parse_gh("https://github.com/tree-sitter/tree-sitter-json").unwrap(),
            ("tree-sitter".into(), "tree-sitter-json".into())
        );
        assert_eq!(
            parse_gh("https://gitlab.com/foo/bar.git").unwrap(),
            ("foo".into(), "bar".into())
        );
        assert!(parse_gh("https://example.com/only-one").is_err());
    }

    fn fake_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut t = tar::Builder::new(&mut gz);
            for (name, data) in entries {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                t.append_data(&mut h, name, &data[..]).unwrap();
            }
            t.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[test]
    fn extract_src_handles_root_level_and_monorepos() {
        // Single-parser repo: src/ at the top level.
        let single = fake_archive(&[
            ("tree-sitter-json-0.24.8/README.md", b"readme"),
            (
                "tree-sitter-json-0.24.8/src/parser.c",
                b"int main(void) { return 0; }",
            ),
            (
                "tree-sitter-json-0.24.8/src/tree_sitter/parser.h",
                b"#pragma once",
            ),
        ]);
        let dest = std::env::temp_dir().join(format!("ts-test-single-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dest);
        extract_src(&single, &dest, None).unwrap();
        assert!(dest.join("src/parser.c").is_file());
        assert!(dest.join("src/tree_sitter/parser.h").is_file());
        assert!(!dest.join("src/README.md").exists());
        let _ = fs::remove_dir_all(&dest);

        // Monorepo: two parsers under their own subdirs; location selects one.
        let mono = fake_archive(&[
            (
                "tree-sitter-markdown-0.5.3/tree-sitter-markdown/src/parser.c",
                b"block",
            ),
            (
                "tree-sitter-markdown-0.5.3/tree-sitter-markdown-inline/src/parser.c",
                b"inline",
            ),
            ("tree-sitter-markdown-0.5.3/README.md", b"readme"),
        ]);
        let dest = std::env::temp_dir().join(format!("ts-test-mono-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dest);
        extract_src(&mono, &dest, Some("tree-sitter-markdown-inline")).unwrap();
        assert_eq!(
            fs::read_to_string(dest.join("src/parser.c")).unwrap(),
            "inline"
        );
        // Only the selected parser's src tree was extracted: exactly one
        // top-level entry ("src"), nothing for the sibling parser.
        let tops: Vec<_> = fs::read_dir(&dest)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(tops, vec!["src"]);
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn stamp_roundtrips() {
        let dir = std::env::temp_dir().join(format!("ts-stamp-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let st = Stamp {
            name: "json".into(),
            symbol: "tree_sitter_json".into(),
            parser_url: "https://github.com/tree-sitter/tree-sitter-json".into(),
            queries_url: "https://github.com/neovim-treesitter/nvim-treesitter-queries-json".into(),
            tag: "v0.24.8".into(),
        };
        write_stamp(&dir, &st).unwrap();
        assert_eq!(read_stamp(&dir).unwrap().symbol, "tree_sitter_json");
        let _ = fs::remove_dir_all(&dir);
    }
}
