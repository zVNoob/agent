//! Append-only, block-compressed conversation memory with an in-memory
//! working set — the "latest N messages from a huge log" store.
//!
//! # Why this shape
//!
//! The driving requirement: pull out the latest 5–10 messages without ever
//! struggling with (say) a 500 MB history file. Three properties deliver that:
//!
//! 1. **Never read the head.** The log is append-only and framed so the
//!    *tail* is self-describing: each block record is
//!    `[gzip payload][u32 LE compressed length]`. The length footer sits at
//!    the very end of the record, so reading the last 4 bytes of the file
//!    yields the length of the newest block; seek back, decompress just that
//!    block, and repeat. Only the blocks that actually hold the tail are
//!    touched and decompressed.
//! 2. **Block-wise compression.** A single gzip stream over the whole file
//!    would destroy random access to the tail; per-block streams keep every
//!    tail read at O(blocks read) while shrinking the file 5–15× (JSON/RPC
//!    logs are extremely repetitive). Each gzip stream carries its own CRC32,
//!    so torn blocks are detected, not mis-parsed.
//! 3. **An in-memory working set.** The last `Options::working_set` messages
//!    (default 64) are kept in a ring so `latest(n <= working_set)` is O(1)
//!    and touches no disk at all during a live session. Reads deeper than the
//!    working set spill to the disk tail reader.
//!
//! # On-disk format
//!
//! ```text
//! [ AMEM ][ ver u16 LE ][ codec u8 ][ pad u8 ]   header (8 bytes)
//! [ payload ][ len u32 LE ]                      block record, repeated
//! ```
//!
//! * payload: one gzip stream whose decompressed content is JSONL — one
//!   message per line, each line a valid JSON value with a trailing newline.
//! * Records are always written `[payload][footer]`, footer last; a crash can
//!   only ever tear the *trailing* record, and the tail reader skips torn
//!   tails by scanning backward a bounded distance for the newest intact
//!   record boundary.
//!
//! # Lifecycle & durability
//!
//! Messages buffer in memory and are sealed into a compressed block when the
//! buffer reaches `Options::block_target` or on `flush()`/`close()`. There is
//! **no per-message fsync**: call `flush()` (which seals the pending buffer
//! and `sync_data`s) at a group-commit cadence you choose. An un-flushed
//! tail lives only in memory (and in the working set); a crash discards at
//! most one block's worth of messages.
//!
//! # Integration
//!
//! The agent loop and Lua both write this log. The TUI opens one `Memory`
//! (path from `agent.llm.memory`, see `agent::lua`) and shares it behind a
//! process-wide `Arc<Mutex<Memory>>` ([`bind_memory`](crate::lua::bind_memory)): the
//! loop archives each history message as it lands (a watermark — never
//! rewrites, compaction just clamps it) and flushes at turn boundaries and on
//! exit; `agent.memory.append / latest / flush / path` expose the same store
//! to Lua. On startup the TUI *replays* the newest archived messages (via
//! [`read_tail`]) into the transcript and request history, so a fresh session
//! continues where the last one left off.
//!
//! Single-owner *within* one lock critical section; the `Mutex` is what makes
//! the store reachable from both sides of the boundary — the loop and the Lua
//! coroutines it drives share it, and neither can assume it is alone in it.
//! There is still exactly one `Memory` per process.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

const HEADER_MAGIC: &[u8; 4] = b"AMEM";
const HEADER_VERSION: u16 = 1;
const HEADER_LEN: u64 = 8;
/// Codec id written into the header at offset 6 (1 = gzip / deflate).
const CODEC_GZIP: u8 = 1;

/// Raw (uncompressed) bytes of one sealed block before compression.
const DEFAULT_BLOCK_TARGET: usize = 1 << 20; // 1 MiB
/// How many of the most recent messages `latest()` serves from memory.
const DEFAULT_WORKING_SET: usize = 64;
/// Upper bound on one record's on-disk footprint: a gzip stream whose raw
/// input is at most one `block_target` (default 1 MiB) plus at most one
/// pending message, never compressed beyond a small constant, and its 4-byte
/// length footer. `newest_valid_record` bounds its torn-tail scan to this
/// window — a crash can only tear the *trailing* record, so the newest intact
/// boundary must sit within one record's footprint of the file end.
const MAX_RECORD_WINDOW: u64 = DEFAULT_BLOCK_TARGET as u64 + (1 << 20);

/// Tunables for [`Memory::with_options`]. Defaults (via `Default`) are the
/// sweet spot for chat-history workloads; small values are handy in tests.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Seal + compress the pending buffer once it holds this many bytes.
    /// Clamped to `>= 64`.
    pub block_target: usize,
    /// Ring size of the in-memory working set. Clamped to `>= 1`.
    pub working_set: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            block_target: DEFAULT_BLOCK_TARGET,
            working_set: DEFAULT_WORKING_SET,
        }
    }
}

/// An append-only, block-compressed conversation log plus the in-memory
/// working set. Owns the file; `latest()` and `append()` are O(1) against
/// memory and the disk tail reader only decompresses the blocks it needs.
pub struct Memory {
    path: PathBuf,
    file: BufWriter<File>,
    block_target: usize,
    working_set: usize,
    /// Unsealed message bytes (JSONL) waiting in the current block.
    buffer: Vec<u8>,
    /// Monotonic, session-local sequence number (persistence of the counter
    /// needs an index — a later milestone; ordering on disk is positional).
    seq: u64,
    working: VecDeque<String>,
    hydrated: bool,
    closed: bool,
}

impl Memory {
    /// Open (or create) the log at `path` with default [`Options`].
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::with_options(path, Options::default())
    }

    /// Open (or create) the log at `path` with explicit [`Options`].
    ///
    /// Missing parent directories are created, so the first run over a
    /// brand-new default path (e.g. `~/.config/agent/history.amem`) "just
    /// works" instead of failing to open.
    pub fn with_options(path: impl AsRef<Path>, opts: Options) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // append-only: existing logs are reopened, never wiped
            .open(&path)?;
        let len = f.metadata()?.len();
        if len == 0 {
            write_header(&mut f)?;
        } else {
            verify_header(&mut f, len)?;
        }
        Ok(Self {
            path,
            file: BufWriter::new(f),
            block_target: opts.block_target.max(64),
            working_set: opts.working_set.max(1),
            buffer: Vec::new(),
            seq: 0,
            working: VecDeque::new(),
            hydrated: false,
            closed: false,
        })
    }

    /// Append one message. `message` must be a valid JSON value (checked —
    /// the log only ever holds valid JSON lines). The message lands in the
    /// working set immediately and is buffered for the current block.
    pub fn append(&mut self, message: &str) -> io::Result<u64> {
        self.ensure_open()?;
        serde_json::from_str::<serde_json::Value>(message).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("memory.append: message is not valid JSON: {e}"),
            )
        })?;
        self.buffer.extend_from_slice(message.as_bytes());
        self.buffer.push(b'\n');
        self.working.push_back(message.to_string());
        while self.working.len() > self.working_set {
            self.working.pop_front();
        }
        if self.buffer.len() >= self.block_target {
            self.seal_block()?;
        }
        self.seq += 1;
        Ok(self.seq)
    }

    /// The last `n` messages in append order (oldest → newest).
    ///
    /// Serves from the in-memory working set when `n` fits (O(1), no disk);
    /// deeper reads seal the pending buffer and walk the on-disk tail,
    /// decompressing only the blocks that hold those messages.
    pub fn latest(&mut self, n: usize) -> io::Result<Vec<String>> {
        self.ensure_open()?;
        if n == 0 {
            return Ok(Vec::new());
        }
        if !self.hydrated {
            // Freshly opened over an existing log: warm the working set from
            // the disk tail (cheap by construction).
            let tail = read_tail(&self.path, self.working_set)?;
            for m in tail {
                self.working.push_back(m);
            }
            self.hydrated = true;
        }
        if n <= self.working.len() {
            let start = self.working.len() - n;
            return Ok(self.working.iter().skip(start).cloned().collect());
        }
        // Deeper than the working set holds: make the pending tail visible on
        // disk, then read from the file directly.
        self.flush()?;
        read_tail(&self.path, n)
    }

    /// Seal the pending buffer into a compressed block, flush the writer, and
    /// `sync_data` the file. Call at your chosen group-commit cadence; there
    /// is no per-message fsync.
    pub fn flush(&mut self) -> io::Result<()> {
        self.ensure_open()?;
        self.seal_block()?;
        self.file.flush()?;
        self.file.get_ref().sync_data()?;
        Ok(())
    }

    /// `flush()` then mark the log closed; further calls fail.
    pub fn close(&mut self) -> io::Result<()> {
        if !self.closed {
            self.flush()?;
            self.closed = true;
        }
        Ok(())
    }

    /// The on-disk location of this log.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn ensure_open(&self) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "memory: log is closed",
            ));
        }
        Ok(())
    }

    fn seal_block(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let compressed = gzip_compress(&self.buffer)?;
        let len = u32::try_from(compressed.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "memory: block too large"))?;
        self.file.write_all(&compressed)?;
        self.file.write_all(&len.to_le_bytes())?;
        self.buffer.clear();
        Ok(())
    }
}

/// Read the last `n` messages of a log at `path` (oldest → newest) without
/// opening a [`Memory`]. Cold-start / history-paging entry point and the
/// engine behind `Memory::latest`'s deep reads.
///
/// Never reads the file from the head: starts at EOF, reads the trailing
/// block length footer, decompresses only the block(s) holding the newest
/// messages, and walks backward. A torn trailing record (crash mid-append)
/// is skipped via a bounded backward scan for the newest intact boundary.
pub fn read_tail(path: impl AsRef<Path>, n: usize) -> io::Result<Vec<String>> {
    Ok(read_before(path, Cursor::end(), n)?.records)
}

/// Where a backward read resumes.
///
/// Two fields, because the log's addressable unit is a **block** — a compressed
/// payload holding however many records fitted under `Options::block_target` — and
/// a caller rarely wants to stop on a block boundary. A page that stops on a record
/// count usually stops *inside* a block, and a byte offset alone cannot say where
/// inside.
///
/// `at` is a position to *search backwards from*, not a block's own start. A
/// backward walk finds the block ending at or before `at`, so a block is found by
/// the start of the block *after* it: handing back a block's start would find the
/// block *before* it and skip everything between.
///
/// `take` bounds how much of the block found at `at` belongs to the read, and it
/// counts *leading records wanted*, not records to drop. Resuming just after one
/// record means the leading `take` records of that block are wanted and the rest are
/// not — the opposite of skipping them, and the difference between paging over a gap
/// in the history and paging over it twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    /// The position to search backwards from.
    pub at: u64,
    /// Records to take from the front of the block found at `at`; [`usize::MAX`] for
    /// all of them.
    pub take: usize,
}

impl Cursor {
    /// Search back from the very end of the log, taking everything.
    pub fn end() -> Self {
        Cursor {
            at: u64::MAX,
            take: usize::MAX,
        }
    }

    /// Whether there is nothing older at this point.
    ///
    /// A page that stops on the oldest record of the first block reaches the header,
    /// which is the floor nothing older can sit behind.
    pub fn exhausted(&self) -> bool {
        self.at <= HEADER_LEN
    }
}

/// One backward page out of the log, with enough bookkeeping to resume from *any*
/// record in it rather than only from its oldest.
///
/// That bookkeeping is not decoration. A caller that keeps a subset — and one has to:
/// the newest `n` **messages** come with the panel records interleaved among them,
/// so the page boundary is not a record count — otherwise has no way to say where
/// the subset ends, and can only resume from the page's own edge. That is either a
/// repeat of records already shown or a hole between them, and nothing downstream
/// can tell which happened.
#[derive(Debug, Clone)]
pub struct Page {
    /// The records read, oldest → newest.
    pub records: Vec<String>,
    /// `resume[i]` reads the record immediately older than `records[i]`.
    pub resume: Vec<Cursor>,
    /// Where to read the next older page from.
    pub next: Cursor,
}

impl Page {
    /// Where to resume if the caller kept `records[index..]` and dropped everything
    /// before it.
    ///
    /// `index >= records.len()` means everything was kept, which is [`Page::next`].
    pub fn resume_after(&self, index: usize) -> Cursor {
        self.resume.get(index).copied().unwrap_or(self.next)
    }
}

/// Read up to `n` records ending at `cursor`, walking backwards.
///
/// The cursor is a [`Cursor`] rather than a bare byte offset because the log stores
/// records in compressed blocks and stops pages on a record count; see [`Cursor`].
///
/// Only the block the cursor points into is bounded by its `take`; blocks older than
/// it are read whole, so a page that ends inside a block still reaches past it.
///
/// The file's size is consulted rather than trusted from the cursor: the file grows
/// as the session writes, and a cursor from a stale read must not read past what is
/// there now.
pub fn read_before(path: impl AsRef<Path>, cursor: Cursor, n: usize) -> io::Result<Page> {
    let mut f = File::open(path)?;
    let empty = Page {
        records: Vec::new(),
        resume: Vec::new(),
        next: cursor,
    };
    if n == 0 || cursor.exhausted() {
        return Ok(empty);
    }

    // Collected newest-first (index 0 = newest), then reversed. `resume` is the
    // matching cursor per record, so the point to continue an *arbitrary* subset
    // from is read off by index rather than guessed as the walk goes.
    let mut newest_first: Vec<String> = Vec::new();
    let mut resume: Vec<Cursor> = Vec::new();
    let mut pos = cursor.at.min(f.metadata()?.len());
    let mut budget = cursor.take;
    while pos > HEADER_LEN && newest_first.len() < n {
        // `pos` is where this block is searched from, so it is also how the block
        // itself is found again — which every record after the first in it needs.
        let search_from = pos;
        let Some((start, blen)) = newest_valid_record(&mut f, pos)? else {
            break;
        };
        let block = read_block_lines(&mut f, start, blen)?;
        let count = block.len().min(budget);
        budget = usize::MAX; // blocks older than the cursor's are read whole
        for k in (0..count).rev() {
            newest_first.push(block[k].clone());
            resume.push(if k == 0 {
                // Nothing in this block is older than its first record, so continue
                // from the block's own start — which finds the block before it.
                Cursor {
                    at: start,
                    take: usize::MAX,
                }
            } else {
                // The records older than this one, inside this block, are exactly the
                // leading `k` of them.
                Cursor {
                    at: search_from,
                    take: k,
                }
            });
        }
        pos = start;
    }

    // Resume just before the oldest record being returned. Read off the array, not
    // from `pos`: `pos` is the start of the oldest block *walked*, which still holds
    // records this page is about to discard. It is the *last* entry, because the
    // array runs newest-first and `truncate` keeps the newest `n`.
    newest_first.truncate(n);
    resume.truncate(n);
    let next = resume.last().copied().unwrap_or(cursor);
    newest_first.reverse();
    resume.reverse();
    Ok(Page {
        records: newest_first,
        resume,
        next,
    })
}

/// Locate the payload start + length of the most recent intact record that
/// ends at or before `end`.
///
/// Only the file tail is ever examined: a crash mid-append can tear the
/// *trailing* record at most, so the newest intact boundary must lie within
/// one record's footprint of `end` ([`MAX_RECORD_WINDOW`]); anything older is
/// untouched. Within that window every byte is tested as a candidate footer
/// end, not just every fourth byte: a genuine u32 footer can sit on any
/// alignment, and a walk stepping 4 bytes from `end` alone silently skips
/// every real boundary whose end remainder differs from `end`'s — a torn tail
/// of the wrong length would otherwise seem to erase the whole log. Candidates
/// are cheap-filtered (plausible length, inside the file) before a gzip
/// CRC-validated decode settles the matter.
fn newest_valid_record(file: &mut File, end: u64) -> io::Result<Option<(u64, u32)>> {
    let floor = end.saturating_sub(MAX_RECORD_WINDOW).max(HEADER_LEN + 4);
    let mut p = end;
    while p >= floor {
        // Four footer ends per 4-byte step (p, p-1, p-2, p-3 — newest first,
        // so a healthy tail resolves on the first candidate). `fe` is the byte
        // *after* the u32 length, keeping each read window [fe-4, fe) inside
        // the file (fe <= end <= size).
        for fe in (p.saturating_sub(3)..=p).rev() {
            let blen = read_u32_at(file, fe - 4)?;
            // A torn tail can produce a garbage length; a checked subtraction
            // keeps the scan from overflowing while stepping over it.
            let start = (fe - 4).checked_sub(u64::from(blen));
            if let Some(start) = start
                && blen > 0
                && start >= HEADER_LEN
                && u64::from(blen) <= fe - 4 - HEADER_LEN
                && read_block_lines(file, start, blen).is_ok()
            {
                return Ok(Some((start, blen)));
            }
        }
        p -= 4;
    }
    Ok(None)
}

/// Decompress one block's payload and split it into its messages.
fn read_block_lines(f: &mut File, start: u64, blen: u32) -> io::Result<Vec<String>> {
    f.seek(SeekFrom::Start(start))?;
    let mut raw = vec![0u8; blen as usize];
    f.read_exact(&mut raw)?;
    let decoded = gzip_decompress(&raw)?;
    let text = String::from_utf8(decoded).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("memory: block payload is not UTF-8: {e}"),
        )
    })?;
    Ok(text.lines().map(str::to_string).collect())
}

fn read_u32_at(f: &mut File, pos: u64) -> io::Result<u32> {
    f.seek(SeekFrom::Start(pos))?;
    let mut b = [0u8; 4];
    f.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn write_header(f: &mut File) -> io::Result<()> {
    let mut h = Vec::with_capacity(HEADER_LEN as usize);
    h.extend_from_slice(HEADER_MAGIC);
    h.extend_from_slice(&HEADER_VERSION.to_le_bytes());
    h.push(CODEC_GZIP);
    h.push(0); // reserved
    f.write_all(&h)
}

fn verify_header(f: &mut File, len: u64) -> io::Result<()> {
    if len < HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "memory: file shorter than the header",
        ));
    }
    f.seek(SeekFrom::Start(0))?;
    let mut head = [0u8; HEADER_LEN as usize];
    f.read_exact(&mut head)?;
    if &head[0..4] != HEADER_MAGIC.as_slice() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "memory: not an agent memory log (bad magic)",
        ));
    }
    let version = u16::from_le_bytes([head[4], head[5]]);
    if version != HEADER_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("memory: unsupported log version {version}"),
        ));
    }
    if head[6] != CODEC_GZIP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "memory: unsupported block codec",
        ));
    }
    Ok(())
}

fn gzip_compress(raw: &[u8]) -> io::Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(raw)?;
    enc.finish()
}

fn gzip_decompress(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut dec = GzDecoder::new(bytes);
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(3));
    dec.read_to_end(&mut out).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("memory: corrupt or torn block payload: {e}"),
        )
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::unique_path;
    use std::time::Instant;

    fn temp_path(tag: &str) -> PathBuf {
        unique_path(&format!("agent-memory-test-{tag}"))
    }

    fn msg(i: u64) -> String {
        format!(r#"{{"seq":{i},"role":"user","content":"message {i}"}}"#)
    }

    #[test]
    fn round_trips_through_append_flush_and_close() {
        let p = temp_path("rt");
        {
            let mut m = Memory::open(&p).expect("open");
            for i in 1..=3 {
                m.append(&msg(i)).expect("append");
            }
            m.flush().expect("flush");
        } // close on drop (BufWriter flush)
        let tail = read_tail(&p, 10).expect("read_tail");
        assert_eq!(tail, vec![msg(1), msg(2), msg(3)]);
        assert_eq!(read_tail(&p, 2).unwrap(), vec![msg(2), msg(3)]);
        std::fs::remove_file(&p).ok();
    }

    /// Paging backwards through a whole log hands back every record exactly once,
    /// in order, and stops.
    ///
    /// The unit of storage is a block and the unit of a page is a record count, so
    /// every page boundary lands *inside* a block and the cursor has to say both
    /// where to look and how much of what it finds to throw away. Getting the skip
    /// wrong repeats records; getting it always-zero skips them; failing to advance
    /// loops forever. All three are invisible to a single-call test and obvious to
    /// walking the whole log.
    #[test]
    fn a_backward_walk_returns_every_record_once_and_stops() {
        let p = temp_path("paging");
        {
            let mut m = Memory::with_options(
                &p,
                Options {
                    block_target: 256,
                    working_set: 64,
                },
            )
            .expect("open");
            for i in 1..=100 {
                m.append(&msg(i)).expect("append");
            }
            m.flush().expect("flush");
        }

        let mut cursor = Cursor::end();
        let mut pages: Vec<Vec<String>> = Vec::new();
        let mut steps = 0;
        while !cursor.exhausted() {
            let page = read_before(&p, cursor, 8).expect("read");
            assert!(
                !page.records.is_empty(),
                "a cursor that is not exhausted must return something"
            );
            assert!(
                page.records.len() <= 8,
                "a page is the count asked for, not more: {}",
                page.records.len()
            );
            pages.push(page.records);
            cursor = page.next;
            steps += 1;
            assert!(steps < 40, "the walk terminates");
        }
        // Pages arrive newest-first and each one is oldest-to-newest, so the log
        // reads back out by walking the pages in reverse.
        let collected: Vec<String> = pages.iter().rev().flat_map(|p| p.iter().cloned()).collect();
        let expected: Vec<String> = (1..=100).map(msg).collect();
        assert_eq!(collected, expected, "every record, once, oldest first");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn blocks_cross_boundaries_and_tail_reads_span_them() {
        // Tiny block target: ~300 messages x ~40 bytes force many sealed
        // blocks, and the requested tail lands mid-block.
        let opts = Options {
            block_target: 256,
            working_set: 64,
        };
        let p = temp_path("blocks");
        {
            let mut m = Memory::with_options(&p, opts).expect("open");
            for i in 1..=300 {
                m.append(&msg(i)).expect("append");
            }
            m.flush().expect("flush");
        }
        let five = read_tail(&p, 5).expect("tail 5");
        assert_eq!(five, (296..=300).map(msg).collect::<Vec<_>>());
        let all = read_tail(&p, 300).expect("tail 300");
        assert_eq!(all.len(), 300);
        assert_eq!(all[0], msg(1));
        assert_eq!(all[299], msg(300));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn payloads_are_actually_gzip_compressed() {
        // First block record starts right after the 8-byte header with the
        // gzip magic 0x1f 0x8b — proof that compression is on disk.
        let p = temp_path("gz");
        {
            let mut m = Memory::open(&p).expect("open");
            for i in 1..=5 {
                m.append(&msg(i)).expect("append");
            }
            m.flush().expect("flush");
        }
        let data = std::fs::read(&p).expect("read file");
        assert!(data.len() > 8, "one compressed block on disk");
        assert_eq!(&data[8..10], &[0x1f, 0x8b], "gzip magic at first block");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn working_set_serves_latest_before_any_disk_write() {
        let p = temp_path("ws");
        let mut m = Memory::open(&p).expect("open");
        for i in 1..=10 {
            m.append(&msg(i)).expect("append");
        }
        // Nothing flushed: latest() must still be correct from memory alone.
        assert_eq!(m.latest(3).unwrap(), vec![msg(8), msg(9), msg(10)]);
        assert_eq!(m.latest(10).unwrap().len(), 10);
        m.close().expect("close");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn latest_spills_to_disk_beyond_the_working_set() {
        let opts = Options {
            block_target: 1 << 20,
            working_set: 4,
        };
        let p = temp_path("spill");
        let mut m = Memory::with_options(&p, opts).expect("open");
        for i in 1..=10 {
            m.append(&msg(i)).expect("append");
        }
        let deep = m.latest(6).expect("latest 6 (spills to disk)");
        assert_eq!(deep, (5..=10).map(msg).collect::<Vec<_>>());
        m.close().expect("close");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn reopen_hydrates_the_working_set_from_the_disk_tail() {
        let p = temp_path("hydrate");
        {
            let mut m = Memory::open(&p).expect("open");
            for i in 1..=20 {
                m.append(&msg(i)).expect("append");
            }
            m.close().expect("close");
        }
        let mut m = Memory::open(&p).expect("reopen");
        assert!(!m.hydrated);
        assert_eq!(m.latest(5).unwrap(), (16..=20).map(msg).collect::<Vec<_>>());
        assert!(m.hydrated, "latest() must hydrate on first call");
        assert_eq!(m.latest(20).unwrap().len(), 20);
        m.close().expect("close");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn torn_tail_is_skipped_by_the_backward_scan() {
        let p = temp_path("torn");
        {
            let mut m = Memory::open(&p).expect("open");
            for i in 1..=5 {
                m.append(&msg(i)).expect("append");
            }
            m.close().expect("close");
        }
        // Simulate a crash mid-append: a partial payload fragment, no footer.
        let mut g = std::fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .expect("append handle");
        g.write_all(b"{\"partial\":true}").expect("torn bytes");
        drop(g);
        let tail = read_tail(&p, 5).expect("read_tail over torn tail");
        assert_eq!(tail, (1..=5).map(msg).collect::<Vec<_>>());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn torn_tail_alignments_never_hide_the_intact_block() {
        // Regression: the backward scan used to walk from the file end in
        // 4-byte steps, which only ever tests footer endings congruent with
        // the file size. A torn tail whose length is not a multiple of 4 put
        // every real block boundary on a skipped alignment, so `read_tail`
        // silently returned nothing — "the memory won't load" after a killed
        // session. Every footer alignment must be reachable.
        for garbage_len in [1usize, 3] {
            let p = temp_path("torn-align");
            {
                let mut m = Memory::open(&p).expect("open");
                for i in 1..=5 {
                    m.append(&msg(i)).expect("append");
                }
                m.close().expect("close");
            }
            let mut g = std::fs::OpenOptions::new()
                .append(true)
                .open(&p)
                .expect("append handle");
            g.write_all(&vec![b'x'; garbage_len]).expect("torn bytes");
            drop(g);
            let tail = read_tail(&p, 5).expect("read_tail over misaligned torn tail");
            assert_eq!(
                tail,
                (1..=5).map(msg).collect::<Vec<_>>(),
                "garbage_len {garbage_len}: intact block must survive any tail alignment"
            );
            std::fs::remove_file(&p).ok();
        }
    }

    #[test]
    fn torn_tail_keeps_multiblock_tails_newest_first() {
        // Multi-block log with a misaligned torn tail: the newest intact block
        // must win, not a lucky hit on an older block from the wrong alignment.
        let opts = Options {
            block_target: 256,
            working_set: 64,
        };
        let p = temp_path("torn-multi");
        {
            let mut m = Memory::with_options(&p, opts).expect("open");
            for i in 1..=300 {
                m.append(&msg(i)).expect("append");
            }
            m.close().expect("close");
        }
        let mut g = std::fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .expect("append handle");
        g.write_all(b"x").expect("torn bytes");
        drop(g);
        let five = read_tail(&p, 5).expect("read_tail over misaligned torn tail");
        assert_eq!(five, (296..=300).map(msg).collect::<Vec<_>>());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn middle_corruption_never_breaks_tail_reads() {
        // Corrupt payload bytes deep in the file: the tail reader must never
        // even look there, so the newest messages come back intact.
        let opts = Options {
            block_target: 256,
            working_set: 64,
        };
        let p = temp_path("middle");
        {
            let mut m = Memory::with_options(&p, opts).expect("open");
            for i in 1..=600 {
                m.append(&msg(i)).expect("append");
            }
            m.close().expect("close");
        }
        let size = std::fs::metadata(&p).expect("meta").len();
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&p)
                .expect("rw handle");
            let mid = (size / 2) as usize;
            f.seek(SeekFrom::Start(mid as u64)).expect("seek to middle");
            let junk = vec![0xA5u8; 2048];
            f.write_all(&junk).expect("corrupt middle payload");
        }
        let tail = read_tail(&p, 5).expect("tail after middle corruption");
        assert_eq!(tail, (596..=600).map(msg).collect::<Vec<_>>());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn invalid_json_is_rejected_at_append() {
        let p = temp_path("badjson");
        let mut m = Memory::open(&p).expect("open");
        let e = m.append("{not json").expect_err("append must reject");
        assert!(e.to_string().contains("not valid JSON"));
        // The counter is unchanged, so the rejected message took no sequence
        // number: the log's `seq` values stay contiguous.
        let ok = m
            .append(r#"{"role":"user","content":"next"}"#)
            .expect("the next append");
        assert_eq!(ok, 1, "so the rejected one did not consume number 1");
        m.close().expect("close");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn fresh_and_empty_logs_behave() {
        let p = temp_path("empty");
        {
            let mut m = Memory::open(&p).expect("open");
            assert!(m.latest(5).unwrap().is_empty(), "a fresh log is empty");
        }
        assert_eq!(std::fs::metadata(&p).unwrap().len(), HEADER_LEN);
        assert!(read_tail(&p, 5).unwrap().is_empty());
        let mut m = Memory::open(&p).expect("reopen");
        assert!(m.latest(5).unwrap().is_empty());
        m.close().expect("close");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn fewer_messages_than_requested_returns_what_exists() {
        let p = temp_path("few");
        {
            let mut m = Memory::open(&p).expect("open");
            m.append(&msg(1)).expect("append");
            m.append(&msg(2)).expect("append");
            m.close().expect("close");
        }
        assert_eq!(read_tail(&p, 100).unwrap(), vec![msg(1), msg(2)]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn operations_after_close_fail_fast() {
        let p = temp_path("closed");
        let mut m = Memory::open(&p).expect("open");
        m.close().expect("close");
        assert!(m.append(&msg(1)).is_err(), "append after close");
        assert!(m.latest(1).is_err(), "latest after close");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn big_log_tail_read_stays_fast_and_correct() {
        // ~100k messages, ~6 MB raw: tail reads must not scale with the file.
        let opts = Options {
            block_target: 1 << 20,
            working_set: 64,
        };
        let p = temp_path("big");
        let mut total_raw = 0usize;
        {
            let mut m = Memory::with_options(&p, opts).expect("open");
            for i in 1..=100_000 {
                let m0 = msg(i);
                total_raw += m0.len() + 1; // + the framing newline
                m.append(&m0).expect("append");
            }
            m.flush().expect("flush");
        }
        let on_disk = std::fs::metadata(&p).unwrap().len() as usize;
        assert!(
            on_disk > 100_000,
            "log should span real blocks, got {on_disk}"
        );
        assert!(
            on_disk < total_raw / 4,
            "expected >=4x compression: raw={total_raw} on_disk={on_disk}"
        );

        let t0 = Instant::now();
        let tail = read_tail(&p, 10).expect("tail 10");
        let elapsed = t0.elapsed();
        assert_eq!(tail, (99_991..=100_000).map(msg).collect::<Vec<_>>());
        assert!(
            elapsed.as_millis() < 2_000,
            "tail read took {elapsed:?} on a {on_disk}-byte log"
        );
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn compression_shrinks_a_repetitive_log() {
        let opts = Options {
            block_target: 1 << 20,
            working_set: 64,
        };
        let p = temp_path("ratio");
        {
            let mut m = Memory::with_options(&p, opts).expect("open");
            for i in 1..=50_000 {
                m.append(&msg(i)).expect("append");
            }
            m.close().expect("close");
        }
        let raw_messages: usize = (1..=50_000).map(msg).map(|s| s.len() + 1).sum();
        let on_disk = std::fs::metadata(&p).unwrap().len() as usize;
        assert!(
            on_disk < raw_messages / 4,
            "expected >=4x compression: raw={raw_messages} on_disk={on_disk}"
        );
        std::fs::remove_file(&p).ok();
    }
}
