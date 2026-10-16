//! Durable work-unit persistence and recovery for interrupted proxy work.
//!
//! A proxy request (identified by a correlation/request id) is decomposed
//! into deterministic work units (`parse`, `validate_target`, `fetch`,
//! `validate_content`, `classify`, `wrap`). Every unit transition is
//! persisted to a file-backed store so an interrupted process can, on
//! restart, either **resume** the request from its last persisted work unit
//! or **mark it blocked** according to a configured recovery policy —
//! without ever re-executing a completed work unit.
//!
//! Design constraints (deliberately dependency-free, matching the rest of
//! this crate):
//! - no external crates (hand-rolled minimal JSON encode/parse);
//! - explicit timestamps everywhere so tests are fully deterministic;
//! - the store is at-least-once: a completed unit is never executed twice
//!   (`UnitAlreadyCompleted`), which is the observable dedupe contract.

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Default heartbeat TTL for a running work unit (seconds).
pub const DEFAULT_HEARTBEAT_TTL_SECS: u64 = 300;

/// Sub-directory holding one JSON record per request.
const REQUESTS_DIR: &str = "requests";
/// Sub-directory holding per-request payload artifacts.
const PAYLOADS_DIR: &str = "payloads";
/// Append-only audit log file name.
const AUDIT_LOG_FILE: &str = "audit.log";
/// Max bytes for a single audit log line (defensive bound).
const MAX_AUDIT_LINE_BYTES: usize = 4096;
/// Max bytes for a single record file (defensive bound).
const MAX_RECORD_BYTES: usize = 64 * 1024;
/// Max bytes for a single payload artifact (defensive bound; the transport
/// already enforces `max_body_size`, this is a second fence).
const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

/// Current unix time in milliseconds.
pub fn current_time_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Status model
// ---------------------------------------------------------------------------

/// Lifecycle of a single work unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitStatus {
    /// Recorded but not yet started.
    Pending,
    /// Currently executing (heartbeat expected).
    Running,
    /// Finished successfully — never executed again.
    Completed,
    /// Finished unsuccessfully (recovery policy decision or policy block).
    Blocked,
    /// Finished unsuccessfully (transient/unrecoverable).
    Failed,
}

impl UnitStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "blocked" => Some(Self::Blocked),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Lifecycle of a whole request record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    Running,
    Completed,
    Blocked,
    Failed,
}

impl RequestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "blocked" => Some(Self::Blocked),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// A single persisted work unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkUnit {
    pub id: String,
    pub status: UnitStatus,
    pub heartbeat_at: u64,
    pub created_at: u64,
    pub completed_at: Option<u64>,
}

impl WorkUnit {
    fn new(id: &str, now: u64) -> Self {
        Self {
            id: id.to_string(),
            status: UnitStatus::Pending,
            heartbeat_at: now,
            created_at: now,
            completed_at: None,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            UnitStatus::Completed | UnitStatus::Blocked | UnitStatus::Failed
        )
    }
}

/// A durable request record: the request-level envelope plus its units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRecord {
    pub request_id: String,
    pub url: String,
    pub status: RequestStatus,
    pub created_at: u64,
    /// Recovery policy snapshot at record creation ("resume" | "block").
    pub policy: String,
    pub units: Vec<WorkUnit>,
}

/// Errors produced by the durable store and recovery layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// I/O failure while reading or writing state.
    Io(String),
    /// No record exists for the given request id.
    NotFound(String),
    /// A record file exists but cannot be parsed (interrupted write etc.).
    CorruptRecord(String),
    /// The unit is already completed — never execute it again (dedupe).
    UnitAlreadyCompleted(String),
    /// The unit is already terminal (blocked/failed) — cannot transition.
    AlreadyTerminal(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "io error: {}", msg),
            Self::NotFound(id) => write!(f, "record not found: {}", id),
            Self::CorruptRecord(id) => write!(f, "corrupt record: {}", id),
            Self::UnitAlreadyCompleted(id) => {
                write!(f, "unit already completed: {}", id)
            }
            Self::AlreadyTerminal(id) => write!(f, "unit already terminal: {}", id),
        }
    }
}

impl std::error::Error for StoreError {}

// ---------------------------------------------------------------------------
// Minimal JSON (encode + parse) — no external dependencies.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum JsonVal {
    Str(String),
    Num(u64),
    Bool(bool),
    Arr(Vec<JsonVal>),
    Obj(Vec<(String, JsonVal)>),
    Null,
}

pub(crate) fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn json_write(v: &JsonVal, out: &mut String) {
    match v {
        JsonVal::Null => out.push_str("null"),
        JsonVal::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsonVal::Num(n) => out.push_str(&n.to_string()),
        JsonVal::Str(s) => {
            out.push('"');
            out.push_str(&json_escape(s));
            out.push('"');
        }
        JsonVal::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_write(item, out);
            }
            out.push(']');
        }
        JsonVal::Obj(entries) => {
            out.push('{');
            for (i, (k, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&json_escape(k));
                out.push('"');
                out.push(':');
                json_write(val, out);
            }
            out.push('}');
        }
    }
}

pub(crate) fn json_to_string(v: &JsonVal) -> String {
    let mut out = String::new();
    json_write(v, &mut out);
    out
}

/// Parse a JSON document with a minimal recursive-descent parser.
///
/// Supports the exact subset this crate persists: objects, arrays, strings
/// (with escapes), u64 numbers, booleans, null. Rejects anything else
/// (no floats, no exponents) so persisted timestamps stay lossless.
pub(crate) fn json_parse(input: &str) -> Result<JsonVal, String> {
    let bytes = input.as_bytes();
    let mut pos = 0usize;
    let value = parse_value(bytes, &mut pos)?;
    skip_ws(bytes, &mut pos);
    if pos != bytes.len() {
        return Err("trailing characters".to_string());
    }
    Ok(value)
}

fn skip_ws(bytes: &[u8], pos: &mut usize) {
    while *pos < bytes.len() && matches!(bytes[*pos], b' ' | b'\t' | b'\r' | b'\n') {
        *pos += 1;
    }
}

fn peek(bytes: &[u8], pos: &mut usize, expected: u8) -> Result<(), String> {
    skip_ws(bytes, pos);
    if *pos < bytes.len() && bytes[*pos] == expected {
        *pos += 1;
        Ok(())
    } else {
        Err(format!("expected '{}' at {}", expected as char, *pos))
    }
}

fn parse_value(bytes: &[u8], pos: &mut usize) -> Result<JsonVal, String> {
    skip_ws(bytes, pos);
    if *pos >= bytes.len() {
        return Err("unexpected end of input".to_string());
    }
    match bytes[*pos] {
        b'{' => parse_object(bytes, pos),
        b'[' => parse_array(bytes, pos),
        b'"' => Ok(JsonVal::Str(parse_string(bytes, pos)?)),
        b't' | b'f' => parse_bool(bytes, pos),
        b'n' => {
            if bytes[*pos..].starts_with(b"null") {
                *pos += 4;
                Ok(JsonVal::Null)
            } else {
                Err("invalid literal".to_string())
            }
        }
        b'-' | b'0'..=b'9' => Ok(JsonVal::Num(parse_number(bytes, pos)?)),
        _ => Err(format!("unexpected token at {}", *pos)),
    }
}

fn parse_object(bytes: &[u8], pos: &mut usize) -> Result<JsonVal, String> {
    peek(bytes, pos, b'{')?;
    let mut entries: Vec<(String, JsonVal)> = Vec::new();
    skip_ws(bytes, pos);
    if *pos < bytes.len() && bytes[*pos] == b'}' {
        *pos += 1;
        return Ok(JsonVal::Obj(entries));
    }
    loop {
        skip_ws(bytes, pos);
        let key = parse_string(bytes, pos)?;
        peek(bytes, pos, b':')?;
        let value = parse_value(bytes, pos)?;
        entries.push((key, value));
        skip_ws(bytes, pos);
        if *pos >= bytes.len() {
            return Err("unterminated object".to_string());
        }
        match bytes[*pos] {
            b',' => {
                *pos += 1;
            }
            b'}' => {
                *pos += 1;
                return Ok(JsonVal::Obj(entries));
            }
            _ => return Err("expected ',' or '}' in object".to_string()),
        }
    }
}

fn parse_array(bytes: &[u8], pos: &mut usize) -> Result<JsonVal, String> {
    peek(bytes, pos, b'[')?;
    let mut items: Vec<JsonVal> = Vec::new();
    skip_ws(bytes, pos);
    if *pos < bytes.len() && bytes[*pos] == b']' {
        *pos += 1;
        return Ok(JsonVal::Arr(items));
    }
    loop {
        let value = parse_value(bytes, pos)?;
        items.push(value);
        skip_ws(bytes, pos);
        if *pos >= bytes.len() {
            return Err("unterminated array".to_string());
        }
        match bytes[*pos] {
            b',' => {
                *pos += 1;
            }
            b']' => {
                *pos += 1;
                return Ok(JsonVal::Arr(items));
            }
            _ => return Err("expected ',' or ']' in array".to_string()),
        }
    }
}

fn parse_string(bytes: &[u8], pos: &mut usize) -> Result<String, String> {
    peek(bytes, pos, b'"')?;
    let mut out = String::new();
    loop {
        if *pos >= bytes.len() {
            return Err("unterminated string".to_string());
        }
        match bytes[*pos] {
            b'"' => {
                *pos += 1;
                return Ok(out);
            }
            b'\\' => {
                *pos += 1;
                if *pos >= bytes.len() {
                    return Err("unterminated escape".to_string());
                }
                let c = bytes[*pos];
                *pos += 1;
                match c {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000c}'),
                    b'u' => {
                        if *pos + 4 > bytes.len() {
                            return Err("truncated unicode escape".to_string());
                        }
                        let hex = std::str::from_utf8(&bytes[*pos..*pos + 4])
                            .map_err(|_| "invalid unicode escape".to_string())?;
                        let code = u32::from_str_radix(hex, 16)
                            .map_err(|_| "invalid unicode escape".to_string())?;
                        *pos += 4;
                        match char::from_u32(code) {
                            Some(ch) => out.push(ch),
                            None => return Err("invalid unicode codepoint".to_string()),
                        }
                    }
                    _ => return Err("invalid escape sequence".to_string()),
                }
            }
            b if b < 0x20 => return Err("unescaped control character".to_string()),
            _ => {
                // Copy a single UTF-8 char.
                let rest = &bytes[*pos..];
                let ch = std::str::from_utf8(rest)
                    .map_err(|_| "invalid utf-8 in string".to_string())?
                    .chars()
                    .next()
                    .ok_or_else(|| "empty string remainder".to_string())?;
                out.push(ch);
                *pos += ch.len_utf8();
            }
        }
    }
}

fn parse_bool(bytes: &[u8], pos: &mut usize) -> Result<JsonVal, String> {
    if bytes[*pos..].starts_with(b"true") {
        *pos += 4;
        Ok(JsonVal::Bool(true))
    } else if bytes[*pos..].starts_with(b"false") {
        *pos += 5;
        Ok(JsonVal::Bool(false))
    } else {
        Err("invalid boolean literal".to_string())
    }
}

/// Parse an unsigned integer (no sign, no fraction, no exponent).
fn parse_number(bytes: &[u8], pos: &mut usize) -> Result<u64, String> {
    let start = *pos;
    if *pos < bytes.len() && bytes[*pos] == b'-' {
        // Persisted timestamps are always non-negative; reject negatives.
        return Err("negative numbers not supported".to_string());
    }
    while *pos < bytes.len() && bytes[*pos].is_ascii_digit() {
        *pos += 1;
    }
    if *pos == start {
        return Err("expected number".to_string());
    }
    let text =
        std::str::from_utf8(&bytes[start..*pos]).map_err(|_| "invalid number utf-8".to_string())?;
    text.parse::<u64>()
        .map_err(|_| format!("number out of range: {}", text))
}

// ---------------------------------------------------------------------------
// Record <-> JSON serialization
// ---------------------------------------------------------------------------

impl RequestRecord {
    pub(crate) fn to_json_value(&self) -> JsonVal {
        let units: Vec<JsonVal> = self
            .units
            .iter()
            .map(|u| {
                let mut entries = vec![
                    ("id".to_string(), JsonVal::Str(u.id.clone())),
                    (
                        "status".to_string(),
                        JsonVal::Str(u.status.as_str().to_string()),
                    ),
                    ("heartbeat_at".to_string(), JsonVal::Num(u.heartbeat_at)),
                    ("created_at".to_string(), JsonVal::Num(u.created_at)),
                ];
                if let Some(ts) = u.completed_at {
                    entries.push(("completed_at".to_string(), JsonVal::Num(ts)));
                }
                JsonVal::Obj(entries)
            })
            .collect();
        JsonVal::Obj(vec![
            (
                "request_id".to_string(),
                JsonVal::Str(self.request_id.clone()),
            ),
            ("url".to_string(), JsonVal::Str(self.url.clone())),
            (
                "status".to_string(),
                JsonVal::Str(self.status.as_str().to_string()),
            ),
            ("created_at".to_string(), JsonVal::Num(self.created_at)),
            ("policy".to_string(), JsonVal::Str(self.policy.clone())),
            ("units".to_string(), JsonVal::Arr(units)),
        ])
    }

    pub(crate) fn to_json_string(&self) -> String {
        json_to_string(&self.to_json_value())
    }

    pub(crate) fn from_json_value(v: &JsonVal) -> Option<Self> {
        let obj = match v {
            JsonVal::Obj(o) => o,
            _ => return None,
        };
        let get_str = |key: &str| {
            obj.iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, val)| match val {
                    JsonVal::Str(s) => Some(s.clone()),
                    _ => None,
                })
        };
        let get_num = |key: &str| {
            obj.iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, val)| match val {
                    JsonVal::Num(n) => Some(*n),
                    _ => None,
                })
        };
        let request_id = get_str("request_id")?;
        let url = get_str("url").unwrap_or_default();
        let status = get_str("status")
            .and_then(|s| RequestStatus::parse(&s))
            .unwrap_or(RequestStatus::Running);
        let created_at = get_num("created_at").unwrap_or(0);
        let policy = get_str("policy").unwrap_or_else(|| "resume".to_string());
        let mut units = Vec::new();
        let mut units_field_present = false;
        if let Some(JsonVal::Arr(items)) =
            obj.iter().find(|(k, _)| k == "units").map(|(_, val)| val)
        {
            units_field_present = true;
            for item in items {
                if let Some(u) = work_unit_from_json(item) {
                    units.push(u);
                }
            }
        }
        // A record must carry a `units` array (possibly empty right after
        // creation, populated by `ensure_units_at`).
        if !units_field_present {
            return None;
        }
        Some(Self {
            request_id,
            url,
            status,
            created_at,
            policy,
            units,
        })
    }
}

fn work_unit_from_json(v: &JsonVal) -> Option<WorkUnit> {
    let obj = match v {
        JsonVal::Obj(o) => o,
        _ => return None,
    };
    let get_str = |key: &str| {
        obj.iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, val)| match val {
                JsonVal::Str(s) => Some(s.clone()),
                _ => None,
            })
    };
    let get_num = |key: &str| {
        obj.iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, val)| match val {
                JsonVal::Num(n) => Some(*n),
                _ => None,
            })
    };
    let id = get_str("id")?;
    let status = get_str("status")
        .and_then(|s| UnitStatus::parse(&s))
        .unwrap_or(UnitStatus::Pending);
    let heartbeat_at = get_num("heartbeat_at").unwrap_or(0);
    let created_at = get_num("created_at").unwrap_or(0);
    let completed_at = get_num("completed_at");
    Some(WorkUnit {
        id,
        status,
        heartbeat_at,
        created_at,
        completed_at,
    })
}

// ---------------------------------------------------------------------------
// Durable store
// ---------------------------------------------------------------------------

/// File-backed durable store for request records and the audit log.
///
/// Layout:
/// ```text
/// <state_dir>/
///   requests/<request_id>.json   one JSON record per request
///   audit.log                    append-only outcome log
/// ```
#[derive(Debug, Clone)]
pub struct DurableStore {
    state_dir: PathBuf,
    ttl_secs: u64,
}

impl DurableStore {
    pub fn new(state_dir: &Path, ttl_secs: u64) -> Self {
        Self {
            state_dir: state_dir.to_path_buf(),
            ttl_secs,
        }
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    fn requests_dir(&self) -> PathBuf {
        self.state_dir.join(REQUESTS_DIR)
    }

    fn record_path(&self, request_id: &str) -> PathBuf {
        self.requests_dir().join(format!("{}.json", request_id))
    }

    fn audit_path(&self) -> PathBuf {
        self.state_dir.join(AUDIT_LOG_FILE)
    }

    /// Path of a payload artifact (`ext` is a fixed suffix like `.bin`).
    pub fn payload_path(&self, request_id: &str, ext: &str) -> PathBuf {
        debug_assert!(
            !ext.contains('/'),
            "extension must not contain a path separator"
        );
        self.state_dir
            .join(PAYLOADS_DIR)
            .join(format!("{}{}", request_id, ext))
    }

    /// Persist a payload artifact (e.g. the raw fetch response `.bin` or the
    /// final validated content `.out`). Written BEFORE the unit that produced
    /// it is marked completed, so a completed unit always has its output.
    pub fn save_payload(
        &self,
        request_id: &str,
        ext: &str,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(StoreError::Io(format!(
                "payload for {} exceeds {} bytes",
                request_id, MAX_PAYLOAD_BYTES
            )));
        }
        let path = self.payload_path(request_id, ext);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| StoreError::Io(format!("payload dir: {}", e)))?;
        }
        let tmp = path.with_extension(format!("{}tmp", ext.trim_start_matches('.')));
        fs::write(&tmp, bytes)
            .map_err(|e| StoreError::Io(format!("write payload {}: {}", tmp.display(), e)))?;
        fs::rename(&tmp, &path)
            .map_err(|e| StoreError::Io(format!("rename payload {}: {}", path.display(), e)))?;
        Ok(())
    }

    /// Load a persisted payload artifact.
    pub fn load_payload(&self, request_id: &str, ext: &str) -> Result<Vec<u8>, StoreError> {
        let path = self.payload_path(request_id, ext);
        let mut buf = Vec::new();
        let mut file = fs::File::open(&path)
            .map_err(|e| StoreError::NotFound(format!("{}: {}", path.display(), e)))?;
        file.read_to_end(&mut buf)
            .map_err(|e| StoreError::Io(format!("read payload {}: {}", path.display(), e)))?;
        if buf.len() > MAX_PAYLOAD_BYTES {
            return Err(StoreError::CorruptRecord(format!(
                "payload {} too large",
                path.display()
            )));
        }
        Ok(buf)
    }

    /// Delete a payload artifact (missing files are a no-op).
    pub fn delete_payload(&self, request_id: &str, ext: &str) -> Result<(), StoreError> {
        let path = self.payload_path(request_id, ext);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(format!(
                "delete payload {}: {}",
                path.display(),
                e
            ))),
        }
    }

    /// Remove all payload artifacts for a request (terminal state hygiene).
    pub fn cleanup_payloads(&self, request_id: &str) -> Result<(), StoreError> {
        self.delete_payload(request_id, ".bin")?;
        self.delete_payload(request_id, ".out")?;
        Ok(())
    }

    fn ensure_dirs(&self) -> Result<(), StoreError> {
        fs::create_dir_all(self.requests_dir())
            .map_err(|e| StoreError::Io(format!("state dir: {}", e)))
    }

    /// Start a new request record with all units in `Pending`.
    ///
    /// Fails with `AlreadyTerminal`-style errors only if record already exists
    /// in a terminal state; an existing running record is left untouched so a
    /// caller can resume it.
    pub fn start_request_at(
        &self,
        request_id: &str,
        url: &str,
        policy: &str,
        now: u64,
    ) -> Result<RequestRecord, StoreError> {
        self.ensure_dirs()?;
        let path = self.record_path(request_id);
        if path.exists() {
            let existing = self.load(request_id)?;
            if existing.status != RequestStatus::Running {
                return Err(StoreError::AlreadyTerminal(format!(
                    "request {} is {}",
                    request_id,
                    existing.status.as_str()
                )));
            }
            return Ok(existing);
        }
        let record = RequestRecord {
            request_id: request_id.to_string(),
            url: url.to_string(),
            status: RequestStatus::Running,
            created_at: now,
            policy: policy.to_string(),
            units: Vec::new(),
        };
        self.save(&record)?;
        Ok(record)
    }

    /// Declare the canonical list of work units for a request (idempotent).
    ///
    /// Existing units are never re-created or re-ordered; new ids are appended
    /// as `Pending`. Completed units keep their terminal state (dedupe).
    pub fn ensure_units_at(
        &self,
        request_id: &str,
        unit_ids: &[&str],
        now: u64,
    ) -> Result<RequestRecord, StoreError> {
        let mut record = self.load_or_start(request_id, now)?;
        for id in unit_ids {
            if !record.units.iter().any(|u| u.id == *id) {
                record.units.push(WorkUnit::new(id, now));
            }
        }
        self.save(&record)?;
        Ok(record)
    }

    fn load_or_start(&self, request_id: &str, now: u64) -> Result<RequestRecord, StoreError> {
        match self.load(request_id) {
            Ok(r) => Ok(r),
            Err(StoreError::NotFound(_)) => self.start_request_at(request_id, "", "resume", now),
            Err(e) => Err(e),
        }
    }

    pub fn load(&self, request_id: &str) -> Result<RequestRecord, StoreError> {
        let path = self.record_path(request_id);
        let mut buf = Vec::new();
        let mut file = fs::File::open(&path)
            .map_err(|e| StoreError::NotFound(format!("{}: {}", request_id, e)))?;
        file.read_to_end(&mut buf)
            .map_err(|e| StoreError::Io(format!("read {}: {}", path.display(), e)))?;
        if buf.len() > MAX_RECORD_BYTES {
            return Err(StoreError::CorruptRecord(request_id.to_string()));
        }
        let text = String::from_utf8_lossy(&buf);
        let value = json_parse(&text)
            .map_err(|e| StoreError::CorruptRecord(format!("{}: {}", request_id, e)))?;
        RequestRecord::from_json_value(&value)
            .ok_or_else(|| StoreError::CorruptRecord(request_id.to_string()))
    }

    pub fn save(&self, record: &RequestRecord) -> Result<(), StoreError> {
        self.ensure_dirs()?;
        let path = self.record_path(&record.request_id);
        let tmp = path.with_extension("json.tmp");
        let content = record.to_json_string();
        fs::write(&tmp, content)
            .map_err(|e| StoreError::Io(format!("write {}: {}", tmp.display(), e)))?;
        fs::rename(&tmp, &path)
            .map_err(|e| StoreError::Io(format!("rename {}: {}", path.display(), e)))?;
        Ok(())
    }

    pub fn list_request_ids(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(self.requests_dir()) else {
            return Vec::new();
        };
        let mut ids = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(stem) = name.strip_suffix(".json") {
                if !stem.ends_with(".tmp") {
                    ids.push(stem.to_string());
                }
            }
        }
        ids.sort();
        ids
    }

    /// Whether a unit is already completed (dedupe check).
    pub fn is_unit_completed(&self, request_id: &str, unit_id: &str) -> Result<bool, StoreError> {
        let record = self.load(request_id)?;
        Ok(record
            .units
            .iter()
            .any(|u| u.id == unit_id && u.status == UnitStatus::Completed))
    }

    /// Mark a unit as running (heartbeat stamp). A `completed` unit rejects
    /// this transition — this is the durable dedupe guard.
    pub fn start_unit_at(
        &self,
        request_id: &str,
        unit_id: &str,
        now: u64,
    ) -> Result<(), StoreError> {
        let mut record = self.load(request_id)?;
        let unit = record
            .units
            .iter_mut()
            .find(|u| u.id == unit_id)
            .ok_or_else(|| StoreError::NotFound(format!("unit {} in {}", unit_id, request_id)))?;
        match unit.status {
            UnitStatus::Completed => {
                return Err(StoreError::UnitAlreadyCompleted(unit_id.to_string()));
            }
            UnitStatus::Blocked | UnitStatus::Failed => {
                return Err(StoreError::AlreadyTerminal(format!(
                    "{} ({})",
                    unit_id,
                    unit.status.as_str()
                )));
            }
            UnitStatus::Pending | UnitStatus::Running => {
                unit.status = UnitStatus::Running;
                unit.heartbeat_at = now;
            }
        }
        self.save(&record)
    }

    /// Refresh the heartbeat of a running unit.
    pub fn heartbeat_at(
        &self,
        request_id: &str,
        unit_id: &str,
        now: u64,
    ) -> Result<(), StoreError> {
        let mut record = self.load(request_id)?;
        let unit = record
            .units
            .iter_mut()
            .find(|u| u.id == unit_id)
            .ok_or_else(|| StoreError::NotFound(format!("unit {} in {}", unit_id, request_id)))?;
        if unit.status != UnitStatus::Running {
            return Err(StoreError::AlreadyTerminal(format!(
                "{} is {}",
                unit_id,
                unit.status.as_str()
            )));
        }
        unit.heartbeat_at = now;
        self.save(&record)
    }

    /// Complete a unit. Returns `true` when this call transitioned the unit;
    /// returns `false` when it was already completed (idempotent, no error —
    /// the caller must simply not re-execute the effect).
    pub fn complete_unit_at(
        &self,
        request_id: &str,
        unit_id: &str,
        now: u64,
    ) -> Result<bool, StoreError> {
        let mut record = self.load(request_id)?;
        let unit = record
            .units
            .iter_mut()
            .find(|u| u.id == unit_id)
            .ok_or_else(|| StoreError::NotFound(format!("unit {} in {}", unit_id, request_id)))?;
        if unit.status == UnitStatus::Completed {
            return Ok(false);
        }
        if unit.is_terminal() {
            return Err(StoreError::AlreadyTerminal(format!(
                "{} is {}",
                unit_id,
                unit.status.as_str()
            )));
        }
        unit.status = UnitStatus::Completed;
        unit.heartbeat_at = now;
        unit.completed_at = Some(now);
        self.save(&record)?;
        Ok(true)
    }

    /// Transition a unit to `Blocked` (policy decision).
    pub fn block_unit_at(
        &self,
        request_id: &str,
        unit_id: &str,
        now: u64,
    ) -> Result<(), StoreError> {
        self._terminal_unit(request_id, unit_id, now, UnitStatus::Blocked)
    }

    /// Transition a unit to `Failed` (transient/unrecoverable).
    pub fn fail_unit_at(
        &self,
        request_id: &str,
        unit_id: &str,
        now: u64,
    ) -> Result<(), StoreError> {
        self._terminal_unit(request_id, unit_id, now, UnitStatus::Failed)
    }

    fn _terminal_unit(
        &self,
        request_id: &str,
        unit_id: &str,
        now: u64,
        status: UnitStatus,
    ) -> Result<(), StoreError> {
        let mut record = self.load(request_id)?;
        let unit = record
            .units
            .iter_mut()
            .find(|u| u.id == unit_id)
            .ok_or_else(|| StoreError::NotFound(format!("unit {} in {}", unit_id, request_id)))?;
        if unit.is_terminal() {
            return Ok(());
        }
        unit.status = status;
        unit.heartbeat_at = now;
        unit.completed_at = Some(now);
        self.save(&record)
    }

    /// Request-level terminal transitions. Payload artifacts are removed once
    /// a request reaches a terminal state (the response was either delivered
    /// or will never be resumed).
    pub fn complete_request_at(&self, request_id: &str, _now: u64) -> Result<(), StoreError> {
        let mut record = self.load(request_id)?;
        record.status = RequestStatus::Completed;
        self.save(&record)?;
        let _ = self.cleanup_payloads(request_id);
        Ok(())
    }

    pub fn block_request_at(&self, request_id: &str, _now: u64) -> Result<(), StoreError> {
        let mut record = self.load(request_id)?;
        record.status = RequestStatus::Blocked;
        self.save(&record)?;
        let _ = self.cleanup_payloads(request_id);
        Ok(())
    }

    pub fn fail_request_at(&self, request_id: &str, _now: u64) -> Result<(), StoreError> {
        let mut record = self.load(request_id)?;
        record.status = RequestStatus::Failed;
        self.save(&record)?;
        let _ = self.cleanup_payloads(request_id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Recovery policy + coordinator
// ---------------------------------------------------------------------------

/// Recovery decision for an interrupted request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPolicy {
    /// Re-open fresh running units as `Pending` so the pipeline continues
    /// from the last persisted unit (at-least-once with per-unit dedupe).
    Resume,
    /// Mark any interrupted request as `Blocked` (fail closed).
    Block,
}

impl RecoveryPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Resume => "resume",
            Self::Block => "block",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "resume" => Some(Self::Resume),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

/// Auditable outcome kind for a recovery decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOutcome {
    Resumed,
    Blocked,
    Failed,
}

impl RecoveryOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Resumed => "resumed",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
        }
    }
}

/// One recovery decision item (request + unit level).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryItem {
    pub request_id: String,
    pub unit_id: String,
    pub outcome: RecoveryOutcome,
    pub reason: String,
}

/// Summary of a recovery pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub items: Vec<RecoveryItem>,
    pub resumed: usize,
    pub blocked: usize,
    pub failed: usize,
}

impl RecoveryReport {
    fn push(&mut self, item: RecoveryItem) {
        match item.outcome {
            RecoveryOutcome::Resumed => self.resumed += 1,
            RecoveryOutcome::Blocked => self.blocked += 1,
            RecoveryOutcome::Failed => self.failed += 1,
        }
        self.items.push(item);
    }
}

/// An append-only audit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub ts: u64,
    pub outcome: RecoveryOutcome,
    pub request_id: String,
    pub unit_id: String,
    pub reason: String,
}

impl AuditEntry {
    fn to_json_line(&self) -> String {
        let v = JsonVal::Obj(vec![
            ("ts".to_string(), JsonVal::Num(self.ts)),
            (
                "outcome".to_string(),
                JsonVal::Str(self.outcome.as_str().to_string()),
            ),
            (
                "request_id".to_string(),
                JsonVal::Str(self.request_id.clone()),
            ),
            ("unit_id".to_string(), JsonVal::Str(self.unit_id.clone())),
            ("reason".to_string(), JsonVal::Str(self.reason.clone())),
        ]);
        json_to_string(&v)
    }

    fn from_json_line(line: &str) -> Option<Self> {
        let value = json_parse(line).ok()?;
        let obj = match value {
            JsonVal::Obj(o) => o,
            _ => return None,
        };
        let get_str = |key: &str| {
            obj.iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, val)| match val {
                    JsonVal::Str(s) => Some(s.clone()),
                    _ => None,
                })
        };
        let get_num = |key: &str| {
            obj.iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, val)| match val {
                    JsonVal::Num(n) => Some(*n),
                    _ => None,
                })
        };
        Some(Self {
            ts: get_num("ts").unwrap_or(0),
            outcome: get_str("outcome").and_then(|s| match s.as_str() {
                "resumed" => Some(RecoveryOutcome::Resumed),
                "blocked" => Some(RecoveryOutcome::Blocked),
                "failed" => Some(RecoveryOutcome::Failed),
                _ => None,
            })?,
            request_id: get_str("request_id")?,
            unit_id: get_str("unit_id").unwrap_or_default(),
            reason: get_str("reason").unwrap_or_default(),
        })
    }
}

/// Append one audit entry to `<state_dir>/audit.log`.
pub fn audit_append(store: &DurableStore, entry: &AuditEntry) -> Result<(), StoreError> {
    fs::create_dir_all(store.state_dir())
        .map_err(|e| StoreError::Io(format!("state dir: {}", e)))?;
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    let mut file = options
        .open(store.audit_path())
        .map_err(|e| StoreError::Io(format!("open audit: {}", e)))?;
    let mut line = entry.to_json_line();
    line.push('\n');
    writeln!(file, "{}", line.trim_end())
        .map_err(|e| StoreError::Io(format!("append audit: {}", e)))?;
    Ok(())
}

/// Read all parsed audit entries (unparseable lines are skipped).
pub fn audit_read(store: &DurableStore) -> Vec<AuditEntry> {
    let mut buf = Vec::new();
    let mut file = match fs::File::open(store.audit_path()) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    if file.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    if buf.len() > 1024 * 1024 {
        buf.truncate(1024 * 1024);
    }
    let text = String::from_utf8_lossy(&buf);
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.len() > MAX_AUDIT_LINE_BYTES {
            continue;
        }
        if let Some(e) = AuditEntry::from_json_line(line) {
            entries.push(e);
        }
    }
    entries
}

/// Run one recovery pass with an explicit clock (deterministic for tests).
///
/// Decision table per request record:
///
/// | State                                   | Policy `Resume`      | Policy `Block`   |
/// |-----------------------------------------|----------------------|------------------|
/// | unit running, heartbeat fresh           | `resumed` (pending)  | `blocked`        |
/// | unit running, heartbeat stale (orphan)  | `failed`             | `blocked`        |
/// | all units completed, request not closed | `resumed` (finalize) | `resumed`        |
/// | record file unreadable/corrupt          | `failed`             | `failed`         |
///
/// Completed units are never modified (dedupe). Every decision is appended to
/// the audit log with an outcome in {resumed, blocked, failed}.
pub fn recover_pending_at(
    store: &DurableStore,
    policy: RecoveryPolicy,
    now: u64,
) -> RecoveryReport {
    let ttl_ms = store.ttl_secs().saturating_mul(1000);
    let mut report = RecoveryReport::default();

    for request_id in store.list_request_ids() {
        let mut record = match store.load(&request_id) {
            Ok(r) => r,
            Err(_) => {
                // File exists but cannot be parsed: interrupted write.
                let item = RecoveryItem {
                    request_id: request_id.clone(),
                    unit_id: String::new(),
                    outcome: RecoveryOutcome::Failed,
                    reason: "unreadable_record".to_string(),
                };
                report.push(item.clone());
                let _ = audit_append(
                    store,
                    &AuditEntry {
                        ts: now,
                        outcome: item.outcome,
                        request_id: item.request_id.clone(),
                        unit_id: item.unit_id.clone(),
                        reason: item.reason.clone(),
                    },
                );
                continue;
            }
        };

        if record.status == RequestStatus::Completed
            || record.status == RequestStatus::Blocked
            || record.status == RequestStatus::Failed
        {
            continue;
        }

        let mut changed = false;
        let mut any_failed = false;
        let mut any_blocked = false;

        for unit in record.units.iter_mut() {
            if unit.is_terminal() {
                continue;
            }
            let stale = now.saturating_sub(unit.heartbeat_at) > ttl_ms;
            let (outcome, reason) = match policy {
                RecoveryPolicy::Block => {
                    unit.status = UnitStatus::Blocked;
                    unit.completed_at = Some(now);
                    any_blocked = true;
                    (
                        RecoveryOutcome::Blocked,
                        if stale {
                            "heartbeat_ttl_expired".to_string()
                        } else {
                            "recovery_policy_block".to_string()
                        },
                    )
                }
                RecoveryPolicy::Resume => {
                    if stale {
                        unit.status = UnitStatus::Failed;
                        unit.completed_at = Some(now);
                        any_failed = true;
                        (RecoveryOutcome::Failed, "heartbeat_ttl_expired".to_string())
                    } else {
                        unit.status = UnitStatus::Pending;
                        (RecoveryOutcome::Resumed, "fresh_heartbeat".to_string())
                    }
                }
            };
            changed = true;
            report.push(RecoveryItem {
                request_id: request_id.clone(),
                unit_id: unit.id.clone(),
                outcome,
                reason: reason.clone(),
            });
            let _ = audit_append(
                store,
                &AuditEntry {
                    ts: now,
                    outcome,
                    request_id: request_id.clone(),
                    unit_id: unit.id.clone(),
                    reason,
                },
            );
        }

        // All units completed while the request never closed (crash between
        // the last unit completion and the request close): finalize it. The
        // request is treated as resumable-to-delivery (`.out` payload is kept).
        let all_units_completed = !record.units.is_empty()
            && record
                .units
                .iter()
                .all(|u| u.status == UnitStatus::Completed);

        if !changed && all_units_completed {
            record.status = RequestStatus::Completed;
            report.push(RecoveryItem {
                request_id: request_id.clone(),
                unit_id: String::new(),
                outcome: RecoveryOutcome::Resumed,
                reason: "finalize_completed".to_string(),
            });
            let _ = audit_append(
                store,
                &AuditEntry {
                    ts: now,
                    outcome: RecoveryOutcome::Resumed,
                    request_id: request_id.clone(),
                    unit_id: String::new(),
                    reason: "finalize_completed".to_string(),
                },
            );
            let _ = store.save(&record);
            continue;
        }

        if !changed {
            continue;
        }

        if any_blocked {
            record.status = RequestStatus::Blocked;
        } else if any_failed {
            record.status = RequestStatus::Failed;
        } else {
            record.status = RequestStatus::Running;
        }

        let _ = store.save(&record);
        // Terminal outcomes shed their payload artifacts; a finalized
        // (completed) request keeps `.out` so `--resume` can still deliver it.
        if record.status == RequestStatus::Blocked || record.status == RequestStatus::Failed {
            let _ = store.cleanup_payloads(&request_id);
        }
    }

    report
}

/// Convenience wrapper using the current wall clock.
pub fn recover_pending(store: &DurableStore, policy: RecoveryPolicy) -> RecoveryReport {
    recover_pending_at(store, policy, current_time_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("agp-recovery-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn json_roundtrip_escapes_and_unicode() {
        let v = JsonVal::Obj(vec![
            (
                "url".to_string(),
                JsonVal::Str("http://a.b/x?q=\"q\"\\n\\t&\u{00e9}".to_string()),
            ),
            ("n".to_string(), JsonVal::Num(42)),
        ]);
        let s = json_to_string(&v);
        let parsed = json_parse(&s).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn json_parse_rejects_float_and_trailing() {
        assert!(json_parse("1.5").is_err());
        assert!(json_parse("{}x").is_err());
        assert!(json_parse("{\"a\":1,").is_err());
    }

    #[test]
    fn store_start_and_load_roundtrip() {
        let dir = temp_dir("roundtrip");
        let store = DurableStore::new(&dir, 300);
        let now = 1_000_000;
        let rec = store
            .start_request_at("req-1", "http://example.com/", "resume", now)
            .unwrap();
        assert_eq!(rec.status, RequestStatus::Running);
        store
            .ensure_units_at("req-1", &["parse", "fetch"], now)
            .unwrap();
        let loaded = store.load("req-1").unwrap();
        assert_eq!(loaded.url, "http://example.com/");
        assert_eq!(loaded.units.len(), 2);
        assert_eq!(loaded.units[0].id, "parse");
        assert_eq!(loaded.units[0].status, UnitStatus::Pending);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn completed_unit_never_restarts_dedupe() {
        let dir = temp_dir("dedupe");
        let store = DurableStore::new(&dir, 300);
        let now = 1_000_000;
        store
            .start_request_at("req-1", "http://example.com/", "resume", now)
            .unwrap();
        store.ensure_units_at("req-1", &["fetch"], now).unwrap();
        store.start_unit_at("req-1", "fetch", now).unwrap();
        assert!(store.complete_unit_at("req-1", "fetch", now + 1).unwrap());
        // Second completion is a no-op (false = already completed).
        assert!(!store.complete_unit_at("req-1", "fetch", now + 2).unwrap());
        // Starting a completed unit is rejected.
        let err = store.start_unit_at("req-1", "fetch", now + 3).unwrap_err();
        assert_eq!(err, StoreError::UnitAlreadyCompleted("fetch".to_string()));
        // Recovery must NOT restart the completed unit — it only finalizes the
        // request-level record (crash between unit completion and close).
        let report = recover_pending_at(&store, RecoveryPolicy::Resume, now + 10);
        assert_eq!(report.resumed, 1);
        assert_eq!(report.items[0].reason, "finalize_completed");
        let loaded = store.load("req-1").unwrap();
        assert_eq!(loaded.units[0].status, UnitStatus::Completed);
        assert_eq!(loaded.units[0].completed_at, Some(now + 1));
        assert_eq!(loaded.status, RequestStatus::Completed);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resume_policy_reopens_fresh_running_unit() {
        let dir = temp_dir("resume");
        let store = DurableStore::new(&dir, 300);
        let now = 1_000_000;
        store
            .start_request_at("req-1", "http://example.com/", "resume", now)
            .unwrap();
        store
            .ensure_units_at("req-1", &["parse", "fetch"], now)
            .unwrap();
        // parse completed, fetch running with a fresh heartbeat
        store.complete_unit_at("req-1", "parse", now + 1).unwrap();
        store.start_unit_at("req-1", "fetch", now + 2).unwrap();

        let report = recover_pending_at(&store, RecoveryPolicy::Resume, now + 3);
        assert_eq!(report.resumed, 1);
        assert_eq!(report.blocked, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(report.items[0].outcome, RecoveryOutcome::Resumed);
        assert_eq!(report.items[0].unit_id, "fetch");
        assert_eq!(report.items[0].reason, "fresh_heartbeat");

        let loaded = store.load("req-1").unwrap();
        assert_eq!(loaded.units[0].status, UnitStatus::Completed); // untouched
        assert_eq!(loaded.units[1].status, UnitStatus::Pending); // reopened
        let audit = audit_read(&store);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].outcome, RecoveryOutcome::Resumed);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_orphan_detected_and_failed_under_resume() {
        let dir = temp_dir("orphan");
        let store = DurableStore::new(&dir, 300);
        let now = 1_000_000;
        store
            .start_request_at("req-1", "http://example.com/", "resume", now)
            .unwrap();
        store.ensure_units_at("req-1", &["fetch"], now).unwrap();
        // running unit with a stale heartbeat (TTL=300s → 300_000ms)
        store.start_unit_at("req-1", "fetch", now).unwrap();

        let report = recover_pending_at(&store, RecoveryPolicy::Resume, now + 300_000 + 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.items[0].outcome, RecoveryOutcome::Failed);
        assert_eq!(report.items[0].reason, "heartbeat_ttl_expired");

        let loaded = store.load("req-1").unwrap();
        assert_eq!(loaded.units[0].status, UnitStatus::Failed);
        assert_eq!(loaded.status, RequestStatus::Failed);
        let audit = audit_read(&store);
        assert_eq!(audit[0].outcome, RecoveryOutcome::Failed);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn block_policy_blocks_fresh_and_stale() {
        let dir = temp_dir("block");
        let store = DurableStore::new(&dir, 300);
        let now = 1_000_000;
        store
            .start_request_at("req-1", "http://example.com/", "block", now)
            .unwrap();
        store.ensure_units_at("req-1", &["fetch"], now).unwrap();
        store.start_unit_at("req-1", "fetch", now).unwrap();

        let report = recover_pending_at(&store, RecoveryPolicy::Block, now + 1);
        assert_eq!(report.blocked, 1);
        assert_eq!(report.items[0].reason, "recovery_policy_block");
        let loaded = store.load("req-1").unwrap();
        assert_eq!(loaded.units[0].status, UnitStatus::Blocked);
        assert_eq!(loaded.status, RequestStatus::Blocked);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn all_units_completed_finalizes_request_as_resumed() {
        let dir = temp_dir("finalize");
        let store = DurableStore::new(&dir, 300);
        let now = 1_000_000;
        store
            .start_request_at("req-1", "http://example.com/", "resume", now)
            .unwrap();
        store.ensure_units_at("req-1", &["parse"], now).unwrap();
        store.complete_unit_at("req-1", "parse", now + 1).unwrap();
        // request left Running (crash between unit completion and request close)
        let report = recover_pending_at(&store, RecoveryPolicy::Resume, now + 2);
        assert_eq!(report.resumed, 1);
        assert_eq!(report.items[0].reason, "finalize_completed");
        let loaded = store.load("req-1").unwrap();
        assert_eq!(loaded.status, RequestStatus::Completed);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_record_emits_failed() {
        let dir = temp_dir("corrupt");
        let store = DurableStore::new(&dir, 300);
        store
            .start_request_at("req-1", "http://example.com/", "resume", 1)
            .unwrap();
        // Corrupt the file after creation.
        let path = store.record_path("req-1");
        fs::write(&path, b"{\"request_id\":\"req-1\", trailing").unwrap();
        let report = recover_pending_at(&store, RecoveryPolicy::Resume, 2);
        assert_eq!(report.failed, 1);
        assert_eq!(report.items[0].reason, "unreadable_record");
        let audit = audit_read(&store);
        assert_eq!(audit[0].outcome, RecoveryOutcome::Failed);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovery_never_touches_terminal_records() {
        let dir = temp_dir("terminal-skip");
        let store = DurableStore::new(&dir, 300);
        let now = 1_000_000;
        store
            .start_request_at("req-done", "http://example.com/", "resume", now)
            .unwrap();
        store.ensure_units_at("req-done", &["parse"], now).unwrap();
        store
            .complete_unit_at("req-done", "parse", now + 1)
            .unwrap();
        store.complete_request_at("req-done", now + 2).unwrap();
        let report = recover_pending_at(&store, RecoveryPolicy::Block, now + 3);
        assert_eq!(report.items.len(), 0);
        let audit = audit_read(&store);
        assert!(audit.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn heartbeat_refreshes_running_unit() {
        let dir = temp_dir("heartbeat");
        let store = DurableStore::new(&dir, 300);
        let now = 1_000_000;
        store
            .start_request_at("req-1", "http://example.com/", "resume", now)
            .unwrap();
        store.ensure_units_at("req-1", &["fetch"], now).unwrap();
        store.start_unit_at("req-1", "fetch", now).unwrap();
        store.heartbeat_at("req-1", "fetch", now + 100).unwrap();
        let loaded = store.load("req-1").unwrap();
        assert_eq!(loaded.units[0].heartbeat_at, now + 100);
        // A refreshed heartbeat keeps the unit alive well past the original
        // start: recovery reopens it as pending (resumed), never fails it.
        let report = recover_pending_at(&store, RecoveryPolicy::Resume, now + 299_000);
        assert_eq!(report.resumed, 1);
        assert_eq!(report.failed, 0);
        assert_eq!(report.items[0].reason, "fresh_heartbeat");
        let loaded = store.load("req-1").unwrap();
        assert_eq!(loaded.units[0].status, UnitStatus::Pending);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_log_is_append_only_and_parseable() {
        let dir = temp_dir("audit");
        let store = DurableStore::new(&dir, 300);
        audit_append(
            &store,
            &AuditEntry {
                ts: 1,
                outcome: RecoveryOutcome::Resumed,
                request_id: "r1".to_string(),
                unit_id: "fetch".to_string(),
                reason: "fresh_heartbeat".to_string(),
            },
        )
        .unwrap();
        audit_append(
            &store,
            &AuditEntry {
                ts: 2,
                outcome: RecoveryOutcome::Blocked,
                request_id: "r2".to_string(),
                unit_id: "fetch".to_string(),
                reason: "recovery_policy_block".to_string(),
            },
        )
        .unwrap();
        let entries = audit_read(&store);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].outcome, RecoveryOutcome::Resumed);
        assert_eq!(entries[1].outcome, RecoveryOutcome::Blocked);
        let _ = fs::remove_dir_all(&dir);
    }
}
