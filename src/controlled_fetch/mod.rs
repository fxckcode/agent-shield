//! Controlled fetch module — security-hardened HTTP fetch for the agent proxy.
//!
//! Provides SSRF protection, redirect validation, content filtering,
//! prompt-injection detection, and untrusted-data enveloping.

mod content_filter;
mod envelope;
mod error;
mod injection_detector;
pub mod ip_validator;
mod policy;
mod redirect;
mod request;

pub use envelope::{ContentClassification, UntrustedEnvelope};
pub use error::{BlockReason, FetchError};
pub use policy::FetchPolicy;
pub use request::FetchRequest;

use content_filter::validate_response;
use envelope::wrap_untrusted;
use injection_detector::classify_content;
use ip_validator::validate_url_target;
use redirect::{
    follow_redirects, follow_redirects_with_transport, FetchResponse, HttpTransport,
    SocketValidatingTransport,
};

use crate::recovery::{DurableStore, RequestStatus, StoreError};

/// Test-only entry point for the injection classifier.
///
/// Allows integration tests to exercise the prompt-injection detection
/// step in isolation without requiring a full network round-trip.
pub fn classify_content_for_test(
    body: &[u8],
    policy: &FetchPolicy,
    correlation_id: &str,
) -> Result<Vec<u8>, FetchError> {
    classify_content(body, policy, correlation_id)
}

/// Execute a fetch with full security policy enforcement.
///
/// Returns the content wrapped in an untrusted-data envelope on success,
/// or a `FetchError` with a safe reason code and correlation id on block.
pub fn fetch_with_policy(
    req: &FetchRequest,
    policy: &FetchPolicy,
) -> Result<UntrustedEnvelope, FetchError> {
    let correlation_id = uuid::Uuid::new_v4().to_string();

    // Step 0: Reject unsupported schemes before any DNS/network access
    let parsed_url = url::Url::parse(req.url())
        .map_err(|_| FetchError::new(BlockReason::UnsupportedScheme, &correlation_id))?;
    if parsed_url.scheme() != "http" {
        return Err(FetchError::new(
            BlockReason::UnsupportedScheme,
            &correlation_id,
        ));
    }

    // Step 1: Validate the initial URL target against IP policy
    validate_url_target(req.url(), policy, &correlation_id)?;

    // Step 2: Fetch with redirect following and per-hop validation
    let response = follow_redirects(req, policy, &correlation_id)?;

    // Step 3: Validate content-type and body size
    let body = validate_response(&response, policy, &correlation_id)?;

    // Step 4: Prompt-injection detection
    let safe_content = classify_content(&body, policy, &correlation_id)?;

    // Step 5: Wrap in untrusted-data envelope
    Ok(wrap_untrusted(safe_content, &correlation_id))
}

// ---------------------------------------------------------------------------
// Durable fetch — work-unit persistence + resume without duplicate effects
// ---------------------------------------------------------------------------

/// Canonical durable work units of the controlled-fetch pipeline, in
/// execution order. `fetch` is the only unit with external side effects
/// (network I/O); `process` (validate + classify + wrap) is pure computation
/// whose result is persisted so a resumed run can deliver it without
/// recomputation.
pub const DURABLE_FETCH_UNITS: [&str; 4] = ["parse", "validate_target", "fetch", "process"];

/// Payload artifact extension for the raw fetch response (written when the
/// `fetch` unit completes).
const PAYLOAD_RESPONSE_EXT: &str = ".bin";
/// Payload artifact extension for the final validated content (written when
/// the `process` unit completes).
const PAYLOAD_OUTPUT_EXT: &str = ".out";

/// Map a durable-store failure into a safe, closed `FetchError`. The detail
/// is deliberately dropped: reason codes never echo paths or store internals.
fn durable_err(correlation_id: &str, _store_err: StoreError) -> FetchError {
    FetchError::new(BlockReason::DurableStoreError, correlation_id)
}

fn completed(store: &DurableStore, rid: &str, unit: &str, corr: &str) -> Result<bool, FetchError> {
    store
        .is_unit_completed(rid, unit)
        .map_err(|e| durable_err(corr, e))
}

/// Start a unit, tolerating a concurrent/prior terminal transition (the
/// dedupe guard at the store level is defense-in-depth; the pipeline decides
/// from `is_unit_completed` before running).
fn start_unit_ok(
    store: &DurableStore,
    rid: &str,
    unit: &str,
    now: u64,
    corr: &str,
) -> Result<(), FetchError> {
    match store.start_unit_at(rid, unit, now) {
        Ok(()) => Ok(()),
        Err(StoreError::UnitAlreadyCompleted(_)) | Err(StoreError::AlreadyTerminal(_)) => Ok(()),
        Err(e) => Err(durable_err(corr, e)),
    }
}

/// Mark a unit completed; an already-terminal unit is a no-op (idempotent).
fn complete_ok(
    store: &DurableStore,
    rid: &str,
    unit: &str,
    now: u64,
    corr: &str,
) -> Result<(), FetchError> {
    match store.complete_unit_at(rid, unit, now) {
        Ok(_) => Ok(()),
        Err(StoreError::AlreadyTerminal(_)) => Ok(()),
        Err(e) => Err(durable_err(corr, e)),
    }
}

/// Fail the unit and the whole request (best effort persistence before the
/// caller returns the original block error).
fn fail_unit_and_request(
    store: &DurableStore,
    rid: &str,
    unit: &str,
    now: u64,
    _corr: &str,
) -> Result<(), FetchError> {
    let _ = store.fail_unit_at(rid, unit, now);
    let _ = store.fail_request_at(rid, now);
    Ok(())
}

/// Execute a fetch with full security policy enforcement AND durable
/// work-unit persistence.
///
/// Every pipeline step is recorded in `store`. A completed work unit is never
/// executed twice (dedupe): if `request_id` already has a durable record from
/// an interrupted run, execution resumes from the last persisted unit and the
/// raw fetch response is loaded from the persisted payload instead of hitting
/// the network again.
pub fn fetch_with_policy_durable(
    req: &FetchRequest,
    policy: &FetchPolicy,
    request_id: &str,
    store: &DurableStore,
) -> Result<UntrustedEnvelope, FetchError> {
    fetch_with_policy_durable_with_transport(
        req,
        policy,
        request_id,
        store,
        &SocketValidatingTransport,
    )
}

/// Transport-parameterized variant of `fetch_with_policy_durable` so the
/// pipeline can be exercised with a mock transport in tests.
pub(crate) fn fetch_with_policy_durable_with_transport(
    req: &FetchRequest,
    policy: &FetchPolicy,
    request_id: &str,
    store: &DurableStore,
    transport: &dyn HttpTransport,
) -> Result<UntrustedEnvelope, FetchError> {
    let correlation_id = request_id.to_string();
    let now = crate::recovery::current_time_millis();

    // Terminal records cannot be resumed (policy already decided).
    if let Ok(rec) = store.load(request_id) {
        match rec.status {
            RequestStatus::Completed => {
                // Recovery may have finalized the request WITHOUT cleaning the
                // output: deliver the persisted result instead of recomputing.
                if let Ok(bytes) = store.load_payload(request_id, PAYLOAD_OUTPUT_EXT) {
                    let envelope = wrap_untrusted(bytes, &correlation_id);
                    let _ = store.complete_request_at(request_id, now);
                    return Ok(envelope);
                }
                return Err(FetchError::new(
                    BlockReason::DurableStoreError,
                    &correlation_id,
                ));
            }
            RequestStatus::Blocked | RequestStatus::Failed => {
                return Err(FetchError::new(
                    BlockReason::DurableStoreError,
                    &correlation_id,
                ));
            }
            RequestStatus::Running => {}
        }
    }

    // Durable record: create a fresh one or reuse the persisted one.
    if store.load(request_id).is_err() {
        store
            .start_request_at(request_id, req.url(), "resume", now)
            .map_err(|e| durable_err(&correlation_id, e))?;
    }
    store
        .ensure_units_at(request_id, &DURABLE_FETCH_UNITS, now)
        .map_err(|e| durable_err(&correlation_id, e))?;

    // Step 0 — parse + scheme validation (`parse` unit; pure, deduped)
    if !completed(store, request_id, "parse", &correlation_id)? {
        start_unit_ok(store, request_id, "parse", now, &correlation_id)?;
        let parsed_url = url::Url::parse(req.url())
            .map_err(|_| FetchError::new(BlockReason::UnsupportedScheme, &correlation_id))?;
        if parsed_url.scheme() != "http" {
            fail_unit_and_request(store, request_id, "parse", now, &correlation_id)?;
            return Err(FetchError::new(
                BlockReason::UnsupportedScheme,
                &correlation_id,
            ));
        }
        complete_ok(store, request_id, "parse", now, &correlation_id)?;
    }

    // Step 1 — validate the initial target (`validate_target` unit; pure)
    if !completed(store, request_id, "validate_target", &correlation_id)? {
        start_unit_ok(store, request_id, "validate_target", now, &correlation_id)?;
        if let Err(e) = validate_url_target(req.url(), policy, &correlation_id) {
            fail_unit_and_request(store, request_id, "validate_target", now, &correlation_id)?;
            return Err(e);
        }
        complete_ok(store, request_id, "validate_target", now, &correlation_id)?;
    }

    // Step 2 — network fetch with redirects (`fetch` unit; THE deduped side
    // effect). The raw response is persisted BEFORE the unit completes so any
    // resumed run continues from the payload instead of re-fetching.
    let fetch_response: Option<FetchResponse> =
        if !completed(store, request_id, "fetch", &correlation_id)? {
            start_unit_ok(store, request_id, "fetch", now, &correlation_id)?;
            let response =
                match follow_redirects_with_transport(req, policy, &correlation_id, transport) {
                    Ok(r) => r,
                    Err(e) => {
                        fail_unit_and_request(store, request_id, "fetch", now, &correlation_id)?;
                        return Err(e);
                    }
                };
            store
                .save_payload(
                    request_id,
                    PAYLOAD_RESPONSE_EXT,
                    &encode_response(&response),
                )
                .map_err(|e| durable_err(&correlation_id, e))?;
            complete_ok(store, request_id, "fetch", now, &correlation_id)?;
            Some(response)
        } else {
            // Resumed: load the persisted response — the network effect is NOT
            // re-executed.
            let bytes = store
                .load_payload(request_id, PAYLOAD_RESPONSE_EXT)
                .map_err(|e| durable_err(&correlation_id, e))?;
            Some(decode_response(&bytes).map_err(|_| {
                durable_err(
                    &correlation_id,
                    StoreError::CorruptRecord(request_id.to_string()),
                )
            })?)
        };

    // Step 3 — validate + classify + wrap (`process` unit; pure computation).
    if completed(store, request_id, "process", &correlation_id)? {
        // Resumed after the full pipeline ran: deliver the persisted output.
        let bytes = store
            .load_payload(request_id, PAYLOAD_OUTPUT_EXT)
            .map_err(|e| durable_err(&correlation_id, e))?;
        let envelope = wrap_untrusted(bytes, &correlation_id);
        store
            .complete_request_at(request_id, now)
            .map_err(|e| durable_err(&correlation_id, e))?;
        return Ok(envelope);
    }
    start_unit_ok(store, request_id, "process", now, &correlation_id)?;
    let response = fetch_response
        .ok_or_else(|| FetchError::new(BlockReason::TransportError, &correlation_id))?;
    let body = match validate_response(&response, policy, &correlation_id) {
        Ok(b) => b,
        Err(e) => {
            fail_unit_and_request(store, request_id, "process", now, &correlation_id)?;
            return Err(e);
        }
    };
    let safe_content = match classify_content(&body, policy, &correlation_id) {
        Ok(c) => c,
        Err(e) => {
            fail_unit_and_request(store, request_id, "process", now, &correlation_id)?;
            return Err(e);
        }
    };
    store
        .save_payload(request_id, PAYLOAD_OUTPUT_EXT, &safe_content)
        .map_err(|e| durable_err(&correlation_id, e))?;
    complete_ok(store, request_id, "process", now, &correlation_id)?;

    let envelope = wrap_untrusted(safe_content, &correlation_id);
    store
        .complete_request_at(request_id, now)
        .map_err(|e| durable_err(&correlation_id, e))?;
    Ok(envelope)
}

/// Serialize a `FetchResponse` into the payload artifact format:
/// `status\n final_url\n header_count\n name: value\n ... \n\n body`.
fn encode_response(response: &FetchResponse) -> Vec<u8> {
    let mut out = Vec::with_capacity(response.body.len() + 256);
    out.extend_from_slice(response.status_code.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(response.final_url.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(response.headers.len().to_string().as_bytes());
    out.push(b'\n');
    for (name, value) in &response.headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    }
    out.push(b'\n');
    out.extend_from_slice(&response.body);
    out
}

/// Parse a payload artifact produced by [`encode_response`].
fn decode_response(bytes: &[u8]) -> Result<FetchResponse, ()> {
    let mut pos = 0usize;
    let status_line = take_payload_line(bytes, &mut pos)?;
    let status_code = status_line.parse::<u16>().map_err(|_| ())?;
    let final_url = take_payload_line(bytes, &mut pos)?;
    let count_line = take_payload_line(bytes, &mut pos)?;
    let header_count = count_line.parse::<usize>().map_err(|_| ())?;
    let mut headers = Vec::with_capacity(header_count);
    for _ in 0..header_count {
        let line = take_payload_line(bytes, &mut pos)?;
        let (name, value) = line.split_once(": ").ok_or(())?;
        headers.push((name.to_string(), value.to_string()));
    }
    // Blank line separating headers from the body.
    let _blank = take_payload_line(bytes, &mut pos)?;
    let body = bytes[pos..].to_vec();
    Ok(FetchResponse {
        status_code,
        headers,
        body,
        final_url,
    })
}

/// Read one `\n`-terminated line as UTF-8 (without the terminator).
fn take_payload_line(bytes: &[u8], pos: &mut usize) -> Result<String, ()> {
    let start = *pos;
    while *pos < bytes.len() && bytes[*pos] != b'\n' {
        *pos += 1;
    }
    if *pos >= bytes.len() {
        return Err(());
    }
    let line = std::str::from_utf8(&bytes[start..*pos]).map_err(|_| ())?;
    *pos += 1;
    Ok(line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{RequestStatus, UnitStatus};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock transport that counts every network execution.
    struct CountingTransport {
        calls: AtomicUsize,
    }

    impl CountingTransport {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl HttpTransport for CountingTransport {
        fn execute(
            &self,
            request: &FetchRequest,
            _policy: &FetchPolicy,
            _correlation_id: &str,
        ) -> Result<FetchResponse, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(FetchResponse {
                status_code: 200,
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                body: b"durable body".to_vec(),
                final_url: request.url().to_string(),
            })
        }
    }

    fn temp_store(name: &str) -> (DurableStore, PathBuf) {
        let mut dir = std::env::temp_dir();
        dir.push(format!("agp-durable-fetch-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (DurableStore::new(&dir, 300), dir)
    }

    fn sample_request() -> FetchRequest {
        // TEST-NET-3: a public, non-routable literal IP — DNS-free and
        // policy-allowed, so tests never depend on network or DNS.
        FetchRequest::new("http://203.0.113.1/page")
    }

    #[test]
    fn durable_fresh_run_executes_fetch_once_and_completes() {
        let (store, dir) = temp_store("fresh");
        let transport = CountingTransport::new();
        let policy = FetchPolicy::default();

        let env = fetch_with_policy_durable_with_transport(
            &sample_request(),
            &policy,
            "req-fresh",
            &store,
            &transport,
        )
        .expect("durable fetch should succeed");

        assert_eq!(env.body_str(), "durable body");
        assert_eq!(transport.calls(), 1);
        let rec = store.load("req-fresh").unwrap();
        assert_eq!(rec.status, RequestStatus::Completed);
        assert!(rec.units.iter().all(|u| u.status == UnitStatus::Completed));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn durable_resume_never_re_executes_completed_fetch_unit() {
        let (store, dir) = temp_store("resume");
        let transport = CountingTransport::new();

        // Simulate a crash AFTER the `fetch` unit completed (raw response
        // persisted) but BEFORE the `process` unit ran.
        let now = crate::recovery::current_time_millis();
        store
            .start_request_at("req-interrupted", "http://203.0.113.1/page", "resume", now)
            .unwrap();
        store
            .ensure_units_at("req-interrupted", &DURABLE_FETCH_UNITS, now)
            .unwrap();
        for unit in ["parse", "validate_target", "fetch"] {
            store.start_unit_at("req-interrupted", unit, now).unwrap();
            store
                .complete_unit_at("req-interrupted", unit, now)
                .unwrap();
        }
        let response = FetchResponse {
            status_code: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: b"durable body".to_vec(),
            final_url: "http://203.0.113.1/page".to_string(),
        };
        store
            .save_payload(
                "req-interrupted",
                PAYLOAD_RESPONSE_EXT,
                &encode_response(&response),
            )
            .unwrap();

        // The resumed run must NOT hit the network: the completed `fetch`
        // unit is loaded from the persisted payload (AC: no duplicate side
        // effects, no re-execution of a completed unit).
        let policy = FetchPolicy::default();
        let env = fetch_with_policy_durable_with_transport(
            &sample_request(),
            &policy,
            "req-interrupted",
            &store,
            &transport,
        )
        .expect("resumed durable fetch should succeed");

        assert_eq!(env.body_str(), "durable body");
        assert_eq!(transport.calls(), 0, "completed fetch unit re-executed");
        let rec = store.load("req-interrupted").unwrap();
        assert_eq!(rec.status, RequestStatus::Completed);
        assert!(rec.units.iter().all(|u| u.status == UnitStatus::Completed));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
