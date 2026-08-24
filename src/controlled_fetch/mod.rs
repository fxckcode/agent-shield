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
use redirect::follow_redirects;

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
