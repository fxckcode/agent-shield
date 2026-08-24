use super::error::{BlockReason, FetchError};
use super::policy::FetchPolicy;
use super::redirect::FetchResponse;

/// Validate the response Content-Type and body size against policy.
///
/// Blocks responses that:
/// - Have a Content-Type not in the allowed list.
/// - Have a body exceeding the configured size limit.
///
/// This check happens BEFORE the body is forwarded to the caller.
pub fn validate_response(
    response: &FetchResponse,
    policy: &FetchPolicy,
    correlation_id: &str,
) -> Result<Vec<u8>, FetchError> {
    // Check Content-Type
    let content_type = response
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_lowercase());

    if let Some(ct) = &content_type {
        let allowed = policy
            .allowed_content_types
            .iter()
            .any(|allowed| ct.starts_with(&allowed.to_lowercase()));
        if !allowed {
            return Err(FetchError::new(
                BlockReason::DisallowedContentType,
                correlation_id,
            ));
        }
    }
    // If no Content-Type header, allow (some responses legitimately lack it)

    // Check body size
    if response.body.len() > policy.max_body_size {
        return Err(FetchError::new(
            BlockReason::BodySizeLimitExceeded,
            correlation_id,
        ));
    }

    // Also check Content-Length header if present (early rejection)
    if let Some(cl) = response
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.clone())
    {
        if let Ok(length) = cl.parse::<usize>() {
            if length > policy.max_body_size {
                return Err(FetchError::new(
                    BlockReason::BodySizeLimitExceeded,
                    correlation_id,
                ));
            }
        }
    }

    Ok(response.body.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response(content_type: &str, body_size: usize) -> FetchResponse {
        FetchResponse {
            status_code: 200,
            headers: vec![
                ("content-type".to_string(), content_type.to_string()),
                ("content-length".to_string(), body_size.to_string()),
            ],
            body: vec![0u8; body_size],
            final_url: "http://example.com".to_string(),
        }
    }

    #[test]
    fn test_allowed_content_type() {
        let policy = FetchPolicy::default();
        let response = make_response("text/html; charset=utf-8", 100);
        assert!(validate_response(&response, &policy, "test-id").is_ok());
    }

    #[test]
    fn test_disallowed_content_type() {
        let policy = FetchPolicy::default();
        let response = make_response("application/octet-stream", 100);
        assert!(validate_response(&response, &policy, "test-id").is_err());
    }

    #[test]
    fn test_body_too_large() {
        let policy = FetchPolicy {
            max_body_size: 100,
            ..FetchPolicy::default()
        };
        let response = make_response("text/html", 200);
        let result = validate_response(&response, &policy, "test-id");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.reason_code(), "BODY_SIZE_LIMIT_EXCEEDED");
    }
}
