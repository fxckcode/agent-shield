use std::fmt;
use uuid::Uuid;

/// Reason codes for blocked requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    /// Target resolves to a private/loopback/link-local/metadata IP.
    SsrfPrivateIp,
    /// DNS rebinding detected — re-resolution returned a disallowed IP.
    DnsRebinding,
    /// Redirect target resolves to a disallowed destination.
    RedirectToPrivateIp,
    /// Redirect chain exceeds configured maximum hops.
    ExcessiveRedirects,
    /// Response Content-Type is not in the allowed list.
    DisallowedContentType,
    /// Response body exceeds configured size limit.
    BodySizeLimitExceeded,
    /// Prompt-injection pattern detected in fetched content.
    PromptInjectionDetected,
    /// Prompt-injection classifier confidence below threshold (fail closed).
    InjectionClassifierUncertain,
    /// URL scheme is not supported (only http:// is allowed in this transport).
    UnsupportedScheme,
    /// Transport-level I/O error (connection refused, timeout, etc.).
    TransportError,
}

impl BlockReason {
    /// Returns a safe, stable reason code string.
    pub fn code(&self) -> &'static str {
        match self {
            Self::SsrfPrivateIp => "SSRF_PRIVATE_IP",
            Self::DnsRebinding => "DNS_REBINDING",
            Self::RedirectToPrivateIp => "REDIRECT_TO_PRIVATE_IP",
            Self::ExcessiveRedirects => "EXCESSIVE_REDIRECTS",
            Self::DisallowedContentType => "DISALLOWED_CONTENT_TYPE",
            Self::BodySizeLimitExceeded => "BODY_SIZE_LIMIT_EXCEEDED",
            Self::PromptInjectionDetected => "PROMPT_INJECTION_DETECTED",
            Self::InjectionClassifierUncertain => "INJECTION_CLASSIFIER_UNCERTAIN",
            Self::UnsupportedScheme => "UNSUPPORTED_SCHEME",
            Self::TransportError => "TRANSPORT_ERROR",
        }
    }
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

/// Error type for blocked fetch requests.
///
/// Contains a safe reason code and correlation id.
/// NEVER echoes secrets, credentials, or hostile payloads.
#[derive(Debug, Clone)]
pub struct FetchError {
    reason: BlockReason,
    correlation_id: String,
}

impl FetchError {
    pub fn new(reason: BlockReason, correlation_id: &str) -> Self {
        Self {
            reason,
            correlation_id: correlation_id.to_string(),
        }
    }

    /// Generate a new FetchError with a fresh correlation id.
    pub fn with_new_correlation(reason: BlockReason) -> Self {
        Self {
            reason,
            correlation_id: Uuid::new_v4().to_string(),
        }
    }

    /// Safe reason code — never contains user input.
    pub fn reason_code(&self) -> &str {
        self.reason.code()
    }

    /// Correlation id for tracing.
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// The block reason enum variant.
    pub fn reason(&self) -> &BlockReason {
        &self.reason
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SECURITY: Never echo target URLs, IPs, payloads, or credentials.
        write!(
            f,
            "Request blocked: reason={}, correlation_id={}",
            self.reason.code(),
            self.correlation_id
        )
    }
}

impl std::error::Error for FetchError {}
