/// Untrusted-data envelope.
///
/// Wraps external content to prevent it from altering gateway policy
/// or tool permissions. The envelope explicitly marks the content as
/// untrusted and includes provenance metadata.
#[derive(Debug, Clone)]
pub struct UntrustedEnvelope {
    /// The fetched content body.
    body: Vec<u8>,
    /// Correlation id for tracing.
    correlation_id: String,
    /// Explicit trust marker — always `false` for external content.
    trusted: bool,
    /// Content classification.
    classification: ContentClassification,
}

/// Classification of content trust level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentClassification {
    /// Content has passed all security checks but is still untrusted.
    ExternalUntrusted,
}

impl UntrustedEnvelope {
    /// Get the body content.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Get the body as a UTF-8 string (lossy).
    pub fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// Whether this content is trusted (always false for external fetches).
    pub fn is_trusted(&self) -> bool {
        self.trusted
    }

    /// The content classification.
    pub fn classification(&self) -> &ContentClassification {
        &self.classification
    }

    /// The correlation id for this fetch.
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }
}

/// Wrap validated content in an untrusted-data envelope.
///
/// This is the FINAL step in the fetch pipeline. Even content that
/// passed all security validations is wrapped as untrusted to prevent
/// it from altering gateway policy or tool permissions downstream.
pub fn wrap_untrusted(content: Vec<u8>, correlation_id: &str) -> UntrustedEnvelope {
    UntrustedEnvelope {
        body: content,
        correlation_id: correlation_id.to_string(),
        trusted: false,
        classification: ContentClassification::ExternalUntrusted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_is_never_trusted() {
        let envelope = wrap_untrusted(b"hello".to_vec(), "test-id");
        assert!(!envelope.is_trusted());
        assert_eq!(
            envelope.classification(),
            &ContentClassification::ExternalUntrusted
        );
    }

    #[test]
    fn test_envelope_preserves_content() {
        let content = b"Some fetched HTML content";
        let envelope = wrap_untrusted(content.to_vec(), "corr-123");
        assert_eq!(envelope.body(), content);
        assert_eq!(envelope.correlation_id(), "corr-123");
    }
}
