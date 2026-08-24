/// Fetch policy configuration.
///
/// Controls what destinations, content types, and sizes are allowed.
#[derive(Debug, Clone)]
pub struct FetchPolicy {
    /// Maximum number of redirect hops to follow.
    pub max_redirects: u32,
    /// Allowed Content-Type prefixes (e.g., "text/html", "application/json").
    pub allowed_content_types: Vec<String>,
    /// Maximum response body size in bytes.
    pub max_body_size: usize,
    /// Prompt-injection detection confidence threshold.
    /// Content with confidence below this is blocked (fail closed).
    pub injection_confidence_threshold: f64,
    /// Whether to block private/loopback/link-local/metadata IPs.
    pub block_private_ips: bool,
    /// Prompt-injection detection policy version.
    pub injection_policy_version: String,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            max_redirects: 5,
            allowed_content_types: vec![
                "text/html".to_string(),
                "text/plain".to_string(),
                "application/json".to_string(),
                "application/xml".to_string(),
                "text/xml".to_string(),
                "text/css".to_string(),
                "application/javascript".to_string(),
                "text/markdown".to_string(),
            ],
            max_body_size: 10 * 1024 * 1024, // 10 MiB
            injection_confidence_threshold: 0.8,
            block_private_ips: true,
            injection_policy_version: "v1".to_string(),
        }
    }
}
