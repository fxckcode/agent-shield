/// A fetch request to be executed through the controlled-fetch pipeline.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    url: String,
    headers: Vec<(String, String)>,
}

impl FetchRequest {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            headers: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }
}
