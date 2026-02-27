//! HTTP-backed [`FileMedia`] implementation.
//!
//! [`HttpFileMedia`] implements the `rar-stream` [`FileMedia`] trait using
//! HTTP range requests (`Range: bytes=start-end`). This allows reading RAR
//! archives directly from HTTP/HTTPS URLs without downloading the entire file.
//!
//! # Requirements
//!
//! The HTTP server must support:
//! - `Accept-Ranges: bytes` header
//! - `Content-Length` header (for determining file size)
//! - `Range: bytes=start-end` request header
//!
//! Most static file servers (nginx, Apache, S3, CDNs) support this.
//!
//! # Example
//!
//! ```rust,no_run
//! use rar_access::HttpFileMedia;
//! use rar_stream::FileMedia;
//!
//! let media = HttpFileMedia::new("https://example.com/archive.rar").unwrap();
//! println!("Archive size: {} bytes", media.length());
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rar_stream::{FileMedia, ReadInterval, RarError};

use crate::error::Result as AccessResult;
use crate::error::RarError as AccessError;

/// HTTP-backed file media source.
///
/// Fetches byte ranges from a remote URL using HTTP range requests.
/// The file size is determined by a HEAD request on construction.
#[derive(Debug, Clone)]
pub struct HttpFileMedia {
    url: String,
    name: String,
    length: u64,
    client: Arc<reqwest::Client>,
}

impl HttpFileMedia {
    /// Create a new `HttpFileMedia` from a URL.
    ///
    /// Performs a HEAD request to determine the file size.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The URL is invalid
    /// - The server is unreachable
    /// - The server does not return a `Content-Length` header
    pub fn new(url: &str) -> AccessResult<Self> {
        let blocking_client = reqwest::blocking::Client::builder()
            .user_agent("rar-access/0.2")
            .build()
            .map_err(|e| AccessError::Http(e.to_string()))?;

        // HEAD request to get file size.
        let response = blocking_client
            .head(url)
            .send()
            .map_err(|e| AccessError::Http(format!("HEAD {url}: {e}")))?;

        if !response.status().is_success() {
            return Err(AccessError::Http(format!(
                "HEAD {url}: HTTP {}",
                response.status()
            )));
        }

        let length = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| {
                AccessError::Http(format!(
                    "server did not return Content-Length for {url}"
                ))
            })?;

        // Extract filename from URL path.
        let name = url
            .split('/')
            .last()
            .and_then(|s| s.split('?').next())
            .filter(|s| !s.is_empty())
            .unwrap_or("archive.rar")
            .to_string();

        // Build an async client for the FileMedia trait.
        let async_client = reqwest::Client::builder()
            .user_agent("rar-access/0.2")
            .build()
            .map_err(|e| AccessError::Http(e.to_string()))?;

        Ok(HttpFileMedia {
            url: url.to_string(),
            name,
            length,
            client: Arc::new(async_client),
        })
    }

    /// Return the URL of this media source.
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl FileMedia for HttpFileMedia {
    fn length(&self) -> u64 {
        self.length
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn read_range(
        &self,
        interval: ReadInterval,
    ) -> Pin<Box<dyn Future<Output = rar_stream::error::Result<Vec<u8>>> + Send + '_>> {
        let url = self.url.clone();
        let client = Arc::clone(&self.client);
        let start = interval.start;
        let end = interval.end;

        Box::pin(async move {
            let range_header = format!("bytes={start}-{end}");

            let response = client
                .get(&url)
                .header(reqwest::header::RANGE, &range_header)
                .send()
                .await
                .map_err(|e| {
                    RarError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("HTTP GET {url} range {range_header}: {e}"),
                    ))
                })?;

            // 206 Partial Content is the expected success status for range requests.
            // 200 OK is also acceptable (server returned full content).
            if !response.status().is_success()
                && response.status() != reqwest::StatusCode::PARTIAL_CONTENT
            {
                return Err(RarError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("HTTP {url}: status {}", response.status()),
                )));
            }

            let bytes = response.bytes().await.map_err(|e| {
                RarError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("HTTP read body {url}: {e}"),
                ))
            })?;

            Ok(bytes.to_vec())
        })
    }
}
