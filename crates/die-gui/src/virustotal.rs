//! VirusTotal integration mirroring upstream `XOnlineTools`.
//!
//! Upstream behavior (from `formatswidget.cpp:1133-1152`):
//! - If API key is configured → open VT Dialog (API query + result table)
//! - If no API key → compute MD5 and open browser to
//!   `https://www.virustotal.com/gui/file/{md5}`
//!
//! The hash type is always **MD5** (not SHA-256), matching
//! `xvirustotalwidget.cpp:56` and `xvirustotal.cpp:158`.

use serde::{Deserialize, Serialize};

/// VirusTotal scan result for a single engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtScanResult {
    /// Engine name (e.g. "Kaspersky").
    pub engine_name: String,
    /// Engine version.
    pub engine_version: String,
    /// Engine update date.
    pub engine_update: String,
    /// Detection result (empty = clean).
    pub result: String,
    /// Detection category (e.g. "malicious", "harmless", "undetected").
    pub category: String,
    /// Scan method (e.g. "blacklist", "heuristic").
    pub method: String,
}

/// Aggregated scan info from VirusTotal API v3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtScanInfo {
    /// Whether the file was found on VirusTotal.
    pub found: bool,
    /// First submission date (POSIX timestamp).
    pub first_submission_date: Option<i64>,
    /// Last analysis date (POSIX timestamp).
    pub last_analysis_date: Option<i64>,
    /// Number of detections.
    pub detects: i32,
    /// Total number of engines.
    pub total: i32,
    /// Status string "X/Y".
    pub status: String,
    /// Per-engine scan results.
    pub results: Vec<VtScanResult>,
    /// Error message if the query failed.
    pub error: Option<String>,
}

/// Open the VirusTotal website for the given hash in the default browser.
///
/// Uses MD5 to match upstream `XVirusTotal::getFileLink`.
pub fn open_in_browser(md5: &str) {
    let url = format!("https://www.virustotal.com/gui/file/{}", md5);
    let _ = open::that(&url);
}

/// Query the VirusTotal API v3 for file scan info.
///
/// Uses `GET /api/v3/files/{md5}` with the `x-apikey` header.
pub async fn query_scan_info(md5: &str, api_key: &str) -> VtScanInfo {
    let client = match reqwest::Client::builder()
        .user_agent("diec-rust-gui")
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return VtScanInfo {
                found: false,
                first_submission_date: None,
                last_analysis_date: None,
                detects: 0,
                total: 0,
                status: String::new(),
                results: Vec::new(),
                error: Some(format!("HTTP client build failed: {}", e)),
            };
        }
    };

    let url = format!("https://www.virustotal.com/api/v3/files/{}", md5);

    let resp = match client.get(&url).header("x-apikey", api_key).send().await {
        Ok(r) => r,
        Err(e) => {
            return VtScanInfo {
                found: false,
                first_submission_date: None,
                last_analysis_date: None,
                detects: 0,
                total: 0,
                status: String::new(),
                results: Vec::new(),
                error: Some(format!("Request failed: {}", e)),
            };
        }
    };

    let status_code = resp.status();
    if status_code.as_u16() == 404 {
        return VtScanInfo {
            found: false,
            first_submission_date: None,
            last_analysis_date: None,
            detects: 0,
            total: 0,
            status: String::new(),
            results: Vec::new(),
            error: None,
        };
    }

    if !status_code.is_success() {
        return VtScanInfo {
            found: false,
            first_submission_date: None,
            last_analysis_date: None,
            detects: 0,
            total: 0,
            status: String::new(),
            results: Vec::new(),
            error: Some(format!("HTTP {}", status_code)),
        };
    }

    let json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(e) => {
            return VtScanInfo {
                found: false,
                first_submission_date: None,
                last_analysis_date: None,
                detects: 0,
                total: 0,
                status: String::new(),
                results: Vec::new(),
                error: Some(format!("JSON parse failed: {}", e)),
            };
        }
    };

    parse_scan_info(&json)
}

/// Parse VirusTotal API v3 JSON response into `VtScanInfo`.
///
/// Response structure: `data.attributes.last_analysis_results.{engine}.{fields}`
fn parse_scan_info(json: &serde_json::Value) -> VtScanInfo {
    let attributes = json
        .pointer("/data/attributes")
        .unwrap_or(&serde_json::Value::Null);

    let first_submission_date = attributes
        .get("first_submission_date")
        .and_then(|v| v.as_i64());

    let last_analysis_date = attributes
        .get("last_analysis_date")
        .and_then(|v| v.as_i64());

    let analysis_results = attributes
        .get("last_analysis_results")
        .unwrap_or(&serde_json::Value::Null);

    let mut results = Vec::new();
    let mut detects = 0;

    if let Some(obj) = analysis_results.as_object() {
        for (engine_name, engine_data) in obj {
            let result_str = engine_data
                .get("result")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let category = engine_data
                .get("category")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let is_detected = !result_str.is_empty();

            if is_detected {
                detects += 1;
            }

            results.push(VtScanResult {
                engine_name: engine_name.clone(),
                engine_version: engine_data
                    .get("engine_version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                engine_update: engine_data
                    .get("engine_update")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                result: result_str,
                category,
                method: engine_data
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }

    let total = results.len() as i32;
    let status = format!("{}/{}", detects, total);

    // If there are no attributes, the file was not found.
    let found = !attributes.is_null();

    VtScanInfo {
        found,
        first_submission_date,
        last_analysis_date,
        detects,
        total,
        status,
        results,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scan_info_clean() {
        let json = serde_json::json!({
            "data": {
                "attributes": {
                    "first_submission_date": 1609459200,
                    "last_analysis_date": 1704067200,
                    "last_analysis_results": {
                        "Engine1": {
                            "result": "",
                            "category": "undetected",
                            "engine_version": "1.0",
                            "engine_update": "2024-01-01",
                            "method": "blacklist"
                        },
                        "Engine2": {
                            "result": "Trojan.Generic",
                            "category": "malicious",
                            "engine_version": "2.0",
                            "engine_update": "2024-01-02",
                            "method": "blacklist"
                        }
                    }
                }
            }
        });

        let info = parse_scan_info(&json);
        assert!(info.found);
        assert_eq!(info.detects, 1);
        assert_eq!(info.total, 2);
        assert_eq!(info.status, "1/2");
        assert_eq!(info.results.len(), 2);
        assert_eq!(info.first_submission_date, Some(1609459200));
        assert_eq!(info.last_analysis_date, Some(1704067200));
    }

    #[test]
    fn test_parse_scan_info_not_found() {
        let json = serde_json::json!({});
        let info = parse_scan_info(&json);
        assert!(!info.found);
        assert_eq!(info.detects, 0);
    }
}
