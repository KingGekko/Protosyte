// Lazy Data Filtering - Filter Before Encryption
// Dramatically reduces CPU, memory, and bandwidth by filtering early

use std::sync::Arc;
use tokio::sync::Mutex;
use regex::Regex;
use anyhow::Result;

pub struct FilterPattern {
    regex: Regex,
    data_type: String,
    priority: u8, // Higher priority = checked first
}

pub struct LazyFilter {
    patterns: Arc<Mutex<Vec<FilterPattern>>>,
    stats: Arc<Mutex<FilterStats>>,
}

#[derive(Default)]
struct FilterStats {
    total_bytes_checked: u64,
    total_bytes_matched: u64,
    total_bytes_discarded: u64,
    pattern_matches: std::collections::HashMap<String, u64>,
}

impl LazyFilter {
    pub fn new() -> Self {
        let mut patterns = Vec::new();
        
        // High-priority patterns (credentials, keys)
        if let Ok(re) = Regex::new(r"-----BEGIN.*PRIVATE KEY-----") {
            patterns.push(FilterPattern {
                regex: re,
                data_type: "PRIVATE_KEY".to_string(),
                priority: 10,
            });
        }
        
        if let Ok(re) = Regex::new(r#"(?i)(password|passwd|pwd)\s*[=:]\s*["']?([^"'\s]+)"#) {
            patterns.push(FilterPattern {
                regex: re,
                data_type: "PASSWORD".to_string(),
                priority: 9,
            });
        }
        
        if let Ok(re) = Regex::new(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*([a-zA-Z0-9_-]{20,})") {
            patterns.push(FilterPattern {
                regex: re,
                data_type: "API_KEY".to_string(),
                priority: 8,
            });
        }
        
        // Medium-priority patterns
        if let Ok(re) = Regex::new(r"(?i)(token|bearer|authorization)\s*[=:]\s*([a-zA-Z0-9_-]{32,})") {
            patterns.push(FilterPattern {
                regex: re,
                data_type: "TOKEN".to_string(),
                priority: 7,
            });
        }
        
        if let Ok(re) = Regex::new(r"(?i)(secret|secret[_-]?key)\s*[=:]\s*([a-zA-Z0-9_-]{16,})") {
            patterns.push(FilterPattern {
                regex: re,
                data_type: "SECRET".to_string(),
                priority: 6,
            });
        }
        
        // Sort by priority (highest first)
        patterns.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        Self {
            patterns: Arc::new(Mutex::new(patterns)),
            stats: Arc::new(Mutex::new(FilterStats::default())),
        }
    }
    
    /// Filter data - returns Some(data) if matches, None if should be discarded
    pub async fn filter(&self, data: &[u8]) -> Option<Vec<u8>> {
        let mut stats = self.stats.lock().await;
        stats.total_bytes_checked += data.len() as u64;
        
        // Try to decode as UTF-8 for text-based filtering
        if let Ok(text) = std::str::from_utf8(data) {
            let patterns = self.patterns.lock().await;
            
            // Check patterns in priority order
            for pattern in patterns.iter() {
                if pattern.regex.is_match(text) {
                    // Match found - record statistics
                    stats.total_bytes_matched += data.len() as u64;
                    *stats.pattern_matches.entry(pattern.data_type.clone()).or_insert(0) += 1;
                    
                    return Some(data.to_vec());
                }
            }
        }
        
        // No match - discard
        stats.total_bytes_discarded += data.len() as u64;
        None
    }
    
    /// Add custom filter pattern
    pub async fn add_pattern(&self, regex: Regex, data_type: String, priority: u8) {
        let mut patterns = self.patterns.lock().await;
        patterns.push(FilterPattern {
            regex,
            data_type,
            priority,
        });
        patterns.sort_by(|a, b| b.priority.cmp(&a.priority));
    }
    
    /// Get filter statistics
    pub async fn get_stats(&self) -> (u64, u64, u64, f32) {
        let stats = self.stats.lock().await;
        let discard_ratio = if stats.total_bytes_checked > 0 {
            stats.total_bytes_discarded as f32 / stats.total_bytes_checked as f32
        } else {
            0.0
        };
        
        (
            stats.total_bytes_checked,
            stats.total_bytes_matched,
            stats.total_bytes_discarded,
            discard_ratio,
        )
    }
    
    /// Get pattern match counts
    pub async fn get_pattern_matches(&self) -> std::collections::HashMap<String, u64> {
        let stats = self.stats.lock().await;
        stats.pattern_matches.clone()
    }
    
    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.lock().await;
        *stats = FilterStats::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_lazy_filter_password() {
        let filter = LazyFilter::new();
        
        let data = b"password=secret123";
        let result = filter.filter(data).await;
        assert!(result.is_some());
    }
    
    #[tokio::test]
    async fn test_lazy_filter_no_match() {
        let filter = LazyFilter::new();
        
        let data = b"normal text without sensitive information";
        let result = filter.filter(data).await;
        assert!(result.is_none());
    }
    
    #[tokio::test]
    async fn test_lazy_filter_stats() {
        let filter = LazyFilter::new();
        
        filter.filter(b"password=test").await;
        filter.filter(b"normal text").await;
        
        let (checked, matched, discarded, ratio) = filter.get_stats().await;
        assert_eq!(checked, 25); // 13 + 12
        assert_eq!(matched, 13);
        assert_eq!(discarded, 12);
        assert!(ratio > 0.0);
    }
}


