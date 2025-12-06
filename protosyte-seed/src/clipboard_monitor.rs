// Clipboard Monitoring
// Monitors system clipboard for sensitive patterns

use std::sync::Arc;
use tokio::sync::Mutex;
use regex::Regex;
use anyhow::Result;
use std::time::Duration;

pub struct ClipboardMonitor {
    patterns: Arc<Mutex<Vec<Regex>>>,
    check_interval: Duration,
    enabled: Arc<Mutex<bool>>,
}

impl ClipboardMonitor {
    pub fn new() -> Self {
        let mut patterns = Vec::new();
        
        // Default patterns
        if let Ok(re) = Regex::new(r"(?i)(password|passwd|pwd)\s*[=:]\s*([^\s]+)") {
            patterns.push(re);
        }
        
        if let Ok(re) = Regex::new(r"(?i)(api[_-]?key|token)\s*[=:]\s*([a-zA-Z0-9_-]{20,})") {
            patterns.push(re);
        }
        
        Self {
            patterns: Arc::new(Mutex::new(patterns)),
            check_interval: Duration::from_secs(crate::constants::CLIPBOARD_CHECK_INTERVAL_SECS),
            enabled: Arc::new(Mutex::new(true)),
        }
    }
    
    /// Check clipboard for sensitive data
    pub async fn check_clipboard(&self) -> Result<Option<String>> {
        if !*self.enabled.lock().await {
            return Ok(None);
        }
        
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::DataExchange::{OpenClipboard, GetClipboardData, CloseClipboard};
            use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};
            use windows::Win32::Foundation::{HGLOBAL, HANDLE};
            
            unsafe {
                if OpenClipboard(None).is_err() {
                    return Ok(None);
                }
                
                // CF_TEXT = 1
                let handle_result = GetClipboardData(1u32);
                let handle = match handle_result {
                    Ok(h) => h,
                    Err(_) => {
                        let _ = CloseClipboard();
                        return Ok(None);
                    }
                };
                
                if handle.is_invalid() {
                    let _ = CloseClipboard();
                    return Ok(None);
                }
                
                // Convert HANDLE to HGLOBAL (they're compatible types)
                let hglobal = HGLOBAL(handle.0 as *mut _);
                let text_ptr = GlobalLock(hglobal);
                if text_ptr.is_null() {
                    let _ = CloseClipboard();
                    return Ok(None);
                }
                
                let text = std::ffi::CStr::from_ptr(text_ptr as *const i8).to_string_lossy();
                
                GlobalUnlock(hglobal);
                let _ = CloseClipboard();
                
                // Check patterns
                let patterns = self.patterns.lock().await;
                for pattern in patterns.iter() {
                    if pattern.is_match(&text) {
                        return Ok(Some(text.to_string()));
                    }
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // X11 clipboard or Wayland
            // Would use xclip or similar
        }
        
        #[cfg(target_os = "macos")]
        {
            // NSPasteboard
        }
        
        Ok(None)
    }
    
    /// Start monitoring loop
    pub async fn start_monitoring(&self, callback: impl Fn(String) -> tokio::task::JoinHandle<()> + Send + 'static) {
        let monitor = self.clone();
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(monitor.check_interval).await;
                
                if let Ok(Some(data)) = monitor.check_clipboard().await {
                    callback(data);
                }
            }
        });
    }
}

impl Clone for ClipboardMonitor {
    fn clone(&self) -> Self {
        Self {
            patterns: self.patterns.clone(),
            check_interval: self.check_interval,
            enabled: self.enabled.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_clipboard_monitor() {
        let monitor = ClipboardMonitor::new();
        let _ = monitor.check_clipboard().await;
    }
}

