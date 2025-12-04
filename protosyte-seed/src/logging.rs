// Enhanced Logging and Observability
// Provides structured logging and metrics collection

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Metrics {
    payloads_sent: AtomicU64,
    payloads_failed: AtomicU64,
    bytes_exfiltrated: AtomicU64,
    hooks_active: AtomicU64,
    errors_total: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            payloads_sent: AtomicU64::new(0),
            payloads_failed: AtomicU64::new(0),
            bytes_exfiltrated: AtomicU64::new(0),
            hooks_active: AtomicU64::new(0),
            errors_total: AtomicU64::new(0),
        }
    }

    pub fn increment_payloads_sent(&self) {
        self.payloads_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_payloads_failed(&self) {
        self.payloads_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_exfiltrated(&self, bytes: u64) {
        self.bytes_exfiltrated.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn set_hooks_active(&self, count: u64) {
        self.hooks_active.store(count, Ordering::Relaxed);
    }

    pub fn increment_errors(&self) {
        self.errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            payloads_sent: self.payloads_sent.load(Ordering::Relaxed),
            payloads_failed: self.payloads_failed.load(Ordering::Relaxed),
            bytes_exfiltrated: self.bytes_exfiltrated.load(Ordering::Relaxed),
            hooks_active: self.hooks_active.load(Ordering::Relaxed),
            errors_total: self.errors_total.load(Ordering::Relaxed),
        }
    }
}

pub struct MetricsSnapshot {
    pub payloads_sent: u64,
    pub payloads_failed: u64,
    pub bytes_exfiltrated: u64,
    pub hooks_active: u64,
    pub errors_total: u64,
}

pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

pub struct Logger;

impl Logger {
    pub fn log(level: LogLevel, component: &str, message: &str) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let level_str = match level {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        };

        // In production, this would use a proper logging framework
        // For now, we'll use a simple format
        eprintln!("[{}] [{}] [{}] {}", timestamp, level_str, component, message);
    }

    pub fn debug(component: &str, message: &str) {
        Self::log(LogLevel::Debug, component, message);
    }

    pub fn info(component: &str, message: &str) {
        Self::log(LogLevel::Info, component, message);
    }

    pub fn warn(component: &str, message: &str) {
        Self::log(LogLevel::Warn, component, message);
    }

    pub fn error(component: &str, message: &str) {
        Self::log(LogLevel::Error, component, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metrics_new() {
        let metrics = Metrics::new();
        let stats = metrics.get_stats();
        assert_eq!(stats.payloads_sent, 0);
        assert_eq!(stats.payloads_failed, 0);
        assert_eq!(stats.bytes_exfiltrated, 0);
        assert_eq!(stats.hooks_active, 0);
        assert_eq!(stats.errors_total, 0);
    }
    
    #[test]
    fn test_metrics_increment() {
        let metrics = Metrics::new();
        
        metrics.increment_payloads_sent();
        metrics.increment_payloads_sent();
        metrics.increment_payloads_failed();
        metrics.add_bytes_exfiltrated(1024);
        metrics.set_hooks_active(5);
        metrics.increment_errors();
        
        let stats = metrics.get_stats();
        assert_eq!(stats.payloads_sent, 2);
        assert_eq!(stats.payloads_failed, 1);
        assert_eq!(stats.bytes_exfiltrated, 1024);
        assert_eq!(stats.hooks_active, 5);
        assert_eq!(stats.errors_total, 1);
    }
    
    #[test]
    fn test_metrics_thread_safety() {
        use std::thread;
        
        let metrics = Metrics::new();
        let mut handles = vec![];
        
        // Spawn multiple threads to test thread safety
        for _ in 0..10 {
            let metrics_clone = &metrics;
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    metrics_clone.increment_payloads_sent();
                    metrics_clone.add_bytes_exfiltrated(100);
                }
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        let stats = metrics.get_stats();
        assert_eq!(stats.payloads_sent, 1000);
        assert_eq!(stats.bytes_exfiltrated, 100000);
    }
    
    #[test]
    fn test_logger_levels() {
        // Test that logger methods don't panic
        Logger::debug("TEST", "Debug message");
        Logger::info("TEST", "Info message");
        Logger::warn("TEST", "Warn message");
        Logger::error("TEST", "Error message");
    }
}
