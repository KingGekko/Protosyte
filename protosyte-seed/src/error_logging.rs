// Verbose Error Logging and Diagnostics
// Comprehensive error logging with encrypted log exfiltration

use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Error,
    Warning,
    Info,
    Debug,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: SystemTime,
    pub level: LogLevel,
    pub component: String,
    pub message: String,
    pub context: serde_json::Value,
}

pub struct Logger {
    logs: Arc<Mutex<Vec<LogEntry>>>,
    max_logs: usize,
    exfil_interval: tokio::time::Duration,
}

impl Logger {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(Mutex::new(Vec::new())),
            max_logs: 1000,
            exfil_interval: tokio::time::Duration::from_secs(3600), // 1 hour
        }
    }
    
    pub async fn log(
        &self,
        level: LogLevel,
        component: &str,
        message: &str,
        context: serde_json::Value,
    ) {
        let entry = LogEntry {
            timestamp: SystemTime::now(),
            level,
            component: component.to_string(),
            message: message.to_string(),
            context,
        };
        
        let mut logs = self.logs.lock().await;
        logs.push(entry);
        
        // Limit log size
        if logs.len() > self.max_logs {
            logs.remove(0);
        }
    }
    
    pub async fn error(&self, component: &str, message: &str, context: serde_json::Value) {
        self.log(LogLevel::Error, component, message, context).await;
    }
    
    pub async fn warn(&self, component: &str, message: &str, context: serde_json::Value) {
        self.log(LogLevel::Warning, component, message, context).await;
    }
    
    pub async fn info(&self, component: &str, message: &str, context: serde_json::Value) {
        self.log(LogLevel::Info, component, message, context).await;
    }
    
    pub async fn debug(&self, component: &str, message: &str, context: serde_json::Value) {
        self.log(LogLevel::Debug, component, message, context).await;
    }
    
    /// Get logs for exfiltration
    pub async fn get_logs(&self) -> Vec<LogEntry> {
        let mut logs = self.logs.lock().await;
        logs.drain(..).collect()
    }
    
    /// Start periodic log exfiltration
    pub async fn start_exfiltration_loop(&self, exfil_fn: impl Fn(Vec<LogEntry>) -> tokio::task::JoinHandle<()> + Send + 'static) {
        let logs = self.logs.clone();
        let interval = self.exfil_interval;
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                
                let logs_to_exfil: Vec<LogEntry> = {
                    let mut logs_guard = logs.lock().await;
                    logs_guard.drain(..).collect()
                };
                
                if !logs_to_exfil.is_empty() {
                    exfil_fn(logs_to_exfil);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_logger() {
        let logger = Logger::new();
        
        logger.error("test", "error message", serde_json::json!({})).await;
        logger.warn("test", "warning message", serde_json::json!({})).await;
        
        let logs = logger.get_logs().await;
        assert_eq!(logs.len(), 2);
    }
}

