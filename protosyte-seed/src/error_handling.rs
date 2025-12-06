// Enhanced Error Handling with Retry Mechanisms
// Provides robust error recovery and retry logic

use std::time::Duration;
use std::fmt;

#[derive(Debug, Clone)]
pub enum ProtosyteError {
    CryptoError(String),
    NetworkError(String),
    HookError(String),
    BufferError(String),
    ExfilError(String),
    ConfigError(String),
    SystemError(String),
}

impl fmt::Display for ProtosyteError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProtosyteError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            ProtosyteError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            ProtosyteError::HookError(msg) => write!(f, "Hook error: {}", msg),
            ProtosyteError::BufferError(msg) => write!(f, "Buffer error: {}", msg),
            ProtosyteError::ExfilError(msg) => write!(f, "Exfiltration error: {}", msg),
            ProtosyteError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            ProtosyteError::SystemError(msg) => write!(f, "System error: {}", msg),
        }
    }
}

impl std::error::Error for ProtosyteError {}

// Conversion traits for easy error handling
impl From<String> for ProtosyteError {
    fn from(msg: String) -> Self {
        ProtosyteError::SystemError(msg)
    }
}

impl From<&str> for ProtosyteError {
    fn from(msg: &str) -> Self {
        ProtosyteError::SystemError(msg.to_string())
    }
}

impl From<anyhow::Error> for ProtosyteError {
    fn from(err: anyhow::Error) -> Self {
        ProtosyteError::SystemError(err.to_string())
    }
}

impl From<windows::core::Error> for ProtosyteError {
    fn from(err: windows::core::Error) -> Self {
        ProtosyteError::SystemError(format!("Windows error: {}", err))
    }
}

impl From<aes_gcm::Error> for ProtosyteError {
    fn from(err: aes_gcm::Error) -> Self {
        ProtosyteError::CryptoError(format!("AES-GCM error: {:?}", err))
    }
}

impl From<reqwest::Error> for ProtosyteError {
    fn from(err: reqwest::Error) -> Self {
        ProtosyteError::NetworkError(format!("HTTP error: {}", err))
    }
}

impl From<prost::EncodeError> for ProtosyteError {
    fn from(err: prost::EncodeError) -> Self {
        ProtosyteError::ExfilError(format!("Protobuf encode error: {}", err))
    }
}

impl From<prost::DecodeError> for ProtosyteError {
    fn from(err: prost::DecodeError) -> Self {
        ProtosyteError::ExfilError(format!("Protobuf decode error: {}", err))
    }
}

#[derive(Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }
}

pub async fn retry_with_backoff<F, T, E>(
    config: RetryConfig,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>>,
    E: std::fmt::Debug,
{
    let mut delay = config.initial_delay;
    let mut last_error = None;

    for attempt in 1..=config.max_attempts {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                
                if attempt < config.max_attempts {
                    tokio::time::sleep(delay).await;
                    delay = Duration::from_secs_f64(
                        (delay.as_secs_f64() * config.backoff_multiplier)
                            .min(config.max_delay.as_secs_f64())
                    );
                }
            }
        }
    }

    // This will never be reached, but Rust needs it
    Err(last_error.expect("Should have at least one error"))
}

pub fn is_retryable_error(error: &ProtosyteError) -> bool {
    match error {
        ProtosyteError::NetworkError(_) => true,
        ProtosyteError::ExfilError(_) => true,
        ProtosyteError::SystemError(_) => true,
        _ => false,
    }
}

pub struct ErrorRecovery;

impl ErrorRecovery {
    pub fn recover_from_error(error: &ProtosyteError) -> Result<(), ProtosyteError> {
        match error {
            ProtosyteError::CryptoError(_) => {
                // Crypto errors are usually not recoverable
                Err(error.clone())
            }
            ProtosyteError::NetworkError(_) => {
                // Network errors might be recoverable
                Ok(())
            }
            ProtosyteError::HookError(_) => {
                // Try to reinitialize hooks
                Ok(())
            }
            ProtosyteError::BufferError(_) => {
                // Buffer errors might be recoverable by clearing buffer
                Ok(())
            }
            ProtosyteError::ExfilError(_) => {
                // Exfiltration errors might be recoverable
                Ok(())
            }
            ProtosyteError::ConfigError(_) => {
                // Config errors are usually not recoverable
                Err(error.clone())
            }
            ProtosyteError::SystemError(_) => {
                // System errors might be recoverable
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protosyte_error_display() {
        let err = ProtosyteError::NetworkError("Connection failed".to_string());
        assert!(err.to_string().contains("Network error"));
        assert!(err.to_string().contains("Connection failed"));
    }
    
    #[test]
    fn test_is_retryable_error() {
        assert!(is_retryable_error(&ProtosyteError::NetworkError("test".to_string())));
        assert!(is_retryable_error(&ProtosyteError::ExfilError("test".to_string())));
        assert!(is_retryable_error(&ProtosyteError::SystemError("test".to_string())));
        assert!(!is_retryable_error(&ProtosyteError::CryptoError("test".to_string())));
        assert!(!is_retryable_error(&ProtosyteError::ConfigError("test".to_string())));
    }
    
    #[test]
    fn test_error_recovery() {
        // Recoverable errors
        assert!(ErrorRecovery::recover_from_error(&ProtosyteError::NetworkError("test".to_string())).is_ok());
        assert!(ErrorRecovery::recover_from_error(&ProtosyteError::HookError("test".to_string())).is_ok());
        assert!(ErrorRecovery::recover_from_error(&ProtosyteError::ExfilError("test".to_string())).is_ok());
        
        // Non-recoverable errors
        assert!(ErrorRecovery::recover_from_error(&ProtosyteError::CryptoError("test".to_string())).is_err());
        assert!(ErrorRecovery::recover_from_error(&ProtosyteError::ConfigError("test".to_string())).is_err());
    }
    
    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_delay, Duration::from_secs(1));
        assert_eq!(config.max_delay, Duration::from_secs(30));
        assert_eq!(config.backoff_multiplier, 2.0);
    }
    
    #[tokio::test]
    async fn test_retry_with_backoff_success() {
        let config = RetryConfig {
            max_attempts: 3,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_secs(1),
            backoff_multiplier: 2.0,
        };
        
        let mut attempt = 0;
        let result = retry_with_backoff(config, || {
            attempt += 1;
            Box::pin(async move {
                if attempt == 1 {
                    Ok(42)
                } else {
                    Err("error")
                }
            })
        }).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempt, 1);
    }
    
    #[tokio::test]
    async fn test_retry_with_backoff_failure() {
        let config = RetryConfig {
            max_attempts: 3,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_secs(1),
            backoff_multiplier: 2.0,
        };
        
        let result: Result<i32, &str> = retry_with_backoff(config, || {
            Box::pin(async move {
                Err::<i32, &str>("persistent error")
            })
        }).await;
        
        assert!(result.is_err());
    }
}
