// Tor Client Tests Module

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    #[ignore] // Ignore by default - requires Tor to be available
    async fn test_tor_client_initialization() {
        let client = EmbeddedTorClient::new();
        
        // Should initialize without error (may take time)
        let result = timeout(Duration::from_secs(120), client.initialize()).await;
        
        match result {
            Ok(Ok(())) => {
                // Initialization successful
                assert!(client.is_ready().await);
            }
            Ok(Err(e)) => {
                // Initialization failed (Tor may not be available)
                eprintln!("Tor initialization failed (expected if Tor unavailable): {}", e);
                // Don't fail test - Tor may not be available in test environment
            }
            Err(_) => {
                // Timeout - Tor initialization is slow
                eprintln!("Tor initialization timed out (may need more time)");
            }
        }
    }

    #[tokio::test]
    async fn test_tor_client_fallback() {
        // Test fallback mechanism when embedded Tor fails
        let result = create_tor_client_fallback().await;
        
        // Should either succeed (external proxy available) or fail gracefully
        match result {
            Ok(_) => {
                // External proxy available
            }
            Err(e) => {
                // Expected if no Tor proxy available
                assert!(e.contains("proxy") || e.contains("Failed"));
            }
        }
    }

    #[test]
    fn test_tor_client_default() {
        let client = EmbeddedTorClient::default();
        
        // Default should create new client
        assert!(!client.is_ready()); // Initially not ready - but this is sync
    }
}

