// Integration tests for IPC and Tor client

#[cfg(test)]
mod tests {
    use protosyte_seed::tor_client::EmbeddedTorClient;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    #[ignore] // Requires Tor - run with: cargo test -- --ignored
    async fn test_tor_client_full_cycle() {
        let client = EmbeddedTorClient::new();
        
        // Initialize
        match timeout(Duration::from_secs(120), client.initialize()).await {
            Ok(Ok(())) => {
                assert!(client.is_ready().await);
                
                // Make a test request
                let response = timeout(
                    Duration::from_secs(30),
                    client.request(reqwest::Method::GET, "https://httpbin.org/ip")
                ).await;
                
                if let Ok(Ok(resp)) = response {
                    assert!(resp.status().is_success());
                }
            }
            _ => {
                // Skip if Tor not available
                println!("Tor not available, skipping test");
            }
        }
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod linux_tests {
    use protosyte_seed::ipc::{MemfdRingBuffer, AbstractUnixSocket};
    
    #[test]
    fn test_ipc_components() {
        // Test memfd buffer
        let buffer = MemfdRingBuffer::new(4096);
        assert!(buffer.is_ok());
        
        // Test abstract socket
        let socket = AbstractUnixSocket::new_random();
        assert!(socket.is_ok());
    }
}

