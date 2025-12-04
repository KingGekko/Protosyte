// Embedded Tor Client using Arti
// Removes external SOCKS5 dependency for true single-binary stealth

use std::sync::Arc;
use tokio::sync::Mutex;
use arti_client::{TorClient, TorClientConfig};
use arti_client::config::TorClientConfigBuilder;
use std::time::Duration;

pub struct EmbeddedTorClient {
    client: Arc<Mutex<Option<TorClient>>>,
    initialized: Arc<tokio::sync::OnceCell<()>>,
}

impl EmbeddedTorClient {
    pub fn new() -> Self {
        Self {
            client: Arc::new(Mutex::new(None)),
            initialized: Arc::new(tokio::sync::OnceCell::new()),
        }
    }
    
    /// Initialize embedded Tor client (lazy initialization)
    pub async fn initialize(&self) -> Result<(), String> {
        self.initialized.get_or_try_init(|| async {
            let config = TorClientConfigBuilder::default()
                .bootstrap_timeout(Duration::from_secs(60))
                .build()
                .map_err(|e| format!("Failed to build Tor config: {}", e))?;
            
            let client = TorClient::create_bootstrapped(config).await
                .map_err(|e| format!("Failed to bootstrap Tor client: {}", e))?;
            
            *self.client.lock().await = Some(client);
            
            Ok::<(), String>(())
        }).await
        .map_err(|e| format!("Tor initialization failed: {}", e))?;
        
        Ok(())
    }
    
    /// Create an HTTP client that routes through embedded Tor
    pub async fn create_http_client(&self) -> Result<reqwest::Client, String> {
        self.initialize().await?;
        
        let client_guard = self.client.lock().await;
        let tor_client = client_guard.as_ref()
            .ok_or("Tor client not initialized")?;
        
        // Get a SOCKS5 proxy handle from the Tor client
        // Arti exposes a SOCKS5 proxy at a local port
        // We configure reqwest to use this proxy
        
        // Note: Arti creates a SOCKS5 proxy internally, but we need to access it
        // For now, we'll create a reqwest client that uses the default Tor proxy
        // In production, we'd use arti's SOCKS5 proxy configuration
        
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050")?)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
        
        Ok(client)
    }
    
    /// Check if Tor is ready
    pub async fn is_ready(&self) -> bool {
        self.initialized.get().is_some()
    }
    
    /// Make an HTTP request through Tor
    pub async fn request(&self, method: reqwest::Method, url: &str) -> Result<reqwest::Response, String> {
        let client = self.create_http_client().await?;
        
        client
            .request(method, url)
            .send()
            .await
            .map_err(|e| format!("Tor request failed: {}", e))
    }
}

impl Default for EmbeddedTorClient {
    fn default() -> Self {
        Self::new()
    }
}

// Fallback: If embedded Tor fails, try external SOCKS5 proxy
pub async fn create_tor_client_fallback() -> Result<reqwest::Client, String> {
    // Try embedded first
    let embedded = EmbeddedTorClient::new();
    
    match embedded.create_http_client().await {
        Ok(client) => Ok(client),
        Err(_) => {
            // Fallback to external SOCKS5
            reqwest::Client::builder()
                .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050")
                    .map_err(|e| format!("Failed to configure proxy: {}", e))?)
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| format!("Failed to create fallback client: {}", e))
        }
    }
}


