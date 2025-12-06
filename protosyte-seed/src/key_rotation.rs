// Key Rotation and Expiration
// Automatic key rotation on time-based or volume-based intervals

use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use anyhow::Result;
#[cfg(feature = "forward-secrecy")]
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

pub struct KeyRotationConfig {
    pub rotation_interval_days: u64,      // Rotate every N days
    pub rotation_interval_messages: u64,  // Rotate every N messages
    pub key_retention_days: u64,          // Keep old keys for N days
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            rotation_interval_days: 7,
            rotation_interval_messages: 10000,
            key_retention_days: 30,
        }
    }
}

pub struct KeyEpoch {
    pub epoch: u64,
    pub key: Vec<u8>,
    pub created_at: SystemTime,
    pub message_count: u64,
}

impl Zeroize for KeyEpoch {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

pub struct KeyRotationManager {
    config: Arc<Mutex<KeyRotationConfig>>,
    master_key: Arc<Mutex<Vec<u8>>>, // Master key (never used directly)
    current_epoch: Arc<Mutex<KeyEpoch>>,
    key_history: Arc<Mutex<Vec<KeyEpoch>>>, // For decryption of old messages
}

impl KeyRotationManager {
    pub fn new(master_key: Vec<u8>, config: KeyRotationConfig) -> Self {
        let epoch = Self::derive_epoch_key(&master_key, 0);
        
        Self {
            config: Arc::new(Mutex::new(config)),
            master_key: Arc::new(Mutex::new(master_key)),
            current_epoch: Arc::new(Mutex::new(KeyEpoch {
                epoch: 0,
                key: epoch,
                created_at: SystemTime::now(),
                message_count: 0,
            })),
            key_history: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    /// Derive key for specific epoch
    fn derive_epoch_key(master_key: &[u8], epoch: u64) -> Vec<u8> {
        #[cfg(feature = "forward-secrecy")]
        {
            use hkdf::Hkdf;
            let hk = Hkdf::<Sha256>::new(None, master_key);
            let mut key = vec![0u8; 32];
            let epoch_bytes = epoch.to_le_bytes();
            hk.expand(&epoch_bytes, &mut key).expect("HKDF expansion failed");
            key
        }
        #[cfg(not(feature = "forward-secrecy"))]
        {
            use sha2::Digest;
            let mut hasher = Sha256::new();
            hasher.update(master_key);
            hasher.update(&epoch.to_le_bytes());
            hasher.finalize().to_vec()
        }
    }
    
    /// Get current encryption key
    pub async fn get_current_key(&self) -> Vec<u8> {
        let epoch = self.current_epoch.lock().await;
        epoch.key.clone()
    }
    
    /// Get key for specific epoch (for decryption)
    pub async fn get_key_for_epoch(&self, epoch: u64) -> Option<Vec<u8>> {
        let current = self.current_epoch.lock().await;
        if current.epoch == epoch {
            return Some(current.key.clone());
        }
        drop(current);
        
        let history = self.key_history.lock().await;
        for key_epoch in history.iter() {
            if key_epoch.epoch == epoch {
                return Some(key_epoch.key.clone());
            }
        }
        
        // Derive from master key if not in history
        let master = self.master_key.lock().await;
        Some(Self::derive_epoch_key(&master, epoch))
    }
    
    /// Check if key rotation is needed
    pub async fn should_rotate(&self) -> bool {
        let config = {
            let guard = self.config.lock().await;
            KeyRotationConfig {
                rotation_interval_days: guard.rotation_interval_days,
                rotation_interval_messages: guard.rotation_interval_messages,
                key_retention_days: guard.key_retention_days,
            }
        };
        let mut epoch = self.current_epoch.lock().await;
        
        // Check time-based rotation
        let elapsed = epoch.created_at.elapsed().unwrap_or(Duration::ZERO);
        if elapsed.as_secs() >= config.rotation_interval_days * 86400 {
            return true;
        }
        
        // Check volume-based rotation
        if epoch.message_count >= config.rotation_interval_messages {
            return true;
        }
        
        false
    }
    
    /// Rotate to new key epoch
    pub async fn rotate(&self) -> Result<u64> {
        let config = {
            let guard = self.config.lock().await;
            KeyRotationConfig {
                rotation_interval_days: guard.rotation_interval_days,
                rotation_interval_messages: guard.rotation_interval_messages,
                key_retention_days: guard.key_retention_days,
            }
        };
        let master = self.master_key.lock().await.clone();
        
        // Get current epoch number
        let current_epoch_num = {
            let epoch = self.current_epoch.lock().await;
            epoch.epoch
        };
        
        let new_epoch_num = current_epoch_num + 1;
        let new_key = Self::derive_epoch_key(&master, new_epoch_num);
        
        // Move current epoch to history
        let mut current = self.current_epoch.lock().await;
        let old_epoch = KeyEpoch {
            epoch: current.epoch,
            key: current.key.clone(),
            created_at: current.created_at,
            message_count: current.message_count,
        };
        drop(current);
        
        let mut history = self.key_history.lock().await;
        history.push(old_epoch);
        
        // Clean up old keys beyond retention period
        let now = SystemTime::now();
        history.retain(|k| {
            now.duration_since(k.created_at)
                .map(|d| d.as_secs() < config.key_retention_days * 86400)
                .unwrap_or(true)
        });
        
        // Set new epoch
        let mut current = self.current_epoch.lock().await;
        *current = KeyEpoch {
            epoch: new_epoch_num,
            key: new_key,
            created_at: SystemTime::now(),
            message_count: 0,
        };
        
        Ok(new_epoch_num)
    }
    
    /// Increment message count (call after each encryption)
    pub async fn increment_message_count(&self) {
        let mut epoch = self.current_epoch.lock().await;
        epoch.message_count += 1;
    }
    
    /// Get current epoch number
    pub async fn get_current_epoch(&self) -> u64 {
        let epoch = self.current_epoch.lock().await;
        epoch.epoch
    }
    
    /// Get key statistics
    pub async fn get_stats(&self) -> (u64, u64, usize) {
        let epoch = self.current_epoch.lock().await;
        let history = self.key_history.lock().await;
        (epoch.epoch, epoch.message_count, history.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_key_rotation() {
        let master_key = vec![0u8; 32];
        let config = KeyRotationConfig {
            rotation_interval_days: 0, // Rotate immediately for test
            rotation_interval_messages: 100,
            key_retention_days: 30,
        };
        
        let manager = KeyRotationManager::new(master_key, config);
        
        let epoch1 = manager.get_current_epoch().await;
        assert_eq!(epoch1, 0);
        
        // Force rotation
        let epoch2 = manager.rotate().await.unwrap();
        assert_eq!(epoch2, 1);
        
        // Old key should still be accessible
        let old_key = manager.get_key_for_epoch(0).await;
        assert!(old_key.is_some());
        
        // New key should be different
        let new_key = manager.get_key_for_epoch(1).await;
        assert!(new_key.is_some());
        assert_ne!(old_key.unwrap(), new_key.unwrap());
    }
}

