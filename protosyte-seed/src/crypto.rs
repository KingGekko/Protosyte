use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, AeadCore, OsRng}};
use lz4::block::{compress, decompress};
use zeroize::Zeroize;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit as HmacKeyInit;
use std::env;

type HmacSha256 = Hmac<Sha256>;

pub struct CryptoManager {
    key: Vec<u8>,
    passphrase: String,
}

impl CryptoManager {
    pub fn new() -> Self {
        // Key derivation from mission passphrase
        let passphrase = env::var("PROTOSYTE_PASSPHRASE")
            .unwrap_or_else(|_| "default-passphrase-change-in-production".to_string());
        
        // Derive key using PBKDF2-like approach with SHA256
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        hasher.update(b"protosyte-salt-v2");
        let key = hasher.finalize().to_vec();
        
        Self { 
            key,
            passphrase,
        }
    }
    
    pub fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        hasher.update(salt);
        hasher.finalize().to_vec()
    }
    
    pub async fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        // Compress first
        let compressed = compress(data, Some(lz4::block::CompressionMode::HIGHCOMPRESSION(1)), true)
            .unwrap_or_else(|_| data.to_vec());
        
        // Generate random nonce
        let cipher = Aes256Gcm::new_from_slice(&self.key).expect("Key init failed");
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        // Encrypt with AES-GCM
        let ciphertext = cipher.encrypt(&nonce, compressed.as_ref())
            .expect("Encryption failed");
        
        // Prepend nonce to ciphertext
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        result
    }
    
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted.len() < 12 {
            return Err("Ciphertext too short".to_string());
        }
        
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| format!("Key init failed: {}", e))?;
        
        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(nonce_bytes);
        
        let decrypted = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        // Decompress
        decompress(&decrypted, None)
            .map_err(|e| format!("Decompression failed: {}", e))
    }
    
    pub fn compute_hmac(&self, data: &[u8]) -> Vec<u8> {
        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(&self.key)
            .expect("HMAC key init failed");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
}

impl Zeroize for CryptoManager {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.passphrase.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_crypto_encrypt_decrypt() {
        let crypto = CryptoManager::new();
        let data = b"test data";
        
        let encrypted = crypto.encrypt(data).await;
        assert!(!encrypted.is_empty());
        assert!(encrypted.len() > data.len()); // Should be larger due to nonce + encryption overhead
        
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
    
    #[tokio::test]
    async fn test_crypto_encrypt_decrypt_large_data() {
        let crypto = CryptoManager::new();
        let data = vec![0u8; 1024 * 1024]; // 1MB of data
        
        let encrypted = crypto.encrypt(&data).await;
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
    
    #[tokio::test]
    async fn test_crypto_encrypt_decrypt_empty() {
        let crypto = CryptoManager::new();
        let data = b"";
        
        let encrypted = crypto.encrypt(data).await;
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
    
    #[test]
    fn test_hmac_computation() {
        let crypto = CryptoManager::new();
        let data = b"test data";
        
        let hmac1 = crypto.compute_hmac(data);
        let hmac2 = crypto.compute_hmac(data);
        
        assert_eq!(hmac1, hmac2);
        assert_eq!(hmac1.len(), 32); // SHA256 HMAC is 32 bytes
        assert!(!hmac1.is_empty());
    }
    
    #[test]
    fn test_hmac_different_data() {
        let crypto = CryptoManager::new();
        
        let hmac1 = crypto.compute_hmac(b"data1");
        let hmac2 = crypto.compute_hmac(b"data2");
        
        assert_ne!(hmac1, hmac2);
    }
    
    #[test]
    fn test_derive_key_from_passphrase() {
        let key1 = CryptoManager::derive_key_from_passphrase("test", b"salt1");
        let key2 = CryptoManager::derive_key_from_passphrase("test", b"salt1");
        let key3 = CryptoManager::derive_key_from_passphrase("test", b"salt2");
        
        assert_eq!(key1, key2); // Same passphrase and salt
        assert_ne!(key1, key3); // Different salt
        assert_eq!(key1.len(), 32); // SHA256 produces 32 bytes
    }
    
    #[test]
    fn test_decrypt_invalid_ciphertext() {
        let crypto = CryptoManager::new();
        
        // Too short
        assert!(crypto.decrypt(b"short").is_err());
        
        // Invalid format
        let invalid = vec![0u8; 20];
        assert!(crypto.decrypt(&invalid).is_err());
    }
    
    #[test]
    fn test_crypto_manager_new() {
        let crypto = CryptoManager::new();
        // Should not panic
        assert!(!crypto.key.is_empty());
    }
    
    #[tokio::test]
    async fn test_encrypt_deterministic_key() {
        // Test that same passphrase produces same key
        std::env::set_var("PROTOSYTE_PASSPHRASE", "test-passphrase");
        
        let crypto1 = CryptoManager::new();
        let crypto2 = CryptoManager::new();
        
        let data = b"test data";
        let enc1 = crypto1.encrypt(data).await;
        let enc2 = crypto2.encrypt(data).await;
        
        // Encryptions will differ due to random nonce, but should both decrypt correctly
        let dec1 = crypto1.decrypt(&enc1).unwrap();
        let dec2 = crypto2.decrypt(&enc2).unwrap();
        
        assert_eq!(dec1, data);
        assert_eq!(dec2, data);
        
        // Cross-decryption should work with same key
        let dec1_with_crypto2 = crypto2.decrypt(&enc1).unwrap();
        assert_eq!(dec1_with_crypto2, data);
    }
    
    #[test]
    fn test_crypto_manager_zeroize() {
        let mut crypto = CryptoManager::new();
        let key_before = crypto.key.clone();
        crypto.zeroize();
        // After zeroize, key should be zeroed (all zeros)
        assert_ne!(key_before, crypto.key);
        assert!(crypto.key.iter().all(|&b| b == 0));
    }
    
    #[test]
    fn test_decrypt_wrong_key() {
        std::env::set_var("PROTOSYTE_PASSPHRASE", "key1");
        let crypto1 = CryptoManager::new();
        let data = b"test";
        let encrypted = tokio::runtime::Runtime::new().unwrap().block_on(crypto1.encrypt(data));
        
        std::env::set_var("PROTOSYTE_PASSPHRASE", "key2");
        let crypto2 = CryptoManager::new();
        // Should fail to decrypt with wrong key
        assert!(crypto2.decrypt(&encrypted).is_err());
    }
    
    #[test]
    fn test_derive_key_empty_passphrase() {
        let key = CryptoManager::derive_key_from_passphrase("", b"salt");
        assert_eq!(key.len(), 32);
    }
    
    #[test]
    fn test_derive_key_empty_salt() {
        let key = CryptoManager::derive_key_from_passphrase("pass", b"");
        assert_eq!(key.len(), 32);
    }
    
    #[test]
    fn test_hmac_empty_data() {
        let crypto = CryptoManager::new();
        let hmac = crypto.compute_hmac(b"");
        assert_eq!(hmac.len(), 32);
    }
}
