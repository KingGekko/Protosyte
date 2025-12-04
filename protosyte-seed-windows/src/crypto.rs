// Windows version - same as Linux version
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
        let passphrase = env::var("PROTOSYTE_PASSPHRASE")
            .unwrap_or_else(|_| "default-passphrase-change-in-production".to_string());
        
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
        let (encrypted, nonce) = self.encrypt_with_nonce(data).await;
        let mut result = nonce;
        result.extend_from_slice(&encrypted);
        result
    }
    
    pub async fn encrypt_with_nonce(&self, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let compressed = compress(data, Some(lz4::block::CompressionMode::HIGHCOMPRESSION(1)), true)
            .unwrap_or_else(|_| data.to_vec());
        
        let cipher = Aes256Gcm::new_from_slice(&self.key).expect("Key init failed");
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let ciphertext = cipher.encrypt(&nonce, compressed.as_ref())
            .expect("Encryption failed");
        
        (ciphertext, nonce.to_vec())
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

impl Drop for CryptoManager {
    fn drop(&mut self) {
        self.key.zeroize();
        // Note: passphrase is String, zeroize doesn't work directly
        // In production, use a zeroize-compatible string type
    }
}

