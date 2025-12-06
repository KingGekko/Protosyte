// Forward Secrecy Implementation (Signal Protocol / Double Ratchet)
// Continuous key rotation for forward and future secrecy

#[cfg(feature = "forward-secrecy")]
use x25519_dalek::{PublicKey, StaticSecret, SharedSecret};
#[cfg(feature = "forward-secrecy")]
use hkdf::Hkdf;
#[cfg(not(feature = "forward-secrecy"))]
use sha2::Hkdf;
use sha2::Sha256;
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::{Result, Context};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, ZeroizeOnDrop)]
pub struct RatchetState {
    root_key: Vec<u8>,           // Root key (never used directly)
    sending_chain_key: Vec<u8>,  // Current sending chain key
    receiving_chain_key: Vec<u8>, // Current receiving chain key
    sending_message_number: u32, // Message number in sending chain
    receiving_message_number: u32, // Message number in receiving chain
    sending_ratchet_public: Option<Vec<u8>>, // Current sending ratchet public key
    receiving_ratchet_public: Option<Vec<u8>>, // Current receiving ratchet public key
}

impl RatchetState {
    fn new(root_key: Vec<u8>) -> Self {
        // Initialize chain keys from root key
        let hk = Hkdf::<Sha256>::new(None, &root_key);
        let mut sending_chain = vec![0u8; 32];
        let mut receiving_chain = vec![0u8; 32];
        
        hk.expand(b"sending_chain", &mut sending_chain)
            .expect("HKDF expansion failed");
        hk.expand(b"receiving_chain", &mut receiving_chain)
            .expect("HKDF expansion failed");
        
        Self {
            root_key,
            sending_chain_key: sending_chain,
            receiving_chain_key: receiving_chain,
            sending_message_number: 0,
            receiving_message_number: 0,
            sending_ratchet_public: None,
            receiving_ratchet_public: None,
        }
    }
    
    /// Derive message key from chain key
    fn derive_message_key(&mut self, is_sending: bool) -> (Vec<u8>, Vec<u8>) {
        let chain_key = if is_sending {
            &mut self.sending_chain_key
        } else {
            &mut self.receiving_chain_key
        };
        
        // Derive message key and next chain key
        let hk = Hkdf::<Sha256>::new(None, chain_key);
        let mut message_key = vec![0u8; 32];
        let mut next_chain_key = vec![0u8; 32];
        
        hk.expand(b"message_key", &mut message_key)
            .expect("HKDF expansion failed");
        hk.expand(b"chain_key", &mut next_chain_key)
            .expect("HKDF expansion failed");
        
        // Update chain key
        *chain_key = next_chain_key;
        
        // Increment message number
        if is_sending {
            self.sending_message_number += 1;
        } else {
            self.receiving_message_number += 1;
        }
        
        (message_key, chain_key.clone())
    }
    
    /// Perform ratchet step (key exchange)
    fn ratchet_step(&mut self, new_public_key: &[u8]) -> Result<()> {
        #[cfg(feature = "forward-secrecy")]
        {
            // Generate new ephemeral key pair
            let new_secret = StaticSecret::random_from_rng(rand::thread_rng());
            let new_public = PublicKey::from(&new_secret);
            
            // Compute shared secret
            let peer_public = PublicKey::from_bytes(new_public_key)
                .context("Invalid public key")?;
            let shared_secret = new_secret.diffie_hellman(&peer_public);
            
            // Update root key and chain keys
            let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
            let mut new_root = vec![0u8; 32];
            let mut new_chain = vec![0u8; 32];
            
            hk.expand(b"root_key", &mut new_root)
                .context("HKDF expansion failed")?;
            hk.expand(b"chain_key", &mut new_chain)
                .context("HKDF expansion failed")?;
            
            self.root_key = new_root;
            self.receiving_chain_key = new_chain;
            self.receiving_ratchet_public = Some(new_public_key.to_vec());
            self.receiving_message_number = 0;
            
            // Store our new public key for sending
            self.sending_ratchet_public = Some(new_public.as_bytes().to_vec());
            
            Ok(())
        }
        
        #[cfg(not(feature = "forward-secrecy"))]
        {
            Err(anyhow::anyhow!("Forward secrecy requires 'forward-secrecy' feature"))
        }
    }
}

pub struct ForwardSecrecyCrypto {
    state: Arc<Mutex<RatchetState>>,
    peer_public_key: Option<Vec<u8>>, // Peer's long-term public key (for X3DH)
}

impl ForwardSecrecyCrypto {
    pub fn new(peer_public_key: Option<Vec<u8>>) -> Result<Self> {
        #[cfg(feature = "forward-secrecy")]
        {
            // Initialize with X3DH key agreement
            let root_key = if let Some(peer_pub) = peer_public_key {
                // Perform X3DH key exchange
                // This is simplified - full X3DH requires identity keys, signed prekeys, etc.
                Self::x3dh_key_exchange(&peer_pub)?
            } else {
                // Generate random root key (for testing or initial setup)
                let mut key = vec![0u8; 32];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut key);
                key
            };
            
            Ok(Self {
                state: Arc::new(Mutex::new(RatchetState::new(root_key))),
                peer_public_key,
            })
        }
        
        #[cfg(not(feature = "forward-secrecy"))]
        {
            Err(anyhow::anyhow!("Forward secrecy requires 'forward-secrecy' feature"))
        }
    }
    
    #[cfg(feature = "forward-secrecy")]
    fn x3dh_key_exchange(peer_public_key: &[u8]) -> Result<Vec<u8>> {
        // X3DH (Extended Triple Diffie-Hellman) key agreement
        // Simplified version - full implementation requires:
        // - Identity keys (long-term)
        // - Signed prekeys
        // - One-time prekeys
        // - Ephemeral keys
        
        // For now, use simple ECDH
        let our_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let peer_public = PublicKey::from_bytes(peer_public_key)
            .context("Invalid peer public key")?;
        
        let shared_secret = our_secret.diffie_hellman(&peer_public);
        
        // Derive root key from shared secret
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut root_key = vec![0u8; 32];
        hk.expand(b"x3dh_root_key", &mut root_key)
            .context("HKDF expansion failed")?;
        
        Ok(root_key)
    }
    
    /// Encrypt data with forward secrecy
    pub async fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut state = self.state.lock().await;
        
        // Derive message key
        let (message_key, _) = state.derive_message_key(true);
        
        // Encrypt with AES-GCM using message key
        use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, AeadCore, OsRng}};
        let cipher = Aes256Gcm::new_from_slice(&message_key)
            .context("Failed to create cipher")?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let ciphertext = cipher.encrypt(&nonce, data)
            .context("Encryption failed")?;
        
        // Zeroize message key immediately after use
        message_key.zeroize();
        
        Ok((ciphertext, nonce.to_vec()))
    }
    
    /// Decrypt data with forward secrecy
    pub async fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        let mut state = self.state.lock().await;
        
        // Derive message key
        let (message_key, _) = state.derive_message_key(false);
        
        // Decrypt with AES-GCM
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        let cipher = Aes256Gcm::new_from_slice(&message_key)
            .context("Failed to create cipher")?;
        let nonce_array = aes_gcm::aead::generic_array::GenericArray::from_slice(nonce);
        
        let plaintext = cipher.decrypt(nonce_array, ciphertext)
            .context("Decryption failed")?;
        
        // Zeroize message key immediately after use
        message_key.zeroize();
        
        Ok(plaintext)
    }
    
    /// Perform ratchet step (key exchange)
    pub async fn ratchet(&self, new_public_key: &[u8]) -> Result<()> {
        let mut state = self.state.lock().await;
        state.ratchet_step(new_public_key)
    }
    
    /// Get current sending public key (for key exchange)
    pub async fn get_sending_public_key(&self) -> Option<Vec<u8>> {
        let state = self.state.lock().await;
        state.sending_ratchet_public.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    #[cfg(feature = "forward-secrecy")]
    async fn test_forward_secrecy_encrypt_decrypt() {
        // Generate test peer public key
        let peer_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let peer_public = PublicKey::from(&peer_secret);
        
        let crypto1 = ForwardSecrecyCrypto::new(Some(peer_public.as_bytes().to_vec()))
            .expect("Failed to create crypto");
        
        let data = b"test message";
        let (ciphertext, nonce) = crypto1.encrypt(data).await
            .expect("Encryption failed");
        
        let plaintext = crypto1.decrypt(&ciphertext, &nonce).await
            .expect("Decryption failed");
        
        assert_eq!(plaintext, data);
    }
    
    #[tokio::test]
    #[cfg(feature = "forward-secrecy")]
    async fn test_key_rotation() {
        let crypto = ForwardSecrecyCrypto::new(None)
            .expect("Failed to create crypto");
        
        // Encrypt multiple messages - each should use different keys
        let data1 = b"message 1";
        let data2 = b"message 2";
        
        let (cipher1, nonce1) = crypto.encrypt(data1).await.unwrap();
        let (cipher2, nonce2) = crypto.encrypt(data2).await.unwrap();
        
        // Ciphertexts should be different (different keys)
        assert_ne!(cipher1, cipher2);
        
        // Both should decrypt correctly
        let plain1 = crypto.decrypt(&cipher1, &nonce1).await.unwrap();
        let plain2 = crypto.decrypt(&cipher2, &nonce2).await.unwrap();
        
        assert_eq!(plain1, data1);
        assert_eq!(plain2, data2);
    }
}

