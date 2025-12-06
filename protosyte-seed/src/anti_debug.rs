// Anti-Debugging and Anti-VM Detection
// Detects debugging, instrumentation, and VM execution

use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::Result;

pub struct AntiDebugConfig {
    pub enable_anti_debug: bool,
    pub enable_anti_vm: bool,
    pub action_on_detection: DetectionAction,
}

#[derive(Clone, Copy)]
pub enum DetectionAction {
    SelfDestruct,    // Immediately exit
    Dormant,         // Enter dormant mode
    Continue,        // Continue but log
}

pub struct AntiDebug {
    config: Arc<Mutex<AntiDebugConfig>>,
    detection_count: Arc<Mutex<u32>>,
}

impl AntiDebug {
    pub fn new(config: AntiDebugConfig) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
            detection_count: Arc::new(Mutex::new(0)),
        }
    }
    
    /// Perform all anti-debugging and anti-VM checks
    pub async fn check(&self) -> Result<bool> {
        let config = self.config.lock().await;
        
        if config.enable_anti_debug {
            if self.check_debugging().await? {
                self.handle_detection(&config.action_on_detection).await?;
                return Ok(true);
            }
        }
        
        if config.enable_anti_vm {
            if self.check_vm().await? {
                self.handle_detection(&config.action_on_detection).await?;
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// Check for debugging
    async fn check_debugging(&self) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            // Check /proc/self/status for TracerPid
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("TracerPid:") {
                        let pid = line.split_whitespace().nth(1)
                            .and_then(|s| s.parse::<u32>().ok())
                            .unwrap_or(0);
                        if pid != 0 {
                            return Ok(true); // Being debugged
                        }
                    }
                }
            }
            
            // Check ptrace
            use nix::sys::ptrace;
            if ptrace::ptrace(ptrace::PtraceRequest::PTRACE_TRACEME, None, None, None).is_err() {
                return Ok(true); // Already being traced
            }
            
            // Timing attack: check if code executes too slowly (debugger overhead)
            let start = std::time::Instant::now();
            let _ = 1 + 1; // Simple operation
            let elapsed = start.elapsed();
            if elapsed.as_nanos() > 1000 {
                return Ok(true); // Suspiciously slow
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
            use windows::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
            use windows::Win32::System::Threading::GetCurrentProcess;
            
            // IsDebuggerPresent
            unsafe {
                if IsDebuggerPresent().as_bool() {
                    return Ok(true);
                }
            }
            
            // CheckRemoteDebuggerPresent
            unsafe {
                use windows::Win32::Foundation::BOOL;
                let mut debug_flag = BOOL::from(false);
                let process = GetCurrentProcess();
                if CheckRemoteDebuggerPresent(process, &mut debug_flag).is_ok() {
                    if debug_flag.as_bool() {
                        return Ok(true);
                    }
                }
            }
            
            // PEB BeingDebugged flag (would require direct memory access)
            // Simplified for now
            
            // Timing attack (RDTSC)
            let start = std::time::Instant::now();
            let _ = 1 + 1;
            let elapsed = start.elapsed();
            if elapsed.as_nanos() > 1000 {
                return Ok(true);
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            // Similar checks for macOS
            // Check for debugger via sysctl
            use std::process::Command;
            if let Ok(output) = Command::new("sysctl")
                .args(&["-n", "kern.proc.pid"])
                .output()
            {
                // Parse output for debug flags
                // (Simplified - real implementation would check specific flags)
            }
        }
        
        Ok(false)
    }
    
    /// Check for VM execution
    async fn check_vm(&self) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            // Check for VM-specific processes
            let vm_processes = ["vmtoolsd", "VBoxService", "vmware"];
            for proc in vm_processes {
                if self.check_process_exists(proc).await {
                    return Ok(true);
                }
            }
            
            // Check for VM-specific hardware (DMI)
            if let Ok(dmi) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
                let dmi_lower = dmi.to_lowercase();
                if dmi_lower.contains("vmware") || dmi_lower.contains("virtualbox") ||
                   dmi_lower.contains("qemu") || dmi_lower.contains("kvm") {
                    return Ok(true);
                }
            }
            
            // Check MAC address vendor (VMware: 00:50:56, VirtualBox: 08:00:27)
            // This would require network interface enumeration
        }
        
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::Registry::*;
            
            // Check registry for VM indicators
            unsafe {
                let mut hkey = windows::Win32::System::Registry::HKEY::default();
                let key_path = windows::core::PCSTR(b"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest\0".as_ptr());
                
                if RegOpenKeyExA(
                    HKEY_LOCAL_MACHINE,
                    key_path,
                    0,
                    KEY_READ,
                    &mut hkey,
                ).is_ok() {
                    RegCloseKey(hkey);
                    return Ok(true); // VirtualBox detected
                }
            }
            
            // Check for VMware processes
            if self.check_process_exists("vmtoolsd.exe").await {
                return Ok(true);
            }
            
            // CPUID hypervisor bit
            // (Would require inline assembly or CPUID instruction)
        }
        
        #[cfg(target_os = "macos")]
        {
            // Check for VM processes on macOS
            if self.check_process_exists("VMware").await ||
               self.check_process_exists("VirtualBox").await {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    async fn check_process_exists(&self, name: &str) -> bool {
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("pgrep")
                .arg(name)
                .output()
            {
                return output.status.success();
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("tasklist")
                .args(&["/FI", &format!("IMAGENAME eq {}", name)])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return stdout.contains(name);
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("pgrep")
                .arg(name)
                .output()
            {
                return output.status.success();
            }
        }
        
        false
    }
    
    async fn handle_detection(&self, action: &DetectionAction) -> Result<()> {
        let mut count = self.detection_count.lock().await;
        *count += 1;
        
        match action {
            DetectionAction::SelfDestruct => {
                std::process::exit(1);
            }
            DetectionAction::Dormant => {
                // Enter dormant mode (would implement state machine)
                // For now, just log
                eprintln!("[ANTI-DEBUG] Entering dormant mode");
            }
            DetectionAction::Continue => {
                eprintln!("[ANTI-DEBUG] Detection logged (count: {})", count);
            }
        }
        
        Ok(())
    }
    
    /// Get detection count
    pub async fn get_detection_count(&self) -> u32 {
        *self.detection_count.lock().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_anti_debug_config() {
        let config = AntiDebugConfig {
            enable_anti_debug: true,
            enable_anti_vm: true,
            action_on_detection: DetectionAction::Continue,
        };
        
        let anti_debug = AntiDebug::new(config);
        let detected = anti_debug.check().await.unwrap();
        // Should not detect in test environment (unless actually being debugged)
        // This test just verifies the code compiles and runs
        let _ = detected;
    }
}

