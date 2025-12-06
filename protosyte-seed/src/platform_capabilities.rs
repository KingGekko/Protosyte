// Platform Capability Detection
// Detects platform capabilities and enables/disables features accordingly

use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub ebpf: bool,
    pub kprobes: bool,
    pub direct_syscalls: bool,
    pub dll_injection: bool,
    pub dyld_injection: bool,
    pub raw_sockets: bool,
    pub kernel_modules: bool,
}

pub struct CapabilityDetector;

impl CapabilityDetector {
    /// Detect all platform capabilities
    pub fn detect() -> PlatformCapabilities {
        #[cfg(target_os = "linux")]
        {
            PlatformCapabilities {
                ebpf: Self::check_ebpf(),
                kprobes: Self::check_kprobes(),
                direct_syscalls: true,
                dll_injection: false,
                dyld_injection: false,
                raw_sockets: Self::check_raw_sockets(),
                kernel_modules: Self::check_kernel_modules(),
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            PlatformCapabilities {
                ebpf: false,
                kprobes: false,
                direct_syscalls: Self::check_direct_syscalls_windows(),
                dll_injection: true,
                dyld_injection: false,
                raw_sockets: Self::check_raw_sockets(),
                kernel_modules: false,
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            PlatformCapabilities {
                ebpf: false,
                kprobes: false,
                direct_syscalls: true,
                dll_injection: false,
                dyld_injection: true,
                raw_sockets: Self::check_raw_sockets(),
                kernel_modules: false,
            }
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            PlatformCapabilities {
                ebpf: false,
                kprobes: false,
                direct_syscalls: true,
                dll_injection: false,
                dyld_injection: false,
                raw_sockets: false,
                kernel_modules: false,
            }
        }
    }
    
    #[cfg(target_os = "linux")]
    fn check_ebpf() -> bool {
        // Check kernel version (eBPF requires 4.4+)
        if let Ok(version) = std::fs::read_to_string("/proc/version") {
            // Parse kernel version
            // Simplified check
            version.contains("Linux")
        } else {
            false
        }
    }
    
    #[cfg(target_os = "linux")]
    fn check_kprobes() -> bool {
        // Check if /sys/kernel/debug/tracing is available
        std::path::Path::new("/sys/kernel/debug/tracing").exists()
    }
    
    #[cfg(target_os = "linux")]
    fn check_raw_sockets() -> bool {
        // Check CAP_NET_RAW capability
        // Simplified - would check actual capabilities
        true
    }
    
    #[cfg(target_os = "linux")]
    fn check_kernel_modules() -> bool {
        // Check if kernel modules can be loaded
        std::path::Path::new("/proc/modules").exists()
    }
    
    #[cfg(target_os = "windows")]
    fn check_direct_syscalls_windows() -> bool {
        // Windows 10+ supports direct syscalls
        use winapi::um::winnt::OSVERSIONINFOEXW;
        unsafe {
            let mut os_info: OSVERSIONINFOEXW = std::mem::zeroed();
            os_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
            
            // Would use RtlGetVersion
            // For now, assume Windows 10+
            true
        }
    }
    
    fn check_raw_sockets() -> bool {
        // Check if raw sockets are available
        // Would require root/admin on most systems
        false // Conservative default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_capability_detection() {
        let caps = CapabilityDetector::detect();
        assert!(caps.direct_syscalls); // Should be available on all platforms
    }
}


