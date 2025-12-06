// Traffic Padding and Shaping
// Adds random padding and shapes traffic to mimic legitimate protocols

use std::sync::Arc;
use tokio::sync::Mutex;
use rand::Rng;
use std::time::Duration;

pub struct TrafficPaddingConfig {
    pub padding_percentage: f32,      // 0.0-0.3 (0-30% padding)
    pub chunk_size_variance: f32,     // Variance in chunk sizes
    pub mimic_protocol: ProtocolType,  // Protocol to mimic
}

#[derive(Clone, Copy)]
pub enum ProtocolType {
    FileUpload,    // Steady stream, ~1 Mbps
    VideoStreaming, // Variable bitrate
    WebBrowsing,   // Bursty, small requests
    SoftwareUpdate, // Large bulk transfers
}

pub struct TrafficShaper {
    config: Arc<Mutex<TrafficPaddingConfig>>,
}

impl TrafficShaper {
    pub fn new(config: TrafficPaddingConfig) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
        }
    }
    
    /// Add padding to payload
    pub async fn add_padding(&self, data: &[u8]) -> Vec<u8> {
        let config = self.config.lock().await;
        let mut rng = rand::thread_rng();
        
        // Calculate padding size
        let padding_size = (data.len() as f32 * config.padding_percentage) as usize;
        let padding: Vec<u8> = (0..padding_size)
            .map(|_| rng.gen())
            .collect();
        
        // Combine data and padding
        let mut result = data.to_vec();
        result.extend_from_slice(&padding);
        
        result
    }
    
    /// Fragment payload into chunks with size variance
    pub async fn fragment(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let config = self.config.lock().await;
        let mut rng = rand::thread_rng();
        
        let base_chunk_size = match config.mimic_protocol {
            ProtocolType::FileUpload => 8192,      // 8KB chunks
            ProtocolType::VideoStreaming => 4096,   // 4KB chunks (variable)
            ProtocolType::WebBrowsing => 1024,       // 1KB chunks
            ProtocolType::SoftwareUpdate => 65536,  // 64KB chunks
        };
        
        let mut chunks = Vec::new();
        let mut offset = 0;
        
        while offset < data.len() {
            // Add variance to chunk size
            let variance = (base_chunk_size as f32 * config.chunk_size_variance) as usize;
            let chunk_size = base_chunk_size + rng.gen_range(-(variance as i32)..=variance as i32) as usize;
            let chunk_size = chunk_size.max(1).min(data.len() - offset);
            
            chunks.push(data[offset..offset + chunk_size].to_vec());
            offset += chunk_size;
        }
        
        chunks
    }
    
    /// Shape traffic according to protocol type
    pub async fn shape_traffic(&self, chunks: &[Vec<u8>]) -> Vec<(Vec<u8>, Duration)> {
        let config = self.config.lock().await;
        let mut rng = rand::thread_rng();
        
        match config.mimic_protocol {
            ProtocolType::FileUpload => {
                // Steady stream with occasional pauses
                chunks.iter().map(|chunk| {
                    let delay = if rng.gen_bool(0.1) {
                        Duration::from_millis(rng.gen_range(100..500)) // Occasional pause
                    } else {
                        Duration::from_millis(10) // Steady stream
                    };
                    (chunk.clone(), delay)
                }).collect()
            }
            ProtocolType::VideoStreaming => {
                // Variable bitrate with buffering pauses
                chunks.iter().map(|chunk| {
                    let delay = if rng.gen_bool(0.2) {
                        Duration::from_millis(rng.gen_range(50..200)) // Buffering
                    } else {
                        Duration::from_millis(rng.gen_range(5..30)) // Variable rate
                    };
                    (chunk.clone(), delay)
                }).collect()
            }
            ProtocolType::WebBrowsing => {
                // Bursty traffic
                chunks.iter().map(|chunk| {
                    let delay = if rng.gen_bool(0.3) {
                        Duration::from_millis(rng.gen_range(100..1000)) // Long pause
                    } else {
                        Duration::from_millis(rng.gen_range(1..10)) // Quick burst
                    };
                    (chunk.clone(), delay)
                }).collect()
            }
            ProtocolType::SoftwareUpdate => {
                // Large bulk transfer with occasional pauses
                chunks.iter().map(|chunk| {
                    let delay = if rng.gen_bool(0.05) {
                        Duration::from_millis(rng.gen_range(200..1000)) // Network pause
                    } else {
                        Duration::from_millis(5) // Fast transfer
                    };
                    (chunk.clone(), delay)
                }).collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_traffic_padding() {
        let config = TrafficPaddingConfig {
            padding_percentage: 0.1,
            chunk_size_variance: 0.2,
            mimic_protocol: ProtocolType::FileUpload,
        };
        
        let shaper = TrafficShaper::new(config);
        let data = vec![0u8; 1000];
        let padded = shaper.add_padding(&data).await;
        
        assert!(padded.len() >= data.len());
    }
    
    #[tokio::test]
    async fn test_fragmentation() {
        let config = TrafficPaddingConfig {
            padding_percentage: 0.0,
            chunk_size_variance: 0.1,
            mimic_protocol: ProtocolType::WebBrowsing,
        };
        
        let shaper = TrafficShaper::new(config);
        let data = vec![0u8; 10000];
        let chunks = shaper.fragment(&data).await;
        
        assert!(!chunks.is_empty());
    }
}

