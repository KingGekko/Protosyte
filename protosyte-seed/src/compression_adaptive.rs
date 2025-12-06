// Adaptive Compression Algorithm Selection
// Chooses optimal compression based on data type and network conditions

use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::{Result, Context};

pub enum CompressionAlgorithm {
    LZ4,        // Fast, low ratio (~2:1), low CPU
    Zstandard,  // Balanced (250 MB/s), good ratio (~3:1), medium CPU
    LZMA,        // Slow (50 MB/s), excellent ratio (~5:1), high CPU
    Brotli,      // Medium (100 MB/s), very good ratio (~4:1), high CPU
}

pub struct CompressionStats {
    pub algorithm: CompressionAlgorithm,
    pub original_size: usize,
    pub compressed_size: usize,
    pub compression_ratio: f32,
    pub compression_time_ms: u64,
}

pub struct AdaptiveCompressor {
    network_bandwidth_mbps: Arc<Mutex<f32>>,
    time_sensitive: Arc<Mutex<bool>>,
    data_type: Arc<Mutex<DataType>>,
}

#[derive(Clone, Copy)]
pub enum DataType {
    Text,
    Binary,
    Encrypted,
    Mixed,
}

impl AdaptiveCompressor {
    pub fn new() -> Self {
        Self {
            network_bandwidth_mbps: Arc::new(Mutex::new(10.0)), // Default 10 Mbps
            time_sensitive: Arc::new(Mutex::new(false)),
            data_type: Arc::new(Mutex::new(DataType::Mixed)),
        }
    }
    
    /// Select optimal compression algorithm
    pub async fn select_algorithm(&self) -> CompressionAlgorithm {
        let bandwidth = *self.network_bandwidth_mbps.lock().await;
        let time_sensitive = *self.time_sensitive.lock().await;
        let data_type = *self.data_type.lock().await;
        
        // Decision logic:
        // - Text + not time-sensitive → LZMA (best compression)
        // - Low bandwidth (< 1 Mbps) → Zstandard (balanced)
        // - Time-sensitive → LZ4 (fastest)
        // - Default → Zstandard (balanced)
        
        match (data_type, time_sensitive, bandwidth) {
            (DataType::Text, false, _) => CompressionAlgorithm::LZMA,
            (_, true, _) => CompressionAlgorithm::LZ4,
            (_, _, bw) if bw < 1.0 => CompressionAlgorithm::Zstandard,
            _ => CompressionAlgorithm::Zstandard,
        }
    }
    
    /// Compress data with selected algorithm
    pub async fn compress(&self, data: &[u8]) -> Result<(Vec<u8>, CompressionStats)> {
        let algorithm = self.select_algorithm().await;
        let start = std::time::Instant::now();
        
        let compressed = match algorithm {
            CompressionAlgorithm::LZ4 => self.compress_lz4(data).await?,
            CompressionAlgorithm::Zstandard => self.compress_zstd(data).await?,
            CompressionAlgorithm::LZMA => self.compress_lzma(data).await?,
            CompressionAlgorithm::Brotli => self.compress_brotli(data).await?,
        };
        
        let elapsed = start.elapsed().as_millis() as u64;
        let ratio = compressed.len() as f32 / data.len() as f32;
        
        let stats = CompressionStats {
            algorithm,
            original_size: data.len(),
            compressed_size: compressed.len(),
            compression_ratio: ratio,
            compression_time_ms: elapsed,
        };
        
        Ok((compressed, stats))
    }
    
    async fn compress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        use lz4::block::compress;
        compress(data, Some(lz4::block::CompressionMode::HIGHCOMPRESSION(1)), true)
            .map_err(|e| anyhow::anyhow!("LZ4 compression failed: {}", e))
    }
    
    async fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "compression-adaptive")]
        {
            use zstd::encode_all;
            encode_all(data, 3) // Level 3 (balanced)
                .map_err(|e| anyhow::anyhow!("Zstandard compression failed: {}", e))
        }
        
        #[cfg(not(feature = "compression-adaptive"))]
        {
            // Fallback to LZ4
            self.compress_lz4(data).await
        }
    }
    
    async fn compress_lzma(&self, data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "compression-adaptive")]
        {
            use lzma_rs::lzma_compress;
            let mut compressed = Vec::new();
            lzma_compress(&mut std::io::Cursor::new(data), &mut compressed)
                .map_err(|e| anyhow::anyhow!("LZMA compression failed: {}", e))?;
            Ok(compressed)
        }
        
        #[cfg(not(feature = "compression-adaptive"))]
        {
            // Fallback to LZ4
            self.compress_lz4(data).await
        }
    }
    
    async fn compress_brotli(&self, data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "compression-adaptive")]
        {
            use brotli::enc::BrotliEncoderParams;
            use std::io::Write;
            
            let mut compressed = Vec::new();
            let params = BrotliEncoderParams::default();
            brotli::enc::BrotliCompress(
                &mut std::io::Cursor::new(data),
                &mut compressed,
                &params,
            ).map_err(|e| anyhow::anyhow!("Brotli compression failed: {}", e))?;
            Ok(compressed)
        }
        
        #[cfg(not(feature = "compression-adaptive"))]
        {
            // Fallback to LZ4
            self.compress_lz4(data).await
        }
    }
    
    /// Decompress data (auto-detect algorithm or use specified)
    pub async fn decompress(&self, compressed: &[u8], algorithm: Option<CompressionAlgorithm>) -> Result<Vec<u8>> {
        let algo = algorithm.unwrap_or_else(|| {
            // Auto-detect based on magic bytes
            if compressed.len() >= 4 {
                match &compressed[0..4] {
                    [0x04, 0x22, 0x4D, 0x18] => CompressionAlgorithm::LZ4,
                    [0x28, 0xB5, 0x2F, 0xFD] => CompressionAlgorithm::Zstandard,
                    [0x5D, 0x00, 0x00, 0x00] => CompressionAlgorithm::LZMA,
                    _ => CompressionAlgorithm::LZ4, // Default
                }
            } else {
                CompressionAlgorithm::LZ4
            }
        });
        
        match algo {
            CompressionAlgorithm::LZ4 => self.decompress_lz4(compressed).await,
            CompressionAlgorithm::Zstandard => self.decompress_zstd(compressed).await,
            CompressionAlgorithm::LZMA => self.decompress_lzma(compressed).await,
            CompressionAlgorithm::Brotli => self.decompress_brotli(compressed).await,
        }
    }
    
    async fn decompress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        use lz4::block::decompress;
        decompress(data, None)
            .map_err(|e| anyhow::anyhow!("LZ4 decompression failed: {}", e))
    }
    
    async fn decompress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "compression-adaptive")]
        {
            use zstd::decode_all;
            decode_all(data)
                .map_err(|e| anyhow::anyhow!("Zstandard decompression failed: {}", e))
        }
        
        #[cfg(not(feature = "compression-adaptive"))]
        {
            self.decompress_lz4(data).await
        }
    }
    
    async fn decompress_lzma(&self, data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "compression-adaptive")]
        {
            use lzma_rs::lzma_decompress;
            let mut decompressed = Vec::new();
            lzma_decompress(&mut std::io::Cursor::new(data), &mut decompressed)
                .map_err(|e| anyhow::anyhow!("LZMA decompression failed: {}", e))?;
            Ok(decompressed)
        }
        
        #[cfg(not(feature = "compression-adaptive"))]
        {
            self.decompress_lz4(data).await
        }
    }
    
    async fn decompress_brotli(&self, data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "compression-adaptive")]
        {
            use std::io::Read;
            let mut decompressed = Vec::new();
            brotli::Decompressor::new(std::io::Cursor::new(data), 4096)
                .read_to_end(&mut decompressed)
                .map_err(|e| anyhow::anyhow!("Brotli decompression failed: {}", e))?;
            Ok(decompressed)
        }
        
        #[cfg(not(feature = "compression-adaptive"))]
        {
            self.decompress_lz4(data).await
        }
    }
    
    /// Update network bandwidth estimate
    pub async fn update_bandwidth(&self, mbps: f32) {
        *self.network_bandwidth_mbps.lock().await = mbps;
    }
    
    /// Set time sensitivity
    pub async fn set_time_sensitive(&self, sensitive: bool) {
        *self.time_sensitive.lock().await = sensitive;
    }
    
    /// Set data type
    pub async fn set_data_type(&self, data_type: DataType) {
        *self.data_type.lock().await = data_type;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_compression_selection() {
        let compressor = AdaptiveCompressor::new();
        
        // Text + not time-sensitive → LZMA
        compressor.set_data_type(DataType::Text).await;
        compressor.set_time_sensitive(false).await;
        let algo = compressor.select_algorithm().await;
        assert!(matches!(algo, CompressionAlgorithm::LZMA));
        
        // Time-sensitive → LZ4
        compressor.set_time_sensitive(true).await;
        let algo = compressor.select_algorithm().await;
        assert!(matches!(algo, CompressionAlgorithm::LZ4));
    }
    
    #[tokio::test]
    async fn test_lz4_compress_decompress() {
        let compressor = AdaptiveCompressor::new();
        let data = b"test data for compression";
        
        let (compressed, stats) = compressor.compress(data).await.unwrap();
        assert!(compressed.len() < data.len());
        assert!(stats.compression_ratio < 1.0);
        
        let decompressed = compressor.decompress(&compressed, Some(CompressionAlgorithm::LZ4)).await.unwrap();
        assert_eq!(decompressed, data);
    }
}


