// Ring Buffer Optimization with Wait/Notify Mechanism
// Eliminates busy polling, reduces CPU usage dramatically

use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use std::collections::VecDeque;
use std::time::Instant;

pub struct OptimizedRingBuffer<T> {
    buffer: Arc<Mutex<VecDeque<T>>>,
    max_size: usize,
    notify: Arc<Notify>,
    producer_count: Arc<Mutex<usize>>,
}

impl<T> OptimizedRingBuffer<T> {
    pub fn new(max_size: usize) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(VecDeque::with_capacity(max_size))),
            max_size,
            notify: Arc::new(Notify::new()),
            producer_count: Arc::new(Mutex::new(0)),
        }
    }
    
    /// Push item to buffer (non-blocking)
    pub async fn push(&self, item: T) -> Result<(), String> {
        let mut buffer = self.buffer.lock().await;
        
        // If buffer is full, remove oldest item (ring buffer behavior)
        if buffer.len() >= self.max_size {
            buffer.pop_front();
        }
        
        buffer.push_back(item);
        
        // Notify waiting consumers
        self.notify.notify_one();
        
        Ok(())
    }
    
    /// Pop item from buffer (blocks until data available)
    pub async fn pop(&self) -> T {
        loop {
            // Try to get item without blocking
            {
                let mut buffer = self.buffer.lock().await;
                if let Some(item) = buffer.pop_front() {
                    return item;
                }
            }
            
            // Wait for notification
            self.notify.notified().await;
        }
    }
    
    /// Try to pop item without blocking
    pub async fn try_pop(&self) -> Option<T> {
        let mut buffer = self.buffer.lock().await;
        buffer.pop_front()
    }
    
    /// Get current size
    pub async fn len(&self) -> usize {
        let buffer = self.buffer.lock().await;
        buffer.len()
    }
    
    /// Check if buffer is empty
    pub async fn is_empty(&self) -> bool {
        let buffer = self.buffer.lock().await;
        buffer.is_empty()
    }
    
    /// Clear buffer
    pub async fn clear(&self) {
        let mut buffer = self.buffer.lock().await;
        buffer.clear();
    }
}

// Double-buffered ring buffer for concurrent read/write
pub struct DoubleBufferedRingBuffer<T> {
    active_buffer: Arc<Mutex<VecDeque<T>>>,
    swap_buffer: Arc<Mutex<VecDeque<T>>>,
    max_size: usize,
    notify: Arc<Notify>,
    swap_lock: Arc<Mutex<()>>,
}

impl<T> DoubleBufferedRingBuffer<T> {
    pub fn new(max_size: usize) -> Self {
        Self {
            active_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(max_size))),
            swap_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(max_size))),
            max_size,
            notify: Arc::new(Notify::new()),
            swap_lock: Arc::new(Mutex::new(())),
        }
    }
    
    /// Push item to active buffer
    pub async fn push(&self, item: T) -> Result<(), String> {
        let mut buffer = self.active_buffer.lock().await;
        
        if buffer.len() >= self.max_size {
            // Swap buffers if active is full
            self.swap_buffers().await?;
            buffer = self.active_buffer.lock().await;
        }
        
        buffer.push_back(item);
        self.notify.notify_one();
        
        Ok(())
    }
    
    /// Pop all items from active buffer (for batch processing)
    pub async fn pop_all(&self) -> Vec<T> {
        loop {
            {
                let mut buffer = self.active_buffer.lock().await;
                if !buffer.is_empty() {
                    let items: Vec<T> = buffer.drain(..).collect();
                    return items;
                }
            }
            
            self.notify.notified().await;
        }
    }
    
    async fn swap_buffers(&self) -> Result<(), String> {
        let _lock = self.swap_lock.lock().await;
        
        let mut active = self.active_buffer.lock().await;
        let mut swap = self.swap_buffer.lock().await;
        
        std::mem::swap(&mut *active, &mut *swap);
        swap.clear();
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_ring_buffer_push_pop() {
        let buffer = OptimizedRingBuffer::new(10);
        
        buffer.push(1).await.unwrap();
        buffer.push(2).await.unwrap();
        
        assert_eq!(buffer.pop().await, 1);
        assert_eq!(buffer.pop().await, 2);
    }
    
    #[tokio::test]
    async fn test_ring_buffer_blocking() {
        let buffer = Arc::new(OptimizedRingBuffer::new(10));
        let buffer_clone = buffer.clone();
        
        // Spawn producer
        tokio::spawn(async move {
            tokio::time::sleep(crate::constants::POLL_INTERVAL_NORMAL).await;
            buffer_clone.push(42).await.unwrap();
        });
        
        // Consumer should block until data arrives
        let start = Instant::now();
        let value = buffer.pop().await;
        let elapsed = start.elapsed();
        
        assert_eq!(value, 42);
        assert!(elapsed.as_millis() >= 100);
    }
    
    #[tokio::test]
    async fn test_double_buffered() {
        let buffer = DoubleBufferedRingBuffer::new(5);
        
        for i in 0..10 {
            buffer.push(i).await.unwrap();
        }
        
        let items = buffer.pop_all().await;
        assert_eq!(items.len(), 5); // Should get items from active buffer
    }
}

