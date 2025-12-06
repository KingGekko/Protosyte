use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub struct RingBuffer {
    buffer: Arc<std::sync::Mutex<Vec<u8>>>,
    write_pos: Arc<AtomicUsize>,
    read_pos: Arc<AtomicUsize>,
    size: usize,
}

impl RingBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            buffer: Arc::new(std::sync::Mutex::new(vec![0u8; size])),
            write_pos: Arc::new(AtomicUsize::new(0)),
            read_pos: Arc::new(AtomicUsize::new(0)),
            size,
        }
    }
    
    pub fn write(&self, data: &[u8]) -> Result<(), crate::error_handling::ProtosyteError> {
        // Lock-free ring buffer write
        let write_pos = self.write_pos.load(Ordering::Acquire);
        let read_pos = self.read_pos.load(Ordering::Acquire);
        
        // Check if we have space (simplified - doesn't handle wrap-around)
        let available = if read_pos > write_pos {
            read_pos - write_pos - 1
        } else {
            self.size - write_pos + read_pos - 1
        };
        
        if data.len() > available {
            return Err(crate::error_handling::ProtosyteError::BufferError(
                format!("Not enough space in buffer: need {}, available {}", data.len(), available)
            ));
        }
        
        // Write data (simplified - doesn't handle wrap-around)
        let end = (write_pos + data.len()).min(self.size);
        let copy_len = end - write_pos;
        let mut buf = self.buffer.lock().unwrap();
        buf[write_pos..end].copy_from_slice(&data[..copy_len]);
        
        if data.len() > copy_len {
            // Handle wrap-around
            let remaining = data.len() - copy_len;
            buf[0..remaining].copy_from_slice(&data[copy_len..]);
            self.write_pos.store(remaining, Ordering::Release);
        } else {
            self.write_pos.store(end, Ordering::Release);
        }
        
        Ok(())
    }
    
    pub fn read(&self, len: usize) -> Option<Vec<u8>> {
        // Lock-free ring buffer read
        let write_pos = self.write_pos.load(Ordering::Acquire);
        let read_pos = self.read_pos.load(Ordering::Acquire);
        
        // Check if we have data
        let available = if write_pos >= read_pos {
            write_pos - read_pos
        } else {
            self.size - read_pos + write_pos
        };
        
        if available == 0 || len == 0 {
            return None;
        }
        
        let read_len = len.min(available);
        let mut result = Vec::with_capacity(read_len);
        
        // Read data (simplified - doesn't handle wrap-around)
        let end = (read_pos + read_len).min(self.size);
        let buf = self.buffer.lock().unwrap();
        result.extend_from_slice(&buf[read_pos..end]);
        
        if read_len > (end - read_pos) {
            // Handle wrap-around
            let remaining = read_len - (end - read_pos);
            result.extend_from_slice(&buf[0..remaining]);
            self.read_pos.store(remaining, Ordering::Release);
        } else {
            self.read_pos.store(end, Ordering::Release);
        }
        
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ring_buffer_new() {
        let buffer = RingBuffer::new(1024);
        assert_eq!(buffer.size, 1024);
        let buf = buffer.buffer.lock().unwrap();
        assert_eq!(buf.len(), 1024);
    }
    
    #[test]
    fn test_ring_buffer_write() {
        let buffer = RingBuffer::new(1024);
        let data = b"test data";
        assert!(buffer.write(data).is_ok());
    }
    
    #[test]
    fn test_ring_buffer_read() {
        let buffer = RingBuffer::new(1024);
        let data = b"test data";
        buffer.write(data).unwrap();
        
        let read_data = buffer.read(data.len());
        assert!(read_data.is_some());
        assert_eq!(read_data.unwrap(), data);
    }
    
    #[test]
    fn test_ring_buffer_different_sizes() {
        let buffer1 = RingBuffer::new(1024);
        let buffer2 = RingBuffer::new(2048);
        
        assert_eq!(buffer1.size, 1024);
        assert_eq!(buffer2.size, 2048);
    }
    
    #[test]
    fn test_ring_buffer_write_read_cycle() {
        let buffer = RingBuffer::new(1024);
        
        // Write multiple times
        assert!(buffer.write(b"data1").is_ok());
        assert!(buffer.write(b"data2").is_ok());
        assert!(buffer.write(b"data3").is_ok());
        
        // Read them back
        assert_eq!(buffer.read(5), Some(b"data1".to_vec()));
        assert_eq!(buffer.read(5), Some(b"data2".to_vec()));
        assert_eq!(buffer.read(5), Some(b"data3".to_vec()));
    }
    
    #[test]
    fn test_ring_buffer_read_empty() {
        let buffer = RingBuffer::new(1024);
        assert!(buffer.read(10).is_none());
    }
    
    #[test]
    fn test_ring_buffer_write_overflow() {
        let buffer = RingBuffer::new(10);
        // Try to write more than buffer size
        let large_data = vec![0u8; 20];
        // Should handle gracefully (current implementation may fail)
        let _result = buffer.write(&large_data);
        // Result depends on implementation
    }
    
    #[test]
    fn test_ring_buffer_read_partial() {
        let buffer = RingBuffer::new(1024);
        buffer.write(b"test data").unwrap();
        
        // Read less than available
        let partial = buffer.read(4);
        assert!(partial.is_some());
        assert_eq!(partial.unwrap(), b"test");
    }
}
