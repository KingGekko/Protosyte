// IPC Tests Module

#[cfg(test)]
mod tests {
    // Import parent module items
    use crate::ipc::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_abstract_unix_socket_creation() {
        let socket = AbstractUnixSocket::new_random().unwrap();
        
        // Socket should be created successfully
        assert!(socket.fd >= 0);
        
        // Socket name should start with null byte (abstract socket)
        assert!(socket.path.starts_with('\0'));
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_memfd_ring_buffer() {
        let buffer = MemfdRingBuffer::new(4096).unwrap();
        
        // Verify buffer was created
        assert!(buffer.get_fd() >= 0);
        assert_eq!(buffer.size, 4096);
        
        // Test accessing the buffer as a slice
        let slice = buffer.as_slice().unwrap();
        assert_eq!(slice.len(), 4096);
        
        // Test writing to buffer
        slice[0..4].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(slice[0], 1);
        assert_eq!(slice[1], 2);
        assert_eq!(slice[2], 3);
        assert_eq!(slice[3], 4);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_ipc_no_filesystem_footprint() {
        use std::fs;
        use std::path::Path;
        
        // Create IPC components
        let socket = AbstractUnixSocket::new_random().unwrap();
        let buffer = MemfdRingBuffer::new(1024).unwrap();
        
        // Verify no files are created in /dev/shm
        let shm_path = Path::new("/dev/shm");
        if shm_path.exists() {
            let entries: Vec<_> = fs::read_dir(shm_path)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().contains("protosyte"))
                .collect();
            
            // Should have no protosyte files in /dev/shm (using memfd/abstract sockets)
            assert_eq!(entries.len(), 0, "No filesystem artifacts should be created");
        }
    }
}
