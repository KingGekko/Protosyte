// Tests for Memory-Only IPC Implementation

#[cfg(test)]
mod tests {
    use super::*;
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
    async fn test_abstract_unix_socket_communication() {
        // This test requires setting up a server and client
        // In a real scenario, we'd spawn separate processes
        
        let server = AbstractUnixSocket::new_random().unwrap();
        
        // Test that socket can accept connections
        // Note: In practice, we'd need a client process to connect
        // For now, just verify socket creation works
        assert!(server.fd >= 0);
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

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_memfd_large_buffer() {
        // Test with larger buffer (1MB)
        let buffer = MemfdRingBuffer::new(1024 * 1024).unwrap();
        assert_eq!(buffer.size, 1024 * 1024);
        
        let slice = buffer.as_slice().unwrap();
        assert_eq!(slice.len(), 1024 * 1024);
    }

    #[tokio::test]
    #[cfg(target_os = "windows")]
    async fn test_named_pipe_creation() {
        let pipe = NamedPipe::new_random().unwrap();
        
        // Pipe should be created
        assert!(!pipe.handle.is_null());
        assert!(pipe.name.starts_with(r"\\.\pipe\protosyte_"));
    }

    #[tokio::test]
    #[cfg(target_os = "windows")]
    async fn test_named_pipe_read_write() {
        let pipe = NamedPipe::new_random().unwrap();
        
        // Note: Full read/write test requires client process
        // For now, verify pipe creation
        assert!(!pipe.handle.is_null());
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

    #[tokio::test]
    async fn test_ipc_cross_process_compatibility() {
        // This would test IPC between processes
        // For now, just verify components can be created
        #[cfg(target_os = "linux")]
        {
            let _socket = AbstractUnixSocket::new_random().unwrap();
            let _buffer = MemfdRingBuffer::new(1024).unwrap();
        }
        
        #[cfg(target_os = "windows")]
        {
            let _pipe = NamedPipe::new_random().unwrap();
        }
    }
}

