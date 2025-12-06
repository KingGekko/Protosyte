// Secure Memory Wiping
// Overwrites sensitive data with random bytes before deallocation

use zeroize::{Zeroize, ZeroizeOnDrop};
use std::alloc::{Layout, alloc, dealloc};
use std::ptr;

pub struct SecureMemory {
    data: *mut u8,
    size: usize,
}

unsafe impl Send for SecureMemory {}
unsafe impl Sync for SecureMemory {}

impl SecureMemory {
    /// Allocate secure memory that will be wiped on drop
    pub fn new(size: usize) -> Result<Self, crate::error_handling::ProtosyteError> {
        let layout = Layout::from_size_align(size, 8)
            .map_err(|e| crate::error_handling::ProtosyteError::SystemError(format!("Invalid layout: {}", e)))?;
        
        unsafe {
            let ptr = alloc(layout);
            if ptr.is_null() {
                return Err(crate::error_handling::ProtosyteError::SystemError(
                    "Memory allocation failed".to_string()
                ));
            }
            
            // Initialize with zeros
            ptr::write_bytes(ptr, 0, size);
            
            Ok(Self {
                data: ptr,
                size,
            })
        }
    }
    
    /// Write data to secure memory
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), crate::error_handling::ProtosyteError> {
        if offset + data.len() > self.size {
            return Err(crate::error_handling::ProtosyteError::SystemError(
                format!("Write out of bounds: offset {}, len {}, size {}", offset, data.len(), self.size)
            ));
        }
        
        unsafe {
            ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.data.add(offset),
                data.len(),
            );
        }
        
        Ok(())
    }
    
    /// Read data from secure memory
    pub fn read(&self, offset: usize, len: usize) -> Result<Vec<u8>, crate::error_handling::ProtosyteError> {
        if offset + len > self.size {
            return Err(crate::error_handling::ProtosyteError::SystemError(
                format!("Read out of bounds: offset {}, len {}, size {}", offset, len, self.size)
            ));
        }
        
        let mut result = vec![0u8; len];
        unsafe {
            ptr::copy_nonoverlapping(
                self.data.add(offset),
                result.as_mut_ptr(),
                len,
            );
        }
        
        Ok(result)
    }
    
    /// Get pointer to memory (use with caution)
    pub fn as_ptr(&self) -> *const u8 {
        self.data
    }
    
    /// Get mutable pointer to memory (use with caution)
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data
    }
    
    /// Securely wipe memory (3-pass overwrite)
    fn secure_wipe(&mut self) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        // 3-pass overwrite: random, zeros, random
        for pass in 0..3 {
            unsafe {
                for i in 0..self.size {
                    let byte = if pass == 1 {
                        0u8 // Second pass: zeros
                    } else {
                        rng.random::<u8>() // First and third pass: random
                    };
                    ptr::write_volatile(self.data.add(i), byte);
                }
            }
        }
    }
    
    /// Lock memory to prevent swapping to disk
    #[cfg(target_os = "linux")]
    pub fn lock_memory(&self) -> Result<(), crate::error_handling::ProtosyteError> {
        use nix::sys::mman::mlock;
        use nix::errno::Errno;
        
        unsafe {
            match mlock(self.data as *const _, self.size) {
                Ok(_) => Ok(()),
                Err(Errno::EPERM) => Err(crate::error_handling::ProtosyteError::SystemError(
                    "Insufficient privileges to lock memory".to_string()
                )),
                Err(e) => Err(crate::error_handling::ProtosyteError::SystemError(
                    format!("Failed to lock memory: {}", e)
                )),
            }
        }
    }
    
    #[cfg(target_os = "windows")]
    pub fn lock_memory(&self) -> Result<(), crate::error_handling::ProtosyteError> {
        use windows::Win32::System::Memory::VirtualLock;
        
        unsafe {
            let result = VirtualLock(self.data as *mut _, self.size);
            if result.is_ok() {
                Ok(())
            } else {
                Err(crate::error_handling::ProtosyteError::SystemError(
                    "Failed to lock memory".to_string()
                ))
            }
        }
    }
    
    #[cfg(target_os = "macos")]
    pub fn lock_memory(&self) -> Result<(), crate::error_handling::ProtosyteError> {
        use libc::mlock;
        
        unsafe {
            if mlock(self.data as *const _, self.size) == 0 {
                Ok(())
            } else {
                Err(crate::error_handling::ProtosyteError::SystemError(
                    "Failed to lock memory".to_string()
                ))
            }
        }
    }
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        // Securely wipe before deallocation
        self.secure_wipe();
        
        // Deallocate
        unsafe {
            let layout = Layout::from_size_align(self.size, 8).unwrap();
            dealloc(self.data, layout);
        }
    }
}

impl Zeroize for SecureMemory {
    fn zeroize(&mut self) {
        self.secure_wipe();
    }
}

/// Secure string that wipes on drop
#[derive(ZeroizeOnDrop)]
pub struct SecureString {
    inner: String,
}

impl SecureString {
    pub fn new(s: String) -> Self {
        Self { inner: s }
    }
    
    pub fn as_str(&self) -> &str {
        &self.inner
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

/// Wipe stack frame containing sensitive data
pub fn wipe_stack_frame<T>(_value: T) {
    // This is a no-op in Rust - stack frames are automatically cleaned up
    // But we can use volatile writes to ensure compiler doesn't optimize away
    use std::ptr;
    
    // Force compiler to not optimize away the value
    unsafe {
        let ptr = &_value as *const T as *const u8;
        let size = std::mem::size_of::<T>();
        for i in 0..size {
            ptr::write_volatile(ptr.add(i) as *mut u8, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_memory() {
        let mut mem = SecureMemory::new(100).unwrap();
        mem.write(0, b"test").unwrap();
        
        let data = mem.read(0, 4).unwrap();
        assert_eq!(data, b"test");
        
        // Memory will be wiped on drop
    }
    
    #[test]
    fn test_secure_string() {
        let s = SecureString::new("sensitive".to_string());
        assert_eq!(s.as_str(), "sensitive");
        
        // Will be zeroized on drop automatically via ZeroizeOnDrop
    }
}

