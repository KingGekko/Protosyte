// Memory-Only IPC Implementation
// Uses Abstract Unix Domain Sockets (Linux) and Named Pipes (Windows)
// Zero filesystem footprint - completely invisible to file monitoring

use std::sync::Arc;
use tokio::sync::mpsc;
use std::sync::atomic::AtomicBool;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nix::sys::socket::{socket, AddressFamily, SockType, SockFlag, SockProtocol};
    use nix::sys::socket::{bind, listen, accept, sendmsg, recvmsg, MsgFlags};
    use nix::sys::socket::{sockaddr_un, UnixAddr};
    use nix::unistd::{close, unlink};
    use std::os::unix::io::{RawFd, AsRawFd};
    use std::ffi::CString;
    use std::path::Path;
    
    pub struct AbstractUnixSocket {
        fd: RawFd,
        path: String,
    }
    
    impl AbstractUnixSocket {
        pub fn new_random() -> Result<Self, String> {
            // Generate random abstract socket name (no filesystem path)
            let pid = std::process::id();
            let random: u64 = rand::random();
            let name = format!("\0protosyte_{}_{}", pid, random);
            
            let addr = UnixAddr::new_abstract(name.as_bytes())
                .map_err(|e| format!("Failed to create abstract address: {}", e))?;
            
            let fd = socket(
                AddressFamily::Unix,
                SockType::Stream,
                SockFlag::empty(),
                None,
            ).map_err(|e| format!("Failed to create socket: {}", e))?;
            
            bind(fd, &addr)
                .map_err(|e| format!("Failed to bind abstract socket: {}", e))?;
            
            listen(fd, 10)
                .map_err(|e| format!("Failed to listen: {}", e))?;
            
            Ok(Self {
                fd,
                path: name,
            })
        }
        
        pub fn accept_connection(&self) -> Result<RawFd, String> {
            accept(self.fd)
                .map_err(|e| format!("Failed to accept connection: {}", e))
        }
        
        pub fn send_data(&self, client_fd: RawFd, data: &[u8]) -> Result<(), String> {
            sendmsg(client_fd, &[data], &[], MsgFlags::empty(), None)
                .map_err(|e| format!("Failed to send: {}", e))?;
            Ok(())
        }
        
        pub fn recv_data(&self, client_fd: RawFd, buf: &mut [u8]) -> Result<usize, String> {
            recvmsg(client_fd, &mut [buf], None, MsgFlags::empty())
                .map_err(|e| format!("Failed to recv: {}", e))
                .map(|msg| msg.bytes)
        }
    }
    
    impl Drop for AbstractUnixSocket {
        fn drop(&mut self) {
            let _ = close(self.fd);
            // Abstract sockets don't need unlink - they disappear when closed
        }
    }
    
    pub struct MemfdRingBuffer {
        fd: RawFd,
        size: usize,
    }
    
    impl MemfdRingBuffer {
        pub fn new(size: usize) -> Result<Self, String> {
            use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
            use std::ffi::CString;
            
            let name = CString::new("protosyte_buffer").unwrap();
            let fd = memfd_create(&name, MemFdCreateFlag::MFD_CLOEXEC | MemFdCreateFlag::MFD_ALLOW_SEALING)
                .map_err(|e| format!("Failed to create memfd: {}", e))?;
            
            // Set size
            use nix::unistd::ftruncate;
            ftruncate(fd, size as i64)
                .map_err(|e| format!("Failed to truncate memfd: {}", e))?;
            
            Ok(Self { fd, size })
        }
        
        pub fn get_fd(&self) -> RawFd {
            self.fd
        }
        
        pub fn as_slice(&self) -> Result<&mut [u8], String> {
            unsafe {
                use std::ffi::c_void;
                let addr = nix::sys::mman::mmap(
                    None,
                    self.size,
                    nix::sys::mman::ProtFlags::PROT_READ | nix::sys::mman::ProtFlags::PROT_WRITE,
                    nix::sys::mman::MapFlags::MAP_SHARED,
                    self.fd,
                    0,
                ).map_err(|e| format!("Failed to mmap memfd: {}", e))?;
                
                Ok(std::slice::from_raw_parts_mut(addr as *mut u8, self.size))
            }
        }
    }
    
    impl Drop for MemfdRingBuffer {
        fn drop(&mut self) {
            let _ = nix::unistd::close(self.fd);
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use winapi::um::winbase::{CreateNamedPipeA, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, PIPE_READMODE_BYTE, PIPE_WAIT};
    use winapi::um::namedpipeapi::{ConnectNamedPipe, DisconnectNamedPipe};
    use winapi::um::fileapi::{ReadFile, WriteFile};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::winnt::{HANDLE, GENERIC_READ, GENERIC_WRITE};
    use std::ffi::CString;
    use std::os::windows::io::AsRawHandle;
    
    pub struct NamedPipe {
        handle: HANDLE,
        name: String,
    }
    
    impl NamedPipe {
        pub fn new_random() -> Result<Self, String> {
            let pid = std::process::id();
            let random: u64 = rand::random();
            let name = format!(r"\\.\pipe\protosyte_{}_{}", pid, random);
            
            let name_cstr = CString::new(name.clone())
                .map_err(|e| format!("Invalid pipe name: {}", e))?;
            
            let handle = unsafe {
                CreateNamedPipeA(
                    name_cstr.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1, // max instances
                    4096, // out buffer
                    4096, // in buffer
                    0, // default timeout
                    std::ptr::null_mut(), // default security
                )
            };
            
            if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
                return Err("Failed to create named pipe".to_string());
            }
            
            Ok(Self { handle, name })
        }
        
        pub fn wait_for_client(&self) -> Result<(), String> {
            unsafe {
                if ConnectNamedPipe(self.handle, std::ptr::null_mut()) == 0 {
                    let err = winapi::um::errhandlingapi::GetLastError();
                    if err != winapi::um::winerror::ERROR_PIPE_CONNECTED {
                        return Err(format!("Failed to connect pipe: {}", err));
                    }
                }
            }
            Ok(())
        }
        
        pub fn write(&self, data: &[u8]) -> Result<(), String> {
            unsafe {
                let mut written = 0u32;
                if WriteFile(
                    self.handle,
                    data.as_ptr() as *const _,
                    data.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                ) == 0 {
                    return Err("Failed to write to pipe".to_string());
                }
            }
            Ok(())
        }
        
        pub fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
            unsafe {
                let mut read = 0u32;
                if ReadFile(
                    self.handle,
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                ) == 0 {
                    return Err("Failed to read from pipe".to_string());
                }
                Ok(read as usize)
            }
        }
    }
    
    impl Drop for NamedPipe {
        fn drop(&mut self) {
            unsafe {
                DisconnectNamedPipe(self.handle);
                CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{AbstractUnixSocket, MemfdRingBuffer};

#[cfg(target_os = "windows")]
pub use windows::NamedPipe;


