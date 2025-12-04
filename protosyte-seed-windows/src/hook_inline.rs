// Windows Inline Hook Implementation (MinHook/Detours-style)
// Patches function prologues to redirect execution to our hook handlers

use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect, FlushInstructionCache};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::handleapi::CloseHandle;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

// Hook structure
pub struct InlineHook {
    target_function: *mut u8,
    original_bytes: Vec<u8>,
    trampoline: *mut u8,
    hook_function: *mut u8,
}

impl InlineHook {
    pub fn new(target: *mut u8, hook: extern "C" fn() -> i32) -> Result<Self, String> {
        unsafe {
            // Get function pointer
            let hook_fn = hook as *mut u8;
            
            // Create trampoline to store original bytes and jump back
            let trampoline = Self::create_trampoline(target, hook_fn)?;
            
            // Save original bytes
            let original_bytes = Self::read_function_prologue(target, 14)?; // x64: 14 bytes needed
            
            // Install hook
            Self::install_hook(target, hook_fn)?;
            
            Ok(Self {
                target_function: target,
                original_bytes,
                trampoline,
                hook_function: hook_fn,
            })
        }
    }
    
    // Create trampoline: original_bytes + jmp back to target+14
    unsafe fn create_trampoline(target: *mut u8, hook: *mut u8) -> Result<*mut u8, String> {
        let h_process = GetCurrentProcess();
        
        // Allocate executable memory for trampoline
        let tramp = VirtualAlloc(
            ptr::null_mut(),
            64,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        
        if tramp.is_null() {
            return Err("Failed to allocate trampoline".to_string());
        }
        
        let tramp_ptr = tramp as *mut u8;
        
        // Write original prologue bytes
        let orig_bytes = Self::read_function_prologue(target, 14)?;
        ptr::copy_nonoverlapping(orig_bytes.as_ptr(), tramp_ptr, orig_bytes.len());
        
        // Add JMP back to original function + 14
        let offset = (target as usize + 14) as i64 - (tramp_ptr as usize + orig_bytes.len() + 5) as i64;
        
        // JMP [RIP+offset] (x64)
        *tramp_ptr.add(orig_bytes.len()) = 0xE9; // JMP rel32
        ptr::write(tramp_ptr.add(orig_bytes.len() + 1) as *mut i32, offset as i32);
        
        // Make executable
        let mut old_protect = 0u32;
        VirtualProtect(
            tramp,
            64,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        
        FlushInstructionCache(h_process, tramp, 64);
        
        Ok(tramp_ptr)
    }
    
    // Read function prologue bytes
    unsafe fn read_function_prologue(func: *mut u8, len: usize) -> Result<Vec<u8>, String> {
        let mut bytes = vec![0u8; len];
        ptr::copy_nonoverlapping(func, bytes.as_mut_ptr(), len);
        Ok(bytes)
    }
    
    // Install inline hook: patch prologue with JMP to hook function
    unsafe fn install_hook(target: *mut u8, hook: *mut u8) -> Result<(), String> {
        let h_process = GetCurrentProcess();
        
        // Make memory writable
        let mut old_protect = 0u32;
        VirtualProtect(
            target as *mut winapi::ctypes::c_void,
            14,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        
        // Calculate relative offset
        let offset = hook as i64 - target as i64 - 5; // -5 for JMP instruction
        
        // Write JMP instruction (x64)
        *target = 0xE9; // JMP rel32
        ptr::write(target.add(1) as *mut i32, offset as i32);
        
        // NOP remaining bytes
        for i in 5..14 {
            *target.add(i) = 0x90; // NOP
        }
        
        // Restore protection
        VirtualProtect(
            target as *mut winapi::ctypes::c_void,
            14,
            old_protect,
            &mut old_protect,
        );
        
        FlushInstructionCache(h_process, target as *mut winapi::ctypes::c_void, 14);
        
        Ok(())
    }
    
    pub fn disable(&mut self) -> Result<(), String> {
        unsafe {
            let h_process = GetCurrentProcess();
            let mut old_protect = 0u32;
            
            VirtualProtect(
                self.target_function as *mut winapi::ctypes::c_void,
                14,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );
            
            // Restore original bytes
            ptr::copy_nonoverlapping(
                self.original_bytes.as_ptr(),
                self.target_function,
                self.original_bytes.len(),
            );
            
            VirtualProtect(
                self.target_function as *mut winapi::ctypes::c_void,
                14,
                old_protect,
                &mut old_protect,
            );
            
            FlushInstructionCache(h_process, self.target_function as *mut winapi::ctypes::c_void, 14);
        }
        
        Ok(())
    }
}

impl Drop for InlineHook {
    fn drop(&mut self) {
        let _ = self.disable();
        unsafe {
            if !self.trampoline.is_null() {
                use winapi::um::memoryapi::VirtualFree;
                use winapi::um::winnt::MEM_RELEASE;
                VirtualFree(self.trampoline as *mut winapi::ctypes::c_void, 0, MEM_RELEASE);
            }
        }
    }
}

