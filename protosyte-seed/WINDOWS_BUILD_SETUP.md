# Windows Build Setup Guide

## Current Status

✅ **Good News**: The library compiles successfully without NASM/CMake currently installed!

The NASM requirement mentioned in the code quality assessment was for `aws-lc-sys`, but the current build doesn't require it.

## If You Need to Install NASM/CMake

### Solution 1: Run as Administrator (Recommended)

1. **Right-click** on PowerShell or Command Prompt
2. Select **"Run as Administrator"**
3. Run the installation:

```powershell
choco install nasm cmake -y
```

### Solution 2: Manual Installation (No Admin Required)

**NASM:**
1. Download NASM from: https://www.nasm.us/pub/nasm/releasebuilds/3.1.0/win64/
2. Extract to a user directory: `C:\Users\YourName\Tools\nasm`
3. Add to your user PATH:
   ```powershell
   $env:Path += ";C:\Users\YourName\Tools\nasm"
   ```
4. Or add permanently via System Properties → Environment Variables

**CMake:**
1. Download CMake installer: https://cmake.org/download/
2. During installation, choose "Add CMake to system PATH for all users" (if admin) or "Add CMake to system PATH for current user" (if not admin)

### Solution 3: Use Scoop (Alternative Package Manager)

If you prefer not to use admin rights:

```powershell
# Install Scoop (no admin required)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex

# Install NASM and CMake
scoop install nasm cmake
```

### Solution 4: Skip Installation (Current State)

**You don't need NASM/CMake right now!** The library builds successfully without them.

Only install if:
- You encounter build errors mentioning NASM
- You want to use features that require native crypto backends
- You're setting up a CI/CD environment

## Verification

After installation, verify:

```powershell
nasm --version
cmake --version
```

## Troubleshooting

### "Access Denied" Error
- **Cause**: Chocolatey requires administrator privileges
- **Solution**: Run terminal as Administrator, or use manual installation (Solution 2)

### "Command Not Found"
- **Cause**: Tool not in PATH
- **Solution**: 
  - Restart terminal after installation
  - Manually add to PATH if needed
  - Use full path: `C:\Program Files\NASM\nasm.exe`

### Build Still Fails
- Check if the error is actually related to NASM
- Current build works without NASM, so the issue might be elsewhere
- Check `cargo build --release --lib` output for actual errors

## Current Build Status

✅ Library compiles: `cargo build --release --lib`  
✅ No NASM required for current dependencies  
✅ All critical issues from code quality assessment addressed

## Next Steps

1. **If build works**: No action needed! Continue development.
2. **If you get NASM errors**: Follow Solution 1 or 2 above.
3. **For CI/CD**: Install NASM/CMake in your build environment.

---

**Note**: The code quality assessment mentioned NASM as a potential issue, but the current dependency tree doesn't require it. This guide is provided for future reference or if you add dependencies that do require it.


