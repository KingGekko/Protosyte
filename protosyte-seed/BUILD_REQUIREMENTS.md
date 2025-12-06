# Build Requirements for Protosyte

## Windows Build Dependencies

### Required Tools

1. **NASM** (Netwide Assembler) - Required by `aws-lc-sys` crypto backend
2. **CMake** - Build system for native dependencies

### Installation Options

#### Option 1: Chocolatey (Recommended - Requires Admin)

Run PowerShell or Command Prompt **as Administrator**, then:

```powershell
choco install nasm cmake -y
```

#### Option 2: Manual Installation

**NASM:**
1. Download from: https://www.nasm.us/pub/nasm/releasebuilds/
2. Extract to a directory (e.g., `C:\nasm`)
3. Add to PATH: `C:\nasm`

**CMake:**
1. Download from: https://cmake.org/download/
2. Install using the installer
3. Ensure "Add CMake to system PATH" is checked during installation

#### Option 3: Alternative Crypto Backend (No NASM Required)

If you cannot install NASM, you can switch to the `ring` crypto backend instead of `aws-lc-sys`:

```toml
# In Cargo.toml, replace aws-lc-sys with:
ring = "0.17"  # Pure Rust crypto, no NASM required
```

Then update crypto code to use `ring` instead of `aws-lc-sys`.

#### Option 4: Use Pre-built Binaries

Some Rust crates provide pre-built binaries that don't require NASM:
- Use `rustls` instead of `native-tls` for TLS
- Use `ring` instead of `aws-lc-sys` for crypto

### Verification

After installation, verify tools are available:

```bash
nasm --version
cmake --version
```

### Troubleshooting

**Issue**: "Access to the path 'C:\ProgramData\chocolatey\lib\nasm\tools' is denied"
- **Solution**: Run terminal as Administrator

**Issue**: "NASM command not found"
- **Solution**: Add NASM to system PATH or use full path

**Issue**: Build still fails with NASM errors
- **Solution**: Try switching to `ring` crypto backend (see Option 3)

### Alternative: Docker Build

If you cannot install dependencies locally, use Docker:

```dockerfile
FROM rust:latest
RUN apt-get update && apt-get install -y nasm cmake
WORKDIR /app
COPY . .
RUN cargo build --release
```

### CI/CD Recommendations

For CI/CD pipelines, ensure build environment includes:
- NASM (or use `ring` backend)
- CMake
- Rust toolchain
- All Rust dependencies

---

**Note**: The library currently compiles successfully without these dependencies if you're not using features that require them. NASM is only needed for the `aws-lc-sys` crypto backend.


