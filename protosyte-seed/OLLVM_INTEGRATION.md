# O-LLVM Obfuscation Integration Guide

This guide explains how to integrate O-LLVM (Obfuscator-LLVM) into the Protosyte build process for compile-time code obfuscation.

## What is O-LLVM?

O-LLVM is an LLVM-based obfuscator that provides:
- Control flow flattening
- Instruction substitution
- Bogus control flow
- Function splitting
- String encryption

This is **much safer** than runtime polymorphism, which can cause crashes.

## Prerequisites

### Option 1: Install O-LLVM (Recommended)

```bash
# Ubuntu/Debian
sudo apt-get install obfuscator-llvm-14

# Or build from source (see O-LLVM GitHub)
git clone https://github.com/obfuscator-llvm/obfuscator.git
cd obfuscator
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install
```

### Option 2: Use Docker (Easier)

```bash
# Use pre-built O-LLVM Docker image
docker pull obfuscator-llvm/obfuscator:latest
```

## Integration Methods

### Method 1: Custom Rust Toolchain (Recommended)

Create a custom Rust toolchain that uses O-LLVM:

```bash
# Install rustup-component for custom LLVM
rustup component add rustc-dev

# Configure Rust to use O-LLVM LLVM
# This requires modifying rustc's build configuration
```

### Method 2: Post-Build Obfuscation

Obfuscate the compiled binary after Rust compilation:

1. **Create obfuscation script** (`scripts/obfuscate-binary.sh`):

```bash
#!/bin/bash
# Obfuscate compiled Rust binary using O-LLVM

BINARY="$1"
OBFUSCATED="$2"

# Disassemble to LLVM IR
llvm-extract "$BINARY" -o temp.ll

# Apply obfuscation passes
opt -load /usr/lib/obfuscator/libObfuscatorPass.so \
    -fla -sub -bcf -split \
    temp.ll -o obfuscated.ll

# Recompile
clang obfuscated.ll -o "$OBFUSCATED"

rm -f temp.ll obfuscated.ll
```

2. **Modify build script** to call obfuscation:

```bash
# In scripts/build-all.sh, after cargo build:
if [ "$OBFUSCATE" = "true" ]; then
    ./scripts/obfuscate-binary.sh \
        target/release/protosyte-seed \
        target/release/protosyte-seed-obfuscated
fi
```

### Method 3: Docker Build with O-LLVM

```dockerfile
# Dockerfile.obfuscated
FROM rust:1.75 as builder

# Install O-LLVM
RUN apt-get update && apt-get install -y obfuscator-llvm-14

# Copy source
COPY . /app
WORKDIR /app/protosyte-seed

# Build with obfuscation
RUN cargo build --release

# Post-process binary with O-LLVM
RUN opt -load /usr/lib/obfuscator/libObfuscatorPass.so \
    -fla -sub -bcf target/release/protosyte-seed
```

## Build Configuration

### Using Cargo Features

Add to `Cargo.toml`:

```toml
[features]
default = []
obfuscate = []  # Enable obfuscation (requires O-LLVM)
```

### Environment Variables

```bash
export OBFUSCATE=1
export OLLVM_PATH=/usr/lib/obfuscator
cargo build --release --features obfuscate
```

## Obfuscation Passes

### Control Flow Flattening (`-fla`)

Flattens control flow graphs to make reverse engineering harder.

**Usage:**
```bash
opt -load libObfuscatorPass.so -fla input.ll -o output.ll
```

### Instruction Substitution (`-sub`)

Replaces simple instructions with more complex equivalents.

**Usage:**
```bash
opt -load libObfuscatorPass.so -sub input.ll -o output.ll
```

### Bogus Control Flow (`-bcf`)

Inserts fake conditional branches that are always true/false.

**Usage:**
```bash
opt -load libObfuscatorPass.so -bcf input.ll -o output.ll
```

### Function Splitting (`-split`)

Splits functions into multiple parts to obscure control flow.

**Usage:**
```bash
opt -load libObfuscatorPass.so -split input.ll -o output.ll
```

### Combine Multiple Passes

```bash
opt -load libObfuscatorPass.so \
    -fla -sub -bcf -split \
    input.ll -o output.ll
```

## Integration with Build.rs

Update `build.rs` to handle obfuscation:

```rust
fn main() {
    // Existing build steps...
    
    // Obfuscation (if enabled)
    if env::var("CARGO_FEATURE_OBFUSCATE").is_ok() {
        obfuscate_binary();
    }
}

fn obfuscate_binary() {
    use std::process::Command;
    
    let binary_path = env::var("CARGO_BIN_FILE_PROTOSYTE_SEED")
        .expect("Binary path not found");
    
    // Run O-LLVM obfuscation
    // Note: This requires the binary to be in LLVM IR format
    // Which may require additional tooling
}
```

## Alternative: Hikari Obfuscator

Hikari is a fork of O-LLVM with additional features:

```bash
git clone https://github.com/HikariObfuscator/Hikari.git
cd Hikari
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install
```

## Limitations

1. **Binary Size**: Obfuscation increases binary size significantly
2. **Performance**: Some passes can reduce performance
3. **Compatibility**: May break on some platforms
4. **Complexity**: Requires LLVM toolchain knowledge

## Recommendations

1. **Start Simple**: Use only `-fla` (control flow flattening) initially
2. **Test Thoroughly**: Obfuscation can introduce bugs
3. **Measure Impact**: Test performance and size impact
4. **Gradual Rollout**: Add passes incrementally

## Example Workflow

```bash
# 1. Build normally first
cargo build --release

# 2. Test the binary
./target/release/protosyte-seed --help

# 3. Build with obfuscation
OBFUSCATE=1 cargo build --release --features obfuscate

# 4. Verify obfuscation worked (check binary size increase)
ls -lh target/release/protosyte-seed*

# 5. Test obfuscated binary
./target/release/protosyte-seed-obfuscated --help
```

## Troubleshooting

### "ObfuscatorPass not found"
- Ensure O-LLVM is installed: `sudo apt-get install obfuscator-llvm-14`
- Check library path: `find /usr -name "libObfuscatorPass.so"`

### "Cannot load pass"
- Verify LLVM version matches between Rust and O-LLVM
- Check library dependencies: `ldd libObfuscatorPass.so`

### Build failures
- Try reducing obfuscation passes (use only `-fla`)
- Check Rust version compatibility
- Review O-LLVM logs for specific errors

## References

- [O-LLVM GitHub](https://github.com/obfuscator-llvm/obfuscator)
- [Hikari Obfuscator](https://github.com/HikariObfuscator/Hikari)
- [LLVM Pass Documentation](https://llvm.org/docs/WritingAnLLVMPass.html)

