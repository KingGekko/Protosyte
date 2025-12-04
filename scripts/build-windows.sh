#!/bin/bash
# Build script for Windows version

set -e

echo "[BUILD] Building protosyte-seed for Windows..."

cd protosyte-seed-windows

# Build Windows DLL
RUSTFLAGS='-C panic=abort -C strip=symbols -C opt-level=z' \
cargo build --release \
  --target x86_64-pc-windows-msvc

echo "[BUILD] DLL built at target/x86_64-pc-windows-msvc/release/protosyte.dll"

# Optional: Compress with UPX (if available)
if command -v upx &> /dev/null; then
    echo "[BUILD] Compressing with UPX..."
    upx --ultra-brute target/x86_64-pc-windows-msvc/release/protosyte.dll
fi

echo "[BUILD] Build complete"

