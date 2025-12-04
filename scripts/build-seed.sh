#!/bin/bash
# Build command for a minimal, static, stripped binary

set -e

echo "[BUILD] Building protosyte-seed..."

RUSTFLAGS='-C panic=abort -C strip=symbols -C opt-level=z' \
cargo build --release \
  --target x86_64-unknown-linux-musl

echo "[BUILD] Binary built at target/x86_64-unknown-linux-musl/release/protosyte-seed"

# Optional: Further strip and compress with UPX
if command -v upx &> /dev/null; then
    echo "[BUILD] Compressing with UPX..."
    upx --ultra-brute target/x86_64-unknown-linux-musl/release/protosyte-seed
fi

echo "[BUILD] Build complete"

