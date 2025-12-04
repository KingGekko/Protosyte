#!/bin/bash
# Build script for macOS version

set -e

echo "[BUILD] Building protosyte-seed for macOS..."

cd protosyte-seed-macos

# Build macOS dynamic library
RUSTFLAGS='-C panic=abort -C strip=symbols -C opt-level=z' \
cargo build --release \
  --target x86_64-apple-darwin

echo "[BUILD] Dynamic library built at target/x86_64-apple-darwin/release/libprotosyte.dylib"

# For Apple Silicon, also build:
# cargo build --release --target aarch64-apple-darwin

echo "[BUILD] Build complete"

