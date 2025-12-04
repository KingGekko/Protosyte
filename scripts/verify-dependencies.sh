#!/bin/bash
# Dependency Verification Script
# Checks all dependencies for latest versions

set -e

echo "=== Protosyte Dependency Verification ==="
echo ""

# Check Rust/Cargo version
echo "Rust/Cargo Version:"
cargo --version
echo ""

# Check Go version
echo "Go Version:"
go version
echo ""

# Check Rust dependencies
echo "=== Checking Rust Dependencies (protosyte-seed) ==="
cd protosyte-seed

if command -v cargo-outdated &> /dev/null; then
    echo "Checking for outdated Rust crates..."
    cargo outdated || echo "Some dependencies may have updates available"
else
    echo "cargo-outdated not installed. Install with: cargo install cargo-outdated"
    echo "Checking current versions..."
    cargo tree --depth 1
fi

echo ""
cd ..

# Check Go dependencies
for component in broadcast-engine analysis-rig legal-bridge; do
    echo "=== Checking Go Dependencies ($component) ==="
    cd "$component"
    
    echo "Current dependencies:"
    go list -m all | head -10
    
    echo ""
    echo "Checking for updates..."
    go list -u -m all 2>&1 | grep -E "\[.*\]" || echo "All dependencies up to date"
    
    echo ""
    cd ..
done

echo "=== Security Audit ==="

# Rust security audit
if command -v cargo-audit &> /dev/null; then
    echo "Running Rust security audit..."
    cd protosyte-seed
    cargo audit || echo "Security audit completed (warnings may exist)"
    cd ..
else
    echo "cargo-audit not installed. Install with: cargo install cargo-audit"
fi

# Go vulnerability check
if command -v govulncheck &> /dev/null; then
    echo "Running Go vulnerability check..."
    for component in broadcast-engine analysis-rig legal-bridge; do
        echo "Checking $component..."
        cd "$component"
        govulncheck ./... || true
        cd ..
    done
else
    echo "govulncheck not installed. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"
fi

echo ""
echo "=== Verification Complete ==="
echo "Review the output above and update dependencies as needed."

