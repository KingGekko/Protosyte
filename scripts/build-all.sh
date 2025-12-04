#!/bin/bash
# Build All Protosyte Components
# Builds all components of the framework

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Building Protosyte Framework ===${NC}"

# Build Silent Seed (Linux)
echo -e "${GREEN}[1/6] Building Silent Seed (Linux)...${NC}"
cd "$PROJECT_ROOT/protosyte-seed"
cargo build --release || echo -e "${YELLOW}Failed to build Linux seed (may need Rust toolchain)${NC}"

# Build Silent Seed (Windows)
echo -e "${GREEN}[2/6] Building Silent Seed (Windows)...${NC}"
cd "$PROJECT_ROOT/protosyte-seed-windows"
cargo build --release --target x86_64-pc-windows-msvc 2>/dev/null || echo -e "${YELLOW}Failed to build Windows seed (may need Windows target)${NC}"

# Build Silent Seed (macOS)
echo -e "${GREEN}[3/6] Building Silent Seed (macOS)...${NC}"
cd "$PROJECT_ROOT/protosyte-seed-macos"
cargo build --release --target x86_64-apple-darwin 2>/dev/null || echo -e "${YELLOW}Failed to build macOS seed (may need macOS target)${NC}"

# Build Broadcast Engine
echo -e "${GREEN}[4/6] Building Broadcast Engine...${NC}"
cd "$PROJECT_ROOT/broadcast-engine"
go build -o protosyte-broadcast . || echo -e "${YELLOW}Failed to build broadcast engine${NC}"

# Build Analysis Rig
echo -e "${GREEN}[5/6] Building Analysis Rig...${NC}"
cd "$PROJECT_ROOT/analysis-rig"
go build -o protosyte-rig . || echo -e "${YELLOW}Failed to build analysis rig${NC}"

# Build Legal Bridge
echo -e "${GREEN}[6/6] Building Legal Bridge...${NC}"
cd "$PROJECT_ROOT/legal-bridge"
CGO_ENABLED=0 go build -o protosyte-bridge . || echo -e "${YELLOW}Failed to build legal bridge${NC}"

# Build AdaptixC2 Bridge (optional)
if [ -d "$PROJECT_ROOT/protosyte-adaptixc2" ]; then
    echo -e "${GREEN}[7/8] Building AdaptixC2 Bridge...${NC}"
    cd "$PROJECT_ROOT/protosyte-adaptixc2"
    go build -o protosyte-adaptixc2 . || echo -e "${YELLOW}Failed to build AdaptixC2 bridge${NC}"
fi

echo "      Run './scripts/setup-env.sh' to install dependencies automatically"

