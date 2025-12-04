#!/bin/bash
# Setup Environment
# Configures the development environment for Protosyte

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Protosyte Environment Setup ===${NC}"

# Check for .env file
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    echo -e "${YELLOW}Creating .env file from template...${NC}"
    cat > "$PROJECT_ROOT/.env" << EOF
# Protosyte Configuration
PROTOSYTE_BOT_TOKEN=your_bot_token_here
PROTOSYTE_PASSPHRASE=your_secure_passphrase_here


# AdaptixC2 Integration (Optional)
ADAPTIXC2_SERVER_URL=
ADAPTIXC2_API_KEY=

# Legal Bridge (Optional)
LE_PORTAL_URL=
LE_PORTAL_KEY=
EOF
    echo -e "${GREEN}.env file created. Please edit it with your values.${NC}"
else
    echo -e "${GREEN}.env file already exists${NC}"
fi

# Load .env file
if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a
    source "$PROJECT_ROOT/.env"
    set +a
fi

# Check dependencies
echo -e "${GREEN}Checking dependencies...${NC}"

# Check Rust
if command -v cargo &> /dev/null; then
    echo -e "${GREEN}✓ Rust/Cargo installed${NC}"
else
    echo -e "${YELLOW}⚠ Rust/Cargo not found. Install from https://rustup.rs/${NC}"
fi

# Check Go
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "${GREEN}✓ Go installed ($GO_VERSION)${NC}"
else
    echo -e "${YELLOW}⚠ Go not found. Install from https://go.dev/dl/${NC}"
fi

if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo -e "${GREEN}✓ Node.js installed ($NODE_VERSION)${NC}"
    
    fi
else
    echo -e "${YELLOW}⚠ Node.js not found. Install from https://nodejs.org/${NC}"
fi

# Check Tor
if command -v tor &> /dev/null; then
    echo -e "${GREEN}✓ Tor installed${NC}"
else
    echo -e "${YELLOW}⚠ Tor not found. Install for exfiltration support.${NC}"
fi

# Create necessary directories
echo -e "${GREEN}Creating necessary directories...${NC}"
mkdir -p "$PROJECT_ROOT/analysis-rig/static"
mkdir -p /tmp/rig_store
mkdir -p /tmp/rig_out

echo -e "${GREEN}=== Environment Setup Complete ===${NC}"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Run: ./scripts/build-all.sh"
echo "3. Run: ./scripts/start-all.sh"
echo ""
echo "CLI Usage:"
echo "  ./analysis-rig/protosyte-rig --mode stats"
echo "  ./analysis-rig/protosyte-rig --mode records"
echo "  ./analysis-rig/protosyte-rig --mode hosts"
echo "  ./analysis-rig/protosyte-rig --mode fip"

