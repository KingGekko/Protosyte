#!/bin/bash
# Start All Protosyte Components
# Automatically starts all necessary services for the framework

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Protosyte Framework Startup ===${NC}"

# Check environment variables
if [ -z "$PROTOSYTE_BOT_TOKEN" ]; then
    echo -e "${YELLOW}Warning: PROTOSYTE_BOT_TOKEN not set${NC}"
fi

if [ -z "$PROTOSYTE_PASSPHRASE" ]; then
    echo -e "${YELLOW}Warning: PROTOSYTE_PASSPHRASE not set${NC}"
fi

# Function to check if a port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        return 0
    else
        return 1
    fi
}

# Start Broadcast Engine
echo -e "${GREEN}[1/2] Starting Broadcast Engine...${NC}"
cd "$PROJECT_ROOT/broadcast-engine"
if [ ! -f "./protosyte-broadcast" ]; then
    echo "Building broadcast engine..."
    go build -o protosyte-broadcast .
fi

if check_port 8081; then
    echo -e "${YELLOW}Port 8081 already in use, skipping broadcast engine${NC}"
else
    nohup ./protosyte-broadcast > /tmp/protosyte-broadcast.log 2>&1 &
    echo $! > /tmp/protosyte-broadcast.pid
    echo -e "${GREEN}Broadcast Engine started (PID: $(cat /tmp/protosyte-broadcast.pid))${NC}"
    sleep 2
fi

# Start AdaptixC2 Bridge (if configured)
if [ ! -z "$ADAPTIXC2_SERVER_URL" ] && [ ! -z "$ADAPTIXC2_API_KEY" ]; then
    echo -e "${GREEN}[2/2] Starting AdaptixC2 Bridge...${NC}"
    cd "$PROJECT_ROOT/protosyte-adaptixc2"
    if [ ! -f "./protosyte-adaptixc2" ]; then
        echo "Building AdaptixC2 bridge..."
        go build -o protosyte-adaptixc2 .
    fi
    
    if check_port 8082; then
        echo -e "${YELLOW}Port 8082 already in use, skipping AdaptixC2 bridge${NC}"
    else
        nohup ./protosyte-adaptixc2 > /tmp/protosyte-adaptixc2.log 2>&1 &
        echo $! > /tmp/protosyte-adaptixc2.pid
        echo -e "${GREEN}AdaptixC2 Bridge started (PID: $(cat /tmp/protosyte-adaptixc2.pid))${NC}"
    fi
else
    echo -e "${YELLOW}[2/2] AdaptixC2 Bridge not configured (set ADAPTIXC2_SERVER_URL and ADAPTIXC2_API_KEY)${NC}"
fi

echo -e "${GREEN}=== All Services Started ===${NC}"
echo ""
echo "Services:"
echo "  - Broadcast Engine: http://localhost:8081 (internal)"
echo "  - AdaptixC2 Bridge: http://localhost:8082 (if configured)"
echo "  - CLI: Use analysis-rig commands directly"
echo ""
echo "CLI Commands:"
echo "  - Stats: ./analysis-rig/protosyte-rig --mode stats"
echo "  - Records: ./analysis-rig/protosyte-rig --mode records"
echo "  - Hosts: ./analysis-rig/protosyte-rig --mode hosts"
echo "  - FIP: ./analysis-rig/protosyte-rig --mode fip"
echo ""
echo "Logs:"
echo "  - Broadcast Engine: /tmp/protosyte-broadcast.log"
echo "  - AdaptixC2: /tmp/protosyte-adaptixc2.log"
echo ""
echo "To stop all services: ./scripts/stop-all.sh"

