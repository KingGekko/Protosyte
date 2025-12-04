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
echo -e "${GREEN}[1/4] Starting Broadcast Engine...${NC}"
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

# Start Analysis Rig API Server (Analyze Mode)
echo -e "${GREEN}[2/4] Starting Analysis Rig API Server...${NC}"
cd "$PROJECT_ROOT/analysis-rig"
if [ ! -f "./protosyte-rig" ]; then
    echo "Building analysis rig..."
    go build -o protosyte-rig .
fi

if check_port 8080; then
    echo -e "${YELLOW}Port 8080 already in use, skipping analysis rig API server${NC}"
else
    export DASHBOARD_ADDR="localhost:8080"
    nohup ./protosyte-rig --mode analyze > /tmp/protosyte-rig.log 2>&1 &
    echo $! > /tmp/protosyte-rig.pid
    echo -e "${GREEN}Analysis Rig API Server started (PID: $(cat /tmp/protosyte-rig.pid))${NC}"
    echo -e "${GREEN}API Server available at: http://localhost:8080${NC}"
    sleep 3
fi

# Start Next.js Dashboard (optional)
if [ -d "$PROJECT_ROOT/analysis-rig/node_modules" ]; then
    echo -e "${GREEN}[3/4] Starting Next.js Dashboard...${NC}"
    cd "$PROJECT_ROOT/analysis-rig"
    
    if check_port 3000; then
        echo -e "${YELLOW}Port 3000 already in use, skipping Next.js dashboard${NC}"
    else
        nohup npm run dev > /tmp/protosyte-nextjs.log 2>&1 &
        echo $! > /tmp/protosyte-nextjs.pid
        echo -e "${GREEN}Next.js Dashboard started (PID: $(cat /tmp/protosyte-nextjs.pid))${NC}"
        echo -e "${GREEN}Next.js Dashboard available at: http://localhost:3000${NC}"
    fi
else
    echo -e "${YELLOW}[3/4] Next.js Dashboard not installed (run 'cd analysis-rig && npm install')${NC}"
fi

# Start AdaptixC2 Bridge (if configured)
if [ ! -z "$ADAPTIXC2_SERVER_URL" ] && [ ! -z "$ADAPTIXC2_API_KEY" ]; then
    echo -e "${GREEN}[4/4] Starting AdaptixC2 Bridge...${NC}"
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
    echo -e "${YELLOW}[4/4] AdaptixC2 Bridge not configured (set ADAPTIXC2_SERVER_URL and ADAPTIXC2_API_KEY)${NC}"
fi

echo -e "${GREEN}=== All Services Started ===${NC}"
echo ""
echo "Services:"
echo "  - Next.js Dashboard: http://localhost:3000 (primary interface)"
echo "  - API Server: http://localhost:8080 (backend for Next.js)"
echo "  - Broadcast Engine: http://localhost:8081 (internal)"
echo "  - AdaptixC2 Bridge: http://localhost:8082 (if configured)"
echo ""
echo "CLI Commands (quick access without dashboard):"
echo "  - Stats: ./analysis-rig/protosyte-rig --mode stats"
echo "  - Records: ./analysis-rig/protosyte-rig --mode records"
echo "  - Hosts: ./analysis-rig/protosyte-rig --mode hosts"
echo "  - FIP: ./analysis-rig/protosyte-rig --mode fip"
echo ""
echo "Logs:"
echo "  - Broadcast Engine: /tmp/protosyte-broadcast.log"
echo "  - Analysis Rig: /tmp/protosyte-rig.log"
echo "  - Next.js: /tmp/protosyte-nextjs.log"
echo "  - AdaptixC2: /tmp/protosyte-adaptixc2.log"
echo ""
echo "To stop all services: ./scripts/stop-all.sh"

