#!/bin/bash
# Stop All Protosyte Components
# Gracefully stops all running Protosyte services

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Stopping Protosyte Services ===${NC}"

# Function to stop a service by PID file
stop_service() {
    local name=$1
    local pid_file=$2
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            echo -e "${GREEN}Stopping $name (PID: $pid)...${NC}"
            kill "$pid" 2>/dev/null || true
            sleep 1
            # Force kill if still running
            if ps -p "$pid" > /dev/null 2>&1; then
                kill -9 "$pid" 2>/dev/null || true
            fi
            rm -f "$pid_file"
            echo -e "${GREEN}$name stopped${NC}"
        else
            echo -e "${YELLOW}$name not running (stale PID file)${NC}"
            rm -f "$pid_file"
        fi
    else
        echo -e "${YELLOW}$name not running${NC}"
    fi
}

# Stop all services
stop_service "Broadcast Engine" "/tmp/protosyte-broadcast.pid"
stop_service "Analysis Rig" "/tmp/protosyte-rig.pid"
stop_service "Next.js Dashboard" "/tmp/protosyte-nextjs.pid"
stop_service "AdaptixC2 Bridge" "/tmp/protosyte-adaptixc2.pid"

# Also kill any remaining processes by name (fallback)
echo -e "${GREEN}Cleaning up any remaining processes...${NC}"
pkill -f "protosyte-broadcast" 2>/dev/null || true
pkill -f "protosyte-rig" 2>/dev/null || true
pkill -f "next-server" 2>/dev/null || true
pkill -f "protosyte-adaptixc2" 2>/dev/null || true

echo -e "${GREEN}=== All Services Stopped ===${NC}"

