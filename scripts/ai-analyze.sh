#!/bin/bash
# AI Analysis Script
# Uses Ollama AI to analyze targets with mission.yaml integration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Protosyte AI Analysis ===${NC}"

# Check for mission.yaml
MISSION_PATH=""
if [ -f "$PROJECT_ROOT/mission.yaml" ]; then
    MISSION_PATH="$PROJECT_ROOT/mission.yaml"
elif [ -f "./mission.yaml" ]; then
    MISSION_PATH="./mission.yaml"
fi

# Check if Ollama is running
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo -e "${YELLOW}Warning: Ollama not running on localhost:11434${NC}"
    echo "Start Ollama with: ollama serve"
    exit 1
fi

# Run AI analysis
cd "$PROJECT_ROOT/protosyte-ai"

if [ -n "$MISSION_PATH" ]; then
    echo -e "${GREEN}Using mission.yaml: $MISSION_PATH${NC}"
    go run ollama_integration.go --mission "$MISSION_PATH"
else
    echo -e "${YELLOW}No mission.yaml found, using environment variables${NC}"
    go run ollama_integration.go
fi

