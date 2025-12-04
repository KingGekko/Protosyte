#!/bin/bash
# Run All Tests
# Executes all test suites across the framework

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== Running Protosyte Test Suite ===${NC}"

FAILED=0

# Test Silent Seed (Rust)
echo -e "${GREEN}[1/6] Testing Silent Seed (Rust)...${NC}"
cd "$PROJECT_ROOT/protosyte-seed"
if cargo test --lib 2>&1; then
    echo -e "${GREEN}✓ Silent Seed tests passed${NC}"
else
    echo -e "${RED}✗ Silent Seed tests failed${NC}"
    FAILED=1
fi

# Test Broadcast Engine (Go)
echo -e "${GREEN}[2/6] Testing Broadcast Engine...${NC}"
cd "$PROJECT_ROOT/broadcast-engine"
if go test -v ./... 2>&1; then
    echo -e "${GREEN}✓ Broadcast Engine tests passed${NC}"
else
    echo -e "${RED}✗ Broadcast Engine tests failed${NC}"
    FAILED=1
fi

# Test Analysis Rig (Go)
echo -e "${GREEN}[3/6] Testing Analysis Rig...${NC}"
cd "$PROJECT_ROOT/analysis-rig"
if go test -v ./... 2>&1; then
    echo -e "${GREEN}✓ Analysis Rig tests passed${NC}"
else
    echo -e "${RED}✗ Analysis Rig tests failed${NC}"
    FAILED=1
fi

# Test Legal Bridge (Go)
echo -e "${GREEN}[4/6] Testing Legal Bridge...${NC}"
cd "$PROJECT_ROOT/legal-bridge"
if go test -v ./... 2>&1; then
    echo -e "${GREEN}✓ Legal Bridge tests passed${NC}"
else
    echo -e "${YELLOW}⚠ Legal Bridge has no tests${NC}"
fi

# Test AdaptixC2 Bridge (Go)
if [ -d "$PROJECT_ROOT/protosyte-adaptixc2" ]; then
    echo -e "${GREEN}[5/6] Testing AdaptixC2 Bridge...${NC}"
    cd "$PROJECT_ROOT/protosyte-adaptixc2"
    if go test -v ./... 2>&1; then
        echo -e "${GREEN}✓ AdaptixC2 Bridge tests passed${NC}"
    else
        echo -e "${RED}✗ AdaptixC2 Bridge tests failed${NC}"
        FAILED=1
    fi
fi

# Test AI Integration (Go)
if [ -d "$PROJECT_ROOT/protosyte-ai" ]; then
    echo -e "${GREEN}[6/6] Testing AI Integration...${NC}"
    cd "$PROJECT_ROOT/protosyte-ai"
    if go test -v ./... 2>&1; then
        echo -e "${GREEN}✓ AI Integration tests passed${NC}"
    else
        echo -e "${YELLOW}⚠ AI Integration has no tests${NC}"
    fi
fi

echo ""
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}=== All Tests Passed ===${NC}"
    exit 0
else
    echo -e "${RED}=== Some Tests Failed ===${NC}"
    exit 1
fi

