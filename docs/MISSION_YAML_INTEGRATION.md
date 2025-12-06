# Mission.yaml Integration Guide

## Overview

The `mission.yaml` file provides centralized configuration for all Protosyte components. It integrates seamlessly with AdaptixC2 and is used throughout the framework.

---

## Integration Points

### 1. **Silent Seed (Rust)**

**Location**: `protosyte-seed/src/config.rs`

**Usage**:
```rust
use protosyte_seed::config::MissionConfig;

let config = MissionConfig::load()?;
let mission_id = config.get_mission_id();
```

**Configuration Used**:
- `mission.id` → Embedded in all Protobuf envelopes
- `exfiltration.interval_seconds` → Exfiltration timing
- `exfiltration.jitter_percent` → Timing jitter
- `target.hooks` → System call hooks to install
- `target.filters` → Data pattern filters
- `stealth.*` → Stealth configuration

**Fallback**: Environment variables if `mission.yaml` not found

### 2. **Analysis Rig (Go)**

**Location**: `analysis-rig/main.go`

**Usage**:
```bash
# Load mission.yaml automatically
./protosyte-rig --mode analyze

# Or specify path
./protosyte-rig --mode analyze --mission /path/to/mission.yaml
```

**Configuration Used**:
- `mission.id` → Stored with intelligence records
- `exfiltration.telegram_token` → Bot token (or env var)

**Code Integration**:
```go
import "protosyte.io/mission-config"

missionConfig, err := mission.LoadMissionConfig("")
if err != nil {
    // Fallback to environment variables
}
```

### 3. **Broadcast Engine (Go)**

**Location**: `broadcast-engine/main.go`

**Usage**:
```bash
# Load mission.yaml automatically
./protosyte-broadcast

# Or specify path
./protosyte-broadcast --mission /path/to/mission.yaml
```

**Configuration Used**:
- `exfiltration.telegram_token` → Bot token
- `mission.id` → Mission tracking

**Code Integration**:
```go
import "protosyte.io/mission-config"

missionConfig, err := mission.LoadMissionConfig("")
if err != nil {
    // Fallback to environment variables
}
botToken := missionConfig.Exfiltration.TelegramToken
```

### 4. **AdaptixC2 Bridge (Go)**

**Location**: `protosyte-adaptixc2/main.go`, `protosyte-adaptixc2/bridge.go`

**Usage**:
```bash
# Load mission.yaml automatically
./protosyte-adaptixc2

# Or specify path
./protosyte-adaptixc2 --mission /path/to/mission.yaml
```

**Configuration Used**:
- `adaptixc2.enabled` → Enable/disable integration
- `adaptixc2.server` → AdaptixC2 server URL
- `adaptixc2.api_key` → API key (or env var)
- `adaptixc2.auto_deploy_protosyte` → Auto-deployment flag
- `adaptixc2.active_phase` → Active C2 phase config
- `adaptixc2.passive_phase` → Passive collection phase config
- `mission.id` → Mission tracking

**Code Integration**:
```go
import "protosyte.io/mission-config"

missionConfig, err := mission.LoadMissionConfig("")
if missionConfig != nil && missionConfig.IsAdaptixC2Enabled() {
    serverURL := missionConfig.AdaptixC2.Server
    apiKey := missionConfig.AdaptixC2.APIKey
    // Use configuration
}
```

### 5. **Legal Bridge (Go)**

**Location**: `legal-bridge/main.go`

**Note**: Legal Bridge uses environment variables only (for security). Mission ID can be embedded in FIP.

---

## Mission Configuration Structure

### Complete Example

```yaml
mission:
  id: 0xDEADBEEFCAFEBABE
  name: "Operation Example"

target:
  ip: "192.168.1.100"
  hostname: "target-server"
  os: "linux"
  hooks:
    - "fwrite"
    - "send"
    - "SSL_write"
  filters:
    - pattern: "-----BEGIN.*PRIVATE KEY-----"
      type: "CREDENTIAL_BLOB"
    - pattern: "password.*=.*"
      type: "CREDENTIAL_BLOB"

exfiltration:
  interval_seconds: 347
  jitter_percent: 25
  tor_proxy: "127.0.0.1:9050"
  telegram_token: ""  # From PROTOSYTE_BOT_TOKEN env var

analysis:
  vm_ip: "192.168.56.10"

adaptixc2:
  enabled: true
  server: ""  # From ADAPTIXC2_SERVER_URL env var
  api_key: ""  # From ADAPTIXC2_API_KEY env var
  auto_deploy_protosyte: true
  active_phase:
    enabled: true
    duration: 3600
    operations:
      - reconnaissance
      - protosyte_deployment
  passive_phase:
    enabled: true
    start_after: 3600
    collection_only: true

stealth:
  memory_only: true
  hide_from_proc: true
  use_tor: true
  timing_jitter: true
```

---

## Environment Variable Override

Sensitive values are **always** overridden by environment variables for security:

| YAML Field | Environment Variable | Priority |
|------------|---------------------|----------|
| `exfiltration.telegram_token` | `PROTOSYTE_BOT_TOKEN` | Env var wins |
| `adaptixc2.api_key` | `ADAPTIXC2_API_KEY` | Env var wins |
| `adaptixc2.server` | `ADAPTIXC2_SERVER_URL` | Env var wins |
| `mission.passphrase` | `PROTOSYTE_PASSPHRASE` | Env var only (**REQUIRED** in v3.0+) |

---

## AdaptixC2 Integration Flow

### 1. Mission Configuration Loads

```go
missionConfig, _ := mission.LoadMissionConfig("")
if missionConfig.IsAdaptixC2Enabled() {
    // Initialize AdaptixC2 bridge
}
```

### 2. Active Phase Begins

```go
if missionConfig.AdaptixC2.ActivePhase.Enabled {
    // Perform active C2 operations
    // - Reconnaissance
    // - Lateral movement
    // - Deploy Protosyte
}
```

### 3. Passive Phase Starts

```go
if missionConfig.AdaptixC2.PassivePhase.Enabled {
    // Switch to passive collection
    // - Protosyte collects intelligence
    // - No active commands
}
```

### 4. Intelligence Feed

```go
// Protosyte intelligence fed to AdaptixC2
intel := collectProtosyteIntelligence(missionConfig.GetMissionID())
bridge.FeedIntelligence(agentID, intel)
```

---

## Component-Specific Usage

### Silent Seed

**Build-time**: Mission ID embedded in binary
**Runtime**: Configuration loaded from `mission.yaml` or environment

```rust
// In protosyte-seed/src/main.rs or lib.rs
let config = MissionConfig::load()?;
let mission_id = config.get_mission_id();

// Use in Protobuf envelope
envelope.mission_id = mission_id;
```

### Analysis Rig

**Startup**: Loads `mission.yaml` and uses configuration

```bash
# Automatically finds mission.yaml
./protosyte-rig --mode analyze

# Or specify path
./protosyte-rig --mode analyze --mission /custom/path/mission.yaml
```


### Broadcast Engine

**Startup**: Loads bot token from `mission.yaml` or environment

```bash
./protosyte-broadcast --mission mission.yaml
```

### AdaptixC2 Bridge

**Startup**: Loads AdaptixC2 configuration

```bash
./protosyte-adaptixc2 --mission mission.yaml
```

**Deployment**: Uses mission configuration for deployment parameters

```go
// Deploy Protosyte with mission configuration
if missionConfig.AdaptixC2.AutoDeployProtosyte {
    bridge.DeployProtosyte(agentID)
}
```

---

## File Location Resolution

The mission configuration loader searches for `mission.yaml` in this order:

1. **Specified path** (via `--mission` flag)
2. **Current directory** (`./mission.yaml`)
3. **Parent directory** (`../mission.yaml`)
4. **Environment variable** (`PROTOSYTE_MISSION_YAML`)

---

## Mission ID Usage

The mission ID (`mission.id`) is used throughout the framework:

1. **Protobuf Envelopes**: Every payload includes `mission_id`
2. **Database Records**: Intelligence records tagged with mission ID
3. **AdaptixC2 Integration**: Mission ID links Protosyte data to AdaptixC2 agents
4. **FIP Generation**: Mission ID included in Forensic Intelligence Packets

**Format**: Hex string (e.g., `0xDEADBEEFCAFEBABE`)

---

## Security Considerations

1. **Sensitive Values**: Never store in `mission.yaml`
   - Bot tokens → Environment variables
   - Passphrases → Environment variables
   - API keys → Environment variables

2. **File Permissions**: Restrict access to `mission.yaml`
   ```bash
   chmod 600 mission.yaml
   ```

3. **Git Ignore**: Add to `.gitignore` if containing sensitive data
   ```gitignore
   mission.yaml
   ```

4. **Template**: Use `mission.yaml.example` as template

---

## Troubleshooting

### Mission.yaml Not Found

**Error**: `mission.yaml not found in current or parent directory`

**Solution**:
```bash
# Specify path explicitly
./protosyte-rig --mode analyze --mission /path/to/mission.yaml

# Or set environment variable
export PROTOSYTE_MISSION_YAML="/path/to/mission.yaml"
```

### Configuration Not Loading

**Check**:
1. YAML syntax is valid
2. File path is correct
3. File permissions allow reading
4. Environment variables override YAML values

### AdaptixC2 Not Enabled

**Check**:
```yaml
adaptixc2:
  enabled: true  # Must be true
```

**Verify**:
```go
if missionConfig.IsAdaptixC2Enabled() {
    // AdaptixC2 is enabled
}
```

---

## Example Workflow

### 1. Create Mission Configuration

```bash
cp mission.yaml.example mission.yaml
nano mission.yaml
```

### 2. Set Environment Variables

```bash
export PROTOSYTE_BOT_TOKEN="your_token"
export PROTOSYTE_PASSPHRASE="your_passphrase"  # REQUIRED in v3.0+ - will panic if not set
export ADAPTIXC2_SERVER_URL="https://c2.example.com"
export ADAPTIXC2_API_KEY="your_api_key"
```

### 3. Start Components

```bash
# All components automatically load mission.yaml
./scripts/start-all.sh
```

### 4. Verify Integration

```bash
curl http://localhost:8080/api/stats

# Check AdaptixC2 bridge status
curl http://localhost:8082/api/status
```

---

## API Reference

### Go Package: `protosyte.io/mission-config`

**Functions**:
- `LoadMissionConfig(path string) (*MissionConfig, error)`
- `GetMissionConfig() *MissionConfig`

**Methods**:
- `GetMissionID() uint64`
- `GetMissionIDString() string`
- `IsAdaptixC2Enabled() bool`

### Rust Module: `protosyte_seed::config`

**Functions**:
- `MissionConfig::load() -> Result<MissionConfig, String>`

**Methods**:
- `get_mission_id() -> u64`

---

## Integration Summary

| Component | Loads mission.yaml | Uses Mission ID | Uses AdaptixC2 Config |
|-----------|-------------------|-----------------|----------------------|
| Silent Seed | ✅ (via config.rs) | ✅ | ❌ |
| Analysis Rig | ✅ | ✅ | ❌ |
| Broadcast Engine | ✅ | ✅ | ❌ |
| AdaptixC2 Bridge | ✅ | ✅ | ✅ |
| Legal Bridge | ❌ | ✅ (in FIP) | ❌ |

---

**Last Updated**: 2025-12-03

