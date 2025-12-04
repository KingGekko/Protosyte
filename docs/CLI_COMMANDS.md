# Protosyte CLI Commands Reference

Complete reference for all command-line interfaces and scripts in the Protosyte framework.

## Table of Contents

1. [Analysis Rig CLI](#analysis-rig-cli)
2. [Automation Scripts](#automation-scripts)
3. [VM Management Scripts](#vm-management-scripts)
4. [Build Scripts](#build-scripts)
5. [Quick Reference](#quick-reference)

---

## Analysis Rig CLI

The Analysis Rig provides a comprehensive CLI for intelligence analysis operations.

### Binary Location

```bash
./analysis-rig/protosyte-rig
# or after building:
cd analysis-rig && go build -o protosyte-rig . && ./protosyte-rig
```

### Command Syntax

```bash
protosyte-rig --mode <mode> [options]
```

### Available Modes

#### `retrieve` - Retrieve Payloads from Telegram

Retrieves encrypted payloads from the Telegram bot via Tor.

```bash
# Basic usage
export PROTOSYTE_BOT_TOKEN="your_token"
torsocks ./analysis-rig/protosyte-rig --mode retrieve

# With custom token environment variable
torsocks ./analysis-rig/protosyte-rig --mode retrieve --token-env TELEGRAM_BOT_TOKEN

# With mission configuration
torsocks ./analysis-rig/protosyte-rig --mode retrieve --mission /path/to/mission.yaml
```

**Options**:
- `--token-env <var>`: Environment variable name for Telegram token (default: `PROTOSYTE_BOT_TOKEN`)
- `--mission <path>`: Path to mission.yaml (default: `./mission.yaml` or `../mission.yaml`)

**Requirements**:
- Tor running (port 9050 or 9150)
- `PROTOSYTE_BOT_TOKEN` environment variable set
- Network connectivity (WAN adapter enabled in VM)

---

#### `analyze` - Decrypt and Analyze Intelligence

Decrypts retrieved payloads and stores intelligence data in SQLite database.

```bash
# Basic usage
export PROTOSYTE_PASSPHRASE="your_passphrase"
./analysis-rig/protosyte-rig --mode analyze

# Using file descriptor for passphrase (more secure)
./analysis-rig/protosyte-rig --mode analyze --passphrase-fd 3 3< <(echo "$PASSPHRASE")

# With mission configuration
./analysis-rig/protosyte-rig --mode analyze --mission mission.yaml
```

**Options**:
- `--passphrase-fd <fd>`: File descriptor for passphrase input (default: 0)
- `--mission <path>`: Path to mission.yaml

**Requirements**:
- `PROTOSYTE_PASSPHRASE` environment variable set
- Payloads retrieved (run `retrieve` mode first)
- Database write permissions

**Output**:
- Stores intelligence records in SQLite database
- Creates database if it doesn't exist
- Associates records with mission ID

---

#### `stats` - Display Intelligence Statistics

Shows summary statistics about collected intelligence.

```bash
# Table format (default)
./analysis-rig/protosyte-rig --mode stats

# JSON format
./analysis-rig/protosyte-rig --mode stats --format json

# With passphrase (if database is encrypted)
export PROTOSYTE_PASSPHRASE="your_passphrase"
./analysis-rig/protosyte-rig --mode stats
```

**Options**:
- `--format <format>`: Output format - `table` or `json` (default: `table`)

**Output Includes**:
- Total records count
- Records by type (credentials, network flows, file metadata)
- Records by host
- Date range of collected data
- Mission ID information

**Example Output**:
```
Intelligence Statistics
======================
Total Records: 1,234
By Type:
  CREDENTIAL_BLOB: 456
  NETWORK_FLOW: 523
  FILE_METADATA: 255
By Host:
  192.168.1.10: 342
  10.0.0.5: 892
Mission ID: 0xDEADBEEFCAFEBABE
Date Range: 2025-12-01 10:23:45 - 2025-12-03 14:56:12
```

---

#### `records` - List Intelligence Records

Lists collected intelligence records with filtering options.

```bash
# Default (first 50 records)
./analysis-rig/protosyte-rig --mode records

# Limit number of records
./analysis-rig/protosyte-rig --mode records --limit 100

# JSON format
./analysis-rig/protosyte-rig --mode records --limit 200 --format json

# With passphrase
export PROTOSYTE_PASSPHRASE="your_passphrase"
./analysis-rig/protosyte-rig --mode records --limit 50
```

**Options**:
- `--limit <n>`: Maximum number of records to display (default: 50)
- `--format <format>`: Output format - `table` or `json` (default: `table`)

**Output Includes**:
- Record ID
- Timestamp
- Host identifier
- Data type
- Record summary
- Mission ID

---

#### `hosts` - List Unique Target Hosts

Lists all unique target hosts from which intelligence was collected.

```bash
# Table format
./analysis-rig/protosyte-rig --mode hosts

# JSON format
./analysis-rig/protosyte-rig --mode hosts --format json

# With passphrase
export PROTOSYTE_PASSPHRASE="your_passphrase"
./analysis-rig/protosyte-rig --mode hosts
```

**Options**:
- `--format <format>`: Output format - `table` or `json` (default: `table`)

**Output Includes**:
- Host identifier/fingerprint
- First seen timestamp
- Last seen timestamp
- Record count per host
- Associated mission ID

---

#### `fip` - Generate Forensic Intelligence Packet

Generates a complete Forensic Intelligence Packet (FIP) for reporting.

```bash
# Generate FIP (prints to stdout)
./analysis-rig/protosyte-rig --mode fip

# JSON format
./analysis-rig/protosyte-rig --mode fip --format json

# Save to file
./analysis-rig/protosyte-rig --mode fip > forensic_intel_packet.json

# With passphrase
export PROTOSYTE_PASSPHRASE="your_passphrase"
./analysis-rig/protosyte-rig --mode fip --format json > fip_$(date +%Y%m%d).json
```

**Options**:
- `--format <format>`: Output format - `table` or `json` (default: `table`)
- `--output <path>`: Output file path (if supported)

**FIP Contents**:
- Mission metadata
- Collection timeline
- All intelligence records
- Host summaries
- Statistics and analysis
- Cryptographic signatures

**Usage**:
- Submit to Legal Bridge for law enforcement reporting
- Archive for compliance documentation
- Share with authorized parties

---

#### `mission` - Display Mission Information

Shows current mission configuration and status.

```bash
# Display mission info
./analysis-rig/protosyte-rig --mode mission

# JSON format
./analysis-rig/protosyte-rig --mode mission --format json

# Specify mission file
./analysis-rig/protosyte-rig --mode mission --mission /path/to/mission.yaml
```

**Options**:
- `--mission <path>`: Path to mission.yaml
- `--format <format>`: Output format - `table` or `json` (default: `table`)

**Output Includes**:
- Mission ID (hexadecimal)
- Mission name
- Configuration parameters
- Component status
- Integration settings

---

#### `adaptixc2` - Check AdaptixC2 Integration Status

Displays AdaptixC2 bridge connection status and agent information.

```bash
# Check status
./analysis-rig/protosyte-rig --mode adaptixc2

# JSON format
./analysis-rig/protosyte-rig --mode adaptixc2 --format json

# With mission config
./analysis-rig/protosyte-rig --mode adaptixc2 --mission mission.yaml
```

**Options**:
- `--format <format>`: Output format - `table` or `json`
- `--mission <path>`: Path to mission.yaml

**Output Includes**:
- AdaptixC2 connection status
- Server URL
- Connected agents
- Deployment status
- Intelligence feed status

---

### Help and Usage

```bash
# Show help
./analysis-rig/protosyte-rig --help
# or
./analysis-rig/protosyte-rig --mode invalid_mode
# or just
./analysis-rig/protosyte-rig
```

---

## Automation Scripts

All automation scripts are located in the `scripts/` directory and can be executed directly from the command line.

### Environment Setup

#### `setup-env.sh`

Initial environment setup and dependency verification.

```bash
./scripts/setup-env.sh
```

**What it does**:
- Creates `.env` file from template
- Checks for required dependencies (Rust, Go, Tor, etc.)
- Verifies tool versions
- Creates necessary directories
- Sets up environment structure

**Output**:
- Creates `.env` file (if missing)
- Prints dependency status
- Reports any missing requirements

---

### Build Scripts

#### `build-all.sh`

Builds all Protosyte components.

```bash
./scripts/build-all.sh
```

**What it builds**:
- Silent Seed (Linux, Windows, macOS)
- Broadcast Engine
- Analysis Rig
- Legal Bridge
- AdaptixC2 Bridge (if present)
- AI Integration (if present)

**Options**: None (builds everything)

**Output**:
- Compiled binaries in respective directories
- Build logs to console
- Error messages for failed builds

---

#### `build-seed.sh`

Builds only the Silent Seed component (Linux).

```bash
./scripts/build-seed.sh
```

---

#### `build-windows.sh`

Builds Windows Silent Seed DLL.

```bash
./scripts/build-windows.sh
```

---

#### `build-macos.sh`

Builds macOS Silent Seed dynamic library.

```bash
./scripts/build-macos.sh
```

---

### Service Management

#### `start-all.sh`

Starts all Protosyte services.

```bash
./scripts/start-all.sh
```

**What it starts**:
- Broadcast Engine (port 8081)
- Analysis Rig API (if configured, port 8080)
- AdaptixC2 Bridge (if configured, port 8082)

**Requirements**:
- Components must be built (`build-all.sh`)
- Environment variables set (`.env` file)
- Ports 8080, 8081, 8082 available (if services use them)

**Output**:
- Service logs in `/tmp/protosyte-*.log`
- PID files in `/tmp/protosyte-*.pid`
- Console messages for each service

**Example**:
```bash
./scripts/start-all.sh
# [BROADCAST] Starting Broadcast Engine...
# [BROADCAST] Broadcast Engine running on port 8081
# [RIG] Starting Analysis Rig...
```

---

#### `stop-all.sh`

Stops all running Protosyte services.

```bash
./scripts/stop-all.sh
```

**What it stops**:
- All services started by `start-all.sh`
- Processes identified by PID files
- Cleans up PID files and logs

**Example**:
```bash
./scripts/stop-all.sh
# [BROADCAST] Stopping Broadcast Engine (PID 12345)...
# [RIG] Stopping Analysis Rig (PID 12346)...
# [OK] All services stopped
```

---

### Testing

#### `test-all.sh`

Runs all component test suites.

```bash
./scripts/test-all.sh
```

**What it tests**:
- Silent Seed (Rust unit tests)
- Broadcast Engine (Go tests)
- Analysis Rig (Go tests)
- Legal Bridge (Go tests)
- AdaptixC2 Bridge (Go tests)
- AI Integration (Go tests)

**Output**:
- Test results for each component
- Summary of passed/failed tests
- Coverage reports (if available)

---

### Verification

#### `verify-dependencies.sh`

Verifies all required dependencies are installed.

```bash
./scripts/verify-dependencies.sh
```

**Checks**:
- Rust compiler version
- Go version
- Tor installation
- Required system tools
- Network connectivity

---

## VM Management Scripts

These scripts manage the Analysis Rig virtual machine for ephemeral operation.

### `rig_start.sh`

Starts the Analysis Rig VM and verifies connectivity.

```bash
./scripts/rig_start.sh
```

**What it does**:
1. Checks if VM exists
2. Starts VM in headless mode
3. Disables WAN adapter (secure default)
4. Waits for VM to become reachable
5. Verifies SSH connectivity (optional)
6. Displays VM status

**Requirements**:
- VirtualBox installed
- VM named "protosyte-rig" exists
- Host-only network configured

**Output**:
```
[RIG] Starting Analysis Rig VM...
[RIG] Starting VM 'protosyte-rig'...
[RIG] Waiting for VM to boot...
[OK] VM is reachable at 192.168.56.10
[OK] Analysis Rig VM is ready for operation
```

**Options**: None

---

### `rig_destroy.sh`

Reverts VM to baseline snapshot and ensures clean state.

```bash
./scripts/rig_destroy.sh
```

**What it does**:
1. Disables WAN adapter
2. Stops VM (graceful shutdown)
3. Verifies baseline snapshot exists
4. Reverts VM to baseline snapshot
5. Displays snapshot information

**Requirements**:
- VM named "protosyte-rig" exists
- Baseline snapshot named "baseline" exists

**Output**:
```
[RIG] Cleaning up Analysis Rig VM...
[RIG] Ensuring WAN adapter is disabled...
[RIG] Stopping VM...
[OK] VM stopped
[RIG] Reverting VM to baseline snapshot 'baseline'...
[OK] VM reverted to baseline snapshot
[OK] Analysis Rig VM cleanup complete
```

**Options**: None

**⚠️ Warning**: This destroys all data collected in the current session. Ensure you've exported any needed data first.

---

### `vm-manage.sh`

Basic VM control operations.

```bash
./scripts/vm-manage.sh <command>
```

**Commands**:

**`enable-wan`** - Enable WAN adapter for internet access
```bash
./scripts/vm-manage.sh enable-wan
```
- Enables NAT/Bridged adapter
- Required for payload retrieval via Tor

**`disable-wan`** - Disable WAN adapter (isolate VM)
```bash
./scripts/vm-manage.sh disable-wan
```
- Disables NAT/Bridged adapter
- Isolates VM from internet
- Default secure state

**`revert`** - Revert to baseline snapshot
```bash
./scripts/vm-manage.sh revert
```
- Stops VM if running
- Restores baseline snapshot
- Same as `rig_destroy.sh` but without status checks

**`start`** - Start VM
```bash
./scripts/vm-manage.sh start
```
- Starts VM in headless mode
- Basic startup (use `rig_start.sh` for full verification)

**`stop`** - Stop VM
```bash
./scripts/vm-manage.sh stop
```
- Sends poweroff signal to VM
- Force stops if needed

**Example**:
```bash
./scripts/vm-manage.sh enable-wan   # Enable internet
./scripts/vm-manage.sh disable-wan  # Disable internet
```

---

### `retrieval-session.sh`

Orchestrates a complete retrieval session workflow.

```bash
./scripts/retrieval-session.sh
```

**What it does**:
1. Reverts VM to baseline
2. Starts VM
3. Waits for boot
4. Enables WAN adapter
5. Triggers payload retrieval (requires SSH setup)
6. Waits for retrieval to complete
7. Disables WAN adapter

**Requirements**:
- VM configured
- SSH access to VM
- Environment variables set in VM

**Note**: This script is a template and may need customization for your setup.

---

## Build Scripts

### Individual Component Builds

```bash
# Build Linux Silent Seed
./scripts/build-seed.sh

# Build Windows Silent Seed
./scripts/build-windows.sh

# Build macOS Silent Seed
./scripts/build-macos.sh
```

Each script:
- Navigates to component directory
- Runs build command (cargo/go build)
- Handles platform-specific build options
- Reports build status

---

## AI Integration Scripts

### `ai-analyze.sh`

Runs AI-powered target analysis.

```bash
./scripts/ai-analyze.sh
```

**What it does**:
- Initializes Ollama client
- Analyzes target (from mission.yaml or input)
- Searches for CVEs
- Generates exploit payloads
- Provides attack vector recommendations

**Requirements**:
- Ollama installed and running
- Model downloaded (e.g., `ollama pull llama3.2`)
- Mission configuration or target information

**Example**:
```bash
export PROTOSYTE_TARGET_IP="197.243.17.150"
./scripts/ai-analyze.sh
```

---

## Quick Reference

### Complete Analysis Workflow

```bash
# 1. Setup (first time only)
./scripts/setup-env.sh
nano .env  # Edit configuration

# 2. Build all components
./scripts/build-all.sh

# 3. Start VM
./scripts/rig_start.sh

# 4. Enable WAN and retrieve payloads
./scripts/vm-manage.sh enable-wan
ssh user@192.168.56.10
export PROTOSYTE_BOT_TOKEN="your_token"
export PROTOSYTE_PASSPHRASE="your_passphrase"
torsocks ./protosyte-rig --mode retrieve

# 5. Disable WAN
exit  # Exit SSH
./scripts/vm-manage.sh disable-wan

# 6. Analyze (in VM or from host)
ssh user@192.168.56.10
./protosyte-rig --mode analyze

# 7. Query intelligence
./protosyte-rig --mode stats
./protosyte-rig --mode records --limit 100
./protosyte-rig --mode hosts

# 8. Generate FIP
./protosyte-rig --mode fip > /tmp/fip.json

# 9. Cleanup
exit  # Exit SSH
./scripts/rig_destroy.sh
```

### Daily Operations

```bash
# Start all services
./scripts/start-all.sh

# Check status
./analysis-rig/protosyte-rig --mode stats

# Generate report
./analysis-rig/protosyte-rig --mode fip --format json > report.json

# Stop all services
./scripts/stop-all.sh
```

### Quick Commands

```bash
# View help
./analysis-rig/protosyte-rig --help

# Quick stats
export PROTOSYTE_PASSPHRASE="pass"
./analysis-rig/protosyte-rig --mode stats

# List recent records
./analysis-rig/protosyte-rig --mode records --limit 20

# VM operations
./scripts/rig_start.sh              # Start VM
./scripts/vm-manage.sh enable-wan   # Enable internet
./scripts/vm-manage.sh disable-wan  # Disable internet
./scripts/rig_destroy.sh            # Cleanup VM
```

---

## Environment Variables

All commands use these environment variables:

### Required

- `PROTOSYTE_BOT_TOKEN`: Telegram bot token (for retrieval)
- `PROTOSYTE_PASSPHRASE`: Encryption passphrase (for analysis)

### Optional

- `PROTOSYTE_MISSION_ID`: Mission identifier (hex, e.g., `0xDEADBEEFCAFEBABE`)
- `PROTOSYTE_MISSION_YAML`: Path to mission.yaml file
- `PROTOSYTE_HMAC_KEY`: HMAC key for envelope authentication
- `PROTOSYTE_TOR_PROXY`: Tor proxy URL (default: `socks5://127.0.0.1:9050`)

### Setting Environment Variables

```bash
# Temporary (current session)
export PROTOSYTE_BOT_TOKEN="your_token"
export PROTOSYTE_PASSPHRASE="your_passphrase"

# Persistent (add to ~/.bashrc or ~/.zshrc)
echo 'export PROTOSYTE_BOT_TOKEN="your_token"' >> ~/.bashrc
echo 'export PROTOSYTE_PASSPHRASE="your_passphrase"' >> ~/.bashrc
source ~/.bashrc

# From .env file (if using scripts)
source .env
```

---

## Common Workflows

### New Analysis Session

```bash
# 1. Start fresh VM
./scripts/rig_destroy.sh  # Clean state
./scripts/rig_start.sh    # Start VM

# 2. Retrieve payloads
./scripts/vm-manage.sh enable-wan
# ... retrieve via SSH ...

# 3. Analyze offline
./scripts/vm-manage.sh disable-wan
# ... analyze via SSH ...

# 4. Generate report
# ... generate FIP ...

# 5. Cleanup
./scripts/rig_destroy.sh
```

### Quick Intelligence Check

```bash
export PROTOSYTE_PASSPHRASE="pass"
./analysis-rig/protosyte-rig --mode stats
./analysis-rig/protosyte-rig --mode records --limit 10
```

### Full Campaign Workflow

See `OPERATIONAL_WORKFLOW.md` for complete campaign procedures.

---

## Troubleshooting

### Command Not Found

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Check if binary exists
ls -la analysis-rig/protosyte-rig

# Rebuild if missing
./scripts/build-all.sh
```

### Permission Denied

```bash
# Fix script permissions
chmod +x scripts/*.sh

# Check file ownership
ls -la scripts/

# Run with appropriate user
sudo -u <user> ./scripts/setup-env.sh
```

### VM Not Found

```bash
# List VMs
VBoxManage list vms

# Check VM name matches
grep VM_NAME scripts/vm-manage.sh

# Create VM if missing (see docs/ANALYSIS_VM.md)
```

### Database Access Issues

```bash
# Check passphrase is set
echo $PROTOSYTE_PASSPHRASE

# Check database file permissions
ls -la ~/protosyte_*.db

# Verify SQLite is installed
sqlite3 --version
```

---

## See Also

- `analysis-rig/README.md` - Analysis Rig detailed documentation
- `scripts/README.md` - Scripts overview
- `docs/ANALYSIS_VM.md` - VM setup and management
- `OPERATIONAL_WORKFLOW.md` - Complete operational procedures
- `MISSION_YAML_INTEGRATION.md` - Mission configuration

---

**Last Updated**: 2025-12-03

