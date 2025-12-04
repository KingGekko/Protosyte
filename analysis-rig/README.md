# Analysis Rig

The Analysis Rig is the intelligence analysis component of the Protosyte framework. It retrieves encrypted payloads from the Telegram Broadcast Engine, decrypts and analyzes them, and stores intelligence data in a SQLite database for query and reporting.

## Overview

The Analysis Rig operates in an isolated virtual machine and provides a comprehensive CLI interface for:
- Payload retrieval from Telegram
- Data decryption and analysis
- Intelligence querying and statistics
- Forensic Intelligence Packet (FIP) generation
- Mission configuration management

## Quick Start

### Build

```bash
cd analysis-rig
go build -o protosyte-rig .
```

### Basic Usage

```bash
# Set environment variables
export PROTOSYTE_BOT_TOKEN="your_telegram_bot_token"
export PROTOSYTE_PASSPHRASE="your_encryption_passphrase"

# Retrieve payloads (requires Tor and WAN enabled)
torsocks ./protosyte-rig --mode retrieve

# Analyze intelligence
./protosyte-rig --mode analyze

# View statistics
./protosyte-rig --mode stats
```

## CLI Commands

**📖 Complete Documentation**: See `docs/CLI_COMMANDS.md` for full command reference.

### Available Modes

#### `retrieve` - Retrieve Payloads

Retrieves encrypted payloads from the Telegram bot via Tor.

```bash
export PROTOSYTE_BOT_TOKEN="your_token"
torsocks ./protosyte-rig --mode retrieve
```

**Options**:
- `--token-env <var>`: Environment variable name (default: `PROTOSYTE_BOT_TOKEN`)
- `--mission <path>`: Path to mission.yaml

**Requirements**:
- Tor running (port 9050 or 9150)
- WAN adapter enabled (in VM)
- Bot token configured

---

#### `analyze` - Analyze Intelligence

Decrypts retrieved payloads and stores intelligence in SQLite database.

```bash
export PROTOSYTE_PASSPHRASE="your_passphrase"
./protosyte-rig --mode analyze
```

**Options**:
- `--passphrase-fd <fd>`: File descriptor for passphrase (more secure)
- `--mission <path>`: Path to mission.yaml

**Requirements**:
- Payloads retrieved (run `retrieve` first)
- Passphrase must match encryption key

---

#### `stats` - View Statistics

Displays summary statistics about collected intelligence.

```bash
# Table format (default)
./protosyte-rig --mode stats

# JSON format
./protosyte-rig --mode stats --format json
```

**Options**:
- `--format <format>`: `table` or `json` (default: `table`)

**Output**:
- Total records count
- Records by type (credentials, network flows, file metadata)
- Records by host
- Date range
- Mission ID

---

#### `records` - List Records

Lists collected intelligence records.

```bash
# Default (first 50)
./protosyte-rig --mode records

# Custom limit
./protosyte-rig --mode records --limit 100

# JSON output
./protosyte-rig --mode records --limit 200 --format json
```

**Options**:
- `--limit <n>`: Maximum records to display (default: 50)
- `--format <format>`: `table` or `json` (default: `table`)

---

#### `hosts` - List Target Hosts

Lists unique target hosts from which intelligence was collected.

```bash
./protosyte-rig --mode hosts
./protosyte-rig --mode hosts --format json
```

**Options**:
- `--format <format>`: `table` or `json` (default: `table`)

---

#### `fip` - Generate Forensic Intelligence Packet

Generates a complete FIP report for legal/compliance documentation.

```bash
# Print to stdout
./protosyte-rig --mode fip

# Save to file
./protosyte-rig --mode fip --format json > forensic_report.json

# With date stamp
./protosyte-rig --mode fip --format json > fip_$(date +%Y%m%d_%H%M%S).json
```

**Options**:
- `--format <format>`: `table` or `json` (default: `table`)

**FIP Contents**:
- Mission metadata
- Collection timeline
- All intelligence records
- Host summaries
- Cryptographic signatures

---

#### `mission` - Mission Information

Displays current mission configuration.

```bash
./protosyte-rig --mode mission
./protosyte-rig --mode mission --format json
```

**Options**:
- `--mission <path>`: Path to mission.yaml
- `--format <format>`: `table` or `json` (default: `table`)

---

#### `adaptixc2` - AdaptixC2 Status

Checks AdaptixC2 integration connection status.

```bash
./protosyte-rig --mode adaptixc2
./protosyte-rig --mode adaptixc2 --format json
```

**Options**:
- `--format <format>`: `table` or `json` (default: `table`)

---

### Help

```bash
# Show usage and help
./protosyte-rig
# or
./protosyte-rig --help
# or
./protosyte-rig --mode invalid
```

---

## Complete Workflow Example

### Step 1: Setup VM (First Time)

See `docs/ANALYSIS_VM.md` for complete VM setup instructions.

### Step 2: Start VM

```bash
./scripts/rig_start.sh
```

### Step 3: Retrieve Payloads

```bash
# Enable WAN adapter
./scripts/vm-manage.sh enable-wan

# SSH into VM
ssh user@192.168.56.10

# In VM: Retrieve payloads
export PROTOSYTE_BOT_TOKEN="your_token"
torsocks ./protosyte-rig --mode retrieve
```

### Step 4: Analyze Intelligence

```bash
# Disable WAN (back to isolated state)
# Exit SSH, then from host:
./scripts/vm-manage.sh disable-wan

# SSH back into VM
ssh user@192.168.56.10

# In VM: Analyze payloads
export PROTOSYTE_PASSPHRASE="your_passphrase"
./protosyte-rig --mode analyze
```

### Step 5: Query Intelligence

```bash
# View statistics
./protosyte-rig --mode stats

# List records
./protosyte-rig --mode records --limit 100

# List hosts
./protosyte-rig --mode hosts

# View in JSON format
./protosyte-rig --mode stats --format json
```

### Step 6: Generate Report

```bash
# Generate FIP
./protosyte-rig --mode fip --format json > /tmp/fip.json

# Copy to host (exit SSH first)
exit
scp user@192.168.56.10:/tmp/fip.json ./
```

### Step 7: Cleanup

```bash
# Revert VM to baseline
./scripts/rig_destroy.sh
```

---

## Configuration

### Environment Variables

**Required**:
- `PROTOSYTE_BOT_TOKEN`: Telegram bot token (for retrieval)
- `PROTOSYTE_PASSPHRASE`: Encryption passphrase (for analysis)

**Optional**:
- `PROTOSYTE_MISSION_YAML`: Path to mission.yaml
- `PROTOSYTE_MISSION_ID`: Mission identifier (hex)

### Mission Configuration

The Analysis Rig automatically loads `mission.yaml` from:
1. Current directory (`./mission.yaml`)
2. Parent directory (`../mission.yaml`)
3. Path specified with `--mission` flag
4. Path from `PROTOSYTE_MISSION_YAML` environment variable

See `MISSION_YAML_INTEGRATION.md` for complete mission configuration guide.

---

## Database

Intelligence data is stored in SQLite database:
- **Location**: `~/protosyte_intelligence.db` (default)
- **Encryption**: Database encrypted with passphrase
- **Schema**: See `DATABASE_MANAGEMENT.md`

### Database Operations

```bash
# Access database directly (if needed)
sqlite3 ~/protosyte_intelligence.db

# Query records
sqlite3 ~/protosyte_intelligence.db "SELECT * FROM records LIMIT 10;"

# Check schema
sqlite3 ~/protosyte_intelligence.db ".schema"
```

See `DATABASE_MANAGEMENT.md` for complete database documentation.

---

## Output Formats

### Table Format (Default)

Human-readable table format:
```
Intelligence Statistics
======================
Total Records: 1,234
By Type:
  CREDENTIAL_BLOB: 456
  NETWORK_FLOW: 523
  FILE_METADATA: 255
```

### JSON Format

Structured JSON output for programmatic use:
```bash
./protosyte-rig --mode stats --format json | jq .
```

```json
{
  "total_records": 1234,
  "by_type": {
    "CREDENTIAL_BLOB": 456,
    "NETWORK_FLOW": 523,
    "FILE_METADATA": 255
  },
  "mission_id": "0xDEADBEEFCAFEBABE"
}
```

---

## Integration with Scripts

The Analysis Rig integrates with automation scripts:

```bash
# Complete retrieval session
./scripts/retrieval-session.sh

# VM lifecycle
./scripts/rig_start.sh      # Start VM
./scripts/rig_destroy.sh    # Cleanup VM
./scripts/vm-manage.sh enable-wan   # Network control
```

---

## Troubleshooting

### Command Not Found

```bash
# Build the binary
cd analysis-rig
go build -o protosyte-rig .

# Or use build script
./scripts/build-all.sh
```

### Passphrase Error

```bash
# Verify passphrase is set
echo $PROTOSYTE_PASSPHRASE

# Use file descriptor for better security
./protosyte-rig --mode analyze --passphrase-fd 3 3< <(echo "$PASSPHRASE")
```

### Database Locked

```bash
# Check if another process is using database
lsof ~/protosyte_intelligence.db

# Close any other Analysis Rig instances
pkill protosyte-rig
```

### No Records Found

```bash
# Verify payloads were retrieved
ls -la ~/payloads/  # or wherever payloads are stored

# Check database
./protosyte-rig --mode stats

# Re-run analysis
./protosyte-rig --mode analyze
```

---

## See Also

- **`docs/CLI_COMMANDS.md`** - Complete CLI commands reference
- `DATABASE_MANAGEMENT.md` - Database operations and maintenance
- `docs/ANALYSIS_VM.md` - VM setup and management
- `OPERATIONAL_WORKFLOW.md` - Complete operational procedures
- `MISSION_YAML_INTEGRATION.md` - Mission configuration

---

**Last Updated**: 2025-12-03
