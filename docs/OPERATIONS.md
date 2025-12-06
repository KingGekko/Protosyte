# Operations Guide

Complete guide for secure deployment, operational workflows, and security procedures for the Protosyte framework.

## Table of Contents

1. [Operational Security (OPSEC)](#operational-security-opsec)
2. [Complete Campaign Workflow](#complete-campaign-workflow)
3. [Security Procedures](#security-procedures)
4. [Daily/Weekly Procedures](#dailyweekly-procedures)
5. [Troubleshooting](#troubleshooting)
6. [Quick Reference](#quick-reference)

---

## Operational Security (OPSEC)

### Core Principles

1. **Zero Infrastructure**: No persistent servers, domains, or endpoints
2. **Memory-Only Operation**: Critical components operate solely in volatile memory
3. **Anonymous Communication**: All network traffic via Tor
4. **Stateless Operations**: No persistent state that could be traced
5. **Ephemeral Analysis**: Analysis environments destroyed after use
6. **Encryption**: All data encrypted in transit and at rest

### Network Security

#### Tor Usage

**Always use Tor for all network operations:**

```bash
# Exfiltration (Silent Seed) - Configured automatically via mission.yaml

# Retrieval (Analysis Rig)
torsocks ./protosyte-rig --mode retrieve

# Broadcast Engine - Run through Tor or deploy to ephemeral cloud
```

**Best Practices:**
- Verify Tor is running: `systemctl status tor`
- Check Tor connectivity: `torsocks wget -O- https://check.torproject.org`
- Use separate Tor circuits for different operations
- Monitor Tor logs for anomalies

#### Network Isolation

**Analysis Rig VM Setup:**

1. **Dual Network Adapters**:
   - Adapter 1: NAT/Bridged (WAN) - **DISABLED BY DEFAULT**
   - Adapter 2: Host-only - Static IP `192.168.56.10`

2. **WAN Enablement** (Only for retrieval):
   ```bash
   # Enable WAN for retrieval
   # Retrieve payloads
   torsocks ./protosyte-rig --mode retrieve
   # DISABLE WAN IMMEDIATELY AFTER
   ```

3. **Host-Only Network**:
   - Only enabled adapter during analysis
   - Isolated from internet
   - Accessible only from host machine

---

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

# 5. Copy binary to VM
scp protosyte-rig user@192.168.56.10:/home/user/

# 6. Create baseline snapshot: "Baseline - Clean State"
```

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
# Run AI analysis
./scripts/ai-analyze.sh target-ip

# AI will analyze target, search CVEs, generate exploits
```

### Phase 3: Silent Seed Deployment

#### 3.1 Choose Deployment Method

**Linux:**
- Method 1: LD_PRELOAD: `LD_PRELOAD=/path/to/libprotosyte.so /path/to/app`
- Method 2: Process injection (ptrace/eBPF)

**Windows:**
- Method 1: DLL Injection (requires SeDebugPrivilege)
- Method 2: Process Hollowing

**macOS:**
- Method 1: DYLD_INSERT_LIBRARIES
- Method 2: Function Interposing

See component READMEs for detailed deployment instructions.

#### 3.2 Verify Deployment

```bash
# Check if data collection is working
# Monitor Broadcast Engine for incoming messages
```

### Phase 4: Broadcast Engine Operation

#### 4.1 Start Broadcast Engine

```bash
# Local deployment
export PROTOSYTE_BOT_TOKEN="your_token"
./broadcast-engine/protosyte-broadcast

# Ephemeral cloud deployment (Fly.io, Render, etc.)
# Configure via environment variables
# Auto-shutdown after inactivity
```

#### 4.2 Monitor Operations

- Check Broadcast Engine logs
- Monitor Telegram bot (messages auto-delete after 30 seconds)

### Phase 5: Intelligence Collection

#### 5.1 Passive Collection

- Silent Seed automatically collects data
- Data is encrypted and sent via Tor to Broadcast Engine
- No active interaction needed

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
torsocks ./protosyte-rig --mode retrieve
# DISABLE WAN ADAPTER IMMEDIATELY AFTER
```

#### 6.3 Analyze Intelligence

```bash
export PROTOSYTE_PASSPHRASE="your_passphrase"  # REQUIRED in v3.0+ - will panic if not set
./protosyte-rig --mode analyze
```

#### 6.4 Query Intelligence Data

```bash
# View statistics
./protosyte-rig --mode stats

# List records
./protosyte-rig --mode records --limit 100

# List hosts
./protosyte-rig --mode hosts

# Export to JSON
./protosyte-rig --mode records --format json > records.json
```

### Phase 7: Reporting

#### 7.1 Generate FIP

```bash
./protosyte-rig --mode fip --format json > forensic_intel_packet.json.gz
```

#### 7.2 Transfer FIP to Host

```bash
# From host machine
scp user@192.168.56.10:/path/to/fip.json.gz ./
```

### Phase 8: Cleanup and Sanitization

#### 8.1 Secure Data Backup

```bash
# Backup database
cp protosyte.db protosyte.db.backup

# Encrypt backup
gpg -c protosyte.db.backup
```

#### 8.2 Cleanup Analysis Rig VM

1. Generate FIP and transfer to host
2. Backup database securely
3. Securely delete database: `shred -u protosyte.db`
4. Delete payloads
5. Restore VM to baseline snapshot OR destroy VM completely

#### 8.3 Cleanup Broadcast Engine

```bash
# If running locally:
# Stop process, securely delete logs

# If on ephemeral cloud:
# Delete deployment, verify data is destroyed
```

#### 8.4 Credential Rotation

- Generate new Telegram bot token
- Update environment variables
- Revoke old token
- Update all configurations

---

## Security Procedures

### Secure Deployment Procedures

#### Silent Seed Deployment Security

**Linux:**
```bash
# Security checklist:
# - Deploy only with proper authorization
# - Verify binary integrity before deployment
# - Use obfuscated builds for sensitive targets
```

**Windows:**
```bash
# Security checklist:
# - Bypass AMSI/ETW before injection
# - Use advanced evasion techniques
# - Deploy from memory when possible
```

**macOS:**
```bash
# Security checklist:
# - Bypass SIP/TCC when needed
# - Use advanced anti-debugging
# - Deploy with proper authorization
```

### Credential Management

#### Passphrase Handling

**⚠️ BREAKING CHANGE (v3.0+)**: `PROTOSYTE_PASSPHRASE` is now **REQUIRED**. The application will panic if not set. This is a security requirement - there is no default passphrase.

**Key Derivation**:
- Uses PBKDF2-HMAC-SHA256 with 100,000 iterations (OWASP recommended minimum)
- Random salt generated per instance
- 32-byte key for AES-256 encryption

✅ **GOOD**: Environment variable
```bash
export PROTOSYTE_PASSPHRASE="your_passphrase"  # REQUIRED in v3.0+ - will panic if not set
```

❌ **BAD**: In mission.yaml or scripts (never hardcode)

#### Token Management

✅ **GOOD**: Environment variable
```bash
export PROTOSYTE_BOT_TOKEN="your_token"
```

❌ **BAD**: Hardcoded in code or version control

### Data Protection

#### Encryption

- All data encrypted with AES-GCM
- Keys derived from passphrase via PBKDF2-HMAC-SHA256 with 100,000 iterations (OWASP recommended minimum)
- Random salt generated per instance
- No default passphrase - REQUIRED in v3.0+ (application will panic if not set)
- Post-quantum crypto optional (Kyber/Dilithium)

#### Secure Deletion

```bash
# Secure deletion (Linux)
shred -u sensitive_file
# Or
rm -P sensitive_file

# After analysis session:
# 1. Generate FIP and transfer
# 2. Securely delete database
# 3. Destroy VM or restore to baseline
# 4. Verify VM is clean before next use
```

### Access Control

#### File Permissions

```bash
# Analysis Rig binary
chmod 750 protosyte-rig
chown root:protosyte protosyte-rig

# Database
chmod 600 protosyte.db
chown protosyte:protosyte protosyte.db

# Storage directory
chmod 700 /var/lib/protosyte
```

### Logging and Monitoring

#### Secure Logging

- Logs should not contain sensitive data
- Use secure log rotation
- Encrypt log archives

#### Monitoring

- Monitor Tor connectivity
- Monitor Broadcast Engine status
- Monitor Analysis Rig operations
- Alert on anomalies

### Incident Response

#### Security Breach Procedures

1. Immediately isolate affected systems
2. Preserve evidence
3. Notify stakeholders
4. Investigate breach scope
5. Implement containment measures
6. Document incident

#### Data Breach Procedures

1. Assess scope of data exposure
2. Notify affected parties (if required)
3. Secure affected systems
4. Document breach details
5. Implement remediation

### Legal and Compliance

#### Authorization Requirements

- Written authorization required
- Scope clearly defined
- Rules of Engagement documented
- Legal review if necessary

#### Documentation

- Document all operations
- Maintain audit logs
- Keep authorization documents
- Generate FIP reports

---

## Daily/Weekly Procedures

### Daily Routine

#### Morning
1. Check Broadcast Engine status
2. Check Silent Seed collection (via bot monitoring)
3. Review previous day's intelligence

#### Mid-Day
1. Retrieve new payloads (if needed)
2. Analyze new payloads
3. Quick statistics check

#### Evening
1. Full intelligence review
2. Host activity analysis
3. Generate daily summary

### Weekly Procedures

#### Weekly Intelligence Review
1. Export all records
2. Generate comprehensive statistics
3. Host activity analysis
4. Generate FIP

#### Database Maintenance
1. Backup database
2. Integrity check
3. Vacuum (reclaim space)
4. Archive old records (if needed)

See `docs/DATABASE_MANAGEMENT.md` for details.

---

## Troubleshooting

### Silent Seed Not Collecting Data

1. Verify deployment: Check if process is running
2. Check hook library: Verify LD_PRELOAD/DLL injection worked
3. Check filters: Verify data matches filter patterns
4. Check exfiltration: Verify Tor connectivity
5. Check Broadcast Engine: Verify bot is receiving messages

### Broadcast Engine Not Receiving Messages

1. Verify bot token: Check environment variable
2. Check Telegram API: Verify bot is online
3. Check Tor connectivity: Verify network access
4. Check logs: Review Broadcast Engine logs

### Analysis Rig Cannot Retrieve Payloads

1. Verify WAN enabled: Check VM network adapter
2. Verify Tor running: `systemctl status tor`
3. Check passphrase: Verify environment variable set
4. Check database: Verify database exists and is accessible

### Database Issues

1. Check integrity: `sqlite3 protosyte.db "PRAGMA integrity_check;"`
2. Backup before operations
3. Vacuum if needed: `sqlite3 protosyte.db "VACUUM;"`
4. See `docs/DATABASE_MANAGEMENT.md` for detailed procedures

---

## Quick Reference

### Essential Commands

```bash
# Retrieve payloads
torsocks ./protosyte-rig --mode retrieve

# Analyze intelligence
export PROTOSYTE_PASSPHRASE="your_passphrase"  # REQUIRED in v3.0+ - will panic if not set
./protosyte-rig --mode analyze

# View statistics
./protosyte-rig --mode stats

# List records
./protosyte-rig --mode records --limit 100

# List hosts
./protosyte-rig --mode hosts

# Generate FIP
./protosyte-rig --mode fip --format json > fip.json.gz

# Mission info
./protosyte-rig --mode mission
```

### Environment Variables

```bash
# Required
export PROTOSYTE_BOT_TOKEN="your_telegram_bot_token"
export PROTOSYTE_PASSPHRASE="your_encryption_passphrase"

# Optional
export PROTOSYTE_TOR_PROXY="127.0.0.1:9050"
export PROTOSYTE_DB_PATH="./protosyte.db"
```

---

## See Also

- `docs/DATABASE_MANAGEMENT.md` - Database maintenance and management
- `docs/ANALYSIS_VM.md` - VM setup and management
- `docs/CLI_COMMANDS.md` - Complete CLI reference
- Component READMEs - Component-specific documentation

