# Security Procedures & Operational Security Guide

## Overview

This document outlines security procedures, operational security (OPSEC) best practices, and secure deployment guidelines for the Protosyte framework.

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
# Exfiltration (Silent Seed)
# Configured automatically via mission.yaml

# Retrieval (Analysis Rig)
torsocks ./protosyte-rig --mode retrieve

# Broadcast Engine
# Run through Tor or deploy to ephemeral cloud
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
   # (VM-specific command, e.g., VirtualBox, VMware)
   
   # Retrieve payloads
   torsocks ./protosyte-rig --mode retrieve
   
   # DISABLE WAN IMMEDIATELY AFTER
   ```

3. **Host-Only Network**:
   - Only enabled adapter during analysis
   - Isolated from internet
   - Accessible only from host machine

### Secure Deployment Procedures

#### Silent Seed Deployment

**Linux:**
```bash
# Method 1: LD_PRELOAD (requires access)
LD_PRELOAD=/path/to/libprotosyte.so /path/to/target_app

# Method 2: Process injection (requires privileges)
# Use ptrace or eBPF-based injection

# Security:
# - Deploy only with proper authorization
# - Verify binary integrity before deployment
# - Use obfuscated builds for sensitive targets
```

**Windows:**
```bash
# Method 1: DLL Injection (requires SeDebugPrivilege)
# Use SetWindowsHookEx or classic DLL injection

# Method 2: Process Hollowing (advanced)
# See protosyte-seed-windows/README.md

# Security:
# - Bypass AMSI/ETW before injection
# - Use advanced evasion techniques
# - Deploy from memory when possible
```

**macOS:**
```bash
# Method 1: DYLD_INSERT_LIBRARIES
DYLD_INSERT_LIBRARIES=/path/to/libprotosyte.dylib /path/to/app

# Method 2: Function Interposing
# See protosyte-seed-macos/README.md

# Security:
# - Bypass SIP/TCC when needed
# - Use advanced anti-debugging
# - Deploy with proper authorization
```

#### Broadcast Engine Deployment

**Ephemeral Cloud Deployment (Recommended):**

```bash
# Deploy to Fly.io, Render, or similar
# Set environment variables securely
# Auto-shutdown after inactivity
```

**Security Considerations:**
- Use ephemeral cloud services (auto-delete after use)
- Never log message content
- Delete messages immediately (30-second window)
- Use environment variables for tokens (never hardcode)
- Rotate bot tokens regularly

#### Analysis Rig Deployment

**VM Security:**

1. **Create Baseline Snapshot**:
   ```bash
   # After initial VM setup
   # - Base OS installed
   # - Go installed
   # - Tor installed
   # - Binary copied
   # - Network configured
   # Create snapshot: "Baseline - Clean"
   ```

2. **Secure Configuration**:
   - Disable unnecessary services
   - Firewall configured (host-only access)
   - No WAN adapter enabled
   - Encrypted filesystem (if available)

3. **Analysis Workflow**:
   ```bash
   # 1. Restore from baseline snapshot
   # 2. Enable WAN adapter
   # 3. Retrieve payloads
   torsocks ./protosyte-rig --mode retrieve
   # 4. DISABLE WAN adapter
   # 5. Analyze (offline)
   ./protosyte-rig --mode analyze
   # 6. Query data (offline)
   ./protosyte-rig --mode stats
   # 7. Generate FIP (offline)
   ./protosyte-rig --mode fip
   # 8. Transfer FIP to host
   # 9. DESTROY VM or restore to baseline
   ```

## Credential Management

### Passphrase Handling

**Never store passphrases in files:**

```bash
# ✅ GOOD: Environment variable
export PROTOSYTE_PASSPHRASE="your_passphrase"
./protosyte-rig --mode analyze

# ✅ GOOD: File descriptor
./protosyte-rig --mode analyze --passphrase-fd 3 3< <(echo "$PASSPHRASE")

# ✅ GOOD: Interactive input
echo "your_passphrase" | ./protosyte-rig --mode analyze

# ❌ BAD: In mission.yaml
# passphrase: "your_passphrase"  # NEVER DO THIS

# ❌ BAD: In scripts
# PASSPHRASE="your_passphrase"  # AVOID
```

**Secure Passphrase Storage:**

1. **Password Manager**: Store in encrypted password manager
2. **Hardware Security Module (HSM)**: For high-security environments
3. **Secure Enclave**: Use platform-specific secure storage
4. **Key Derivation**: Use key derivation from master passphrase

### Token Management

**Telegram Bot Token:**

```bash
# ✅ GOOD: Environment variable
export PROTOSYTE_BOT_TOKEN="your_token"

# ✅ GOOD: mission.yaml (with encryption)
# telegram_token: "[encrypted]"
# Decrypt at runtime

# ❌ BAD: Hardcoded in code
# ❌ BAD: In version control
```

**Token Rotation:**

1. Generate new bot token via BotFather
2. Update environment variables
3. Deploy updated configuration
4. Revoke old token

## Data Protection

### Encryption

**Data at Rest:**

1. **Database Encryption**:
   - Use encrypted filesystem for database storage
   - Or use SQLCipher for database-level encryption
   - Secure database file permissions: `chmod 600 /tmp/rig_intel.db`

2. **File Encryption**:
   ```bash
   # Encrypt FIP files
   gpg --symmetric --cipher-algo AES256 forensic_intel_packet.json.gz
   
   # Or use encrypted filesystem
   encfs /encrypted/path /decrypted/path
   ```

**Data in Transit:**

- All data encrypted via AES-GCM before transmission
- Transmission via Tor (additional layer)
- Telegram API uses TLS (HTTPS)

### Secure Deletion

**Database Files:**

```bash
# Secure deletion (Linux)
shred -u /tmp/rig_intel.db
# Or
srm /tmp/rig_intel.db
```

**VM Cleanup:**

```bash
# After analysis session:
# 1. Generate FIP
# 2. Transfer FIP to host
# 3. Securely delete database
# 4. Destroy VM or restore to baseline snapshot
# 5. Verify VM is clean before next use
```

**Disk Wiping:**

```bash
# For complete VM destruction
# Use secure deletion tool or:
dd if=/dev/zero of=/dev/sda bs=1M  # WARNING: Destructive
```

## Access Control

### File Permissions

```bash
# Analysis Rig binary
chmod 700 ./protosyte-rig
chown $USER:$USER ./protosyte-rig

# Database
chmod 600 /tmp/rig_intel.db
chown $USER:$USER /tmp/rig_intel.db

# Storage directory
chmod 700 /tmp/rig_store
chown $USER:$USER /tmp/rig_store

# FIP output
chmod 600 /tmp/rig_out/forensic_intel_packet.json.gz
```

### User Isolation

- Run Analysis Rig as non-root user
- Use separate user accounts for different operations
- Restrict sudo access to Analysis Rig user
- Use `su` or `sudo` only when necessary

## Logging and Monitoring

### Secure Logging

**What NOT to Log:**
- ❌ Passphrases
- ❌ Decrypted payload content
- ❌ Full Telegram messages
- ❌ Host fingerprints (in plaintext logs)
- ❌ Mission IDs (in public logs)

**What TO Log:**
- ✅ Operation status (success/failure)
- ✅ Record counts
- ✅ Timestamps
- ✅ Error codes (without sensitive context)
- ✅ Database operations (counts only)

### Log Rotation and Retention

```bash
# Configure log rotation
# /etc/logrotate.d/protosyte

/var/log/protosyte/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0600 $USER $USER
}
```

### Monitoring

**Monitor for Anomalies:**

1. **Network Monitoring**: Unusual Tor traffic patterns
2. **Process Monitoring**: Unexpected processes
3. **Disk Usage**: Database growth patterns
4. **System Resources**: CPU/memory usage

## Incident Response

### Security Breach Procedures

**If Silent Seed is Detected:**

1. **Immediate Actions**:
   - Document detection method
   - Assess exposure level
   - Review collected intelligence

2. **Cleanup**:
   - Remove Silent Seed (if possible)
   - Secure all collected data
   - Review operational security procedures

3. **Post-Incident**:
   - Conduct security review
   - Update evasion techniques
   - Adjust operational procedures

**If Analysis Rig is Compromised:**

1. **Immediate Actions**:
   - Isolate VM immediately
   - Backup database securely
   - Document compromise

2. **Assessment**:
   - Determine attack vector
   - Assess data exposure
   - Review access logs

3. **Recovery**:
   - Restore from clean baseline
   - Rotate all credentials
   - Review security procedures

### Data Breach Procedures

**If Intelligence Data is Exposed:**

1. **Containment**:
   - Identify exposed data
   - Secure remaining data
   - Revoke access immediately

2. **Notification**:
   - Notify stakeholders (if authorized)
   - Document incident
   - Review legal requirements

3. **Remediation**:
   - Rotate all credentials
   - Update security procedures
   - Conduct security audit

## Legal and Compliance

### Authorization Requirements

**Before Deployment:**

1. ✅ **Written Authorization**: Obtain explicit written permission
2. ✅ **Scope Definition**: Clear boundaries of what can be tested
3. ✅ **Rules of Engagement**: Documented and agreed upon
4. ✅ **Legal Review**: Legal counsel review if needed
5. ✅ **Compliance Check**: Verify compliance with local/international laws

### Documentation

**Required Documentation:**

1. **Authorization Letter**: Written permission from target
2. **Scope Document**: What is in/out of scope
3. **ROE Document**: Rules of engagement
4. **Mission Log**: Operational log (sanitized)
5. **Intelligence Reports**: Findings and evidence

### Data Handling

**Intelligence Data:**

- Store securely (encrypted)
- Access control (need-to-know)
- Retention policies (as per authorization)
- Secure deletion after authorized period
- Legal compliance for data retention

## Security Checklist

### Pre-Deployment

- [ ] Written authorization obtained
- [ ] Scope clearly defined
- [ ] Legal review completed
- [ ] Security procedures reviewed
- [ ] Credentials secured (passphrase, tokens)
- [ ] Network isolation configured
- [ ] Tor connectivity verified
- [ ] VM baseline snapshot created

### During Operations

- [ ] Tor used for all network operations
- [ ] WAN adapter disabled during analysis
- [ ] Passphrases never stored in files
- [ ] Database permissions secured
- [ ] Logs sanitized (no sensitive data)
- [ ] Regular backups performed
- [ ] Integrity checks run

### Post-Operations

- [ ] FIP generated and secured
- [ ] Database backed up
- [ ] VM restored to baseline
- [ ] All credentials rotated
- [ ] Logs reviewed and sanitized
- [ ] Security review conducted
- [ ] Documentation updated

## Advanced Security Measures

### Multi-Layer Encryption

```bash
# Layer 1: Application-level (AES-GCM)
# Layer 2: Tor network
# Layer 3: Filesystem encryption
# Layer 4: Database encryption (if using SQLCipher)
```

### Air-Gapped Analysis

For maximum security:

1. **Completely Air-Gapped VM**:
   - No network adapters
   - Manual payload transfer via USB
   - No internet connectivity ever

2. **Workflow**:
   - Retrieve payloads on separate machine
   - Transfer via encrypted USB drive
   - Analyze in air-gapped VM
   - Export FIP to encrypted USB
   - Destroy VM after analysis

### Hardware Security Module (HSM)

For high-security environments:

- Use HSM for key storage
- Hardware-backed encryption
- Tamper-resistant key protection
- Audit logging

## See Also

- `analysis-rig/DATABASE_MANAGEMENT.md` - Database security
- `OPERATIONAL_WORKFLOW.md` - Operational procedures
- Component-specific READMEs for platform security
