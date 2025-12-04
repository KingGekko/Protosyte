# Analysis Rig VM Setup and Management

This guide provides comprehensive instructions for setting up, managing, and operating the ephemeral Analysis Rig virtual machine.

## Table of Contents

1. [Overview](#overview)
2. [VM Architecture](#vm-architecture)
3. [Initial Setup](#initial-setup)
4. [VM Lifecycle Management](#vm-lifecycle-management)
5. [Network Configuration](#network-configuration)
6. [Snapshots and Ephemeral Operation](#snapshots-and-ephemeral-operation)
7. [Automated Scripts](#automated-scripts)
8. [Troubleshooting](#troubleshooting)

## Overview

The Analysis Rig runs in an isolated virtual machine to ensure:
- **Security**: Intelligence analysis is isolated from host system
- **Ephemeral Operation**: VM can be destroyed/reverted after each session
- **Network Isolation**: WAN adapter only enabled for payload retrieval
- **Forensic Clean State**: Baseline snapshot provides clean state for each analysis session

## VM Architecture

### Network Adapters

The VM uses a dual-adapter configuration:

**Adapter 1: NAT/Bridged (WAN)**
- **Purpose**: Internet access for payload retrieval
- **Default State**: DISABLED (security)
- **Enabled Only For**: Retrieving payloads via Tor from Telegram
- **IP**: DHCP-assigned (external)

**Adapter 2: Host-Only**
- **Purpose**: Communication with host machine
- **Default State**: ENABLED (always)
- **IP**: Static `192.168.56.10`
- **Network**: `192.168.56.0/24` (VirtualBox default)

### VM Specifications

**Recommended Configuration**:
- **OS**: Linux (Alpine, Debian, or Ubuntu minimal)
- **RAM**: 2-4 GB
- **Disk**: 20-40 GB (dynamically allocated)
- **CPU**: 2 cores
- **Network**: 2 adapters (NAT + Host-only)

## Initial Setup

### Step 1: Create VM

```bash
# Using VirtualBox
VBoxManage createvm --name "protosyte-rig" --ostype "Linux_64" --register
VBoxManage modifyvm "protosyte-rig" --memory 2048 --cpus 2
VBoxManage modifyvm "protosyte-rig" --nic1 nat --nic2 hostonly
VBoxManage modifyvm "protosyte-rig" --hostonlyadapter2 "vboxnet0"
VBoxManage modifyvm "protosyte-rig" --cableconnected1 off  # WAN disabled by default
```

### Step 2: Install Base OS

1. **Attach Installation ISO**:
   ```bash
   VBoxManage storageattach "protosyte-rig" \
       --storagectl "IDE Controller" \
       --port 0 --device 0 \
       --type dvddrive \
       --medium /path/to/debian-live.iso
   ```

2. **Start VM and Install**:
   ```bash
   VBoxManage startvm "protosyte-rig" --type headless
   ```

3. **Follow OS installation wizard**
4. **Remove installation ISO after installation**

### Step 3: Configure Host-Only Network

**Inside VM** (after OS installation):

```bash
# Configure static IP on host-only adapter (eth1)
sudo nmtui  # Or edit /etc/netplan/01-netcfg.yaml

# For Debian/Ubuntu:
sudo nano /etc/netplan/01-netcfg.yaml
```

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth1:  # Host-only adapter
      addresses:
        - 192.168.56.10/24
      gateway4: 192.168.56.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

Apply configuration:
```bash
sudo netplan apply
```

**Verify connectivity from host**:
```bash
ping 192.168.56.10
```

### Step 4: Install Dependencies

```bash
# Update package manager
sudo apt-get update  # Debian/Ubuntu
# or
sudo apk update  # Alpine

# Install required packages
sudo apt-get install -y \
    tor \
    torsocks \
    sqlite3 \
    curl \
    wget \
    openssh-server

# Start Tor service
sudo systemctl enable tor
sudo systemctl start tor

# Verify Tor is running
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

### Step 5: Install Go

```bash
# Download Go (adjust version as needed)
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz

# Extract
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# Add to PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
go version
```

### Step 6: Copy Analysis Rig Binary

**From host machine**:
```bash
# Build the binary first
cd analysis-rig
go build -o protosyte-rig .

# Copy to VM
scp protosyte-rig user@192.168.56.10:/home/user/

# Make executable
ssh user@192.168.56.10 "chmod +x protosyte-rig"
```

### Step 7: Create Baseline Snapshot

**Before creating snapshot, ensure**:
- ✅ Base OS installed
- ✅ Dependencies installed (Tor, Go, SQLite)
- ✅ Host-only network configured
- ✅ Binary copied
- ✅ WAN adapter DISABLED
- ✅ No intelligence data in database
- ✅ Clean state

```bash
# Stop VM
VBoxManage controlvm "protosyte-rig" poweroff

# Create snapshot
VBoxManage snapshot "protosyte-rig" take "baseline" \
    --description "Clean baseline state - ready for analysis sessions"

# Verify snapshot
VBoxManage snapshot "protosyte-rig" list
```

## VM Lifecycle Management

### Standard Analysis Session Workflow

```bash
# 1. Revert to baseline (ensures clean state)
./scripts/rig_destroy.sh

# 2. Start VM
./scripts/rig_start.sh

# 3. Enable WAN (for retrieval)
./scripts/vm-manage.sh enable-wan

# 4. In VM: Retrieve payloads
ssh user@192.168.56.10
export PROTOSYTE_BOT_TOKEN="your_token"
export PROTOSYTE_PASSPHRASE="your_passphrase"
torsocks ./protosyte-rig --mode retrieve

# 5. Disable WAN (back to isolated state)
./scripts/vm-manage.sh disable-wan

# 6. In VM: Analyze payloads (offline)
./protosyte-rig --mode analyze

# 7. In VM: Query intelligence
./protosyte-rig --mode stats
./protosyte-rig --mode records --limit 100
./protosyte-rig --mode hosts

# 8. Generate FIP report
./protosyte-rig --mode fip --output /tmp/rig_out/

# 9. Copy FIP to host
exit  # Exit SSH session
scp user@192.168.56.10:/tmp/rig_out/forensic_intel_packet.json.gz ./

# 10. Clean up: Revert VM to baseline
./scripts/rig_destroy.sh
```

## Network Configuration

### Enabling/Disabling WAN Adapter

**Enable WAN** (only when needed):
```bash
VBoxManage controlvm "protosyte-rig" setlinkstate1 on
```

**Disable WAN** (default state):
```bash
VBoxManage controlvm "protosyte-rig" setlinkstate1 off
```

**Check adapter status**:
```bash
VBoxManage showvminfo "protosyte-rig" | grep -A 5 "NIC"
```

### Testing Network Isolation

**Verify WAN is disabled**:
```bash
# From inside VM
ping 8.8.8.8
# Should fail if WAN is disabled

# From inside VM
curl https://www.google.com
# Should fail if WAN is disabled
```

**Verify Host-Only is working**:
```bash
# From host
ping 192.168.56.10
# Should succeed

# From VM
ping 192.168.56.1
# Should succeed
```

## Snapshots and Ephemeral Operation

### Creating Snapshots

**Baseline Snapshot** (created once during setup):
- Clean state
- All dependencies installed
- No intelligence data
- WAN disabled

**Create additional snapshots** (optional):
```bash
# After successful analysis session
VBoxManage snapshot "protosyte-rig" take "session-complete-$(date +%Y%m%d)" \
    --description "Analysis session completed on $(date)"
```

### Reverting to Baseline

**Manual revert**:
```bash
VBoxManage controlvm "protosyte-rig" poweroff
VBoxManage snapshot "protosyte-rig" restore "baseline"
```

**Using script**:
```bash
./scripts/rig_destroy.sh
```

### Snapshot Management

**List snapshots**:
```bash
VBoxManage snapshot "protosyte-rig" list
```

**Delete old snapshots** (if needed):
```bash
VBoxManage snapshot "protosyte-rig" delete "session-complete-20241201"
```

**⚠️ Warning**: Never delete the "baseline" snapshot!

## Automated Scripts

### rig_start.sh

Starts the VM and verifies it's running:
```bash
#!/bin/bash
VM_NAME="protosyte-rig"
./scripts/vm-manage.sh start
sleep 5
if ping -c 1 192.168.56.10 > /dev/null 2>&1; then
    echo "[OK] VM is running and reachable"
else
    echo "[ERROR] VM started but not reachable"
    exit 1
fi
```

### rig_destroy.sh

Reverts VM to baseline and ensures WAN is disabled:
```bash
#!/bin/bash
VM_NAME="protosyte-rig"
./scripts/vm-manage.sh disable-wan
./scripts/vm-manage.sh stop
sleep 2
./scripts/vm-manage.sh revert
echo "[OK] VM reverted to baseline state"
```

### vm-manage.sh

Basic VM control operations (already exists):
- `enable-wan`: Enable WAN adapter
- `disable-wan`: Disable WAN adapter
- `revert`: Revert to baseline snapshot
- `start`: Start VM
- `stop`: Stop VM

## Troubleshooting

### VM Not Reachable

**Problem**: Cannot ping 192.168.56.10 from host

**Solutions**:
1. Check VM is running:
   ```bash
   VBoxManage showvminfo "protosyte-rig" | grep State
   ```

2. Check host-only adapter:
   ```bash
   VBoxManage list hostonlyifs
   ```

3. Verify network configuration in VM:
   ```bash
   ssh user@192.168.56.10 "ip addr show"
   ```

4. Restart host-only adapter:
   ```bash
   VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0
   ```

### WAN Adapter Issues

**Problem**: Cannot retrieve payloads (no internet in VM)

**Solutions**:
1. Verify WAN is enabled:
   ```bash
   VBoxManage showvminfo "protosyte-rig" | grep -A 2 "NIC 1"
   ```

2. Enable WAN:
   ```bash
   ./scripts/vm-manage.sh enable-wan
   ```

3. Check NAT/Bridged adapter settings in VirtualBox GUI

4. Test connectivity:
   ```bash
   ssh user@192.168.56.10 "ping -c 3 8.8.8.8"
   ```

### Snapshot Issues

**Problem**: Cannot revert to baseline

**Solutions**:
1. Verify snapshot exists:
   ```bash
   VBoxManage snapshot "protosyte-rig" list
   ```

2. Ensure VM is stopped:
   ```bash
   VBoxManage controlvm "protosyte-rig" poweroff
   ```

3. Force stop if needed:
   ```bash
   VBoxManage controlvm "protosyte-rig" acpipowerbutton
   sleep 5
   VBoxManage controlvm "protosyte-rig" poweroff
   ```

### Tor Connection Issues

**Problem**: Cannot connect through Tor from VM

**Solutions**:
1. Verify Tor is running in VM:
   ```bash
   ssh user@192.168.56.10 "systemctl status tor"
   ```

2. Test Tor connection:
   ```bash
   ssh user@192.168.56.10 "curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip"
   ```

3. Check Tor configuration:
   ```bash
   ssh user@192.168.56.10 "cat /etc/tor/torrc | grep -v '^#' | grep -v '^$'"
   ```

### Database Issues

**Problem**: Analysis Rig cannot access database

**Solutions**:
1. Verify passphrase is set:
   ```bash
   ssh user@192.168.56.10 "echo \$PROTOSYTE_PASSPHRASE"
   ```

2. Check database file permissions:
   ```bash
   ssh user@192.168.56.10 "ls -la ~/protosyte_*.db"
   ```

3. Check SQLite installation:
   ```bash
   ssh user@192.168.56.10 "sqlite3 --version"
   ```

## Security Best Practices

1. **Always disable WAN after retrieval**: Prevents accidental data leakage
2. **Revert to baseline after each session**: Ensures clean state
3. **Use strong passphrases**: Protect encryption keys
4. **Isolate VM network**: Use host-only when possible
5. **Verify snapshot integrity**: Before important operations
6. **Monitor VM state**: Check WAN adapter status regularly
7. **Secure host machine**: VM isolation doesn't protect compromised host

## Alternative: Ephemeral Cloud Deployment

For cloud deployments, consider:

- **Fly.io**: Automatically destroys containers after execution
- **Render**: Ephemeral one-off tasks
- **AWS Lambda/ECS**: Serverless execution
- **Kubernetes Jobs**: One-time execution pods

See `OPERATIONAL_WORKFLOW.md` for cloud deployment details.

## See Also

- `OPERATIONAL_WORKFLOW.md` - Complete operational procedures
- `SECURITY_PROCEDURES.md` - Security and OPSEC procedures
- `scripts/vm-manage.sh` - VM management script
- `scripts/rig_start.sh` - VM startup script
- `scripts/rig_destroy.sh` - VM cleanup script

