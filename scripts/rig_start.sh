#!/bin/bash
# Analysis Rig VM Startup Script
# Starts the VM, verifies connectivity, and ensures proper state

set -e

VM_NAME="protosyte-rig"
HOST_ONLY_IP="192.168.56.10"
MAX_WAIT=60  # Maximum seconds to wait for VM to become reachable

echo "[RIG] Starting Analysis Rig VM..."

# Check if VM exists
if ! VBoxManage showvminfo "$VM_NAME" &>/dev/null; then
    echo "[ERROR] VM '$VM_NAME' not found. Please create it first."
    echo "See docs/ANALYSIS_VM.md for setup instructions."
    exit 1
fi

# Check if VM is already running
VM_STATE=$(VBoxManage showvminfo "$VM_NAME" --machinereadable | grep 'VMState=' | cut -d'=' -f2 | tr -d '"')

if [ "$VM_STATE" = "running" ]; then
    echo "[INFO] VM is already running"
else
    # Start VM
    echo "[RIG] Starting VM '$VM_NAME'..."
    VBoxManage startvm "$VM_NAME" --type headless
    
    # Wait for VM to boot
    echo "[RIG] Waiting for VM to boot..."
    sleep 5
fi

# Ensure WAN adapter is DISABLED (default secure state)
echo "[RIG] Ensuring WAN adapter is disabled..."
VBoxManage controlvm "$VM_NAME" setlinkstate1 off

# Wait for host-only network to be reachable
echo "[RIG] Waiting for VM to become reachable on host-only network..."
COUNTER=0
while [ $COUNTER -lt $MAX_WAIT ]; do
    if ping -c 1 -W 1 "$HOST_ONLY_IP" &>/dev/null; then
        echo "[OK] VM is reachable at $HOST_ONLY_IP"
        break
    fi
    
    COUNTER=$((COUNTER + 2))
    echo "[WAIT] Still waiting... ($COUNTER/$MAX_WAIT seconds)"
    sleep 2
done

if [ $COUNTER -ge $MAX_WAIT ]; then
    echo "[ERROR] VM did not become reachable within $MAX_WAIT seconds"
    echo "[INFO] VM may still be booting. Check with: VBoxManage showvminfo $VM_NAME"
    exit 1
fi

# Verify SSH connectivity (optional)
if command -v ssh &>/dev/null; then
    echo "[RIG] Testing SSH connectivity..."
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "user@$HOST_ONLY_IP" "echo 'SSH OK'" &>/dev/null 2>&1; then
        echo "[OK] SSH connectivity confirmed"
    else
        echo "[WARN] SSH not available or not configured (this is OK if you use other access methods)"
    fi
fi

# Display VM status
echo ""
echo "[RIG] VM Status:"
echo "  - Name: $VM_NAME"
echo "  - State: $(VBoxManage showvminfo "$VM_NAME" --machinereadable | grep 'VMState=' | cut -d'=' -f2 | tr -d '"')"
echo "  - IP: $HOST_ONLY_IP"
echo "  - WAN Adapter: DISABLED (secure)"
echo ""
echo "[OK] Analysis Rig VM is ready for operation"
echo "[INFO] Enable WAN adapter when needed: ./scripts/vm-manage.sh enable-wan"
echo "[INFO] Connect to VM: ssh user@$HOST_ONLY_IP"

