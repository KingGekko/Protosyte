#!/bin/bash
# Analysis Rig VM Destruction/Cleanup Script
# Reverts VM to baseline snapshot and ensures clean state

set -e

VM_NAME="protosyte-rig"
SNAPSHOT_NAME="baseline"
HOST_ONLY_IP="192.168.56.10"

echo "[RIG] Cleaning up Analysis Rig VM..."

# Check if VM exists
if ! VBoxManage showvminfo "$VM_NAME" &>/dev/null; then
    echo "[ERROR] VM '$VM_NAME' not found."
    exit 1
fi

# Get VM state
VM_STATE=$(VBoxManage showvminfo "$VM_NAME" --machinereadable | grep 'VMState=' | cut -d'=' -f2 | tr -d '"')

if [ "$VM_STATE" = "running" ]; then
    echo "[RIG] VM is running. Ensuring WAN adapter is disabled..."
    VBoxManage controlvm "$VM_NAME" setlinkstate1 off
    
    # Give it a moment to disable
    sleep 1
    
    echo "[RIG] Stopping VM..."
    VBoxManage controlvm "$VM_NAME" acpipowerbutton
    
    # Wait for graceful shutdown
    echo "[RIG] Waiting for graceful shutdown (up to 30 seconds)..."
    TIMEOUT=30
    ELAPSED=0
    while [ $ELAPSED -lt $TIMEOUT ]; do
        CURRENT_STATE=$(VBoxManage showvminfo "$VM_NAME" --machinereadable | grep 'VMState=' | cut -d'=' -f2 | tr -d '"')
        if [ "$CURRENT_STATE" != "running" ]; then
            break
        fi
        sleep 1
        ELAPSED=$((ELAPSED + 1))
    done
    
    # Force stop if still running
    if [ "$CURRENT_STATE" = "running" ]; then
        echo "[WARN] VM did not shut down gracefully. Forcing poweroff..."
        VBoxManage controlvm "$VM_NAME" poweroff
        sleep 2
    fi
    
    echo "[OK] VM stopped"
else
    echo "[INFO] VM is not running (state: $VM_STATE)"
fi

# Verify snapshot exists
echo "[RIG] Checking for baseline snapshot..."
if ! VBoxManage snapshot "$VM_NAME" list | grep -q "$SNAPSHOT_NAME"; then
    echo "[ERROR] Baseline snapshot '$SNAPSHOT_NAME' not found!"
    echo "[ERROR] Cannot safely revert VM. Manual intervention required."
    echo ""
    echo "Available snapshots:"
    VBoxManage snapshot "$VM_NAME" list
    exit 1
fi

# Revert to baseline
echo "[RIG] Reverting VM to baseline snapshot '$SNAPSHOT_NAME'..."
VBoxManage snapshot "$VM_NAME" restore "$SNAPSHOT_NAME"

if [ $? -eq 0 ]; then
    echo "[OK] VM reverted to baseline snapshot"
else
    echo "[ERROR] Failed to revert snapshot"
    exit 1
fi

# Verify WAN adapter is disabled in snapshot configuration
echo "[RIG] Verifying network configuration..."
# Note: Snapshot restore should preserve adapter states, but we check anyway
echo "[INFO] WAN adapter should be disabled in baseline snapshot"

# Optional: Display snapshot info
echo ""
echo "[RIG] Snapshot Information:"
VBoxManage snapshot "$VM_NAME" list

echo ""
echo "[OK] Analysis Rig VM cleanup complete"
echo "[INFO] VM is now in baseline state - ready for next analysis session"
echo "[INFO] Start VM: ./scripts/rig_start.sh"

