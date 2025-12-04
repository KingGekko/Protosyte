#!/bin/bash
# Stage 1: Data Retrieval Session
# This script orchestrates the retrieval phase

set -e

VM_NAME="protosyte-rig"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[SESSION] Starting retrieval session..."

# Step 1: Revert to baseline
echo "[SESSION] Reverting VM to baseline..."
"$SCRIPT_DIR/vm-manage.sh" revert

# Step 2: Start VM
echo "[SESSION] Starting VM..."
"$SCRIPT_DIR/vm-manage.sh" start

# Wait for VM to boot
sleep 30

# Step 3: Enable WAN adapter
echo "[SESSION] Enabling WAN adapter..."
"$SCRIPT_DIR/vm-manage.sh" enable-wan

# Step 4: Trigger retrieval inside VM (via SSH or guest additions)
echo "[SESSION] Triggering retrieval in VM..."
# This would SSH into the VM and run: torsocks protosyte-rig --mode retrieve --token-env TELE_TOKEN

# Wait for retrieval to complete
sleep 60

# Step 5: Disable WAN adapter
echo "[SESSION] Disabling WAN adapter..."
"$SCRIPT_DIR/vm-manage.sh" disable-wan

echo "[SESSION] Retrieval session complete. VM is now air-gapped."

