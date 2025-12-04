#!/bin/bash
# VM Management Script for Analysis Rig
# Controls network adapters and snapshots

VM_NAME="protosyte-rig"
SNAPSHOT_NAME="baseline"

case "$1" in
    enable-wan)
        echo "[VM] Enabling WAN adapter..."
        VBoxManage controlvm "$VM_NAME" setlinkstate1 on
        ;;
    disable-wan)
        echo "[VM] Disabling WAN adapter..."
        VBoxManage controlvm "$VM_NAME" setlinkstate1 off
        ;;
    revert)
        echo "[VM] Reverting to baseline snapshot..."
        VBoxManage snapshot "$VM_NAME" restore "$SNAPSHOT_NAME"
        ;;
    start)
        echo "[VM] Starting VM..."
        VBoxManage startvm "$VM_NAME" --type headless
        ;;
    stop)
        echo "[VM] Stopping VM..."
        VBoxManage controlvm "$VM_NAME" poweroff
        ;;
    *)
        echo "Usage: $0 {enable-wan|disable-wan|revert|start|stop}"
        exit 1
        ;;
esac

