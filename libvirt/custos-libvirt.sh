#!/bin/bash
# custos-libvirt.sh - Setup libvirt VMs for CustosVirginum testing
# Note: The filter is now deployed via Docker (see docker-compose.yml)
# This script only manages client and router VMs.
# Usage: sudo ./custos-libvirt.sh [start|stop|create|delete]

set -e

VM_DIR="/var/lib/libvirt/images"
IMG_DIR="$(dirname "$0")/../images"
OWRT_VERSION="25.12.1"

# Create base VM images (using cloud-init for Debian, raw for OpenWrt)
create_base_images() {
    mkdir -p "$VM_DIR" "$IMG_DIR"

    # OpenWrt x86/64 (router)
    if [ ! -f "$IMG_DIR/openwrt.qcow2" ]; then
        echo "Downloading OpenWrt ${OWRT_VERSION} for x86/64..."
        curl -L -o "$IMG_DIR/openwrt.qcow2.gz" \
            "https://downloads.openwrt.org/releases/${OWRT_VERSION}/targets/x86/64/openwrt-${OWRT_VERSION}-x86-64-generic-ext4-combined.img.gz"
        gunzip "$IMG_DIR/openwrt.qcow2.gz"
    fi

    # Debian cloud image (client)
    if [ ! -f "$IMG_DIR/debian.qcow2" ]; then
        echo "Downloading Debian 13 cloud image..."
        curl -L -o "$IMG_DIR/debian.qcow2" \
            "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
    fi

    # Create differencing images
    if [ ! -f "$VM_DIR/custos-client.qcow2" ]; then
        qemu-img create -f qcow2 -b "$IMG_DIR/debian.qcow2" \
            -F qcow2 "$VM_DIR/custos-client.qcow2" 2G
    fi

    if [ ! -f "$VM_DIR/custos-router.qcow2" ]; then
        cp "$IMG_DIR/openwrt.qcow2" "$VM_DIR/custos-router.qcow2"
        # Resize to 512M for headroom
        qemu-img resize "$VM_DIR/custos-router.qcow2" 512M
    fi
}

case "$1" in
    create)
        create_base_images
        ;;
    start)
        for vm in custos-client custos-router; do
            virsh start "$vm" 2>/dev/null || true
        done
        ;;
    stop)
        for vm in custos-client custos-router; do
            virsh shutdown "$vm" 2>/dev/null || true
        done
        sleep 5
        ;;
    delete)
        for vm in custos-client custos-router; do
            virsh destroy "$vm" 2>/dev/null || true
            virsh undefine "$vm" 2>/dev/null || true
        done
        virsh net-destroy lan 2>/dev/null || true
        virsh net-undefine lan 2>/dev/null || true
        rm -f "$VM_DIR"/custos-*.qcow2
        ;;
    *)
        echo "Usage: $0 {create|start|stop|delete}"
        echo "Note: Filter is now deployed via Docker (see docker-compose.yml)"
        exit 1
        ;;
esac
