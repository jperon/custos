#!/bin/bash
# custos-libvirt.sh - Manage libvirt VMs for CustosVirginum KVM tests
# Usage: sudo ./custos-libvirt.sh create
#        ./custos-libvirt.sh [start|stop|delete|filter-ip|wait-agents]

set -e

export LIBVIRT_DEFAULT_URI=qemu:///system

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VM_DIR="/var/lib/libvirt/images"
IMG_DIR="$PROJECT_DIR/images"
FILTER_USER="debian"
SSH_KEY="$HOME/.ssh/id_rsa"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes"

# --- Helpers -----------------------------------------------------------------

# Get the management IP of the filter VM (wan network, 192.168.200.x)
filter_ip() {
    local ip
    ip=$(virsh domifaddr custos-filter --source agent 2>/dev/null \
        | awk '/192\.168\.200\./ {split($4,a,"/"); print a[1]; exit}')
    if [ -z "$ip" ]; then
        ip=$(virsh net-dhcp-leases wan 2>/dev/null \
            | awk '/custos-filter/ {print $5}' | cut -d/ -f1 | head -1)
    fi
    echo "$ip"
}

# Wait until SSH is available on the filter management interface
wait_for_ssh() {
    echo "Waiting for SSH on filter VM..."
    local ip tries=0
    while true; do
        ip=$(filter_ip)
        if [ -n "$ip" ]; then
            if ssh $SSH_OPTS -i "$SSH_KEY" "${FILTER_USER}@${ip}" true 2>/dev/null; then
                echo "Filter VM reachable at $ip"
                return 0
            fi
        fi
        tries=$((tries+1))
        if [ "$tries" -ge 60 ]; then
            echo "ERROR: filter VM not reachable after 5 minutes" >&2
            return 1
        fi
        sleep 5
    done
}

# Wait until the qemu-guest-agent on a VM responds
wait_for_agent() {
    local vm="$1" tries=0
    echo "Waiting for guest agent on $vm..."
    while true; do
        if virsh qemu-agent-command "$vm" '{"execute":"guest-ping"}' 2>/dev/null \
                | grep -q '"return"'; then
            echo "Guest agent ready on $vm"
            return 0
        fi
        tries=$((tries+1))
        if [ "$tries" -ge 24 ]; then
            echo "ERROR: guest agent on $vm not ready after 2 minutes" >&2
            return 1
        fi
        sleep 5
    done
}

# Generate a cloud-init ISO (supports optional network-config file)
make_cidata() {
    local out="$1" userdata="$2" metadata="$3" netconfig="${4:-}"
    local args=("user-data=$userdata" "meta-data=$metadata")
    [ -n "$netconfig" ] && [ -f "$netconfig" ] && args+=("network-config=$netconfig")
    if command -v genisoimage &>/dev/null; then
        genisoimage -output "$out" -volid cidata -joliet -rock \
            -graft-points "${args[@]}" 2>/dev/null
    else
        mkisofs -output "$out" -volid cidata -joliet -rock \
            -graft-points "${args[@]}" 2>/dev/null
    fi
}

# Apply NAT masquerade on the router VM — idempotent, called after each start.
# Requires jq (for safe JSON encoding) and the qemu-guest-agent to be running.
setup_router_nat() {
    echo "Configuring router NAT (masquerade)..."
    wait_for_agent custos-router
    local script
    read -r -d '' script <<'SCRIPT' || true
WAN=$(ip -o link | awk '/52:54:00:00:02:02/ {print $2}' | tr -d :)
[ -z "$WAN" ] && exit 0
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
nft add table ip nat 2>/dev/null || true
nft add chain ip nat postrouting '{ type nat hook postrouting priority 100; }' 2>/dev/null || true
nft list ruleset | grep -q masquerade || \
    nft add rule ip nat postrouting oifname "$WAN" masquerade
SCRIPT
    local payload
    payload=$(jq -n --arg cmd "$script" \
        '{"execute":"guest-exec","arguments":{"path":"/bin/sh","arg":["-c",$cmd],"capture-output":true}}')
    virsh qemu-agent-command custos-router "$payload" >/dev/null 2>&1 || true
    sleep 3
    echo "Router NAT configured"
}

# Define a libvirt network if not already defined, then start/autostart it
ensure_network() {
    local name="$1" xmlfile="$2"
    virsh net-info "$name" &>/dev/null || virsh net-define "$xmlfile"
    virsh net-autostart "$name" 2>/dev/null || true
    virsh net-start "$name" 2>/dev/null || true
}

# --- Image creation ----------------------------------------------------------

create_base_images() {
    mkdir -p "$VM_DIR" "$IMG_DIR"

    # Debian 13 cloud image (filter + client + router)
    if [ ! -f "$IMG_DIR/debian.qcow2" ]; then
        echo "Downloading Debian 13 cloud image..."
        curl -L -o "$IMG_DIR/debian.qcow2" \
            "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
    fi

    # Extract kernel and initrd from base image for direct kernel boot
    # (Avoids GRUB/BIOS boot issues with qcow2 backing files)
    if [ ! -f /tmp/custos-vmlinuz ] || [ ! -f /tmp/custos-initrd.img ]; then
        echo "Extracting kernel and initrd from base image..."
        local mnt
        mnt=$(mktemp -d)
        local nbd_dev=/dev/nbd0
        modprobe nbd max_part=8 2>/dev/null || true
        qemu-nbd --connect="$nbd_dev" -r "$IMG_DIR/debian.qcow2"
        sleep 2
        mount -o ro "${nbd_dev}p1" "$mnt"
        vmlinuz=$(ls "$mnt"/boot/vmlinuz-* 2>/dev/null | sort | tail -1)
        initrd=$(ls "$mnt"/boot/initrd.img-* 2>/dev/null | sort | tail -1)
        cp "$vmlinuz" /tmp/custos-vmlinuz
        cp "$initrd" /tmp/custos-initrd.img
        chmod 644 /tmp/custos-vmlinuz /tmp/custos-initrd.img
        umount "$mnt"
        rmdir "$mnt"
        qemu-nbd --disconnect "$nbd_dev"
        echo "Kernel: $vmlinuz"
    fi

    # Per-VM copy-on-write images
    for vm in custos-filter custos-router custos-client; do
        if [ ! -f "$VM_DIR/${vm}.qcow2" ]; then
            qemu-img create -f qcow2 -b "$IMG_DIR/debian.qcow2" \
                -F qcow2 "$VM_DIR/${vm}.qcow2" 4G
        fi
    done

    # custos-client2 uses a pre-built base image with packages already installed.
    # debian-client-base.qcow2 is created once from custos-client.qcow2 (flattened)
    # after its first cloud-init boot, so apt packages are baked in.
    if [ ! -f "$IMG_DIR/debian-client-base.qcow2" ]; then
        echo "ERROR: $IMG_DIR/debian-client-base.qcow2 not found."
        echo "Run: sudo qemu-img convert -f qcow2 -O qcow2 $VM_DIR/custos-client.qcow2 $IMG_DIR/debian-client-base.qcow2"
        echo "(requires custos-client to be stopped first)"
        exit 1
    fi
    if [ ! -f "$VM_DIR/custos-client2.qcow2" ]; then
        qemu-img create -f qcow2 -b "$IMG_DIR/debian-client-base.qcow2" \
            -F qcow2 "$VM_DIR/custos-client2.qcow2" 4G
    fi

    # Cloud-init ISO for filter VM
    if [ ! -f "$VM_DIR/cidata-filter.iso" ]; then
        echo "Building cidata-filter.iso..."
        make_cidata "$VM_DIR/cidata-filter.iso" \
            "$PROJECT_DIR/user-data" "$PROJECT_DIR/meta-data" \
            "$SCRIPT_DIR/network-config-filter"
    fi

    # Cloud-init ISO for router VM
    if [ ! -f "$VM_DIR/cidata-router.iso" ]; then
        echo "Building cidata-router.iso..."
        make_cidata "$VM_DIR/cidata-router.iso" \
            "$SCRIPT_DIR/user-data-router" "$SCRIPT_DIR/meta-data-router" \
            "$SCRIPT_DIR/network-config-router"
    fi

    # Cloud-init ISO for client VM
    if [ ! -f "$VM_DIR/cidata-client.iso" ]; then
        echo "Building cidata-client.iso..."
        make_cidata "$VM_DIR/cidata-client.iso" \
            "$SCRIPT_DIR/user-data-client" "$SCRIPT_DIR/meta-data-client" \
            "$SCRIPT_DIR/network-config-client"
    fi

    # Cloud-init ISO for client2 VM (packages from backing, distinct hostname/IP/MAC)
    if [ ! -f "$VM_DIR/cidata-client2.iso" ]; then
        echo "Building cidata-client2.iso..."
        make_cidata "$VM_DIR/cidata-client2.iso" \
            "$SCRIPT_DIR/user-data-client2" "$SCRIPT_DIR/meta-data-client2" \
            "$SCRIPT_DIR/network-config-client2"
    fi

    # Define libvirt networks
    ensure_network lan     "$SCRIPT_DIR/network-lan.xml"
    ensure_network wanfilter "$SCRIPT_DIR/network-wanfilter.xml"
    ensure_network wan     "$SCRIPT_DIR/network-wan.xml"

    # Define VMs
    virsh dominfo custos-router  2>/dev/null || virsh define "$SCRIPT_DIR/router.xml"
    virsh dominfo custos-client  2>/dev/null || virsh define "$SCRIPT_DIR/client.xml"
    virsh dominfo custos-client2 2>/dev/null || virsh define "$SCRIPT_DIR/client2.xml"
    virsh dominfo custos-filter  2>/dev/null || virsh define "$SCRIPT_DIR/filter.xml"
}

# --- Lifecycle ---------------------------------------------------------------

case "$1" in
    create)
        create_base_images
        ;;
    start)
        for vm in custos-router custos-filter custos-client custos-client2; do
            virsh start "$vm" 2>/dev/null || true
        done
        wait_for_ssh
        setup_router_nat
        ;;
    wait-agents)
        wait_for_agent custos-client
        wait_for_agent custos-client2
        ;;
    stop)
        for vm in custos-client2 custos-client custos-filter custos-router; do
            virsh shutdown "$vm" 2>/dev/null || true
        done
        for vm in custos-client2 custos-client custos-filter custos-router; do
            for _ in $(seq 1 6); do
                virsh domstate "$vm" 2>/dev/null | grep -q "shut off" && break
                sleep 5
            done
            virsh destroy "$vm" 2>/dev/null || true
        done
        ;;
    delete)
        for vm in custos-client2 custos-client custos-filter custos-router; do
            virsh destroy  "$vm" 2>/dev/null || true
            virsh undefine "$vm" 2>/dev/null || true
        done
        for net in lan wanfilter wan; do
            virsh net-destroy  "$net" 2>/dev/null || true
            virsh net-undefine "$net" 2>/dev/null || true
        done
        rm -f "$VM_DIR"/custos-*.qcow2 "$VM_DIR"/cidata-*.iso
        ;;
    filter-ip)
        ip=$(filter_ip)
        if [ -z "$ip" ]; then
            echo "ERROR: could not determine filter VM IP" >&2
            exit 1
        fi
        echo "$ip"
        ;;
    *)
        echo "Usage: $0 {create|start|stop|delete|filter-ip|wait-agents}"
        exit 1
        ;;
esac
