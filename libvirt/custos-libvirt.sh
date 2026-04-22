#!/bin/bash
# custos-libvirt.sh — orchestre l'environnement libvirt 3 VMs pour les
# tests E2E custos : client → filtre OpenWrt bridge → serveur DNS.
#
# Usage :
#   ./custos-libvirt.sh ensure      # crée images, réseaux, VMs (idempotent)
#   ./custos-libvirt.sh start       # démarre les VMs et attend que SSH réponde
#   ./custos-libvirt.sh stop        # arrête proprement
#   ./custos-libvirt.sh nuke        # supprime tout (VMs, réseaux, images)
#   ./custos-libvirt.sh show        # affiche les IPs
#   ./custos-libvirt.sh filter-ip   # imprime l'IP mgmt du filtre
#   ./custos-libvirt.sh client-ip   # imprime l'IP statique du client
#   ./custos-libvirt.sh dns-ip      # imprime l'IP statique du DNS
#
# Nécessite : qemu-kvm, virsh, qemu-img, genisoimage, sudo (losetup/mount
# pour l'injection OpenWrt), curl (premier téléchargement).

set -e

export LIBVIRT_DEFAULT_URI=qemu:///system

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VM_DIR="/var/lib/libvirt/images"
IMG_DIR="$PROJECT_DIR/images"

FILTER_USER="${FILTER_USER:-root}"
CLIENT_USER="${CLIENT_USER:-debian}"
DNS_USER="${DNS_USER:-debian}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa}"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=5 -o BatchMode=yes"

DEBIAN_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"

# ── Helpers ───────────────────────────────────────────────────────

log()  { echo "[custos-libvirt] $*"; }
err()  { echo "[custos-libvirt] ERROR: $*" >&2; exit 1; }

virsh_has() { virsh dominfo "$1" &>/dev/null; }
net_has()   { virsh net-info "$1" &>/dev/null; }

ensure_network() {
    local name="$1" xmlfile="$2"
    if ! net_has "$name"; then
        log "Définition du réseau $name..."
        virsh net-define "$xmlfile"
    fi
    virsh net-autostart "$name" 2>/dev/null || true
    virsh net-start "$name" 2>/dev/null || true
}

make_cidata() {
    local out="$1" userdata="$2" metadata="$3" netconfig="${4:-}"
    local args=("user-data=$userdata" "meta-data=$metadata")
    [ -n "$netconfig" ] && [ -f "$netconfig" ] && args+=("network-config=$netconfig")
    genisoimage -output "$out" -volid cidata -joliet -rock \
        -graft-points "${args[@]}" 2>/dev/null
}

filter_mgmt_ip() {
    # Essaie d'abord les leases libvirt, puis arp.
    local ip
    ip=$(virsh net-dhcp-leases custos-mgmt 2>/dev/null \
        | awk '/52:54:00:00:01:03/ {split($5,a,"/"); print a[1]; exit}')
    if [ -z "$ip" ]; then
        ip=$(ip neigh show dev custos-mgmt 2>/dev/null \
            | awk '/52:54:00:00:01:03/ {print $1; exit}')
    fi
    echo "$ip"
}

wait_ssh() {
    local user="$1" ip="$2" label="${3:-$user@$ip}" tries=0 max=60
    log "Attente SSH sur $label..."
    while [ $tries -lt $max ]; do
        if [ -n "$ip" ] && ssh $SSH_OPTS -i "$SSH_KEY" "${user}@${ip}" true 2>/dev/null; then
            log "$label accessible."
            return 0
        fi
        tries=$((tries + 1))
        sleep 5
    done
    err "$label non accessible après $((max * 5))s"
}

# ── Image base Debian (kernel direct boot) ────────────────────────

ensure_debian_base() {
    mkdir -p "$IMG_DIR"
    if [ ! -f "$IMG_DIR/debian.qcow2" ]; then
        log "Téléchargement Debian 13 cloud image..."
        curl -L --fail -o "$IMG_DIR/debian.qcow2" "$DEBIAN_URL"
    fi

    # Extraction kernel/initrd (évite les soucis de bootloader avec
    # les backing files qcow2).
    if [ ! -f /tmp/custos-vmlinuz ] || [ ! -f /tmp/custos-initrd.img ]; then
        log "Extraction kernel/initrd..."
        local mnt nbd_dev
        mnt=$(mktemp -d)
        nbd_dev=/dev/nbd0
        sudo modprobe nbd max_part=8 2>/dev/null || true
        sudo qemu-nbd --connect="$nbd_dev" -r "$IMG_DIR/debian.qcow2"
        sleep 2
        sudo mount -o ro "${nbd_dev}p1" "$mnt"
        local vmlinuz initrd
        vmlinuz=$(ls "$mnt"/boot/vmlinuz-* 2>/dev/null | sort | tail -1)
        initrd=$(ls "$mnt"/boot/initrd.img-* 2>/dev/null | sort | tail -1)
        sudo cp "$vmlinuz" /tmp/custos-vmlinuz
        sudo cp "$initrd"  /tmp/custos-initrd.img
        sudo chmod 644 /tmp/custos-vmlinuz /tmp/custos-initrd.img
        sudo umount "$mnt"
        sudo qemu-nbd --disconnect "$nbd_dev"
        rmdir "$mnt"
    fi
}

# ── VM disks + cloud-init ISOs ────────────────────────────────────

ensure_debian_vm_disk() {
    local vm="$1"
    if sudo test -f "$VM_DIR/${vm}.qcow2"; then
        return
    fi
    log "Création du disque $vm..."
    sudo qemu-img create -f qcow2 -b "$IMG_DIR/debian.qcow2" \
        -F qcow2 "$VM_DIR/${vm}.qcow2" 4G >/dev/null
}

ensure_cidata() {
    local iso="$1" userdata="$2" metadata="$3" netconfig="$4"
    if sudo test -f "$VM_DIR/$iso"; then
        return
    fi
    log "Génération $iso..."
    local tmpiso
    tmpiso=$(mktemp --suffix=.iso)
    make_cidata "$tmpiso" "$userdata" "$metadata" "$netconfig"
    sudo install -m 0644 "$tmpiso" "$VM_DIR/$iso"
    rm -f "$tmpiso"
}

ensure_filter_disk() {
    # Prépare l'image OpenWrt (télécharge, resize, injecte clé SSH + config).
    bash "$SCRIPT_DIR/openwrt-inject.sh"

    # Copie l'image préparée dans le répertoire libvirt (évite les soucis
    # AppArmor/path resolution avec un backing file hors /var/lib/libvirt).
    need_copy=1
    if sudo test -f "$VM_DIR/openwrt-base.img"; then
        if ! sudo test "$IMG_DIR/openwrt-base.img" -nt "$VM_DIR/openwrt-base.img"; then
            need_copy=0
        fi
    fi
    if [ "$need_copy" = 1 ]; then
        log "Copie openwrt-base.img → $VM_DIR..."
        sudo cp "$IMG_DIR/openwrt-base.img" "$VM_DIR/openwrt-base.img"
    fi

    if ! sudo test -f "$VM_DIR/custos-filter.qcow2"; then
        log "Création du disque filter (qcow2 sur openwrt-base.img)..."
        sudo qemu-img create -f qcow2 -b "$VM_DIR/openwrt-base.img" \
            -F raw "$VM_DIR/custos-filter.qcow2" 1G >/dev/null
    fi
}

# ── Cycles de vie ──────────────────────────────────────────────────

cmd_ensure() {
    ensure_debian_base

    ensure_debian_vm_disk custos-client
    ensure_debian_vm_disk custos-dns
    ensure_filter_disk

    ensure_cidata cidata-client.iso \
        "$SCRIPT_DIR/user-data-client" \
        "$SCRIPT_DIR/meta-data-client" \
        "$SCRIPT_DIR/network-config-client"

    ensure_cidata cidata-dns.iso \
        "$SCRIPT_DIR/user-data-dns" \
        "$SCRIPT_DIR/meta-data-dns" \
        "$SCRIPT_DIR/network-config-dns"

    ensure_network custos-lan  "$SCRIPT_DIR/network-lan.xml"
    ensure_network custos-up   "$SCRIPT_DIR/network-upstream.xml"
    ensure_network custos-mgmt "$SCRIPT_DIR/network-mgmt.xml"

    # Redéfinition inconditionnelle des VMs : le XML peut changer entre
    # deux runs, on veut la dernière version.
    for vm in custos-client custos-dns custos-filter; do
        if virsh_has "$vm"; then
            virsh destroy "$vm" 2>/dev/null || true
            virsh undefine "$vm" 2>/dev/null || true
        fi
        virsh define "$SCRIPT_DIR/$(echo $vm | sed 's/^custos-//').xml" >/dev/null
    done
    log "Environnement défini."
}

cmd_start() {
    for vm in custos-client custos-dns custos-filter; do
        virsh_has "$vm" || err "$vm n'est pas défini (exécute d'abord ensure)"
        virsh start "$vm" 2>/dev/null || true
    done

    # Debian VMs ont une IP statique connue sur le réseau bridge.
    # Client et DNS sont joignables via… le filtre en bridge transparent !
    # Donc depuis l'hôte, on n'y accède pas directement — on y accède
    # via SSH sur l'IP mgmt du filtre puis bridges vers client/dns.
    # On attend juste que le filtre soit joignable via son NIC mgmt.

    local ip
    local tries=0
    while [ $tries -lt 60 ]; do
        ip=$(filter_mgmt_ip)
        [ -n "$ip" ] && break
        tries=$((tries + 1))
        sleep 5
    done
    [ -n "$ip" ] || err "IP mgmt du filtre introuvable après 5 min"
    log "IP mgmt filtre : $ip"

    wait_ssh "$FILTER_USER" "$ip" "filtre ($ip)"
}

cmd_stop() {
    for vm in custos-client custos-dns custos-filter; do
        virsh shutdown "$vm" 2>/dev/null || true
    done
    # Attendre un peu, puis forcer
    for _ in 1 2 3 4 5 6; do
        all_off=1
        for vm in custos-client custos-dns custos-filter; do
            virsh domstate "$vm" 2>/dev/null | grep -q "shut off" || all_off=0
        done
        [ "$all_off" = 1 ] && break
        sleep 5
    done
    for vm in custos-client custos-dns custos-filter; do
        virsh destroy "$vm" 2>/dev/null || true
    done
}

cmd_nuke() {
    for vm in custos-client custos-dns custos-filter; do
        virsh destroy "$vm"  2>/dev/null || true
        virsh undefine "$vm" 2>/dev/null || true
    done
    for net in custos-lan custos-up custos-mgmt; do
        virsh net-destroy  "$net" 2>/dev/null || true
        virsh net-undefine "$net" 2>/dev/null || true
    done
    sudo rm -f "$VM_DIR"/custos-*.qcow2 "$VM_DIR"/cidata-*.iso
    sudo rm -f "$IMG_DIR"/openwrt-base.img "$IMG_DIR"/.openwrt-base-injected-v1
    log "Nuked."
}

cmd_show() {
    local ip
    ip=$(filter_mgmt_ip)
    echo "filter mgmt IP : ${ip:-(unknown)}"
    echo "filter LAN IP  : 10.99.0.254 (br-lan)"
    echo "client IP      : 10.99.0.10 (custos-lan)"
    echo "dns IP         : 10.99.0.1  (custos-up), aliases 10.99.0.50/60/70"
}

# ── Entry point ───────────────────────────────────────────────────

case "${1:-}" in
    ensure)    cmd_ensure ;;
    start)     cmd_start ;;
    stop)      cmd_stop ;;
    nuke)      cmd_nuke ;;
    show)      cmd_show ;;
    filter-ip) filter_mgmt_ip ;;
    client-ip) echo "10.99.0.10" ;;
    dns-ip)    echo "10.99.0.1" ;;
    *)
        echo "Usage: $0 {ensure|start|stop|nuke|show|filter-ip|client-ip|dns-ip}"
        exit 1
        ;;
esac
