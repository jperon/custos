#!/usr/bin/env bash
# inject.sh — copie un script uci-defaults dans une image OpenWrt qcow2.
#
# Usage : inject.sh <qcow2> <uci-defaults-script> <ssh-pubkey>
#
# Stratégie :
#   1. guestfish (libguestfs) — pure userspace, pas de sudo requis.
#   2. qemu-nbd + mount       — fallback si guestfish absent ; nécessite sudo
#      et le module nbd (modprobe nbd).
#
# Le placeholder __SSH_PUBKEY__ dans le script est remplacé par la clé fournie.

set -e

QCOW2="${1:?qcow2 path required}"
SCRIPT="${2:?uci-defaults script required}"
PUBKEY="${3:?ssh pubkey required}"

[ -f "$QCOW2" ]  || { echo "image absente : $QCOW2"  >&2; exit 1; }
[ -f "$SCRIPT" ] || { echo "script absent : $SCRIPT" >&2; exit 1; }

tmpfile=$(mktemp)
trap "rm -f $tmpfile" EXIT
awk -v key="$PUBKEY" '{gsub(/__SSH_PUBKEY__/, key); print}' "$SCRIPT" > "$tmpfile"
chmod 0755 "$tmpfile"

# ── Stratégie 1 : guestfish ───────────────────────────────────────────────────
if command -v guestfish >/dev/null 2>&1; then
    guestfish --rw -a "$QCOW2" -i <<EOF
mkdir-p /etc/uci-defaults
upload $tmpfile /etc/uci-defaults/99-homelab
chmod 0755 /etc/uci-defaults/99-homelab
EOF
    exit 0
fi

# ── Stratégie 2 : qemu-nbd + sudo mount ───────────────────────────────────────
echo "inject.sh : guestfish absent, utilisation de qemu-nbd (sudo requis)..." >&2

sudo modprobe nbd max_part=8 2>/dev/null || true

# Trouver un périphérique nbd libre.
nbd_dev=""
for d in /dev/nbd{0..15}; do
    [ -b "$d" ] || continue
    # Un device libre ne répond pas à nbd-client -s ; on tente une connexion
    # read-only légère pour vérifier qu'il est libre.
    if ! sudo qemu-nbd --read-only -c "$d" "$QCOW2" 2>/dev/null; then
        continue
    fi
    sudo qemu-nbd -d "$d" >/dev/null 2>&1 || true
    nbd_dev="$d"
    break
done
[ -n "$nbd_dev" ] || { echo "inject.sh : aucun périphérique nbd disponible" >&2; exit 1; }

# Connexion lecture-écriture.
sudo qemu-nbd --detect-zeroes=off -c "$nbd_dev" "$QCOW2"

tmpmnt=$(mktemp -d)
cleanup() {
    sudo umount "$tmpmnt"    2>/dev/null || true
    sudo qemu-nbd -d "$nbd_dev" 2>/dev/null || true
    rmdir "$tmpmnt"          2>/dev/null || true
    rm -f "$tmpfile"
}
trap cleanup EXIT

# Laisser le temps au kernel de détecter les partitions.
sleep 1

# OpenWrt x86-64 ext4-combined : rootfs sur la 2ème partition.
sudo mount "${nbd_dev}p2" "$tmpmnt"
sudo mkdir -p "$tmpmnt/etc/uci-defaults"
sudo install -m 755 "$tmpfile" "$tmpmnt/etc/uci-defaults/99-homelab"
