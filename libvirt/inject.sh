#!/usr/bin/env bash
# inject.sh — copie un script uci-defaults dans une image OpenWrt qcow2
# via guestfish (libguestfs, pure userspace : pas de sudo+losetup).
#
# Usage : inject.sh <qcow2> <uci-defaults-script> <ssh-pubkey>
#
# Le placeholder __SSH_PUBKEY__ dans le script est remplacé par la clé fournie.

set -e

QCOW2="${1:?qcow2 path required}"
SCRIPT="${2:?uci-defaults script required}"
PUBKEY="${3:?ssh pubkey required}"

[ -f "$QCOW2" ]  || { echo "image absente : $QCOW2" >&2; exit 1; }
[ -f "$SCRIPT" ] || { echo "script absent : $SCRIPT" >&2; exit 1; }

# Prépare le script avec la clé SSH substituée.
tmpfile=$(mktemp)
trap "rm -f $tmpfile" EXIT
awk -v key="$PUBKEY" '{gsub(/__SSH_PUBKEY__/, key); print}' "$SCRIPT" > "$tmpfile"

# guestfish : monte la partition rootfs OpenWrt et y dépose le script.
# OpenWrt x86-64 generic ext4 a le rootfs en /dev/sda2 (ou /dev/sda) selon
# le layout ; --inspector délègue cette détection à libguestfs.
guestfish --rw -a "$QCOW2" -i <<EOF
mkdir-p /etc/uci-defaults
upload $tmpfile /etc/uci-defaults/99-homelab
chmod 0755 /etc/uci-defaults/99-homelab
EOF
