#!/bin/bash
# openwrt-inject.sh — Prépare l'image OpenWrt pour la VM filtre de test.
#
# Étapes :
#   1. Décompresse openwrt-*-ext4-combined-efi.img.gz → openwrt-base.img
#   2. Étend l'image à TARGET_SIZE (512 Mo) et resize la partition 2 (rootfs)
#   3. Monte la partition 2 via losetup, injecte :
#        - /etc/dropbear/authorized_keys   (clé publique de l'hôte)
#        - /etc/config/network             (br-lan + mgmt)
#        - /etc/uci-defaults/99-custos-test-env (désactive firewall, etc.)
#   4. Démonte et détache le loop device.
#
# Nécessite : sudo (losetup, mount, parted, resize2fs).
# Idempotent : si l'image est déjà préparée, tout est sauté.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMG_DIR="$(dirname "$SCRIPT_DIR")/images"

OPENWRT_VERSION="${OPENWRT_VERSION:-24.10.0}"
OPENWRT_URL="${OPENWRT_URL:-https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/x86/64/openwrt-${OPENWRT_VERSION}-x86-64-generic-ext4-combined-efi.img.gz}"
TARGET_SIZE_MB="${TARGET_SIZE_MB:-512}"
PUBKEY="${PUBKEY:-$HOME/.ssh/id_rsa.pub}"

BASE_IMG="$IMG_DIR/openwrt-base.img"
SENTINEL="$IMG_DIR/.openwrt-base-injected-v1"

log() { echo "[openwrt-inject] $*"; }
err() { echo "[openwrt-inject] ERROR: $*" >&2; exit 1; }

mkdir -p "$IMG_DIR"

if [ -f "$SENTINEL" ] && [ -f "$BASE_IMG" ]; then
    log "Image déjà préparée ($BASE_IMG) — rien à faire."
    exit 0
fi

[ -f "$PUBKEY" ] || err "Clé publique introuvable : $PUBKEY (set PUBKEY env var)"

# ── 1. Téléchargement ─────────────────────────────────────────────
if [ ! -f "$BASE_IMG.gz" ] && [ ! -f "$BASE_IMG" ]; then
    log "Téléchargement de l'image OpenWrt $OPENWRT_VERSION..."
    curl -L --fail -o "$BASE_IMG.gz" "$OPENWRT_URL" \
        || err "Téléchargement échoué : $OPENWRT_URL"
fi
if [ ! -f "$BASE_IMG" ]; then
    log "Décompression..."
    gunzip -k "$BASE_IMG.gz"
fi

# ── 2. Extension ──────────────────────────────────────────────────
CUR_SIZE=$(stat -c %s "$BASE_IMG")
TARGET_BYTES=$((TARGET_SIZE_MB * 1024 * 1024))
if [ "$CUR_SIZE" -lt "$TARGET_BYTES" ]; then
    log "Extension de l'image à ${TARGET_SIZE_MB} Mo..."
    truncate -s "${TARGET_SIZE_MB}M" "$BASE_IMG"
    log "Mise à jour de la table de partitions..."
    # Supprime la partition 2 et la recrée couvrant tout l'espace restant.
    START=$(sudo parted -s "$BASE_IMG" unit s print \
        | awk '/^ 2 / {gsub("s","",$2); print $2}')
    [ -n "$START" ] || err "Impossible de détecter le début de la partition 2"
    sudo parted -s "$BASE_IMG" rm 2
    sudo parted -s "$BASE_IMG" mkpart primary ext4 "${START}s" 100%
fi

# ── 3. Mount + inject ─────────────────────────────────────────────
LOOP=$(sudo losetup --find --partscan --show "$BASE_IMG")
trap "sudo losetup -d '$LOOP' 2>/dev/null || true" EXIT

# Laisser le temps à partprobe.
sleep 1

# Resize FS au cas où.
sudo resize2fs "${LOOP}p2" >/dev/null 2>&1 || true

MNT=$(mktemp -d)
sudo mount "${LOOP}p2" "$MNT"
trap "sudo umount '$MNT' 2>/dev/null; sudo losetup -d '$LOOP' 2>/dev/null; rmdir '$MNT' 2>/dev/null || true" EXIT

log "Injection de la clé SSH..."
sudo install -d -m 0700 "$MNT/etc/dropbear"
sudo install -m 0600 "$PUBKEY" "$MNT/etc/dropbear/authorized_keys"

log "Injection de /etc/config/network..."
sudo install -m 0644 "$SCRIPT_DIR/openwrt-network.config" "$MNT/etc/config/network"

log "Injection de /etc/uci-defaults/99-custos-test-env..."
sudo install -d -m 0755 "$MNT/etc/uci-defaults"
sudo install -m 0755 "$SCRIPT_DIR/openwrt-uci-defaults.sh" \
    "$MNT/etc/uci-defaults/99-custos-test-env"

sudo umount "$MNT"
rmdir "$MNT"
sudo losetup -d "$LOOP"
trap - EXIT

touch "$SENTINEL"
log "Image prête : $BASE_IMG"
