#!/bin/sh
# custos-sync — Synchronise la configuration depuis le dépôt central (pull-only).
# Lit les variables CUSTOS_CONFIG_REPO et CUSTOS_CONFIG_HOSTNAME depuis /etc/custos/sync.conf.

CONF=/etc/custos/sync.conf
[ -f "$CONF" ] && . "$CONF"

[ -z "$CUSTOS_CONFIG_REPO" ] && {
  echo "custos-sync: CUSTOS_CONFIG_REPO non configuré dans $CONF" >&2
  exit 1
}

HOSTNAME="${CUSTOS_CONFIG_HOSTNAME:-$(uname -n)}"
WORKDIR=/var/run/custos-sync
APPLY=/usr/share/custos/sync/apply.lua
OUTPUT=/etc/custos/config.moon
LUA_PATH_CUSTOS="/usr/share/custos/?.lua;/usr/share/custos/?/init.lua;;"

mkdir -p "$WORKDIR"

# Télécharger l'archive du dépôt (tarball main)
ARCHIVE="$WORKDIR/configs.tar.gz"
if ! wget -q -O "$ARCHIVE" "$CUSTOS_CONFIG_REPO/archive/main.tar.gz"; then
  echo "custos-sync: échec téléchargement $CUSTOS_CONFIG_REPO/archive/main.tar.gz" >&2
  exit 1
fi

# Extraire dans un répertoire temporaire
rm -rf "$WORKDIR/repo"
mkdir -p "$WORKDIR/repo"
if ! tar -xzf "$ARCHIVE" -C "$WORKDIR/repo" --strip-components=1; then
  echo "custos-sync: échec extraction de l'archive" >&2
  exit 1
fi

BASE="$WORKDIR/repo/base/config.moon"
[ -f "$BASE" ] || {
  echo "custos-sync: base/config.moon introuvable dans l'archive" >&2
  exit 1
}

# Appliquer (merge base + device) avec rechargement si changement
LUA_PATH="$LUA_PATH_CUSTOS" luajit "$APPLY" \
  --base     "$BASE" \
  --hostname "$HOSTNAME" \
  --output   "$OUTPUT" \
  --reload   || exit 1
