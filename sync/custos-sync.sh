#!/bin/sh
# custos-sync — Synchronise la configuration depuis le dépôt central (pull-only).
# Lit les variables CUSTOS_CONFIG_REPO et CUSTOS_CONFIG_HOSTNAME depuis /etc/custos/sync.conf.

# CUSTOS_SYNC_CONF permet de surcharger le chemin en test (défaut inchangé).
CONF="${CUSTOS_SYNC_CONF:-/etc/custos/sync.conf}"
[ -f "$CONF" ] && . "$CONF"

[ -z "$CUSTOS_CONFIG_REPO" ] && {
  echo "custos-sync: CUSTOS_CONFIG_REPO non configuré dans $CONF" >&2
  exit 1
}

# L'archive devient /etc/custos/config.moon, chargée et exécutée en root :
# refuser tout transport non chiffré (une URL http:// permettrait une
# substitution de config par un tiers on-path).
case "$CUSTOS_CONFIG_REPO" in
  https://*) ;;
  *)
    echo "custos-sync: CUSTOS_CONFIG_REPO refusé (https:// requis) : $CUSTOS_CONFIG_REPO" >&2
    exit 1
    ;;
esac

HOSTNAME="${CUSTOS_CONFIG_HOSTNAME:-$(uname -n)}"
WORKDIR=/var/run/custos-sync
APPLY=/usr/share/custos/sync/apply.lua
OUTPUT=/etc/custos/config.moon
LUA_PATH_CUSTOS="/usr/share/custos/?.lua;/usr/share/custos/?/init.lua;;"

mkdir -p "$WORKDIR"

# Télécharger l'archive du dépôt (tarball main).
# curl est la dépendance du paquet : --fail (pas de corps d'erreur pris pour
# une archive), TLS contraint à https (aucune redirection vers http) et
# vérification des certificats par défaut (jamais --insecure). wget (busybox)
# n'est utilisé que si curl est absent de l'image.
ARCHIVE="$WORKDIR/configs.tar.gz"
URL="$CUSTOS_CONFIG_REPO/archive/main.tar.gz"
if command -v curl >/dev/null 2>&1; then
  if ! curl --fail --silent --show-error --location \
            --proto '=https' --proto-redir '=https' \
            --output "$ARCHIVE" "$URL"; then
    echo "custos-sync: échec téléchargement $URL" >&2
    exit 1
  fi
elif command -v wget >/dev/null 2>&1; then
  if ! wget -q -O "$ARCHIVE" "$URL"; then
    echo "custos-sync: échec téléchargement $URL" >&2
    exit 1
  fi
else
  echo "custos-sync: ni curl ni wget disponible pour télécharger $URL" >&2
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
