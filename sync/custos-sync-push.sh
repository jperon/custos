#!/bin/sh
# custos-sync-push — Publie la config locale vers le dépôt central.
# Réservé aux filtres de référence (nécessite git installé sur le device).
# Lit les variables depuis /etc/custos/sync.conf.

CONF=/etc/custos/sync.conf
[ -f "$CONF" ] && . "$CONF"

[ -z "$CUSTOS_CONFIG_REPO" ] && {
  echo "custos-sync-push: CUSTOS_CONFIG_REPO non configuré dans $CONF" >&2
  exit 1
}

HOSTNAME="${CUSTOS_CONFIG_HOSTNAME:-$(uname -n)}"
REPO_DIR="${CUSTOS_CONFIG_REPO_DIR:-/etc/custos/configs-repo}"
LOCAL_CONFIG=/etc/custos/config.moon
LUA_PATH_CUSTOS="/usr/share/custos/?.lua;/usr/share/custos/?/init.lua;;"

# Initialiser le clone si nécessaire
if [ ! -d "$REPO_DIR/.git" ]; then
  git clone "$CUSTOS_CONFIG_REPO" "$REPO_DIR" || {
    echo "custos-sync-push: git clone échoué" >&2
    exit 1
  }
fi

cd "$REPO_DIR" || exit 1

# Récupérer les dernières modifications (fast-forward uniquement)
git pull --ff-only origin main || {
  echo "custos-sync-push: git pull échoué (conflits à résoudre manuellement ?)" >&2
  exit 1
}

# Appliquer la base + config dépôt sur ce device si une base existe
BASE="$REPO_DIR/base/config.moon"
if [ -f "$BASE" ]; then
  LUA_PATH="$LUA_PATH_CUSTOS" luajit /usr/share/custos/sync/apply.lua \
    --base "$BASE" --hostname "$HOSTNAME" --output "$LOCAL_CONFIG" --reload || {
    echo "custos-sync-push: application de la config échouée" >&2
    exit 1
  }
fi

# Publier la config locale vers devices/<hostname>/
mkdir -p "$REPO_DIR/devices/$HOSTNAME"
cp "$LOCAL_CONFIG" "$REPO_DIR/devices/$HOSTNAME/config.moon"

git add "devices/$HOSTNAME/config.moon"

if git diff --cached --quiet; then
  echo "custos-sync-push: aucun changement à publier"
  exit 0
fi

git commit -m "sync: $HOSTNAME $(date -Iseconds)" || {
  echo "custos-sync-push: git commit échoué" >&2
  exit 1
}

git push origin main && echo "custos-sync-push: config publiée" || {
  echo "custos-sync-push: git push échoué" >&2
  exit 1
}
