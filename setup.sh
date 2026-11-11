#!/usr/bin/env bash
# setup.sh — Configure l'environnement système pour dns-filter.
# Usage : sudo ./setup.sh [up|down|status]
#
# Prérequis vérifiés automatiquement :
#   - nft disponible
#   - libnetfilter-queue et libnftables présents
#   - LuaJIT + moonc disponibles

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[-]${NC} $*"; }

require_root() {
  [ "$(id -u)" = "0" ] || { fail "Ce script doit être lancé en root."; exit 1; }
}

# ── Vérification des dépendances ─────────────────────────────────
check_deps() {
  local errors=0

  echo "Vérification des dépendances..."

  # nft
  if command -v nft &>/dev/null; then
    ok "nft $(nft --version 2>&1 | head -1)"
  else
    fail "nft introuvable — installer nftables"
    errors=$((errors+1))
  fi

  # LuaJIT
  if command -v luajit &>/dev/null; then
    ok "luajit $(luajit -v 2>&1 | head -1)"
  else
    fail "luajit introuvable"
    errors=$((errors+1))
  fi

  # moonc
  if command -v moonc &>/dev/null; then
    ok "moonc $(moonc -v 2>&1 | head -1)"
  else
    fail "moonc introuvable — installer moonscript (luarocks install moonscript)"
    errors=$((errors+1))
  fi

  # Une seule capture de `ldconfig -p` : sous `set -o pipefail`, un
  # `ldconfig -p | grep -q` peut renvoyer 141 (SIGPIPE) quand grep sort tôt,
  # ce qui faisait échouer la détection à tort. On teste ensuite en shell pur.
  local libs
  libs=$(ldconfig -p 2>/dev/null || true)

  # libnetfilter_queue
  case "$libs" in
    *libnetfilter_queue*) ok "libnetfilter_queue trouvée" ;;
    *) fail "libnetfilter_queue introuvable — installer libnetfilter-queue1"; errors=$((errors+1)) ;;
  esac

  # libnftables
  case "$libs" in
    *libnftables*) ok "libnftables trouvée" ;;
    *) fail "libnftables introuvable — installer libnftables1"; errors=$((errors+1)) ;;
  esac

  # libwolfssl (TLS du serveur d'authentification, via FFI ffi_wolfssl)
  case "$libs" in
    *libwolfssl*) ok "libwolfssl trouvée" ;;
    *) fail "libwolfssl introuvable — installer libwolfssl (OpenWrt) / libwolfssl-dev (Debian)"; errors=$((errors+1)) ;;
  esac

  # libxxhash (hash xxHash via FFI, format .bin)
  case "$libs" in
    *libxxhash*) ok "libxxhash trouvée" ;;
    *) fail "libxxhash introuvable — installer libxxhash (OpenWrt) / libxxhash-dev (Debian)"; errors=$((errors+1)) ;;
  esac

  [ $errors -eq 0 ] || { fail "$errors dépendance(s) manquante(s)"; exit 1; }
}

# ── up ────────────────────────────────────────────────────────────
# `nft-rules/dns-filter-bridge.nft` est un GABARIT à placeholders
# ({QUEUE_*}, {NFT_IP_TIMEOUT}, {DOH_PORT}, {COMPILED_FILTER_*}, …) : il ne
# peut pas être chargé tel quel par `nft -f`. Les règles sont rendues et
# appliquées par le service au démarrage (`src/nft_rules.moon`,
# `nft_rules.apply`). `setup.sh up` se limite donc à vérifier l'environnement.
rules_up() {
  require_root
  check_deps

  echo ""
  echo "Règles nft : le gabarit nft-rules/dns-filter-bridge.nft contient des"
  echo "placeholders et est rendu par le service. Elles sont appliquées"
  echo "automatiquement au démarrage (nft_rules.apply)."
  echo ""
  echo "Lancer le filtre avec : sudo make run"
  echo "Ou directement       : sudo luajit lua/main.lua"
}

# ── down ──────────────────────────────────────────────────────────
rules_down() {
  require_root
  nft delete table bridge dns-filter-bridge 2>/dev/null \
    && ok "Table bridge dns-filter-bridge supprimée" \
    || warn "Table bridge dns-filter-bridge absente"
}

# ── status ────────────────────────────────────────────────────────
show_status() {
  echo "=== Table bridge dns-filter-bridge ==="
  nft list table bridge dns-filter-bridge 2>/dev/null || echo "(absente)"

  echo ""
  echo "=== Processus custos ==="
  pgrep -a luajit 2>/dev/null | grep -i "main" || echo "(aucun)"

  echo ""
  echo "=== Dernières lignes de log ==="
  journalctl -u custos --no-pager -n 20 2>/dev/null || echo "(logs via stdout — utiliser journalctl -u custos)"
}

case "${1:-up}" in
  up)     rules_up   ;;
  down)   rules_down ;;
  status) show_status ;;
  *)      echo "Usage: $0 [up|down|status]"; exit 1 ;;
esac
