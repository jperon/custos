#!/usr/bin/env bash
# setup.sh — Configure l'environnement système pour dns-filter.
# Usage : sudo ./setup.sh [up|down|status]
#
# Prérequis vérifiés automatiquement :
#   - br_netfilter chargé
#   - nft disponible
#   - libnetfilter-queue et libnftables présents
#   - LuaJIT + moonc disponibles

set -euo pipefail

NFT_RULES="$(dirname "$0")/nft-rules/dns-filter.nft"

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

  # libnetfilter_queue
  if ldconfig -p 2>/dev/null | grep -q libnetfilter_queue; then
    ok "libnetfilter_queue trouvée"
  else
    fail "libnetfilter_queue introuvable — installer libnetfilter-queue1"
    errors=$((errors+1))
  fi

  # libnftables
  if ldconfig -p 2>/dev/null | grep -q libnftables; then
    ok "libnftables trouvée"
  else
    fail "libnftables introuvable — installer libnftables1"
    errors=$((errors+1))
  fi

  # lyaml (lua-yaml sur Debian, lyaml sur OpenWrt)
  if luajit -e "require 'lyaml'" &>/dev/null; then
    ok "lyaml disponible"
  else
    fail "lyaml introuvable — installer lua-yaml (Debian) ou lyaml (OpenWrt)"
    errors=$((errors+1))
  fi

  [ $errors -eq 0 ] || { fail "$errors dépendance(s) manquante(s)"; exit 1; }
}

# ── br_netfilter ─────────────────────────────────────────────────
enable_br_netfilter() {
  modprobe br_netfilter 2>/dev/null || true

  if [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null)" != "1" ]; then
    sysctl -qw net.bridge.bridge-nf-call-iptables=1
    sysctl -qw net.bridge.bridge-nf-call-ip6tables=1
    ok "br_netfilter activé"
  else
    ok "br_netfilter déjà actif"
  fi
}

# ── Application des règles nft ────────────────────────────────────
apply_nft_rules() {
  nft -f "$NFT_RULES"
  ok "Règles nft appliquées"
}

# ── up ────────────────────────────────────────────────────────────
rules_up() {
  require_root
  check_deps
  enable_br_netfilter
  apply_nft_rules

  echo ""
  echo "Tables actives :"
  nft list tables
  echo ""
  echo "Lancer le filtre avec : sudo make run"
  echo "Ou directement       : sudo luajit lua/main.lua"
}

# ── down ──────────────────────────────────────────────────────────
rules_down() {
  require_root
  nft delete table ip  dns-filter 2>/dev/null && ok "Table ip  dns-filter supprimée" || warn "Table ip  dns-filter absente"
  nft delete table ip6 dns-filter 2>/dev/null && ok "Table ip6 dns-filter supprimée" || warn "Table ip6 dns-filter absente"
}

# ── status ────────────────────────────────────────────────────────
show_status() {
  echo "=== Tables nft ==="
  nft list tables 2>/dev/null || echo "(aucune)"

  echo ""
  echo "=== Sets ip4_allowed ==="
  nft list set ip dns-filter ip4_allowed 2>/dev/null || echo "(absent)"

  echo ""
  echo "=== Sets ip6_allowed ==="
  nft list set ip6 dns-filter ip6_allowed 2>/dev/null || echo "(absent)"

  echo ""
  echo "=== Processus dns-filter ==="
  pgrep -a luajit 2>/dev/null | grep -i "main\|dns" || echo "(aucun)"

  echo ""
  echo "=== Dernières lignes de log ==="
  tail -20 /tmp/dns-filter.log 2>/dev/null || echo "(pas de log)"
}

case "${1:-up}" in
  up)     rules_up   ;;
  down)   rules_down ;;
  status) show_status ;;
  *)      echo "Usage: $0 [up|down|status]"; exit 1 ;;
esac
