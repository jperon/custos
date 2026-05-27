#!/usr/bin/env bash
# test_first_request_after_auth.sh
# Reproduit le scénario : restart custos → auth → 1re requête → 2e requête → logs
#
# Prérequis :
#   - SSH sans mot de passe vers le routeur (root@ROUTER)
#   - curl avec support TLS
#   - Le client qui exécute ce script doit être sur le même réseau que custos
#
# Usage : ./test_first_request_after_auth.sh [DOMAIN]

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────
ROUTER="${CUSTOS_ROUTER:-root@10.35.1.254}"
AUTH_HOST="${CUSTOS_AUTH_HOST:-10.35.1.254}"
AUTH_PORT="${CUSTOS_AUTH_PORT:-33443}"
AUTH_USER="${CUSTOS_AUTH_USER:-j@prn.ovh}"
AUTH_PASS="${CUSTOS_AUTH_PASS:-patouche}"
TARGET_DOMAIN="${1:-lesalonbeige.fr}"
COOKIE_JAR="$(mktemp)"
LOGFILE="$(mktemp)"

cleanup() {
  rm -f "$COOKIE_JAR" "$LOGFILE" "$LIVE_LOG"
}
trap cleanup EXIT
LIVE_LOG=""

log() { printf '\033[1;36m[%s]\033[0m %s\n' "$(date +%H:%M:%S.%3N)" "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[ OK ]\033[0m %s\n' "$*"; }

# ── Étape 0 : marqueur temporel pour filtrer les logs ────────────────────
log "Marqueur temporel avant restart"
MARK_BEFORE=$(ssh "$ROUTER" "date +%s")

# ── Étape 1 : Redémarrage de custos ─────────────────────────────────────
log "Redémarrage de custos sur $ROUTER..."
ssh "$ROUTER" "/etc/init.d/custos restart 2>&1 || /usr/share/custos/custos.sh restart 2>&1 || true"
log "Attente de stabilisation (5s)..."
sleep 5

# Vérifier que custos tourne
if ! ssh "$ROUTER" "pgrep -f 'custos.*main' >/dev/null 2>&1"; then
  fail "custos ne semble pas tourner après restart"
  exit 1
fi
ok "custos redémarré"

# ── Étape 2 : Authentification ───────────────────────────────────────────
log "Authentification de $AUTH_USER sur https://$AUTH_HOST:$AUTH_PORT/login..."

HTTP_CODE=$(curl -sk -o /dev/null -w '%{http_code}' \
  --connect-timeout 10 \
  -c "$COOKIE_JAR" \
  -d "user=${AUTH_USER}&password=${AUTH_PASS}" \
  "https://${AUTH_HOST}:${AUTH_PORT}/login")

if [[ "$HTTP_CODE" == "302" || "$HTTP_CODE" == "200" ]]; then
  ok "Authentification réussie (HTTP $HTTP_CODE)"
else
  fail "Authentification échouée (HTTP $HTTP_CODE)"
  cat "$COOKIE_JAR"
  exit 1
fi

# Extraire le cookie de session
SESSION_COOKIE=$(grep -i "custos_session\|session" "$COOKIE_JAR" | tail -1 | awk '{print $NF}')
log "Cookie de session : ${SESSION_COOKIE:0:40}..."

# ── Étape 2b : Ping pour confirmer l'auth (comme Firefox) ────────────────
sleep 1
log "Ping auth pour confirmer la session..."
PING_CODE=$(curl -sk -o /dev/null -w '%{http_code}' \
  --connect-timeout 10 \
  -b "$COOKIE_JAR" \
  "https://${AUTH_HOST}:${AUTH_PORT}/ping")

if [[ "$PING_CODE" == "204" ]]; then
  ok "Ping auth réussi (204 No Content)"
else
  fail "Ping auth échoué (HTTP $PING_CODE)"
fi

# ── Étape 3 : Démarrer la capture de logs en arrière-plan ─────────────────
LIVE_LOG="$(mktemp)"
ssh "$ROUTER" "logread -f" > "$LIVE_LOG" 2>/dev/null &
LOG_PID=$!
sleep 0.5

# ── Étape 4 : Première requête HTTPS (reproduit le cas Firefox) ──────────
# Flush du cache DNS local pour forcer la résolution à traverser le bridge
resolvectl flush-caches 2>/dev/null || systemd-resolve --flush-caches 2>/dev/null || true

# Pas de résolution préalable : curl fait DNS + connect en une seule étape
# C'est exactement ce que fait Firefox (résolution → SYN immédiat)
log "1re requête vers https://$TARGET_DOMAIN/ (DNS + connect, comme Firefox)..."
T1_START=$(date +%s%3N)
HTTP1=$(curl -sk -o /dev/null -w '%{http_code} dns:%{time_namelookup} connect:%{time_connect} ttfb:%{time_starttransfer} total:%{time_total} ip:%{remote_ip}' \
  --connect-timeout 5 \
  --max-time 10 \
  "https://${TARGET_DOMAIN}/" 2>&1) || true
T1_END=$(date +%s%3N)
T1_MS=$((T1_END - T1_START))

if echo "$HTTP1" | grep -qE '^(200|301|302|303|304|307|308|403)'; then
  ok "1re requête : $HTTP1 (${T1_MS}ms)"
else
  fail "1re requête : $HTTP1 (${T1_MS}ms)"
fi

# ── Étape 5 : Deuxième requête (mêmes conditions, cache DNS frais) ───────
sleep 1
resolvectl flush-caches 2>/dev/null || true
log "2e requête vers https://$TARGET_DOMAIN/ (DNS + connect, cache flushé)..."
T2_START=$(date +%s%3N)
HTTP2=$(curl -sk -o /dev/null -w '%{http_code} dns:%{time_namelookup} connect:%{time_connect} ttfb:%{time_starttransfer} total:%{time_total} ip:%{remote_ip}' \
  --connect-timeout 5 \
  --max-time 10 \
  "https://${TARGET_DOMAIN}/" 2>&1) || true
T2_END=$(date +%s%3N)
T2_MS=$((T2_END - T2_START))

if echo "$HTTP2" | grep -qE '^(200|301|302|303|304|307|308|403)'; then
  ok "2e requête : $HTTP2 (${T2_MS}ms)"
else
  fail "2e requête : $HTTP2 (${T2_MS}ms)"
fi

# Stopper la capture de logs
kill $LOG_PID 2>/dev/null || true
wait $LOG_PID 2>/dev/null || true

# ── Étape 6 : Collecte des logs ─────────────────────────────────────────
log "Analyse des logs capturés en temps réel..."
grep "custos" "$LIVE_LOG" | \
  grep -E "ALLOW.*${TARGET_DOMAIN}|response.*qnames=.*${TARGET_DOMAIN}|reject.*10.35.99|reject.*2a11.*443|nft_batch|nft_ack_timeout|batch_ok|batch_ack" \
  > "$LOGFILE" 2>/dev/null || true

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  RÉSUMÉ"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  1re requête : $HTTP1 (${T1_MS}ms)  [DNS + connect, comme Firefox]"
echo "  2e requête  : $HTTP2 (${T2_MS}ms)  [DNS + connect, 1s après, cache flushé]"
echo ""
echo "────────────────────────────────────────────────────────────────"
echo "  Logs pertinents ($(wc -l < "$LOGFILE") lignes) :"
echo "────────────────────────────────────────────────────────────────"
cat "$LOGFILE"
echo ""
echo "════════════════════════════════════════════════════════════════"

# ── Diagnostic ───────────────────────────────────────────────────────────
if echo "$HTTP1" | grep -q '^000'; then
  echo ""
  echo "⚠  La 1re requête a échoué (status 0 = connexion TCP refusée/timeout)."
  echo "   Hypothèses :"
  echo "   - Race condition : le set nft n'est pas peuplé au moment du SYN/443"
  echo "   - Le wait_ack n'a pas fonctionné (timeout ou barrier manquante)"
  echo "   - Le client utilise une IP non couverte par le set"
  echo ""
  echo "   Vérification du set :"
  ssh "$ROUTER" "nft list set bridge dns-filter-bridge r_utilisateurs_ip4 2>/dev/null" | grep "$TARGET_DOMAIN" || \
    ssh "$ROUTER" "nft list set bridge dns-filter-bridge r_utilisateurs_ip4 2>/dev/null" | tail -5
fi
