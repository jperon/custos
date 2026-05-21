#!/usr/bin/env bash
# tests/e2e/homelab_e2e.sh — suite de tests E2E pour CustosVirginum
#
# Appelé par homelab.sh test-e2e après déploiement de homelab-e2e.moon.
# Variables d'environnement fournies par homelab.sh :
#   SSH_OPTS, SSH_KEY
#   E2E_IP_CUSTOS, E2E_IP_SERVUS, E2E_IP_CLIENS, E2E_IP_VIA
#
# Dépendances sur les VMs : bind-dig (dig) installé par homelab.sh sur servus+cliens.

set -euo pipefail

# ─── Compteurs ────────────────────────────────────────────────────────────────
PASS=0; FAIL=0

ok() {
    printf "  ok  %s\n" "$1"
    PASS=$((PASS + 1))
}

fail() {
    printf "FAIL  %s — %s\n" "$1" "${2:-}"
    FAIL=$((FAIL + 1))
}

assert_contains() {
    local label="$1" pattern="$2" output="$3"
    if echo "$output" | grep -qE "$pattern"; then
        ok "$label"
    else
        fail "$label" "pattern /$pattern/ absent"
    fi
}

assert_not_contains() {
    local label="$1" pattern="$2" output="$3"
    if echo "$output" | grep -qE "$pattern"; then
        fail "$label" "pattern /$pattern/ présent (inattendu)"
    else
        ok "$label"
    fi
}

assert_eq() {
    local label="$1" got="$2" expected="$3"
    if [ "$got" = "$expected" ]; then
        ok "$label"
    else
        fail "$label" "got=$got expected=$expected"
    fi
}

# ─── Helpers SSH ──────────────────────────────────────────────────────────────
ssh_vm() {
    local ip="$1"; shift
    ssh -n $SSH_OPTS -i "$SSH_KEY" "root@$ip" "$@" 2>/dev/null || true
}

# dig via SSH : retourne le texte complet de la réponse DNS.
# Usage : dig_from <vm_ip> <domaine> [type] [options...]
dig_from() {
    local vm="$1" domain="$2"; shift 2
    local rtype="${1:-A}"; [ $# -gt 0 ] && shift
    ssh_vm "$vm" "dig +timeout=3 +tries=1 $* $domain $rtype 2>/dev/null"
}

# nslookup simple (pour vérifier NOERROR/REFUSED sans bind-dig).
nslookup_from() {
    local vm="$1" domain="$2"
    ssh_vm "$vm" "nslookup $domain 2>/dev/null"
}

# Retourne le code de statut DNS (NOERROR, REFUSED, NXDOMAIN…).
dns_status() {
    echo "$1" | grep -oE 'status: [A-Z]+' | awk '{print $2}'
}

# Retourne le TTL de la première réponse A/AAAA.
dns_ttl() {
    echo "$1" | grep -vE '^;' | awk 'NF>=4 && ($4=="A" || $4=="AAAA") {print $2; exit}'
}

# Vérifie si un set nftables contient une valeur.
nft_set_contains() {
    local set_name="$1" value="$2"
    ssh_vm "$E2E_IP_CUSTOS" \
        "nft list set bridge dns-filter-bridge $set_name 2>/dev/null" \
        | grep -qF "$value"
}

# Récupère les 80 dernières lignes de log pertinentes sur custos.
custos_logs() {
    ssh_vm "$E2E_IP_CUSTOS" "logread 2>/dev/null" | grep -iE 'custos|rule_id|action=' | tail -80
}

# Curl vers le serveur auth de custos (IP mgmt, port 33443).
curl_auth() {
    local path="${1:-/auth}"; shift 2>/dev/null || true
    curl -sk --max-time 5 "$@" "https://$E2E_IP_CUSTOS:33443$path" 2>/dev/null || true
}

# ─── Vider les sets nft + logs avant les tests ────────────────────────────────
flush_state() {
    ssh_vm "$E2E_IP_CUSTOS" \
        "nft flush set bridge dns-filter-bridge ip4_allowed 2>/dev/null;
         nft flush set bridge dns-filter-bridge ip6_allowed 2>/dev/null;
         logread -f 2>/dev/null &" || true
    sleep 1
}

# ─── GROUPE 0 : infra de base ─────────────────────────────────────────────────
echo ""
echo "=== Groupe 0 : infra de base ==="

out=$(nslookup_from "$E2E_IP_SERVUS" "via.lan")
assert_contains "T00a servus obtient IP DHCP (10.42.)" "10\.42\." \
    "$(ssh_vm "$E2E_IP_SERVUS" 'ip -4 -o addr show eth0 2>/dev/null')"

out=$(nslookup_from "$E2E_IP_CLIENS" "via.lan")
assert_contains "T00b cliens obtient IP DHCP (10.43.)" "10\.43\." \
    "$(ssh_vm "$E2E_IP_CLIENS" 'ip -4 -o addr show eth0 2>/dev/null')"

# ─── GROUPE 1 : DNS autorisé depuis homelab (servus) ─────────────────────────
echo ""
echo "=== Groupe 1 : DNS autorisé depuis homelab ==="
flush_state

resp=$(dig_from "$E2E_IP_SERVUS" "site-a.lan" "A")
assert_eq    "T01 site-a.lan → NOERROR"      "$(dns_status "$resp")" "NOERROR"
assert_contains "T01 site-a.lan → IP 10.42.0.50" "10\.42\.0\.50" "$resp"

resp=$(dig_from "$E2E_IP_SERVUS" "via.lan" "A")
assert_eq    "T02 via.lan → NOERROR"         "$(dns_status "$resp")" "NOERROR"

# TTL patché par custos (ttl_grace.min=30)
ttl=$(dns_ttl "$resp")
assert_eq    "T03 TTL patché → 30s"          "$ttl" "30"

# TTL direct sur via (non patché) = valeur dnsmasq native (généralement 0 ou 3600)
resp_direct=$(ssh_vm "$E2E_IP_SERVUS" "dig +timeout=3 +tries=1 via.lan A @10.42.0.1 2>/dev/null")
ttl_direct=$(dns_ttl "$resp_direct")
if [ "$ttl_direct" != "30" ]; then
    ok "T04 TTL direct sur via ≠ 30s (non patché)"
else
    fail "T04 TTL direct sur via ≠ 30s (non patché)" "got=30 (même valeur)"
fi

# ip4_allowed doit contenir 10.42.0.50 après allow
sleep 1
if nft_set_contains "ip4_allowed" "10.42.0.50"; then
    ok "T05 ip4_allowed contient 10.42.0.50"
else
    fail "T05 ip4_allowed contient 10.42.0.50" "entrée absente du set"
fi

# ─── GROUPE 2 : DNS bloqué depuis homelab ─────────────────────────────────────
echo ""
echo "=== Groupe 2 : DNS bloqué depuis homelab ==="

resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A")
assert_eq "T06 blocked.lan → REFUSED"       "$(dns_status "$resp")" "REFUSED"
assert_contains "T07 blocked.lan → EDE 15"  "EDE.*15|15.*Filtered" "$resp"

resp=$(dig_from "$E2E_IP_SERVUS" "unknown.example.com" "A")
assert_eq "T08 domaine inconnu → REFUSED"   "$(dns_status "$resp")" "REFUSED"

# ─── GROUPE 3 : condition `not` ───────────────────────────────────────────────
echo ""
echo "=== Groupe 3 : condition \`not\` (homelab_not_blocked) ==="
flush_state

# site-a.lan depuis servus : R3 matche (NOT blocked.lan + homelab)
resp=$(dig_from "$E2E_IP_SERVUS" "site-a.lan" "A")
assert_eq "T09 not : site-a.lan → allow" "$(dns_status "$resp")" "NOERROR"

# blocked.lan depuis servus : R3 ne matche pas → R5 default_deny
resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A")
assert_eq "T10 not : blocked.lan → deny" "$(dns_status "$resp")" "REFUSED"

logs=$(custos_logs)
assert_contains "T10b log homelab_not_blocked" "homelab_not_blocked" "$logs"

# ─── GROUPE 4 : sous-réseau ext / cliens ──────────────────────────────────────
echo ""
echo "=== Groupe 4 : sous-réseau ext (cliens, from_net 10.43.0.0/24) ==="
flush_state

# cliens → dnsonly : DNS résout, mais IP non mise dans le set
resp=$(dig_from "$E2E_IP_CLIENS" "site-a.lan" "A")
assert_eq "T11 cliens site-a.lan → NOERROR (dnsonly)" "$(dns_status "$resp")" "NOERROR"

resp=$(dig_from "$E2E_IP_CLIENS" "blocked.lan" "A")
assert_eq "T12 cliens blocked.lan → NOERROR (dnsonly)" "$(dns_status "$resp")" "NOERROR"

sleep 1
cliens_ip=$(ssh_vm "$E2E_IP_CLIENS" 'ip -4 -o addr show eth0 2>/dev/null' \
    | grep -oE '10\.43\.[0-9]+\.[0-9]+' | head -1)
if [ -n "$cliens_ip" ] && nft_set_contains "ip4_allowed" "$cliens_ip"; then
    fail "T13 ip4_allowed ne contient pas l'IP cliens (dnsonly)" "IP $cliens_ip présente"
else
    ok "T13 ip4_allowed ne contient pas l'IP cliens (dnsonly)"
fi

logs=$(custos_logs)
assert_contains "T14 log ext_dnsonly" "ext_dnsonly" "$logs"

# ─── GROUPE 5 : VLAN 10 (servus avec eth0.10) ────────────────────────────────
echo ""
echo "=== Groupe 5 : VLAN 10 ==="

# Setup
ssh_vm "$E2E_IP_SERVUS" \
    'ip link add link eth0 name eth0.10 type vlan id 10 2>/dev/null || true
     ip addr add 10.42.10.5/24 dev eth0.10 2>/dev/null || true
     ip link set eth0.10 up 2>/dev/null || true'
sleep 1

resp=$(ssh_vm "$E2E_IP_SERVUS" \
    "dig +timeout=3 +tries=1 -b 10.42.10.5 site-a.lan A 2>/dev/null")
# R1 (vlan10_dnsonly) → NOERROR mais DNS only
assert_eq "T15 VLAN 10 : site-a.lan → NOERROR (dnsonly)" \
    "$(dns_status "$resp")" "NOERROR"

logs=$(custos_logs)
assert_contains "T16 log vlan10_dnsonly" "vlan10_dnsonly" "$logs"

# Teardown
ssh_vm "$E2E_IP_SERVUS" 'ip link del eth0.10 2>/dev/null || true'

# ─── GROUPE 6 : sets nftables ─────────────────────────────────────────────────
echo ""
echo "=== Groupe 6 : sets nftables ==="

# ip4_allowed contient 10.42.0.50 (résolution site-a.lan du groupe 1)
if nft_set_contains "ip4_allowed" "10.42.0.50"; then
    ok "T17 ip4_allowed contient 10.42.0.50 (allow persisté)"
else
    fail "T17 ip4_allowed contient 10.42.0.50 (allow persisté)" "entrée absente"
fi

# blocked.lan refusé → pas d'ajout dans ip4_allowed
if nft_set_contains "ip4_allowed" "10.42.0.52"; then
    fail "T19 blocked.lan refusé → ip4_allowed inchangé" "10.42.0.52 présent"
else
    ok "T19 blocked.lan refusé → ip4_allowed inchangé"
fi

# ─── GROUPE 7 : logs ─────────────────────────────────────────────────────────
echo ""
echo "=== Groupe 7 : logs ==="

logs=$(custos_logs)
assert_contains "T20 log rule=homelab_not_blocked action=allow" \
    "homelab_not_blocked" "$logs"
assert_contains "T21 log rule=default_deny action=deny"        \
    "default_deny"        "$logs"
assert_contains "T22 log rule=ext_dnsonly"                     \
    "ext_dnsonly"         "$logs"

# ─── GROUPE 8 : EDE ───────────────────────────────────────────────────────────
echo ""
echo "=== Groupe 8 : EDE (Extended DNS Errors) ==="

resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A" "+noall" "+comments" "+additional")
assert_contains "T23 blocked.lan → EDE code 15 (Filtered)" \
    "EDE.*15|EDE.*Filtered|15.*Filtered" "$resp"

resp=$(dig_from "$E2E_IP_SERVUS" "site-a.lan" "A" "+noall" "+comments" "+additional")
assert_not_contains "T24 site-a.lan → pas d'EDE 15" \
    "EDE.*15|15.*Filtered" "$resp"

# ─── GROUPE 9 : IPv6 ──────────────────────────────────────────────────────────
echo ""
echo "=== Groupe 9 : IPv6 (premier classe) ==="
flush_state

resp=$(dig_from "$E2E_IP_SERVUS" "site-a.lan" "AAAA")
assert_eq "T27 site-a.lan AAAA → NOERROR"       "$(dns_status "$resp")" "NOERROR"
assert_contains "T27b IP fd42:42:0:1::50 présente" "fd42:42:0:1::50" "$resp"

ttl6=$(dns_ttl "$resp")
assert_eq "T27c TTL IPv6 patché → 30s" "$ttl6" "30"

resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "AAAA")
assert_eq "T28 blocked.lan AAAA → REFUSED" "$(dns_status "$resp")" "REFUSED"
assert_contains "T28b EDE 15 sur AAAA"    "EDE.*15|15.*Filtered" "$resp"

sleep 1
if nft_set_contains "ip6_allowed" "fd42:42:0:1::50"; then
    ok "T29 ip6_allowed contient fd42:42:0:1::50"
else
    fail "T29 ip6_allowed contient fd42:42:0:1::50" "entrée absente du set"
fi

resp=$(dig_from "$E2E_IP_CLIENS" "site-a.lan" "AAAA")
assert_eq "T30 cliens AAAA dnsonly → NOERROR" "$(dns_status "$resp")" "NOERROR"

cliens_ip6=$(ssh_vm "$E2E_IP_CLIENS" 'ip -6 -o addr show eth0 2>/dev/null' \
    | grep -oE 'fd42:[^ /]+' | head -1)
if [ -n "$cliens_ip6" ] && nft_set_contains "ip6_allowed" "$cliens_ip6"; then
    fail "T30b ip6_allowed ne contient pas l'IPv6 cliens (dnsonly)" "IP $cliens_ip6 présente"
else
    ok "T30b ip6_allowed ne contient pas l'IPv6 cliens (dnsonly)"
fi

# Requête DNS via IPv6 (si servus a une adresse fd42:42:0:1:: SLAAC)
servus_ip6=$(ssh_vm "$E2E_IP_SERVUS" 'ip -6 -o addr show eth0 2>/dev/null' \
    | grep -oE 'fd42:[^ /]+' | head -1)
if [ -n "$servus_ip6" ]; then
    resp=$(ssh_vm "$E2E_IP_SERVUS" \
        "dig +timeout=3 +tries=1 -6 site-a.lan AAAA 2>/dev/null")
    assert_eq "T31 dig -6 site-a.lan → NOERROR" "$(dns_status "$resp")" "NOERROR"
else
    fail "T31 dig -6 site-a.lan → NOERROR" "servus sans adresse IPv6 fd42:: (SLAAC non reçu)"
fi

# ─── GROUPE 10 : portail captif / auth ────────────────────────────────────────
echo ""
echo "=== Groupe 10 : portail captif / auth ==="

resp_auth=$(curl_auth "/auth")
if [ -n "$resp_auth" ]; then
    ok "T32 GET /auth → réponse non vide (portail accessible)"
else
    fail "T32 GET /auth → réponse non vide" "réponse vide (service non démarré ?)"
fi

resp_reg=$(curl_auth "/register" \
    -X POST -d "user=bob&password=secret123" \
    -H "Content-Type: application/x-www-form-urlencoded")
if echo "$resp_reg" | grep -qiE '200|201|ok|success|created'; then
    ok "T33 POST /register → bob créé"
else
    fail "T33 POST /register → bob créé" "réponse : $(echo "$resp_reg" | head -1)"
fi

resp_login=$(curl_auth "/auth" \
    -X POST -d "user=alice&password=motdepasse123" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -c /tmp/custos_e2e_cookies.txt)
if echo "$resp_login" | grep -qiE '200|302|ok|success'; then
    ok "T34 POST /auth alice → session créée"
else
    fail "T34 POST /auth alice → session créée" "réponse : $(echo "$resp_login" | head -1)"
fi
rm -f /tmp/custos_e2e_cookies.txt

# ─── RAPPORT FINAL ─────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────────"
printf "Résultats : %d passed, %d failed\n" "$PASS" "$FAIL"
echo "─────────────────────────────────────────"
[ "$FAIL" -eq 0 ] || exit 1
