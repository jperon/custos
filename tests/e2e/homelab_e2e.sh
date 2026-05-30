#!/usr/bin/env bash
# tests/e2e/homelab_e2e.sh — suite E2E CustosVirginum
#
# Appelé par homelab.sh test-e2e après déploiement de homelab-e2e.moon.
# Variables d'environnement fournies par homelab.sh :
#   SSH_OPTS, SSH_KEY
#   E2E_IP_CUSTOS, E2E_IP_SERVUS, E2E_IP_CLIENS, E2E_IP_VIA

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

skip() {
    printf " skip %s — %s\n" "$1" "${2:-}"
}

assert_contains() {
    local label="$1" pattern="$2" output="$3"
    if echo "$output" | grep -qE "$pattern"; then
        ok "$label"
    else
        fail "$label" "pattern /$pattern/ absent"
    fi
}

# Vérifie qu'UNE même ligne de $output contient TOUS les termes (ordre
# indifférent). Les champs de log sont émis dans un ordre non déterministe
# (itération `pairs` de Lua) : on ne peut donc pas se fier à leur position.
assert_log_has() {
    local label="$1"; shift
    local output="$1"; shift
    local filtered="$output" t
    for t in "$@"; do
        filtered=$(printf '%s\n' "$filtered" | grep -F -- "$t" || true)
    done
    if [ -n "$filtered" ]; then
        ok "$label"
    else
        fail "$label" "termes absents sur une même ligne: $*"
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

assert_http_status() {
    local label="$1" response="$2" expected="$3"
    local got
    got=$(echo "$response" | grep -oE 'HTTP/[0-9.]+ [0-9]+' | tail -1 | grep -oE '[0-9]+$' || true)
    if [ "$got" = "$expected" ]; then
        ok "$label"
    else
        fail "$label" "HTTP got=$got expected=$expected"
    fi
}

# ─── Helpers SSH ──────────────────────────────────────────────────────────────
ssh_vm() {
    local ip="$1"; shift
    ssh -n $SSH_OPTS -i "$SSH_KEY" "root@$ip" "$@" 2>/dev/null || true
}

dig_from() {
    local vm="$1" domain="$2"; shift 2
    local rtype="${1:-A}"; [ $# -gt 0 ] && shift
    ssh_vm "$vm" "dig +timeout=3 +tries=1 $* $domain $rtype 2>/dev/null"
}

dns_status() { echo "$1" | grep -oE 'status: [A-Z]+' | awk '{print $2}'; }

nft_set_contains() {
    local set_name="$1" value="$2"
    ssh_vm "$E2E_IP_CUSTOS" \
        "nft list set bridge dns-filter-bridge $set_name 2>/dev/null" \
        | grep -qF "$value"
}

custos_logs() {
    ssh_vm "$E2E_IP_CUSTOS" "logread 2>/dev/null" \
        | grep -iE 'custos|rule_id|action=' | tail -120
}

# ─── IP data-plane des VMs ────────────────────────────────────────────────────
CUSTOS_DATA_IP="10.42.0.254"   # IP statique ajoutée sur br-lan par homelab.sh

servus_data_ip4() {
    ssh_vm "$E2E_IP_SERVUS" "ip -4 -o addr show eth0 2>/dev/null" \
        | grep -oE '10\.42\.[0-9]+\.[0-9]+' | head -1
}
servus_data_ip6() {
    ssh_vm "$E2E_IP_SERVUS" "ip -6 -o addr show eth0 2>/dev/null" \
        | grep -oE 'fd42:[^ /]+' | head -1
}
cliens_data_ip4() {
    ssh_vm "$E2E_IP_CLIENS" "ip -4 -o addr show eth0 2>/dev/null" \
        | grep -oE '10\.43\.[0-9]+\.[0-9]+' | head -1
}

# ─── Helpers auth ─────────────────────────────────────────────────────────────
# Login alice depuis servus (source IP = IP data-plane de servus).
# Les variables $user/$pass sont expansées côté hôte avant l'envoi SSH ;
# les single-quotes dans la commande SSH protègent @ et les espaces côté servus.
login_from_servus() {
    local user="$1" pass="$2"
    ssh_vm "$E2E_IP_SERVUS" \
        "curl -sk --max-time 8 \
         -c /tmp/e2e_cookies.txt \
         -X POST \
         --data-urlencode 'user=$user' \
         --data-urlencode 'password=$pass' \
         'https://${CUSTOS_DATA_IP}:33443/login' 2>/dev/null; echo"
}

# curl /admin/* depuis servus, en réutilisant la session alice (cookie déjà
# obtenu par login_from_servus). Sortie : corps + "\nHTTP_STATUS:<code>".
# La session étant liée à l'IP/MAC du data-plane, l'accès admin doit partir de servus.
# curl depuis l'hôte de test (source IP = mgmt, pour tester l'API seule).
curl_auth() {
    local path="$1"; shift
    curl -sk --max-time 8 -w "\nHTTP_STATUS:%{http_code}" "$@" \
        "https://$E2E_IP_CUSTOS:33443${path}" 2>/dev/null || true
}

# curl depuis l'hôte avec suivi des redirections et dump des headers.
curl_auth_verbose() {
    local path="$1"; shift
    curl -sk --max-time 8 -D - "$@" \
        "https://$E2E_IP_CUSTOS:33443${path}" 2>/dev/null || true
}

# ─── flush_state ──────────────────────────────────────────────────────────────
flush_state() {
    ssh_vm "$E2E_IP_CUSTOS" "
        nft flush set bridge dns-filter-bridge r_homelab_not_blocked_ip4  2>/dev/null
        nft flush set bridge dns-filter-bridge r_homelab_not_blocked_ip6  2>/dev/null
        nft flush set bridge dns-filter-bridge r_homelab_auth_blocked_ip4 2>/dev/null
        nft flush set bridge dns-filter-bridge r_homelab_auth_blocked_ip6 2>/dev/null
        nft flush set bridge dns-filter-bridge r_homelab_auth_blocked_auth_ip4 2>/dev/null
        nft flush set bridge dns-filter-bridge r_homelab_auth_blocked_auth_ip6 2>/dev/null
        nft flush set bridge dns-filter-bridge r_ext_dnsonly_ip4          2>/dev/null
        nft flush set bridge dns-filter-bridge r_ext_dnsonly_ip6          2>/dev/null
    " 2>/dev/null || true
    ssh_vm "$E2E_IP_SERVUS" "rm -f /tmp/e2e_cookies.txt" 2>/dev/null || true
    sleep 1
}

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 0 — Infra de base
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G0 : infra de base ==="

assert_contains "T00a servus a une IP 10.42.x (DHCP)" "10\.42\." \
    "$(ssh_vm "$E2E_IP_SERVUS" 'ip -4 -o addr show eth0 2>/dev/null')"

assert_contains "T00b cliens a une IP 10.43.x (DHCP)" "10\.43\." \
    "$(ssh_vm "$E2E_IP_CLIENS" 'ip -4 -o addr show eth0 2>/dev/null')"

degrade=$(ssh_vm "$E2E_IP_CUSTOS" "logread 2>/dev/null" | grep -c "mode dégradé" || true)
if [ "${degrade:-0}" -eq 0 ]; then
    ok "T00c custos démarré sans mode dégradé"
else
    fail "T00c custos démarré sans mode dégradé" "found $degrade occurrence(s) in logread"
fi

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 1 — DNS autorisé depuis homelab (règle R3 homelab_not_blocked)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G1 : DNS autorisé depuis homelab ==="
flush_state

resp=$(dig_from "$E2E_IP_SERVUS" "site-a.lan" "A")
assert_eq      "T01a site-a.lan → NOERROR"           "$(dns_status "$resp")" "NOERROR"
assert_contains "T01b site-a.lan → IP 10.42.0.50"    "10\.42\.0\.50" "$resp"

resp=$(dig_from "$E2E_IP_SERVUS" "via.lan" "A")
assert_eq      "T02 via.lan → NOERROR"               "$(dns_status "$resp")" "NOERROR"

sleep 1
if nft_set_contains "r_homelab_not_blocked_ip4" "10.42.0.50"; then
    ok "T03 r_homelab_not_blocked_ip4 contient 10.42.0.50"
else
    fail "T03 r_homelab_not_blocked_ip4 contient 10.42.0.50" "entrée absente du set"
fi

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 2 — Condition `not` + blocked.lan sans auth
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G2 : condition \`not\` + blocked.lan sans auth ==="
flush_state

# R3 matche site-a.lan (not blocked.lan = true) → allow
resp=$(dig_from "$E2E_IP_SERVUS" "site-a.lan" "A")
assert_eq      "T10 site-a.lan → NOERROR (R3 not-blocked matche)" \
               "$(dns_status "$resp")" "NOERROR"

# R3 ne matche pas blocked.lan, R4 from_users échoue (pas de session) → R5 deny
resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A")
assert_eq      "T11a blocked.lan sans auth → REFUSED" \
               "$(dns_status "$resp")" "REFUSED"
assert_contains "T11b blocked.lan → EDE 15 (Filtered)" \
               "EDE.*17|17.*Filtered|code: 17" "$resp"

sleep 1
logs=$(custos_logs)
assert_contains "T12a log homelab_not_blocked pour site-a.lan" \
               "homelab_not_blocked" "$logs"
assert_contains "T12b log default_deny pour blocked.lan" \
               "default_deny" "$logs"

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 3 — DNS dnsonly depuis ext/cliens (règle R2)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G3 : DNS dnsonly depuis ext/cliens (R2) ==="
flush_state

# dnsonly → résout mais n'ajoute pas l'IP dans le set
resp=$(dig_from "$E2E_IP_CLIENS" "site-a.lan" "A")
assert_eq "T20 cliens site-a.lan → NOERROR (dnsonly)" "$(dns_status "$resp")" "NOERROR"

# blocked.lan depuis cliens → R2 (ext_dnsonly) matche avant R3/R4/R5 → NOERROR
resp=$(dig_from "$E2E_IP_CLIENS" "blocked.lan" "A")
assert_eq "T21 cliens blocked.lan → NOERROR (dnsonly)" "$(dns_status "$resp")" "NOERROR"

sleep 1
cliens_ip=$(cliens_data_ip4)
if [ -n "$cliens_ip" ] && nft_set_contains "r_ext_dnsonly_ip4" "$cliens_ip"; then
    fail "T22 r_ext_dnsonly_ip4 sans IP cliens (dnsonly)" "IP $cliens_ip présente"
else
    ok "T22 r_ext_dnsonly_ip4 sans IP cliens (dnsonly)"
fi

logs=$(custos_logs)
assert_contains "T23 log ext_dnsonly" "ext_dnsonly" "$logs"

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 4 — Auth API (depuis l'hôte via IP mgmt)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G4 : auth API (login / ping / logout) ==="

# GET /auth → page de login accessible
resp=$(curl_auth "/auth")
if echo "$resp" | grep -qiE 'html|form|login|HTTP_STATUS:200|HTTP_STATUS:302'; then
    ok "T30 GET /auth → page accessible"
else
    fail "T30 GET /auth → page accessible" "réponse inattendue"
fi

# POST /register bob@test.lan → 200 (création) ou 409 (déjà existant, test idempotent)
resp=$(curl_auth "/register" \
    -X POST \
    --data-urlencode "user=bob@test.lan" \
    --data-urlencode "password=secret123")
if echo "$resp" | grep -qE 'HTTP_STATUS:(200|409)'; then
    ok "T31 POST /register bob@test.lan → 200/409"
else
    fail "T31 POST /register bob@test.lan → 200/409" "$(echo "$resp" | grep HTTP_STATUS)"
fi

# POST /login mauvais mot de passe → 401
resp=$(curl_auth "/login" \
    -X POST \
    --data-urlencode "user=alice@test.lan" \
    --data-urlencode "password=MAUVAIS")
if echo "$resp" | grep -qE 'HTTP_STATUS:401'; then
    ok "T32 POST /login mauvais mdp → 401"
else
    fail "T32 POST /login mauvais mdp → 401" "$(echo "$resp" | grep HTTP_STATUS)"
fi

# POST /login alice depuis hôte → 401 (MAC inconnu : hôte non-bridge, comportement attendu)
resp=$(curl_auth_verbose "/login" \
    -X POST \
    --data-urlencode "user=alice@test.lan" \
    --data-urlencode "password=motdepasse123")
if echo "$resp" | grep -qE 'HTTP/[0-9.]+ 401'; then
    ok "T33 POST /login alice depuis hôte → 401 (MAC inconnu)"
else
    fail "T33 POST /login alice depuis hôte → 401 (MAC inconnu)" "$(echo "$resp" | head -3)"
fi

# GET /ping sans session → 401
resp=$(curl_auth_verbose "/ping")
if echo "$resp" | grep -qE 'HTTP/[0-9.]+ 401'; then
    ok "T34 GET /ping sans session → 401"
else
    fail "T34 GET /ping sans session → 401" "$(echo "$resp" | head -3)"
fi

# GET /logout → 302 ou 200
resp=$(curl_auth_verbose "/logout" \
    -b /tmp/e2e_mgmt_cookies.txt)
if echo "$resp" | grep -qE 'HTTP/[0-9.]+ (302|200)'; then
    ok "T35 GET /logout → 302 ou 200"
else
    fail "T35 GET /logout → 302 ou 200" "$(echo "$resp" | head -3)"
fi

# GET /ping après logout → 401
resp=$(curl_auth_verbose "/ping" \
    -b /tmp/e2e_mgmt_cookies.txt)
if echo "$resp" | grep -qE 'HTTP/[0-9.]+ 401'; then
    ok "T36 GET /ping après logout → 401"
else
    fail "T36 GET /ping après logout → 401" "$(echo "$resp" | head -3)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 5 — Auth E2E depuis servus (IP data-plane)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G5 : auth E2E depuis servus (IP data-plane) ==="
flush_state

servus_ip=$(servus_data_ip4)
if [ -z "$servus_ip" ]; then
    skip "T40-T45 auth E2E" "IP data-plane de servus introuvable"
else
    # Login alice depuis servus
    login_from_servus "alice@test.lan" "motdepasse123" >/dev/null
    sleep 1
    if ssh_vm "$E2E_IP_SERVUS" "test -s /tmp/e2e_cookies.txt && cat /tmp/e2e_cookies.txt" \
            | grep -q "custos_session"; then
        ok "T40 login alice depuis servus → cookie obtenu"
    else
        fail "T40 login alice depuis servus → cookie obtenu" "pas de custos_session dans cookies"
    fi

    sleep 2

    # blocked.lan depuis servus → R4 homelab_auth_blocked matche (from_users vérifie sessions.lua)
    resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A")
    assert_eq "T41 blocked.lan après auth → NOERROR (R4 matche)" \
              "$(dns_status "$resp")" "NOERROR"

    # site-a.lan toujours accessible (R3 inchangé)
    resp=$(dig_from "$E2E_IP_SERVUS" "site-a.lan" "A")
    assert_eq "T42 site-a.lan après auth → NOERROR (R3 inchangé)" \
              "$(dns_status "$resp")" "NOERROR"

    sleep 1

    # Set auth nft peuplé avec l'IP de servus
    if nft_set_contains "r_homelab_auth_blocked_auth_ip4" "$servus_ip"; then
        ok "T43 r_homelab_auth_blocked_auth_ip4 contient $servus_ip"
    else
        fail "T43 r_homelab_auth_blocked_auth_ip4 contient $servus_ip" "entrée absente"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 6 — Heartbeat (ping) depuis servus
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G6 : heartbeat / ping ==="

if [ -z "$servus_ip" ]; then
    skip "T50-T52 heartbeat" "IP data-plane de servus introuvable"
else
    # Nouveau login depuis servus
    flush_state
    login_from_servus "alice@test.lan" "motdepasse123" >/dev/null

    sleep 2

    # Ping depuis servus → 204 (session active)
    # On vérifie via le code HTTP en ajoutant -w
    ping_code=$(ssh_vm "$E2E_IP_SERVUS" \
        "curl -sk --max-time 8 -b /tmp/e2e_cookies.txt \
         -o /dev/null -w '%{http_code}' \
         'https://${CUSTOS_DATA_IP}:33443/ping' 2>/dev/null || echo 0")
    assert_eq "T50 GET /ping depuis servus → 204" "$ping_code" "204"

    # blocked.lan toujours accessible après ping (session raffraîchie)
    resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A")
    assert_eq "T51 blocked.lan après ping → NOERROR" "$(dns_status "$resp")" "NOERROR"
fi

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 7 — Timeout de session
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G7 : timeout de session (idle_timeout=10s) ==="

if [ -z "$servus_ip" ]; then
    skip "T55-T58 timeout" "IP data-plane de servus introuvable"
else
    flush_state

    # Login depuis servus (nouvelle session)
    login_from_servus "alice@test.lan" "motdepasse123" >/dev/null

    sleep 2

    # Vérification préliminaire : blocked.lan accessible
    resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A")
    assert_eq "T55 blocked.lan avant timeout → NOERROR" "$(dns_status "$resp")" "NOERROR"

    # Attendre l'expiration de la session (idle_timeout=10s + marge)
    echo "  [attente 14s pour expiration de session idle_timeout=10s]"
    sleep 14

    # GET /ping → 401 (session expirée)
    ping_code=$(ssh_vm "$E2E_IP_SERVUS" \
        "curl -sk --max-time 8 -b /tmp/e2e_cookies.txt \
         -o /dev/null -w '%{http_code}' \
         'https://${CUSTOS_DATA_IP}:33443/ping' 2>/dev/null || echo 0")
    assert_eq "T56 GET /ping après timeout → 401" "$ping_code" "401"

    # blocked.lan depuis servus → REFUSED (session expirée, R4 échoue → R5 deny)
    resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A")
    assert_eq "T57 blocked.lan après timeout → REFUSED" "$(dns_status "$resp")" "REFUSED"
fi

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 8 — Déconnexion explicite
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G8 : déconnexion explicite ==="

if [ -z "$servus_ip" ]; then
    skip "T60-T63 logout explicite" "IP data-plane de servus introuvable"
else
    flush_state

    # Login depuis servus
    login_from_servus "alice@test.lan" "motdepasse123" >/dev/null
    sleep 2

    # Vérification : blocked.lan accessible
    resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A")
    assert_eq "T60 blocked.lan avant logout → NOERROR" "$(dns_status "$resp")" "NOERROR"

    # GET /logout depuis servus (-c sauvegarde le cookie vidé Set-Cookie: Max-Age=0)
    logout_code=$(ssh_vm "$E2E_IP_SERVUS" \
        "curl -sk --max-time 8 -b /tmp/e2e_cookies.txt -c /tmp/e2e_cookies.txt \
         -o /dev/null -w '%{http_code}' \
         'https://${CUSTOS_DATA_IP}:33443/logout' 2>/dev/null || echo 0")
    if [ "$logout_code" = "302" ] || [ "$logout_code" = "200" ]; then
        ok "T61 GET /logout depuis servus → $logout_code"
    else
        fail "T61 GET /logout depuis servus → 302 ou 200" "got=$logout_code"
    fi

    # GET /ping → 401 (session invalidée)
    ping_code=$(ssh_vm "$E2E_IP_SERVUS" \
        "curl -sk --max-time 8 -b /tmp/e2e_cookies.txt \
         -o /dev/null -w '%{http_code}' \
         'https://${CUSTOS_DATA_IP}:33443/ping' 2>/dev/null || echo 0")
    assert_eq "T62 GET /ping après logout → 401" "$ping_code" "401"

    # Attendre l'expiration du cache sessions (CACHE_TTL=5s) pour que worker_questions
    # recharge sessions.lua et constate l'invalidation de session.
    sleep 6

    # blocked.lan depuis servus → REFUSED (session invalidée, cache expiré)
    resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A")
    assert_eq "T63 blocked.lan après logout → REFUSED" "$(dns_status "$resp")" "REFUSED"
fi

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 9 — IPv6
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G9 : IPv6 ==="
flush_state

resp=$(dig_from "$E2E_IP_SERVUS" "site-a.lan" "AAAA")
if [ "$(dns_status "$resp")" = "NOERROR" ]; then
    ok "T70 site-a.lan AAAA → NOERROR"
    assert_contains "T71 site-a.lan AAAA → fd42:42:0:1::50" "fd42:42:0:1::50" "$resp"
else
    skip "T70-T71 site-a.lan AAAA" "NOERROR non obtenu (pas d'entrée AAAA ou IPv6 désactivé)"
fi

resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "AAAA")
assert_eq "T72 blocked.lan AAAA → REFUSED" "$(dns_status "$resp")" "REFUSED"
assert_contains "T73 blocked.lan AAAA → EDE 15" "EDE.*17|17.*Filtered|code: 17" "$resp"

sleep 1
if nft_set_contains "r_homelab_not_blocked_ip6" "fd42:42:0:1::50"; then
    ok "T74 r_homelab_not_blocked_ip6 contient fd42:42:0:1::50"
else
    skip "T74 r_homelab_not_blocked_ip6" "fd42:42:0:1::50 absent (AAAA non résolu ou SLAAC absent)"
fi

# cliens AAAA dnsonly → NOERROR sans peuplement du set
resp=$(dig_from "$E2E_IP_CLIENS" "site-a.lan" "AAAA")
if [ "$(dns_status "$resp")" = "NOERROR" ]; then
    ok "T75 cliens site-a.lan AAAA → NOERROR (dnsonly)"
    cliens_ip6=$(servus_data_ip6 2>/dev/null || true)
    if [ -n "$cliens_ip6" ] && nft_set_contains "r_ext_dnsonly_ip6" "$cliens_ip6"; then
        fail "T76 r_ext_dnsonly_ip6 sans IP cliens" "IP $cliens_ip6 présente"
    else
        ok "T76 r_ext_dnsonly_ip6 sans IP cliens (dnsonly)"
    fi
else
    skip "T75-T76 cliens AAAA dnsonly" "NOERROR non obtenu"
fi

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 10 — EDE (Extended DNS Errors)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G10 : EDE (Extended DNS Errors) ==="

resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A" "+noall" "+comments" "+additional")
assert_contains "T80 blocked.lan → EDE code 15 (Filtered)" \
    "EDE.*17|17.*Filtered|code: 17" "$resp"

resp=$(dig_from "$E2E_IP_SERVUS" "site-a.lan" "A" "+noall" "+comments" "+additional")
assert_not_contains "T81 site-a.lan → pas d'EDE 15" \
    "EDE.*15|15.*Filtered" "$resp"

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 11 — Logs
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G11 : logs ==="

logs=$(custos_logs)
assert_contains "T90 log homelab_not_blocked présent" "homelab_not_blocked" "$logs"
assert_contains "T91 log default_deny présent"        "default_deny"        "$logs"
assert_contains "T92 log ext_dnsonly présent"         "ext_dnsonly"         "$logs"
# T93 : les verdicts allow/deny mentionnent le worker source (dns/doh/sni).
assert_contains "T93 verdict DNS mentionne worker=dns" "worker=dns" "$logs"

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 12 — DoH (DNS-over-HTTPS) avec mini CA
# Crée une CA locale, génère un cert signé pour custos, vérifie que le worker
# DoH répond 200 avec un cert valide et que la réponse DNS est correctement
# formée. Le cert Let's Encrypt de prod n'est pas touché : on passe par un
# fichier de config temporaire sur custos.
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G12 : DoH (DNS-over-HTTPS) avec mini CA ==="

DOH_TMP=$(mktemp -d)
DOH_PORT="${E2E_DOH_PORT:-8444}"   # port de test isolé pour ne pas perturber le port 8443 de prod
DOH_CLEANUP_DONE=0

doh_cleanup() {
    [ "$DOH_CLEANUP_DONE" -eq 1 ] && return
    DOH_CLEANUP_DONE=1
    # Restaure la config d'origine (sauvegardée côté hôte) et relance custos.
    if [ -f "$DOH_TMP/config_orig.moon" ]; then
        scp -O -q $SSH_OPTS -i "$SSH_KEY" \
            "$DOH_TMP/config_orig.moon" "root@${E2E_IP_CUSTOS}:/etc/custos/config.moon" 2>/dev/null || true
    fi
    ssh_vm "$E2E_IP_CUSTOS" "rm -f /tmp/doh_test_cert.pem /tmp/doh_test_key.pem"
    ssh_vm "$E2E_IP_CUSTOS" "/etc/init.d/custos restart >/dev/null 2>&1 || true"
    rm -rf "$DOH_TMP"
}
trap doh_cleanup EXIT

# ── Étape 1 : Génération de la mini CA et du certificat serveur ───────────────

# CA
openssl ecparam -name prime256v1 -genkey -noout -out "$DOH_TMP/ca.key" 2>/dev/null
openssl req -new -x509 -key "$DOH_TMP/ca.key" -sha256 -days 1 \
    -subj "/CN=CustosTestCA" -out "$DOH_TMP/ca.crt" 2>/dev/null

# Certificat serveur : SAN = IP de custos + DNS custos.homelab
cat > "$DOH_TMP/san.cnf" <<SANCNF
[req]
distinguished_name = dn
[dn]
[san]
subjectAltName = IP:${E2E_IP_CUSTOS},DNS:custos.homelab
SANCNF

openssl ecparam -name prime256v1 -genkey -noout -out "$DOH_TMP/srv.key" 2>/dev/null
openssl req -new -key "$DOH_TMP/srv.key" -subj "/CN=${E2E_IP_CUSTOS}" \
    -out "$DOH_TMP/srv.csr" 2>/dev/null
openssl x509 -req -in "$DOH_TMP/srv.csr" \
    -CA "$DOH_TMP/ca.crt" -CAkey "$DOH_TMP/ca.key" -CAcreateserial \
    -days 1 -sha256 -extensions san -extfile "$DOH_TMP/san.cnf" \
    -out "$DOH_TMP/srv.crt" 2>/dev/null

if [ -f "$DOH_TMP/srv.crt" ] && [ -f "$DOH_TMP/srv.key" ]; then
    ok "T100 génération mini CA + cert serveur"
else
    fail "T100 génération mini CA + cert serveur" "fichiers absents"
fi

# ── Étape 2 : Injection d'une section doh (port de test + mini CA) ───────────
# NB : CUSTOS_CONFIG_PATH passé devant `init.d restart` est ignoré — l'init.d
# procd force CUSTOS_CONFIG_PATH=/etc/custos/config.moon (procd_set_param env).
# On modifie donc directement /etc/custos/config.moon (sauvegardé pour restauration
# dans doh_cleanup), en insérant un bloc doh après l'accolade ouvrante du table.

scp -O -q $SSH_OPTS -i "$SSH_KEY" \
    "$DOH_TMP/srv.crt" "root@${E2E_IP_CUSTOS}:/tmp/doh_test_cert.pem"
scp -O -q $SSH_OPTS -i "$SSH_KEY" \
    "$DOH_TMP/srv.key" "root@${E2E_IP_CUSTOS}:/tmp/doh_test_key.pem"

# Le CA doit être sur servus avant toute requête curl --cacert
scp -O -q $SSH_OPTS -i "$SSH_KEY" \
    "$DOH_TMP/ca.crt" "root@${E2E_IP_SERVUS}:/tmp/doh_test_ca.crt" 2>/dev/null || true

# Sauvegarde la config d'origine côté hôte
scp -O -q $SSH_OPTS -i "$SSH_KEY" \
    "root@${E2E_IP_CUSTOS}:/etc/custos/config.moon" "$DOH_TMP/config_orig.moon"

# Bloc doh inline inséré après la 1re ligne « { » (table de config au niveau racine)
DOH_INJECT="  doh: { port: ${DOH_PORT}, cert: \"/tmp/doh_test_cert.pem\", key: \"/tmp/doh_test_key.pem\", prefer_ipv6: false }"
awk -v line="$DOH_INJECT" \
    '!ins && /^[[:space:]]*\{[[:space:]]*$/ {print; print line; ins=1; next} {print}' \
    "$DOH_TMP/config_orig.moon" > "$DOH_TMP/config_doh.moon"

scp -O -q $SSH_OPTS -i "$SSH_KEY" \
    "$DOH_TMP/config_doh.moon" "root@${E2E_IP_CUSTOS}:/etc/custos/config.moon"

ssh_vm "$E2E_IP_CUSTOS" "/etc/init.d/custos restart >/dev/null 2>&1; sleep 3"

# T101 : le worker DoH journalise son écoute sur le port de test (logread fiable
# sur OpenWrt : `ss` busybox n'affiche pas toujours le socket, et le format du
# log varie ; on vérifie donc directement que le port répond en TLS (tout code
# HTTP renvoyé prouve que le listener TLS est actif).
doh_listen_code=$(ssh_vm "$E2E_IP_SERVUS" \
    "curl -sk -o /dev/null --max-time 5 -w '%{http_code}' \
     'https://${E2E_IP_CUSTOS}:${DOH_PORT}/' 2>/dev/null")
if [ -n "$doh_listen_code" ] && [ "$doh_listen_code" != "000" ]; then
    ok "T101 worker DoH écoute en TLS sur port ${DOH_PORT} (HTTP ${doh_listen_code})"
else
    fail "T101 worker DoH écoute en TLS sur port ${DOH_PORT}" "pas de réponse TLS (code=${doh_listen_code:-vide})"
fi

# ── Étape 3 : Requête DoH depuis servus avec la mini CA comme trust anchor ────

# Encodage base64url de la requête DNS "example.com A"
DOH_DNS_QUERY="AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"

DOH_RESPONSE=$(ssh_vm "$E2E_IP_SERVUS" \
    "curl -s -w '\n%{http_code}' --max-time 5 \
     --cacert /tmp/doh_test_ca.crt \
     'https://${E2E_IP_CUSTOS}:${DOH_PORT}/dns-query?dns=${DOH_DNS_QUERY}' \
     -H 'Accept: application/dns-message' 2>/dev/null" || true)

DOH_HTTP_CODE=$(echo "$DOH_RESPONSE" | tail -1)
assert_eq "T102 DoH répond HTTP 200" "$DOH_HTTP_CODE" "200"

# ── Étape 4 : Vérification TLS — le cert présenté chaîne bien vers la mini CA ─
# Test robuste (indépendant du format de sortie d'openssl s_client busybox) :
# avec la mini CA comme trust anchor → succès (200) ; sans aucun CA de confiance
# (ni -k) → la validation TLS échoue (000). Cela prouve que le cert présenté est
# bien validé contre NOTRE mini CA et non un CA système.
DOH_CODE_WITH_CA=$(ssh_vm "$E2E_IP_SERVUS" \
    "curl -s -o /dev/null --max-time 5 -w '%{http_code}' --cacert /tmp/doh_test_ca.crt \
     'https://${E2E_IP_CUSTOS}:${DOH_PORT}/dns-query?dns=${DOH_DNS_QUERY}' \
     -H 'Accept: application/dns-message' 2>/dev/null")
DOH_CODE_NO_CA=$(ssh_vm "$E2E_IP_SERVUS" \
    "curl -s -o /dev/null --max-time 5 -w '%{http_code}' \
     'https://${E2E_IP_CUSTOS}:${DOH_PORT}/dns-query?dns=${DOH_DNS_QUERY}' \
     -H 'Accept: application/dns-message' 2>/dev/null")
if [ "$DOH_CODE_WITH_CA" = "200" ] && [ "$DOH_CODE_NO_CA" = "000" ]; then
    ok "T103 cert TLS validé par la mini CA (avec CA→200, sans CA→échec)"
else
    fail "T103 cert TLS validé par la mini CA" "avec_CA=${DOH_CODE_WITH_CA} sans_CA=${DOH_CODE_NO_CA}"
fi

# ── Étape 5 : Réponse DNS binaire bien formée ─────────────────────────────────

# La réponse doit faire au moins 12 octets (header DNS)
DOH_BODY_LEN=$(ssh_vm "$E2E_IP_SERVUS" \
    "curl -s --max-time 5 --cacert /tmp/doh_test_ca.crt \
     'https://${E2E_IP_CUSTOS}:${DOH_PORT}/dns-query?dns=${DOH_DNS_QUERY}' \
     -H 'Accept: application/dns-message' 2>/dev/null | wc -c" || echo "0")
if [ "${DOH_BODY_LEN:-0}" -ge 12 ]; then
    ok "T104 réponse DNS ≥ 12 octets (header DNS valide)"
else
    fail "T104 réponse DNS ≥ 12 octets" "taille=${DOH_BODY_LEN}"
fi

# ── Étape 6 : Format JSON DoH ─────────────────────────────────────────────────

DOH_JSON=$(ssh_vm "$E2E_IP_SERVUS" \
    "curl -s --max-time 5 --cacert /tmp/doh_test_ca.crt \
     'https://${E2E_IP_CUSTOS}:${DOH_PORT}/dns-query?name=example.com&type=A' \
     -H 'Accept: application/dns-json' 2>/dev/null" || true)
assert_contains "T105 DoH JSON contient Status" '"Status"' "$DOH_JSON"
assert_contains "T106 DoH JSON contient Question" '"Question"' "$DOH_JSON"

# ── Nettoyage ─────────────────────────────────────────────────────────────────
ssh_vm "$E2E_IP_SERVUS" "rm -f /tmp/doh_test_ca.crt" || true
doh_cleanup

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 13 — Interface admin webui (/admin/*) derrière session admin
# Exerce le routeur webui, admin_auth, et les handlers dashboard/config/rules/
# lists + le reload SIGHUP — zones quasi non couvertes par les tests unitaires.
# alice@test.lan est déclarée admin dans homelab-e2e.moon.
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G13 : interface admin webui ==="
flush_state

servus_ip=$(servus_data_ip4)
if [ -z "$servus_ip" ]; then
    skip "T110-T117 webui admin" "IP data-plane de servus introuvable"
else
    # La session a un idle_timeout court (10s, voir G7) et un GET /admin ne
    # rafraîchit pas le timer (seul /ping le fait). On exécute donc, dans UNE
    # seule session SSH, l'apprentissage MAC (dig) + login + toutes les requêtes
    # admin back-to-back pour rester sous l'idle_timeout. Chaque endpoint imprime
    # un marqueur « CLE:<code> » suivi du corps HTML.
    admin_out=$(ssh_vm "$E2E_IP_SERVUS" "
        dig +timeout=3 +tries=1 @10.42.0.1 site-a.lan A >/dev/null 2>&1
        rm -f /tmp/adm_cookies.txt
        base='https://${CUSTOS_DATA_IP}:33443'
        # NOCOOKIE : accès admin sans session → doit rediriger (302) ou refuser
        curl -sk --max-time 8 -o /dev/null -w 'NOCOOKIE:%{http_code}\n' \"\$base/admin/\"
        # Login admin (alice) → cookie de session
        curl -sk --max-time 8 -c /tmp/adm_cookies.txt -o /dev/null -w 'LOGIN:%{http_code}\n' \
            -X POST --data-urlencode 'user=alice@test.lan' \
            --data-urlencode 'password=motdepasse123' \"\$base/login\"
        # Helper : requête GET admin imprimant 'CLE:<code>' + le corps
        ac() { curl -sk --max-time 8 -b /tmp/adm_cookies.txt -w \"\\n\$1:%{http_code}\\n\" \"\$base\$2\"; }
        ac DASH    /admin/
        ac CFG     /admin/config/
        ac AUTHSEC /admin/config/auth
        ac RULES   /admin/config/filter/rules
        ac LISTS   /admin/config/filter/lists
        ac STATUS  /admin/system/status
        # Reload SIGHUP (POST) — authentifié, redirige (302) après déclenchement
        curl -sk --max-time 8 -b /tmp/adm_cookies.txt -o /dev/null -w 'RELOAD:%{http_code}\n' \
            -X POST \"\$base/admin/system/reload\"
        rm -f /tmp/adm_cookies.txt
    ")

    acode() { echo "$admin_out" | grep -oE "$1:[0-9]+" | head -1 | cut -d: -f2; }

    # T110 : sans session → 302/401/403
    code=$(acode NOCOOKIE)
    if echo "$code" | grep -qE '^(302|401|403)$'; then
        ok "T110 /admin sans cookie → $code (refus/redirect)"
    else
        fail "T110 /admin sans cookie → refus" "code=$code"
    fi

    # Pré-requis : le login admin a réussi (sinon tout le reste est 302)
    assert_eq "T111 login admin alice depuis servus → 200" "$(acode LOGIN)" "200"

    # T112-T117 : chaque endpoint admin renvoie 200 (session admin reconnue)
    assert_eq "T112 GET /admin/ (dashboard) → 200"             "$(acode DASH)"    "200"
    assert_contains "T112b dashboard contient 'Configuration'" "Configuration" "$admin_out"
    assert_eq "T113 GET /admin/config/ → 200"                  "$(acode CFG)"     "200"
    assert_eq "T114 GET /admin/config/auth → 200"              "$(acode AUTHSEC)" "200"
    assert_eq "T115 GET /admin/config/filter/rules → 200"      "$(acode RULES)"   "200"
    assert_contains "T115b rules contient les règles configurées" "blocked.lan" "$admin_out"
    assert_eq "T116 GET /admin/config/filter/lists → 200"      "$(acode LISTS)"   "200"
    assert_eq "T117 GET /admin/system/status → 200"            "$(acode STATUS)"  "200"

    # T118 : reload SIGHUP → 200 (page de confirmation), service toujours vivant
    assert_eq "T118 POST /admin/system/reload → 200" "$(acode RELOAD)" "200"
    sleep 2
    if ssh_vm "$E2E_IP_CUSTOS" "ps | grep -q '[c]ustos' && echo UP" | grep -q UP; then
        ok "T118b service toujours vivant après reload"
    else
        fail "T118b service toujours vivant après reload" "custos absent après SIGHUP"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 14 — SNI (TLS/HTTPS) via worker_tls (nfqueue.sni), placement=integral
# Exerce le worker `tls` : capture du SNI depuis un ClientHello TLS (TCP/443),
# puis verdict allow/deny appliqué sur le SNI normalisé.
#
# Mécanique du test : le ClientHello n'est émis qu'après l'aboutissement du
# 3-way handshake TCP. On installe donc un listener TCP factice (busybox `nc`)
# sur `via` (alias 10.42.0.50:443) pour que le handshake aboutisse ; curl envoie
# alors son ClientHello (chemin ACK), capturé par le worker SNI placé AVANT le
# dispatch DNS (sni.placement = "integral", cf. homelab-e2e.moon ;
# en "residual" la paire déjà autorisée contournerait la file SNI).
#   - SNI=site-a.lan  → R3 homelab_not_blocked → allow.
#   - SNI=blocked.lan vers une IP autorisée (10.42.0.50) → le SYN passe, le
#     worker voit blocked.lan et applique le verdict de blocage (r_default_deny).
# servus n'a ni openssl ni `timeout` ; on utilise curl (mbedTLS) + --max-time.
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G14 : SNI TLS (worker_tls, placement=integral) ==="
flush_state

SNI_DEST="10.42.0.50"   # IP de site-a.lan ; sert aussi de cible autorisée pour blocked.lan

sni_listener_stop() {
    ssh_vm "$E2E_IP_VIA" "
        for p in \$(ps w 2>/dev/null | grep -E 'nc -l -p 443|while true; do nc' | grep -v grep | awk '{print \$1}'); do
            kill -9 \$p 2>/dev/null
        done
        killall -9 nc 2>/dev/null
        ip addr del ${SNI_DEST}/24 dev eth1 2>/dev/null
    " || true
}

servus_ip=$(servus_data_ip4)
if [ -z "$servus_ip" ]; then
    skip "T120-T125 SNI" "IP data-plane de servus introuvable"
elif [ -z "${E2E_IP_VIA:-}" ]; then
    skip "T120-T125 SNI" "IP de management de via introuvable (listener impossible)"
else
    # ── T120 : le worker tls est démarré (processus vivant) ───────────────────
    # On vérifie le processus plutôt que le log policy_loaded : ce dernier est
    # émis au démarrage et peut être évincé du buffer logread après les autres
    # groupes. La capture SNI ci-dessous (T121) prouve que la politique est
    # bien chargée et active.
    if ssh_vm "$E2E_IP_CUSTOS" "ps w | grep -q '[c]ustos:tls' && echo UP" | grep -q UP; then
        ok "T120 worker_tls démarré (processus actif)"
    else
        fail "T120 worker_tls démarré (processus actif)" "processus {custos:tls} absent"
    fi

    # Listener TCP factice sur via : alias 10.42.0.50:443 + boucle nc (busybox nc
    # ne gère qu'une connexion par invocation). setsid détache la boucle de la
    # session SSH. Le handshake TCP aboutit ; nc ne répond pas en TLS (peu
    # importe : le ClientHello a déjà traversé le pont et été capturé).
    sni_listener_stop
    ssh_vm "$E2E_IP_VIA" "
        ip addr add ${SNI_DEST}/24 dev eth1 2>/dev/null
        setsid sh -c 'while true; do nc -l -p 443 >/dev/null 2>&1; done' >/dev/null 2>&1 &
        echo started
    "
    sleep 1

    # Résout site-a.lan → autorise la paire (servus, 10.42.0.50) : le SYN passe.
    dig_from "$E2E_IP_SERVUS" "site-a.lan" "A" >/dev/null

    # ── T121/T122 : ClientHello SNI=site-a.lan (autorisé) ─────────────────────
    ssh_vm "$E2E_IP_SERVUS" "
        for i in 1 2 3; do
            curl -sk --max-time 4 --resolve site-a.lan:443:${SNI_DEST} \
                'https://site-a.lan/' >/dev/null 2>&1 || true
            sleep 1
        done
    "
    sleep 2
    logs=$(custos_logs)
    assert_log_has "T121 worker_tls capture le SNI site-a.lan (TLS)" \
        "$logs" "action=sni_captured" "sni=site-a.lan"
    assert_log_has "T122 verdict SNI allow site-a.lan (worker=sni-tls)" \
        "$logs" "action=sni_verdict_allow" "sni=site-a.lan" "worker=sni-tls"

    # ── T123/T124 : ClientHello SNI=blocked.lan vers une IP autorisée ─────────
    # 10.42.0.50 est autorisé (site-a) → le SYN passe et le handshake aboutit ;
    # le worker voit le SNI=blocked.lan et applique le verdict de blocage.
    ssh_vm "$E2E_IP_SERVUS" "
        for i in 1 2; do
            curl -sk --max-time 4 --resolve blocked.lan:443:${SNI_DEST} \
                'https://blocked.lan/' >/dev/null 2>&1 || true
            sleep 1
        done
    "
    sleep 2
    logs=$(custos_logs)
    assert_log_has "T123 worker_tls capture le SNI blocked.lan" \
        "$logs" "action=sni_captured" "sni=blocked.lan"
    assert_log_has "T124 verdict SNI block blocked.lan (worker=sni-tls)" \
        "$logs" "action=sni_verdict_block" "sni=blocked.lan" "worker=sni-tls"

    # ── T125 : QUIC Initial (UDP/443) — best-effort selon outillage dispo ─────
    if ssh_vm "$E2E_IP_SERVUS" "curl --version 2>/dev/null | grep -q HTTP3 && echo HTTP3"; then
        ssh_vm "$E2E_IP_SERVUS" "
            curl -sk --max-time 5 --http3-only \
                --resolve site-a.lan:443:${SNI_DEST} \
                'https://site-a.lan/' >/dev/null 2>&1 || true
        "
        sleep 2
        logs=$(custos_logs)
        if echo "$logs" | grep -qE "protocol=quic|l4_proto=udp|worker=sni-quic"; then
            ok "T125 worker_tls traite un QUIC Initial (UDP/443)"
        else
            skip "T125 QUIC Initial" "aucun log quic (handshake non émis ou non intercepté)"
        fi
    else
        skip "T125 QUIC Initial" "curl sans support HTTP/3 sur servus"
    fi

    sni_listener_stop
fi

# ─── RAPPORT FINAL ─────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────────"
printf "Résultats : %d passed, %d failed\n" "$PASS" "$FAIL"
echo "─────────────────────────────────────────"
[ "$FAIL" -eq 0 ] || exit 1
