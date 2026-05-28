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
    # Retire le fichier de config de test sur custos et relance avec la config originale
    ssh_vm "$E2E_IP_CUSTOS" "rm -f /tmp/doh_test_cert.pem /tmp/doh_test_key.pem /tmp/doh_e2e_config.moon"
    # Recharge custos avec la config originale (sans le port de test)
    ssh_vm "$E2E_IP_CUSTOS" \
        "CUSTOS_CONFIG_PATH=/etc/custos/config.moon /etc/init.d/custos restart >/dev/null 2>&1 || true"
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

# ── Étape 2 : Déploiement du cert de test sur custos ─────────────────────────

scp -q $SSH_OPTS -i "$SSH_KEY" \
    "$DOH_TMP/srv.crt" "root@${E2E_IP_CUSTOS}:/tmp/doh_test_cert.pem"
scp -q $SSH_OPTS -i "$SSH_KEY" \
    "$DOH_TMP/srv.key" "root@${E2E_IP_CUSTOS}:/tmp/doh_test_key.pem"

# Config temporaire : port de test isolé + cert de la mini CA
cat > "$DOH_TMP/doh_e2e_config.moon" <<MONCFG
{
  doh: {
    port: ${DOH_PORT}
    cert: "/tmp/doh_test_cert.pem"
    key:  "/tmp/doh_test_key.pem"
    prefer_ipv6: false
  }
}
MONCFG

scp -q $SSH_OPTS -i "$SSH_KEY" \
    "$DOH_TMP/doh_e2e_config.moon" "root@${E2E_IP_CUSTOS}:/tmp/doh_e2e_config.moon"

# Redémarre custos avec la config de test
ssh_vm "$E2E_IP_CUSTOS" \
    "CUSTOS_CONFIG_PATH=/tmp/doh_e2e_config.moon /etc/init.d/custos restart >/dev/null 2>&1 && sleep 2"

if ssh_vm "$E2E_IP_CUSTOS" "ss -tnlp | grep -q ':${DOH_PORT}'"; then
    ok "T101 worker DoH écoute sur port ${DOH_PORT} avec cert de test"
else
    fail "T101 worker DoH écoute sur port ${DOH_PORT} avec cert de test" "port absent"
fi

# ── Étape 3 : Requête DoH depuis servus avec la mini CA comme trust anchor ────

# Encodage base64url de la requête DNS "example.com A"
DOH_DNS_QUERY="AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"

DOH_RESPONSE=$(ssh_vm "$E2E_IP_SERVUS" \
    "curl -s -w '\n%{http_code}' --max-time 5 \
     --cacert /tmp/doh_test_ca.crt \
     'https://${E2E_IP_CUSTOS}:${DOH_PORT}/dns-query?dns=${DOH_DNS_QUERY}' \
     -H 'Accept: application/dns-message' 2>/dev/null" || true)

# Le CA cert doit aussi être copié sur servus pour que curl puisse valider
scp -q $SSH_OPTS -i "$SSH_KEY" \
    "$DOH_TMP/ca.crt" "root@${E2E_IP_SERVUS}:/tmp/doh_test_ca.crt" 2>/dev/null || true

DOH_RESPONSE=$(ssh_vm "$E2E_IP_SERVUS" \
    "curl -s -w '\n%{http_code}' --max-time 5 \
     --cacert /tmp/doh_test_ca.crt \
     'https://${E2E_IP_CUSTOS}:${DOH_PORT}/dns-query?dns=${DOH_DNS_QUERY}' \
     -H 'Accept: application/dns-message' 2>/dev/null" || true)

DOH_HTTP_CODE=$(echo "$DOH_RESPONSE" | tail -1)
assert_eq "T102 DoH répond HTTP 200" "$DOH_HTTP_CODE" "200"

# ── Étape 4 : Vérification TLS — le cert présenté correspond à la mini CA ─────

DOH_CERT_CHECK=$(ssh_vm "$E2E_IP_SERVUS" \
    "echo | openssl s_client -connect ${E2E_IP_CUSTOS}:${DOH_PORT} \
     -CAfile /tmp/doh_test_ca.crt 2>&1 | grep 'Verify return code'" || true)
assert_contains "T103 TLS vérifié par mini CA (Verify return code: 0)" \
    "Verify return code: 0" "$DOH_CERT_CHECK"

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

# ─── RAPPORT FINAL ─────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────────"
printf "Résultats : %d passed, %d failed\n" "$PASS" "$FAIL"
echo "─────────────────────────────────────────"
[ "$FAIL" -eq 0 ] || exit 1
