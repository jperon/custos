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
# GROUPE 0b — Approvisionnement des listes pré-compilées (custos-update)
# Exerce le script de packaging /usr/sbin/custos-update : il télécharge les .bin
# depuis les releases du dépôt custos-lists (curl + zstd + SHA256) puis les
# déploie. Placé tôt (volet infra/approvisionnement, voisin de G0) : retour
# immédiat sur la dépendance externe avant les tests fonctionnels, et le SIGHUP
# de rechargement du démon survient avant que l'état fonctionnel ne soit construit.
# CE GROUPE EST CONDITIONNÉ À UNE DÉPENDANCE EXTERNE (accès internet + release
# publiée) : si la ressource n'est pas joignable (pas d'internet, dépôt ou release
# absent, outils manquants), on émet un `skip` « dépendance manquante » — JAMAIS
# un `fail`, afin de ne pas faire échouer la suite sur une cause externe.
# Le téléchargement vise un répertoire isolé (CUSTOS_LISTS_DIR) pour ne pas
# écraser /etc/custos/lists ; on choisit le profil lowmem (archive la plus légère).
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G0b : approvisionnement listes (custos-update) ==="

G15_REPO="${CUSTOS_LISTS_REPO:-jperon/custos-lists}"
G15_TAG="${CUSTOS_LISTS_TAG:-latest}"
G15_PROFILE="lowmem"
G15_ARCHIVE="custos-lists-${G15_PROFILE}.tar.zst"
G15_TAGPAGE="https://github.com/${G15_REPO}/releases/tag/${G15_TAG}"
G15_DEST="/tmp/e2e-lists"

# Outils requis par custos-update, vérifiés sur custos (un par ligne si absent).
G15_MISSING=$(ssh_vm "$E2E_IP_CUSTOS" \
    "for t in curl zstd tar sha256sum; do command -v \$t >/dev/null 2>&1 || echo \$t; done")

# Sonde de connectivité + existence de la release : on interroge la PAGE du tag
# (HTML, réponse 200 directe) plutôt que l'asset (qui redirige vers S3 — un -L
# instable y renvoie parfois 302). curl rapporte lui-même « 000 » s'il ne peut
# joindre l'hôte (pas de `|| echo` qui concaténerait au code déjà imprimé).
# 000 → pas de réseau ; 404 → release absente ; 200 → on lance custos-update.
G15_HTTP=$(ssh_vm "$E2E_IP_CUSTOS" \
    "curl -sL -o /dev/null -m 20 -w '%{http_code}' '$G15_TAGPAGE' 2>/dev/null")
G15_HTTP="${G15_HTTP:-000}"

if [ -n "$G15_MISSING" ]; then
    skip "T04a-T04c custos-update" \
        "dépendance manquante : outils absents sur custos ($(echo $G15_MISSING | tr '\n' ' '))"
elif [ "$G15_HTTP" = "000" ]; then
    skip "T04a-T04c custos-update" \
        "dépendance manquante : pas d'accès internet (curl $G15_TAGPAGE → aucune réponse)"
elif [ "$G15_HTTP" != "200" ]; then
    skip "T04a-T04c custos-update" \
        "dépendance manquante : release indisponible (HTTP $G15_HTTP pour le tag $G15_TAG)"
else
    # T04a : le script de packaging est bien déployé et exécutable.
    if ssh_vm "$E2E_IP_CUSTOS" "test -x /usr/sbin/custos-update && echo OK" | grep -q OK; then
        ok "T04a /usr/sbin/custos-update présent et exécutable"
    else
        fail "T04a /usr/sbin/custos-update présent et exécutable" "absent ou non exécutable"
    fi

    # T04b : téléchargement + vérification SHA256 + extraction → exit 0.
    # custos-update (set -eu) propage le code de curl ; les codes « réseau »
    # (6 DNS, 7 connexion, 28 timeout, 35/52/56 TLS/réponse) signalent un CDN
    # d'assets GitHub injoignable (objects/codeload) — dépendance externe, donc
    # `skip` plutôt que `fail`. Tout autre code non nul = vraie anomalie → fail.
    g15_out=$(ssh_vm "$E2E_IP_CUSTOS" "
        rm -rf '$G15_DEST'
        CUSTOS_LISTS_REPO='$G15_REPO' CUSTOS_LISTS_DIR='$G15_DEST' \
            /usr/sbin/custos-update '$G15_PROFILE' '$G15_TAG' 2>&1
        echo \"EXIT=\$?\"
    ")
    g15_rc=$(echo "$g15_out" | grep -oE 'EXIT=[0-9]+' | tail -1 | cut -d= -f2)
    case "${g15_rc:-1}" in
        0)
            ok "T04b custos-update $G15_PROFILE → exit 0 (download + SHA256 + extraction)"
            # T04c : au moins une liste .bin a bien été déployée.
            g15_nbin=$(ssh_vm "$E2E_IP_CUSTOS" "find '$G15_DEST' -name '*.bin' 2>/dev/null | wc -l")
            if [ "${g15_nbin:-0}" -ge 1 ]; then
                ok "T04c listes .bin déployées ($g15_nbin fichier(s)) dans $G15_DEST"
            else
                fail "T04c listes .bin déployées" "aucun .bin dans $G15_DEST"
            fi
            ;;
        6|7|28|35|52|56)
            skip "T04b-T04c custos-update" \
                "dépendance manquante : CDN d'assets GitHub injoignable (curl rc=$g15_rc)"
            ;;
        *)
            fail "T04b custos-update $G15_PROFILE → exit 0" \
                "rc=${g15_rc:-?} : $(echo "$g15_out" | tail -3 | tr '\n' ' ')"
            ;;
    esac

    ssh_vm "$E2E_IP_CUSTOS" "rm -rf '$G15_DEST'" || true
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

# POST /login alice depuis hôte → 200.
# L'hôte de test joint le portail via l'IP de management ; custos résout
# néanmoins son MAC (ARP/table de voisinage), donc un login à identifiants
# valides aboutit et lie la session à ce MAC. Le rejet d'un MAC réellement
# irrésoluble reste couvert par les chemins captifs/auth (G5+).
resp=$(curl_auth_verbose "/login" \
    -X POST \
    --data-urlencode "user=alice@test.lan" \
    --data-urlencode "password=motdepasse123")
if echo "$resp" | grep -qE 'HTTP/[0-9.]+ 200'; then
    ok "T33 POST /login alice depuis hôte → 200 (MAC résolu)"
else
    fail "T33 POST /login alice depuis hôte → 200 (MAC résolu)" "$(echo "$resp" | head -3)"
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

# L'image de servus configure eth0 en DHCPv4 seul (pas de client DHCPv6/SLAAC) :
# servus n'a donc aucune IPv6 data-plane par défaut. Or le worker n'apprend
# l'IPv6 d'un client (table MAC→{v4,v6}) que s'il le voit émettre du trafic IPv6 ;
# sans cela, r_homelab_not_blocked_ip6 reste vide et T74 ne peut être vérifié.
# On attribue donc une ULA dans le /64 du LAN (fd42:42:0:1::/64, annoncé par via)
# puis on émettra une requête AAAA sur transport IPv6 (cf. avant T74).
SERVUS_V6="fd42:42:0:1::99"
ssh_vm "$E2E_IP_SERVUS" "ip -6 addr add ${SERVUS_V6}/64 dev eth0 2>/dev/null || true"
sleep 2   # laisse le DAD (Duplicate Address Detection) se terminer

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

# Requête AAAA sur transport IPv6 (@fd42:42:0:1::1, dnsmasq de via) : la source
# du paquet est l'IPv6 de servus, le worker l'apprend et injecte l'adresse
# résolue dans le set ip6 (clé servus_v6 . fd42:42:0:1::50).
ssh_vm "$E2E_IP_SERVUS" \
    "dig +timeout=3 +tries=1 @fd42:42:0:1::1 site-a.lan AAAA >/dev/null 2>&1 || true"
sleep 1
if nft_set_contains "r_homelab_not_blocked_ip6" "fd42:42:0:1::50"; then
    ok "T74 r_homelab_not_blocked_ip6 contient fd42:42:0:1::50"
else
    fail "T74 r_homelab_not_blocked_ip6" "fd42:42:0:1::50 absent du set ip6 après requête AAAA sur transport IPv6"
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

# Les VMs OpenWrt peuvent dériver de quelques secondes sans NTP ; un cert
# fraîchement émis peut alors apparaître "not yet valid" côté servus.
# On aligne l'horloge de servus sur l'hôte avant les vérifications TLS.
HOST_UTC_NOW="$(date -u '+%Y-%m-%d %H:%M:%S')"
ssh_vm "$E2E_IP_SERVUS" "date -u -s '${HOST_UTC_NOW}' >/dev/null 2>&1 || true"
sleep 1

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

    # ── T125 : QUIC Initial (UDP/443) ─────────────────────────────────────────
    # curl n'embarque pas HTTP/3 sur servus ; au lieu de dépendre d'un client
    # QUIC, on rejoue un vrai QUIC Initial (charge utile UDP capturée, cf.
    # tests/e2e/fixtures/quic_initial.bin) en un datagramme UDP vers
    # 10.42.0.50:443. La règle nft `udp dport 443 → queue SNI` (placement
    # integral) l'achemine vers worker_tls, qui le classe protocol=quic et
    # journalise la capture. UDP étant sans connexion, aucun listener n'est
    # requis ; l'alias 10.42.0.50 monté sur via (plus haut) répond à l'ARP.
    # Le busybox `nc` des images OpenWrt est l'applet minimal (TCP seul, pas
    # d'option -u) : on utilise socat pour émettre le datagramme UDP. socat n'est
    # pas préinstallé ; on l'ajoute via apk (servus a internet par le NAT de via).
    # Faute de réseau pour l'installer, on `skip` « dépendance manquante » plutôt
    # que d'échouer (cohérent avec G0b).
    QUIC_FIXTURE="$PROJECT_DIR/tests/e2e/fixtures/quic_initial.bin"
    has_socat=$(ssh_vm "$E2E_IP_SERVUS" "
        command -v socat >/dev/null 2>&1 || { apk add socat >/dev/null 2>&1 || opkg install socat >/dev/null 2>&1; }
        command -v socat >/dev/null 2>&1 && echo OK")
    if [ ! -f "$QUIC_FIXTURE" ]; then
        fail "T125 QUIC Initial" "fixture absente ($QUIC_FIXTURE)"
    elif [ "$has_socat" != "OK" ]; then
        skip "T125 QUIC Initial" "dépendance manquante : socat indisponible (pas de réseau pour l'installer)"
    elif ! scp -O $SSH_OPTS -i "$SSH_KEY" -q "$QUIC_FIXTURE" \
              "root@${E2E_IP_SERVUS}:/tmp/quic_initial.bin" 2>/dev/null; then
        fail "T125 QUIC Initial" "échec du scp de la fixture vers servus"
    else
        # Pré-résout site-a.lan → autorise la paire (servus, 10.42.0.50).
        dig_from "$E2E_IP_SERVUS" "site-a.lan" "A" >/dev/null
        for i in 1 2 3; do
            ssh_vm "$E2E_IP_SERVUS" \
                "socat -t1 -T1 -u OPEN:/tmp/quic_initial.bin UDP-SENDTO:${SNI_DEST}:443 >/dev/null 2>&1 || true"
            sleep 1
        done
        sleep 2
        logs=$(custos_logs)
        if echo "$logs" | grep -qE "protocol=quic|l4_proto=udp|worker=sni-quic"; then
            ok "T125 worker_tls traite un QUIC Initial (UDP/443, rejeu de capture)"
        else
            fail "T125 QUIC Initial" "aucun log quic après rejeu du datagramme UDP/443"
        fi
        ssh_vm "$E2E_IP_SERVUS" "rm -f /tmp/quic_initial.bin" || true
    fi

    sni_listener_stop
fi

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 15 — Mode lowmem : désactivation des workers tls et doh
# Injecte runtime: { lowmem: "on" } dans la config, redémarre custos et vérifie
# que le worker tls (SNI) n'est pas démarré, que les queues sont réduites à une
# seule file, et que le filtrage DNS reste opérationnel. Restaure ensuite la
# config d'origine.
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G15 : mode lowmem (désactivation workers tls/doh) ==="

LOWMEM_TMP=$(mktemp -d)
LOWMEM_CLEANUP_DONE=0

lowmem_cleanup() {
    [ "$LOWMEM_CLEANUP_DONE" -eq 1 ] && return
    LOWMEM_CLEANUP_DONE=1
    if [ -f "$LOWMEM_TMP/config_orig.moon" ]; then
        scp -O -q $SSH_OPTS -i "$SSH_KEY" \
            "$LOWMEM_TMP/config_orig.moon" "root@${E2E_IP_CUSTOS}:/etc/custos/config.moon" 2>/dev/null || true
        ssh_vm "$E2E_IP_CUSTOS" "/etc/init.d/custos restart >/dev/null 2>&1; sleep 3" || true
    fi
    rm -rf "$LOWMEM_TMP"
}
trap 'lowmem_cleanup' EXIT

# Sauvegarde la config d'origine
scp -O -q $SSH_OPTS -i "$SSH_KEY" \
    "root@${E2E_IP_CUSTOS}:/etc/custos/config.moon" "$LOWMEM_TMP/config_orig.moon"

# Injecte lowmem: "on" dans le bloc runtime: existant, ou crée le bloc si absent.
# Une clé dupliquée serait écrasée par Lua (dernière valeur gagne) ; on injecte
# donc à l'intérieur du bloc existant plutôt qu'en créant un nouveau.
if grep -q 'runtime:' "$LOWMEM_TMP/config_orig.moon"; then
    awk '!ins && /runtime:[[:space:]]*\{/ {print; print "    lowmem: \"on\""; ins=1; next} {print}' \
        "$LOWMEM_TMP/config_orig.moon" > "$LOWMEM_TMP/config_lowmem.moon"
else
    awk '!ins && /^[[:space:]]*\{[[:space:]]*$/ {print; print "  runtime: { lowmem: \"on\" }"; ins=1; next} {print}' \
        "$LOWMEM_TMP/config_orig.moon" > "$LOWMEM_TMP/config_lowmem.moon"
fi

scp -O -q $SSH_OPTS -i "$SSH_KEY" \
    "$LOWMEM_TMP/config_lowmem.moon" "root@${E2E_IP_CUSTOS}:/etc/custos/config.moon"

ssh_vm "$E2E_IP_CUSTOS" "/etc/init.d/custos restart >/dev/null 2>&1; sleep 4"

# T130 : logread mentionne la réduction des queues (lowmem_collapse_queues)
lm_logs=$(ssh_vm "$E2E_IP_CUSTOS" "logread 2>/dev/null" | grep "custos" || true)
assert_contains "T130 lowmem_collapse_queues journalisé" "lowmem_collapse_queues" "$lm_logs"

# T131 : le worker tls (SNI) ne tourne pas
# Les workers Custos ont leur comm mis à "custos:<name>" via prctl.
# On cherche dans /proc/*/comm pour être indépendant du format de ps busybox.
tls_running=$(ssh_vm "$E2E_IP_CUSTOS" \
    "grep -rl 'custos:tls' /proc/*/comm 2>/dev/null | wc -l")
assert_eq "T131 worker tls absent en mode lowmem" "${tls_running:-0}" "0"

# T132 : le worker doh ne tourne pas (il n'est pas configuré par défaut et
# le mode lowmem le bloquerait de toute façon si activé)
doh_running=$(ssh_vm "$E2E_IP_CUSTOS" \
    "grep -rl 'custos:doh' /proc/*/comm 2>/dev/null | wc -l")
assert_eq "T132 worker doh absent en mode lowmem" "${doh_running:-0}" "0"

# T133 : le filtrage DNS reste opérationnel (domaine autorisé)
lm_dig=$(dig_from "$E2E_IP_SERVUS" "site-a.lan" "A" "+short" 2>/dev/null || true)
if [ -n "$lm_dig" ]; then
    ok "T133 filtrage DNS opérationnel en lowmem (site-a.lan résolu)"
else
    fail "T133 filtrage DNS opérationnel en lowmem" "site-a.lan non résolu"
fi

# T134 : un domaine bloqué reste bloqué
lm_blocked=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A" "+noall" "+comments" 2>/dev/null || true)
if echo "$lm_blocked" | grep -q "NXDOMAIN\|REFUSED"; then
    ok "T134 domaine bloqué rejeté en lowmem (blocked.lan)"
else
    fail "T134 domaine bloqué rejeté en lowmem" "blocked.lan non bloqué (réponse: $lm_blocked)"
fi

# Restauration
lowmem_cleanup

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 16 — Rotation d'adresse IPv6 (Privacy Extensions)
# Vérifie que worker_captive reconnaît une MAC authentifiée dont l'adresse
# IPv6 temporaire a changé (Privacy Extensions) : pas de redirection captive,
# nouvelle IP injectée dans authenticated_ips6, action loguée
# captive_skip_authenticated.
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G16 : rotation IPv6 (Privacy Extensions / captive_skip_authenticated) ==="

servus_ip=$(servus_data_ip4)
if [ -z "$servus_ip" ]; then
    skip "T140-T143 rotation IPv6" "IP data-plane IPv4 de servus introuvable"
else
    flush_state

    # IPv6 initiale et IPv6 «rotée»
    IPV6_OLD="fd42:42:0:1::99"
    IPV6_NEW="fd42:42:0:1::98"
    # Destination non-ULA pour le SYN TCP/80 de test : hors fc00::/7, donc
    # non court-circuitée par la règle nft `ip6 daddr fc00::/7 accept`.
    # OpenWrt ip ne supporte pas `nodad`, on laisse le DAD se terminer.
    IPV6_TEST_DEST="2001:db8:e2e::1"

    # ── Setup réseau (avant le chrono de session idle_timeout=10s) ─────────────
    # Alias non-ULA sur via : on le démarre en premier pour que son DAD (~1s)
    # se termine avant d'en avoir besoin.
    ssh_vm "$E2E_IP_VIA" \
        "ip -6 addr add ${IPV6_TEST_DEST}/64 dev eth1 2>/dev/null || true"

    # Assure IPV6_OLD sur servus ; IPV6_NEW retiré si présent.
    ssh_vm "$E2E_IP_SERVUS" "
        ip -6 addr del ${IPV6_NEW}/64 dev eth0 2>/dev/null || true
        ip -6 addr add ${IPV6_OLD}/64 dev eth0 2>/dev/null || true
    "

    sleep 3   # DAD via + DAD servus IPV6_OLD

    # Route ajoutée APRÈS le DAD : IPV6_OLD doit être PREFERRED pour que le
    # noyau accepte la route avec source ULA (fd42:42:0:1::99 → via fd42:42:0:1::1).
    ssh_vm "$E2E_IP_SERVUS" \
        "ip -6 route add 2001:db8:e2e::/64 via fd42:42:0:1::1 dev eth0 2>/dev/null || true"

    # Amorçage mac_learner (voir G16 run précédent).
    # Ce dig est aussi suffisamment ancien (>5s) pour que le cache sessions
    # (CACHE_TTL=5s) soit expiré naturellement au premier dig post-login.
    dig_from "$E2E_IP_SERVUS" "site-a.lan" "A" >/dev/null
    sleep 1

    # ── Login alice (session créée ; expires = now + idle_timeout) ─────────────
    login_from_servus "alice@test.lan" "motdepasse123" >/dev/null

    # Vérifier le cookie ; skip si login échoué
    if ! ssh_vm "$E2E_IP_SERVUS" \
            "test -s /tmp/e2e_cookies.txt && grep -q custos_session /tmp/e2e_cookies.txt && echo OK" \
            | grep -q OK; then
        skip "T140-T143 rotation IPv6" "login alice échoué (pas de cookie custos_session)"
    else
        # sleep 1 : sessions.lua écrite + cache sessions expiré naturellement
        # (dernier dig = >5s avant login, donc CACHE_TTL déjà dépassé).
        sleep 1

        # T140 : session active avant rotation (précondition)
        resp=$(dig_from "$E2E_IP_SERVUS" "blocked.lan" "A")
        assert_eq "T140 session alice active avant rotation IPv6" \
                  "$(dns_status "$resp")" "NOERROR"

        # ── Rotation dans la fenêtre de validité de session (~10s) ─────────────
        # Vide authenticated_macs pour simuler l'expiration naturelle de l'élément
        # nft (en production : expiration entre deux pings lors d'une rotation
        # rapide, ou après restart — scenario couvert par G12 restart+replay).
        ssh_vm "$E2E_IP_CUSTOS" \
            "nft flush set bridge dns-filter-bridge authenticated_macs 2>/dev/null || true"

        # Rotation IPv6 : del IPV6_OLD, add IPV6_NEW.
        ssh_vm "$E2E_IP_SERVUS" "
            ip -6 addr del ${IPV6_OLD}/64 dev eth0 2>/dev/null || true
            ip -6 addr add ${IPV6_NEW}/64 dev eth0 2>/dev/null || true
        "
        sleep 2   # DAD pour IPV6_NEW (~1s) + marge

        # SYN TCP/80 depuis IPV6_NEW vers la destination non-ULA.
        # IPV6_NEW ∉ authenticated_ips6, MAC ∉ authenticated_macs (vidé ci-dessus)
        # → QUEUE_CAPTIVE → worker_captive → user_for_mac → session valide (~5s
        # après login, idle_timeout=10s) → captive_skip_authenticated.
        ssh_vm "$E2E_IP_SERVUS" \
            "curl -m 2 --interface ${IPV6_NEW} 'http://[${IPV6_TEST_DEST}]/' >/dev/null 2>&1 || true"
        sleep 1

        logs=$(custos_logs)

        # T141 : captive_skip_authenticated loguée pour IPV6_NEW
        assert_log_has "T141 captive_skip_authenticated loguée pour la nouvelle IPv6" \
            "$logs" "captive_skip_authenticated" "${IPV6_NEW}"

        # T142 : IPV6_NEW présente dans authenticated_ips6
        if nft_set_contains "authenticated_ips6" "$IPV6_NEW"; then
            ok "T142 authenticated_ips6 contient la nouvelle IPv6 ${IPV6_NEW}"
        else
            fail "T142 authenticated_ips6 contient la nouvelle IPv6 ${IPV6_NEW}" \
                 "entrée absente du set"
        fi

        # T143 : pas de redirect_captive pour IPV6_NEW (session valide → skip)
        if echo "$logs" | grep -F "redirect_captive" | grep -qF "${IPV6_NEW}"; then
            fail "T143 pas de redirect_captive pour ${IPV6_NEW}" \
                 "log redirect_captive trouvé (302 forguée à tort)"
        else
            ok "T143 pas de redirect_captive pour ${IPV6_NEW}"
        fi

        # Nettoyage
        ssh_vm "$E2E_IP_SERVUS" "
            ip -6 addr del ${IPV6_NEW}/64 dev eth0 2>/dev/null || true
            ip -6 addr del ${IPV6_OLD}/64 dev eth0 2>/dev/null || true
            ip -6 route del 2001:db8:e2e::/64 dev eth0 2>/dev/null || true
        " || true
        ssh_vm "$E2E_IP_VIA" \
            "ip -6 addr del ${IPV6_TEST_DEST}/64 dev eth1 2>/dev/null || true" || true
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 17 — validate_resolvers per-règle (second avis DNS sélectif)
# Vérifie que :
#   T170 : un résolveur per-règle est armé au démarrage (dns_validator_armed)
#   T171 : le filtrage DNS normal reste opérationnel (fail-open transparent)
#   T172 : une requête ciblant la règle validate passe (fail-open, pas REFUSED)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G17 : validate_resolvers per-règle (second avis DNS sélectif) ==="

VAL_TMP=$(mktemp -d)
VAL_CLEANUP_DONE=0
# IP routable mais sans DNS : 10.42.0.253 est sur le sous-réseau homelab (10.42.0.0/24)
# mais n'est assignée à aucune VM → pas de réponse du validateur → fail-open.
VAL_RESOLVER_IP="10.42.0.253"
VAL_TEST_DOMAIN="e2e-validator-test.lan"

val_cleanup() {
    [ "$VAL_CLEANUP_DONE" -eq 1 ] && return
    VAL_CLEANUP_DONE=1
    if [ -f "$VAL_TMP/config_orig.moon" ]; then
        scp -O -q $SSH_OPTS -i "$SSH_KEY" \
            "$VAL_TMP/config_orig.moon" "root@${E2E_IP_CUSTOS}:/etc/custos/config.moon" 2>/dev/null || true
        ssh_vm "$E2E_IP_CUSTOS" "/etc/init.d/custos restart >/dev/null 2>&1; sleep 3" || true
    fi
    rm -rf "$VAL_TMP"
}
trap 'val_cleanup; lowmem_cleanup' EXIT

# Sauvegarde la config d'origine
scp -O -q $SSH_OPTS -i "$SSH_KEY" \
    "root@${E2E_IP_CUSTOS}:/etc/custos/config.moon" "$VAL_TMP/config_orig.moon"

# Étape 1 : injecter second_opinion (sans résolveur global) après l'accolade ouvrante.
# Si un bloc second_opinion existe déjà, on l'écrase via une clé dupliquée (Lua :
# dernière valeur gagne) — on injecte donc avant la première règle plutôt qu'à
# l'intérieur d'un éventuel bloc existant.
awk -v ip="$VAL_RESOLVER_IP" -v dom="$VAL_TEST_DOMAIN" '
    !ins_so && /^[[:space:]]*\{[[:space:]]*$/ {
        print
        print "  second_opinion: { resolvers: {}, budget_ms: 300, fail_open: true }"
        ins_so=1
        next
    }
    !ins_rule && /rules:[[:space:]]*\{/ {
        print
        print "      {"
        print "        rule_id:            \"e2e_validate_per_rule\""
        print "        description:        \"E2E validate_resolvers per-règle\""
        print "        actions:            {\"validate\"}"
        print "        validate_resolvers: {\"" ip "\"}"
        print "        conditions:         { to_domain: \"" dom "\" }"
        print "      }"
        ins_rule=1
        next
    }
    { print }
' "$VAL_TMP/config_orig.moon" > "$VAL_TMP/config_val.moon"

scp -O -q $SSH_OPTS -i "$SSH_KEY" \
    "$VAL_TMP/config_val.moon" "root@${E2E_IP_CUSTOS}:/etc/custos/config.moon"

ssh_vm "$E2E_IP_CUSTOS" "/etc/init.d/custos restart >/dev/null 2>&1; sleep 4"

# Lecture des logs après redémarrage (fenêtre large pour ne pas rater le log de démarrage)
val_logs=$(ssh_vm "$E2E_IP_CUSTOS" "logread 2>/dev/null" | grep "custos" | tail -200)

# T170 : dns_validator_armed journalisée avec le résolveur per-règle
assert_log_has "T170 dns_validator_armed avec résolveur per-règle ($VAL_RESOLVER_IP)" \
    "$val_logs" "dns_validator_armed" "$VAL_RESOLVER_IP"

# T171 : le filtrage DNS classique reste opérationnel (rule homelab_not_blocked)
val_dig=$(dig_from "$E2E_IP_SERVUS" "site-a.lan" "A" "+short" 2>/dev/null || true)
if [ -n "$val_dig" ]; then
    ok "T171 DNS opérationnel après injection validate_resolvers (site-a.lan résolu)"
else
    fail "T171 DNS opérationnel après injection validate_resolvers" \
         "site-a.lan non résolu (val_dig vide)"
fi

# T172 : requête ciblant la règle validate → fail-open (pas REFUSED de custos)
# Le domaine n'existe pas dans le DNS local → NXDOMAIN attendu depuis l'upstream ;
# un REFUSED ou SERVFAIL serait le signe que custos a bloqué au lieu de fail-open.
val_dig2=$(dig_from "$E2E_IP_SERVUS" "$VAL_TEST_DOMAIN" "A" "+noall" "+comments" 2>/dev/null || true)
if echo "$val_dig2" | grep -qiE "NOERROR|NXDOMAIN"; then
    ok "T172 fail-open validate_resolvers : réponse upstream (pas REFUSED)"
elif echo "$val_dig2" | grep -qi "REFUSED"; then
    fail "T172 fail-open validate_resolvers" \
         "custos a refusé la requête (REFUSED) au lieu de fail-open"
else
    fail "T172 fail-open validate_resolvers" \
         "réponse inattendue : $val_dig2"
fi

val_cleanup
VAL_CLEANUP_DONE=1

# ══════════════════════════════════════════════════════════════════════════════
# GROUPE 18 — Timeout des connexions muettes au portail (client_timeout)
# Une connexion TLS qui n'envoie jamais de requête (préconnexion spéculative de
# navigateur) doit libérer son processus AUTH-conn après client_timeout (15 s
# par défaut) au lieu de rester suspendue indéfiniment.
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== G18 : timeout connexions muettes (client_timeout) ==="

if command -v openssl >/dev/null 2>&1; then
    # 2 connexions TLS muettes tenues ouvertes (-quiet implique -ign_eof :
    # openssl ne ferme pas sur EOF stdin, il faut le tuer explicitement)
    (sleep 60 | openssl s_client -connect "$E2E_IP_CUSTOS:33443" -quiet >/dev/null 2>&1) &
    MUTE_PID1=$!
    (sleep 60 | openssl s_client -connect "$E2E_IP_CUSTOS:33443" -quiet >/dev/null 2>&1) &
    MUTE_PID2=$!
    sleep 4

    mute_children=$(ssh_vm "$E2E_IP_CUSTOS" "ps w | grep AUTH-con | grep -v grep | wc -l")
    if [ "${mute_children:-0}" -ge 2 ]; then
        ok "T180 connexions muettes : enfants AUTH-conn présents"
    else
        fail "T180 connexions muettes : enfants AUTH-conn présents" \
             "attendu ≥2, obtenu ${mute_children:-0}"
    fi

    # client_timeout=15s par défaut ; pire cas timeout + un SO_RCVTIMEO
    # (arrondi d'horloge) ≈ 30 s → vérifier à t+36s
    sleep 32
    mute_children=$(ssh_vm "$E2E_IP_CUSTOS" "ps w | grep AUTH-con | grep -v grep | wc -l")
    assert_eq "T181 enfants AUTH-conn libérés après client_timeout" "${mute_children:-?}" "0"

    # Le portail répond toujours normalement
    portal_code=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' \
        "https://$E2E_IP_CUSTOS:33443/login" 2>/dev/null || echo 0)
    if echo "$portal_code" | grep -qE '^(200|302)$'; then
        ok "T182 portail fonctionnel après libération"
    else
        fail "T182 portail fonctionnel après libération" "code HTTP : $portal_code"
    fi

    kill "$MUTE_PID1" "$MUTE_PID2" 2>/dev/null || true
    pkill -f "openssl s_client -connect $E2E_IP_CUSTOS:33443" 2>/dev/null || true
else
    echo "  (openssl absent : G18 sauté)"
fi

# ─── RAPPORT FINAL ─────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────────"
printf "Résultats : %d passed, %d failed\n" "$PASS" "$FAIL"
echo "─────────────────────────────────────────"
[ "$FAIL" -eq 0 ] || exit 1
