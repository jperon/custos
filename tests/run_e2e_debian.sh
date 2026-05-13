#!/usr/bin/env bash
# tests/run_e2e_debian.sh
# Suite E2E custos sur environnement Vagrant 3 VMs Debian.
#
# Prérequis : vagrant up dns filter client

set -euo pipefail

cd "$(dirname "$0")/.."

C_RED='\033[31m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_BOLD='\033[1m'
C_RESET='\033[0m'
C_GREY='\033[90m'

passed=0
failed=0

test_ok()  { echo -e "  ${C_GREEN}✓ $1${C_RESET}"; ((passed++)) || true; }
test_ko()  { echo -e "  ${C_RED}✗ $1${C_RESET}"; ((failed++)) || true; echo -e "    ${C_GREY}$2${C_RESET}"; }

# ── Récupération config Vagrant ─────────────────────────────────────

FILTER_IP=$(vagrant ssh-config filter 2>/dev/null | awk '/HostName/{print $2}')
FILTER_KEY=$(vagrant ssh-config filter 2>/dev/null | awk '/IdentityFile/{print $2}')
CLIENT_IP="10.99.0.10"
DNS_IP="10.99.0.1"
FILTER_BR="10.99.0.254"
CAPTIVE_URL="https://${FILTER_BR}:33443/"

if [ -z "$FILTER_IP" ] || [ -z "$FILTER_KEY" ]; then
    echo -e "${C_RED}✗ Impossible de récupérer la config Vagrant du filtre${C_RESET}"
    exit 1
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR -i $FILTER_KEY"

ssh_filter() { ssh $SSH_OPTS vagrant@$FILTER_IP "$@"; }
ssh_client() { vagrant ssh client -c "$@" 2>/dev/null; }

# ── [1/4] Connectivité ─────────────────────────────────────────────

echo -e "${C_BOLD}CustosVirginum — tests E2E Vagrant/Debian${C_RESET}"
echo "  Filtre mgmt : $FILTER_IP"
echo "  Client      : $CLIENT_IP"
echo "  DNS         : $DNS_IP"
echo ""

echo -e "${C_BOLD}[1/4] Connectivité${C_RESET}"

if ssh_filter "uname -r" >/dev/null 2>&1; then
    test_ok "filter joignable"
else
    test_ko "filter joignable" "SSH vers $FILTER_IP échoué"
    exit 1
fi

if ssh_client "uname -r" >/dev/null 2>&1; then
    test_ok "client joignable"
else
    test_ko "client joignable" "SSH vers client échoué"
    exit 1
fi

if ssh_client "host -W 2 -t A allowed.test $DNS_IP" | grep -q '10.99.0.50'; then
    test_ok "client → DNS (via filtre) fonctionne"
else
    test_ko "client → DNS (via filtre) fonctionne" "DNS non joignable"
    exit 1
fi

# ── [2/4] Déploiement custos ─────────────────────────────────────

echo -e "\n${C_BOLD}[2/4] Déploiement custos${C_RESET}"

echo "  Compilation locale..."
make all >/dev/null 2>&1 || true

echo "  Copie des fichiers Lua sur le filtre..."
ssh_filter "sudo mkdir -p /usr/share/custos /etc/custos /var/log/custos && sudo chown vagrant /var/log/custos"
rsync -az -e "ssh $SSH_OPTS" --delete lua/ vagrant@$FILTER_IP:/tmp/custos-deploy/ >/dev/null 2>&1
rsync -az -e "ssh $SSH_OPTS" nft-rules/ vagrant@$FILTER_IP:/tmp/custos-deploy/ >/dev/null 2>&1
ssh_filter "sudo rm -rf /usr/share/custos/* && sudo cp -a /tmp/custos-deploy/* /usr/share/custos/ && sudo chown -R root:root /usr/share/custos"

# Copie du libwolfssl si absent
if ! ssh_filter "ldconfig -p | grep -q libwolfssl" 2>/dev/null; then
    echo "  Copie de libwolfssl..."
    WOLF=$(ldconfig -p | grep 'libwolfssl' | awk '{print $4}' | head -1 || true)
    if [ -n "$WOLF" ]; then
        scp $SSH_OPTS "$WOLF" vagrant@$FILTER_IP:/tmp/libwolfssl.so.1 >/dev/null 2>&1
        ssh_filter "sudo cp /tmp/libwolfssl.so.1 /usr/lib/x86_64-linux-gnu/ && sudo ln -sf libwolfssl.so.1 /usr/lib/x86_64-linux-gnu/libwolfssl.so && sudo ldconfig"
    fi
fi

# Génération de config.lua minimal (pas d'UCI sur Debian)
echo "  Génération config.lua..."
ssh_filter "sudo mkdir -p /var/run/custos"
cat > /tmp/config.lua <<'LUAEOF'
return {
  QUEUE_QUESTIONS = '0-1',
  QUEUE_RESPONSES = '4',
  QUEUE_CAPTIVE   = '20',
  QUEUE_REJECT    = '10-11',
  QUEUE_AUTH      = '5',
  NFT_FAMILY      = 'bridge',
  NFT_FAMILY6     = 'bridge',
  NFT_TABLE       = 'dns-filter-bridge',
  NFT_SET_IP4     = 'ip4_allowed',
  NFT_SET_IP6     = 'ip6_allowed',
  NFT_SET_MAC4    = 'mac4_allowed',
  NFT_SET_MAC6    = 'mac6_allowed',
  NFT_IP_TIMEOUT  = '2m',
  NFT_ADD_RETRY_COUNT = 6,
  NFT_ADD_BACKOFF_MS = {20, 50, 100, 200, 400, 800},
  NFT_ADD_FAILURE_POLICY = 'fail-closed',
  NFT_ACK_TIMEOUT_MS = 150,
  IPC_PENDING_TTL = 5,
  IPC_MATCH_RETRY_ENABLED = true,
  IPC_MATCH_RETRY_COUNT = 5,
  IPC_MATCH_RETRY_SLEEP_MS = 20,
  CLIENT_EXPIRY = 300,
  MAC_LEARNER_QUERY_SOCK = '/var/run/custos/mac_query.sock',
  MAC_LEARNER_LEARN_MSG_SIZE = 22,
  MAC_LEARNER_ENTRY_TTL = 300,
  FORCED_TTL = 60,
  DNS_PORT = 53,
  AF_INET = 2,
  AF_INET6 = 10,
  AUTH_SESSIONS_FILE = './tmp/sessions.lua',
  EVENTS_DIR = '/tmp/custos/events',
  EVENTS_MAX_AGE_HOURS = 168,
  EVENTS_MIN_FREE_PCT = 30,
  DEST_WHITELIST = {},
  ALLOWED_DOMAINS = {'local', 'lan', 'home.arpa'},
  NFT_EXTRA_RULES = {},
  LOG_LEVEL = 'INFO',
  DOH_ENABLED = '1',
  DOH_PORT = 8443,
  DOH_UPSTREAM_IPV4 = '1.1.1.3',
  DOH_UPSTREAM_IPV6 = '2606:4700:4700::1113',
  DOH_UPSTREAM_PORT = 53,
  DOH_UPSTREAM_TIMEOUT_MS = 2000,
  DOH_CERT_PATH = '',
  DOH_KEY_PATH = '',
  DOH_PREFER_IPV6 = '1',
}
LUAEOF
scp $SSH_OPTS /tmp/config.lua vagrant@$FILTER_IP:/tmp/config.lua >/dev/null 2>&1
ssh_filter "sudo cp /tmp/config.lua /var/run/custos/config.lua"

# Création du /etc/custos et copie de config.moon
ssh_filter "sudo mkdir -p /etc/custos"
scp $SSH_OPTS libvirt/config.moon vagrant@$FILTER_IP:/tmp/config.moon >/dev/null 2>&1
ssh_filter "sudo cp /tmp/config.moon /etc/custos/config.moon"

# Création d'un service systemd minimal pour custos
echo "  Création du service systemd custos..."
ssh_filter "sudo tee /etc/systemd/system/custos.service >/dev/null <<'EOF'
[Unit]
Description=CustosVirginum DNS Filter
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/luajit /usr/share/custos/main.lua
Environment=LUA_PATH=/usr/share/custos/?.lua;/usr/share/custos/?/init.lua;;
Environment=LUA_CPATH=/usr/lib/x86_64-linux-gnu/lua/5.1/?.so;;
Environment=CUSTOS_CONFIG_PATH=/etc/custos/config.moon
Restart=always
RestartSec=2
StandardOutput=file:/var/log/custos/custos.log
StandardError=file:/var/log/custos/custos.log

[Install]
WantedBy=multi-user.target
EOF"

ssh_filter "sudo systemctl daemon-reload && sudo systemctl enable custos"

# Substitution des placeholders et application des règles nftables
echo "  Application des règles nftables..."
ssh_filter "sed -e 's/{QUEUE_QUESTIONS}/0-1/g' -e 's/{QUEUE_RESPONSES}/4/g' -e 's/{QUEUE_CAPTIVE}/20/g' -e 's/{QUEUE_REJECT}/10-11/g' -e 's/{QUEUE_AUTH}/5/g' -e 's/{NFT_IP_TIMEOUT}/2m/g' /usr/share/custos/dns-filter-bridge.nft > /tmp/custos-rules.nft && sudo nft -f /tmp/custos-rules.nft" 2>/dev/null || true

# Démarrage du service
echo "  Démarrage custos..."
ssh_filter "sudo systemctl stop custos 2>/dev/null || true"
ssh_filter "sudo systemctl start custos"

# ── [3/4] Attente des workers ──────────────────────────────────────

echo -e "\n${C_BOLD}[3/4] Attente des workers${C_RESET}"

workers_ready=false
for i in $(seq 1 30); do
    count=$(ssh_filter "grep -c 'queue_listening' /var/log/custos/custos.log 2>/dev/null || true")
    if [ -n "$count" ] && [ "$count" -ge 3 ] 2>/dev/null; then
        workers_ready=true
        break
    fi
    sleep 2
done

if $workers_ready; then
    test_ok "workers prêts"
else
    test_ko "workers prêts" "Pas assez de workers après 60s"
    ssh_filter "tail -n 40 /var/log/custos/custos.log" || true
    exit 1
fi

# ── [4/4] Tests fonctionnels (depuis le client) ───────────────────

echo -e "\n${C_BOLD}[4/4] Tests fonctionnels (depuis le client)${C_RESET}"

# 1. DNS allow
out=$(ssh_client "host -W 2 -t A allowed.test $DNS_IP" 2>/dev/null || true)
if echo "$out" | grep -q '10.99.0.50'; then
    test_ok "host allowed.test → 10.99.0.50"
else
    test_ko "host allowed.test → 10.99.0.50" "$out"
fi

# 2. DNS block
out=$(ssh_client "host -W 2 -t A blocked.test $DNS_IP" 2>/dev/null || true)
if echo "$out" | grep -q 'NXDOMAIN'; then
    test_ok "host blocked.test → NXDOMAIN"
else
    test_ko "host blocked.test → NXDOMAIN" "$out"
fi

# 3. DNS default deny
out=$(ssh_client "host -W 2 -t A nonexistent.invalid $DNS_IP" 2>/dev/null || true)
if echo "$out" | grep -q 'NXDOMAIN'; then
    test_ok "host nonexistent.invalid → NXDOMAIN"
else
    test_ko "host nonexistent.invalid → NXDOMAIN" "$out"
fi

# 4. HTTP allowed (depuis le client vers le DNS — si un serveur HTTP tourne sur 10.99.0.50)
# NOTE: le test HTTP nécessite qu'un serveur web tourne sur l'IP allowed.test.
# Pour l'instant on ne teste que la résolution DNS.

# ── Résumé ─────────────────────────────────────────────────────────

echo ""
echo -e "${C_BOLD}Résultat${C_RESET} : $passed passés, $failed échoués"

if [ "$failed" -gt 0 ]; then
    exit 1
fi
