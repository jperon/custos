-- tests/test_openwrt.moon
--
-- OpenWrt end-to-end test for CustosVirginum DNS filter (live deployment).
-- Connects to a running OpenWrt router via SSH and tests all functionality.
--
-- Architecture tested:
--   [router FORWARD chain] -- queue 0/1 --> worker Q0/Q1
--   LuaJIT workers + auth server (33443) + captive portal (33080)
--
-- DNS queries are sent from the local machine to an EXTERNAL resolver (8.8.8.8).
-- Those packets transit the router's FORWARD chain, where NFQUEUE intercepts
-- them (Q0 decides allow/deny, Q1 patches the response).
-- Auth curl source IP = LOCAL_IP = DNS query source IP → from_user matches.
--
-- Usage:
--   luajit tests/test_openwrt.lua root@esm.y
--   luajit tests/test_openwrt.lua root@esm.y --no-restart
--   make test-openwrt HOST=root@esm.y

-- ── Constants ──────────────────────────────────────────────────────────────────

CUSTOS_DIR    = "/usr/share/custos"
CFG_DIR       = "/etc/custos"
LOG_FILE      = "#{CUSTOS_DIR}/tmp/custos.log"
SESSIONS_FILE = "#{CUSTOS_DIR}/tmp/sessions.lua"

DOMAIN_ALLOWED = "github.com"
DOMAIN_AAAA    = "cloudflare.com"
DOMAIN_BLOCKED = "facebook.com"
DOMAIN_UNKNOWN = "nonexistent.invalid"
DOMAIN_AUTH    = "auth-required.test"

C =
  red:    "\27[31m"
  green:  "\27[32m"
  yellow: "\27[33m"
  bold:   "\27[1m"
  reset:  "\27[0m"
  grey:   "\27[90m"

tests_passed = 0
tests_failed = 0

-- ── Argument parsing ───────────────────────────────────────────────────────────

SSH_TARGET = nil
no_restart = false

for _, a in ipairs arg or {}
  if a\match "^%-%-no%-restart"
    no_restart = true
  elseif (not a\match "^%-%-") and not SSH_TARGET
    SSH_TARGET = a

unless SSH_TARGET
  io.stderr\write "Usage: #{arg[0] or 'test_openwrt'} user@host [--no-restart]\n"
  os.exit 1

SSH_OPTS = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes"
-- Use legacy SCP protocol (-O) because OpenWrt does not have sftp-server.
SCP_OPTS = "-O #{SSH_OPTS}"

-- ── Helpers ────────────────────────────────────────────────────────────────────

--- Run a local shell command; return (ok, output).
-- @tparam string cmd
-- @treturn boolean ok
-- @treturn string  output (stdout+stderr)
run = (cmd) ->
  fh = io.popen "#{cmd} 2>&1"
  out = fh\read "*a"
  ok  = fh\close!
  ok, out

--- SSH to the router; return (ok, output).
-- @tparam string cmd Shell command to run on the router
-- @treturn boolean ok
-- @treturn string  output (stdout+stderr)
ssh = (cmd) ->
  escaped = cmd\gsub("'", "'\\''")
  run "ssh #{SSH_OPTS} #{SSH_TARGET} '#{escaped}'"

--- SSH to the router; raise on failure.
-- @tparam string cmd
-- @treturn string output
ssh_check = (cmd) ->
  ok, out = ssh cmd
  error "SSH failed: #{cmd}\n#{out}" unless ok
  out

--- Record and print a test result.
-- @tparam string         name  Test description
-- @tparam boolean|function ok  true/false or a 0-arity function returning (ok, msg)
-- @tparam[opt] string    msg   Context shown on failure
report = (name, ok, msg) ->
  if type(ok) == "function"
    ok, msg = ok!
  if ok
    tests_passed += 1
    print "  #{C.green}✓#{C.reset} #{name}"
  else
    tests_failed += 1
    print "  #{C.red}✗ #{name}#{C.reset}"
    if msg and msg\match "%S"
      print "    #{C.grey}#{(msg\gsub '%s+$', '')\sub 1, 200}#{C.reset}"

-- ── Header ─────────────────────────────────────────────────────────────────────

print "#{C.bold}CustosVirginum — OpenWrt end-to-end tests#{C.reset}"
print "  Cible SSH : #{SSH_TARGET}"
print ""

-- ── [1/5] Connectivity check ───────────────────────────────────────────────────

print "#{C.bold}[1/5] Vérification de la connexion SSH...#{C.reset}"

ok_ssh, kernel = ssh "uname -r"
unless ok_ssh
  print "  #{C.red}✗ Impossible de joindre #{SSH_TARGET}#{C.reset}"
  os.exit 1
print "  Noyau : #{kernel\gsub '%s+$', ''}"

-- Detect LAN IP (bridge's primary IPv4 address, used for auth URL)
_, lan_raw = ssh "ip addr show br 2>/dev/null | grep -m1 'inet ' | awk '{print $2}' | cut -d'/' -f1"
LAN_IP = lan_raw and lan_raw\match "%d+%.%d+%.%d+%.%d+"
LAN_IP = LAN_IP or "127.0.0.1"
-- Detect LOCAL_IP (this machine's IP as seen by the router, used as session key)
_, local_raw = run "ip route get #{LAN_IP} 2>/dev/null | sed -En 's/.*src ([0-9.]+).*/\\1/p' | head -1"
LOCAL_IP = local_raw and local_raw\match "%d+%.%d+%.%d+%.%d+"
LOCAL_IP = LOCAL_IP or "127.0.0.1"
print "  IP locale : #{LOCAL_IP}"
-- Detect LOCAL_IPV6 (IPv6 source address routed via the bridge, for AAAA tests)
-- When a DNS query is sent over IPv6, Q1 directly knows client_v6 without MAC lookup.
_, local_v6_raw = run "ip -6 route get 2001:4860:4860::8888 2>/dev/null | sed -En 's/.*src ([0-9a-f:]+).*/\\1/p' | head -1"
LOCAL_IPV6 = local_v6_raw and local_v6_raw\match "[0-9a-f]+:[0-9a-f:]+"
print "  IP locale IPv6 : #{LOCAL_IPV6 or '(aucune)'}"
-- Detect LOCAL_MAC (MAC of the interface used to reach the router LAN — visible in nft ether saddr)
_, local_iface_raw = run "ip route get #{LAN_IP} 2>/dev/null | sed -En 's/.*dev ([^ ]+).*/\\1/p' | head -1"
LOCAL_IFACE = local_iface_raw and local_iface_raw\match "%S+"
_, local_mac_raw = if LOCAL_IFACE
  run "ip link show #{LOCAL_IFACE} 2>/dev/null | sed -En 's/.*ether ([0-9a-f:]+).*/\\1/p' | head -1"
else
  nil, nil
LOCAL_MAC = local_mac_raw and local_mac_raw\match "[0-9a-f]+:[0-9a-f:]+"
print "  MAC locale : #{LOCAL_MAC or '(inconnue)'}"

AUTH_URL    = "https://#{LAN_IP}:33443"
CAPTIVE_URL = "http://#{LAN_IP}:33080"

-- ── [2/5] Service management ───────────────────────────────────────────────────

print ""
print "#{C.bold}[2/5] Démarrage du service...#{C.reset}"

ssh "mkdir -p #{CUSTOS_DIR}/tmp"

unless no_restart
  -- Stop the procd-managed service first so procd stops restarting main.lua
  -- while we're trying to kill processes.
  ssh "service custos stop 2>/dev/null; true"
  os.execute "sleep 1"
  -- Kill any remaining workers (supervisor restart loop may still be live).
  for _ = 1, 30
    _, procs = ssh "for pid in $(pgrep -f 'luajit2.*main' 2>/dev/null); do kill -9 $pid 2>/dev/null; done; pgrep -f 'luajit2.*main' 2>/dev/null | wc -l"
    break if (tonumber(procs or "1") or 1) == 0
    os.execute "sleep 0.5"
  os.execute "sleep 1"  -- extra margin for kernel to release NFQUEUE handles + ports
  ssh "nft flush ruleset 2>/dev/null; true"

  -- Clear log and sessions
  ssh "> #{LOG_FILE}; > #{SESSIONS_FILE} 2>/dev/null; true"

  -- Remove newuser leftovers from a previous run BEFORE starting the server
  -- (server loads users into memory at startup; file-only removal won't help after that)
  ssh "grep -v '^newuser:' #{CFG_DIR}/secrets > /tmp/_secrets.tmp 2>/dev/null && mv /tmp/_secrets.tmp #{CFG_DIR}/secrets 2>/dev/null; true"

  -- Ensure testuser exists in secrets
  ok_tu, _ = ssh "grep -q '^testuser:' #{CFG_DIR}/secrets 2>/dev/null"
  unless ok_tu
    print "  Création du compte testuser..."
    ssh "LUA_PATH='/usr/lib/lua/?.lua;/usr/lib/lua/?/init.lua;#{CUSTOS_DIR}/?.lua;#{CUSTOS_DIR}/?/init.lua;;' luajit2 -e \"local c=require('auth.credentials'); c.register_user('testuser','testpass','#{CFG_DIR}/secrets',{}); print('ok')\""

  -- Deploy Lua files and nft ruleset to the router before starting the service.
  -- Ensures the tested code matches what was just compiled locally.
  script_dir = (arg[0] or "tests/test_openwrt.lua")\gsub "[^/]+%.lua$", ""
  project_root = (script_dir\gsub "tests/?$", "")\gsub "/$", ""
  project_root = project_root == "" and "." or project_root
  print "  Déploiement des fichiers Lua + nft → #{SSH_TARGET}:#{CUSTOS_DIR}..."
  run "scp #{SCP_OPTS} #{project_root}/nft-rules/dns-filter.nft #{SSH_TARGET}:#{CUSTOS_DIR}/dns-filter.nft"
  run "ssh #{SSH_OPTS} #{SSH_TARGET} 'mkdir -p #{CUSTOS_DIR}/parse #{CUSTOS_DIR}/auth #{CUSTOS_DIR}/filter/conditions #{CUSTOS_DIR}/filter/actions #{CUSTOS_DIR}/filter/lib'"
  run "scp #{SCP_OPTS} #{project_root}/lua/*.lua #{SSH_TARGET}:#{CUSTOS_DIR}/"
  run "scp #{SCP_OPTS} #{project_root}/lua/parse/*.lua #{SSH_TARGET}:#{CUSTOS_DIR}/parse/"
  run "scp #{SCP_OPTS} #{project_root}/lua/auth/*.lua #{SSH_TARGET}:#{CUSTOS_DIR}/auth/"
  run "scp #{SCP_OPTS} #{project_root}/lua/filter/*.lua #{SSH_TARGET}:#{CUSTOS_DIR}/filter/"
  run "scp #{SCP_OPTS} #{project_root}/lua/filter/conditions/*.lua #{SSH_TARGET}:#{CUSTOS_DIR}/filter/conditions/"
  run "scp #{SCP_OPTS} #{project_root}/lua/filter/actions/*.lua #{SSH_TARGET}:#{CUSTOS_DIR}/filter/actions/"
  run "scp #{SCP_OPTS} #{project_root}/lua/filter/lib/*.lua #{SSH_TARGET}:#{CUSTOS_DIR}/filter/lib/"

  -- Load nft rules
  print "  Chargement des règles nft..."
  ok_nft, nft_err = ssh "nft -f #{CUSTOS_DIR}/dns-filter.nft 2>&1"
  unless ok_nft
    print "  #{C.red}✗ Échec chargement nft : #{(nft_err or '')\gsub '%s+$', ''}#{C.reset}"
    os.exit 1

  -- Start LuaJIT workers in background (busybox-compatible, no nohup)
  -- cd to CUSTOS_DIR so relative paths (tmp/auth.key, cfg/secrets, etc.) work.
  -- CUSTOS_FILTER_CONFIG must point to the deployed config file (absolute path).
  -- LUA_PATH must include /usr/lib/lua/ for LuaSocket/LuaSSL on OpenWrt.
  print "  Démarrage des workers LuaJIT..."
  lua_path = "/usr/lib/lua/?.lua;/usr/lib/lua/?/init.lua;#{CUSTOS_DIR}/?.lua;#{CUSTOS_DIR}/?/init.lua;;"
  ssh "(cd #{CUSTOS_DIR} && CUSTOS_FILTER_CONFIG=#{CFG_DIR}/filter.yml LUA_PATH=\"#{lua_path}\" luajit2 #{CUSTOS_DIR}/main.lua </dev/null >>#{LOG_FILE} 2>&1) &"
  os.execute "sleep 5"

-- Wait for queue workers
print "  Attente des workers (queue_listening)..."
workers_ready = false
for _ = 1, 20
  _, log = ssh "cat #{LOG_FILE} 2>/dev/null"
  if log and log\match "queue_listening"
    workers_ready = true
    break
  os.execute "sleep 1"
print "  Workers : #{workers_ready and (C.green..'prêts'..C.reset) or (C.red..'NON prêts'..C.reset)}"
error "Workers pas démarrés — vérifier #{LOG_FILE} sur le routeur" unless workers_ready

-- Wait for auth server
auth_ready = false
for _ = 1, 20
  _, log = ssh "cat #{LOG_FILE} 2>/dev/null"
  if log and log\match "auth_listening"
    auth_ready = true
    break
  os.execute "sleep 1"
print "  Auth    : #{auth_ready and (C.green..'prêt'..C.reset) or (C.yellow..'pas prêt (tests auth possiblement en échec)'..C.reset)}"

-- DNS and auth tests run from the LOCAL machine (not via SSH):
--   • dig @8.8.8.8 domain  → packets transit router FORWARD chain → intercepted by Q0/Q1
--   • curl https://LAN_IP:33443  → auth server, source IP = LOCAL_IP
-- Both use LOCAL_IP as session key → from_user matching is consistent.
-- This also avoids needing dig/curl on the router (busybox doesn't have them).
print "  DNS/auth depuis machine locale (#{LOCAL_IP} → #{LAN_IP})"

-- ── [3/5] Infrastructure tests ────────────────────────────────────────────────

print ""
print "#{C.bold}[3/5] Infrastructure#{C.reset}"
print ""

-- nft tables
_, nft_t = ssh "nft list tables 2>/dev/null"
report "Tables nft dns-filter chargées",
  (nft_t and nft_t\match "dns%-filter") != nil, nft_t or ""

-- authenticated_macs sets (ip + ip6)
_, macs4 = ssh "nft list set ip  dns-filter authenticated_macs 2>/dev/null"
report "authenticated_macs dans ip  dns-filter",
  (macs4 and macs4\match "ether_addr") != nil, macs4 or ""

_, macs6 = ssh "nft list set ip6 dns-filter authenticated_macs 2>/dev/null"
report "authenticated_macs dans ip6 dns-filter",
  (macs6 and macs6\match "ether_addr") != nil, macs6 or ""

-- ether saddr @authenticated_macs rules
_, pr4 = ssh "nft list chain ip  dns-filter prerouting 2>/dev/null"
report "ether saddr @authenticated_macs dans ip  prerouting",
  (pr4 and pr4\match "ether saddr @authenticated_macs") != nil, pr4 or ""

_, pr6 = ssh "nft list chain ip6 dns-filter prerouting 2>/dev/null"
report "ether saddr @authenticated_macs dans ip6 prerouting",
  (pr6 and pr6\match "ether saddr @authenticated_macs") != nil, pr6 or ""

-- mac4_allowed / mac6_allowed sets (DNS cross-family)
_, mac4s = ssh "nft list set ip  dns-filter mac4_allowed 2>/dev/null"
report "mac4_allowed dans ip  dns-filter",
  (mac4s and mac4s\match "ether_addr") != nil, mac4s or ""

_, mac6s = ssh "nft list set ip6 dns-filter mac6_allowed 2>/dev/null"
report "mac6_allowed dans ip6 dns-filter",
  (mac6s and mac6s\match "ether_addr") != nil, mac6s or ""

-- ether saddr . ip daddr @mac4_allowed rules in forward chains
_, fwd4 = ssh "nft list chain ip  dns-filter forward 2>/dev/null"
report "ether saddr . ip daddr @mac4_allowed dans ip  forward",
  (fwd4 and fwd4\match "mac4_allowed") != nil, fwd4 or ""

_, fwd6 = ssh "nft list chain ip6 dns-filter forward 2>/dev/null"
report "ether saddr . ip6 daddr @mac6_allowed dans ip6 forward",
  (fwd6 and fwd6\match "mac6_allowed") != nil, fwd6 or ""


_, brnf = ssh "cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null"
report "bridge-nf-call-iptables = 1",
  (brnf and brnf\match "1") != nil, brnf or ""

-- NFQUEUE workers
_, qraw = ssh "cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null"
report "NFQUEUE 0 connecté (worker Q0)",
  (qraw and qraw\match "^%s*0%s") != nil, qraw or ""
report "NFQUEUE 1 connecté (worker Q1)",
  (qraw and qraw\match "\n?%s*1%s") != nil, qraw or ""

-- Auth + captive portal ports (test from local machine via nc)
_, nc443 = run "nc -z -w3 #{LAN_IP} 33443 2>/dev/null && echo open || echo closed"
report "Auth server sur 33443",
  (nc443 and nc443\match "open") != nil, ""

_, nc080 = run "nc -z -w3 #{LAN_IP} 33080 2>/dev/null && echo open || echo closed"
report "Portail captif sur 33080",
  (nc080 and nc080\match "open") != nil, ""

-- DNAT structural check (actual redirect requires a LAN client)
_, pr4b = ssh "nft list chain ip dns-filter prerouting 2>/dev/null"
report "DNAT HTTP (80 → 33080) dans ip prerouting",
  (pr4b and pr4b\match "redirect to :33080") != nil, pr4b or ""
report "Pas de DNAT 443 dans ip prerouting",
  not (pr4b and pr4b\match "redirect to :33443"), pr4b or ""

_, fwd4 = ssh "nft list chain ip dns-filter forward 2>/dev/null"
report "REJECT tcp 443 dans ip forward",
  (fwd4 and fwd4\match "tcp dport 443 reject") != nil, fwd4 or ""

-- ip_dest_whitelist sets structural check
_, wl4 = ssh "nft list set ip  dns-filter ip4_dest_whitelist 2>/dev/null"
report "Set ip4_dest_whitelist dans ip  dns-filter",
  (wl4 and wl4\match "ip4_dest_whitelist") != nil, wl4 or ""
_, wl6 = ssh "nft list set ip6 dns-filter ip6_dest_whitelist 2>/dev/null"
report "Set ip6_dest_whitelist dans ip6 dns-filter",
  (wl6 and wl6\match "ip6_dest_whitelist") != nil, wl6 or ""
report "ip daddr @ip4_dest_whitelist accept dans ip forward",
  (fwd4 and fwd4\match "ip4_dest_whitelist") != nil, fwd4 or ""

-- ── [4/5] DNS filtering ────────────────────────────────────────────────────────

print ""
print "#{C.bold}[4/5] Filtrage DNS#{C.reset}"
print ""

--- Query DNS via the router's FORWARD-chain filter, from the local machine.
-- dig sends queries to 8.8.8.8. Those packets transit the router's FORWARD
-- chain where NFQUEUE intercepts them (Q0 decide allow/deny, Q1 patches TTL).
-- Source IP = LOCAL_IP, same as auth curl → from_user session key matches.
-- @tparam string domain
-- @tparam[opt] string qtype  Record type (default "A")
-- @tparam[opt] string extra  Additional dig flags (e.g. "+tcp")
-- @treturn boolean ok
-- @treturn string  output
dig_lan = (domain, qtype = "A", extra = "") ->
  run "dig +time=8 +tries=1 #{qtype} #{domain} @8.8.8.8 #{extra} 2>&1"

-- Flush allowed sets before DNS tests
ssh "nft flush set ip  dns-filter ip4_allowed 2>/dev/null; true"
ssh "nft flush set ip6 dns-filter ip6_allowed 2>/dev/null; true"

-- ── Allowed domain ─────────────────────────────────────────────────────────────

print "#{C.bold}▶ Domaine autorisé (#{DOMAIN_ALLOWED})#{C.reset}"

_, allow_out = dig_lan DOMAIN_ALLOWED
has_ip = allow_out and allow_out\match "%d+%.%d+%.%d+%.%d+"
report "dig #{DOMAIN_ALLOWED} → enregistrement A",
  has_ip != nil, (allow_out or "")\gsub("%s+$", "")\sub(1, 200)

os.execute "sleep 1"
_, set4 = ssh "nft list set ip dns-filter ip4_allowed 2>/dev/null"
report "ip4_allowed peuplé après #{DOMAIN_ALLOWED}",
  (set4 and set4\match "%d+%.%d+%.%d+%.%d+") != nil, set4 or "(vide)"

-- TTL patching check
ttl_val = allow_out and (allow_out\match("\t(%d+)\t[^\t]*IN\t[^\t]*A\t") or
                          allow_out\match("(%d+)%s+IN%s+A%s"))
report "TTL patché à 60s (#{DOMAIN_ALLOWED})",
  ttl_val == "60", "TTL trouvé : #{tostring ttl_val}"

-- ── Blocked domain ─────────────────────────────────────────────────────────────

print ""
print "#{C.bold}▶ Domaine bloqué (#{DOMAIN_BLOCKED})#{C.reset}"

_, blk_out = dig_lan DOMAIN_BLOCKED
report "dig #{DOMAIN_BLOCKED} → REFUSED",
  (blk_out and blk_out\upper!\match "REFUSED") != nil,
  (blk_out or "")\gsub("%s+$", "")\sub(1, 200)

-- Check the log: Q0 must have logged a BLOCK entry for LOCAL_IP + facebook.com.
-- Checking the nft set is unreliable because background DNS traffic from the
-- test machine (allowed domains) adds LOCAL_IP entries independently.
os.execute "sleep 1"
_, blk_log = ssh "grep BLOCK #{LOG_FILE} 2>/dev/null | grep '#{DOMAIN_BLOCKED}' | grep '#{LOCAL_IP}' | tail -1"
report "Log BLOCK #{DOMAIN_BLOCKED} depuis #{LOCAL_IP}",
  (blk_log and #blk_log > 5) != nil, blk_log or "(absent)"

-- ── Unknown domain (NXDOMAIN) ─────────────────────────────────────────────────

print ""
print "#{C.bold}▶ Domaine inconnu (#{DOMAIN_UNKNOWN})#{C.reset}"

_, unk_out = dig_lan DOMAIN_UNKNOWN
report "dig #{DOMAIN_UNKNOWN} → NXDOMAIN",
  (unk_out and unk_out\upper!\match "NXDOMAIN") != nil,
  (unk_out or "")\gsub("%s+$", "")\sub(1, 200)

-- ── AAAA records → ip6_allowed ─────────────────────────────────────────────────
--
-- Deux scénarios sont testés quand LOCAL_IPV6 est disponible :
--
-- 1. DNS sur IPv6 → AAAA : Q1 obtient client_v6 = client_ip directement.
--    Sert aussi de warmup : Q0 enregistre MAC → IPv6 dans mac_clients, ce qui
--    permet à Q1 de résoudre l'IPv6 du client pour le scénario 2 ci-dessous.
--
-- 2. Cross-family (DNS sur IPv4 → AAAA) : Q1 peuple mac6_allowed avec
--    l'adresse MAC du client (toujours connue) + les IPs AAAA résolues.
--    mac6_allowed doit contenir LOCAL_MAC . <ipv6_dest>.
--
-- 3. Cross-family inverse (DNS sur IPv6 → A) : Q1 peuple mac4_allowed avec
--    l'adresse MAC du client + les IPs A résolues.
--    mac4_allowed doit contenir LOCAL_MAC . <ipv4_dest>.

print ""
print "#{C.bold}▶ Enregistrements AAAA → ip6_allowed + mac6_allowed (#{DOMAIN_AAAA})#{C.reset}"

ssh "nft flush set ip6 dns-filter ip6_allowed 2>/dev/null; true"
ssh "nft flush set ip6 dns-filter mac6_allowed 2>/dev/null; true"
-- Scénario 1 : requête DNS sur IPv6 (warmup + test de base).
-- Si LOCAL_IPV6 est absent, retombe sur IPv4 (MAC lookup peut échouer).
dig_aaaa = if LOCAL_IPV6
  (domain) -> run "dig +time=8 +tries=1 AAAA #{domain} @2001:4860:4860::8888 2>&1"
else
  (domain) -> dig_lan domain, "AAAA"
_, aa_out = dig_aaaa DOMAIN_AAAA
has_aaaa = aa_out and aa_out\match "[0-9a-f]+:[0-9a-f:]+"
if has_aaaa
  os.execute "sleep 2"
  _, set6 = ssh "nft list set ip6 dns-filter ip6_allowed 2>/dev/null"
  report "ip6_allowed peuplé après #{DOMAIN_AAAA} AAAA",
    (set6 and set6\match "[0-9a-f]+:[0-9a-f:]+") != nil, set6 or "(vide)"
  if LOCAL_MAC
    _, mac6_set = ssh "nft list set ip6 dns-filter mac6_allowed 2>/dev/null"
    found_mac6 = mac6_set and mac6_set\find(LOCAL_MAC, 1, true) != nil
    report "mac6_allowed contient LOCAL_MAC (#{LOCAL_MAC}) après AAAA",
      found_mac6, mac6_set or "(vide)"
  else
    report "mac6_allowed après AAAA — LOCAL_MAC inconnu (ignoré)", true, ""
else
  -- No upstream AAAA or no IPv6 connectivity; unit tests cover the code path.
  report "AAAA #{DOMAIN_AAAA} — pas d'enregistrement upstream (ignoré)",
    true, (aa_out or "")\gsub "%s+$", ""

-- ── Cross-family: DNS IPv4 → AAAA → mac6_allowed (client identifié par MAC) ────
-- ── Cross-family: DNS IPv6 → A   → mac4_allowed (client identifié par MAC) ────
--
-- Ces tests vérifient le cas réel : un client interroge DNS dans une famille
-- et reçoit des enregistrements de l'autre famille. Q1 peuple mac4_allowed /
-- mac6_allowed directement à partir du MAC client (toujours connu via IPC).
-- Pas besoin de warmup ni de résolution IP cross-family.
-- Requis : LOCAL_MAC disponible (interface locale détectée).

if LOCAL_MAC
  print ""
  print "#{C.bold}▶ Cross-family: DNS sur IPv4 → AAAA → mac6_allowed#{C.reset}"
  print "  (MAC client attendu : #{LOCAL_MAC})"

  -- Q1 reçoit le MAC du client via IPC (Q0) indépendamment du transport DNS.
  -- mac6_allowed doit être peuplé avec LOCAL_MAC . <dest_ipv6>.
  ssh "nft flush set ip6 dns-filter mac6_allowed 2>/dev/null; true"
  _, aa4_out = run "dig +time=8 +tries=1 AAAA #{DOMAIN_AAAA} @8.8.8.8 2>&1"
  has_aa4 = aa4_out and aa4_out\match "[0-9a-f]+:[0-9a-f:]+"
  if has_aa4
    os.execute "sleep 2"
    _, mac6b = ssh "nft list set ip6 dns-filter mac6_allowed 2>/dev/null"
    found_mac6b = mac6b and mac6b\find(LOCAL_MAC, 1, true) != nil
    report "mac6_allowed contient LOCAL_MAC (#{LOCAL_MAC}) après AAAA sur IPv4",
      found_mac6b, mac6b or "(vide)"
  else
    report "Cross-family AAAA sur IPv4 — pas d'enregistrement (ignoré)", true, ""

  print ""
  print "#{C.bold}▶ Cross-family: DNS sur IPv6 → A → mac4_allowed#{C.reset}"
  print "  (MAC client attendu : #{LOCAL_MAC})"

  -- Q1 reçoit le MAC du client via IPC, indépendamment du transport DNS IPv6.
  -- mac4_allowed doit être peuplé avec LOCAL_MAC . <dest_ipv4>.
  ssh "nft flush set ip  dns-filter mac4_allowed 2>/dev/null; true"
  a6_dns_target = if LOCAL_IPV6 then "2001:4860:4860::8888" else "8.8.8.8"
  _, a6_out = run "dig +time=8 +tries=1 A #{DOMAIN_ALLOWED} @#{a6_dns_target} 2>&1"
  has_a6 = a6_out and a6_out\match "%d+%.%d+%.%d+%.%d+"
  if has_a6
    os.execute "sleep 2"
    _, mac4b = ssh "nft list set ip  dns-filter mac4_allowed 2>/dev/null"
    found_mac4b = mac4b and mac4b\find(LOCAL_MAC, 1, true) != nil
    report "mac4_allowed contient LOCAL_MAC (#{LOCAL_MAC}) après A sur IPv6",
      found_mac4b, mac4b or "(vide)"
  else
    report "Cross-family A sur IPv6 — pas d'enregistrement (ignoré)", true, ""

-- ── DNS over TCP + TTL ─────────────────────────────────────────────────────────

print ""
print "#{C.bold}▶ DNS over TCP + TTL (#{DOMAIN_ALLOWED})#{C.reset}"

_, tcp_out = dig_lan DOMAIN_ALLOWED, "A", "+tcp"
tcp_ip  = tcp_out and tcp_out\match "%d+%.%d+%.%d+%.%d+"
report "DNS over TCP → enregistrement A",
  tcp_ip != nil, (tcp_out or "")\sub(1, 150)

tcp_ttl = tcp_out and (tcp_out\match("\t(%d+)\t[^\t]*IN\t[^\t]*A\t") or
                        tcp_out\match("(%d+)%s+IN%s+A%s"))
report "DNS over TCP — TTL patché à 60",
  tcp_ttl == "60", "TTL : #{tostring tcp_ttl}"

-- ── [5/5] Auth + portail captif ───────────────────────────────────────────────

print ""
print "#{C.bold}[5/5] Authentification (#{AUTH_URL})#{C.reset}"
print ""

-- Clear sessions before auth tests
ssh "> #{SESSIONS_FILE} 2>/dev/null; true"

--- Run curl from the LOCAL machine against the auth server.
-- Source IP = LOCAL_IP = same as dig_lan source → from_user session key matches.
-- @tparam string method  HTTP method (GET or POST)
-- @tparam string path    URL path
-- @tparam[opt] string data  POST form data
-- @treturn boolean ok
-- @treturn string  HTTP status code string
auth_curl = (method, path, data) ->
  data_flag = if data then "-d '#{data}' " else ""
  _, out = run "curl -k -s -o /dev/null -w '%{http_code}' -X #{method} #{data_flag}#{AUTH_URL}#{path} 2>&1"
  code = (out or "")\match "%d%d%d"
  (code != nil and code != "000"), code or "000"

-- ── Login / heartbeat / logout ────────────────────────────────────────────────

print "#{C.bold}▶ Login / heartbeat / logout#{C.reset}"

_, bad_code = auth_curl "POST", "/login", "user=testuser&password=WRONG"
bad_code = bad_code\gsub "%s+", ""
report "Auth — mauvais mot de passe → 401",
  bad_code == "401", "HTTP #{bad_code}"

_, ok_code = auth_curl "POST", "/login", "user=testuser&password=testpass"
ok_code = ok_code\gsub "%s+", ""
report "Auth — identifiants valides → 200",
  ok_code == "200", "HTTP #{ok_code}"

_, sess = ssh "cat #{SESSIONS_FILE} 2>/dev/null"
report "sessions.lua contient testuser",
  (sess and sess\match "testuser") != nil,
  (sess or "(absent)")\sub(1, 120)

_, ping_code = auth_curl "GET", "/ping"
ping_code = ping_code\gsub "%s+", ""
report "Auth — heartbeat GET /ping → 204",
  ping_code == "204", "HTTP #{ping_code}"

-- IP in authenticated_ips after login
_, auth_set = ssh "nft list set ip dns-filter authenticated_ips 2>/dev/null"
local_ip_pat = LOCAL_IP\gsub "%.", "%%."
report "IP (#{LOCAL_IP}) dans authenticated_ips après login",
  (auth_set and auth_set\match local_ip_pat) != nil,
  (auth_set or "(vide)")\sub(1, 120)

-- ── from_user ────────────────────────────────────────────────────────────────

print ""
print "#{C.bold}▶ from_user : #{DOMAIN_AUTH}#{C.reset}"
print "  Attente flush cache session (6 s)..."
os.execute "sleep 6"

-- Query goes from local machine through the router's FORWARD chain to 8.8.8.8;
-- source IP = LOCAL_IP = auth session key.
_, nxd_out = dig_lan DOMAIN_AUTH
nxd_str = (nxd_out or "")\gsub "%s+$", ""
report "from_user — #{DOMAIN_AUTH} → NXDOMAIN après login",
  (nxd_out and ((nxd_out\upper!\match "NXDOMAIN") or (nxd_out\match "can't find"))) != nil,
  "dig: #{nxd_str\sub 1, 200}"

-- Logout
_, out_code = auth_curl "GET", "/logout"
out_code = out_code\gsub "%s+", ""
report "Auth — logout → 303",
  out_code == "303", "HTTP #{out_code}"

print "  Attente flush cache session (6 s)..."
os.execute "sleep 6"

-- from_user after logout → REFUSED
_, ref_out = dig_lan DOMAIN_AUTH
ref_str = (ref_out or "")\gsub "%s+$", ""
report "from_user — #{DOMAIN_AUTH} → REFUSED après logout",
  (ref_out and ref_out\upper!\match "REFUSED") != nil,
  "dig: #{ref_str\sub 1, 200}"

-- IP removed from authenticated_ips after logout
_, auth_set2 = ssh "nft list set ip dns-filter authenticated_ips 2>/dev/null"
report "IP retirée de authenticated_ips après logout",
  not (auth_set2 and auth_set2\match local_ip_pat),
  (auth_set2 or "(vide)")\sub(1, 120)

-- ── Portail captif (direct access, port 33080) ────────────────────────────────

print ""
print "#{C.bold}▶ Portail captif (port 33080)#{C.reset}"

--- GET a path on the captive portal from the local machine (port 33080, direct).
-- @tparam[opt] string path  URL path (default "/")
-- @treturn string  HTTP status code
-- @treturn string  Location header value (or "")
captive_get = (path = "/") ->
  _, out = run "curl -s -D - -o /dev/null --max-redirs 0 #{CAPTIVE_URL}#{path} 2>&1"
  code = (out or "")\match "HTTP/%S+ (%d%d%d)"
  loc  = (out or "")\match "[Ll]ocation: (%S+)"
  code, (loc or "")

cp_code, cp_loc = captive_get "/"
report "Portail captif GET / → 302",
  cp_code == "302", "HTTP #{cp_code}"
report "Portail captif redirect → https://",
  (cp_loc\match "^https://") != nil, "Location: #{cp_loc}"

g204_code, _ = captive_get "/generate_204"
report "Portail captif /generate_204 → 302",
  g204_code == "302", "HTTP #{g204_code}"

-- ── Bypass MAC (authenticated_macs in ip + ip6) ───────────────────────────────

print ""
print "#{C.bold}▶ Bypass MAC (authenticated_macs ip + ip6)#{C.reset}"

TEST_MAC = "aa:bb:cc:dd:ee:ff"

ok_add, add_out = ssh "nft add element ip  dns-filter authenticated_macs { #{TEST_MAC} timeout 10s } && nft add element ip6 dns-filter authenticated_macs { #{TEST_MAC} timeout 10s } 2>&1"
report "Ajout MAC atomique (ip + ip6)",
  ok_add, add_out or ""

_, chk4 = ssh "nft list set ip  dns-filter authenticated_macs 2>/dev/null"
_, chk6 = ssh "nft list set ip6 dns-filter authenticated_macs 2>/dev/null"
report "MAC #{TEST_MAC} présent dans ip  authenticated_macs",
  (chk4 and chk4\match "aa:bb:cc:dd:ee:ff") != nil, chk4 or ""
report "MAC #{TEST_MAC} présent dans ip6 authenticated_macs",
  (chk6 and chk6\match "aa:bb:cc:dd:ee:ff") != nil, chk6 or ""

ok_del, del_out = ssh "nft delete element ip  dns-filter authenticated_macs { #{TEST_MAC} } && nft delete element ip6 dns-filter authenticated_macs { #{TEST_MAC} } 2>&1"
report "Suppression MAC atomique (ip + ip6)",
  ok_del, del_out or ""

_, chk4b = ssh "nft list set ip  dns-filter authenticated_macs 2>/dev/null"
report "MAC #{TEST_MAC} retiré de ip authenticated_macs",
  not (chk4b and chk4b\match "aa:bb:cc:dd:ee:ff"),
  chk4b or "(vide)"

-- ── Inscription d'utilisateurs ────────────────────────────────────────────────

print ""
print "#{C.bold}▶ Inscription d'utilisateurs#{C.reset}"

ssh "> #{SESSIONS_FILE} 2>/dev/null; true"

--- POST to the /register endpoint from the local machine.
-- @tparam string user
-- @tparam string pass
-- @tparam string pass2
-- @treturn string code  HTTP status code
-- @treturn string body  Response body
register = (user, pass, pass2) ->
  _, out = run "curl -k -s -w '%{http_code}' -X POST -d 'user=#{user}&password=#{pass}&password2=#{pass2}' #{AUTH_URL}/register 2>&1"
  code = (out or "")\match "(%d%d%d)%s*$"
  body = (out or "")\gsub "(%d%d%d)%s*$", ""
  code or "000", body

code, body = register "a", "pass123", "pass123"
report "Inscription — nom trop court → erreur",
  (code == "200" or code == "400") and body\match("Nom d'utilisateur invalide") != nil,
  "HTTP #{code} | #{body\sub 1, 100}"

code, body = register "newuser", "pass", "pass"
report "Inscription — mot de passe trop court → erreur",
  (code == "200" or code == "400") and body\match("8 caractères") != nil,
  "HTTP #{code} | #{body\sub 1, 100}"

code, body = register "newuser", "pass123", "pass456"
report "Inscription — mots de passe différents → erreur",
  (code == "200" or code == "400") and body\match("ne correspondent pas") != nil,
  "HTTP #{code} | #{body\sub 1, 100}"

code, body = register "testuser", "newpass123", "newpass123"
report "Inscription — utilisateur existant → erreur",
  (code == "200" or code == "409") and
    (body\match("déjà pris") or body\match("Impossible de créer")) != nil,
  "HTTP #{code} | #{body\sub 1, 100}"

-- Remove newuser leftovers from a previous run, then register fresh
-- busybox sed -i doesn't reliably support in-place edits; use grep -v + mv.
ssh "grep -v '^newuser:' #{CFG_DIR}/secrets > /tmp/_secrets.tmp && mv /tmp/_secrets.tmp #{CFG_DIR}/secrets 2>/dev/null; true"
ssh "> #{SESSIONS_FILE} 2>/dev/null; true"

code, body = register "newuser", "newpass123", "newpass123"
report "Inscription — nouvel utilisateur → 200",
  code == "200",
  "HTTP #{code} | #{body\sub 1, 100}"

if code == "200"
  _, sess2 = ssh "cat #{SESSIONS_FILE} 2>/dev/null"
  report "Inscription — sessions.lua contient newuser",
    (sess2 and sess2\match "newuser") != nil,
    (sess2 or "(absent)")\sub(1, 120)

-- ── Log verification ──────────────────────────────────────────────────────────

print ""
print "#{C.bold}▶ Vérification du log#{C.reset}"

_, cnt_allow = ssh "grep -c ALLOW #{LOG_FILE} 2>/dev/null"
_, cnt_block = ssh "grep -c BLOCK #{LOG_FILE} 2>/dev/null"
report "Log contient des entrées ALLOW",
  (tonumber(cnt_allow or "0") or 0) > 0, "count : #{cnt_allow}"
report "Log contient des entrées BLOCK",
  (tonumber(cnt_block or "0") or 0) > 0, "count : #{cnt_block}"

-- ── ip_dest_whitelist functional test (SIGHUP reload) ───────────────────────

print ""
print "#{C.bold}▶ Liste blanche statique (ip_whitelist, rechargement SIGHUP)#{C.reset}"

TEST_WL_IP = "10.253.254.255"
TEST_WL_IP6 = "fd99::1"
FILTER_YML = "#{CFG_DIR}/filter.yml"

-- Inject test IPs into filter.yml
ssh "printf '\\nip_whitelist:\\n- #{TEST_WL_IP}\\n- #{TEST_WL_IP6}\\n' >> #{FILTER_YML}"

-- Send SIGHUP to the main process (propagated to workers via pipe)
-- filter.reload() is called on the next DNS packet, so trigger one.
ssh "pid=$(pgrep -f 'luajit2.*main' 2>/dev/null | head -1); [ -n \"$pid\" ] && kill -HUP $pid 2>/dev/null; true"
-- Trigger a DNS packet so Q0 worker picks up reload_requested
os.execute "dig @#{ROUTER_IP} github.com A +time=2 +tries=1 >/dev/null 2>&1; true"
os.execute "sleep 1"

_, wl4_set = ssh "nft list set ip  dns-filter ip4_dest_whitelist 2>/dev/null"
report "ip_whitelist — #{TEST_WL_IP} présent dans ip4_dest_whitelist après SIGHUP",
  (wl4_set and wl4_set\match TEST_WL_IP) != nil, wl4_set or "(vide)"

_, wl6_set = ssh "nft list set ip6 dns-filter ip6_dest_whitelist 2>/dev/null"
report "ip_whitelist — #{TEST_WL_IP6} présent dans ip6_dest_whitelist après SIGHUP",
  (wl6_set and wl6_set\match "fd99") != nil, wl6_set or "(vide)"

-- Remove test IPs from filter.yml and reload again
ssh "grep -v '^ip_whitelist:\\|^- #{TEST_WL_IP}\\|^- #{TEST_WL_IP6}' #{FILTER_YML} > /tmp/_filter.tmp && mv /tmp/_filter.tmp #{FILTER_YML}; true"
ssh "pid=$(pgrep -f 'luajit2.*main' 2>/dev/null | head -1); [ -n \"$pid\" ] && kill -HUP $pid 2>/dev/null; true"
os.execute "dig @#{ROUTER_IP} github.com A +time=2 +tries=1 >/dev/null 2>&1; true"
os.execute "sleep 1"

_, wl4_after = ssh "nft list set ip dns-filter ip4_dest_whitelist 2>/dev/null"
report "ip_whitelist — set vidé après suppression + SIGHUP",
  not (wl4_after and wl4_after\match TEST_WL_IP), wl4_after or "(vide)"

-- ── Summary ───────────────────────────────────────────────────────────────────

print ""
print string.rep "─", 50
fail_color = tests_failed > 0 and C.red or C.grey
print "#{C.bold}Résumé :#{C.reset} #{C.green}#{tests_passed} réussis#{C.reset}  #{fail_color}#{tests_failed} échoués#{C.reset}"

os.exit tests_failed > 0 and 1 or 0
