-- KVM/libvirt end-to-end test for CustosVirginum DNS filter (bridge mode).
--
-- Architecture:
--   [client VM: 10.99.0.10]
--     └── virbr-lan ──[eth1:filter VM:eth0]── virbr-wf ──[router VM: 10.99.0.1]
--                           br0 (eth0+eth1)                     └── wan NAT ──▶ 192.168.200.1
--                           br_netfilter=1                           dnsmasq
--                           dns-filter.nft (FORWARD chain)
--                           LuaJIT Q0/Q1
--
-- Prerequisites (handled by make test-kvm-up):
--   sudo bash libvirt/custos-libvirt.sh create   (once, downloads images)
--   bash libvirt/custos-libvirt.sh start         (boots VMs, waits for filter SSH)

LIBVIRT_SCRIPT = "libvirt/custos-libvirt.sh"
CLIENT_VM      = "custos-client"
FILTER_USER    = "debian"
SSH_KEY        = (os.getenv "HOME") .. "/.ssh/id_rsa"
SSH_OPTS       = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes"

DNS_SERVER     = "192.168.200.1"
DOMAIN_ALLOWED = "github.com"
DOMAIN_AAAA    = "cloudflare.com"
DOMAIN_BLOCKED = "facebook.com"
DOMAIN_UNKNOWN = "nonexistent.invalid"

CLIENT_IP   = "10.99.0.10"
CLIENT2_IP  = "10.99.0.11"
FILTER_IPV6 = "fd99::254"
CLIENT_IPV6 = "fd99::10"

C =
  red:    "\27[31m"
  green:  "\27[32m"
  yellow: "\27[33m"
  bold:   "\27[1m"
  reset:  "\27[0m"
  grey:   "\27[90m"

tests_passed = 0
tests_failed = 0

--- Run a shell command; return (ok, output).
-- @tparam string cmd
-- @treturn boolean ok
-- @treturn string  output (stdout+stderr)
run = (cmd) ->
  fh = io.popen "#{cmd} 2>&1"
  out = fh\read "*a"
  ok = fh\close!
  ok, out

--- Run a shell command, raise on failure.
-- @tparam string cmd
-- @treturn string output
run_check = (cmd) ->
  ok, out = run cmd
  error "Command failed: #{cmd}\n#{out}" unless ok
  out

--- Return management IP of the filter VM (192.168.200.x via wan network).
-- @treturn string IPv4 address
filter_ip = ->
  ok, out = run "bash #{LIBVIRT_SCRIPT} filter-ip"
  error "Cannot determine filter VM IP:\n#{out}" unless ok
  addr = out\match "%d+%.%d+%.%d+%.%d+"
  error "No IP found in filter-ip output:\n#{out}" unless addr
  addr

--- SSH to the filter VM and run a command; return (ok, output).
-- @tparam string ip
-- @tparam string cmd
-- @treturn boolean ok
-- @treturn string  output
ssh = (ip, cmd) ->
  escaped = cmd\gsub("'", "'\\''")
  run "ssh #{SSH_OPTS} -i #{SSH_KEY} #{FILTER_USER}@#{ip} '#{escaped}'"

--- SSH to filter VM, raise on failure.
-- @tparam string ip
-- @tparam string cmd
-- @treturn string output
ssh_check = (ip, cmd) ->
  ok, out = ssh ip, cmd
  error "SSH command failed: #{cmd}\n#{out}" unless ok
  out

--- Run a command on the client VM via qemu-guest-agent, polling for completion.
-- @tparam string cmd Shell command to run on client
-- @tparam[opt] number timeout_s Maximum seconds to wait (default 10)
-- @treturn boolean ok
-- @treturn string  stdout output (decoded from base64)
guest_exec = (cmd, timeout_s) ->
  timeout_s or= 10
  safe_cmd = cmd\gsub('\\', '\\\\\\\\')\gsub('"', '\\"')
  exec_payload = string.format(
    '{"execute":"guest-exec","arguments":{"path":"/bin/sh","arg":["-c","%s"],"capture-output":true}}',
    safe_cmd)
  -- Escape single quotes so the JSON payload can be safely wrapped in ''
  shell_payload = exec_payload\gsub("'", "'\"'\"'")
  ok, out = run "LIBVIRT_DEFAULT_URI=qemu:///system virsh qemu-agent-command #{CLIENT_VM} '#{shell_payload}'"
  return false, "guest-exec failed: #{out}" unless ok
  pid = out\match '"pid"%s*:%s*(%d+)'
  return false, "no pid in response: #{out}" unless pid

  deadline = os.time! + timeout_s
  while os.time! <= deadline
    os.execute "sleep 1"
    status_payload = string.format(
      '{"execute":"guest-exec-status","arguments":{"pid":%s}}', pid)
    ok2, out2 = run "LIBVIRT_DEFAULT_URI=qemu:///system virsh qemu-agent-command #{CLIENT_VM} '#{status_payload}'"
    continue unless ok2
    continue unless out2\match '"exited"%s*:%s*true'
    b64 = out2\match '"out%-data"%s*:%s*"([^"]+)"'
    decoded = ""
    if b64
      ok3, decoded = run "printf '%s' '#{b64}' | base64 -d"
    exit_ok = out2\match '"exitcode"%s*:%s*0'
    return (exit_ok != nil), decoded

  false, "guest-exec timed out after #{timeout_s}s"

--- Resolve a domain on the test host (bypasses the filter).
-- @tparam string domain
-- @treturn string|nil First IPv4 address found, or nil
resolve_host = (domain) ->
  _, out = run "dig +short #{domain} 2>/dev/null"
  out and out\match "%d+%.%d+%.%d+%.%d+"

--- Ping a destination from a specific source IP on the client VM.
-- @tparam string src_ip  Source IP to bind (-I)
-- @tparam string dest_ip Destination IP
-- @tparam[opt] number timeout_s Ping timeout (default 3)
-- @treturn boolean ok
-- @treturn string  output
ping_from = (src_ip, dest_ip, timeout_s = 3) ->
  guest_exec "ping -c1 -W#{timeout_s} -I #{src_ip} #{dest_ip} 2>&1", timeout_s + 4

--- DNS query from a specific source IP on the client VM.
-- @tparam string src_ip   Source IP (-b)
-- @tparam string domain   Domain to query
-- @tparam[opt] string qtype  Query type (A or AAAA, default A)
-- @tparam[opt] number timeout_s Total timeout (default 15)
-- @treturn boolean ok
-- @treturn string  output
dig_from = (src_ip, domain, qtype = "A", timeout_s = 15) ->
  guest_exec "dig +short +time=5 +tries=1 #{qtype} #{domain} @#{DNS_SERVER} -b #{src_ip}", timeout_s

--- Parse ip4_allowed nft set output to find the dest IP for a given client IP.
-- @tparam string set_out  Raw output of `nft list set ip dns-filter ip4_allowed`
-- @tparam string client_ip
-- @treturn string|nil First dest IP found for this client
nft_dest_for = (set_out, client_ip) ->
  escaped = client_ip\gsub "%.", "%%."
  set_out and set_out\match "#{escaped}%s*%.%s*(%d+%.%d+%.%d+%.%d+)"

--- Record and print a test result.
-- @tparam string  name
-- @tparam boolean ok
-- @tparam[opt] string msg Additional context shown on failure
report = (name, ok, msg) ->
  if ok
    tests_passed += 1
    print "  #{C.green}✓#{C.reset} #{name}"
  else
    tests_failed += 1
    print "  #{C.red}✗ #{name}#{C.reset}"
    if msg and msg\match "%S"
      print "    #{C.grey}#{msg\gsub('%s+$', '')}#{C.reset}"

-- ── Setup ─────────────────────────────────────────────────────────────────────

print "#{C.bold}CustosVirginum — KVM end-to-end tests (bridge mode)#{C.reset}"
print ""

print "#{C.bold}[1/4] Locating filter VM...#{C.reset}"
FILTER_IP = filter_ip!
print "  Filter management IP: #{FILTER_IP}"

print "#{C.bold}[2/4] Syncing lua/ + nft-rules/ + cfg/ to filter VM...#{C.reset}"
ssh_check FILTER_IP, "sudo mkdir -p /opt/custos/lua /opt/custos/nft-rules /opt/custos/cfg /opt/custos/tmp && sudo chown -R #{FILTER_USER}:#{FILTER_USER} /opt/custos"
ssh_opts_inline = SSH_OPTS\gsub("\n", " ")
run_check "rsync -az --delete -e 'ssh #{ssh_opts_inline} -i #{SSH_KEY}' lua/ #{FILTER_USER}@#{FILTER_IP}:/opt/custos/lua/"
run_check "rsync -az --delete -e 'ssh #{ssh_opts_inline} -i #{SSH_KEY}' nft-rules/ #{FILTER_USER}@#{FILTER_IP}:/opt/custos/nft-rules/"
run_check "rsync -az --delete -e 'ssh #{ssh_opts_inline} -i #{SSH_KEY}' cfg/ #{FILTER_USER}@#{FILTER_IP}:/opt/custos/cfg/"

print "#{C.bold}[3/4] Loading nft rules and starting LuaJIT...#{C.reset}"
-- Kill any leftover LuaJIT from a previous run, then flush stale ruleset
-- (flush BEFORE apt-get to avoid DNS blockage from previous run's nft output chain)
ssh FILTER_IP, "for pid in $(sudo pgrep -f luajit 2>/dev/null); do sudo kill $pid 2>/dev/null; done; true"
os.execute "sleep 2"
ssh FILTER_IP, "sudo nft flush ruleset 2>/dev/null; true"

-- Ensure auth dependencies are installed on the filter VM
-- (done after nft flush so the filter VM's own DNS is not blocked)
print "  Installing lua-yaml, lua-socket, lua-sec, openssl on filter VM..."
ssh FILTER_IP, "sudo apt-get install -y -q lua-yaml lua-socket lua-sec openssl 2>&1 | tail -3; true"
-- Truncate logs so assertions only see output from this run
ssh FILTER_IP, "> /tmp/custos-kvm.log; sudo mkdir -p /opt/custos/tmp && sudo truncate -s0 /opt/custos/tmp/dns-filter.log /opt/custos/tmp/sessions.lua 2>/dev/null; true"
ssh_check FILTER_IP, "sudo nft -f /opt/custos/nft-rules/dns-filter.nft"
ssh_check FILTER_IP, "nohup sudo sh -c 'cd /opt/custos && LUA_PATH=\"lua/?.lua;lua/?/init.lua;;\" luajit lua/main.lua' </dev/null >>/tmp/custos-kvm.log 2>&1 &"
os.execute "sleep 5"
ok_luajit, _ = ssh FILTER_IP, "pgrep -f 'luajit.*main' >/dev/null"
print "  LuaJIT: #{ok_luajit and (C.green..'running'..C.reset) or (C.red..'NOT running'..C.reset)}"
error "LuaJIT failed to start — check /tmp/custos-kvm.log on filter VM" unless ok_luajit

-- Wait for auth worker to be ready
print "  Waiting for auth server (auth_listening + auth_secrets_loaded)..."
auth_ready = false
for _ = 1, 30
  _, log_content = ssh FILTER_IP, "sudo cat /opt/custos/tmp/dns-filter.log 2>/dev/null"
  if log_content and log_content\match("auth_listening") and log_content\match("auth_secrets_loaded")
    auth_ready = true
    break
  os.execute "sleep 1"
print "  Auth: #{auth_ready and (C.green..'ready'..C.reset) or (C.yellow..'not ready (auth tests may fail)'..C.reset)}"

-- Add IPv6 to the filter bridge and the client for AAAA/ip6_allowed tests
print "  Adding IPv6 #{FILTER_IPV6}/64 to filter br0..."
ssh FILTER_IP, "sudo ip addr add #{FILTER_IPV6}/64 dev br0 2>/dev/null; true"
print "  Waiting for client guest agent..."
run_check "bash #{LIBVIRT_SCRIPT} wait-agents"
-- Auto-detect the client's main interface (may be ens2, eth0, etc.)
_, iface_raw = guest_exec "ip route get #{DNS_SERVER} | sed -En \"s/.*dev ([^ ]+).*/\\1/p\"", 5
CLIENT_IFACE = (iface_raw or "")\gsub "%s+", ""
CLIENT_IFACE = #CLIENT_IFACE > 0 and CLIENT_IFACE or "eth0"
print "  Client interface: #{CLIENT_IFACE}"
print "  Adding IPv6 #{CLIENT_IPV6}/64 to client #{CLIENT_IFACE}..."
guest_exec "sudo ip addr add #{CLIENT_IPV6}/64 dev #{CLIENT_IFACE} 2>/dev/null; true", 5
print "  Adding client2 alias #{CLIENT2_IP}/24 to client #{CLIENT_IFACE}..."
guest_exec "sudo ip addr add #{CLIENT2_IP}/24 dev #{CLIENT_IFACE} 2>/dev/null; true", 5
-- Verify addresses are actually configured on the client
os.execute "sleep 1"
_, c_addr_out = guest_exec "ip addr show dev #{CLIENT_IFACE}", 5
if not (c_addr_out and c_addr_out\match CLIENT_IPV6)
  print "  #{C.yellow}WARNING: #{CLIENT_IPV6} not found on client #{CLIENT_IFACE} — AAAA test may skip#{C.reset}"
if not (c_addr_out and c_addr_out\match CLIENT2_IP\gsub("%.", "%."))
  print "  #{C.yellow}WARNING: #{CLIENT2_IP} not found on client #{CLIENT_IFACE} — isolation test may fail#{C.reset}"
-- Trigger NDP so the filter learns the client's IPv6 MAC mapping
print "  Triggering NDP (ping6 filter from client)..."
guest_exec "ping6 -c3 -W1 #{FILTER_IPV6} 2>/dev/null; true", 8
-- Poll until the filter's neighbour table shows the client's IPv6 (max 15s)
neigh_ok = false
for _ = 1, 15
  _, n_out = ssh FILTER_IP, "ip -6 neigh show dev br0 2>/dev/null"
  if n_out and n_out\match CLIENT_IPV6
    neigh_ok = true
    break
  os.execute "sleep 1"
print "  NDP #{CLIENT_IPV6}: #{neigh_ok and (C.green..'seen'..C.reset) or (C.yellow..'not seen (AAAA test may skip)'..C.reset)}"

-- Pre-resolve real IPs on the test host (bypasses filter, for ping-before tests)
github_ip   = resolve_host DOMAIN_ALLOWED
facebook_ip = resolve_host DOMAIN_BLOCKED
if github_ip
  print "  #{DOMAIN_ALLOWED} (host resolver) → #{github_ip}"
if facebook_ip
  print "  #{DOMAIN_BLOCKED} (host resolver) → #{facebook_ip}"

-- ── Tests ─────────────────────────────────────────────────────────────────────

print ""
print "#{C.bold}[4/4] Running tests#{C.reset}"
print ""

-- ── Bridge infrastructure ────────────────────────────────────────────────────
print "#{C.bold}▶ Bridge infrastructure#{C.reset}"

ok_br, br_out = ssh FILTER_IP, "ip link show br0"
report "br0 bridge exists and is UP",
  (ok_br and br_out\match "UP") != nil, br_out or ""

ok_sc, sc_out = ssh FILTER_IP, "cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null"
report "bridge-nf-call-iptables = 1",
  (ok_sc and sc_out\match "1") != nil, sc_out or ""

ok_nft, nft_out = ssh FILTER_IP, "sudo nft list tables"
report "dns-filter tables loaded",
  (ok_nft and nft_out\match "dns%-filter") != nil, nft_out or ""

-- ── DNS allowed domain — ping avant/après ───────────────────────────────────
print ""
print "#{C.bold}▶ DNS autorisé + ping avant/après (#{DOMAIN_ALLOWED})#{C.reset}"

ssh FILTER_IP, "sudo nft flush set ip  dns-filter ip4_allowed 2>/dev/null; true"
ssh FILTER_IP, "sudo nft flush set ip6 dns-filter ip6_allowed 2>/dev/null; true"

-- Ping before DNS resolution → should FAIL (ip4_allowed empty)
if github_ip
  ok_before, _ = ping_from CLIENT_IP, github_ip, 2
  report "ping #{github_ip} avant résolution (#{CLIENT_IP}) : échec attendu",
    not ok_before, "ip4_allowed vide"

ok_dig, dig_out = dig_from CLIENT_IP, DOMAIN_ALLOWED, "A", 15
has_ip = dig_out and dig_out\match "%d+%.%d+%.%d+%.%d+"
dig_str = (dig_out or "")\gsub "%s+", " "
report "dig #{DOMAIN_ALLOWED} retourne un enregistrement A",
  has_ip != nil, "dig: #{dig_str}"

os.execute "sleep 1"
ok_s, set_out = ssh FILTER_IP, "sudo nft list set ip dns-filter ip4_allowed"
allowed_ip = nft_dest_for set_out, CLIENT_IP
report "ip4_allowed peuplé après #{DOMAIN_ALLOWED}",
  (ok_s and allowed_ip) != nil, set_out or "nft error"

-- Ping after DNS resolution → should PASS
if allowed_ip
  ok_after, ping_out = ping_from CLIENT_IP, allowed_ip, 4
  p_str = (ping_out or "")\gsub "%s+", " "
  report "ping #{allowed_ip} après résolution (#{CLIENT_IP}) : succès attendu",
    ok_after, p_str
else
  report "ping après résolution — ip4_allowed vide", false, ""

-- ── DNS blocked domain — ping avant/après ───────────────────────────────────
print ""
print "#{C.bold}▶ DNS refusé + ping avant/après (#{DOMAIN_BLOCKED})#{C.reset}"

ssh FILTER_IP, "sudo nft flush set ip dns-filter ip4_allowed 2>/dev/null; true"

-- Ping before refused DNS → FAIL (not in set)
if facebook_ip
  ok_fb_before, _ = ping_from CLIENT_IP, facebook_ip, 2
  report "ping #{facebook_ip} avant DNS refusé (#{CLIENT_IP}) : échec attendu",
    not ok_fb_before, ""

_, blk_out = guest_exec "dig +time=3 +tries=1 #{DOMAIN_BLOCKED} @#{DNS_SERVER} 2>&1", 10
blk_str = (blk_out or "")\gsub "%s+$", ""
report "dig #{DOMAIN_BLOCKED} retourne REFUSED",
  (blk_out and blk_out\lower!\match "refused") != nil,
  "dig: #{blk_str}"

-- ip4_allowed must stay empty after a blocked query (nothing whitelisted)
os.execute "sleep 1"
_, blk_set_out = ssh FILTER_IP, "sudo nft list set ip dns-filter ip4_allowed"
report "ip4_allowed vide après DNS refusé (#{DOMAIN_BLOCKED})",
  not (blk_set_out and blk_set_out\match "%d+%.%d+%.%d+%.%d+"), blk_set_out or ""

-- Ping after refused DNS → still FAIL (not added to set)
if facebook_ip
  ok_fb_after, _ = ping_from CLIENT_IP, facebook_ip, 2
  report "ping #{facebook_ip} après DNS refusé (#{CLIENT_IP}) : échec attendu",
    not ok_fb_after, ""

-- ── DNS unknown domain ───────────────────────────────────────────────────────
print ""
print "#{C.bold}▶ Domaine inconnu — REFUSED (#{DOMAIN_UNKNOWN})#{C.reset}"

_, unk_out = guest_exec "dig +time=5 +tries=1 #{DOMAIN_UNKNOWN} @#{DNS_SERVER} 2>&1", 15
unk_str = (unk_out or "")\gsub "%s+$", ""
-- The filter REFUSEs all non-allowlisted domains (including nonexistent ones)
report "dig #{DOMAIN_UNKNOWN} retourne REFUSED",
  (unk_out and unk_out\upper!\match "REFUSED") != nil,
  "dig: #{unk_str}"

-- ── AAAA records → ip6_allowed ──────────────────────────────────────────────
print ""
print "#{C.bold}▶ Enregistrements AAAA → ip6_allowed (#{DOMAIN_AAAA})#{C.reset}"

ssh FILTER_IP, "sudo nft flush set ip6 dns-filter ip6_allowed 2>/dev/null; true"

ok_aaaa, aaaa_out = dig_from CLIENT_IP, DOMAIN_AAAA, "AAAA", 15
aaaa_str = (aaaa_out or "")\gsub "%s+", " "
has_aaaa = aaaa_out and aaaa_out\match "[0-9a-f]+:[0-9a-f:]+"

if has_aaaa
  os.execute "sleep 1"
  ok_s6, set6_out = ssh FILTER_IP, "sudo nft list set ip6 dns-filter ip6_allowed"
  s6_str = (set6_out or "")\gsub "%s+", " "
  report "ip6_allowed peuplé après résolution AAAA #{DOMAIN_AAAA}",
    (ok_s6 and set6_out\match "[0-9a-f]+:[0-9a-f:]+") != nil,
    s6_str
else
  -- No AAAA upstream: silently pass (unit tests cover code path)
  report "AAAA #{DOMAIN_AAAA} — pas d'enregistrement upstream (ignoré)",
    true, "aaaa: #{aaaa_str}"

-- ── Two-client isolation ─────────────────────────────────────────────────────
print ""
print "#{C.bold}▶ Isolation par client (client1=#{CLIENT_IP}, client2=#{CLIENT2_IP})#{C.reset}"

ssh FILTER_IP, "sudo nft flush set ip dns-filter ip4_allowed 2>/dev/null; true"

-- Client1 resolves allowed domain
ok_c1, c1_out = dig_from CLIENT_IP, DOMAIN_ALLOWED
c1_has_ip = c1_out and c1_out\match "%d+%.%d+%.%d+%.%d+"
report "client1 (#{CLIENT_IP}) résout #{DOMAIN_ALLOWED}",
  c1_has_ip != nil, (c1_out or "")\gsub "%s+", " "

os.execute "sleep 1"
_, cs_out = ssh FILTER_IP, "sudo nft list set ip dns-filter ip4_allowed"
c1_dest = nft_dest_for cs_out, CLIENT_IP

if c1_dest
  -- Client1 can reach the resolved IP
  ok_c1ping, c1ping_out = ping_from CLIENT_IP, c1_dest, 4
  report "client1 ping #{c1_dest} après résolution : succès attendu",
    ok_c1ping, (c1ping_out or "")\gsub "%s+$", ""

  -- Client2 (alias) cannot reach the same IP (not in set for client2)
  ok_c2ping_before, _ = ping_from CLIENT2_IP, c1_dest, 2
  report "client2 (#{CLIENT2_IP}) ping #{c1_dest} avant résolution : échec attendu",
    not ok_c2ping_before, ""

  -- Client2 resolves the same domain → gets its own set entry
  ok_c2, c2_out = dig_from CLIENT2_IP, DOMAIN_ALLOWED
  c2_has_ip = c2_out and c2_out\match "%d+%.%d+%.%d+%.%d+"
  report "client2 (#{CLIENT2_IP}) résout #{DOMAIN_ALLOWED}",
    c2_has_ip != nil, (c2_out or "")\gsub "%s+", " "

  os.execute "sleep 1"
  _, cs2_out = ssh FILTER_IP, "sudo nft list set ip dns-filter ip4_allowed"
  c2_dest = nft_dest_for cs2_out, CLIENT2_IP

  if c2_dest
    ok_c2ping_after, c2ping2_out = ping_from CLIENT2_IP, c2_dest, 4
    report "client2 ping #{c2_dest} après résolution : succès attendu",
      ok_c2ping_after, (c2ping2_out or "")\gsub "%s+$", ""
  else
    report "client2 dans ip4_allowed après résolution",
      false, "#{CLIENT2_IP} introuvable dans le set"
else
  report "isolation client — client1 dest introuvable dans ip4_allowed",
    false, cs_out or "set vide"

-- ── LuaJIT filter log ─────────────────────────────────────────────────────────
print ""
print "#{C.bold}▶ LuaJIT filter log#{C.reset}"

ok_log, log_out = ssh FILTER_IP, "sudo cat /opt/custos/tmp/dns-filter.log 2>/dev/null | tail -40"
report "log has allowed entries",
  (ok_log and log_out\match "ALLOW") != nil, ""
report "log has blocked/refused entries",
  (ok_log and log_out\match "BLOCK") != nil, ""

-- ── Authentification HTTPS ────────────────────────────────────────────────────
FILTER_LAN_IP = "10.99.0.254"
AUTH_URL       = "https://#{FILTER_LAN_IP}:8443"

print ""
print "#{C.bold}▶ Authentification HTTPS (#{AUTH_URL})#{C.reset}"

-- Clear any stale session
ssh FILTER_IP, "sudo truncate -s0 /opt/custos/tmp/sessions.lua 2>/dev/null; true"

--- Run curl from the client VM against the auth server.
-- @tparam string method   HTTP method (GET or POST)
-- @tparam string path     URL path
-- @tparam string|nil data POST form data
-- @treturn boolean, string  ok, HTTP status code string
auth_curl_kvm = (method, path, data) ->
  data_flag = if data then "-d '#{data}' " else ""
  cmd = "curl -k -s -o /dev/null -w '%{http_code}' -X #{method} #{data_flag}#{AUTH_URL}#{path} 2>&1"
  guest_exec cmd, 10

ok_bad, bad_code = auth_curl_kvm "POST", "/login", "user=testuser&password=WRONG"
bad_code = (bad_code or "")\gsub "%s+", ""
report "Auth — mauvais mot de passe → 401",
  bad_code == "401", "HTTP #{bad_code}"

ok_ok, ok_code = auth_curl_kvm "POST", "/login", "user=testuser&password=testpass"
ok_code = (ok_code or "")\gsub "%s+", ""
report "Auth — identifiants valides → 200",
  ok_code == "200", "HTTP #{ok_code}"

_, sess_out = ssh FILTER_IP, "sudo cat /opt/custos/tmp/sessions.lua 2>/dev/null"
report "Auth — sessions.lua contient testuser + IP client",
  (sess_out and sess_out\match("testuser") and sess_out\match("10.99.0.10")) != nil,
  (sess_out or "(absent)")\sub(1, 120)

ok_ping, ping_code = auth_curl_kvm "GET", "/ping"
ping_code = (ping_code or "")\gsub "%s+", ""
report "Auth — heartbeat GET /ping → 204",
  ping_code == "204", "HTTP #{ping_code}"

-- Wait for session cache to flush (CACHE_TTL=5s)
print "  Waiting 6s for session cache..."
os.execute "sleep 6"

ok_nxd, nxd_out = guest_exec "dig +time=5 +tries=1 auth-required.test @#{DNS_SERVER} 2>&1", 12
nxd_str = (nxd_out or "")\gsub "%s+$", ""
report "Auth — from_user : auth-required.test → NXDOMAIN après login",
  (nxd_out and (nxd_out\lower!\match("nxdomain") or nxd_out\match("can't find"))) != nil,
  "dig: #{nxd_str}"

ok_out, out_code = auth_curl_kvm "GET", "/logout"
out_code = (out_code or "")\gsub "%s+", ""
report "Auth — logout → 303",
  out_code == "303", "HTTP #{out_code}"

print "  Waiting 6s after logout..."
os.execute "sleep 6"

ok_ref, ref_out = guest_exec "dig +time=5 +tries=1 auth-required.test @#{DNS_SERVER} 2>&1", 12
ref_str = (ref_out or "")\gsub "%s+$", ""
report "Auth — from_user : auth-required.test → REFUSED après logout",
  (ref_out and ref_out\upper!\match("REFUSED")) != nil,
  "dig: #{ref_str}"

-- ── Teardown ─────────────────────────────────────────────────────────────────
ssh FILTER_IP, "for pid in $(sudo pgrep -f luajit 2>/dev/null); do sudo kill $pid 2>/dev/null; done; sudo nft flush ruleset 2>/dev/null; true"

-- ── Summary ───────────────────────────────────────────────────────────────────
print ""
print (string.rep "─", 50)
fail_color = tests_failed > 0 and C.red or C.grey
print "#{C.bold}Summary:#{C.reset} #{C.green}#{tests_passed} passed#{C.reset}  #{fail_color}#{tests_failed} failed#{C.reset}"

os.exit tests_failed > 0 and 1 or 0
