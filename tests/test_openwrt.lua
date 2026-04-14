local CUSTOS_DIR = "/usr/share/custos"
local CFG_DIR = "/etc/custos"
local LOG_FILE = tostring(CUSTOS_DIR) .. "/tmp/custos.log"
local SESSIONS_FILE = tostring(CUSTOS_DIR) .. "/tmp/sessions.lua"
local DOMAIN_ALLOWED = "github.com"
local DOMAIN_AAAA = "cloudflare.com"
local DOMAIN_BLOCKED = "facebook.com"
local DOMAIN_UNKNOWN = "nonexistent.invalid"
local DOMAIN_AUTH = "auth-required.test"
local C = {
  red = "\27[31m",
  green = "\27[32m",
  yellow = "\27[33m",
  bold = "\27[1m",
  reset = "\27[0m",
  grey = "\27[90m"
}
local tests_passed = 0
local tests_failed = 0
local SSH_TARGET = nil
local no_restart = false
for _, a in ipairs(arg or { }) do
  if a:match("^%-%-no%-restart") then
    no_restart = true
  elseif (not a:match("^%-%-")) and not SSH_TARGET then
    SSH_TARGET = a
  end
end
if not (SSH_TARGET) then
  io.stderr:write("Usage: " .. tostring(arg[0] or 'test_openwrt') .. " user@host [--no-restart]\n")
  os.exit(1)
end
local SSH_OPTS = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes"
local run
run = function(cmd)
  local fh = io.popen(tostring(cmd) .. " 2>&1")
  local out = fh:read("*a")
  local ok = fh:close()
  return ok, out
end
local ssh
ssh = function(cmd)
  local escaped = cmd:gsub("'", "'\\''")
  return run("ssh " .. tostring(SSH_OPTS) .. " " .. tostring(SSH_TARGET) .. " '" .. tostring(escaped) .. "'")
end
local ssh_check
ssh_check = function(cmd)
  local ok, out = ssh(cmd)
  if not (ok) then
    error("SSH failed: " .. tostring(cmd) .. "\n" .. tostring(out))
  end
  return out
end
local report
report = function(name, ok, msg)
  if type(ok) == "function" then
    ok, msg = ok()
  end
  if ok then
    tests_passed = tests_passed + 1
    return print("  " .. tostring(C.green) .. "✓" .. tostring(C.reset) .. " " .. tostring(name))
  else
    tests_failed = tests_failed + 1
    print("  " .. tostring(C.red) .. "✗ " .. tostring(name) .. tostring(C.reset))
    if msg and msg:match("%S") then
      return print("    " .. tostring(C.grey) .. tostring((msg:gsub('%s+$', '')):sub(1, 200)) .. tostring(C.reset))
    end
  end
end
print(tostring(C.bold) .. "CustosVirginum — OpenWrt end-to-end tests" .. tostring(C.reset))
print("  Cible SSH : " .. tostring(SSH_TARGET))
print("")
print(tostring(C.bold) .. "[1/5] Vérification de la connexion SSH..." .. tostring(C.reset))
local ok_ssh, kernel = ssh("uname -r")
if not (ok_ssh) then
  print("  " .. tostring(C.red) .. "✗ Impossible de joindre " .. tostring(SSH_TARGET) .. tostring(C.reset))
  os.exit(1)
end
print("  Noyau : " .. tostring(kernel:gsub('%s+$', '')))
local _, lan_raw = ssh("ip addr show br 2>/dev/null | grep -m1 'inet ' | awk '{print $2}' | cut -d'/' -f1")
local LAN_IP = lan_raw and lan_raw:match("%d+%.%d+%.%d+%.%d+")
LAN_IP = LAN_IP or "127.0.0.1"
local local_raw
_, local_raw = run("ip route get " .. tostring(LAN_IP) .. " 2>/dev/null | sed -En 's/.*src ([0-9.]+).*/\\1/p' | head -1")
local LOCAL_IP = local_raw and local_raw:match("%d+%.%d+%.%d+%.%d+")
LOCAL_IP = LOCAL_IP or "127.0.0.1"
print("  IP locale : " .. tostring(LOCAL_IP))
local local_v6_raw
_, local_v6_raw = run("ip -6 route get 2001:4860:4860::8888 2>/dev/null | sed -En 's/.*src ([0-9a-f:]+).*/\\1/p' | head -1")
local LOCAL_IPV6 = local_v6_raw and local_v6_raw:match("[0-9a-f]+:[0-9a-f:]+")
print("  IP locale IPv6 : " .. tostring(LOCAL_IPV6 or '(aucune)'))
local local_iface_raw
_, local_iface_raw = run("ip route get " .. tostring(LAN_IP) .. " 2>/dev/null | sed -En 's/.*dev ([^ ]+).*/\\1/p' | head -1")
local LOCAL_IFACE = local_iface_raw and local_iface_raw:match("%S+")
local local_mac_raw
if LOCAL_IFACE then
  _, local_mac_raw = run("ip link show " .. tostring(LOCAL_IFACE) .. " 2>/dev/null | sed -En 's/.*ether ([0-9a-f:]+).*/\\1/p' | head -1")
else
  _, local_mac_raw = nil, nil
end
local LOCAL_MAC = local_mac_raw and local_mac_raw:match("[0-9a-f]+:[0-9a-f:]+")
print("  MAC locale : " .. tostring(LOCAL_MAC or '(inconnue)'))
local AUTH_URL = "https://" .. tostring(LAN_IP) .. ":33443"
local CAPTIVE_URL = "http://" .. tostring(LAN_IP) .. ":33080"
print("")
print(tostring(C.bold) .. "[2/5] Démarrage du service..." .. tostring(C.reset))
ssh("mkdir -p " .. tostring(CUSTOS_DIR) .. "/tmp")
if not (no_restart) then
  for _ = 1, 30 do
    local procs
    _, procs = ssh("for pid in $(pgrep -f 'luajit2.*main' 2>/dev/null); do kill -9 $pid 2>/dev/null; done; pgrep -f 'luajit2.*main' 2>/dev/null | wc -l")
    if (tonumber(procs or "1") or 1) == 0 then
      break
    end
    os.execute("sleep 0.5")
  end
  os.execute("sleep 1")
  ssh("nft flush ruleset 2>/dev/null; true")
  ssh("> " .. tostring(LOG_FILE) .. "; > " .. tostring(SESSIONS_FILE) .. " 2>/dev/null; true")
  ssh("grep -v '^newuser:' " .. tostring(CFG_DIR) .. "/secrets > /tmp/_secrets.tmp 2>/dev/null && mv /tmp/_secrets.tmp " .. tostring(CFG_DIR) .. "/secrets 2>/dev/null; true")
  local ok_tu
  ok_tu, _ = ssh("grep -q '^testuser:' " .. tostring(CFG_DIR) .. "/secrets 2>/dev/null")
  if not (ok_tu) then
    print("  Création du compte testuser...")
    ssh("LUA_PATH='/usr/lib/lua/?.lua;/usr/lib/lua/?/init.lua;" .. tostring(CUSTOS_DIR) .. "/?.lua;" .. tostring(CUSTOS_DIR) .. "/?/init.lua;;' luajit2 -e \"local c=require('auth.credentials'); c.register_user('testuser','testpass','" .. tostring(CFG_DIR) .. "/secrets',{}); print('ok')\"")
  end
  print("  Chargement des règles nft...")
  local ok_nft, nft_err = ssh("nft -f " .. tostring(CUSTOS_DIR) .. "/dns-filter.nft 2>&1")
  if not (ok_nft) then
    print("  " .. tostring(C.red) .. "✗ Échec chargement nft : " .. tostring((nft_err or ''):gsub('%s+$', '')) .. tostring(C.reset))
    os.exit(1)
  end
  print("  Démarrage des workers LuaJIT...")
  local lua_path = "/usr/lib/lua/?.lua;/usr/lib/lua/?/init.lua;" .. tostring(CUSTOS_DIR) .. "/?.lua;" .. tostring(CUSTOS_DIR) .. "/?/init.lua;;"
  ssh("(cd " .. tostring(CUSTOS_DIR) .. " && CUSTOS_FILTER_CONFIG=" .. tostring(CFG_DIR) .. "/filter.yml LUA_PATH=\"" .. tostring(lua_path) .. "\" luajit2 " .. tostring(CUSTOS_DIR) .. "/main.lua </dev/null >>" .. tostring(LOG_FILE) .. " 2>&1) &")
  os.execute("sleep 5")
end
print("  Attente des workers (queue_listening)...")
local workers_ready = false
for _ = 1, 20 do
  local log
  _, log = ssh("cat " .. tostring(LOG_FILE) .. " 2>/dev/null")
  if log and log:match("queue_listening") then
    workers_ready = true
    break
  end
  os.execute("sleep 1")
end
print("  Workers : " .. tostring(workers_ready and (C.green .. 'prêts' .. C.reset) or (C.red .. 'NON prêts' .. C.reset)))
if not (workers_ready) then
  error("Workers pas démarrés — vérifier " .. tostring(LOG_FILE) .. " sur le routeur")
end
local auth_ready = false
for _ = 1, 20 do
  local log
  _, log = ssh("cat " .. tostring(LOG_FILE) .. " 2>/dev/null")
  if log and log:match("auth_listening") then
    auth_ready = true
    break
  end
  os.execute("sleep 1")
end
print("  Auth    : " .. tostring(auth_ready and (C.green .. 'prêt' .. C.reset) or (C.yellow .. 'pas prêt (tests auth possiblement en échec)' .. C.reset)))
print("  DNS/auth depuis machine locale (" .. tostring(LOCAL_IP) .. " → " .. tostring(LAN_IP) .. ")")
print("")
print(tostring(C.bold) .. "[3/5] Infrastructure" .. tostring(C.reset))
print("")
local nft_t
_, nft_t = ssh("nft list tables 2>/dev/null")
report("Tables nft dns-filter chargées", (nft_t and nft_t:match("dns%-filter")) ~= nil, nft_t or "")
local macs4
_, macs4 = ssh("nft list set ip  dns-filter authenticated_macs 2>/dev/null")
report("authenticated_macs dans ip  dns-filter", (macs4 and macs4:match("ether_addr")) ~= nil, macs4 or "")
local macs6
_, macs6 = ssh("nft list set ip6 dns-filter authenticated_macs 2>/dev/null")
report("authenticated_macs dans ip6 dns-filter", (macs6 and macs6:match("ether_addr")) ~= nil, macs6 or "")
local pr4
_, pr4 = ssh("nft list chain ip  dns-filter prerouting 2>/dev/null")
report("ether saddr @authenticated_macs dans ip  prerouting", (pr4 and pr4:match("ether saddr @authenticated_macs")) ~= nil, pr4 or "")
local pr6
_, pr6 = ssh("nft list chain ip6 dns-filter prerouting 2>/dev/null")
report("ether saddr @authenticated_macs dans ip6 prerouting", (pr6 and pr6:match("ether saddr @authenticated_macs")) ~= nil, pr6 or "")
local mac4s
_, mac4s = ssh("nft list set ip  dns-filter mac4_allowed 2>/dev/null")
report("mac4_allowed dans ip  dns-filter", (mac4s and mac4s:match("ether_addr")) ~= nil, mac4s or "")
local mac6s
_, mac6s = ssh("nft list set ip6 dns-filter mac6_allowed 2>/dev/null")
report("mac6_allowed dans ip6 dns-filter", (mac6s and mac6s:match("ether_addr")) ~= nil, mac6s or "")
local fwd4
_, fwd4 = ssh("nft list chain ip  dns-filter forward 2>/dev/null")
report("ether saddr . ip daddr @mac4_allowed dans ip  forward", (fwd4 and fwd4:match("mac4_allowed")) ~= nil, fwd4 or "")
local fwd6
_, fwd6 = ssh("nft list chain ip6 dns-filter forward 2>/dev/null")
report("ether saddr . ip6 daddr @mac6_allowed dans ip6 forward", (fwd6 and fwd6:match("mac6_allowed")) ~= nil, fwd6 or "")
local brnf
_, brnf = ssh("cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null")
report("bridge-nf-call-iptables = 1", (brnf and brnf:match("1")) ~= nil, brnf or "")
local qraw
_, qraw = ssh("cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null")
report("NFQUEUE 0 connecté (worker Q0)", (qraw and qraw:match("^%s*0%s")) ~= nil, qraw or "")
report("NFQUEUE 1 connecté (worker Q1)", (qraw and qraw:match("\n?%s*1%s")) ~= nil, qraw or "")
local nc443
_, nc443 = run("nc -z -w3 " .. tostring(LAN_IP) .. " 33443 2>/dev/null && echo open || echo closed")
report("Auth server sur 33443", (nc443 and nc443:match("open")) ~= nil, "")
local nc080
_, nc080 = run("nc -z -w3 " .. tostring(LAN_IP) .. " 33080 2>/dev/null && echo open || echo closed")
report("Portail captif sur 33080", (nc080 and nc080:match("open")) ~= nil, "")
local pr4b
_, pr4b = ssh("nft list chain ip dns-filter prerouting 2>/dev/null")
report("DNAT HTTP (80 → 33080) dans ip prerouting", (pr4b and pr4b:match("redirect to :33080")) ~= nil, pr4b or "")
report("Pas de DNAT 443 dans ip prerouting", not (pr4b and pr4b:match("redirect to :33443")), pr4b or "")
_, fwd4 = ssh("nft list chain ip dns-filter forward 2>/dev/null")
report("REJECT tcp 443 dans ip forward", (fwd4 and fwd4:match("tcp dport 443 reject")) ~= nil, fwd4 or "")
local wl4
_, wl4 = ssh("nft list set ip  dns-filter ip4_dest_whitelist 2>/dev/null")
report("Set ip4_dest_whitelist dans ip  dns-filter", (wl4 and wl4:match("ip4_dest_whitelist")) ~= nil, wl4 or "")
local wl6
_, wl6 = ssh("nft list set ip6 dns-filter ip6_dest_whitelist 2>/dev/null")
report("Set ip6_dest_whitelist dans ip6 dns-filter", (wl6 and wl6:match("ip6_dest_whitelist")) ~= nil, wl6 or "")
report("ip daddr @ip4_dest_whitelist accept dans ip forward", (fwd4 and fwd4:match("ip4_dest_whitelist")) ~= nil, fwd4 or "")
print("")
print(tostring(C.bold) .. "[4/5] Filtrage DNS" .. tostring(C.reset))
print("")
local dig_lan
dig_lan = function(domain, qtype, extra)
  if qtype == nil then
    qtype = "A"
  end
  if extra == nil then
    extra = ""
  end
  return run("dig +time=8 +tries=1 " .. tostring(qtype) .. " " .. tostring(domain) .. " @8.8.8.8 " .. tostring(extra) .. " 2>&1")
end
ssh("nft flush set ip  dns-filter ip4_allowed 2>/dev/null; true")
ssh("nft flush set ip6 dns-filter ip6_allowed 2>/dev/null; true")
print(tostring(C.bold) .. "▶ Domaine autorisé (" .. tostring(DOMAIN_ALLOWED) .. ")" .. tostring(C.reset))
local allow_out
_, allow_out = dig_lan(DOMAIN_ALLOWED)
local has_ip = allow_out and allow_out:match("%d+%.%d+%.%d+%.%d+")
report("dig " .. tostring(DOMAIN_ALLOWED) .. " → enregistrement A", has_ip ~= nil, (allow_out or ""):gsub("%s+$", ""):sub(1, 200))
os.execute("sleep 1")
local set4
_, set4 = ssh("nft list set ip dns-filter ip4_allowed 2>/dev/null")
report("ip4_allowed peuplé après " .. tostring(DOMAIN_ALLOWED), (set4 and set4:match("%d+%.%d+%.%d+%.%d+")) ~= nil, set4 or "(vide)")
local ttl_val = allow_out and (allow_out:match("\t(%d+)\t[^\t]*IN\t[^\t]*A\t") or allow_out:match("(%d+)%s+IN%s+A%s"))
report("TTL patché à 60s (" .. tostring(DOMAIN_ALLOWED) .. ")", ttl_val == "60", "TTL trouvé : " .. tostring(tostring(ttl_val)))
print("")
print(tostring(C.bold) .. "▶ Domaine bloqué (" .. tostring(DOMAIN_BLOCKED) .. ")" .. tostring(C.reset))
local blk_out
_, blk_out = dig_lan(DOMAIN_BLOCKED)
report("dig " .. tostring(DOMAIN_BLOCKED) .. " → REFUSED", (blk_out and blk_out:upper():match("REFUSED")) ~= nil, (blk_out or ""):gsub("%s+$", ""):sub(1, 200))
os.execute("sleep 1")
local blk_log
_, blk_log = ssh("grep BLOCK " .. tostring(LOG_FILE) .. " 2>/dev/null | grep '" .. tostring(DOMAIN_BLOCKED) .. "' | grep '" .. tostring(LOCAL_IP) .. "' | tail -1")
report("Log BLOCK " .. tostring(DOMAIN_BLOCKED) .. " depuis " .. tostring(LOCAL_IP), (blk_log and #blk_log > 5) ~= nil, blk_log or "(absent)")
print("")
print(tostring(C.bold) .. "▶ Domaine inconnu (" .. tostring(DOMAIN_UNKNOWN) .. ")" .. tostring(C.reset))
local unk_out
_, unk_out = dig_lan(DOMAIN_UNKNOWN)
report("dig " .. tostring(DOMAIN_UNKNOWN) .. " → NXDOMAIN", (unk_out and unk_out:upper():match("NXDOMAIN")) ~= nil, (unk_out or ""):gsub("%s+$", ""):sub(1, 200))
print("")
print(tostring(C.bold) .. "▶ Enregistrements AAAA → ip6_allowed + mac6_allowed (" .. tostring(DOMAIN_AAAA) .. ")" .. tostring(C.reset))
ssh("nft flush set ip6 dns-filter ip6_allowed 2>/dev/null; true")
ssh("nft flush set ip6 dns-filter mac6_allowed 2>/dev/null; true")
local dig_aaaa
if LOCAL_IPV6 then
  dig_aaaa = function(domain)
    return run("dig +time=8 +tries=1 AAAA " .. tostring(domain) .. " @2001:4860:4860::8888 2>&1")
  end
else
  dig_aaaa = function(domain)
    return dig_lan(domain, "AAAA")
  end
end
local aa_out
_, aa_out = dig_aaaa(DOMAIN_AAAA)
local has_aaaa = aa_out and aa_out:match("[0-9a-f]+:[0-9a-f:]+")
if has_aaaa then
  os.execute("sleep 2")
  local set6
  _, set6 = ssh("nft list set ip6 dns-filter ip6_allowed 2>/dev/null")
  report("ip6_allowed peuplé après " .. tostring(DOMAIN_AAAA) .. " AAAA", (set6 and set6:match("[0-9a-f]+:[0-9a-f:]+")) ~= nil, set6 or "(vide)")
  if LOCAL_MAC then
    local mac6_set
    _, mac6_set = ssh("nft list set ip6 dns-filter mac6_allowed 2>/dev/null")
    local found_mac6 = mac6_set and mac6_set:find(LOCAL_MAC, 1, true) ~= nil
    report("mac6_allowed contient LOCAL_MAC (" .. tostring(LOCAL_MAC) .. ") après AAAA", found_mac6, mac6_set or "(vide)")
  else
    report("mac6_allowed après AAAA — LOCAL_MAC inconnu (ignoré)", true, "")
  end
else
  report("AAAA " .. tostring(DOMAIN_AAAA) .. " — pas d'enregistrement upstream (ignoré)", true, (aa_out or ""):gsub("%s+$", ""))
end
if LOCAL_MAC then
  print("")
  print(tostring(C.bold) .. "▶ Cross-family: DNS sur IPv4 → AAAA → mac6_allowed" .. tostring(C.reset))
  print("  (MAC client attendu : " .. tostring(LOCAL_MAC) .. ")")
  ssh("nft flush set ip6 dns-filter mac6_allowed 2>/dev/null; true")
  local aa4_out
  _, aa4_out = run("dig +time=8 +tries=1 AAAA " .. tostring(DOMAIN_AAAA) .. " @8.8.8.8 2>&1")
  local has_aa4 = aa4_out and aa4_out:match("[0-9a-f]+:[0-9a-f:]+")
  if has_aa4 then
    os.execute("sleep 2")
    local mac6b
    _, mac6b = ssh("nft list set ip6 dns-filter mac6_allowed 2>/dev/null")
    local found_mac6b = mac6b and mac6b:find(LOCAL_MAC, 1, true) ~= nil
    report("mac6_allowed contient LOCAL_MAC (" .. tostring(LOCAL_MAC) .. ") après AAAA sur IPv4", found_mac6b, mac6b or "(vide)")
  else
    report("Cross-family AAAA sur IPv4 — pas d'enregistrement (ignoré)", true, "")
  end
  print("")
  print(tostring(C.bold) .. "▶ Cross-family: DNS sur IPv6 → A → mac4_allowed" .. tostring(C.reset))
  print("  (MAC client attendu : " .. tostring(LOCAL_MAC) .. ")")
  ssh("nft flush set ip  dns-filter mac4_allowed 2>/dev/null; true")
  local a6_dns_target
  if LOCAL_IPV6 then
    a6_dns_target = "2001:4860:4860::8888"
  else
    a6_dns_target = "8.8.8.8"
  end
  local a6_out
  _, a6_out = run("dig +time=8 +tries=1 A " .. tostring(DOMAIN_ALLOWED) .. " @" .. tostring(a6_dns_target) .. " 2>&1")
  local has_a6 = a6_out and a6_out:match("%d+%.%d+%.%d+%.%d+")
  if has_a6 then
    os.execute("sleep 2")
    local mac4b
    _, mac4b = ssh("nft list set ip  dns-filter mac4_allowed 2>/dev/null")
    local found_mac4b = mac4b and mac4b:find(LOCAL_MAC, 1, true) ~= nil
    report("mac4_allowed contient LOCAL_MAC (" .. tostring(LOCAL_MAC) .. ") après A sur IPv6", found_mac4b, mac4b or "(vide)")
  else
    report("Cross-family A sur IPv6 — pas d'enregistrement (ignoré)", true, "")
  end
end
print("")
print(tostring(C.bold) .. "▶ DNS over TCP + TTL (" .. tostring(DOMAIN_ALLOWED) .. ")" .. tostring(C.reset))
local tcp_out
_, tcp_out = dig_lan(DOMAIN_ALLOWED, "A", "+tcp")
local tcp_ip = tcp_out and tcp_out:match("%d+%.%d+%.%d+%.%d+")
report("DNS over TCP → enregistrement A", tcp_ip ~= nil, (tcp_out or ""):sub(1, 150))
local tcp_ttl = tcp_out and (tcp_out:match("\t(%d+)\t[^\t]*IN\t[^\t]*A\t") or tcp_out:match("(%d+)%s+IN%s+A%s"))
report("DNS over TCP — TTL patché à 60", tcp_ttl == "60", "TTL : " .. tostring(tostring(tcp_ttl)))
print("")
print(tostring(C.bold) .. "[5/5] Authentification (" .. tostring(AUTH_URL) .. ")" .. tostring(C.reset))
print("")
ssh("> " .. tostring(SESSIONS_FILE) .. " 2>/dev/null; true")
local auth_curl
auth_curl = function(method, path, data)
  local data_flag
  if data then
    data_flag = "-d '" .. tostring(data) .. "' "
  else
    data_flag = ""
  end
  local out
  _, out = run("curl -k -s -o /dev/null -w '%{http_code}' -X " .. tostring(method) .. " " .. tostring(data_flag) .. tostring(AUTH_URL) .. tostring(path) .. " 2>&1")
  local code = (out or ""):match("%d%d%d")
  return (code ~= nil and code ~= "000"), code or "000"
end
print(tostring(C.bold) .. "▶ Login / heartbeat / logout" .. tostring(C.reset))
local bad_code
_, bad_code = auth_curl("POST", "/login", "user=testuser&password=WRONG")
bad_code = bad_code:gsub("%s+", "")
report("Auth — mauvais mot de passe → 401", bad_code == "401", "HTTP " .. tostring(bad_code))
local ok_code
_, ok_code = auth_curl("POST", "/login", "user=testuser&password=testpass")
ok_code = ok_code:gsub("%s+", "")
report("Auth — identifiants valides → 200", ok_code == "200", "HTTP " .. tostring(ok_code))
local sess
_, sess = ssh("cat " .. tostring(SESSIONS_FILE) .. " 2>/dev/null")
report("sessions.lua contient testuser", (sess and sess:match("testuser")) ~= nil, (sess or "(absent)"):sub(1, 120))
local ping_code
_, ping_code = auth_curl("GET", "/ping")
ping_code = ping_code:gsub("%s+", "")
report("Auth — heartbeat GET /ping → 204", ping_code == "204", "HTTP " .. tostring(ping_code))
local auth_set
_, auth_set = ssh("nft list set ip dns-filter authenticated_ips 2>/dev/null")
local local_ip_pat = LOCAL_IP:gsub("%.", "%%.")
report("IP (" .. tostring(LOCAL_IP) .. ") dans authenticated_ips après login", (auth_set and auth_set:match(local_ip_pat)) ~= nil, (auth_set or "(vide)"):sub(1, 120))
print("")
print(tostring(C.bold) .. "▶ from_user : " .. tostring(DOMAIN_AUTH) .. tostring(C.reset))
print("  Attente flush cache session (6 s)...")
os.execute("sleep 6")
local nxd_out
_, nxd_out = dig_lan(DOMAIN_AUTH)
local nxd_str = (nxd_out or ""):gsub("%s+$", "")
report("from_user — " .. tostring(DOMAIN_AUTH) .. " → NXDOMAIN après login", (nxd_out and ((nxd_out:upper():match("NXDOMAIN")) or (nxd_out:match("can't find")))) ~= nil, "dig: " .. tostring(nxd_str:sub(1, 200)))
local out_code
_, out_code = auth_curl("GET", "/logout")
out_code = out_code:gsub("%s+", "")
report("Auth — logout → 303", out_code == "303", "HTTP " .. tostring(out_code))
print("  Attente flush cache session (6 s)...")
os.execute("sleep 6")
local ref_out
_, ref_out = dig_lan(DOMAIN_AUTH)
local ref_str = (ref_out or ""):gsub("%s+$", "")
report("from_user — " .. tostring(DOMAIN_AUTH) .. " → REFUSED après logout", (ref_out and ref_out:upper():match("REFUSED")) ~= nil, "dig: " .. tostring(ref_str:sub(1, 200)))
local auth_set2
_, auth_set2 = ssh("nft list set ip dns-filter authenticated_ips 2>/dev/null")
report("IP retirée de authenticated_ips après logout", not (auth_set2 and auth_set2:match(local_ip_pat)), (auth_set2 or "(vide)"):sub(1, 120))
print("")
print(tostring(C.bold) .. "▶ Portail captif (port 33080)" .. tostring(C.reset))
local captive_get
captive_get = function(path)
  if path == nil then
    path = "/"
  end
  local out
  _, out = run("curl -s -D - -o /dev/null --max-redirs 0 " .. tostring(CAPTIVE_URL) .. tostring(path) .. " 2>&1")
  local code = (out or ""):match("HTTP/%S+ (%d%d%d)")
  local loc = (out or ""):match("[Ll]ocation: (%S+)")
  return code, (loc or "")
end
local cp_code, cp_loc = captive_get("/")
report("Portail captif GET / → 302", cp_code == "302", "HTTP " .. tostring(cp_code))
report("Portail captif redirect → https://", (cp_loc:match("^https://")) ~= nil, "Location: " .. tostring(cp_loc))
local g204_code
g204_code, _ = captive_get("/generate_204")
report("Portail captif /generate_204 → 302", g204_code == "302", "HTTP " .. tostring(g204_code))
print("")
print(tostring(C.bold) .. "▶ Bypass MAC (authenticated_macs ip + ip6)" .. tostring(C.reset))
local TEST_MAC = "aa:bb:cc:dd:ee:ff"
local ok_add, add_out = ssh("nft add element ip  dns-filter authenticated_macs { " .. tostring(TEST_MAC) .. " timeout 10s } && nft add element ip6 dns-filter authenticated_macs { " .. tostring(TEST_MAC) .. " timeout 10s } 2>&1")
report("Ajout MAC atomique (ip + ip6)", ok_add, add_out or "")
local chk4
_, chk4 = ssh("nft list set ip  dns-filter authenticated_macs 2>/dev/null")
local chk6
_, chk6 = ssh("nft list set ip6 dns-filter authenticated_macs 2>/dev/null")
report("MAC " .. tostring(TEST_MAC) .. " présent dans ip  authenticated_macs", (chk4 and chk4:match("aa:bb:cc:dd:ee:ff")) ~= nil, chk4 or "")
report("MAC " .. tostring(TEST_MAC) .. " présent dans ip6 authenticated_macs", (chk6 and chk6:match("aa:bb:cc:dd:ee:ff")) ~= nil, chk6 or "")
local ok_del, del_out = ssh("nft delete element ip  dns-filter authenticated_macs { " .. tostring(TEST_MAC) .. " } && nft delete element ip6 dns-filter authenticated_macs { " .. tostring(TEST_MAC) .. " } 2>&1")
report("Suppression MAC atomique (ip + ip6)", ok_del, del_out or "")
local chk4b
_, chk4b = ssh("nft list set ip  dns-filter authenticated_macs 2>/dev/null")
report("MAC " .. tostring(TEST_MAC) .. " retiré de ip authenticated_macs", not (chk4b and chk4b:match("aa:bb:cc:dd:ee:ff")), chk4b or "(vide)")
print("")
print(tostring(C.bold) .. "▶ Inscription d'utilisateurs" .. tostring(C.reset))
ssh("> " .. tostring(SESSIONS_FILE) .. " 2>/dev/null; true")
local register
register = function(user, pass, pass2)
  local out
  _, out = run("curl -k -s -w '%{http_code}' -X POST -d 'user=" .. tostring(user) .. "&password=" .. tostring(pass) .. "&password2=" .. tostring(pass2) .. "' " .. tostring(AUTH_URL) .. "/register 2>&1")
  local code = (out or ""):match("(%d%d%d)%s*$")
  local body = (out or ""):gsub("(%d%d%d)%s*$", "")
  return code or "000", body
end
local code, body = register("a", "pass123", "pass123")
report("Inscription — nom trop court → erreur", (code == "200" or code == "400") and body:match("Nom d'utilisateur invalide") ~= nil, "HTTP " .. tostring(code) .. " | " .. tostring(body:sub(1, 100)))
code, body = register("newuser", "pass", "pass")
report("Inscription — mot de passe trop court → erreur", (code == "200" or code == "400") and body:match("8 caractères") ~= nil, "HTTP " .. tostring(code) .. " | " .. tostring(body:sub(1, 100)))
code, body = register("newuser", "pass123", "pass456")
report("Inscription — mots de passe différents → erreur", (code == "200" or code == "400") and body:match("ne correspondent pas") ~= nil, "HTTP " .. tostring(code) .. " | " .. tostring(body:sub(1, 100)))
code, body = register("testuser", "newpass123", "newpass123")
report("Inscription — utilisateur existant → erreur", (code == "200" or code == "409") and (body:match("déjà pris") or body:match("Impossible de créer")) ~= nil, "HTTP " .. tostring(code) .. " | " .. tostring(body:sub(1, 100)))
ssh("grep -v '^newuser:' " .. tostring(CFG_DIR) .. "/secrets > /tmp/_secrets.tmp && mv /tmp/_secrets.tmp " .. tostring(CFG_DIR) .. "/secrets 2>/dev/null; true")
ssh("> " .. tostring(SESSIONS_FILE) .. " 2>/dev/null; true")
code, body = register("newuser", "newpass123", "newpass123")
report("Inscription — nouvel utilisateur → 200", code == "200", "HTTP " .. tostring(code) .. " | " .. tostring(body:sub(1, 100)))
if code == "200" then
  local sess2
  _, sess2 = ssh("cat " .. tostring(SESSIONS_FILE) .. " 2>/dev/null")
  report("Inscription — sessions.lua contient newuser", (sess2 and sess2:match("newuser")) ~= nil, (sess2 or "(absent)"):sub(1, 120))
end
print("")
print(tostring(C.bold) .. "▶ Vérification du log" .. tostring(C.reset))
local cnt_allow
_, cnt_allow = ssh("grep -c ALLOW " .. tostring(LOG_FILE) .. " 2>/dev/null")
local cnt_block
_, cnt_block = ssh("grep -c BLOCK " .. tostring(LOG_FILE) .. " 2>/dev/null")
report("Log contient des entrées ALLOW", (tonumber(cnt_allow or "0") or 0) > 0, "count : " .. tostring(cnt_allow))
report("Log contient des entrées BLOCK", (tonumber(cnt_block or "0") or 0) > 0, "count : " .. tostring(cnt_block))
print("")
print(tostring(C.bold) .. "▶ Liste blanche statique (ip_whitelist, rechargement SIGHUP)" .. tostring(C.reset))
local TEST_WL_IP = "10.253.254.255"
local TEST_WL_IP6 = "fd99::1"
local FILTER_YML = tostring(CFG_DIR) .. "/filter.yml"
ssh("printf '\\nip_whitelist:\\n- " .. tostring(TEST_WL_IP) .. "\\n- " .. tostring(TEST_WL_IP6) .. "\\n' >> " .. tostring(FILTER_YML))
ssh("pid=$(pgrep -f 'luajit2.*main' 2>/dev/null | head -1); [ -n \"$pid\" ] && kill -HUP $pid 2>/dev/null; true")
os.execute("dig @" .. tostring(ROUTER_IP) .. " github.com A +time=2 +tries=1 >/dev/null 2>&1; true")
os.execute("sleep 1")
local wl4_set
_, wl4_set = ssh("nft list set ip  dns-filter ip4_dest_whitelist 2>/dev/null")
report("ip_whitelist — " .. tostring(TEST_WL_IP) .. " présent dans ip4_dest_whitelist après SIGHUP", (wl4_set and wl4_set:match(TEST_WL_IP)) ~= nil, wl4_set or "(vide)")
local wl6_set
_, wl6_set = ssh("nft list set ip6 dns-filter ip6_dest_whitelist 2>/dev/null")
report("ip_whitelist — " .. tostring(TEST_WL_IP6) .. " présent dans ip6_dest_whitelist après SIGHUP", (wl6_set and wl6_set:match("fd99")) ~= nil, wl6_set or "(vide)")
ssh("grep -v '^ip_whitelist:\\|^- " .. tostring(TEST_WL_IP) .. "\\|^- " .. tostring(TEST_WL_IP6) .. "' " .. tostring(FILTER_YML) .. " > /tmp/_filter.tmp && mv /tmp/_filter.tmp " .. tostring(FILTER_YML) .. "; true")
ssh("pid=$(pgrep -f 'luajit2.*main' 2>/dev/null | head -1); [ -n \"$pid\" ] && kill -HUP $pid 2>/dev/null; true")
os.execute("dig @" .. tostring(ROUTER_IP) .. " github.com A +time=2 +tries=1 >/dev/null 2>&1; true")
os.execute("sleep 1")
local wl4_after
_, wl4_after = ssh("nft list set ip dns-filter ip4_dest_whitelist 2>/dev/null")
report("ip_whitelist — set vidé après suppression + SIGHUP", not (wl4_after and wl4_after:match(TEST_WL_IP)), wl4_after or "(vide)")
print("")
print(string.rep("─", 50))
local fail_color = tests_failed > 0 and C.red or C.grey
print(tostring(C.bold) .. "Résumé :" .. tostring(C.reset) .. " " .. tostring(C.green) .. tostring(tests_passed) .. " réussis" .. tostring(C.reset) .. "  " .. tostring(fail_color) .. tostring(tests_failed) .. " échoués" .. tostring(C.reset))
return os.exit(tests_failed > 0 and 1 or 0)
