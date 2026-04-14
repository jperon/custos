local LIBVIRT_SCRIPT = "libvirt/custos-libvirt.sh"
local CLIENT_VM = "custos-client"
local FILTER_USER = "debian"
local SSH_KEY = (os.getenv("HOME")) .. "/.ssh/id_rsa"
local SSH_OPTS = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes"
local DNS_SERVER = "192.168.200.1"
local DOMAIN_ALLOWED = "github.com"
local DOMAIN_AAAA = "cloudflare.com"
local DOMAIN_BLOCKED = "facebook.com"
local DOMAIN_UNKNOWN = "nonexistent.invalid"
local CLIENT_IP = "10.99.0.10"
local CLIENT2_IP = "10.99.0.11"
local FILTER_IPV6 = "fd99::254"
local CLIENT_IPV6 = "fd99::10"
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
local run
run = function(cmd)
  local fh = io.popen(tostring(cmd) .. " 2>&1")
  local out = fh:read("*a")
  local ok = fh:close()
  return ok, out
end
local run_check
run_check = function(cmd)
  local ok, out = run(cmd)
  if not (ok) then
    error("Command failed: " .. tostring(cmd) .. "\n" .. tostring(out))
  end
  return out
end
local filter_ip
filter_ip = function()
  local ok, out = run("bash " .. tostring(LIBVIRT_SCRIPT) .. " filter-ip")
  if not (ok) then
    error("Cannot determine filter VM IP:\n" .. tostring(out))
  end
  local addr = out:match("%d+%.%d+%.%d+%.%d+")
  if not (addr) then
    error("No IP found in filter-ip output:\n" .. tostring(out))
  end
  return addr
end
local ssh
ssh = function(ip, cmd)
  local escaped = cmd:gsub("'", "'\\''")
  return run("ssh " .. tostring(SSH_OPTS) .. " -i " .. tostring(SSH_KEY) .. " " .. tostring(FILTER_USER) .. "@" .. tostring(ip) .. " '" .. tostring(escaped) .. "'")
end
local ssh_check
ssh_check = function(ip, cmd)
  local ok, out = ssh(ip, cmd)
  if not (ok) then
    error("SSH command failed: " .. tostring(cmd) .. "\n" .. tostring(out))
  end
  return out
end
local guest_exec
guest_exec = function(cmd, timeout_s)
  timeout_s = timeout_s or 10
  local safe_cmd = cmd:gsub('\\', '\\\\\\\\'):gsub('"', '\\"')
  local exec_payload = string.format('{"execute":"guest-exec","arguments":{"path":"/bin/sh","arg":["-c","%s"],"capture-output":true}}', safe_cmd)
  local shell_payload = exec_payload:gsub("'", "'\"'\"'")
  local ok, out = run("LIBVIRT_DEFAULT_URI=qemu:///system virsh qemu-agent-command " .. tostring(CLIENT_VM) .. " '" .. tostring(shell_payload) .. "'")
  if not (ok) then
    return false, "guest-exec failed: " .. tostring(out)
  end
  local pid = out:match('"pid"%s*:%s*(%d+)')
  if not (pid) then
    return false, "no pid in response: " .. tostring(out)
  end
  local deadline = os.time() + timeout_s
  while os.time() <= deadline do
    local _continue_0 = false
    repeat
      do
        os.execute("sleep 1")
        local status_payload = string.format('{"execute":"guest-exec-status","arguments":{"pid":%s}}', pid)
        local ok2, out2 = run("LIBVIRT_DEFAULT_URI=qemu:///system virsh qemu-agent-command " .. tostring(CLIENT_VM) .. " '" .. tostring(status_payload) .. "'")
        if not (ok2) then
          _continue_0 = true
          break
        end
        if not (out2:match('"exited"%s*:%s*true')) then
          _continue_0 = true
          break
        end
        local b64 = out2:match('"out%-data"%s*:%s*"([^"]+)"')
        local decoded = ""
        if b64 then
          local ok3
          ok3, decoded = run("printf '%s' '" .. tostring(b64) .. "' | base64 -d")
        end
        local exit_ok = out2:match('"exitcode"%s*:%s*0')
        return (exit_ok ~= nil), decoded
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return false, "guest-exec timed out after " .. tostring(timeout_s) .. "s"
end
local resolve_host
resolve_host = function(domain)
  local _, out = run("dig +short " .. tostring(domain) .. " 2>/dev/null")
  return out and out:match("%d+%.%d+%.%d+%.%d+")
end
local ping_from
ping_from = function(src_ip, dest_ip, timeout_s)
  if timeout_s == nil then
    timeout_s = 3
  end
  return guest_exec("ping -c1 -W" .. tostring(timeout_s) .. " -I " .. tostring(src_ip) .. " " .. tostring(dest_ip) .. " 2>&1", timeout_s + 4)
end
local curl_from
curl_from = function(url, timeout_s)
  if timeout_s == nil then
    timeout_s = 5
  end
  local cmd = "curl -k -s -o /dev/null --write-out %{http_code} --connect-timeout " .. tostring(timeout_s) .. " --max-time " .. tostring(timeout_s + 5) .. " " .. tostring(url) .. " 2>&1"
  local _, out = guest_exec(cmd, timeout_s + 8)
  local code = (out or ""):match("%d%d%d" or "000")
  local received = code ~= "000"
  return received, code
end
local dig_from
dig_from = function(src_ip, domain, qtype, timeout_s)
  if qtype == nil then
    qtype = "A"
  end
  if timeout_s == nil then
    timeout_s = 15
  end
  return guest_exec("dig +short +time=5 +tries=1 " .. tostring(qtype) .. " " .. tostring(domain) .. " @" .. tostring(DNS_SERVER) .. " -b " .. tostring(src_ip), timeout_s)
end
local nft_dest_for
nft_dest_for = function(set_out, client_ip)
  local escaped = client_ip:gsub("%.", "%%.")
  return set_out and set_out:match(tostring(escaped) .. "%s*%.%s*(%d+%.%d+%.%d+%.%d+)")
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
      return print("    " .. tostring(C.grey) .. tostring(msg:gsub('%s+$', '')) .. tostring(C.reset))
    end
  end
end
print(tostring(C.bold) .. "CustosVirginum — KVM end-to-end tests (bridge mode)" .. tostring(C.reset))
print("")
print(tostring(C.bold) .. "[1/4] Locating filter VM..." .. tostring(C.reset))
local FILTER_IP = filter_ip()
print("  Filter management IP: " .. tostring(FILTER_IP))
print(tostring(C.bold) .. "[2/4] Syncing lua/ + nft-rules/ + cfg/ to filter VM..." .. tostring(C.reset))
ssh_check(FILTER_IP, "sudo mkdir -p /opt/custos/lua /opt/custos/nft-rules /opt/custos/cfg /opt/custos/tmp && sudo chown -R " .. tostring(FILTER_USER) .. ":" .. tostring(FILTER_USER) .. " /opt/custos")
local ssh_opts_inline = SSH_OPTS:gsub("\n", " ")
run_check("rsync -az --delete -e 'ssh " .. tostring(ssh_opts_inline) .. " -i " .. tostring(SSH_KEY) .. "' lua/ " .. tostring(FILTER_USER) .. "@" .. tostring(FILTER_IP) .. ":/opt/custos/lua/")
run_check("rsync -az --delete -e 'ssh " .. tostring(ssh_opts_inline) .. " -i " .. tostring(SSH_KEY) .. "' nft-rules/ " .. tostring(FILTER_USER) .. "@" .. tostring(FILTER_IP) .. ":/opt/custos/nft-rules/")
run_check("rsync -az --delete -e 'ssh " .. tostring(ssh_opts_inline) .. " -i " .. tostring(SSH_KEY) .. "' cfg/ " .. tostring(FILTER_USER) .. "@" .. tostring(FILTER_IP) .. ":/opt/custos/cfg/")
print(tostring(C.bold) .. "[3/4] Loading nft rules and starting LuaJIT..." .. tostring(C.reset))
ssh(FILTER_IP, "for pid in $(sudo pgrep -f luajit 2>/dev/null); do sudo kill $pid 2>/dev/null; done; true")
os.execute("sleep 2")
ssh(FILTER_IP, "sudo nft flush ruleset 2>/dev/null; true")
print("  Installing lua-yaml, lua-socket, lua-sec, openssl on filter VM...")
ssh(FILTER_IP, "sudo apt-get install -y -q lua-yaml lua-socket lua-sec openssl 2>&1 | tail -3; true")
ssh(FILTER_IP, "> /tmp/custos-kvm.log; sudo truncate -s0 /opt/custos/tmp/sessions.lua 2>/dev/null; true")
print("  Creating test secrets (testuser)...")
ssh(FILTER_IP, "sudo mkdir -p /etc/custos && sudo rm -f /etc/custos/secrets")
run("printf 'local c = require(\"auth.credentials\")\\nc.register_user(\"testuser\",\"testpass\",\"/etc/custos/secrets\",{})\\n' | ssh " .. tostring(SSH_OPTS) .. " -i " .. tostring(SSH_KEY) .. " " .. tostring(FILTER_USER) .. "@" .. tostring(FILTER_IP) .. " 'cat > /tmp/mkuser.lua'")
ssh(FILTER_IP, "sudo sh -c 'cd /opt/custos && LUA_PATH=\"lua/?.lua;lua/?/init.lua;;\" luajit /tmp/mkuser.lua'")
ssh_check(FILTER_IP, "sudo nft -f /opt/custos/nft-rules/dns-filter.nft")
ssh_check(FILTER_IP, "nohup sudo sh -c 'cd /opt/custos && LUA_PATH=\"lua/?.lua;lua/?/init.lua;;\" luajit lua/main.lua' </dev/null >>/tmp/custos-kvm.log 2>&1 &")
os.execute("sleep 5")
local ok_luajit, _ = ssh(FILTER_IP, "pgrep -f 'luajit.*main' >/dev/null")
print("  LuaJIT: " .. tostring(ok_luajit and (C.green .. 'running' .. C.reset) or (C.red .. 'NOT running' .. C.reset)))
if not (ok_luajit) then
  error("LuaJIT failed to start — check /tmp/custos-kvm.log on filter VM")
end
print("  Waiting for auth server (auth_listening + auth_secrets_loaded)...")
local auth_ready = false
for _ = 1, 30 do
  local log_content
  _, log_content = ssh(FILTER_IP, "cat /tmp/custos-kvm.log 2>/dev/null")
  if log_content and log_content:match("auth_listening") and log_content:match("auth_secrets_loaded") then
    auth_ready = true
    break
  end
  os.execute("sleep 1")
end
print("  Auth: " .. tostring(auth_ready and (C.green .. 'ready' .. C.reset) or (C.yellow .. 'not ready (auth tests may fail)' .. C.reset)))
print("  Adding IPv6 " .. tostring(FILTER_IPV6) .. "/64 to filter br0...")
ssh(FILTER_IP, "sudo ip addr add " .. tostring(FILTER_IPV6) .. "/64 dev br0 2>/dev/null; true")
print("  Waiting for client guest agent...")
run_check("bash " .. tostring(LIBVIRT_SCRIPT) .. " wait-agents")
local iface_raw
_, iface_raw = guest_exec("ip route get " .. tostring(DNS_SERVER) .. " | sed -En \"s/.*dev ([^ ]+).*/\\1/p\"", 5)
local CLIENT_IFACE = (iface_raw or ""):gsub("%s+", "")
CLIENT_IFACE = #CLIENT_IFACE > 0 and CLIENT_IFACE or "eth0"
print("  Client interface: " .. tostring(CLIENT_IFACE))
print("  Adding IPv6 " .. tostring(CLIENT_IPV6) .. "/64 to client " .. tostring(CLIENT_IFACE) .. "...")
guest_exec("sudo ip addr add " .. tostring(CLIENT_IPV6) .. "/64 dev " .. tostring(CLIENT_IFACE) .. " 2>/dev/null; true", 5)
print("  Adding client2 alias " .. tostring(CLIENT2_IP) .. "/24 to client " .. tostring(CLIENT_IFACE) .. "...")
guest_exec("sudo ip addr add " .. tostring(CLIENT2_IP) .. "/24 dev " .. tostring(CLIENT_IFACE) .. " 2>/dev/null; true", 5)
os.execute("sleep 1")
local c_addr_out
_, c_addr_out = guest_exec("ip addr show dev " .. tostring(CLIENT_IFACE), 5)
if not (c_addr_out and c_addr_out:match(CLIENT_IPV6)) then
  print("  " .. tostring(C.yellow) .. "WARNING: " .. tostring(CLIENT_IPV6) .. " not found on client " .. tostring(CLIENT_IFACE) .. " — AAAA test may skip" .. tostring(C.reset))
end
if not (c_addr_out and c_addr_out:match(CLIENT2_IP:gsub("%.", "%."))) then
  print("  " .. tostring(C.yellow) .. "WARNING: " .. tostring(CLIENT2_IP) .. " not found on client " .. tostring(CLIENT_IFACE) .. " — isolation test may fail" .. tostring(C.reset))
end
print("  Triggering NDP (ping6 filter from client)...")
guest_exec("ping6 -c3 -W1 " .. tostring(FILTER_IPV6) .. " 2>/dev/null; true", 8)
local neigh_ok = false
for _ = 1, 15 do
  local n_out
  _, n_out = ssh(FILTER_IP, "ip -6 neigh show dev br0 2>/dev/null")
  if n_out and n_out:match(CLIENT_IPV6) then
    neigh_ok = true
    break
  end
  os.execute("sleep 1")
end
print("  NDP " .. tostring(CLIENT_IPV6) .. ": " .. tostring(neigh_ok and (C.green .. 'seen' .. C.reset) or (C.yellow .. 'not seen (AAAA test may skip)' .. C.reset)))
local github_ip = resolve_host(DOMAIN_ALLOWED)
local facebook_ip = resolve_host(DOMAIN_BLOCKED)
if github_ip then
  print("  " .. tostring(DOMAIN_ALLOWED) .. " (host resolver) → " .. tostring(github_ip))
end
if facebook_ip then
  print("  " .. tostring(DOMAIN_BLOCKED) .. " (host resolver) → " .. tostring(facebook_ip))
end
print("")
print(tostring(C.bold) .. "[4/4] Running tests" .. tostring(C.reset))
print("")
print(tostring(C.bold) .. "▶ Bridge infrastructure" .. tostring(C.reset))
local ok_br, br_out = ssh(FILTER_IP, "ip link show br0")
report("br0 bridge exists and is UP", (ok_br and br_out:match("UP")) ~= nil, br_out or "")
local ok_sc, sc_out = ssh(FILTER_IP, "cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null")
report("bridge-nf-call-iptables = 1", (ok_sc and sc_out:match("1")) ~= nil, sc_out or "")
local ok_nft, nft_out = ssh(FILTER_IP, "sudo nft list tables")
report("dns-filter tables loaded", (ok_nft and nft_out:match("dns%-filter")) ~= nil, nft_out or "")
local ok_rs, rs_out = ssh(FILTER_IP, "sudo nft list chain ip dns-filter forward 2>/dev/null")
report("DHCPv4 forward — udp dport { 67, 68 } accept", (ok_rs and rs_out:match("67")) ~= nil, "")
local ok_ri, ri_out = ssh(FILTER_IP, "sudo nft list chain ip dns-filter input 2>/dev/null")
report("DHCPv4 input — udp dport 67 accept", (ok_ri and ri_out:match("67")) ~= nil, "")
local ok_6s, s6_out = ssh(FILTER_IP, "sudo nft list chain ip6 dns-filter forward 2>/dev/null")
report("DHCPv6 forward — udp dport { 546, 547 } accept", (ok_6s and s6_out:match("546")) ~= nil, "")
report("SLAAC RA forward — nd-router-advert accept", (ok_6s and s6_out:match("nd%-router%-advert")) ~= nil, "")
local ok_6i, i6_out = ssh(FILTER_IP, "sudo nft list chain ip6 dns-filter input 2>/dev/null")
report("DHCPv6 input — udp dport 547 accept", (ok_6i and i6_out:match("547")) ~= nil, "")
print("")
print(tostring(C.bold) .. "▶ DNS autorisé + ping avant/après (" .. tostring(DOMAIN_ALLOWED) .. ")" .. tostring(C.reset))
ssh(FILTER_IP, "sudo nft flush set ip  dns-filter ip4_allowed 2>/dev/null; true")
ssh(FILTER_IP, "sudo nft flush set ip6 dns-filter ip6_allowed 2>/dev/null; true")
if github_ip then
  local ok_before
  ok_before, _ = ping_from(CLIENT_IP, github_ip, 2)
  report("ping " .. tostring(github_ip) .. " avant résolution (" .. tostring(CLIENT_IP) .. ") : échec attendu", not ok_before, "ip4_allowed vide")
end
local ok_dig, dig_out = dig_from(CLIENT_IP, DOMAIN_ALLOWED, "A", 15)
local has_ip = dig_out and dig_out:match("%d+%.%d+%.%d+%.%d+")
local dig_str = (dig_out or ""):gsub("%s+", " ")
report("dig " .. tostring(DOMAIN_ALLOWED) .. " retourne un enregistrement A", has_ip ~= nil, "dig: " .. tostring(dig_str))
os.execute("sleep 1")
local ok_s, set_out = ssh(FILTER_IP, "sudo nft list set ip dns-filter ip4_allowed")
local allowed_ip = nft_dest_for(set_out, CLIENT_IP)
report("ip4_allowed peuplé après " .. tostring(DOMAIN_ALLOWED), (ok_s and allowed_ip) ~= nil, set_out or "nft error")
if allowed_ip then
  local ok_after, ping_out = ping_from(CLIENT_IP, allowed_ip, 4)
  local p_str = (ping_out or ""):gsub("%s+", " ")
  report("ping " .. tostring(allowed_ip) .. " après résolution (" .. tostring(CLIENT_IP) .. ") : succès attendu", ok_after, p_str)
else
  report("ping après résolution — ip4_allowed vide", false, "")
end
local ok_curl_http, http_code = curl_from("http://" .. tostring(DOMAIN_ALLOWED) .. "/")
report("curl http://" .. tostring(DOMAIN_ALLOWED) .. "/ après résolution : succès attendu", ok_curl_http, "HTTP " .. tostring(http_code))
local ok_curl_https, https_code = curl_from("https://" .. tostring(DOMAIN_ALLOWED) .. "/")
report("curl https://" .. tostring(DOMAIN_ALLOWED) .. "/ après résolution : succès attendu", ok_curl_https, "HTTP " .. tostring(https_code))
print("")
print(tostring(C.bold) .. "▶ DNS refusé + ping avant/après (" .. tostring(DOMAIN_BLOCKED) .. ")" .. tostring(C.reset))
ssh(FILTER_IP, "sudo nft flush set ip dns-filter ip4_allowed 2>/dev/null; true")
if facebook_ip then
  local ok_fb_before
  ok_fb_before, _ = ping_from(CLIENT_IP, facebook_ip, 2)
  report("ping " .. tostring(facebook_ip) .. " avant DNS refusé (" .. tostring(CLIENT_IP) .. ") : échec attendu", not ok_fb_before, "")
end
local blk_out
_, blk_out = guest_exec("dig +time=3 +tries=1 " .. tostring(DOMAIN_BLOCKED) .. " @" .. tostring(DNS_SERVER) .. " 2>&1", 10)
local blk_str = (blk_out or ""):gsub("%s+$", "")
report("dig " .. tostring(DOMAIN_BLOCKED) .. " retourne REFUSED", (blk_out and blk_out:lower():match("refused")) ~= nil, "dig: " .. tostring(blk_str))
os.execute("sleep 1")
local blk_set_out
_, blk_set_out = ssh(FILTER_IP, "sudo nft list set ip dns-filter ip4_allowed")
report("ip4_allowed vide après DNS refusé (" .. tostring(DOMAIN_BLOCKED) .. ")", not (blk_set_out and blk_set_out:match("%d+%.%d+%.%d+%.%d+")), blk_set_out or "")
if facebook_ip then
  local ok_fb_after
  ok_fb_after, _ = ping_from(CLIENT_IP, facebook_ip, 2)
  report("ping " .. tostring(facebook_ip) .. " après DNS refusé (" .. tostring(CLIENT_IP) .. ") : échec attendu", not ok_fb_after, "")
end
local ok_curl_blk, blk_curl_code = curl_from("http://" .. tostring(DOMAIN_BLOCKED) .. "/")
report("curl http://" .. tostring(DOMAIN_BLOCKED) .. "/ après DNS refusé : échec attendu (000)", blk_curl_code == "000", "HTTP " .. tostring(blk_curl_code))
print("")
print(tostring(C.bold) .. "▶ Domaine inconnu — NXDOMAIN (" .. tostring(DOMAIN_UNKNOWN) .. ")" .. tostring(C.reset))
local unk_out
_, unk_out = guest_exec("dig +time=5 +tries=1 " .. tostring(DOMAIN_UNKNOWN) .. " @" .. tostring(DNS_SERVER) .. " 2>&1", 15)
local unk_str = (unk_out or ""):gsub("%s+$", "")
report("dig " .. tostring(DOMAIN_UNKNOWN) .. " retourne NXDOMAIN", (unk_out and unk_out:upper():match("NXDOMAIN")) ~= nil, "dig: " .. tostring(unk_str))
print("")
print(tostring(C.bold) .. "▶ Enregistrements AAAA → ip6_allowed (" .. tostring(DOMAIN_AAAA) .. ")" .. tostring(C.reset))
ssh(FILTER_IP, "sudo nft flush set ip6 dns-filter ip6_allowed 2>/dev/null; true")
local ok_aaaa, aaaa_out = dig_from(CLIENT_IP, DOMAIN_AAAA, "AAAA", 15)
local aaaa_str = (aaaa_out or ""):gsub("%s+", " ")
local has_aaaa = aaaa_out and aaaa_out:match("[0-9a-f]+:[0-9a-f:]+")
if has_aaaa then
  os.execute("sleep 1")
  local ok_s6, set6_out = ssh(FILTER_IP, "sudo nft list set ip6 dns-filter ip6_allowed")
  local s6_str = (set6_out or ""):gsub("%s+", " ")
  report("ip6_allowed peuplé après résolution AAAA " .. tostring(DOMAIN_AAAA), (ok_s6 and set6_out:match("[0-9a-f]+:[0-9a-f:]+")) ~= nil, s6_str)
else
  report("AAAA " .. tostring(DOMAIN_AAAA) .. " — pas d'enregistrement upstream (ignoré)", true, "aaaa: " .. tostring(aaaa_str))
end
print("")
print(tostring(C.bold) .. "▶ Isolation par client (client1=" .. tostring(CLIENT_IP) .. ", client2=" .. tostring(CLIENT2_IP) .. ")" .. tostring(C.reset))
ssh(FILTER_IP, "sudo nft flush set ip dns-filter ip4_allowed 2>/dev/null; true")
local ok_c1, c1_out = dig_from(CLIENT_IP, DOMAIN_ALLOWED)
local c1_has_ip = c1_out and c1_out:match("%d+%.%d+%.%d+%.%d+")
report("client1 (" .. tostring(CLIENT_IP) .. ") résout " .. tostring(DOMAIN_ALLOWED), c1_has_ip ~= nil, (c1_out or ""):gsub("%s+", " "))
os.execute("sleep 1")
local cs_out
_, cs_out = ssh(FILTER_IP, "sudo nft list set ip dns-filter ip4_allowed")
local c1_dest = nft_dest_for(cs_out, CLIENT_IP)
if c1_dest then
  local ok_c1ping, c1ping_out = ping_from(CLIENT_IP, c1_dest, 4)
  report("client1 ping " .. tostring(c1_dest) .. " après résolution : succès attendu", ok_c1ping, (c1ping_out or ""):gsub("%s+$", ""))
  local ok_c2ping_before
  ok_c2ping_before, _ = ping_from(CLIENT2_IP, c1_dest, 2)
  report("client2 (" .. tostring(CLIENT2_IP) .. ") ping " .. tostring(c1_dest) .. " avant résolution : échec attendu", not ok_c2ping_before, "")
  local ok_c2, c2_out = dig_from(CLIENT2_IP, DOMAIN_ALLOWED)
  local c2_has_ip = c2_out and c2_out:match("%d+%.%d+%.%d+%.%d+")
  report("client2 (" .. tostring(CLIENT2_IP) .. ") résout " .. tostring(DOMAIN_ALLOWED), c2_has_ip ~= nil, (c2_out or ""):gsub("%s+", " "))
  os.execute("sleep 1")
  local cs2_out
  _, cs2_out = ssh(FILTER_IP, "sudo nft list set ip dns-filter ip4_allowed")
  local c2_dest = nft_dest_for(cs2_out, CLIENT2_IP)
  if c2_dest then
    local ok_c2ping_after, c2ping2_out = ping_from(CLIENT2_IP, c2_dest, 4)
    report("client2 ping " .. tostring(c2_dest) .. " après résolution : succès attendu", ok_c2ping_after, (c2ping2_out or ""):gsub("%s+$", ""))
  else
    report("client2 dans ip4_allowed après résolution", false, tostring(CLIENT2_IP) .. " introuvable dans le set")
  end
else
  report("isolation client — client1 dest introuvable dans ip4_allowed", false, cs_out or "set vide")
end
print("")
print(tostring(C.bold) .. "▶ LuaJIT filter log" .. tostring(C.reset))
local log_allow
_, log_allow = ssh(FILTER_IP, "grep -c ALLOW /tmp/custos-kvm.log 2>/dev/null")
local log_block
_, log_block = ssh(FILTER_IP, "grep -c BLOCK /tmp/custos-kvm.log 2>/dev/null")
report("log has allowed entries", (tonumber(log_allow or "0") or 0) > 0, "grep ALLOW count: " .. tostring(log_allow))
report("log has blocked/refused entries", (tonumber(log_block or "0") or 0) > 0, "grep BLOCK count: " .. tostring(log_block))
local FILTER_LAN_IP = "10.99.0.254"
local AUTH_URL = "https://" .. tostring(FILTER_LAN_IP) .. ":33443"
print("")
print(tostring(C.bold) .. "▶ Authentification HTTPS (" .. tostring(AUTH_URL) .. ")" .. tostring(C.reset))
ssh(FILTER_IP, "sudo truncate -s0 /opt/custos/tmp/sessions.lua 2>/dev/null; true")
local auth_curl_kvm
auth_curl_kvm = function(method, path, data)
  local data_flag
  if data then
    data_flag = "-d '" .. tostring(data) .. "' "
  else
    data_flag = ""
  end
  local cmd = "curl -k -s -o /dev/null -w '%{http_code}' -X " .. tostring(method) .. " " .. tostring(data_flag) .. tostring(AUTH_URL) .. tostring(path) .. " 2>&1"
  return guest_exec(cmd, 10)
end
local ok_bad, bad_code = auth_curl_kvm("POST", "/login", "user=testuser&password=WRONG")
bad_code = (bad_code or ""):gsub("%s+", "")
report("Auth — mauvais mot de passe → 401", bad_code == "401", "HTTP " .. tostring(bad_code))
local ok_ok, ok_code = auth_curl_kvm("POST", "/login", "user=testuser&password=testpass")
ok_code = (ok_code or ""):gsub("%s+", "")
report("Auth — identifiants valides → 200", ok_code == "200", "HTTP " .. tostring(ok_code))
local sess_out
_, sess_out = ssh(FILTER_IP, "sudo cat /opt/custos/tmp/sessions.lua 2>/dev/null")
report("Auth — sessions.lua contient testuser + IP client", (sess_out and sess_out:match("testuser") and sess_out:match("10.99.0.10")) ~= nil, (sess_out or "(absent)"):sub(1, 120))
local ok_ping, ping_code = auth_curl_kvm("GET", "/ping")
ping_code = (ping_code or ""):gsub("%s+", "")
report("Auth — heartbeat GET /ping → 204", ping_code == "204", "HTTP " .. tostring(ping_code))
print("  Waiting 6s for session cache...")
os.execute("sleep 6")
local ok_nxd, nxd_out = guest_exec("dig +time=12 +tries=1 auth-required.test @" .. tostring(DNS_SERVER) .. " 2>&1", 20)
local nxd_str = (nxd_out or ""):gsub("%s+$", "")
report("Auth — from_user : auth-required.test → NXDOMAIN après login", (nxd_out and (nxd_out:lower():match("nxdomain") or nxd_out:match("can't find"))) ~= nil, "dig: " .. tostring(nxd_str))
local ok_out, out_code = auth_curl_kvm("GET", "/logout")
out_code = (out_code or ""):gsub("%s+", "")
report("Auth — logout → 303", out_code == "303", "HTTP " .. tostring(out_code))
print("  Waiting 6s after logout...")
os.execute("sleep 6")
local ok_ref, ref_out = guest_exec("dig +time=5 +tries=1 auth-required.test @" .. tostring(DNS_SERVER) .. " 2>&1", 12)
local ref_str = (ref_out or ""):gsub("%s+$", "")
report("Auth — from_user : auth-required.test → REFUSED après logout", (ref_out and ref_out:upper():match("REFUSED")) ~= nil, "dig: " .. tostring(ref_str))
print("")
print(tostring(C.bold) .. "▶ Portail captif (port 33080)" .. tostring(C.reset))
local CAPTIVE_URL = "http://" .. tostring(FILTER_LAN_IP) .. ":33080"
local captive_curl_kvm
captive_curl_kvm = function(path)
  if path == nil then
    path = "/"
  end
  local cmd = "curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 " .. tostring(CAPTIVE_URL) .. tostring(path) .. " 2>&1"
  return guest_exec(cmd, 10)
end
local ok_cp, cp_code = captive_curl_kvm("/")
cp_code = (cp_code or ""):gsub("%s+", "")
report("Portail captif — requête HTTP → 302", cp_code == "302", "HTTP " .. tostring(cp_code))
local ok_g204, g204_code = captive_curl_kvm("/generate_204")
g204_code = (g204_code or ""):gsub("%s+", "")
report("Portail captif — sonde Android /generate_204 → 302", g204_code == "302", "HTTP " .. tostring(g204_code))
auth_curl_kvm("POST", "/login", "user=testuser&password=testpass")
os.execute("sleep 1")
local auth_nft_out
_, auth_nft_out = ssh(FILTER_IP, "sudo nft list set ip dns-filter authenticated_ips 2>/dev/null")
report("Portail captif — IP dans authenticated_ips après login", (auth_nft_out and auth_nft_out:match("10.99.0.10")) ~= nil, (auth_nft_out or "(absent)"):sub(1, 120))
auth_curl_kvm("GET", "/logout")
os.execute("sleep 1")
local auth_nft_out2
_, auth_nft_out2 = ssh(FILTER_IP, "sudo nft list set ip dns-filter authenticated_ips 2>/dev/null")
report("Portail captif — IP retirée de authenticated_ips après logout", (auth_nft_out2 == nil or auth_nft_out2:match("10.99.0.10") == nil), (auth_nft_out2 or "(set vide)"):sub(1, 120))
print("")
print(tostring(C.bold) .. "▶ Inscription d'utilisateurs" .. tostring(C.reset))
ssh(FILTER_IP, "sudo truncate -s0 /opt/custos/tmp/sessions.lua 2>/dev/null; true")
report("Inscription — nom d'utilisateur trop court → erreur", function()
  local cmd = "curl -k -s -w '%{http_code}' -X POST -d 'user=a&password=pass123&password2=pass123' " .. tostring(AUTH_URL) .. "/register"
  local ok, output = guest_exec(cmd, 10)
  local code = (output and output:match("(%d+)$")) or ""
  if code == "200" or code == "400" then
    if output:match("Nom d'utilisateur invalide") then
      return true, "HTTP " .. tostring(code) .. " (erreur attendue)"
    else
      return false, "HTTP " .. tostring(code) .. " mais pas de message d'erreur"
    end
  else
    return false, "HTTP " .. tostring(code) .. " (attendu 200 ou 400)"
  end
end)
report("Inscription — mot de passe trop court → erreur", function()
  local cmd = "curl -k -s -w '%{http_code}' -X POST -d 'user=newuser&password=pass&password2=pass' " .. tostring(AUTH_URL) .. "/register"
  local ok, output = guest_exec(cmd, 10)
  local code = (output and output:match("(%d+)$")) or ""
  if code == "200" or code == "400" then
    if output:match("8 caractères") then
      return true, "HTTP " .. tostring(code) .. " (erreur attendue)"
    else
      return false, "HTTP " .. tostring(code) .. " mais pas de message d'erreur"
    end
  else
    return false, "HTTP " .. tostring(code) .. " (attendu 200 ou 400)"
  end
end)
report("Inscription — mots de passe différents → erreur", function()
  local cmd = "curl -k -s -w '%{http_code}' -X POST -d 'user=newuser&password=pass123&password2=pass456' " .. tostring(AUTH_URL) .. "/register"
  local ok, output = guest_exec(cmd, 10)
  local code = (output and output:match("(%d+)$")) or ""
  if code == "200" or code == "400" then
    if output:match("ne correspondent pas") then
      return true, "HTTP " .. tostring(code) .. " (erreur attendue)"
    else
      return false, "HTTP " .. tostring(code) .. " mais pas de message d'erreur"
    end
  else
    return false, "HTTP " .. tostring(code) .. " (attendu 200 ou 400)"
  end
end)
report("Inscription — utilisateur déjà existant → erreur", function()
  local cmd = "curl -k -s -w '%{http_code}' -X POST -d 'user=testuser&password=newpass123&password2=newpass123' " .. tostring(AUTH_URL) .. "/register"
  local ok, output = guest_exec(cmd, 10)
  local code = (output and output:match("(%d+)$")) or ""
  if code == "200" or code == "409" then
    if output:match("déjà pris") or output:match("Impossible de créer") then
      return true, "HTTP " .. tostring(code) .. " (erreur attendue)"
    else
      return false, "HTTP " .. tostring(code) .. " mais pas de message d'erreur"
    end
  else
    return false, "HTTP " .. tostring(code) .. " (attendu 200 ou 409)"
  end
end)
report("Inscription — nouvel utilisateur réussi → auto-login + session créée", function()
  local cmd = "curl -k -s -w '%{http_code}' -X POST -d 'user=newuser&password=newpass123&password2=newpass123' " .. tostring(AUTH_URL) .. "/register"
  local ok, output = guest_exec(cmd, 10)
  local code = (output and output:match("(%d+)$")) or ""
  if code == "200" then
    _, sess_out = ssh(FILTER_IP, "sudo cat /opt/custos/tmp/sessions.lua 2>/dev/null")
    if sess_out and sess_out:match("newuser") and sess_out:match(CLIENT_IP) then
      local cmd_login = "curl -s -o /dev/null -w '%{http_code}' -X POST -k -d 'user=newuser&password=newpass123' " .. tostring(AUTH_URL) .. "/login"
      local ok_login, code_login = guest_exec(cmd_login, 10)
      code_login = (code_login or ""):gsub("%s+", "")
      return ok_login and code_login == "200", "HTTP " .. tostring(code) .. " (inscription ok), login: " .. tostring(code_login)
    else
      return false, "HTTP " .. tostring(code) .. " mais sessions.lua ne contient pas newuser"
    end
  else
    return false, "HTTP " .. tostring(code) .. " (attendu 200)"
  end
end)
print("  Waiting 6s for session cache to settle after registration...")
os.execute("sleep 6")
report("Inscription — from_user : domaine autorisé après login → NXDOMAIN", function()
  local cmd = "dig +time=12 +tries=1 auth-required.test @" .. tostring(DNS_SERVER) .. " 2>&1"
  local output
  _, output = guest_exec(cmd, 20)
  local ok = output ~= nil and (output:upper():match("NXDOMAIN") ~= nil or output:match("can't find") ~= nil)
  local obtained = (output:match("([^\n]*NXDOMAIN[^\n]*)")) or (output:match("(can't find[^\n]*)")) or (output:match("([^\n]+)")) or "(no output)"
  return ok, obtained
end)
print("")
print(tostring(C.bold) .. "▶ DNS over TCP + TTL patching" .. tostring(C.reset))
local ok_tcp, tcp_out = guest_exec("dig +tcp +time=5 +tries=1 " .. tostring(DOMAIN_ALLOWED) .. " @" .. tostring(DNS_SERVER) .. " 2>&1", 12)
local tcp_has_ip = tcp_out and tcp_out:match("%d+%.%d+%.%d+%.%d+")
local tcp_str = (tcp_out or ""):gsub("%s+$", "")
report("DNS over TCP " .. tostring(DOMAIN_ALLOWED) .. " — répond avec des enregistrements A", tcp_has_ip ~= nil, "dig +tcp: " .. tostring(tcp_str:sub(1, 100)))
local tcp_ttl = nil
if tcp_out then
  tcp_ttl = tcp_out:match("\t(%d+)\t[^\t]*IN\t[^\t]*A\t")
  tcp_ttl = tcp_ttl or tcp_out:match("(%d+)\t+IN\t+A\t")
end
report("DNS over TCP " .. tostring(DOMAIN_ALLOWED) .. " — TTL patché à 60", tcp_ttl == "60", "TTL trouvé: " .. tostring(tostring(tcp_ttl)))
print("")
print(tostring(C.bold) .. "▶ DNAT — TCP port 80 non authentifié → portail captif" .. tostring(C.reset))
auth_curl_kvm("GET", "/logout")
os.execute("sleep 2")
local ok_dnat, dnat_code = guest_exec("curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 --connect-timeout 5 http://1.2.3.4/ 2>&1", 10)
dnat_code = (dnat_code or ""):gsub("%s+", "")
report("DNAT — TCP port 80 non authentifié → 302", dnat_code == "302", "HTTP " .. tostring(dnat_code))
ssh(FILTER_IP, "for pid in $(sudo pgrep -f luajit 2>/dev/null); do sudo kill $pid 2>/dev/null; done; sudo nft flush ruleset 2>/dev/null; true")
print("")
print((string.rep("─", 50)))
local fail_color = tests_failed > 0 and C.red or C.grey
print(tostring(C.bold) .. "Summary:" .. tostring(C.reset) .. " " .. tostring(C.green) .. tostring(tests_passed) .. " passed" .. tostring(C.reset) .. "  " .. tostring(fail_color) .. tostring(tests_failed) .. " failed" .. tostring(C.reset))
return os.exit(tests_failed > 0 and 1 or 0)
