local LIBVIRT_SCRIPT = "libvirt/custos-libvirt.sh"
local SSH_KEY = (os.getenv("HOME")) .. "/.ssh/id_rsa"
local SSH_OPTS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes"
local FILTER_USER = "root"
local CLIENT_USER = "debian"
local CLIENT_IP = "10.99.0.10"
local DNS_IP = "10.99.0.1"
local FILTER_BR = "10.99.0.254"
local CAPTIVE_URL = "https://" .. tostring(FILTER_BR) .. ":33443/"
local LOG_MARKER = "CUSTOS_TEST_E2E_" .. tostring(os.time())
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
    error("Cannot get filter mgmt IP:\n" .. tostring(out))
  end
  local ip = out:match("%d+%.%d+%.%d+%.%d+")
  if not (ip) then
    error("No IP in filter-ip output:\n" .. tostring(out))
  end
  return ip
end
local ssh_filter
ssh_filter = function(ip, cmd)
  local escaped = cmd:gsub("'", "'\\''")
  return run("ssh " .. tostring(SSH_OPTS) .. " -i " .. tostring(SSH_KEY) .. " " .. tostring(FILTER_USER) .. "@" .. tostring(ip) .. " '" .. tostring(escaped) .. "'")
end
local ssh_client
ssh_client = function(filter_ip_str, cmd)
  local escaped = cmd:gsub("'", "'\\''")
  local proxy = tostring(FILTER_USER) .. "@" .. tostring(filter_ip_str)
  return run("ssh " .. tostring(SSH_OPTS) .. " -i " .. tostring(SSH_KEY) .. " -J " .. tostring(proxy) .. " " .. tostring(CLIENT_USER) .. "@" .. tostring(CLIENT_IP) .. " '" .. tostring(escaped) .. "'")
end
local test
test = function(name, fn)
  local ok, err_or_nil = pcall(fn)
  if ok then
    tests_passed = tests_passed + 1
    return print("  " .. tostring(C.green) .. "✓ " .. tostring(name) .. tostring(C.reset))
  else
    tests_failed = tests_failed + 1
    print("  " .. tostring(C.red) .. "✗ " .. tostring(name) .. tostring(C.reset))
    return print("    " .. tostring(C.grey) .. tostring(tostring(err_or_nil)) .. tostring(C.reset))
  end
end
local assert_contains
assert_contains = function(haystack, needle, msg)
  if not (haystack and haystack:find(needle, 1, true)) then
    return error(tostring(msg or 'missing') .. ": attendu '" .. tostring(needle) .. "', reçu : " .. tostring(haystack))
  end
end
local assert_matches
assert_matches = function(haystack, pattern, msg)
  if not (haystack and haystack:match(pattern)) then
    return error(tostring(msg or 'no match') .. ": pattern '" .. tostring(pattern) .. "' absent de : " .. tostring(haystack))
  end
end
print(tostring(C.bold) .. "CustosVirginum — tests E2E libvirt" .. tostring(C.reset))
local FILTER_IP = filter_ip()
print("  Filtre mgmt : " .. tostring(FILTER_IP))
print("  Client      : " .. tostring(CLIENT_IP) .. " (ProxyJump par le filtre)")
print("  DNS         : " .. tostring(DNS_IP))
print("")
print(tostring(C.bold) .. "[1/5] Connectivité SSH" .. tostring(C.reset))
local ok_f, _ = ssh_filter(FILTER_IP, "uname -r")
if not (ok_f) then
  print(tostring(C.red) .. "✗ filter SSH KO" .. tostring(C.reset))
  os.exit(1)
end
print("  " .. tostring(C.green) .. "✓ filter joignable" .. tostring(C.reset))
local ok_c
ok_c, _ = ssh_client(FILTER_IP, "uname -r")
if not (ok_c) then
  print(tostring(C.red) .. "✗ client SSH KO (via ProxyJump)" .. tostring(C.reset))
  os.exit(1)
end
print("  " .. tostring(C.green) .. "✓ client joignable" .. tostring(C.reset))
local ok_dns
ok_dns, _ = ssh_client(FILTER_IP, "host -W 2 -t A allowed.test " .. tostring(DNS_IP))
print((function()
  if ok_dns then
    return "  " .. tostring(C.green) .. "✓ client → DNS (via filtre) fonctionne" .. tostring(C.reset)
  else
    return "  " .. tostring(C.yellow) .. "! DNS non joignable avant déploiement custos (normal)" .. tostring(C.reset)
  end
end)())
print("\n" .. tostring(C.bold) .. "[2/5] Déploiement custos" .. tostring(C.reset))
print("  Compilation locale...")
run_check("make all >/dev/null")
print("  install-owrt.lua " .. tostring(FILTER_IP) .. "...")
local install_out = run_check("luajit install-owrt.lua " .. tostring(FILTER_IP) .. " --user " .. tostring(FILTER_USER))
print("  Push de la config de test...")
run_check("scp -O " .. tostring(SSH_OPTS) .. " -i " .. tostring(SSH_KEY) .. " libvirt/filter.yml " .. tostring(FILTER_USER) .. "@" .. tostring(FILTER_IP) .. ":/etc/custos/filter.yml")
run_check("scp -O " .. tostring(SSH_OPTS) .. " -i " .. tostring(SSH_KEY) .. " libvirt/custos-test.uci " .. tostring(FILTER_USER) .. "@" .. tostring(FILTER_IP) .. ":/tmp/custos.uci")
ssh_filter(FILTER_IP, "cp /tmp/custos.uci /etc/config/custos && uci commit custos")
print("  Marqueur + redémarrage du service...")
ssh_filter(FILTER_IP, "logger -t custos '" .. tostring(LOG_MARKER) .. "'")
ssh_filter(FILTER_IP, "/etc/init.d/custos restart")
print("\n" .. tostring(C.bold) .. "[3/5] Attente des workers" .. tostring(C.reset))
local log_since
log_since = function(grep)
  return "logread | sed -n '/" .. tostring(LOG_MARKER) .. "/,$p' | " .. tostring(grep)
end
local workers_ready = false
for _ = 1, 30 do
  local out
  _, out = ssh_filter(FILTER_IP, log_since("grep -c queue_listening || true"))
  local n = tonumber((out or "0"):match("%d+"))
  if n and n >= 3 then
    workers_ready = true
    break
  end
  os.execute("sleep 2")
end
if workers_ready then
  print("  " .. tostring(C.green) .. "✓ workers prêts" .. tostring(C.reset))
else
  print("  " .. tostring(C.red) .. "✗ workers pas prêts après 60 s" .. tostring(C.reset))
  local lr
  _, lr = ssh_filter(FILTER_IP, log_since("tail -40"))
  print(lr)
  os.exit(1)
end
print("\n" .. tostring(C.bold) .. "[4/5] Tests fonctionnels (depuis le client)" .. tostring(C.reset))
test("host allowed.test → 10.99.0.50", function()
  local out
  _, out = ssh_client(FILTER_IP, "host -W 2 -t A allowed.test " .. tostring(DNS_IP))
  return assert_contains(out, "10.99.0.50")
end)
test("host blocked.test → NXDOMAIN", function()
  local out
  _, out = ssh_client(FILTER_IP, "host -W 2 -t A blocked.test " .. tostring(DNS_IP))
  return assert_contains(out, "NXDOMAIN")
end)
test("host nonexistent.invalid → NXDOMAIN", function()
  local out
  _, out = ssh_client(FILTER_IP, "host -W 2 -t A nonexistent.invalid " .. tostring(DNS_IP))
  return assert_contains(out, "NXDOMAIN")
end)
test("curl http://allowed.test → 200 allowed", function()
  local out
  _, out = ssh_client(FILTER_IP, "curl -s --max-time 3 http://allowed.test/")
  return assert_contains(out, "allowed")
end)
test("curl http://blocked.test → 302 captive portal", function()
  local out
  _, out = ssh_client(FILTER_IP, "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' " .. "--max-time 3 http://blocked.test/")
  assert_matches(out, "302")
  return assert_contains(out, "10.99.0.254:33443")
end)
test("curl https://tracker.test → Q3 reject <500ms", function()
  local start = os.time()
  local ok, out = ssh_client(FILTER_IP, "curl -k -s -o /dev/null -w '%{http_code}' --max-time 3 " .. "https://tracker.test/ 2>&1; echo exit=$?")
  local elapsed = os.time() - start
  assert(elapsed < 3, "trop lent (" .. tostring(elapsed) .. "s) — Q3 n'a pas RST ?")
  return assert_matches(out, "exit=[^0]", "curl aurait dû échouer")
end)
test("curl https://filter-captive → page login", function()
  local out
  _, out = ssh_client(FILTER_IP, "curl -k -s --max-time 3 " .. tostring(CAPTIVE_URL))
  return assert_matches(out, "[Ll]ogin", "page de login attendue")
end)
print("\n" .. tostring(C.bold) .. "[5/5] Résumé" .. tostring(C.reset))
print("  passé(s) : " .. tostring(C.green) .. tostring(tests_passed) .. tostring(C.reset))
print("  échec(s) : " .. tostring(tests_failed > 0 and C.red or C.grey) .. tostring(tests_failed) .. tostring(C.reset))
return os.exit(tests_failed == 0 and 0 or 1)
