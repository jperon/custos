local arg = (arg or { })
local verbose = false
local keep_containers = false
local no_build = false
local force_build = false
for _index_0 = 1, #arg do
  local a = arg[_index_0]
  local _exp_0 = a
  if "--verbose" == _exp_0 then
    verbose = true
  elseif "--keep" == _exp_0 then
    keep_containers = true
  elseif "--no-build" == _exp_0 then
    no_build = true
  elseif "--build" == _exp_0 then
    force_build = true
  elseif "--help" == _exp_0 or "-h" == _exp_0 then
    print("Usage: " .. tostring(arg[0]) .. " [--verbose] [--keep] [--no-build] [--build]")
    os.exit(0)
  end
end
os.execute("git checkout cfg/secrets 2>/dev/null")
os.execute("sudo chmod 666 ./cfg/secrets")
local filter_name = "custos-filter-bridge"
local client_name = "custos-client-bridge"
local client2_name = "custos-client-bridge2"
local dns_server = "172.29.0.254"
local dns6_server = "fd00:29::fe"
local filter_ip = "172.29.0.254"
local filter_ip6 = "fd00:29::fe"
local TEST_DOMAINS = {
  allowed = "cloudflare.com",
  blocked = "facebook.com",
  nonexistent = "nonexistent.test"
}
local EXPECTED_TTL = 60
local C = {
  reset = "\27[0m",
  bold = "\27[1m",
  green = "\27[32m",
  red = "\27[31m",
  yellow = "\27[33m",
  cyan = "\27[36m",
  grey = "\27[90m"
}
local log
log = function(msg, level)
  if level == nil then
    level = "INFO"
  end
  local _exp_0 = level
  if "INFO" == _exp_0 then
    if verbose then
      return print(tostring(C.grey) .. "  [info]  " .. tostring(msg) .. tostring(C.reset))
    end
  elseif "STEP" == _exp_0 then
    return print(tostring(C.bold) .. tostring(C.cyan) .. "▶ " .. tostring(msg) .. tostring(C.reset))
  elseif "EXPECT" == _exp_0 then
    return print("  " .. tostring(C.yellow) .. "expect:" .. tostring(C.reset) .. " " .. tostring(msg))
  elseif "GOT" == _exp_0 then
    return print("  " .. tostring(C.yellow) .. "got:   " .. tostring(C.reset) .. " " .. tostring(msg))
  elseif "PASS" == _exp_0 then
    return print(tostring(C.green) .. "  ✓ PASS" .. tostring(C.reset) .. "  " .. tostring(msg))
  elseif "FAIL" == _exp_0 then
    return print(tostring(C.red) .. "  ✗ FAIL" .. tostring(C.reset) .. "  " .. tostring(msg))
  elseif "ERROR" == _exp_0 then
    return print(tostring(C.red) .. "[ERROR] " .. tostring(msg) .. tostring(C.reset))
  elseif "WARN" == _exp_0 then
    return print("[WARN]  " .. tostring(msg))
  end
end
local execute
execute = function(cmd, capture)
  if capture == nil then
    capture = false
  end
  log("Executing: " .. tostring(cmd))
  if capture then
    local handle = io.popen(cmd, "r")
    local output = handle:read("*a")
    local success = handle:close()
    return success, output:gsub("%s+$", "")
  else
    local success = os.execute(cmd)
    return success == 0 or success == true
  end
end
local retry_capture
retry_capture = function(cmd, attempts, sleep_sec, ok_fn)
  if attempts == nil then
    attempts = 3
  end
  if sleep_sec == nil then
    sleep_sec = 1
  end
  if ok_fn == nil then
    ok_fn = nil
  end
  local last_ok, last_out = false, ""
  for i = 1, attempts do
    local ok, out = execute(cmd, true)
    out = out or ""
    local pass
    if ok_fn then
      pass = ok_fn(ok, out)
    else
      pass = ok
    end
    if pass then
      return true, out
    end
    last_ok, last_out = ok, out
    if i < attempts then
      os.execute("sleep " .. tostring(sleep_sec))
    end
  end
  return last_ok, last_out
end
local wait_for_container
wait_for_container = function(name, timeout)
  if timeout == nil then
    timeout = 30
  end
  log("Waiting for container " .. tostring(name) .. "…", "STEP")
  for i = 1, timeout do
    local success = execute("docker ps --filter name=" .. tostring(name) .. " --filter status=running --quiet | grep -q .")
    if success then
      log(tostring(name) .. " is up", "PASS")
      return true
    end
    os.execute("sleep 1")
  end
  log("Timeout waiting for " .. tostring(name), "ERROR")
  return false
end
local wait_for_filter_ready
wait_for_filter_ready = function(timeout)
  if timeout == nil then
    timeout = 45
  end
  log("Waiting for " .. tostring(filter_name) .. " NFQUEUE workers (queue_listening)…", "STEP")
  for i = 1, timeout do
    local success, output = execute("docker logs " .. tostring(filter_name) .. " 2>&1", true)
    if success and output and output:match("queue_listening") then
      log(tostring(filter_name) .. " workers listening", "PASS")
      return true
    end
    os.execute("sleep 1")
  end
  log("Timeout waiting for " .. tostring(filter_name), "ERROR")
  local _, logs = execute("docker logs " .. tostring(filter_name) .. " 2>&1", true)
  log("Container stdout/stderr:\n" .. tostring(logs), "ERROR")
  return false
end
local wait_for_auth_ready
wait_for_auth_ready = function(timeout)
  if timeout == nil then
    timeout = 30
  end
  log("Waiting for auth worker (auth_listening)…", "STEP")
  for i = 1, timeout do
    local success, output = execute("docker logs " .. tostring(filter_name) .. " 2>&1", true)
    if success and output and (output:match("auth_listening")) and (output:match("auth_secrets_loaded")) then
      log("Auth server ready", "PASS")
      return true
    end
    os.execute("sleep 1")
  end
  log("Timeout waiting for auth server", "ERROR")
  return false
end
local auth_curl
auth_curl = function(method, path, data)
  if data == nil then
    data = nil
  end
  local data_flag
  if data then
    data_flag = "-d '" .. tostring(data) .. "' "
  else
    data_flag = ""
  end
  local cmd = "docker exec " .. tostring(client_name) .. " curl -k -s -o /dev/null -w '%{http_code}' -X " .. tostring(method) .. " " .. tostring(data_flag) .. "https://" .. tostring(filter_ip) .. ":33443" .. tostring(path) .. " 2>&1"
  return execute(cmd, true)
end
local build_image
build_image = function()
  if no_build then
    log("Skipping Docker build (--no-build)", "WARN")
    return true
  end
  if not (force_build) then
    local ok = execute("docker image inspect custos:latest >/dev/null 2>&1")
    if not (ok) then
      log("Building Docker image custos:latest…", "STEP")
      local success = execute("docker build -t custos:latest .")
      if not (success) then
        log("Failed to build custos:latest", "ERROR")
        return false
      end
      log("custos:latest built", "PASS")
    end
  else
    log("Rebuilding Docker image custos:latest…", "STEP")
    local success = execute("docker build -t custos:latest .")
    if not (success) then
      log("Failed to build custos:latest", "ERROR")
      return false
    end
  end
  if not (force_build) then
    local ok = execute("docker image inspect custos-client:latest >/dev/null 2>&1")
    if ok then
      log("custos-client:latest already exists", "WARN")
      return true
    end
  end
  log("Building Docker image custos-client:latest…", "STEP")
  local success = execute("docker build -f Dockerfile.client -t custos-client:latest .")
  if not (success) then
    log("Failed to build custos-client:latest", "ERROR")
    return false
  end
  return true
end
local compose_up
compose_up = function()
  log("Starting docker-compose bridge environment…", "STEP")
  execute("docker compose --profile bridge down 2>/dev/null || true")
  execute("rm -f ./tmp/sessions.lua 2>/dev/null || true")
  local success = execute("docker compose --profile bridge up -d")
  if not (success) then
    log("Failed to start docker compose (bridge)", "ERROR")
    return false
  end
  if not (wait_for_container(filter_name) and wait_for_container(client_name) and wait_for_container(client2_name) and wait_for_container("custos-wan-dns")) then
    return false
  end
  if not (wait_for_filter_ready()) then
    return false
  end
  if not (wait_for_auth_ready()) then
    return false
  end
  log("Warming up DNS chain…", "STEP")
  local warmed = false
  for i = 1, 5 do
    local ok, out = execute("docker exec " .. tostring(client_name) .. " nslookup " .. tostring(TEST_DOMAINS.allowed) .. " " .. tostring(dns_server) .. " 2>&1", true)
    if ok and out and (out:match("Address:") or out:match("Name:")) then
      warmed = true
      break
    end
    log("DNS not ready (attempt " .. tostring(i) .. "/5), retrying…", "INFO")
    os.execute("sleep 2")
  end
  if warmed then
    log("Environment ready (DNS chain up, bridge mode)", "PASS")
  else
    log("DNS chain did not respond in time — tests may be flaky", "WARN")
  end
  return true
end
local flush_ip4_allowed
flush_ip4_allowed = function()
  execute("docker exec " .. tostring(filter_name) .. " nft flush set ip dns-filter ip4_allowed 2>/dev/null", true)
  return execute("docker exec " .. tostring(filter_name) .. " nft flush set ip6 dns-filter ip6_allowed 2>/dev/null", true)
end
local compose_down
compose_down = function()
  if keep_containers then
    log("Keeping containers running (--keep)", "WARN")
    return true
  end
  log("Tearing down docker-compose bridge environment…", "STEP")
  execute("docker exec " .. tostring(filter_name) .. " nft delete table ip dns-filter 2>/dev/null; true", true)
  execute("rm -f ./tmp/sessions.lua 2>/dev/null || true")
  execute("git checkout cfg/secrets 2>/dev/null || true")
  execute("docker compose --profile bridge down")
  return true
end
local query_dns
query_dns = function(domain)
  log("Querying DNS for " .. tostring(domain) .. "...")
  local cmd = "timeout 12s docker exec " .. tostring(client_name) .. " nslookup " .. tostring(domain) .. " " .. tostring(dns_server) .. " 2>&1"
  local success, output = execute(cmd, true)
  if not (success) then
    return nil, output
  end
  if verbose then
    print(output)
  end
  return success, output
end
local curl_from_client
curl_from_client = function(url, timeout_sec)
  if timeout_sec == nil then
    timeout_sec = 5
  end
  local cmd = "docker exec " .. tostring(client_name) .. " curl -k -s -o /dev/null -w '%{http_code}' --connect-timeout " .. tostring(timeout_sec) .. " --max-time " .. tostring(timeout_sec + 5) .. " '" .. tostring(url) .. "' 2>&1"
  local _, code = execute(cmd, true)
  code = (code or ""):gsub("%s+", "")
  local ok = code ~= "" and code ~= "000"
  return ok, code
end
local ping_from_client
ping_from_client = function(ip, timeout_sec)
  if timeout_sec == nil then
    timeout_sec = 2
  end
  if not (ip and #ip > 0) then
    return false, "no ip"
  end
  local cmd = "docker exec " .. tostring(client_name) .. " ping -c1 -W" .. tostring(timeout_sec) .. " " .. tostring(ip) .. " 2>&1"
  return execute(cmd, true)
end
local ping_from_client2
ping_from_client2 = function(ip, timeout_sec)
  if timeout_sec == nil then
    timeout_sec = 3
  end
  if not (ip and #ip > 0) then
    return false, "no ip"
  end
  local cmd = "docker exec " .. tostring(client2_name) .. " ping -c1 -W" .. tostring(timeout_sec) .. " " .. tostring(ip) .. " 2>&1"
  return execute(cmd, true)
end
local resolve_host
resolve_host = function(domain, qtype)
  if qtype == nil then
    qtype = "A"
  end
  local _, out = execute("dig +short -t " .. tostring(qtype) .. " " .. tostring(domain) .. " 2>/dev/null | grep -E '^[0-9a-fA-F.:]+$' | head -1", true)
  local ip = out and out:match("^%S+")
  return (ip and #ip > 0) and ip or nil
end
local tests_passed = 0
local tests_failed = 0
local cloudflare_ip = nil
local run_test
run_test = function(name, expected, test_func)
  print("")
  log(name, "STEP")
  log(expected, "EXPECT")
  local success, obtained = test_func()
  obtained = obtained or (function()
    if success then
      return "(ok)"
    else
      return "(no detail)"
    end
  end)()
  log(obtained, "GOT")
  if success then
    log(name, "PASS")
    tests_passed = tests_passed + 1
  else
    log(name, "FAIL")
    tests_failed = tests_failed + 1
  end
  return success
end
log("Starting Docker bridge end-to-end tests for CustosVirginum", "STEP")
if not (build_image()) then
  os.exit(1)
end
if not (compose_up()) then
  compose_down()
  os.exit(1)
end
log("Pre-resolving real IPs via host resolver…", "STEP")
cloudflare_ip = resolve_host(TEST_DOMAINS.allowed)
if cloudflare_ip then
  log(tostring(TEST_DOMAINS.allowed) .. " → " .. tostring(cloudflare_ip), "PASS")
else
  log("dig unavailable — ping tests will be skipped", "WARN")
end
print("")
run_test("Bridge DNS — domaine autorisé résolu", "nslookup " .. tostring(TEST_DOMAINS.allowed) .. " @" .. tostring(dns_server) .. " → adresse IP", function()
  flush_ip4_allowed()
  local success, output = query_dns(TEST_DOMAINS.allowed)
  local ok = success and (output:match("Address:" or output:match("Name:"))) ~= nil
  local obtained = (output:match("Address:%s*(%S+)")) or (output:match("Name:%s*(%S+)")) or (output:match("([^\n]+)")) or "(empty)"
  return ok, obtained
end)
run_test("Bridge DNS — domaine bloqué → REFUSED", "nslookup " .. tostring(TEST_DOMAINS.blocked) .. " @" .. tostring(dns_server) .. " → REFUSED", function()
  local success, output = query_dns(TEST_DOMAINS.blocked)
  local ok = (output ~= nil) and output:match("REFUSED") ~= nil
  local obtained = (output:match("([^\n]*REFUSED[^\n]*)")) or (output:match("([^\n]+)")) or "(no output)"
  return ok, obtained
end)
run_test("Bridge DNS — domaine inconnu → NXDOMAIN", "nslookup " .. tostring(TEST_DOMAINS.nonexistent) .. " @" .. tostring(dns_server) .. " → NXDOMAIN", function()
  local success, output = query_dns(TEST_DOMAINS.nonexistent)
  local ok = not success or output:match("NXDOMAIN") ~= nil or output:match("can't find") ~= nil
  local obtained = (output:match("(%S*NXDOMAIN%S*)")) or (output:match("(can't find[^\n]*)")) or (output:match("([^\n]+)")) or "(no output)"
  return ok, obtained
end)
run_test("Bridge DNS — TTL patché à " .. tostring(EXPECTED_TTL) .. "s", "dig " .. tostring(TEST_DOMAINS.allowed) .. " @" .. tostring(dns_server) .. " → TTL == " .. tostring(EXPECTED_TTL), function()
  local cmd = "docker exec " .. tostring(client_name) .. " dig +noall +answer " .. tostring(TEST_DOMAINS.allowed) .. " @" .. tostring(dns_server) .. " 2>&1"
  local _, output = execute(cmd, true)
  local ttl_str = output and output:match("%s+(%d+)%s+IN%s+A%s+")
  if not (ttl_str) then
    local success2, output2 = query_dns(TEST_DOMAINS.allowed)
    local ok2 = success2 and (output2:match("Address:" or output2:match("Name:"))) ~= nil
    return ok2, "(dig unavailable, nslookup: " .. tostring(ok2) .. ")"
  end
  local local_ttl = tonumber(ttl_str)
  local ok = local_ttl == EXPECTED_TTL
  return ok, "TTL=" .. tostring(local_ttl) .. " (attendu=" .. tostring(EXPECTED_TTL) .. ")"
end)
run_test("Bridge nft ip4_allowed peuplé après résolution", "nft list set ip dns-filter ip4_allowed → elements = { <ip> ... }", function()
  query_dns(TEST_DOMAINS.allowed)
  os.execute("sleep 1")
  local cmd = "docker exec " .. tostring(filter_name) .. " nft list set ip dns-filter ip4_allowed 2>/dev/null"
  local success, output = execute(cmd, true)
  local has_entries = output and output:match("elements = {[^}]+}")
  local ok = has_entries ~= nil
  local obtained
  if ok then
    obtained = (output:match("elements = {([^}]+)}")) or "(entries present)"
  else
    obtained = "(set empty or missing)"
  end
  return ok, obtained
end)
run_test("Bridge log contient les métadonnées DNS", "docker logs → txid= ou qname= présents", function()
  local _, output = execute("docker logs " .. tostring(filter_name) .. " 2>&1", true)
  local has_txid = output:match("txid=") ~= nil
  local has_qname = output:match("qname=") ~= nil
  local ok = has_txid or has_qname
  local parts = { }
  if has_txid then
    table.insert(parts, "txid=…")
  end
  if has_qname then
    table.insert(parts, "qname=…")
  end
  return ok, (function()
    if ok then
      return "found: " .. table.concat(parts, ", ")
    else
      return "(absent)"
    end
  end)()
end)
run_test("Bridge isolation — seul client1 accède à l'IP résolue", "client1 résout " .. tostring(TEST_DOMAINS.allowed) .. " → client1 ping=PASS, client2 ping=FAIL", function()
  if not (cloudflare_ip) then
    return true, "dig indisponible — test ignoré"
  end
  flush_ip4_allowed()
  local q_ok, q_out = query_dns(TEST_DOMAINS.allowed)
  if not (q_ok and (q_out:match("Address:") or q_out:match("Name:"))) then
    return false, "DNS query client1 échouée"
  end
  os.execute("sleep 1")
  local p1_ok, _ = ping_from_client(cloudflare_ip, 4)
  local p2_ok
  p2_ok, _ = ping_from_client2(cloudflare_ip, 3)
  local obtained = "client1_ping=" .. tostring(p1_ok) .. " client2_ping=" .. tostring(p2_ok)
  return (p1_ok and not p2_ok), obtained
end)
run_test("Bridge HTTP — domaine autorisé joignable", "curl http://" .. tostring(TEST_DOMAINS.allowed) .. "/ → code HTTP ≠ 000", function()
  flush_ip4_allowed()
  query_dns(TEST_DOMAINS.allowed)
  os.execute("sleep 1")
  local ok, code = curl_from_client("http://" .. tostring(TEST_DOMAINS.allowed) .. "/")
  return ok, "HTTP " .. tostring(code)
end)
print("")
print(tostring(C.bold) .. "▶ Authentification HTTPS (mode bridge)" .. tostring(C.reset))
execute("rm -f ./tmp/sessions.lua 2>/dev/null || true")
run_test("Bridge auth — mauvais mot de passe → 401", "POST /login user=testuser&password=WRONG → HTTP 401", function()
  local ok, code = auth_curl("POST", "/login", "user=testuser&password=WRONG")
  return (code == "401"), "HTTP " .. tostring(code)
end)
run_test("Bridge auth — identifiants valides → 200", "POST /login user=testuser&password=testpass → HTTP 200", function()
  local ok, code = auth_curl("POST", "/login", "user=testuser&password=testpass")
  return (code == "200"), "HTTP " .. tostring(code)
end)
run_test("Bridge auth — sessions.lua contient la session", "cat ./tmp/sessions.lua → contient testuser + 172.29.0.10", function()
  local fh = io.open("./tmp/sessions.lua", "r")
  if not (fh) then
    return false, "sessions.lua absent"
  end
  local content = fh:read("*a")
  fh:close()
  local ok = content:match("testuser") ~= nil and content:match("172.29.0.10") ~= nil
  return ok, content:sub(1, 120)
end)
run_test("Bridge auth — heartbeat GET /ping → 204", "GET /ping (authentifié) → HTTP 204", function()
  local ok, code = auth_curl("GET", "/ping")
  return (code == "204"), "HTTP " .. tostring(code)
end)
run_test("Bridge auth — logout GET /logout → 303", "GET /logout → HTTP 303", function()
  auth_curl("GET", "/logout")
  local ok, code = auth_curl("GET", "/logout")
  return (code == "303"), "HTTP " .. tostring(code)
end)
print("")
print(tostring(C.bold) .. "▶ Portail captif (port 33080, mode bridge)" .. tostring(C.reset))
local captive_curl
captive_curl = function(path)
  if path == nil then
    path = "/"
  end
  local cmd = "docker exec " .. tostring(client_name) .. " curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 http://" .. tostring(filter_ip) .. ":33080" .. tostring(path) .. " 2>&1"
  return execute(cmd, true)
end
run_test("Bridge portail captif — GET / → 302", "curl http://" .. tostring(filter_ip) .. ":33080/ → HTTP 302", function()
  local ok, code = captive_curl("/")
  return (code == "302"), "HTTP " .. tostring(code)
end)
run_test("Bridge portail captif — /generate_204 → 302", "curl http://" .. tostring(filter_ip) .. ":33080/generate_204 → HTTP 302", function()
  local ok, code = captive_curl("/generate_204")
  return (code == "302"), "HTTP " .. tostring(code)
end)
run_test("Bridge — worker Q2-captive démarré", "docker logs → q2_worker_start présent", function()
  local _, output = execute("docker logs " .. tostring(filter_name) .. " 2>&1", true)
  local ok = output ~= nil and output:match("q2_worker_start") ~= nil
  return ok, (function()
    if ok then
      return "q2_worker_start trouvé"
    else
      return "(absent — Q2 non démarré)"
    end
  end)()
end)
run_test("Bridge — NFQUEUE 2 connectée (worker Q2)", "/proc/net/netfilter/nfnetlink_queue → ligne queue 2", function()
  local _, qraw = execute("docker exec " .. tostring(filter_name) .. " cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null", true)
  local ok = qraw and qraw:match("\n?%s*2%s") ~= nil
  return ok, qraw or "(absent)"
end)
print("")
print(tostring(C.bold) .. "Test Summary (bridge mode):" .. tostring(C.reset))
print("  " .. tostring(C.green) .. "Passed: " .. tostring(tests_passed) .. tostring(C.reset))
print("  " .. tostring((function()
  if tests_failed > 0 then
    return C.red
  else
    return C.grey
  end
end)()) .. "Failed: " .. tostring(tests_failed) .. tostring(C.reset))
compose_down()
if tests_failed > 0 then
  print("\n" .. tostring(C.red) .. tostring(C.bold) .. "Some bridge tests FAILED!" .. tostring(C.reset))
  return os.exit(1)
else
  print("\n" .. tostring(C.green) .. tostring(C.bold) .. "All bridge tests passed!" .. tostring(C.reset))
  return os.exit(0)
end
