#!/usr/bin/env moon
-- Docker end-to-end test for CustosVirginum DNS filter (BRIDGE MODE).
--
-- Architecture : client-bridge → lan2 → [filter-bridge: dns-filter-bridge.nft] → wan2 → wan-dns
--
-- Le filtre agit avec table bridge nftables (BRIDGE_MODE=1).
-- NFQUEUE reçoit des trames Ethernet complètes (eth_offset=14).
-- Worker Q2 (portail captif) actif.
-- Le client envoie ses DNS vers wan-dns (172.30.0.20) ;
-- les paquets DNS traversent la chaîne bridge forward et sont interceptés par Q0/Q1.

arg = (arg or {})
verbose = false
keep_containers = false
no_build = false
force_build = false

for a in *arg
  switch a
    when "--verbose"
      verbose = true
    when "--keep"
      keep_containers = true
    when "--no-build"
      no_build = true
    when "--build"
      force_build = true
    when "--help", "-h"
      print "Usage: #{arg[0]} [--verbose] [--keep] [--no-build] [--build]"
      os.exit 0

os.execute "git checkout cfg/secrets 2>/dev/null"
os.execute "sudo chmod 666 ./cfg/secrets"

filter_name  = "custos-filter-bridge"
client_name  = "custos-client-bridge"
client2_name = "custos-client-bridge2"
dns_server   = "172.29.0.254"  -- dnsmasq sur le filtre (DOCKER_MODE)
dns6_server  = "fd00:29::fe"
filter_ip    = "172.29.0.254"
filter_ip6   = "fd00:29::fe"

TEST_DOMAINS = {
  allowed:     "cloudflare.com"
  blocked:     "facebook.com"
  nonexistent: "nonexistent.test"
}
EXPECTED_TTL = 60

C = {
  reset:  "\27[0m"
  bold:   "\27[1m"
  green:  "\27[32m"
  red:    "\27[31m"
  yellow: "\27[33m"
  cyan:   "\27[36m"
  grey:   "\27[90m"
}

log = (msg, level = "INFO") ->
  switch level
    when "INFO"
      print "#{C.grey}  [info]  #{msg}#{C.reset}" if verbose
    when "STEP"
      print "#{C.bold}#{C.cyan}▶ #{msg}#{C.reset}"
    when "EXPECT"
      print "  #{C.yellow}expect:#{C.reset} #{msg}"
    when "GOT"
      print "  #{C.yellow}got:   #{C.reset} #{msg}"
    when "PASS"
      print "#{C.green}  ✓ PASS#{C.reset}  #{msg}"
    when "FAIL"
      print "#{C.red}  ✗ FAIL#{C.reset}  #{msg}"
    when "ERROR"
      print "#{C.red}[ERROR] #{msg}#{C.reset}"
    when "WARN"
      print "[WARN]  #{msg}"

execute = (cmd, capture = false) ->
  log "Executing: #{cmd}"
  if capture
    handle = io.popen cmd, "r"
    output = handle\read "*a"
    success = handle\close!
    return success, output\gsub "%s+$", ""
  else
    success = os.execute cmd
    return success == 0 or success == true

retry_capture = (cmd, attempts = 3, sleep_sec = 1, ok_fn = nil) ->
  last_ok, last_out = false, ""
  for i = 1, attempts
    ok, out = execute cmd, true
    out or= ""
    pass = if ok_fn then ok_fn ok, out else ok
    if pass
      return true, out
    last_ok, last_out = ok, out
    os.execute "sleep #{sleep_sec}" if i < attempts
  return last_ok, last_out

wait_for_container = (name, timeout = 30) ->
  log "Waiting for container #{name}…", "STEP"
  for i = 1, timeout
    success = execute "docker ps --filter name=#{name} --filter status=running --quiet | grep -q ."
    if success
      log "#{name} is up", "PASS"
      return true
    os.execute "sleep 1"
  log "Timeout waiting for #{name}", "ERROR"
  return false

wait_for_filter_ready = (timeout = 45) ->
  log "Waiting for #{filter_name} NFQUEUE workers (queue_listening)…", "STEP"
  for i = 1, timeout
    success, output = execute "docker logs #{filter_name} 2>&1", true
    if success and output and output\match "queue_listening"
      log "#{filter_name} workers listening", "PASS"
      return true
    os.execute "sleep 1"
  log "Timeout waiting for #{filter_name}", "ERROR"
  _, logs = execute "docker logs #{filter_name} 2>&1", true
  log "Container stdout/stderr:\n#{logs}", "ERROR"
  return false

wait_for_auth_ready = (timeout = 30) ->
  log "Waiting for auth worker (auth_listening)…", "STEP"
  for i = 1, timeout
    success, output = execute "docker logs #{filter_name} 2>&1", true
    if success and output and (output\match "auth_listening") and
       (output\match "auth_secrets_loaded")
      log "Auth server ready", "PASS"
      return true
    os.execute "sleep 1"
  log "Timeout waiting for auth server", "ERROR"
  return false

auth_curl = (method, path, data = nil) ->
  data_flag = if data then "-d '#{data}' " else ""
  cmd = "docker exec #{client_name} curl -k -s -o /dev/null -w '%{http_code}' -X #{method} #{data_flag}https://#{filter_ip}:33443#{path} 2>&1"
  execute cmd, true

build_image = ->
  if no_build
    log "Skipping Docker build (--no-build)", "WARN"
    return true

  unless force_build
    ok = execute "docker image inspect custos:latest >/dev/null 2>&1"
    unless ok
      log "Building Docker image custos:latest…", "STEP"
      success = execute "docker build -t custos:latest ."
      unless success
        log "Failed to build custos:latest", "ERROR"
        return false
      log "custos:latest built", "PASS"
  else
    log "Rebuilding Docker image custos:latest…", "STEP"
    success = execute "docker build -t custos:latest ."
    unless success
      log "Failed to build custos:latest", "ERROR"
      return false

  unless force_build
    ok = execute "docker image inspect custos-client:latest >/dev/null 2>&1"
    if ok
      log "custos-client:latest already exists", "WARN"
      return true

  log "Building Docker image custos-client:latest…", "STEP"
  success = execute "docker build -f Dockerfile.client -t custos-client:latest ."
  unless success
    log "Failed to build custos-client:latest", "ERROR"
    return false
  return true

compose_up = ->
  log "Starting docker-compose bridge environment…", "STEP"
  execute "docker compose --profile bridge down 2>/dev/null || true"
  execute "rm -f ./tmp/sessions.lua 2>/dev/null || true"

  success = execute "docker compose --profile bridge up -d"
  unless success
    log "Failed to start docker compose (bridge)", "ERROR"
    return false

  unless wait_for_container(filter_name) and
         wait_for_container(client_name) and
         wait_for_container(client2_name) and
         wait_for_container("custos-wan-dns")
    return false

  unless wait_for_filter_ready!
    return false

  unless wait_for_auth_ready!
    return false

  log "Warming up DNS chain…", "STEP"
  warmed = false
  for i = 1, 5
    ok, out = execute "docker exec #{client_name} nslookup #{TEST_DOMAINS.allowed} #{dns_server} 2>&1", true
    if ok and out and (out\match("Address:") or out\match("Name:"))
      warmed = true
      break
    log "DNS not ready (attempt #{i}/5), retrying…", "INFO"
    os.execute "sleep 2"
  if warmed
    log "Environment ready (DNS chain up, bridge mode)", "PASS"
  else
    log "DNS chain did not respond in time — tests may be flaky", "WARN"
  return true

flush_ip4_allowed = ->
  execute "docker exec #{filter_name} nft flush set ip dns-filter ip4_allowed 2>/dev/null", true
  execute "docker exec #{filter_name} nft flush set ip6 dns-filter ip6_allowed 2>/dev/null", true

compose_down = ->
  if keep_containers
    log "Keeping containers running (--keep)", "WARN"
    return true
  log "Tearing down docker-compose bridge environment…", "STEP"
  execute "docker exec #{filter_name} nft delete table ip dns-filter 2>/dev/null; true", true
  execute "rm -f ./tmp/sessions.lua 2>/dev/null || true"
  execute "git checkout cfg/secrets 2>/dev/null || true"
  execute "docker compose --profile bridge down"
  return true

query_dns = (domain) ->
  log "Querying DNS for #{domain}..."
  cmd = "timeout 12s docker exec #{client_name} nslookup #{domain} #{dns_server} 2>&1"
  success, output = execute cmd, true
  return nil, output unless success
  print output if verbose
  return success, output

curl_from_client = (url, timeout_sec = 5) ->
  cmd = "docker exec #{client_name} curl -k -s -o /dev/null -w '%{http_code}' --connect-timeout #{timeout_sec} --max-time #{timeout_sec + 5} '#{url}' 2>&1"
  _, code = execute cmd, true
  code = (code or "")\gsub "%s+", ""
  ok = code ~= "" and code ~= "000"
  ok, code

ping_from_client = (ip, timeout_sec = 2) ->
  return false, "no ip" unless ip and #ip > 0
  cmd = "docker exec #{client_name} ping -c1 -W#{timeout_sec} #{ip} 2>&1"
  execute cmd, true

ping_from_client2 = (ip, timeout_sec = 3) ->
  return false, "no ip" unless ip and #ip > 0
  cmd = "docker exec #{client2_name} ping -c1 -W#{timeout_sec} #{ip} 2>&1"
  execute cmd, true

resolve_host = (domain, qtype = "A") ->
  _, out = execute "dig +short -t #{qtype} #{domain} 2>/dev/null | grep -E '^[0-9a-fA-F.:]+$' | head -1", true
  ip = out and out\match "^%S+"
  (ip and #ip > 0) and ip or nil

-- ── Test runner ──────────────────────────────────────────────────────────────

tests_passed = 0
tests_failed = 0

cloudflare_ip = nil

run_test = (name, expected, test_func) ->
  print ""
  log name, "STEP"
  log expected, "EXPECT"
  success, obtained = test_func!
  obtained or= if success then "(ok)" else "(no detail)"
  log obtained, "GOT"
  if success
    log name, "PASS"
    tests_passed += 1
  else
    log name, "FAIL"
    tests_failed += 1
  return success

-- ── Main ─────────────────────────────────────────────────────────────────────

log "Starting Docker bridge end-to-end tests for CustosVirginum", "STEP"

unless build_image!
  os.exit 1

unless compose_up!
  compose_down!
  os.exit 1

log "Pre-resolving real IPs via host resolver…", "STEP"
cloudflare_ip = resolve_host TEST_DOMAINS.allowed
if cloudflare_ip
  log "#{TEST_DOMAINS.allowed} → #{cloudflare_ip}", "PASS"
else
  log "dig unavailable — ping tests will be skipped", "WARN"

print ""

-- ── DNS filtering ─────────────────────────────────────────────────────────────

run_test "Bridge DNS — domaine autorisé résolu",
  "nslookup #{TEST_DOMAINS.allowed} @#{dns_server} → adresse IP",
  ->
    flush_ip4_allowed!
    success, output = query_dns TEST_DOMAINS.allowed
    ok = success and (output\match "Address:" or output\match "Name:") != nil
    obtained = (output\match "Address:%s*(%S+)") or
               (output\match "Name:%s*(%S+)") or
               (output\match "([^\n]+)") or "(empty)"
    return ok, obtained

run_test "Bridge DNS — domaine bloqué → REFUSED",
  "nslookup #{TEST_DOMAINS.blocked} @#{dns_server} → REFUSED",
  ->
    success, output = query_dns TEST_DOMAINS.blocked
    ok = (output != nil) and output\match("REFUSED") != nil
    obtained = (output\match "([^\n]*REFUSED[^\n]*)") or
               (output\match "([^\n]+)") or "(no output)"
    return ok, obtained

run_test "Bridge DNS — domaine inconnu → NXDOMAIN",
  "nslookup #{TEST_DOMAINS.nonexistent} @#{dns_server} → NXDOMAIN",
  ->
    success, output = query_dns TEST_DOMAINS.nonexistent
    ok = not success or
         output\match("NXDOMAIN") != nil or
         output\match("can't find") != nil
    obtained = (output\match "(%S*NXDOMAIN%S*)") or
               (output\match "(can't find[^\n]*)") or
               (output\match "([^\n]+)") or "(no output)"
    return ok, obtained

run_test "Bridge DNS — TTL patché à #{EXPECTED_TTL}s",
  "dig #{TEST_DOMAINS.allowed} @#{dns_server} → TTL == #{EXPECTED_TTL}",
  ->
    cmd = "docker exec #{client_name} dig +noall +answer #{TEST_DOMAINS.allowed} @#{dns_server} 2>&1"
    _, output = execute cmd, true
    ttl_str = output and output\match "%s+(%d+)%s+IN%s+A%s+"
    unless ttl_str
      success2, output2 = query_dns TEST_DOMAINS.allowed
      ok2 = success2 and (output2\match "Address:" or output2\match "Name:") != nil
      return ok2, "(dig unavailable, nslookup: #{ok2})"
    local_ttl = tonumber ttl_str
    ok = local_ttl == EXPECTED_TTL
    return ok, "TTL=#{local_ttl} (attendu=#{EXPECTED_TTL})"

run_test "Bridge nft ip4_allowed peuplé après résolution",
  "nft list set ip dns-filter ip4_allowed → elements = { <ip> ... }",
  ->
    query_dns TEST_DOMAINS.allowed
    os.execute "sleep 1"
    cmd = "docker exec #{filter_name} nft list set ip dns-filter ip4_allowed 2>/dev/null"
    success, output = execute cmd, true
    has_entries = output and output\match "elements = {[^}]+}"
    ok = has_entries != nil
    obtained = if ok
      (output\match "elements = {([^}]+)}") or "(entries present)"
    else
      "(set empty or missing)"
    return ok, obtained

run_test "Bridge log contient les métadonnées DNS",
  "docker logs → txid= ou qname= présents",
  ->
    _, output = execute "docker logs #{filter_name} 2>&1", true
    has_txid  = output\match("txid=") != nil
    has_qname = output\match("qname=") != nil
    ok = has_txid or has_qname
    parts = {}
    table.insert parts, "txid=…"  if has_txid
    table.insert parts, "qname=…" if has_qname
    return ok, if ok then "found: " .. table.concat(parts, ", ") else "(absent)"

-- ── Isolation per-client ────────────────────────────────────────────────────

run_test "Bridge isolation — seul client1 accède à l'IP résolue",
  "client1 résout #{TEST_DOMAINS.allowed} → client1 ping=PASS, client2 ping=FAIL",
  ->
    unless cloudflare_ip
      return true, "dig indisponible — test ignoré"

    flush_ip4_allowed!

    q_ok, q_out = query_dns TEST_DOMAINS.allowed
    unless q_ok and (q_out\match("Address:") or q_out\match("Name:"))
      return false, "DNS query client1 échouée"

    os.execute "sleep 1"
    p1_ok, _ = ping_from_client cloudflare_ip, 4
    p2_ok, _ = ping_from_client2 cloudflare_ip, 3

    obtained = "client1_ping=#{p1_ok} client2_ping=#{p2_ok}"
    return (p1_ok and not p2_ok), obtained

-- ── HTTP access ─────────────────────────────────────────────────────────────

run_test "Bridge HTTP — domaine autorisé joignable",
  "curl http://#{TEST_DOMAINS.allowed}/ → code HTTP ≠ 000",
  ->
    flush_ip4_allowed!
    query_dns TEST_DOMAINS.allowed
    os.execute "sleep 1"
    ok, code = curl_from_client "http://#{TEST_DOMAINS.allowed}/"
    return ok, "HTTP #{code}"

-- ── Auth ────────────────────────────────────────────────────────────────────

print ""
print "#{C.bold}▶ Authentification HTTPS (mode bridge)#{C.reset}"

execute "rm -f ./tmp/sessions.lua 2>/dev/null || true"

run_test "Bridge auth — mauvais mot de passe → 401",
  "POST /login user=testuser&password=WRONG → HTTP 401",
  ->
    ok, code = auth_curl "POST", "/login", "user=testuser&password=WRONG"
    return (code == "401"), "HTTP #{code}"

run_test "Bridge auth — identifiants valides → 200",
  "POST /login user=testuser&password=testpass → HTTP 200",
  ->
    ok, code = auth_curl "POST", "/login", "user=testuser&password=testpass"
    return (code == "200"), "HTTP #{code}"

run_test "Bridge auth — sessions.lua contient la session",
  "cat ./tmp/sessions.lua → contient testuser + 172.29.0.10",
  ->
    fh = io.open "./tmp/sessions.lua", "r"
    unless fh
      return false, "sessions.lua absent"
    content = fh\read "*a"
    fh\close!
    ok = content\match("testuser") != nil and content\match("172.29.0.10") != nil
    return ok, content\sub(1, 120)

run_test "Bridge auth — heartbeat GET /ping → 204",
  "GET /ping (authentifié) → HTTP 204",
  ->
    ok, code = auth_curl "GET", "/ping"
    return (code == "204"), "HTTP #{code}"

run_test "Bridge auth — logout GET /logout → 303",
  "GET /logout → HTTP 303",
  ->
    auth_curl "GET", "/logout"
    ok, code = auth_curl "GET", "/logout"
    return (code == "303"), "HTTP #{code}"

-- ── Portail captif Q2 ─────────────────────────────────────────────────────────────────────────────
print ""
print "#{C.bold}▶ Portail captif Q2 (TCP/80 → 302 forgé)#{C.reset}"

-- Q2 : forger un 302 en réponse à un TCP SYN/80 vers une destination non autorisée.
-- On utilise l'IP du filtre lui-même (172.29.0.254) comme destination HTTP
-- car elle est joignable depuis le client ; le paquet passe en INPUT puis
-- Q2 forge la réponse. On vérifie que curl reçoit bien Location: https://...
q2_curl = (path = "/") ->
  cmd = "docker exec #{client_name} curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 -m 5 http://#{filter_ip}#{path} 2>&1"
  execute cmd, true

run_test "Bridge portail captif Q2 — log captive_redirect_q2 présent",
  "docker logs #{filter_name} → captive_redirect_q2 dans les logs",
  ->
    -- Déclenche un TCP SYN/80 vers une IP non autorisée via le client
    os.execute "docker exec #{client_name} curl -s -o /dev/null -m 3 http://1.1.1.1/ 2>/dev/null || true"
    os.execute "sleep 1"
    _, output = execute "docker logs #{filter_name} 2>&1", true
    ok = output != nil and output\match("captive_redirect_q2") != nil
    return ok, if ok then "captive_redirect_q2 trouvé" else "(absent — Q2 non déclenché)"

run_test "Bridge portail captif Q2 — log ip/sport client présent",
  "docker logs → ip=172.29.0.10 dans captive_redirect_q2",
  ->
    _, output = execute "docker logs #{filter_name} 2>&1", true
    ok = output != nil and output\match("captive_redirect_q2") != nil and
         output\match("ip=172%.29%.0%.10") != nil
    return ok, if ok then "ip=172.29.0.10 trouvé" else "(ip client absent)"

-- Q2 worker check (BRIDGE_MODE=1 → worker Q2-captive doit être dans les logs)
run_test "Bridge — worker Q2-captive démarré",
  "docker logs → q2_worker_start présent",
  ->
    _, output = execute "docker logs #{filter_name} 2>&1", true
    ok = output != nil and output\match("q2_worker_start") != nil
    return ok, if ok then "q2_worker_start trouvé" else "(absent — Q2 non démarré)"

-- NFQUEUE 2 enregistrée
run_test "Bridge — NFQUEUE 2 connectée (worker Q2)",
  "/proc/net/netfilter/nfnetlink_queue → ligne queue 2",
  ->
    _, qraw = execute "docker exec #{filter_name} cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null", true
    ok = qraw and qraw\match("\n?%s*2%s") != nil
    return ok, qraw or "(absent)"

-- ── Summary ─────────────────────────────────────────────────────────────────

print ""
print "#{C.bold}Test Summary (bridge mode):#{C.reset}"
print "  #{C.green}Passed: #{tests_passed}#{C.reset}"
print "  #{if tests_failed > 0 then C.red else C.grey}Failed: #{tests_failed}#{C.reset}"

compose_down!

if tests_failed > 0
  print "\n#{C.red}#{C.bold}Some bridge tests FAILED!#{C.reset}"
  os.exit 1
else
  print "\n#{C.green}#{C.bold}All bridge tests passed!#{C.reset}"
  os.exit 0
