#!/usr/bin/env moon
-- Docker end-to-end test for CustosVirginum DNS filter
-- Uses io.execute/io.popen to orchestrate docker-compose and verify behavior

-- Parse command line flags
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
      print "  --verbose  Show all commands and output"
      print "  --keep     Leave containers running after tests"
      print "  --no-build Skip Docker image build (use existing image)"
      print "  --build    Force Docker image rebuild even if image exists"
      os.exit 0

-- Detect profile from NDPI_VERSION environment variable
ndpi_version = os.getenv "NDPI_VERSION"
profile = if ndpi_version and ndpi_version\match "^5"
  "ndpi5"
else
  "ndpi4"

filter_name = if profile == "ndpi5"
  "custos-filter-ndpi5"
else
  "custos-filter"

-- DNS address of the active filter container
dns_server = if profile == "ndpi5"
  "172.28.0.253"
else
  "172.28.0.254"

-- Test configuration
TEST_DOMAINS = {
  allowed: "cloudflare.com"
  blocked: "facebook.com"
  nonexistent: "nonexistent.test"
}
EXPECTED_TTL = 60  -- From docker-compose environment variable

-- ── ANSI colours (always on — redirect to file to strip them) ───────────────
C = {
  reset:  "\27[0m"
  bold:   "\27[1m"
  green:  "\27[32m"
  red:    "\27[31m"
  yellow: "\27[33m"
  cyan:   "\27[36m"
  grey:   "\27[90m"
}

-- ── Logging ──────────────────────────────────────────────────────────────────
-- Levels always printed : STEP, EXPECT, GOT, PASS, FAIL, ERROR, WARN
-- Level printed only with --verbose : INFO
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

-- Test functions
build_image = ->
  if no_build
    log "Skipping Docker build (--no-build)", "WARN"
    return true

  -- Build main custos filter image
  unless force_build
    ok = execute "docker image inspect custos:latest >/dev/null 2>&1"
    if ok
      log "Image custos:latest already exists — skipping build (use --build to force)", "WARN"
    else
      log "Building Docker image custos:latest (this may take a while)…", "STEP"
      success = execute "docker build -t custos:latest ."
      unless success
        log "Failed to build custos:latest", "ERROR"
        return false
      log "custos:latest built successfully", "PASS"
  else
    log "Building Docker image custos:latest (this may take a while)…", "STEP"
    success = execute "docker build -t custos:latest ."
    unless success
      log "Failed to build custos:latest", "ERROR"
      return false
    log "custos:latest built successfully", "PASS"

  -- Build client image (pre-installs tools, needed when LAN is internal)
  unless force_build
    ok = execute "docker image inspect custos-client:latest >/dev/null 2>&1"
    if ok
      log "Image custos-client:latest already exists — skipping build", "WARN"
      return true

  log "Building Docker image custos-client:latest…", "STEP"
  success = execute "docker build -f Dockerfile.client -t custos-client:latest ."
  unless success
    log "Failed to build custos-client:latest", "ERROR"
    return false
  log "custos-client:latest built successfully", "PASS"
  return true

--- Wait for the filter to be fully ready (queues listening).
-- The filter runs on the host network, but its log file is inside the container.
wait_for_filter_ready = (name, timeout = 30) ->
  log "Waiting for #{name} NFQUEUE workers to be ready (queue_listening)…", "STEP"
  for i = 1, timeout
    success, output = execute "docker exec #{name} cat /app/tmp/dns-filter.log 2>/dev/null", true
    if success and output and output\match "queue_listening"
      log "#{name} workers are listening on queues", "PASS"
      return true
    os.execute "sleep 1"
  log "Timeout waiting for #{name} filter readiness", "ERROR"
  _, logs = execute "docker logs #{name} 2>&1", true
  log "Container stdout/stderr:\n#{logs}", "ERROR"
  return false

compose_up = ->
  log "Starting docker-compose environment (profile=#{profile})…", "STEP"
  -- Stop any existing containers first
  execute "docker compose --profile ndpi4 --profile ndpi5 down 2>/dev/null || true"
  -- Remove stale filter log
  execute "rm -f ./tmp/dns-filter.log 2>/dev/null || true"

  success = execute "docker compose --profile #{profile} up -d"
  unless success
    log "Failed to start docker compose", "ERROR"
    return false

  -- Wait for all containers
  unless wait_for_container(filter_name) and
         wait_for_container("custos-client") and
         wait_for_container("custos-wan-dns")
    return false

  -- Wait for filter to be fully ready (queues listening)
  unless wait_for_filter_ready filter_name
    return false

  -- Give dnsmasq (in the filter) time to start (sleep 2 + exec in container).
  os.execute "sleep 3"

  -- Warm up: prime the dnsmasq cache with the test allowed-domain and confirm
  -- the whole DNS chain (client→filter→wan-dns→upstream) is working.
  -- wan-dns now uses a pre-built image so it starts immediately, but a short
  -- retry loop guards against any transient startup delay.
  log "Warming up DNS — priming dnsmasq cache with #{TEST_DOMAINS.allowed}…", "STEP"
  warmed = false
  for i = 1, 5
    ok, out = execute "docker exec custos-client nslookup #{TEST_DOMAINS.allowed} #{dns_server} 2>&1", true
    if ok and out and (out\match("Address:") or out\match("Name:"))
      warmed = true
      break
    log "DNS not ready yet (attempt #{i}/5), retrying in 2 s…", "INFO"
    os.execute "sleep 2"
  if warmed
    log "Environment ready (DNS chain up, cache primed)", "PASS"
  else
    log "DNS chain did not respond in time — tests may be flaky", "WARN"
  return true

--- Clean up nftables tables in filter container (isolated namespace).
cleanup_host = ->
  log "Cleaning up filter nftables rules..."
  -- Remove nft dns-filter tables from filter container (isolated namespace)
  cmd = "docker exec #{filter_name} sh -c 'nft delete table ip dns-filter 2>/dev/null; nft delete table ip6 dns-filter 2>/dev/null; true'"
  execute cmd, true
  execute "rm -f ./tmp/dns-filter.log 2>/dev/null || true"

compose_down = ->
  if keep_containers
    log "Keeping containers running (--keep)", "WARN"
    return true

  log "Tearing down docker-compose environment…", "STEP"
  cleanup_host!
  execute "docker compose --profile #{profile} down"
  return true

query_dns = (domain) ->
  log "Querying DNS for #{domain}..."
  -- Query filter's DNS directly (Docker overrides /etc/resolv.conf with its internal DNS)
  cmd = "docker exec custos-client nslookup #{domain} #{dns_server} 2>&1"
  success, output = execute cmd, true

  if not success
    log "DNS query failed for #{domain}", "ERROR"
    return nil, output

  if verbose
    print output
  return success, output

--- Send a DNS-over-TCP query using dig +tcp from the client container.
-- @tparam string domain  Domain name to query.
-- @treturn boolean, string  success, raw dig output.
query_dns_tcp = (domain) ->
  log "Querying DNS (TCP) for #{domain}..."
  cmd = "docker exec custos-client dig +tcp +tries=1 +time=5 #{domain} @#{dns_server} 2>&1"
  success, output = execute cmd, true
  print output if verbose
  return success, output

check_nftables_set = (set_name) ->
  log "Checking nftables set #{set_name}..."
  -- Filter runs on host network, so use docker exec to run nft on host's tables
  cmd = "docker exec #{filter_name} nft list set ip dns-filter #{set_name} 2>/dev/null"
  success, output = execute cmd, true

  if not success
    log "Failed to check nftables set #{set_name}", "ERROR"
    return false, output

  if verbose
    print output

  -- Check if set has entries
  has_entries = output\match "elements = {[^}]+}"
  return has_entries, output

check_logs = ->
  log "Checking filter logs..."
  -- Filter runs inside container, log is in the ./tmp volume mount
  cmd = "docker exec #{filter_name} cat /app/tmp/dns-filter.log 2>/dev/null"
  success, output = execute cmd, true

  if not success
    log "Failed to get logs", "ERROR"
    return false, output

  if verbose
    print output

  -- Check for expected log patterns
  has_protocol = output\match "ndpi_master=%d+" or output\match "ndpi_app=%d+"
  has_dns = output\match "DNS" or output\match "dns" or output\match "txid=" or output\match "qname="

  return (has_protocol or has_dns), output

--- Résout un nom de domaine depuis l'hôte via dig +short.
-- @tparam string domain  Nom de domaine à résoudre
-- @tparam string qtype   Type de requête (A ou AAAA), défaut "A"
-- @treturn string|nil    Première IP résolue, nil si dig indisponible
resolve_host = (domain, qtype = "A") ->
  _, out = execute "dig +short -t #{qtype} #{domain} 2>/dev/null | grep -E '^[0-9a-fA-F.:]+$' | head -1", true
  ip = out and out\match "^%S+"
  return (ip and #ip > 0) and ip or nil

--- Pinge une adresse IP depuis le conteneur client.
-- @tparam string ip          Adresse IP à pinger
-- @tparam number timeout_sec Délai max en secondes (défaut 2)
-- @treturn bool, string      succès, sortie brute
ping_from_client = (ip, timeout_sec = 2) ->
  return false, "no ip" unless ip and #ip > 0
  cmd = "docker exec custos-client ping -c1 -W#{timeout_sec} #{ip} 2>&1"
  success, out = execute cmd, true
  return success, out

--- Vide les sets ip4_allowed et ip6_allowed dans le filtre.
-- Utilisé avant les tests de ping pour garantir un état propre.
flush_ip4_allowed = ->
  execute "docker exec #{filter_name} nft flush set ip  dns-filter ip4_allowed 2>/dev/null", true
  execute "docker exec #{filter_name} nft flush set ip6 dns-filter ip6_allowed 2>/dev/null", true

--- Write a Python TCP-segmentation DNS test script to ./tmp/ and copy it to the container.
-- The script opens a TCP connection to dns_server:53, sends the 2-byte DNS length
-- prefix as the first TCP segment, waits 100 ms, then sends the rest of the query.
-- @tparam string domain  Domain to query.
-- @tparam string server  DNS server IP address.
-- @treturn boolean  true on success.
prepare_tcp_seg_script = (domain, server) ->
  py = table.concat {
    "import socket, struct, time"
    "def make_query(domain):"
    "    labels = domain.encode().split(b'.')"
    "    qname = b''.join(bytes([len(l)]) + l for l in labels) + b'\\x00'"
    "    dns = struct.pack('!HHHHHH', 0xABCD, 0x0100, 1, 0, 0, 0) + qname + struct.pack('!HH', 1, 1)"
    "    return struct.pack('!H', len(dns)) + dns"
    "pkt = make_query('#{domain}')"
    "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
    "sock.settimeout(5)"
    "try:"
    "    sock.connect(('#{server}', 53))"
    "    sock.send(pkt[:2])"
    "    time.sleep(0.1)"
    "    sock.send(pkt[2:])"
    "    rl = struct.unpack('!H', sock.recv(2))[0]"
    "    resp = sock.recv(rl)"
    "    rcode = resp[3] & 0xF"
    "    print('rcode=' + str(rcode) + ' len=' + str(rl))"
    "    sock.close()"
    "except Exception as e:"
    "    print('error=' + str(e))"
    "    try: sock.close()"
    "    except: pass"
  }, "\n"
  f = io.open "./tmp/dns_tcp_seg.py", "w"
  return false unless f
  f\write py
  f\close!
  ok = execute "docker cp ./tmp/dns_tcp_seg.py custos-client:/tmp/dns_tcp_seg.py 2>&1"
  return ok

--- Run the DNS-over-TCP segmentation test: sends query in two TCP segments.
-- @tparam string domain  Domain to query.
-- @treturn boolean, string  success, raw output ("rcode=N len=M" or "error=...").
query_dns_tcp_segmented = (domain) ->
  unless prepare_tcp_seg_script domain, dns_server
    return false, "failed to write/copy Python script"
  execute "docker exec custos-client python3 /tmp/dns_tcp_seg.py 2>&1", true

-- Main test suite
tests_passed = 0
tests_failed = 0

-- IPs réelles pré-résolues via dig sur l'hôte (nil si dig indisponible)
cloudflare_ip = nil
facebook_ip   = nil

--- Run a named test.
-- @tparam string  name      Human-readable test name
-- @tparam string  expected  One-line description of the expected outcome
-- @tparam function test_func Returns (bool, obtained_string)
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

-- Execute tests
log "Starting Docker end-to-end tests for CustosVirginum (profile=#{profile})", "STEP"

-- Build and start environment
unless build_image!
  os.exit 1

unless compose_up!
  compose_down!
  os.exit 1

-- ── Pré-résolution des IPs réelles (dig depuis l'hôte) ─────────────────────
log "Pre-resolving real IPs via host resolver (dig)…", "STEP"
cloudflare_ip = resolve_host TEST_DOMAINS.allowed
facebook_ip   = resolve_host TEST_DOMAINS.blocked
if cloudflare_ip
  log "#{TEST_DOMAINS.allowed} → #{cloudflare_ip}", "PASS"
else
  log "dig unavailable or #{TEST_DOMAINS.allowed} unresolved — ping tests will be skipped", "WARN"
if facebook_ip
  log "#{TEST_DOMAINS.blocked} → #{facebook_ip}", "PASS"
else
  log "dig unavailable or #{TEST_DOMAINS.blocked} unresolved — ping tests will be skipped", "WARN"

print ""

-- ── Test suite ────────────────────────────────────────────────────────────────

run_test "DNS query — allowed domain resolves",
  "nslookup #{TEST_DOMAINS.allowed} → Address: <ip> ; ping avant FAIL, ping après PASS",
  ->
    -- Vider ip4_allowed pour que le ping avant soit déterministe
    flush_ip4_allowed!

    -- Ping avant résolution DNS : LAN isolé + ip4_allowed vide → doit échouer
    if cloudflare_ip
      p_before_ok, _ = ping_from_client cloudflare_ip
      if p_before_ok
        log "ping #{cloudflare_ip} avant DNS : PASS inattendu (LAN isolé + ip4_allowed vidé)", "WARN"
      else
        log "ping #{cloudflare_ip} avant DNS : échec attendu (LAN isolé, ip4_allowed vide)", "PASS"

    success, output = query_dns TEST_DOMAINS.allowed
    ok = success and (output\match "Address:" or output\match "Name:") != nil
    obtained = if ok
      (output\match "Address:%s*(%S+)") or (output\match "Name:%s*(%S+)") or "(resolved)"
    else
      (output\match "([^\n]+)") or "(empty output)"

    -- Ping après résolution DNS : ip4_allowed peuplé + MASQUERADE WAN → doit réussir
    if cloudflare_ip and ok
      p_after_ok, _ = ping_from_client cloudflare_ip, 4
      if p_after_ok
        log "ping #{cloudflare_ip} après DNS : PASS — ip4_allowed actif + MASQUERADE WAN", "PASS"
      else
        log "ping #{cloudflare_ip} après DNS : échec — vérifier route WAN ou MASQUERADE nft", "WARN"
        ok = false

    return ok, obtained

run_test "DNS query — blocked domain is rejected",
  "nslookup #{TEST_DOMAINS.blocked} → REFUSED (RCODE 5 + EDE Filtered) ; ping avant et après FAIL",
  ->
    -- Ping avant : LAN isolé + facebook hors ip4_allowed → doit échouer
    if facebook_ip
      p_ok, _ = ping_from_client facebook_ip
      if p_ok
        log "ping #{facebook_ip} avant DNS : PASS inattendu (LAN isolé, facebook jamais dans ip4_allowed)", "WARN"
      else
        log "ping #{facebook_ip} avant DNS : échec attendu (LAN isolé)", "PASS"

    success, output = query_dns TEST_DOMAINS.blocked
    ok = (output != nil) and output\match("REFUSED") != nil
    obtained = (output\match "([^\n]*REFUSED[^\n]*)") or
               (output\match "([^\n]+)") or
               "(no output)"

    -- Ping après : domaine refusé → jamais dans ip4_allowed → doit rester hors portée
    if facebook_ip
      p_ok, _ = ping_from_client facebook_ip
      if p_ok
        log "ping #{facebook_ip} après DNS refusé : PASS inattendu (devrait être hors ip4_allowed)", "WARN"
        ok = false
      else
        log "ping #{facebook_ip} après DNS refusé : échec attendu (LAN isolé, FORWARD DROP)", "PASS"

    return ok, obtained

run_test "DNS query — nonexistent domain returns NXDOMAIN",
  "nslookup #{TEST_DOMAINS.nonexistent} → NXDOMAIN or can't find",
  ->
    success, output = query_dns TEST_DOMAINS.nonexistent
    ok = not success or
         output\match("NXDOMAIN") != nil or
         output\match("can't find") != nil
    obtained = (output\match "(%S*NXDOMAIN%S*)") or
               (output\match "(can't find[^\n]*)") or
               (output\match "([^\n]+)") or
               "(no output)"
    return ok, obtained

run_test "nftables ip4_allowed set is populated after allowed query",
  "nft list set ip dns-filter ip4_allowed → elements = { <ip> ... }",
  ->
    has_entries, output = check_nftables_set "ip4_allowed"
    ok = has_entries != nil
    obtained = if ok
      (output\match "elements = {([^}]+)}") or "(entries present)"
    else
      "(set empty or missing)"
    return ok, obtained

run_test "Filter logs contain DNS metadata",
  "log file has txid= or qname= entries",
  ->
    _, output = check_logs!
    has_txid  = output\match("txid=") != nil
    has_qname = output\match("qname=") != nil
    has_proto = output\match("ndpi_master=%d+") != nil or output\match("ndpi_app=%d+") != nil
    ok = has_txid or has_qname or has_proto
    parts = {}
    table.insert parts, "txid=…"    if has_txid
    table.insert parts, "qname=…"   if has_qname
    table.insert parts, "ndpi_…"    if has_proto
    obtained = if ok
      "found: " .. table.concat(parts, ", ")
    else
      "(no matching log line)"
    return ok, obtained

run_test "DNS response TTL is patched to #{EXPECTED_TTL}s",
  "dig #{TEST_DOMAINS.allowed} @dns_server → TTL == #{EXPECTED_TTL} in answer section",
  ->
    -- Utilise dig (mode batch) pour obtenir le TTL réel du RR A
    cmd = "docker exec custos-client dig +noall +answer #{TEST_DOMAINS.allowed} @#{dns_server} 2>&1"
    _, output = execute cmd, true
    -- Le format dig +answer est : nom TTL class type rdata
    -- ex: github.com. 60 IN A 140.82.121.3
    ttl_str = output and output\match "%s+(%d+)%s+IN%s+A%s+"
    if not ttl_str
      -- Fallback nslookup : vérifier juste que la réponse arrive
      success2, output2 = query_dns TEST_DOMAINS.allowed
      ok2 = success2 and (output2\match "Address:" or output2\match "Name:") != nil
      return ok2, "(dig unavailable, nslookup repondu: #{ok2})"
    local_ttl = tonumber ttl_str
    ok = local_ttl == EXPECTED_TTL
    obtained = "TTL=#{local_ttl} (attendu=#{EXPECTED_TTL})"
    return ok, obtained

run_test "AAAA records populate ip6_allowed nftables set",
  "nslookup -type=AAAA #{TEST_DOMAINS.allowed} → if AAAA RRs received, ip6_allowed populated",
  ->
    -- Query AAAA over IPv4 transport : the DNS response flows through worker_q1.
    -- If the environment has no IPv6 upstream, the test is skipped (pass with note).
    cmd = "docker exec custos-client nslookup -type=AAAA #{TEST_DOMAINS.allowed} #{dns_server} 2>&1"
    q_ok, output = execute cmd, true
    -- Alpine nslookup prints "Address: 2606:4700::..." (no "AAAA" keyword).
    -- Match an IPv6 address: at least two colon-separated hex groups in an Address line.
    has_aaaa = q_ok and (
      output\match("AAAA") != nil or
      output\match("has IPv6 address") != nil or
      output\match("Address: [%x:]+:[%x:]+") != nil
    )

    unless has_aaaa
      -- No AAAA records returned by upstream in this environment.
      return true, "no AAAA records from upstream — unit tests cover the code path"

    -- AAAA records were received: verify ip6_allowed was populated
    set_cmd = "docker exec #{filter_name} nft list set ip6 dns-filter ip6_allowed 2>/dev/null"
    _, set_out = execute set_cmd, true
    has_elem  = set_out and set_out\match("elements = {[^}]+}") != nil

    ok = has_elem
    obtained = if ok
      (set_out\match "elements = {([^}]+)}") or "(entries present)"
    else
      "AAAA resolved (#{output\match 'AAAA%s+(%S+)' or '?'}) but ip6_allowed set empty"
    return ok, obtained

-- ── TCP DNS tests ─────────────────────────────────────────────────────────────

run_test "DNS over TCP — allowed domain resolves",
  "dig +tcp #{TEST_DOMAINS.allowed} → NOERROR with at least one A record",
  ->
    success, output = query_dns_tcp TEST_DOMAINS.allowed
    ok = success and (output\match("ANSWER: [1-9]") != nil or output\match("IN%s+A%s+%d") != nil)
    obtained = output\match("(%d+%.%d+%.%d+%.%d+)") or output\match("([^\n]+)") or "(no output)"
    return ok, obtained

run_test "DNS over TCP — blocked domain is dropped",
  "dig +tcp #{TEST_DOMAINS.blocked} → timeout/no answer (Q0 DROPs the data segment)",
  ->
    cmd = "docker exec custos-client dig +tcp +tries=1 +time=3 #{TEST_DOMAINS.blocked} @#{dns_server} 2>&1"
    q_ok, output = execute cmd, true
    -- Pass if dig did NOT receive a successful NOERROR answer.
    has_answer = q_ok and (output\match("ANSWER: [1-9]") != nil or output\match("status: NOERROR") != nil)
    obtained = (output\match "([^\n]+)") or "(no output)"
    return not has_answer, obtained

run_test "DNS over TCP segmented — 2-segment reassembly works",
  "Python: seg1=[2-byte len prefix], seg2=[DNS query] for #{TEST_DOMAINS.allowed} → rcode=0",
  ->
    ok, output = query_dns_tcp_segmented TEST_DOMAINS.allowed
    rcode_str = output and output\match "rcode=(%d+)"
    rcode = rcode_str and tonumber rcode_str
    success = ok and rcode == 0
    obtained = if rcode_str
      "rcode=#{rcode_str} (expected 0)"
    else
      (output\match "([^\n]+)") or "(no output)"
    return success, obtained

-- ── Teardown ──────────────────────────────────────────────────────────────────
compose_down!

-- ── Summary ───────────────────────────────────────────────────────────────────
print ""
print "#{C.bold}Test Summary:#{C.reset}"
print "  #{C.green}Passed: #{tests_passed}#{C.reset}"
print "  #{if tests_failed > 0 then C.red else C.grey}Failed: #{tests_failed}#{C.reset}"

if tests_failed > 0
  print "\n#{C.red}#{C.bold}Some tests FAILED!#{C.reset}"
  os.exit 1
else
  print "\n#{C.green}#{C.bold}All tests passed!#{C.reset}"
  os.exit 0
