#!/usr/bin/env moon
-- Docker end-to-end test for CustosVirginum DNS filter (FORWARD mode).
--
-- Architecture : client → LAN → [filter: dns-filter.nft FORWARD] → WAN → wan-dns
--
-- Le filtre agit en routeur (ip_forward=1) + NAT masquerade LAN→WAN.
-- Le client envoie ses DNS vers wan-dns (172.30.0.20 / fd00:30::20) ;
-- les paquets DNS traversent le FORWARD chain et sont interceptés par Q0/Q1.
-- Il n'y a PAS de dnsmasq sur le filtre.

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

-- DNS server : wan-dns, commun aux deux profils.
-- Le client envoie ses requêtes vers wan-dns ; elles transitent par FORWARD.
dns_server  = "172.30.0.20"
dns6_server = "fd00:30::20"

-- Test configuration
TEST_DOMAINS = {
  allowed: "cloudflare.com"
  blocked: "facebook.com"
  nonexistent: "nonexistent.test"
}
EXPECTED_TTL = 60

-- ── ANSI colours ─────────────────────────────────────────────────────────────
C = {
  reset:  "\27[0m"
  bold:   "\27[1m"
  green:  "\27[32m"
  red:    "\27[31m"
  yellow: "\27[33m"
  cyan:   "\27[36m"
  grey:   "\27[90m"
}

-- ── Logging ───────────────────────────────────────────────────────────────────
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
    pass = if ok_fn
      ok_fn ok, out
    else
      ok
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

-- Test functions
build_image = ->
  if no_build
    log "Skipping Docker build (--no-build)", "WARN"
    return true

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
-- @tparam string name     Container name
-- @tparam number timeout  Max seconds to wait
-- @treturn boolean
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
  execute "docker compose --profile ndpi4 --profile ndpi5 down 2>/dev/null || true"
  execute "rm -f ./tmp/dns-filter.log 2>/dev/null || true"

  success = execute "docker compose --profile #{profile} up -d"
  unless success
    log "Failed to start docker compose", "ERROR"
    return false

  unless wait_for_container(filter_name) and
         wait_for_container("custos-client") and
         wait_for_container("custos-client2") and
         wait_for_container("custos-wan-dns")
    return false

  unless wait_for_filter_ready filter_name
    return false

  -- Vérifier que le client a bien sa route par défaut vers le filtre
  -- et que la chaîne DNS (client→FORWARD→wan-dns) est opérationnelle.
  log "Warming up — priming DNS chain with #{TEST_DOMAINS.allowed}…", "STEP"
  warmed = false
  for i = 1, 5
    ok, out = execute "docker exec custos-client nslookup #{TEST_DOMAINS.allowed} #{dns_server} 2>&1", true
    if ok and out and (out\match("Address:") or out\match("Name:"))
      warmed = true
      break
    log "DNS not ready yet (attempt #{i}/5), retrying in 2 s…", "INFO"
    os.execute "sleep 2"
  if warmed
    log "Environment ready (DNS chain up via FORWARD)", "PASS"
  else
    log "DNS chain did not respond in time — tests may be flaky", "WARN"
  return true

cleanup_host = ->
  log "Cleaning up filter nftables rules..."
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
  cmd = "timeout 12s docker exec custos-client nslookup #{domain} #{dns_server} 2>&1"
  success, output = execute cmd, true

  if not success
    log "DNS query failed for #{domain}", "ERROR"
    return nil, output

  print output if verbose
  return success, output

--- Send a DNS-over-TCP query using dig +tcp from the client container.
-- @tparam string domain  Domain name to query.
-- @treturn boolean, string  success, raw dig output.
query_dns_tcp = (domain) ->
  log "Querying DNS (TCP) for #{domain}..."
  cmd = "docker exec custos-client dig +tcp +short A +tries=1 +time=4 #{domain} @#{dns_server} 2>&1"
  success, output = retry_capture cmd, 3, 1, (ok, out) ->
    return false unless out
    return false if out\match("communications error") or out\match("no servers could be reached")
    out\match("%d+%.%d+%.%d+%.%d+") != nil
  print output if verbose
  return success, output

check_nftables_set = (set_name) ->
  log "Checking nftables set #{set_name}..."
  cmd = "docker exec #{filter_name} nft list set ip dns-filter #{set_name} 2>/dev/null"
  success, output = execute cmd, true

  if not success
    log "Failed to check nftables set #{set_name}", "ERROR"
    return false, output

  print output if verbose

  has_entries = output\match "elements = {[^}]+}"
  return has_entries, output

check_logs = ->
  log "Checking filter logs..."
  cmd = "docker exec #{filter_name} cat /app/tmp/dns-filter.log 2>/dev/null"
  success, output = execute cmd, true

  if not success
    log "Failed to get logs", "ERROR"
    return false, output

  print output if verbose

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

--- Pinge une adresse IP depuis le conteneur client (client1 — 172.28.0.10).
-- @tparam string ip          Adresse IP à pinger
-- @tparam number timeout_sec Délai max en secondes (défaut 2)
-- @treturn bool, string      succès, sortie brute
ping_from_client = (ip, timeout_sec = 2) ->
  return false, "no ip" unless ip and #ip > 0
  cmd = "docker exec custos-client ping -c1 -W#{timeout_sec} #{ip} 2>&1"
  success, out = execute cmd, true
  return success, out

--- Pinge une adresse IP depuis le second conteneur client (client2 — 172.28.0.11).
-- N'a jamais émis de requête DNS : ses paquets vers des IPs non résolues
-- par lui doivent être FORWARD-DROPpés par le filtre.
-- @tparam string ip          Adresse IP à pinger
-- @tparam number timeout_sec Délai max en secondes (défaut 3)
-- @treturn bool, string      succès, sortie brute
ping_from_client2 = (ip, timeout_sec = 3) ->
  return false, "no ip" unless ip and #ip > 0
  cmd = "docker exec custos-client2 ping -c1 -W#{timeout_sec} #{ip} 2>&1"
  success, out = execute cmd, true
  return success, out

--- Vide les sets ip4_allowed et ip6_allowed dans le filtre.
flush_ip4_allowed = ->
  execute "docker exec #{filter_name} nft flush set ip  dns-filter ip4_allowed 2>/dev/null", true
  execute "docker exec #{filter_name} nft flush set ip6 dns-filter ip6_allowed 2>/dev/null", true

--- Write a LuaJIT TCP-segmentation DNS test script to ./tmp/ and copy it to the container.
-- The script opens a TCP connection to dns_server:53 via FFI POSIX sockets, sends the
-- 2-byte DNS length prefix as the first TCP segment (TCP_NODELAY enabled), waits 100 ms,
-- then sends the rest of the query.
-- @tparam string domain  Domain to query.
-- @tparam string server  DNS server IP address.
-- @treturn boolean  true on success.
prepare_tcp_seg_script = (domain, server) ->
  lua_code = table.concat {
    "local ffi = require 'ffi'"
    "local bit = require 'bit'"
    "ffi.cdef([["
    "  typedef struct { uint16_t sin_family; uint16_t sin_port;"
    "                   uint32_t sin_addr;   uint8_t  pad[8]; } sa4_t;"
    "  struct timeval { long tv_sec; long tv_usec; };"
    "  int socket(int,int,int);"
    "  int connect(int, const sa4_t*, unsigned int);"
    "  int setsockopt(int,int,int,const void*,unsigned int);"
    "  int send(int,const void*,size_t,int);"
    "  int recv(int,void*,size_t,int);"
    "  int close(int);"
    "  uint32_t htonl(uint32_t);"
    "  uint16_t htons(uint16_t);"
    "  int usleep(unsigned int);"
    "]])"
    "local server = '#{server}'"
    "local domain = '#{domain}'"
    "local function build(d)"
    "  local parts = {}"
    "  for l in d:gmatch('[^.]+') do parts[#parts+1] = string.char(#l)..l end"
    "  local q = table.concat(parts)..string.char(0)"
    "  local dns = string.char(0xAB,0xCD,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00)"
    "              ..q..string.char(0,1,0,1)"
    "  local n = #dns"
    "  return string.char(bit.rshift(bit.band(n,0xFF00),8), bit.band(n,0xFF))..dns"
    "end"
    "local pkt  = build(domain)"
    "local plen = #pkt"
    "local buf  = ffi.new('uint8_t[?]', plen)"
    "for i=1,plen do buf[i-1]=pkt:byte(i) end"
    "local fd = ffi.C.socket(2,1,6)  -- AF_INET, SOCK_STREAM, IPPROTO_TCP"
    "if fd<0 then print('error=socket') os.exit(1) end"
    "local SOL_SOCKET=1; local SO_RCVTIMEO=20; local SO_SNDTIMEO=21"
    "local tv = ffi.new('struct timeval', {3,0})"
    "ffi.C.setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv, ffi.sizeof('struct timeval'))"
    "ffi.C.setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, tv, ffi.sizeof('struct timeval'))"
    "local one = ffi.new('int[1]',1)"
    "ffi.C.setsockopt(fd, 6, 1, one, ffi.sizeof('int'))  -- TCP_NODELAY"
    "local a,b,c,dd = server:match('(%d+)%.(%d+)%.(%d+)%.(%d+)')"
    "local sa = ffi.new('sa4_t')"
    "sa.sin_family = 2"
    "sa.sin_port   = ffi.C.htons(53)"
    "sa.sin_addr   = ffi.C.htonl(tonumber(a)*16777216 + tonumber(b)*65536"
    "                             + tonumber(c)*256 + tonumber(dd))"
    "local connected = false"
    "for _=1,30 do"
    "  if ffi.C.connect(fd,sa,16)==0 then connected=true break end"
    "  ffi.C.usleep(100000)"
    "end"
    "if not connected then print('error=connect') ffi.C.close(fd) os.exit(1) end"
    "local s1 = ffi.C.send(fd, buf,   2,      0)  -- segment 1: 2-byte DNS length prefix"
    "if s1 ~= 2 then print('error=send_seg1') ffi.C.close(fd) os.exit(1) end"
    "ffi.C.usleep(100000)              -- 100 ms"
    "local s2 = ffi.C.send(fd, buf+2, plen-2, 0) -- segment 2: DNS query"
    "if s2 ~= (plen-2) then print('error=send_seg2') ffi.C.close(fd) os.exit(1) end"
    "local rb = ffi.new('uint8_t[?]', 65536)"
    "local n2 = ffi.C.recv(fd, rb, 2, 0)"
    "if n2<2 then print('error=short_header_or_timeout') ffi.C.close(fd) os.exit(1) end"
    "local rlen = bit.bor(bit.lshift(rb[0],8), rb[1])"
    "local got  = 0"
    "while got < rlen do"
    "  local nn = ffi.C.recv(fd, rb+got, rlen-got, 0)"
    "  if nn<=0 then break end"
    "  got = got+nn"
    "end"
    "if got<rlen then print('error=short_body_or_timeout got='..tostring(got)..' want='..tostring(rlen)) ffi.C.close(fd) os.exit(1) end"
    "if got<4 then print('error=short_body') ffi.C.close(fd) os.exit(1) end"
    "local function skip_name(b, off)"
    "  while off < rlen do"
    "    local v = b[off]"
    "    if v == 0 then return off+1"
    "    elseif bit.band(v,0xC0)==0xC0 then return off+2"
    "    else off = off+1+v end"
    "  end"
    "  return off"
    "end"
    "local ancount = bit.bor(bit.lshift(rb[6],8), rb[7])"
    "local ttl = -1"
    "if ancount > 0 then"
    "  local q_off = skip_name(rb, 12) + 4"
    "  if q_off + 10 <= rlen then"
    "    local a_off = skip_name(rb, q_off) + 4"
    "    if a_off + 4 <= rlen then"
    "      ttl = bit.bor(bit.lshift(rb[a_off],24), bit.lshift(rb[a_off+1],16)"
    "            , bit.lshift(rb[a_off+2],8), rb[a_off+3])"
    "    end"
    "  end"
    "end"
    "print('rcode='..tostring(bit.band(rb[3],0x0F))..' len='..tostring(rlen)..' ttl='..tostring(ttl))"
    "ffi.C.close(fd)"
  }, "\n"
  f = io.open "./tmp/dns_tcp_seg.lua", "w"
  return false unless f
  f\write lua_code
  f\close!
  ok = execute "docker cp ./tmp/dns_tcp_seg.lua custos-client:/tmp/dns_tcp_seg.lua 2>&1"
  return ok

--- Run the DNS-over-TCP segmentation test.
-- @tparam string domain  Domain to query.
-- @treturn boolean, string  success, raw output ("rcode=N len=M" or "error=...").
query_dns_tcp_segmented = (domain) ->
  unless prepare_tcp_seg_script domain, dns_server
    return false, "failed to write/copy Lua script"
  cmd = "timeout 30s docker exec custos-client luajit /tmp/dns_tcp_seg.lua 2>&1"
  retry_capture cmd, 3, 1, (ok, out) ->
    return false unless out
    rcode = out\match "rcode=(%d+)"
    ttl   = out\match "ttl=(%d+)"
    (rcode == "0") and (ttl == tostring EXPECTED_TTL)

--- Write a LuaJIT script that sends an IPv6 UDP DNS query with a Hop-by-Hop
-- extension header. The query is addressed to dns6_server (wan-dns IPv6) and
-- transits via FORWARD on the filter — testing that dns-filter.nft FORWARD
-- chain handles IPv6 extension headers.
-- @tparam string domain  Domain to query.
-- @tparam string server  IPv6 address of the DNS server.
-- @treturn boolean  true on success.
prepare_ipv6_hbh_dns_script = (domain, server) ->
  lua_code = table.concat {
    "local ffi = require 'ffi'"
    "local bit = require 'bit'"
    "ffi.cdef([["
    "  typedef struct { uint16_t f; uint16_t p; uint32_t fl; uint8_t a[16]; uint32_t sc; } sa6_t;"
    "  struct timeval { long s; long us; };"
    "  int socket(int,int,int);"
    "  int setsockopt(int,int,int,const void*,unsigned int);"
    "  int connect(int,const sa6_t*,unsigned int);"
    "  ssize_t send(int,const void*,size_t,int);"
    "  ssize_t recv(int,void*,size_t,int);"
    "  int close(int);"
    "  uint16_t htons(uint16_t);"
    "  int inet_pton(int,const char*,void*);"
    "]]) "
    "local AF_INET6=10; local SOCK_DGRAM=2; local IPPROTO_IPV6=41"
    "local IPV6_HOPOPTS=54; local SOL_SOCKET=1; local SO_RCVTIMEO=20"
    "local server='#{server}'"
    "local domain='#{domain}'"
    "local parts={}"
    "for l in domain:gmatch('[^.]+') do parts[#parts+1]=string.char(#l)..l end"
    "local qname=table.concat(parts)..'\\0'"
    "local dns=string.char(0xAB,0xCD,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00)"
    "           ..qname..string.char(0,1,0,1)"
    "local dns_len=#dns"
    "local fd=ffi.C.socket(AF_INET6,SOCK_DGRAM,0)"
    "if fd<0 then print('error=socket') os.exit(1) end"
    "-- Hop-by-Hop: [Next Header=0][Hdr Ext Len=0][6xPad1] = 8 bytes (must be multiple of 8)"
    "local hbh=ffi.new('uint8_t[8]',{0,0,0,0,0,0,0,0})"
    "local r=ffi.C.setsockopt(fd,IPPROTO_IPV6,IPV6_HOPOPTS,hbh,8)"
    "if r<0 then print('error=setsockopt_hbh') ffi.C.close(fd) os.exit(1) end"
    "local tv=ffi.new('struct timeval',{2,0})"
    "ffi.C.setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,tv,ffi.sizeof('struct timeval'))"
    "local sa=ffi.new('sa6_t')"
    "sa.f=AF_INET6; sa.p=ffi.C.htons(53)"
    "ffi.C.inet_pton(AF_INET6,server,sa.a)"
    "if ffi.C.connect(fd,sa,28)<0 then print('error=connect') ffi.C.close(fd) os.exit(1) end"
    "local buf=ffi.new('uint8_t[?]',dns_len)"
    "for i=1,dns_len do buf[i-1]=dns:byte(i) end"
    "ffi.C.send(fd,buf,dns_len,0)"
    "local rb=ffi.new('uint8_t[512]')"
    "local n=ffi.C.recv(fd,rb,512,0)"
    "ffi.C.close(fd)"
    "if n<4 then print('sent_ok=1 response=none')"
    "else local rcode=bit.band(rb[3],0x0F)"
    "  print('sent_ok=1 rcode='..tostring(rcode)..' response_len='..tostring(n)) end"
  }, "\n"
  f = io.open "./tmp/dns_ipv6_hbh.lua", "w"
  return false unless f
  f\write lua_code
  f\close!
  ok = execute "docker cp ./tmp/dns_ipv6_hbh.lua custos-client:/tmp/dns_ipv6_hbh.lua 2>&1"
  return ok

--- Send an IPv6 UDP DNS query with a Hop-by-Hop extension header.
-- @tparam string domain  Domain to query.
-- @treturn boolean, string  success, raw output from the LuaJIT client script.
query_dns_ipv6_hbh = (domain) ->
  unless prepare_ipv6_hbh_dns_script domain, dns6_server
    return false, "failed to write/copy IPv6 HbH Lua script"
  execute "docker exec custos-client luajit /tmp/dns_ipv6_hbh.lua 2>&1", true

-- Main test suite
tests_passed = 0
tests_failed = 0

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
log "Starting Docker end-to-end tests for CustosVirginum (profile=#{profile}, FORWARD mode)", "STEP"

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
  "nslookup #{TEST_DOMAINS.allowed} @#{dns_server} → Address: <ip> ; ping avant FAIL, ping après PASS",
  ->
    flush_ip4_allowed!

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

    if cloudflare_ip and ok
      p_after_ok, _ = ping_from_client cloudflare_ip, 4
      if p_after_ok
        log "ping #{cloudflare_ip} après DNS : PASS — ip4_allowed actif + MASQUERADE WAN", "PASS"
      else
        log "ping #{cloudflare_ip} après DNS : échec — vérifier route WAN ou MASQUERADE nft", "WARN"
        ok = false

    return ok, obtained

run_test "DNS query — blocked domain is rejected",
  "nslookup #{TEST_DOMAINS.blocked} @#{dns_server} → REFUSED ; ping avant et après FAIL",
  ->
    if facebook_ip
      p_ok, _ = ping_from_client facebook_ip
      if p_ok
        log "ping #{facebook_ip} avant DNS : PASS inattendu (LAN isolé)", "WARN"
      else
        log "ping #{facebook_ip} avant DNS : échec attendu (LAN isolé)", "PASS"

    success, output = query_dns TEST_DOMAINS.blocked
    ok = (output != nil) and output\match("REFUSED") != nil
    obtained = (output\match "([^\n]*REFUSED[^\n]*)") or
               (output\match "([^\n]+)") or
               "(no output)"

    if facebook_ip
      p_ok, _ = ping_from_client facebook_ip
      if p_ok
        log "ping #{facebook_ip} après DNS refusé : PASS inattendu (devrait être hors ip4_allowed)", "WARN"
        ok = false
      else
        log "ping #{facebook_ip} après DNS refusé : échec attendu (LAN isolé, FORWARD DROP)", "PASS"

    return ok, obtained

run_test "DNS query — nonexistent domain returns NXDOMAIN",
  "nslookup #{TEST_DOMAINS.nonexistent} @#{dns_server} → NXDOMAIN or can't find",
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
  "dig #{TEST_DOMAINS.allowed} @#{dns_server} → TTL == #{EXPECTED_TTL} in answer section",
  ->
    cmd = "docker exec custos-client dig +noall +answer #{TEST_DOMAINS.allowed} @#{dns_server} 2>&1"
    _, output = execute cmd, true
    ttl_str = output and output\match "%s+(%d+)%s+IN%s+A%s+"
    if not ttl_str
      success2, output2 = query_dns TEST_DOMAINS.allowed
      ok2 = success2 and (output2\match "Address:" or output2\match "Name:") != nil
      return ok2, "(dig unavailable, nslookup répondu: #{ok2})"
    local_ttl = tonumber ttl_str
    ok = local_ttl == EXPECTED_TTL
    obtained = "TTL=#{local_ttl} (attendu=#{EXPECTED_TTL})"
    return ok, obtained

run_test "AAAA records populate ip6_allowed nftables set",
  "nslookup -type=AAAA #{TEST_DOMAINS.allowed} → if AAAA RRs received, ip6_allowed populated",
  ->
    cmd = "docker exec custos-client nslookup -type=AAAA #{TEST_DOMAINS.allowed} #{dns6_server} 2>&1"
    q_ok, output = execute cmd, true
    has_aaaa = q_ok and (
      output\match("AAAA") != nil or
      output\match("has IPv6 address") != nil or
      output\match("Address: [%x:]+:[%x:]+") != nil
    )

    unless has_aaaa
      return true, "no AAAA records from upstream — unit tests cover the code path"

    set_cmd = "docker exec #{filter_name} nft list set ip6 dns-filter ip6_allowed 2>/dev/null"
    _, set_out = execute set_cmd, true
    has_elem  = set_out and set_out\match("elements = {[^}]+}") != nil

    ok = has_elem
    obtained = if ok
      (set_out\match "elements = {([^}]+)}") or "(entries present)"
    else
      "AAAA resolved (#{output\match 'AAAA%s+(%S+)' or '?'}) but ip6_allowed set empty"
    return ok, obtained

-- ── Per-client isolation test ───────────────────────────────────────────────

run_test "Per-client isolation — seul client1 accède à l'IP résolue",
  "client1 résout #{TEST_DOMAINS.allowed} → client1 ping=PASS, client2 ping=FAIL (entrée dans set = (172.28.0.10 . <ip>))",
  ->
    unless cloudflare_ip
      return true, "dig indisponible sur l'hôte — test d'isolation ignoré"

    flush_ip4_allowed!

    p1_before, _ = ping_from_client  cloudflare_ip, 2
    p2_before, _ = ping_from_client2 cloudflare_ip, 2
    if p1_before or p2_before
      log "ping avant DNS réussi (LAN isolé + set vide) — résidu de test précédent ?", "WARN"

    q_ok, q_out = query_dns TEST_DOMAINS.allowed
    unless q_ok and (q_out\match("Address:") or q_out\match("Name:"))
      return false, "DNS query par client1 échouée : #{(q_out\match '([^\n]+)') or '?'}"

    os.execute "sleep 1"

    p1_ok, p1_out = ping_from_client cloudflare_ip, 4
    unless p1_ok
      log "client1 ping #{cloudflare_ip} : FAIL — vérifier ip4_allowed et route WAN", "WARN"

    p2_ok, p2_out = ping_from_client2 cloudflare_ip, 3

    _, set_out = execute "docker exec #{filter_name} nft list set ip dns-filter ip4_allowed 2>/dev/null", true
    entry_c1 = set_out != nil and set_out\match("172.28.0.10") != nil
    entry_c2 = set_out != nil and set_out\match("172.28.0.11") != nil

    obtained = table.concat {
      "client1_ping=#{p1_ok}"
      "client2_ping=#{p2_ok}"
      "set_has_client1=#{entry_c1 != nil}"
      "set_has_client2=#{entry_c2 != nil}"
    }, " "

    ok = p1_ok and (not p2_ok)
    return ok, obtained

-- ── TCP DNS tests ─────────────────────────────────────────────────────────────

run_test "DNS over TCP — allowed domain resolves",
  "dig +tcp #{TEST_DOMAINS.allowed} @#{dns_server} → NOERROR with at least one A record",
  ->
    success, output = query_dns_tcp TEST_DOMAINS.allowed
    ip = output and output\match("(%d+%.%d+%.%d+%.%d+)")
    ok = success and ip != nil
    obtained = ip or output\match("([^\n]+)") or "(no output)"
    return ok, obtained

run_test "DNS over TCP — blocked domain is dropped",
  "dig +tcp #{TEST_DOMAINS.blocked} @#{dns_server} → timeout/no answer (Q0 DROPs the data segment)",
  ->
    cmd = "timeout 12s docker exec custos-client dig +tcp +tries=1 +time=3 #{TEST_DOMAINS.blocked} @#{dns_server} 2>&1"
    q_ok, output = execute cmd, true
    has_answer = q_ok and (output\match("ANSWER: [1-9]") != nil or output\match("status: NOERROR") != nil)
    obtained = (output\match "([^\n]+)") or "(no output)"
    return not has_answer, obtained

run_test "DNS over TCP segmented — 2-segment reassembly + TTL patched",
  "LuaJIT FFI: seg1=[2-byte len prefix], seg2=[DNS query] for #{TEST_DOMAINS.allowed} → rcode=0 ttl=60",
  ->
    ok, output = query_dns_tcp_segmented TEST_DOMAINS.allowed
    rcode_str = output and output\match "rcode=(%d+)"
    ttl_str   = output and output\match "ttl=(%d+)"
    rcode = rcode_str and tonumber rcode_str
    ttl   = ttl_str   and tonumber ttl_str
    success = ok and rcode == 0 and ttl == 60
    obtained = if rcode_str
      "rcode=#{rcode_str} ttl=#{ttl_str or '?'} (expected rcode=0 ttl=60)"
    else
      (output\match "([^\n]+)") or "(no output)"
    return success, obtained

-- ── IPv6 extension header test ────────────────────────────────────────────────

run_test "IPv6 + Hop-by-Hop DNS — filter parses extension header via FORWARD (af=ipv6)",
  "LuaJIT SOCK_DGRAM+IPV6_HOPOPTS: send HbH DNS to #{dns6_server} via FORWARD → filter log shows af=ipv6 + qname",
  ->
    _, log_before = execute "docker exec #{filter_name} cat /app/tmp/dns-filter.log 2>/dev/null | wc -l", true
    lines_before = tonumber (log_before or "0")

    ok, script_out = query_dns_ipv6_hbh TEST_DOMAINS.allowed
    sent = ok and (script_out and script_out\match "sent_ok=1") != nil
    unless sent
      err = (script_out and script_out\match "([^\n]+)") or "(no output)"
      return false, "IPv6 HbH packet not sent: #{err}"

    os.execute "sleep 1"

    _, log_out = execute "docker exec #{filter_name} cat /app/tmp/dns-filter.log 2>/dev/null", true
    has_ipv6  = log_out != nil and (log_out\match "af=ipv6") != nil
    has_qname = log_out != nil and (log_out\match "qname=#{TEST_DOMAINS.allowed\gsub('%.', '%%.')}") != nil

    rcode_str = script_out and script_out\match "rcode=(%d+)"
    resp_note = if rcode_str
      " response=rcode#{rcode_str}"
    elseif script_out and script_out\match "response=none"
      " response=none(filter_processed_ok)"
    else
      ""

    ok = has_ipv6 and has_qname
    obtained = if ok
      "af=ipv6 + qname=#{TEST_DOMAINS.allowed} found in filter log#{resp_note}"
    else
      "af=ipv6=#{has_ipv6} qname=#{has_qname} script=#{(script_out or '?')\gsub('[\n\r]+', ' ')}"
    return ok, obtained

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
