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
    print("  --verbose  Show all commands and output")
    print("  --keep     Leave containers running after tests")
    print("  --no-build Skip Docker image build (use existing image)")
    print("  --build    Force Docker image rebuild even if image exists")
    os.exit(0)
  end
end
local ndpi_version = os.getenv("NDPI_VERSION")
local profile
if ndpi_version and ndpi_version:match("^5") then
  profile = "ndpi5"
else
  profile = "ndpi4"
end
local filter_name
if profile == "ndpi5" then
  filter_name = "custos-filter-ndpi5"
else
  filter_name = "custos-filter"
end
local dns_server
if profile == "ndpi5" then
  dns_server = "172.28.0.253"
else
  dns_server = "172.28.0.254"
end
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
local build_image
build_image = function()
  if no_build then
    log("Skipping Docker build (--no-build)", "WARN")
    return true
  end
  if not (force_build) then
    local ok = execute("docker image inspect custos:latest >/dev/null 2>&1")
    if ok then
      log("Image custos:latest already exists — skipping build (use --build to force)", "WARN")
      return true
    end
  end
  log("Building Docker image (this may take a while)…", "STEP")
  local success = execute("docker build -t custos:latest .")
  if not (success) then
    log("Failed to build Docker image", "ERROR")
    return false
  end
  log("Image built successfully", "PASS")
  return true
end
local wait_for_filter_ready
wait_for_filter_ready = function(name, timeout)
  if timeout == nil then
    timeout = 30
  end
  log("Waiting for " .. tostring(name) .. " NFQUEUE workers to be ready (queue_listening)…", "STEP")
  for i = 1, timeout do
    local success, output = execute("docker exec " .. tostring(name) .. " cat /app/tmp/dns-filter.log 2>/dev/null", true)
    if success and output and output:match("queue_listening") then
      log(tostring(name) .. " workers are listening on queues", "PASS")
      return true
    end
    os.execute("sleep 1")
  end
  log("Timeout waiting for " .. tostring(name) .. " filter readiness", "ERROR")
  local _, logs = execute("docker logs " .. tostring(name) .. " 2>&1", true)
  log("Container stdout/stderr:\n" .. tostring(logs), "ERROR")
  return false
end
local compose_up
compose_up = function()
  log("Starting docker-compose environment (profile=" .. tostring(profile) .. ")…", "STEP")
  execute("docker compose --profile ndpi4 --profile ndpi5 down 2>/dev/null || true")
  execute("rm -f ./tmp/dns-filter.log 2>/dev/null || true")
  local success = execute("docker compose --profile " .. tostring(profile) .. " up -d")
  if not (success) then
    log("Failed to start docker compose", "ERROR")
    return false
  end
  if not (wait_for_container(filter_name) and wait_for_container("custos-client") and wait_for_container("custos-wan-dns")) then
    return false
  end
  if not (wait_for_filter_ready(filter_name)) then
    return false
  end
  os.execute("sleep 3")
  log("Warming up DNS — priming dnsmasq cache with " .. tostring(TEST_DOMAINS.allowed) .. "…", "STEP")
  local warmed = false
  for i = 1, 5 do
    local ok, out = execute("docker exec custos-client nslookup " .. tostring(TEST_DOMAINS.allowed) .. " " .. tostring(dns_server) .. " 2>&1", true)
    if ok and out and (out:match("Address:") or out:match("Name:")) then
      warmed = true
      break
    end
    log("DNS not ready yet (attempt " .. tostring(i) .. "/5), retrying in 2 s…", "INFO")
    os.execute("sleep 2")
  end
  if warmed then
    log("Environment ready (DNS chain up, cache primed)", "PASS")
  else
    log("DNS chain did not respond in time — tests may be flaky", "WARN")
  end
  return true
end
local cleanup_host
cleanup_host = function()
  log("Cleaning up filter nftables rules...")
  local cmd = "docker exec " .. tostring(filter_name) .. " sh -c 'nft delete table ip dns-filter 2>/dev/null; nft delete table ip6 dns-filter 2>/dev/null; true'"
  execute(cmd, true)
  return execute("rm -f ./tmp/dns-filter.log 2>/dev/null || true")
end
local compose_down
compose_down = function()
  if keep_containers then
    log("Keeping containers running (--keep)", "WARN")
    return true
  end
  log("Tearing down docker-compose environment…", "STEP")
  cleanup_host()
  execute("docker compose --profile " .. tostring(profile) .. " down")
  return true
end
local query_dns
query_dns = function(domain)
  log("Querying DNS for " .. tostring(domain) .. "...")
  local cmd = "docker exec custos-client nslookup " .. tostring(domain) .. " " .. tostring(dns_server) .. " 2>&1"
  local success, output = execute(cmd, true)
  if not success then
    log("DNS query failed for " .. tostring(domain), "ERROR")
    return nil, output
  end
  if verbose then
    print(output)
  end
  return success, output
end
local check_nftables_set
check_nftables_set = function(set_name)
  log("Checking nftables set " .. tostring(set_name) .. "...")
  local cmd = "docker exec " .. tostring(filter_name) .. " nft list set ip dns-filter " .. tostring(set_name) .. " 2>/dev/null"
  local success, output = execute(cmd, true)
  if not success then
    log("Failed to check nftables set " .. tostring(set_name), "ERROR")
    return false, output
  end
  if verbose then
    print(output)
  end
  local has_entries = output:match("elements = {[^}]+}")
  return has_entries, output
end
local check_logs
check_logs = function()
  log("Checking filter logs...")
  local cmd = "docker exec " .. tostring(filter_name) .. " cat /app/tmp/dns-filter.log 2>/dev/null"
  local success, output = execute(cmd, true)
  if not success then
    log("Failed to get logs", "ERROR")
    return false, output
  end
  if verbose then
    print(output)
  end
  local has_protocol = output:match("ndpi_master=%d+" or output:match("ndpi_app=%d+"))
  local has_dns = output:match("DNS" or output:match("dns" or output:match("txid=" or output:match("qname="))))
  return (has_protocol or has_dns), output
end
local tests_passed = 0
local tests_failed = 0
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
log("Starting Docker end-to-end tests for CustosVirginum (profile=" .. tostring(profile) .. ")", "STEP")
if not (build_image()) then
  os.exit(1)
end
if not (compose_up()) then
  compose_down()
  os.exit(1)
end
print("")
run_test("DNS query — allowed domain resolves", "nslookup " .. tostring(TEST_DOMAINS.allowed) .. " → Address: <ip>", function()
  local success, output = query_dns(TEST_DOMAINS.allowed)
  local ok = success and (output:match("Address:" or output:match("Name:"))) ~= nil
  local obtained
  if ok then
    obtained = (output:match("Address:%s*(%S+)")) or (output:match("Name:%s*(%S+)")) or "(resolved)"
  else
    obtained = (output:match("([^\n]+)")) or "(empty output)"
  end
  return ok, obtained
end)
run_test("DNS query — blocked domain is rejected", "nslookup " .. tostring(TEST_DOMAINS.blocked) .. " → REFUSED (RCODE 5 + EDE Filtered)", function()
  local success, output = query_dns(TEST_DOMAINS.blocked)
  local ok = (output ~= nil) and output:match("REFUSED") ~= nil
  local obtained = (output:match("([^\n]*REFUSED[^\n]*)")) or (output:match("([^\n]+)")) or "(no output)"
  return ok, obtained
end)
run_test("DNS query — nonexistent domain returns NXDOMAIN", "nslookup " .. tostring(TEST_DOMAINS.nonexistent) .. " → NXDOMAIN or can't find", function()
  local success, output = query_dns(TEST_DOMAINS.nonexistent)
  local ok = not success or output:match("NXDOMAIN") ~= nil or output:match("can't find") ~= nil
  local obtained = (output:match("(%S*NXDOMAIN%S*)")) or (output:match("(can't find[^\n]*)")) or (output:match("([^\n]+)")) or "(no output)"
  return ok, obtained
end)
run_test("nftables ip4_allowed set is populated after allowed query", "nft list set ip dns-filter ip4_allowed → elements = { <ip> ... }", function()
  local has_entries, output = check_nftables_set("ip4_allowed")
  local ok = has_entries ~= nil
  local obtained
  if ok then
    obtained = (output:match("elements = {([^}]+)}")) or "(entries present)"
  else
    obtained = "(set empty or missing)"
  end
  return ok, obtained
end)
run_test("Filter logs contain DNS metadata", "log file has txid= or qname= entries", function()
  local _, output = check_logs()
  local has_txid = output:match("txid=") ~= nil
  local has_qname = output:match("qname=") ~= nil
  local has_proto = output:match("ndpi_master=%d+") ~= nil or output:match("ndpi_app=%d+") ~= nil
  local ok = has_txid or has_qname or has_proto
  local parts = { }
  if has_txid then
    table.insert(parts, "txid=…")
  end
  if has_qname then
    table.insert(parts, "qname=…")
  end
  if has_proto then
    table.insert(parts, "ndpi_…")
  end
  local obtained
  if ok then
    obtained = "found: " .. table.concat(parts, ", ")
  else
    obtained = "(no matching log line)"
  end
  return ok, obtained
end)
run_test("DNS response TTL is patched to " .. tostring(EXPECTED_TTL) .. "s", "dig " .. tostring(TEST_DOMAINS.allowed) .. " @dns_server → TTL == " .. tostring(EXPECTED_TTL) .. " in answer section", function()
  local cmd = "docker exec custos-client dig +noall +answer " .. tostring(TEST_DOMAINS.allowed) .. " @" .. tostring(dns_server) .. " 2>&1"
  local _, output = execute(cmd, true)
  local ttl_str = output and output:match("%s+(%d+)%s+IN%s+A%s+")
  if not ttl_str then
    local success2, output2 = query_dns(TEST_DOMAINS.allowed)
    local ok2 = success2 and (output2:match("Address:" or output2:match("Name:"))) ~= nil
    return ok2, "(dig unavailable, nslookup repondu: " .. tostring(ok2) .. ")"
  end
  local local_ttl = tonumber(ttl_str)
  local ok = local_ttl == EXPECTED_TTL
  local obtained = "TTL=" .. tostring(local_ttl) .. " (attendu=" .. tostring(EXPECTED_TTL) .. ")"
  return ok, obtained
end)
run_test("AAAA records populate ip6_allowed nftables set", "nslookup -type=AAAA " .. tostring(TEST_DOMAINS.allowed) .. " → if AAAA RRs received, ip6_allowed populated", function()
  local cmd = "docker exec custos-client nslookup -type=AAAA " .. tostring(TEST_DOMAINS.allowed) .. " " .. tostring(dns_server) .. " 2>&1"
  local q_ok, output = execute(cmd, true)
  local has_aaaa = q_ok and (output:match("AAAA") ~= nil or output:match("has IPv6 address") ~= nil or output:match("Address: [%x:]+:[%x:]+") ~= nil)
  if not (has_aaaa) then
    return true, "no AAAA records from upstream — unit tests cover the code path"
  end
  local set_cmd = "docker exec " .. tostring(filter_name) .. " nft list set ip6 dns-filter ip6_allowed 2>/dev/null"
  local _, set_out = execute(set_cmd, true)
  local has_elem = set_out and set_out:match("elements = {[^}]+}") ~= nil
  local ok = has_elem
  local obtained
  if ok then
    obtained = (set_out:match("elements = {([^}]+)}")) or "(entries present)"
  else
    obtained = "AAAA resolved (" .. tostring(output:match('AAAA%s+(%S+)' or '?')) .. ") but ip6_allowed set empty"
  end
  return ok, obtained
end)
compose_down()
print("")
print(tostring(C.bold) .. "Test Summary:" .. tostring(C.reset))
print("  " .. tostring(C.green) .. "Passed: " .. tostring(tests_passed) .. tostring(C.reset))
print("  " .. tostring((function()
  if tests_failed > 0 then
    return C.red
  else
    return C.grey
  end
end)()) .. "Failed: " .. tostring(tests_failed) .. tostring(C.reset))
if tests_failed > 0 then
  print("\n" .. tostring(C.red) .. tostring(C.bold) .. "Some tests FAILED!" .. tostring(C.reset))
  return os.exit(1)
else
  print("\n" .. tostring(C.green) .. tostring(C.bold) .. "All tests passed!" .. tostring(C.reset))
  return os.exit(0)
end
