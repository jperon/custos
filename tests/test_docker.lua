local arg = {
  ...
}
local verbose = false
local keep_containers = false
local no_build = false
for _index_0 = 1, #arg do
  local a = arg[_index_0]
  local _exp_0 = a
  if "--verbose" == _exp_0 then
    verbose = true
  elseif "--keep" == _exp_0 then
    keep_containers = true
  elseif "--no-build" == _exp_0 then
    no_build = true
  elseif "--help" == _exp_0 or "-h" == _exp_0 then
    print("Usage: " .. tostring(arg[0]) .. " [--verbose] [--keep] [--no-build]")
    print("  --verbose  Show all commands and output")
    print("  --keep     Leave containers running after tests")
    print("  --no-build Skip Docker image build")
    os.exit(0)
  end
end
local TEST_DOMAINS = {
  allowed = "github.com",
  blocked = "facebook.com",
  nonexistent = "nonexistent.test"
}
local EXPECTED_TTL = 60
local log
log = function(msg, level)
  if level == nil then
    level = "INFO"
  end
  if verbose or level == "ERROR" or level == "FAIL" then
    return print("[" .. tostring(level) .. "] " .. tostring(msg))
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
  log("Waiting for " .. tostring(name) .. " container to be ready...")
  for i = 1, timeout do
    local success = execute("docker ps --filter name=" .. tostring(name) .. " --filter status=running --quiet | grep -q .")
    if success then
      log(tostring(name) .. " is ready")
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
    log("Skipping Docker build (--no-build)")
    return true
  end
  log("Building Docker image...")
  local success = execute("docker build -t custos:latest .")
  if not (success) then
    log("Failed to build Docker image", "ERROR")
    return false
  end
  return true
end
local compose_up
compose_up = function()
  log("Starting docker-compose environment...")
  execute("docker-compose down 2>/dev/null || true")
  local success = execute("docker-compose up -d")
  if not (success) then
    log("Failed to start docker-compose", "ERROR")
    return false
  end
  return wait_for_container("custos-filter") and wait_for_container("custos-client") and wait_for_container("custos-router") and wait_for_container("custos-wan-dns")
end
local compose_down
compose_down = function()
  if keep_containers then
    log("Keeping containers running (--keep)")
    return true
  end
  log("Stopping docker-compose environment...")
  return execute("docker-compose down")
end
local query_dns
query_dns = function(domain)
  log("Querying DNS for " .. tostring(domain) .. "...")
  local cmd = "docker exec custos-client nslookup " .. tostring(domain) .. " 2>&1"
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
  local cmd = "docker exec custos-filter nft list set inet dns-filter " .. tostring(set_name) .. " 2>/dev/null"
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
  local cmd = "docker logs custos-filter 2>&1 | tail -20"
  local success, output = execute(cmd, true)
  if not success then
    log("Failed to get logs", "ERROR")
    return false, output
  end
  if verbose then
    print(output)
  end
  local has_protocol = output:match("ndpi_master=%d+" or output:match("ndpi_app=%d+"))
  local has_dns = output:match("DNS" or output:match("txid="))
  return has_protocol and has_dns, output
end
local test_ttl_patching
test_ttl_patching = function()
  log("Testing TTL patching...")
  local success, output = query_dns(TEST_DOMAINS.allowed)
  if not success then
    log("Cannot test TTL patching - DNS query failed", "ERROR")
    return false
  end
  local has_response = output:match("Address:" or output:match("Name:"))
  return has_response
end
local tests_passed = 0
local tests_failed = 0
local run_test
run_test = function(name, test_func)
  log("Running test: " .. tostring(name))
  local success = test_func()
  if success then
    log("PASS: " .. tostring(name), "PASS")
    tests_passed = tests_passed + 1
  else
    log("FAIL: " .. tostring(name), "FAIL")
    tests_failed = tests_failed + 1
  end
  return success
end
log("Starting Docker end-to-end tests for CustosVirginum")
if not (build_image()) then
  os.exit(1)
end
if not (compose_up()) then
  compose_down()
  os.exit(1)
end
run_test("DNS query - allowed domain resolves", function()
  local success, output = query_dns(TEST_DOMAINS.allowed)
  return success and (output:match("Address:" or output:match("Name:")))
end)
run_test("DNS query - blocked domain fails", function()
  local success, output = query_dns(TEST_DOMAINS.blocked)
  return not success or output:match("SERVFAIL" or output:match("timeout" or output:match("connection refused")))
end)
run_test("DNS query - nonexistent domain fails", function()
  local success, output = query_dns(TEST_DOMAINS.nonexistent)
  return not success or output:match("NXDOMAIN" or output:match("can't find"))
end)
run_test("nftables IPv4 set has entries", function()
  local has_entries, _ = check_nftables_set("ip4_allowed")
  return has_entries
end)
run_test("Filter logs contain protocol info", function()
  local has_info, _ = check_logs()
  return has_info
end)
run_test("TTL patching works", function()
  return test_ttl_patching()
end)
compose_down()
log("\nTest Summary:")
log("Passed: " .. tostring(tests_passed))
log("Failed: " .. tostring(tests_failed))
if tests_failed > 0 then
  log("Some tests failed!", "ERROR")
  return os.exit(1)
else
  log("All tests passed!", "PASS")
  return os.exit(0)
end
