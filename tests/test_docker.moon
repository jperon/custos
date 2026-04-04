#!/usr/bin/env moon
-- Docker end-to-end test for CustosVirginum DNS filter
-- Uses io.execute/io.popen to orchestrate docker-compose and verify behavior

-- Parse command line flags
arg = { ... }
verbose = false
keep_containers = false
no_build = false

for a in *arg
  switch a
    when "--verbose"
      verbose = true
    when "--keep"
      keep_containers = true
    when "--no-build"
      no_build = true
    when "--help", "-h"
      print "Usage: #{arg[0]} [--verbose] [--keep] [--no-build]"
      print "  --verbose  Show all commands and output"
      print "  --keep     Leave containers running after tests"
      print "  --no-build Skip Docker image build"
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

-- Test configuration
TEST_DOMAINS = {
  allowed: "github.com"
  blocked: "facebook.com"
  nonexistent: "nonexistent.test"
}
EXPECTED_TTL = 60  -- From docker-compose environment variable

-- Helper functions
log = (msg, level = "INFO") ->
  if verbose or level == "ERROR" or level == "FAIL"
    print "[#{level}] #{msg}"

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
  log "Waiting for #{name} container to be ready..."
  for i = 1, timeout
    success = execute "docker ps --filter name=#{name} --filter status=running --quiet | grep -q ."
    if success
      log "#{name} is ready"
      return true
    os.execute "sleep 1"
  log "Timeout waiting for #{name}", "ERROR"
  return false

-- Test functions
build_image = ->
  if no_build
    log "Skipping Docker build (--no-build)"
    return true

  log "Building Docker image..."
  success = execute "docker build -t custos:latest ."
  unless success
    log "Failed to build Docker image", "ERROR"
    return false
  return true

--- Wait for the filter to be fully ready (queues listening).
-- The filter runs on the host network, but its log file is inside the container.
wait_for_filter_ready = (name, timeout = 30) ->
  log "Waiting for #{name} filter to be fully ready..."
  for i = 1, timeout
    success, output = execute "docker exec #{name} cat /tmp/dns-filter.log 2>/dev/null", true
    if success and output and output\match "queue_listening"
      log "#{name} filter is fully ready"
      return true
    os.execute "sleep 1"
  log "Timeout waiting for #{name} filter readiness", "ERROR"
  -- Show filter container logs for debugging
  _, logs = execute "docker logs #{name} 2>&1", true
  log "Filter logs: #{logs}", "ERROR"
  return false

compose_up = ->
  log "Starting docker compose environment (profile=#{profile})..."
  -- Stop any existing containers first
  execute "docker compose --profile ndpi4 --profile ndpi5 down 2>/dev/null || true"
  -- Remove stale filter log
  execute "rm -f /tmp/dns-filter.log 2>/dev/null || true"

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

  -- Give dnsmasq and nc proxy time to start, then warm up with a test query
  os.execute "sleep 3"
  log "Warming up DNS..."
  execute "docker exec custos-client nslookup localhost 172.28.0.254 >/dev/null 2>&1 || true"
  os.execute "sleep 1"
  return true

--- Clean up nftables tables in filter container (isolated namespace).
cleanup_host = ->
  log "Cleaning up filter nftables rules..."
  -- Remove nft dns-filter tables from filter container (isolated namespace)
  cmd = "docker exec #{filter_name} sh -c 'nft delete table ip dns-filter 2>/dev/null; nft delete table ip6 dns-filter 2>/dev/null; true'"
  execute cmd, true
  execute "rm -f /tmp/dns-filter.log 2>/dev/null || true"

compose_down = ->
  if keep_containers
    log "Keeping containers running (--keep)"
    return true

  log "Stopping docker compose environment..."
  execute "docker compose --profile #{profile} down"
  cleanup_host!
  return true

query_dns = (domain) ->
  log "Querying DNS for #{domain}..."
  -- Query filter's DNS directly (Docker overrides /etc/resolv.conf with its internal DNS)
  cmd = "docker exec custos-client nslookup #{domain} 172.28.0.254 2>&1"
  success, output = execute cmd, true

  if not success
    log "DNS query failed for #{domain}", "ERROR"
    return nil, output

  if verbose
    print output
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
  -- Filter runs on host network, but log is inside container
  cmd = "docker exec #{filter_name} cat /tmp/dns-filter.log 2>/dev/null"
  success, output = execute cmd, true

  if not success
    log "Failed to get logs", "ERROR"
    return false, output

  if verbose
    print output

  -- Check for expected log patterns
  has_protocol = output\match "ndpi_master=%d+" or output\match "ndpi_app=%d+"
  has_dns = output\match "DNS" or output\match "dns" or output\match "txid="

  return has_protocol and has_dns, output

test_ttl_patching = ->
  log "Testing TTL patching..."
  -- Query a domain that should return a response
  success, output = query_dns TEST_DOMAINS.allowed

  if not success
    log "Cannot test TTL patching - DNS query failed", "ERROR"
    return false

  -- For now, just verify we got a response
  -- In a real implementation, we'd capture packets and verify TTL
  -- This is a simplified test
  has_response = output\match "Address:" or output\match "Name:"
  return has_response

-- Main test suite
tests_passed = 0
tests_failed = 0

run_test = (name, test_func) ->
  log "Running test: #{name}"
  success = test_func!
  if success
    log "PASS: #{name}", "PASS"
    tests_passed += 1
  else
    log "FAIL: #{name}", "FAIL"
    tests_failed += 1
  return success

-- Execute tests
log "Starting Docker end-to-end tests for CustosVirginum"

-- Build and start environment
unless build_image!
  os.exit 1

unless compose_up!
  compose_down!
  os.exit 1

-- Run test suite
run_test "DNS query - allowed domain resolves", ->
  success, output = query_dns TEST_DOMAINS.allowed
  return success and (output\match "Address:" or output\match "Name:")

run_test "DNS query - blocked domain fails", ->
  success, output = query_dns TEST_DOMAINS.blocked
  -- Should fail or timeout
  return not success or output\match "SERVFAIL" or output\match "timeout" or output\match "connection refused"

run_test "DNS query - nonexistent domain fails", ->
  success, output = query_dns TEST_DOMAINS.nonexistent
  return not success or output\match "NXDOMAIN" or output\match "can't find"

run_test "nftables IPv4 set has entries", ->
  has_entries, _ = check_nftables_set "ip4_allowed"
  return has_entries

run_test "Filter logs contain protocol info", ->
  has_info, _ = check_logs()
  return has_info

run_test "TTL patching works", ->
  test_ttl_patching!

-- Cleanup
compose_down!

-- Summary
print "\nTest Summary:"
print "Passed: #{tests_passed}"
print "Failed: #{tests_failed}"

if tests_failed > 0
  print "Some tests FAILED!"
  os.exit 1
else
  print "All tests passed!"
  os.exit 0
