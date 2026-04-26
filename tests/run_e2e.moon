-- tests/run_e2e.moon
-- E2E test suite for CustosVirginum.
-- Usage: luajit run_e2e.lua --filter user@host --client user@host [--client2 user@host]

-- Parse arguments (--key=value or --key value)
parse_args = ->
  args = {}
  i = 1
  while i <= #arg
    a = arg[i]
    if a\match "^--"
      key = a\match "^%-%-(.+)$"
      if key\match "="
        k, v = key\match "([^=]+)=(.*)"
        args[k] = v
      else
        val = arg[i+1]
        if val and not val\match "^--"
          args[key] = val
          i += 1
        else
          args[key] = true
    i += 1
  args

args = parse_args!

-- Validate
unless args.filter and args.client
  error "Missing required arguments.\nUsage: --filter user@host --client user@host [--client2 user@host]"

-- SSH execution with timeout (using ssh options)
ssh_exec = (host, cmd, timeout) ->
  timeout or= 10
  ssh_cmd = string.format(
    "ssh -o ConnectTimeout=%d -o BatchMode=yes -o StrictHostKeyChecking=no %s '%s'",
    timeout, host, cmd\gsub("'", "'\\''")
  )
  f = io.popen ssh_cmd, "r"
  unless f
    return nil, "Failed to run ssh"
  output = f\read "*a"
  ok, status = pcall f.close, f
  -- status is the exit code (if pcall returns it)
  return output, status or -1

-- Logger
log = (msg) -> io.write msg .. "\n"

-- Run a list of tests on a host
run_tests = (host, tests) ->
  results = {}
  for t in *tests
    log "  [#{host}] #{t.name}..."
    out, status = ssh_exec host, t.cmd, t.timeout
    if out == nil and status == nil
      t.result = "ERROR"
      t.error = "SSH execution failed"
    else
      t.result = if t.expect
        -- If expect is a string, check if output contains it; if number, check exit code.
        if type(t.expect) == "string"
          out\match t.expect
        else
          status == t.expect
      else
        status == 0
      t.output = out
      t.status = status
    table.insert results, t
  results

-- Define tests
filter_tests = {
  { name: "Service running", cmd: "ps | grep '[c]ustos' && echo FOUND || echo NOT_FOUND" }
  { name: "NFT rules loaded", cmd: "nft list table bridge dns-filter-bridge >/dev/null 2>&1 && echo OK || echo FAIL" }
  { name: "DNS allowed query", cmd: "dig @10.99.0.1 www.github.com +short +time=5" }
}

client_tests = {
  { name: "DNS allowed", cmd: "dig @10.99.0.1 www.github.com +short +time=5" }
  { name: "DNS blocked", cmd: "dig @10.99.0.1 www.facebook.com +time=5" }
  { name: "Captive portal", cmd: "curl -s -o /dev/null -w '%{http_code}' http://example.com" }
}

client2_tests = {
  { name: "DNS allowed (client2)", cmd: "dig @10.99.0.1 www.github.com +short +time=5" }
}

-- Execute
log "=== E2E Tests ==="
log "Filter: #{args.filter}"
filter_res = run_tests args.filter, filter_tests

log "Client: #{args.client}"
client_res = run_tests args.client, client_tests

client2_res = nil
if args.client2
  log "Client2: #{args.client2}"
  client2_res = run_tests args.client2, client2_tests

-- Generate report (MoonScript table)
report =
  timestamp: os.date "%Y-%m-%d %H:%M:%S"
  filter: filter_res
  client: client_res
  client2: client2_res

os.execute "mkdir -p tmp"
report_path = "tmp/test-e2e-report.moon"
file = assert io.open report_path, "w"
file\write "-- E2E Test Report (#{report.timestamp})\n\n"
file\write "results = {\n"
for section, label in pairs { {"filter", "Filter"}, {"client", "Client"}, {"client2", "Client2"} }
  if report[section]
    file\write "  #{section}: {\n"
    for t in *report[section]
      file\write "    {\n"
      file\write "      name: #{t.name\gsub('"', '\\"')},\n"
      file\write "      result: #{t.result},\n"
      file\write "      output: #{t.output and t.output\gsub('"', '\\"') or ''},\n"
      file\write "    },\n"
    file\write "  },\n"
file\write "}\n"
file\close!

log "Report saved to #{report_path}"

-- Summary
print_section = (label, res) ->
  print "--- #{label} ---"
  for t in *res
    status = if t.result then "OK" else "FAIL"
    print "  [#{status}] #{t.name}"
    if t.error then print "      Error: #{t.error}"

print_section "Filter", filter_res
print_section "Client", client_res
if client2_res then print_section "Client2", client2_res

log "Done."
