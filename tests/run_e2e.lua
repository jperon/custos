local parse_args
parse_args = function()
  local args = { }
  local i = 1
  while i <= #arg do
    local a = arg[i]
    if a:match("^--") then
      local key = a:match("^%-%-(.+)$")
      if key:match("=") then
        local k, v = key:match("([^=]+)=(.*)")
        args[k] = v
      else
        local val = arg[i + 1]
        if val and not val:match("^--") then
          args[key] = val
          i = i + 1
        else
          args[key] = true
        end
      end
    end
    i = i + 1
  end
  return args
end
local args = parse_args()
if not (args.filter and args.client) then
  error("Missing required arguments.\nUsage: --filter user@host --client user@host [--client2 user@host]")
end
local ssh_exec
ssh_exec = function(host, cmd, timeout)
  timeout = timeout or 10
  local ssh_cmd = string.format("ssh -o ConnectTimeout=%d -o BatchMode=yes -o StrictHostKeyChecking=no %s '%s'", timeout, host, cmd:gsub("'", "'\\''"))
  local f = io.popen(ssh_cmd, "r")
  if not (f) then
    return nil, "Failed to run ssh"
  end
  local output = f:read("*a")
  local ok, status = pcall(f.close, f)
  return output, status or -1
end
local log
log = function(msg)
  return io.write(msg .. "\n")
end
local run_tests
run_tests = function(host, tests)
  local results = { }
  for _index_0 = 1, #tests do
    local t = tests[_index_0]
    log("  [" .. tostring(host) .. "] " .. tostring(t.name) .. "...")
    local out, status = ssh_exec(host, t.cmd, t.timeout)
    if out == nil and status == nil then
      t.result = "ERROR"
      t.error = "SSH execution failed"
    else
      if t.expect then
        if type(t.expect) == "string" then
          t.result = out:match(t.expect)
        else
          t.result = status == t.expect
        end
      else
        t.result = status == 0
      end
      t.output = out
      t.status = status
    end
    table.insert(results, t)
  end
  return results
end
local filter_tests = {
  {
    name = "Service running",
    cmd = "ps | grep '[c]ustos' && echo FOUND || echo NOT_FOUND"
  },
  {
    name = "NFT rules loaded",
    cmd = "nft list table bridge dns-filter-bridge >/dev/null 2>&1 && echo OK || echo FAIL"
  },
  {
    name = "DNS allowed query",
    cmd = "dig @10.99.0.1 www.github.com +short +time=5"
  }
}
local client_tests = {
  {
    name = "DNS allowed",
    cmd = "dig @10.99.0.1 www.github.com +short +time=5"
  },
  {
    name = "DNS blocked",
    cmd = "dig @10.99.0.1 www.facebook.com +time=5"
  },
  {
    name = "Captive portal",
    cmd = "curl -s -o /dev/null -w '%{http_code}' http://example.com"
  }
}
local client2_tests = {
  {
    name = "DNS allowed (client2)",
    cmd = "dig @10.99.0.1 www.github.com +short +time=5"
  }
}
log("=== E2E Tests ===")
log("Filter: " .. tostring(args.filter))
local filter_res = run_tests(args.filter, filter_tests)
log("Client: " .. tostring(args.client))
local client_res = run_tests(args.client, client_tests)
local client2_res = nil
if args.client2 then
  log("Client2: " .. tostring(args.client2))
  client2_res = run_tests(args.client2, client2_tests)
end
local report = {
  timestamp = os.date("%Y-%m-%d %H:%M:%S"),
  filter = filter_res,
  client = client_res,
  client2 = client2_res
}
os.execute("mkdir -p tmp")
local report_path = "tmp/test-e2e-report.moon"
local file = assert(io.open(report_path, "w"))
file:write("-- E2E Test Report (" .. tostring(report.timestamp) .. ")\n\n")
file:write("results = {\n")
for section, label in pairs({
  {
    "filter",
    "Filter"
  },
  {
    "client",
    "Client"
  },
  {
    "client2",
    "Client2"
  }
}) do
  if report[section] then
    file:write("  " .. tostring(section) .. ": {\n")
    local _list_0 = report[section]
    for _index_0 = 1, #_list_0 do
      local t = _list_0[_index_0]
      file:write("    {\n")
      file:write("      name: " .. tostring(t.name:gsub('"', '\\"')) .. ",\n")
      file:write("      result: " .. tostring(t.result) .. ",\n")
      file:write("      output: " .. tostring(t.output and t.output:gsub('"', '\\"') or '') .. ",\n")
      file:write("    },\n")
    end
    file:write("  },\n")
  end
end
file:write("}\n")
file:close()
log("Report saved to " .. tostring(report_path))
local print_section
print_section = function(label, res)
  print("--- " .. tostring(label) .. " ---")
  for _index_0 = 1, #res do
    local t = res[_index_0]
    local status
    if t.result then
      status = "OK"
    else
      status = "FAIL"
    end
    print("  [" .. tostring(status) .. "] " .. tostring(t.name))
    if t.error then
      print("      Error: " .. tostring(t.error))
    end
  end
end
print_section("Filter", filter_res)
print_section("Client", client_res)
if client2_res then
  print_section("Client2", client2_res)
end
return log("Done.")
