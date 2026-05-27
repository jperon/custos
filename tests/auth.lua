local DEFAULT_URL = "https://custos.stemarie.dynv6.net:33443"
local DEFAULT_USER = "j@prn.ovh"
local DEFAULT_PASS = "patouche"
local parse_args
parse_args = function()
  local url = arg and arg[1] or DEFAULT_URL
  local user = arg and arg[2] or DEFAULT_USER
  local pass = arg and arg[3] or DEFAULT_PASS
  return url, user, pass
end
local run
run = function(cmd)
  io.stderr:write(">> " .. tostring(cmd) .. "\n")
  local fh = assert(io.popen(tostring(cmd) .. " 2>&1"))
  local out = fh:read("*a")
  local ok, why, code = fh:close()
  if out and out ~= "" then
    io.stderr:write(out)
  end
  if out and out ~= "" and out:sub(-1) ~= "\n" then
    io.stderr:write("\n")
  end
  if not (ok) then
    io.stderr:write("curl exit: " .. tostring(tostring(code or why or ok)) .. "\n")
  end
  return ok, out, code or why
end
local extract_status
extract_status = function(text)
  return tonumber(text:match("HTTP/%d%.%d%s+(%d%d%d)") or "0")
end
local extract_set_cookie
extract_set_cookie = function(text)
  local cookies = { }
  for line in tostring(text):gmatch("[^\r\n]+") do
    local cookie = line:match("[Ss]et%-[Cc]ookie:%s*([^;]+)")
    if cookie and cookie ~= "" then
      cookies[#cookies + 1] = cookie
    end
  end
  return table.concat(cookies, "; ")
end
local main
main = function()
  local url, user, pass = parse_args()
  local base = url:gsub("/+$", "")
  local login_cmd = table.concat({
    "curl -k -v -s -D - -o /dev/null",
    "-H 'Content-Type: application/x-www-form-urlencoded'",
    "-d 'user=" .. tostring(user) .. "&password=" .. tostring(pass) .. "'",
    tostring(base) .. "/login"
  }, " ")
  local ok1, login_out, login_status = run(login_cmd)
  if not (ok1) then
    io.stderr:write("LOGIN command failed (status " .. tostring(tostring(login_status)) .. ")\n")
    io.stderr:write("Command: " .. tostring(login_cmd) .. "\n")
    os.exit(1)
  end
  local login_code = extract_status(login_out)
  if not (login_code == 200) then
    io.stderr:write("LOGIN expected 200, got " .. tostring(login_code) .. "\n")
    io.stderr:write("Command: " .. tostring(login_cmd) .. "\n")
    os.exit(1)
  end
  local cookie = extract_set_cookie(login_out)
  if not (cookie and cookie ~= "") then
    io.stderr:write("LOGIN did not return a usable Set-Cookie header\n")
    io.stderr:write("Command: " .. tostring(login_cmd) .. "\n")
    os.exit(1)
  end
  io.stderr:write("LOGIN cookie: " .. tostring(cookie) .. "\n")
  local ping_cmd = table.concat({
    "curl -k -v -s -D - -o /dev/null",
    "-H 'Cookie: " .. tostring(cookie) .. "'",
    tostring(base) .. "/ping"
  }, " ")
  local ok2, ping_out, ping_status = run(ping_cmd)
  if not (ok2) then
    io.stderr:write("PING command failed (status " .. tostring(tostring(ping_status)) .. ")\n")
    io.stderr:write("Command: " .. tostring(ping_cmd) .. "\n")
    os.exit(1)
  end
  local ping_code = extract_status(ping_out)
  if not (ping_code == 204) then
    io.stderr:write("PING expected 204, got " .. tostring(ping_code) .. "\n")
    io.stderr:write("Command: " .. tostring(ping_cmd) .. "\n")
    os.exit(1)
  end
  print("OK")
  return os.exit(0)
end
return main()
