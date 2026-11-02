local exec_ok = require("lib.os_exec").exec_ok
local sh_quote
sh_quote = function(s)
  return "'" .. tostring(s):gsub("'", "'\"'\"'") .. "'"
end
local ensure_dir
ensure_dir = function(dir)
  if not (dir and dir ~= "") then
    return true
  end
  local ret = os.execute("mkdir -p " .. tostring(sh_quote(dir)))
  return exec_ok(ret)
end
local ensure_parent_dir
ensure_parent_dir = function(path)
  local parent = tostring(path):match("^(.*)/[^/]+$")
  if not (parent and parent ~= "") then
    return true
  end
  local ret = os.execute("mkdir -p " .. tostring(sh_quote(parent)))
  return exec_ok(ret)
end
local download
download = function(url)
  local cmd = "curl --silent --location --max-time 30 --fail " .. sh_quote(url)
  local fh = io.popen(cmd)
  if not (fh) then
    return nil, "popen failed"
  end
  local data = fh:read("*a")
  local ok = fh:close()
  if not (ok and #data > 0) then
    return nil, "curl failed (HTTP error ou timeout) : " .. tostring(url)
  end
  return data, nil
end
local download_file
download_file = function(url, dest, timeout)
  timeout = timeout or 120
  local cmd = "curl --silent --location --max-time " .. tostring(timeout) .. " --fail -o " .. tostring(sh_quote(dest)) .. " " .. tostring(sh_quote(url))
  local ret = os.execute(cmd)
  return exec_ok(ret)
end
return {
  sh_quote = sh_quote,
  ensure_dir = ensure_dir,
  ensure_parent_dir = ensure_parent_dir,
  download = download,
  download_file = download_file
}
