local ffi = require("ffi")
local bin48 = require("filter.lib.bin48")
local parse_domains = require("filter.lib.parse_domains")
local exec_ok = require("lib.os_exec").exec_ok
ffi.cdef([[  int rename(const char *oldpath, const char *newpath);
]])
local sh_quote
sh_quote = function(s)
  return "'" .. tostring(s):gsub("'", "'\"'\"'") .. "'"
end
local bin_name_for
bin_name_for = function(txt_name)
  return (txt_name:match("([^/]+)%.txt$")) or txt_name
end
local write_result_kind
write_result_kind = function(ok, _msg, skipped)
  if ok then
    return "ok"
  end
  if skipped then
    return "skipped"
  end
  return "error"
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
local write_bin
write_bin = function(domains, output_path, dry_run)
  local payload, n = bin48.pack_domains(domains)
  if dry_run then
    return true, "dry-run : " .. tostring(n) .. " domaines → " .. tostring(output_path)
  end
  local tmp = output_path .. ".tmp"
  if not (ensure_parent_dir(tmp)) then
    return false, "impossible de créer le répertoire parent de " .. tostring(tmp)
  end
  local fh = io.open(tmp, "wb")
  if not (fh) then
    return false, "impossible d'écrire " .. tostring(tmp)
  end
  fh:write(payload)
  fh:close()
  local ret = ffi.C.rename(tmp, output_path)
  if ret ~= 0 then
    os.remove(tmp)
    return false, "rename échoué : " .. tostring(tmp) .. " → " .. tostring(output_path)
  end
  if n == 0 then
    return true, "liste vide (0 domaine) → " .. tostring(output_path), false
  end
  return true, tostring(n) .. " domaines → " .. tostring(output_path) .. " (" .. tostring(#payload) .. " octets)"
end
local fetch_local
fetch_local = function(name, source, dry_run)
  local path = source.file
  local format = source.format or "simple"
  local output = source.output or (path:gsub("%.%w+$", ".bin"))
  local fh = io.open(path, "r")
  if not (fh) then
    return false, "impossible de lire " .. tostring(path)
  end
  local data = fh:read("*a")
  fh:close()
  local domains = parse_domains.parse(format, data)
  io.stderr:write("[" .. tostring(name) .. "] " .. tostring(#domains) .. " domaines depuis " .. tostring(path) .. "\n")
  return write_bin(domains, output, dry_run)
end
local process_custom_dir
process_custom_dir = function(src_dir, output_dir, dry_run)
  output_dir = output_dir or src_dir
  local local_updated, local_errors = 0, 0
  ensure_dir(src_dir)
  ensure_dir(output_dir)
  local quoted_dir = sh_quote(src_dir)
  local fh = io.popen("cd " .. tostring(quoted_dir) .. " 2>/dev/null && ls -1 *.txt 2>/dev/null")
  if not (fh) then
    return 0, 0
  end
  local src_base = src_dir:gsub("/+$", "")
  local out_base = output_dir:gsub("/+$", "")
  for txt_name in fh:lines() do
    local _continue_0 = false
    repeat
      txt_name = txt_name:gsub("%s+$", "")
      if txt_name == "" then
        _continue_0 = true
        break
      end
      local txt_path = src_base .. "/" .. txt_name
      local name = bin_name_for(txt_name)
      local bin_path = out_base .. "/" .. name .. ".bin"
      local ok_l, msg, skipped = fetch_local(name, {
        file = txt_path,
        format = "simple",
        output = bin_path
      }, dry_run)
      local kind = write_result_kind(ok_l, msg, skipped)
      if kind == "ok" then
        io.stderr:write("[custom/" .. tostring(name) .. "] ✓ " .. tostring(msg) .. "\n")
        local_updated = local_updated + 1
      elseif kind == "skipped" then
        io.stderr:write("[custom/" .. tostring(name) .. "] ⏭ ignorée (" .. tostring(msg) .. ")\n")
      else
        io.stderr:write("[custom/" .. tostring(name) .. "] ✗ " .. tostring(msg) .. "\n")
        local_errors = local_errors + 1
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  fh:close()
  return local_updated, local_errors
end
return {
  sh_quote = sh_quote,
  bin_name_for = bin_name_for,
  write_result_kind = write_result_kind,
  ensure_dir = ensure_dir,
  ensure_parent_dir = ensure_parent_dir,
  download = download,
  download_file = download_file,
  write_bin = write_bin,
  fetch_local = fetch_local,
  process_custom_dir = process_custom_dir
}
