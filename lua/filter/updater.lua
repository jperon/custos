local ffi = require("ffi")
local xxhash = require("ffi_xxhash")
local parse_domains = require("filter.lib.parse_domains")
local load_config
load_config = require("filter.lib.load_config").load_config
ffi.cdef([[  int rename(const char *oldpath, const char *newpath);
  int kill(int pid, int sig);
]])
local SIGHUP = 1
local parse_args
parse_args = function(argv)
  local opts = {
    dry_run = false
  }
  local i = 1
  while argv[i] do
    local _exp_0 = argv[i]
    if "--config" == _exp_0 then
      i = i + 1
      opts.config = argv[i]
    elseif "--pid" == _exp_0 then
      i = i + 1
      opts.pid_file = argv[i]
    elseif "--dry-run" == _exp_0 then
      opts.dry_run = true
    end
    i = i + 1
  end
  return opts
end
local download
download = function(url)
  local cmd = "curl --silent --location --max-time 30 --fail " .. url
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
  local cmd = "curl --silent --location --max-time " .. tostring(timeout) .. " --fail -o " .. tostring(dest) .. " " .. tostring(url)
  local ret = os.execute(cmd)
  return ret == 0
end
local fetch_toulouse
fetch_toulouse = function(name, source, dry_run)
  local url = source.url
  local cats = source.categories
  local output = source.output
  if not (url) then
    return false, "pas d'URL définie"
  end
  if not (output) then
    return false, "pas de chemin output défini"
  end
  local tmp_tar = output .. ".tar.gz.tmp"
  io.stderr:write("[" .. tostring(name) .. "] GET " .. tostring(url) .. " ... ")
  if not (download_file(url, tmp_tar)) then
    os.remove(tmp_tar)
    return false, "curl échoué (HTTP error ou timeout)"
  end
  io.stderr:write("OK\n")
  if not cats or #cats == 0 then
    local fh = io.popen("tar -tzf " .. tostring(tmp_tar) .. " 2>/dev/null")
    cats = { }
    if fh then
      for line in fh:lines() do
        local cat = line:match("^blacklists/([^/]+)/domains$")
        if cat then
          cats[#cats + 1] = cat
        end
      end
      fh:close()
    end
  end
  if #cats == 0 then
    os.remove(tmp_tar)
    return false, "aucune catégorie trouvée dans le tar"
  end
  io.stderr:write("[" .. tostring(name) .. "] " .. tostring(#cats) .. " catégorie(s) : " .. tostring(table.concat(cats, ', ')) .. "\n")
  local all_domains = { }
  for _index_0 = 1, #cats do
    local cat = cats[_index_0]
    local fh = io.popen("tar -xzf " .. tostring(tmp_tar) .. " -O blacklists/" .. tostring(cat) .. "/domains 2>/dev/null")
    if fh then
      local data = fh:read("*a")
      fh:close()
      local domains = parse_domains.parse("simple", data)
      for _index_1 = 1, #domains do
        local d = domains[_index_1]
        all_domains[#all_domains + 1] = d
      end
    end
  end
  os.remove(tmp_tar)
  io.stderr:write("[" .. tostring(name) .. "] " .. tostring(#all_domains) .. " domaines total\n")
  return write_bin(all_domains, output, dry_run)
end
local write_bin
write_bin = function(domains, output_path, dry_run)
  local seen, hashes, n = { }, { }, 0
  for _index_0 = 1, #domains do
    local _continue_0 = false
    repeat
      local domain = domains[_index_0]
      if seen[domain] then
        _continue_0 = true
        break
      end
      seen[domain] = true
      n = n + 1
      hashes[n] = xxhash.xxh64(domain)
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  if n == 0 then
    return false, "aucun domaine valide"
  end
  table.sort(hashes, function(a, b)
    return a < b
  end)
  local arr = ffi.new("uint64_t[?]", n)
  for i = 1, n do
    arr[i - 1] = hashes[i]
  end
  if dry_run then
    return true, "dry-run : " .. tostring(n) .. " domaines → " .. tostring(output_path)
  end
  local tmp = output_path .. ".tmp"
  local fh = io.open(tmp, "wb")
  if not (fh) then
    return false, "impossible d'écrire " .. tostring(tmp)
  end
  fh:write(ffi.string(arr, n * 8))
  fh:close()
  local ret = ffi.C.rename(tmp, output_path)
  if ret ~= 0 then
    os.remove(tmp)
    return false, "rename échoué : " .. tostring(tmp) .. " → " .. tostring(output_path)
  end
  return true, tostring(n) .. " domaines → " .. tostring(output_path) .. " (" .. tostring(n * 8) .. " octets)"
end
local opts = parse_args(arg)
local cfg_path = opts.config or "cfg/filter.yml"
local cfg, err = load_config(cfg_path)
if not (cfg) then
  io.stderr:write("Erreur de chargement de la config " .. tostring(cfg_path) .. " : " .. tostring(err) .. "\n")
  os.exit(1)
end
local sources = cfg.sources or { }
if next(sources) == nil then
  io.stderr:write("Aucune source définie dans cfg.sources — rien à faire.\n")
  os.exit(0)
end
local updated = 0
local errors = 0
for name, source in pairs(sources) do
  local _continue_0 = false
  repeat
    local format = source.format or "simple"
    local output = source.output
    if not (output) then
      io.stderr:write("[" .. tostring(name) .. "] SKIP : pas de chemin output défini\n")
      errors = errors + 1
      _continue_0 = true
      break
    end
    if format == "toulouse" then
      local ok, msg = fetch_toulouse(name, source, opts.dry_run)
      if ok then
        io.stderr:write("[" .. tostring(name) .. "] ✓ " .. tostring(msg) .. "\n")
        updated = updated + 1
      else
        io.stderr:write("[" .. tostring(name) .. "] ✗ " .. tostring(msg) .. "\n")
        errors = errors + 1
      end
      _continue_0 = true
      break
    end
    local urls = source.urls or { }
    if #urls == 0 then
      io.stderr:write("[" .. tostring(name) .. "] SKIP : aucune URL définie\n")
      errors = errors + 1
      _continue_0 = true
      break
    end
    local all_domains = { }
    local failed = false
    for _index_0 = 1, #urls do
      local url = urls[_index_0]
      io.stderr:write("[" .. tostring(name) .. "] GET " .. tostring(url) .. " ... ")
      local data
      data, err = download(url)
      if err then
        io.stderr:write("ERREUR : " .. tostring(err) .. "\n")
        failed = true
        break
      end
      local domains = parse_domains.parse(format, data)
      io.stderr:write(tostring(#domains) .. " domaines\n")
      for _index_1 = 1, #domains do
        local d = domains[_index_1]
        all_domains[#all_domains + 1] = d
      end
    end
    if failed then
      io.stderr:write("[" .. tostring(name) .. "] Source ignorée (erreur de téléchargement)\n")
      errors = errors + 1
      _continue_0 = true
      break
    end
    io.stderr:write("[" .. tostring(name) .. "] " .. tostring(#all_domains) .. " domaines total → " .. tostring(output) .. "\n")
    local ok, msg = write_bin(all_domains, output, opts.dry_run)
    if ok then
      io.stderr:write("[" .. tostring(name) .. "] ✓ " .. tostring(msg) .. "\n")
      updated = updated + 1
    else
      io.stderr:write("[" .. tostring(name) .. "] ✗ " .. tostring(msg) .. "\n")
      errors = errors + 1
    end
    _continue_0 = true
  until true
  if not _continue_0 then
    break
  end
end
if opts.pid_file and updated > 0 and not opts.dry_run then
  local fh = io.open(opts.pid_file, "r")
  if fh then
    local pid_str = fh:read("*l")
    fh:close()
    local pid = tonumber(pid_str)
    if pid and pid > 0 then
      local ret = ffi.C.kill(pid, SIGHUP)
      if ret == 0 then
        io.stderr:write("SIGHUP envoyé au PID " .. tostring(pid) .. "\n")
      else
        io.stderr:write("Échec de l'envoi du SIGHUP au PID " .. tostring(pid) .. "\n")
      end
    else
      io.stderr:write("PID invalide dans " .. tostring(opts.pid_file) .. "\n")
    end
  else
    io.stderr:write("Impossible de lire " .. tostring(opts.pid_file) .. "\n")
  end
end
io.stderr:write("Terminé : " .. tostring(updated) .. " liste(s) mise(s) à jour, " .. tostring(errors) .. " erreur(s).\n")
return os.exit(errors > 0 and 1 or 0)
