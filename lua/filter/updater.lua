local ffi = require("ffi")
local bin48 = require("filter.lib.bin48")
local parse_domains = require("filter.lib.parse_domains")
ffi.cdef([[  int rename(const char *oldpath, const char *newpath);
  int kill(int pid, int sig);
  int setenv(const char *name, const char *value, int overwrite);
]])
local SIGHUP = 1
local write_bin
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
  return ret == 0 or ret == true
end
local ensure_parent_dir
ensure_parent_dir = function(path)
  local parent = tostring(path):match("^(.*)/[^/]+$")
  if not (parent and parent ~= "") then
    return true
  end
  local ret = os.execute("mkdir -p " .. tostring(sh_quote(parent)))
  return ret == 0 or ret == true
end
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
  return ret == 0
end
local fetch_toulouse
fetch_toulouse = function(name, source, dry_run)
  local url = source.url
  local cats_filter = source.categories
  local output = source.output
  local output_dir = source.output_dir
  if not (url) then
    return false, "pas d'URL définie"
  end
  if not (output or output_dir) then
    return false, "pas de chemin output ou output_dir défini"
  end
  local tmp_root = (os.getenv("TMPDIR") or "/tmp"):gsub("/*$", "")
  local safe_name = tostring(name):gsub("[^%w_.-]", "_")
  local tmp_tar = tostring(tmp_root) .. "/custos-updater-" .. tostring(safe_name) .. ".tar.gz.tmp"
  if not (ensure_parent_dir(tmp_tar)) then
    return false, "impossible de créer le répertoire parent de " .. tostring(tmp_tar)
  end
  io.stderr:write("[" .. tostring(name) .. "] GET " .. tostring(url) .. " ... ")
  if not (download_file(url, tmp_tar)) then
    os.remove(tmp_tar)
    return false, "curl échoué (HTTP error ou timeout)"
  end
  io.stderr:write("OK\n")
  local fh = io.popen("tar -tzf " .. tostring(sh_quote(tmp_tar)) .. " 2>/dev/null")
  local all_cats = { }
  if fh then
    for line in fh:lines() do
      local cat = line:match("^blacklists/([^/]+)/domains$")
      if cat then
        all_cats[#all_cats + 1] = cat
      end
    end
    fh:close()
  end
  local cats
  if cats_filter and #cats_filter > 0 then
    local wanted = { }
    for _index_0 = 1, #cats_filter do
      local c = cats_filter[_index_0]
      wanted[c] = true
    end
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #all_cats do
        local c = all_cats[_index_0]
        if wanted[c] then
          _accum_0[_len_0] = c
          _len_0 = _len_0 + 1
        end
      end
      cats = _accum_0
    end
  else
    cats = all_cats
  end
  if #cats == 0 then
    os.remove(tmp_tar)
    return false, "aucune catégorie trouvée dans le tar"
  end
  io.stderr:write("[" .. tostring(name) .. "] " .. tostring(#cats) .. " catégorie(s)\n")
  if output_dir then
    local base = output_dir:gsub("/*$", "")
    if not (ensure_parent_dir(base .. "/.keep")) then
      os.remove(tmp_tar)
      return false, "impossible de créer " .. tostring(base)
    end
    local ok_count, err_count = 0, 0
    for _index_0 = 1, #cats do
      local cat = cats[_index_0]
      local member = "blacklists/" .. tostring(cat) .. "/domains"
      fh = io.popen("tar -xzf " .. tostring(sh_quote(tmp_tar)) .. " -O " .. tostring(sh_quote(member)) .. " 2>/dev/null")
      local domains = { }
      if fh then
        local data = fh:read("*a")
        fh:close()
        domains = parse_domains.parse("simple", data)
      end
      local cat_path = base .. "/" .. cat .. ".bin"
      local ok, msg = write_bin(domains, cat_path, dry_run)
      if ok then
        io.stderr:write("[" .. tostring(name) .. "/" .. tostring(cat) .. "] ✓ " .. tostring(msg) .. "\n")
        ok_count = ok_count + 1
      else
        io.stderr:write("[" .. tostring(name) .. "/" .. tostring(cat) .. "] ✗ " .. tostring(msg) .. "\n")
        err_count = err_count + 1
      end
    end
    os.remove(tmp_tar)
    if err_count == 0 then
      return true, tostring(ok_count) .. " catégorie(s) → " .. tostring(base) .. "/"
    end
    return err_count < ok_count, tostring(ok_count) .. " ok, " .. tostring(err_count) .. " erreur(s)"
  end
  local all_domains = { }
  for _index_0 = 1, #cats do
    local cat = cats[_index_0]
    local member = "blacklists/" .. tostring(cat) .. "/domains"
    fh = io.popen("tar -xzf " .. tostring(sh_quote(tmp_tar)) .. " -O " .. tostring(sh_quote(member)) .. " 2>/dev/null")
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
write_bin = function(domains, output_path, dry_run)
  local payload, n = bin48.pack_domains(domains)
  if n == 0 then
    return false, "aucun domaine valide", true
  end
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
      local name = txt_name:match("([^/]+)%.txt$" or txt_name)
      local bin_path = out_base .. "/" .. name .. ".bin"
      local ok_l, msg, skipped = fetch_local(name, {
        file = txt_path,
        format = "simple",
        output = bin_path
      }, dry_run)
      if ok_l then
        io.stderr:write("[custom/" .. tostring(name) .. "] ✓ " .. tostring(msg) .. "\n")
        local_updated = local_updated + 1
      elseif skipped then
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
local opts = parse_args(arg)
if opts.config then
  ffi.C.setenv("CUSTOS_CONFIG_PATH", opts.config, 1)
end
local cfg = require("config")
local sources = cfg.filter.sources or { }
local domainlists_dir = cfg.filter.domainlists_dir
local custom_lists_dir = cfg.filter.custom_lists_dir
if domainlists_dir then
  if not (ensure_dir(domainlists_dir)) then
    io.stderr:write("Impossible de créer domainlists_dir : " .. tostring(domainlists_dir) .. "\n")
    os.exit(1)
  end
end
if custom_lists_dir then
  if not (ensure_dir(custom_lists_dir)) then
    io.stderr:write("Impossible de créer custom_lists_dir : " .. tostring(custom_lists_dir) .. "\n")
    os.exit(1)
  end
end
local updated = 0
local errors = 0
for name, source in pairs(sources) do
  local _continue_0 = false
  repeat
    local format = source.format or "simple"
    if source.subdir and not source.output_dir then
      if not (domainlists_dir) then
        io.stderr:write("[" .. tostring(name) .. "] SKIP : subdir défini mais domainlists_dir absent\n")
        errors = errors + 1
        _continue_0 = true
        break
      end
      do
        local _tbl_0 = { }
        for k, v in pairs(source) do
          _tbl_0[k] = v
        end
        source = _tbl_0
      end
      source.output_dir = (domainlists_dir:gsub("/*$", "")) .. "/" .. source.subdir
    end
    if source.output_dir then
      if not (ensure_dir(source.output_dir)) then
        io.stderr:write("[" .. tostring(name) .. "] SKIP : impossible de créer " .. tostring(source.output_dir) .. "\n")
        errors = errors + 1
        _continue_0 = true
        break
      end
    end
    local output = source.output
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
    if source.file then
      local ok, msg = fetch_local(name, source, opts.dry_run)
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
    if not (output) then
      io.stderr:write("[" .. tostring(name) .. "] SKIP : pas de chemin output défini\n")
      errors = errors + 1
      _continue_0 = true
      break
    end
    local urls = source.urls or { }
    if #urls == 0 then
      io.stderr:write("[" .. tostring(name) .. "] SKIP : aucune URL définie ni fichier local (file:)\n")
      errors = errors + 1
      _continue_0 = true
      break
    end
    local all_domains = { }
    local failed = false
    for _index_0 = 1, #urls do
      local url = urls[_index_0]
      io.stderr:write("[" .. tostring(name) .. "] GET " .. tostring(url) .. " ... ")
      local data, err = download(url)
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
if custom_lists_dir then
  local custom_bin_dir
  if domainlists_dir then
    custom_bin_dir = (domainlists_dir:gsub("/*$", "")) .. "/custom"
  else
    custom_bin_dir = custom_lists_dir
  end
  io.stderr:write("\n[custom] Scan de " .. tostring(custom_lists_dir) .. "/*.txt → " .. tostring(custom_bin_dir) .. "/\n")
  local n_ok, n_err = process_custom_dir(custom_lists_dir, custom_bin_dir, opts.dry_run)
  updated = updated + n_ok
  errors = errors + n_err
  io.stderr:write("[custom] " .. tostring(n_ok) .. " liste(s) mise(s) à jour, " .. tostring(n_err) .. " erreur(s).\n")
elseif next(sources) == nil then
  io.stderr:write("Aucune source définie dans cfg.sources — rien à faire.\n")
  os.exit(0)
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
