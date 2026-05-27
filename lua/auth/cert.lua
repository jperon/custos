local ssl = require("auth.ffi_wolfssl")
local log_debug, log_warn, log_error
do
  local _obj_0 = require("log")
  log_debug, log_warn, log_error = _obj_0.log_debug, _obj_0.log_warn, _obj_0.log_error
end
local CERT_DAYS = 730
local hash_string
hash_string = function(s)
  local h = 0
  for i = 1, #s do
    h = (h * 31 + s:byte(i)) % 0x7FFFFFFF
  end
  return string.format("%x", h)
end
local get_local_ips
get_local_ips = function()
  local ips = { }
  local ok, out = pcall(function()
    local f = io.popen("ip -4 addr show | awk '/inet/{print $2}' | cut -d'/' -f1 | grep -v '^127\\.' | sort -u")
    local res = f:read("*a")
    f:close()
    return res
  end)
  if ok and out then
    for ip in out:gmatch("%S+") do
      table.insert(ips, "IP:" .. tostring(ip))
    end
  end
  ok, out = pcall(function()
    local f = io.popen("ip -6 addr show | awk '/inet6/{print $2}' | cut -d'/' -f1 | grep -v '^::1$' | grep -v '^fe80:' | sort -u")
    local res = f:read("*a")
    f:close()
    return res
  end)
  if ok and out then
    for ip in out:gmatch("%S+") do
      table.insert(ips, "IP:" .. tostring(ip))
    end
  end
  return ips
end
local write_pem_file
write_pem_file = function(path, content)
  local fh, err = io.open(path, "w")
  if not (fh) then
    return false, "Impossible d'ouvrir " .. tostring(path) .. " : " .. tostring(err)
  end
  local ok_w, write_err = pcall(function()
    return fh:write(content)
  end)
  fh:close()
  if not (ok_w) then
    return false, "Impossible d'écrire " .. tostring(path) .. " : " .. tostring(write_err)
  end
  return true, nil
end
local generate_self_signed
generate_self_signed = function(key_path, cert_path, sans)
  local gen = require("auth.cert_generator")
  local dns_sans = { }
  local cn = "custos"
  if sans then
    for _index_0 = 1, #sans do
      local san = sans[_index_0]
      local dns_name = san:match("^DNS:(.+)$")
      if dns_name and #dns_name > 0 then
        if cn == "custos" then
          cn = dns_name
        end
        table.insert(dns_sans, dns_name)
      end
    end
  end
  local key_pem, cert_pem, ok, err = gen.generate_self_signed(cn, dns_sans, CERT_DAYS)
  if not (ok) then
    return false, err or "Échec génération px5g"
  end
  local ok_key, key_err = write_pem_file(key_path, key_pem)
  if not (ok_key) then
    return false, key_err
  end
  local ok_cert, cert_err = write_pem_file(cert_path, cert_pem)
  if not (ok_cert) then
    pcall(os.remove, key_path)
    return false, cert_err
  end
  return true, nil
end
local make_context
make_context = function(key_path, cert_path)
  local ctx, err = ssl.newcontext({
    mode = "server",
    protocol = "any",
    key = key_path,
    certificate = cert_path,
    options = {
      "no_sslv2",
      "no_sslv3",
      "no_tlsv1",
      "no_tlsv1_1"
    }
  })
  if not (ctx) then
    error("Échec création contexte TLS : " .. tostring(err))
  end
  return ctx
end
local file_exists
file_exists = function(path)
  local fh = io.open(path, "r")
  if fh then
    fh:close()
    return true
  else
    return false
  end
end
local load_or_generate
load_or_generate = function(key_path, cert_path)
  key_path = key_path or "tmp/auth.key"
  cert_path = cert_path or "tmp/auth.crt"
  if key_path == "tmp/auth.key" and cert_path == "tmp/auth.crt" then
    local ips = get_local_ips()
    local sans = {
      "DNS:custos"
    }
    for _index_0 = 1, #ips do
      local ip_san = ips[_index_0]
      table.insert(sans, ip_san)
    end
    local san_str = table.concat(sans, ",")
    local h = hash_string(san_str)
    key_path = "tmp/auth_" .. tostring(h) .. ".key"
    cert_path = "tmp/auth_" .. tostring(h) .. ".crt"
  end
  if not (file_exists(key_path) and file_exists(cert_path)) then
    local ips = get_local_ips()
    local sans = {
      "DNS:custos"
    }
    for _index_0 = 1, #ips do
      local ip_san = ips[_index_0]
      table.insert(sans, ip_san)
    end
    local ok, out = generate_self_signed(key_path, cert_path, sans)
    if not (ok) then
      error("Impossible de générer le certificat TLS :\n" .. tostring(out))
    end
  end
  return make_context(key_path, cert_path)
end
local load_or_generate_sni
load_or_generate_sni = function(hostname, cache)
  hostname = hostname or "custos"
  local hostname_lower = hostname:lower()
  log_debug(function()
    return {
      action = "cert_sni_request",
      hostname = hostname_lower
    }
  end)
  local entry = cache.get(hostname_lower)
  if entry and entry.ctx then
    log_debug(function()
      return {
        action = "cert_sni_cache_hit_ram",
        hostname = hostname_lower
      }
    end)
    return entry.ctx
  end
  if entry and entry.cert_pem and entry.key_pem then
    log_debug(function()
      return {
        action = "cert_sni_cache_hit_disk",
        hostname = hostname_lower
      }
    end)
    local key_file = "tmp/auth_sni_" .. tostring(hostname_lower) .. "_" .. tostring(os.date("%Y")) .. ".key"
    local cert_file = "tmp/auth_sni_" .. tostring(hostname_lower) .. "_" .. tostring(os.date("%Y")) .. ".crt"
    local key_ok = pcall(function()
      local key_fh = io.open(key_file, "w")
      if not (key_fh) then
        error("Cannot open key file")
      end
      key_fh:write(entry.key_pem)
      return key_fh:close()
    end)
    local cert_ok = pcall(function()
      local cert_fh = io.open(cert_file, "w")
      if not (cert_fh) then
        error("Cannot open cert file")
      end
      cert_fh:write(entry.cert_pem)
      return cert_fh:close()
    end)
    if key_ok and cert_ok then
      local ctx = ssl.newcontext({
        certificate = cert_file,
        key = key_file
      })
      cache.set(hostname_lower, entry.cert_pem, entry.key_pem, ctx)
      log_debug(function()
        return {
          action = "cert_sni_context_recreated",
          hostname = hostname_lower
        }
      end)
      return ctx
    end
  end
  log_debug(function()
    return {
      action = "cert_sni_cache_miss",
      hostname = hostname_lower
    }
  end)
  local gen = require("auth.cert_generator")
  log_debug(function()
    return {
      action = "cert_sni_generating",
      hostname = hostname_lower
    }
  end)
  local key_pem, cert_pem, ok, err = gen.generate_self_signed(hostname_lower)
  if not (ok) then
    log_error(function()
      return {
        action = "cert_sni_generation_failed",
        hostname = hostname_lower,
        err = err
      }
    end)
    error("Impossible de générer le certificat SNI pour " .. tostring(hostname_lower) .. " : " .. tostring(err))
  end
  log_debug(function()
    return {
      action = "cert_sni_generated",
      hostname = hostname_lower,
      key_size = #key_pem,
      cert_size = #cert_pem
    }
  end)
  local key_file = "tmp/auth_sni_" .. tostring(hostname_lower) .. "_" .. tostring(os.date("%Y")) .. ".key"
  local cert_file = "tmp/auth_sni_" .. tostring(hostname_lower) .. "_" .. tostring(os.date("%Y")) .. ".crt"
  log_debug(function()
    return {
      action = "cert_sni_writing_files",
      key_file = key_file,
      cert_file = cert_file
    }
  end)
  local key_fh, open_err = io.open(key_file, "w")
  if not (key_fh) then
    log_error(function()
      return {
        action = "cert_sni_key_write_failed",
        key_file = key_file,
        reason = open_err or "io.open failed"
      }
    end)
    error("Impossible d'écrire la clé SNI : " .. tostring(key_file))
  end
  local bytes_written = key_fh:write(key_pem)
  key_fh:close()
  log_debug(function()
    return {
      action = "cert_sni_key_written",
      key_file = key_file,
      bytes = bytes_written
    }
  end)
  local key_stat
  key_stat, open_err = io.open(key_file, "r")
  if not (key_stat) then
    log_error(function()
      return {
        action = "cert_sni_key_verify_failed",
        key_file = key_file,
        reason = open_err or "io.open failed"
      }
    end)
    error("Clé SNI écrite mais non relisible : " .. tostring(key_file))
  end
  key_stat:close()
  local cert_fh
  cert_fh, open_err = io.open(cert_file, "w")
  if not (cert_fh) then
    os.remove(key_file)
    log_error(function()
      return {
        action = "cert_sni_cert_write_failed",
        cert_file = cert_file,
        reason = open_err or "io.open failed"
      }
    end)
    error("Impossible d'écrire le certificat SNI : " .. tostring(cert_file))
  end
  bytes_written = cert_fh:write(cert_pem)
  cert_fh:close()
  log_debug(function()
    return {
      action = "cert_sni_cert_written",
      cert_file = cert_file,
      bytes = bytes_written
    }
  end)
  local cert_stat
  cert_stat, open_err = io.open(cert_file, "r")
  if not (cert_stat) then
    log_error(function()
      return {
        action = "cert_sni_cert_verify_failed",
        cert_file = cert_file,
        reason = open_err or "io.open failed"
      }
    end)
    error("Certificat SNI écrit mais non relisible : " .. tostring(cert_file))
  end
  cert_stat:close()
  log_debug(function()
    return {
      action = "cert_sni_newcontext",
      hostname = hostname_lower,
      protocol = "tlsv1_2"
    }
  end)
  local ctx = ssl.newcontext({
    mode = "server",
    protocol = "tlsv1_2",
    certificate = cert_file,
    key = key_file,
    options = {
      "no_sslv2",
      "no_sslv3",
      "no_tlsv1",
      "no_tlsv1_1"
    }
  })
  log_debug(function()
    return {
      action = "cert_sni_context_created",
      hostname = hostname_lower
    }
  end)
  cache.set(hostname_lower, cert_pem, key_pem, ctx)
  log_debug(function()
    return {
      action = "cert_sni_cached",
      hostname = hostname_lower
    }
  end)
  return ctx
end
local load_static
load_static = function(key_path, cert_path)
  if not (key_path and cert_path) then
    return nil, "cert_path and key_path must be provided"
  end
  if not (file_exists(key_path) and file_exists(cert_path)) then
    return nil, "cert or key file not found"
  end
  local ok, ctx = pcall(function()
    return make_context(key_path, cert_path)
  end)
  if not (ok) then
    return nil, "Failed to create TLS context from static files"
  end
  return ctx, nil
end
return {
  load_or_generate = load_or_generate,
  generate_self_signed = generate_self_signed,
  make_context = make_context,
  load_or_generate_sni = load_or_generate_sni,
  load_static = load_static,
  hash_string = hash_string
}
