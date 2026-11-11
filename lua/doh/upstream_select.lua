local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local CURL_MOD = "doh.upstream_doh_curl"
local WOLF_MOD = "doh.upstream_doh"
local load_curl
load_curl = function(req)
  local ok, mod = pcall(req, CURL_MOD)
  if not (ok) then
    return nil, "load_failed: " .. tostring(tostring(mod))
  end
  if type(mod.probe) == "function" then
    local ok_p, avail, why = pcall(mod.probe)
    if not (ok_p) then
      return nil, "init_probe_failed: " .. tostring(tostring(avail))
    end
    if not (avail) then
      return nil, "init_failed: " .. tostring(tostring(why))
    end
  end
  return mod
end
local refused_desc
refused_desc = function(reason)
  return {
    transport = "wolfssl_refused",
    verify_tls = false,
    make_client = function(url, timeout_ms, verify_tls)
      return nil, "upstream_doh: tls_verify_unavailable: " .. tostring(reason)
    end,
    close = function() end
  }
end
local make_curl_desc
make_curl_desc = function(mod, opts)
  local verify = opts.verify_tls ~= false
  log_info(function()
    return {
      action = "upstream_doh_curl_enabled",
      url = opts.url,
      verify_tls = verify
    }
  end)
  if not (verify) then
    log_warn(function()
      return {
        action = "upstream_doh_tls_verify_disabled",
        url = opts.url,
        detail = "certificat TLS du résolveur amont NON vérifié (MITM possible)"
      }
    end)
  end
  return {
    transport = "curl",
    verify_tls = verify,
    make_client = function(url, timeout_ms, verify_tls)
      return mod.new_client(url, timeout_ms, verify_tls)
    end,
    close = function(client)
      return mod.close(client)
    end
  }
end
local make_wolf_desc
make_wolf_desc = function(mod, opts, curl_reason)
  local role = opts.role or "upstream"
  local wanted = opts.verify_tls ~= false
  local verify_ok, verify_why, ca_file = true, nil, nil
  if wanted then
    if type(mod.verification_available) == "function" then
      local ok_v, a, why, ca = pcall(mod.verification_available, {
        ca_file = opts.ca_file
      })
      if not (ok_v) then
        verify_ok, verify_why = false, "sonde de vérification en échec: " .. tostring(tostring(a))
      else
        verify_ok = a == true
        verify_why = why
        ca_file = ca
      end
    else
      verify_ok, verify_why = false, "module sans verification_available"
    end
  end
  local insecure_allowed = role ~= "validator" and opts.fallback_insecure == true
  local effective = false
  if wanted and verify_ok then
    effective = true
  elseif wanted and not verify_ok and not insecure_allowed then
    local reason = "curl " .. tostring(curl_reason) .. "; wolfSSL: " .. tostring(verify_why or 'vérification indisponible')
    log_warn(function()
      return {
        action = "doh_upstream_fallback_wolfssl",
        url = opts.url,
        reason = reason,
        verify_tls = false,
        refused = true,
        detail = "repli refusé : vérification TLS impossible et doh.upstream_fallback_insecure=false (ou validateur)"
      }
    end)
    return refused_desc(verify_why or "vérification indisponible")
  end
  local detail = nil
  if not (effective) then
    if wanted then
      detail = "repli wolfSSL NON vérifié (certificat et nom d'hôte) — MITM possible (doh.upstream_fallback_insecure=true)"
    else
      detail = "repli wolfSSL NON vérifié (doh.upstream_doh_tls_verify=false)"
    end
  end
  log_warn(function()
    return {
      action = "doh_upstream_fallback_wolfssl",
      url = opts.url,
      reason = "curl " .. tostring(curl_reason),
      verify_tls = effective,
      detail = detail
    }
  end)
  return {
    transport = "wolfssl",
    verify_tls = effective,
    make_client = function(url, timeout_ms)
      return mod.new_client(url, timeout_ms, effective, {
        ca_file = ca_file
      })
    end,
    close = function(client)
      return mod.close(client)
    end
  }
end
local select
select = function(opts, deps)
  if deps == nil then
    deps = { }
  end
  if not (opts and opts.url) then
    return nil, "upstream_select: url manquante"
  end
  local wanted
  if opts.verify_tls == nil then
    wanted = true
  else
    wanted = opts.verify_tls
  end
  local o = {
    url = opts.url,
    timeout_ms = opts.timeout_ms,
    verify_tls = wanted,
    fallback_insecure = opts.fallback_insecure == true,
    ca_file = opts.ca_file,
    role = opts.role or "upstream"
  }
  local req = deps.require_fn or require
  local curl_mod, curl_reason = load_curl(req)
  if curl_mod then
    return make_curl_desc(curl_mod, o)
  end
  local ok_w, wolf_mod = pcall(req, WOLF_MOD)
  if not (ok_w) then
    local reason = "curl " .. tostring(curl_reason) .. "; wolfSSL load_failed: " .. tostring(tostring(wolf_mod))
    log_warn(function()
      return {
        action = "doh_upstream_fallback_wolfssl",
        url = o.url,
        reason = reason,
        verify_tls = "none",
        detail = "aucun transport DoH amont disponible"
      }
    end)
    return nil, reason
  end
  return make_wolf_desc(wolf_mod, o, curl_reason)
end
return {
  select = select,
  load_curl = load_curl
}
