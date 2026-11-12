local ffi = require("ffi")
local ssl = require("auth.ffi_wolfssl")
local log_warn, log_debug
do
  local _obj_0 = require("log")
  log_warn, log_debug = _obj_0.log_warn, _obj_0.log_debug
end
local SSL_FILETYPE_PEM = 1
local SECONDS_PER_DAY = 86400
local EXPIRY_WARN_DAYS = 14
local days_from_civil
days_from_civil = function(year, month, day)
  local y
  if month <= 2 then
    y = year - 1
  else
    y = year
  end
  local era
  if y >= 0 then
    era = math.floor(y / 400)
  else
    era = math.floor((y - 399) / 400)
  end
  local yoe = y - era * 400
  local mp = (month + 9) % 12
  local doy = math.floor((153 * mp + 2) / 5) + day - 1
  local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
end
local utc_epoch
utc_epoch = function(year, month, day, hour, min, sec)
  return days_from_civil(year, month, day) * SECONDS_PER_DAY + hour * 3600 + min * 60 + sec
end
local parse_asn1_time
parse_asn1_time = function(s)
  if not (type(s) == "string") then
    return nil
  end
  local len = #s
  if not (s:sub(len, len) == "Z") then
    return nil
  end
  local year = nil
  local off = nil
  if len == 13 then
    local yy = tonumber(s:sub(1, 2))
    if not (yy) then
      return nil
    end
    if yy >= 50 then
      year = 1900 + yy
    else
      year = 2000 + yy
    end
    off = 3
  elseif len == 15 then
    year = tonumber(s:sub(1, 4))
    if not (year) then
      return nil
    end
    off = 5
  else
    return nil
  end
  local month = tonumber(s:sub(off, off + 1))
  local day = tonumber(s:sub(off + 2, off + 3))
  local hour = tonumber(s:sub(off + 4, off + 5))
  local min = tonumber(s:sub(off + 6, off + 7))
  local sec = tonumber(s:sub(off + 8, off + 9))
  if not (month and day and hour and min and sec) then
    return nil
  end
  if not (month >= 1 and month <= 12) then
    return nil
  end
  if not (day >= 1 and day <= 31) then
    return nil
  end
  if not (hour <= 23 and min <= 59 and sec <= 59) then
    return nil
  end
  return utc_epoch(year, month, day, hour, min, sec)
end
local certificate_not_after
certificate_not_after = function(path, lib)
  lib = lib or ssl.libwolfssl
  if not (lib) then
    return nil, "library_unavailable"
  end
  local _list_0 = {
    "wolfSSL_X509_load_certificate_file",
    "wolfSSL_X509_get_notAfter",
    "wolfSSL_X509_free"
  }
  for _index_0 = 1, #_list_0 do
    local name = _list_0[_index_0]
    if not (ssl.symbol_available(name, lib)) then
      return nil, "symbol_missing:" .. tostring(name)
    end
  end
  local ok_load, x509 = pcall(function()
    return lib.wolfSSL_X509_load_certificate_file(path, SSL_FILETYPE_PEM)
  end)
  if not (ok_load and x509 ~= nil) then
    return nil, "load_failed"
  end
  local ok_asn, asn = pcall(function()
    return lib.wolfSSL_X509_get_notAfter(x509)
  end)
  if not (ok_asn and asn ~= nil and asn.length and asn.length > 0) then
    pcall(function()
      return lib.wolfSSL_X509_free(x509)
    end)
    return nil, "not_after_unavailable"
  end
  local text = ffi.string(asn.data, asn.length)
  pcall(function()
    return lib.wolfSSL_X509_free(x509)
  end)
  local epoch = parse_asn1_time(text)
  if not (epoch) then
    return nil, "unparsable:" .. tostring(text)
  end
  return epoch
end
local classify_expiry
classify_expiry = function(not_after, now, warn_days)
  if warn_days == nil then
    warn_days = EXPIRY_WARN_DAYS
  end
  if not (type(not_after) == "number") then
    return nil
  end
  if not_after <= now then
    return "expired"
  elseif not_after - now <= warn_days * SECONDS_PER_DAY then
    return "expires_soon"
  else
    return "valid"
  end
end
local check_cert
check_cert = function(path, opts)
  if opts == nil then
    opts = { }
  end
  if not (path) then
    return nil
  end
  local now = opts.now or os.time()
  local warn_fn = opts.log_warn_fn or log_warn
  local debug_fn = opts.log_debug_fn or log_debug
  local not_after, err = certificate_not_after(path, opts.lib)
  if not (not_after) then
    debug_fn(function()
      return {
        action = "cert_expiry_unknown",
        cert = path,
        err = err or "unknown"
      }
    end)
    return nil
  end
  local status = classify_expiry(not_after, now, opts.warn_days)
  if not (status == "expired" or status == "expires_soon") then
    return status
  end
  local fields = {
    cert = path,
    not_after = os.date("!%Y-%m-%dT%H:%M:%SZ", not_after),
    days_left = math.floor((not_after - now) / SECONDS_PER_DAY),
    worker = opts.worker,
    action = (function()
      if status == "expired" then
        return "cert_expired"
      else
        return "cert_expires_soon"
      end
    end)()
  }
  warn_fn(function()
    return fields
  end)
  return status
end
return {
  days_from_civil = days_from_civil,
  utc_epoch = utc_epoch,
  parse_asn1_time = parse_asn1_time,
  certificate_not_after = certificate_not_after,
  classify_expiry = classify_expiry,
  check_cert = check_cert,
  EXPIRY_WARN_DAYS = EXPIRY_WARN_DAYS,
  SECONDS_PER_DAY = SECONDS_PER_DAY
}
