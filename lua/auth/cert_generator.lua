local log_debug, log_warn, log_error
do
  local _obj_0 = require("log")
  log_debug, log_warn, log_error = _obj_0.log_debug, _obj_0.log_warn, _obj_0.log_error
end
local generate_rsa_key
generate_rsa_key = function(bits)
  if bits == nil then
    bits = 2048
  end
  bits = tonumber(bits) or 2048
  local key_file = "/tmp/px5g_rsakey_" .. tostring(os.time()) .. "_" .. tostring(math.random(1000000)) .. ".pem"
  local cmd = "px5g rsakey -out " .. tostring(key_file) .. " " .. tostring(bits) .. " 2>/dev/null"
  local exit_code = os.execute(cmd)
  if not (exit_code == 0 or exit_code == true) then
    local err = "px5g rsakey exited with error code " .. tostring(exit_code)
    log_warn(function()
      return {
        action = "cert_gen_rsakey_failed",
        bits = bits,
        err = err
      }
    end)
    os.remove(key_file)
    return nil, false, err
  end
  local fh = io.open(key_file, "r")
  if not (fh) then
    local err = "Cannot read generated key file: " .. tostring(key_file)
    log_warn(function()
      return {
        action = "cert_gen_rsakey_read_failed",
        bits = bits,
        err = err
      }
    end)
    return nil, false, err
  end
  local key_pem = fh:read("*a")
  fh:close()
  os.remove(key_file)
  if not (key_pem and #key_pem > 0) then
    local err = "px5g rsakey produced empty output"
    log_warn(function()
      return {
        action = "cert_gen_rsakey_empty",
        bits = bits
      }
    end)
    return nil, false, err
  end
  if not (key_pem:match("BEGIN.*PRIVATE KEY")) then
    local err = "px5g rsakey output is not valid PEM"
    log_warn(function()
      return {
        action = "cert_gen_rsakey_invalid_pem",
        bits = bits
      }
    end)
    return nil, false, err
  end
  log_debug(function()
    return {
      action = "cert_gen_rsakey_success",
      bits = bits,
      size = #key_pem
    }
  end)
  return key_pem, true, nil
end
local generate_self_signed
generate_self_signed = function(cn, sans, days)
  if sans == nil then
    sans = { }
  end
  if days == nil then
    days = 3650
  end
  if not (cn and #cn > 0) then
    local err = "CN (Common Name) is empty or nil"
    log_warn(function()
      return {
        action = "cert_gen_selfsigned_nocn",
        err = err
      }
    end)
    return nil, nil, false, err
  end
  days = tonumber(days) or 3650
  local key_file = "/tmp/px5g_key_" .. tostring(os.time()) .. "_" .. tostring(math.random(1000000)) .. ".pem"
  local cert_file = "/tmp/px5g_cert_" .. tostring(os.time()) .. "_" .. tostring(math.random(1000000)) .. ".pem"
  local cmd = "px5g selfsigned -newkey ec -keyout " .. tostring(key_file) .. " -out " .. tostring(cert_file) .. " -subj \"/CN=" .. tostring(cn) .. "\" 2>/dev/null"
  log_debug(function()
    return {
      action = "cert_gen_selfsigned_cmd",
      cn = cn,
      cmd = cmd
    }
  end)
  log_debug(function()
    return {
      action = "cert_gen_px5g_executing",
      cn = cn,
      key_file = key_file,
      cert_file = cert_file
    }
  end)
  local exit_code = os.execute(cmd)
  log_debug(function()
    return {
      action = "cert_gen_px5g_done",
      cn = cn,
      exit_code = exit_code
    }
  end)
  if not (exit_code == 0 or exit_code == true) then
    local err = "px5g selfsigned exited with error code " .. tostring(exit_code)
    log_warn(function()
      return {
        action = "cert_gen_selfsigned_failed",
        cn = cn,
        err = err
      }
    end)
    os.remove(key_file)
    os.remove(cert_file)
    return nil, nil, false, err
  end
  log_debug(function()
    return {
      action = "cert_gen_key_reading",
      cn = cn,
      key_file = key_file
    }
  end)
  local key_fh = io.open(key_file, "r")
  if not (key_fh) then
    local err = "Cannot read generated key file: " .. tostring(key_file)
    log_warn(function()
      return {
        action = "cert_gen_key_read_failed",
        cn = cn,
        err = err
      }
    end)
    os.remove(cert_file)
    return nil, nil, false, err
  end
  local key_pem = key_fh:read("*a")
  key_fh:close()
  if not (key_pem and #key_pem > 0) then
    local err = "px5g generated empty key file"
    log_warn(function()
      return {
        action = "cert_gen_key_empty",
        cn = cn
      }
    end)
    os.remove(cert_file)
    return nil, nil, false, err
  end
  log_debug(function()
    return {
      action = "cert_gen_key_read_ok",
      cn = cn,
      key_size = #key_pem
    }
  end)
  log_debug(function()
    return {
      action = "cert_gen_cert_reading",
      cn = cn,
      cert_file = cert_file
    }
  end)
  local cert_fh = io.open(cert_file, "r")
  if not (cert_fh) then
    local err = "Cannot read generated cert file: " .. tostring(cert_file)
    log_warn(function()
      return {
        action = "cert_gen_cert_read_failed",
        cn = cn,
        err = err
      }
    end)
    return nil, nil, false, err
  end
  local cert_pem = cert_fh:read("*a")
  cert_fh:close()
  if not (cert_pem and #cert_pem > 0) then
    local err = "px5g generated empty cert file"
    log_warn(function()
      return {
        action = "cert_gen_cert_empty",
        cn = cn
      }
    end)
    return nil, nil, false, err
  end
  os.remove(key_file)
  os.remove(cert_file)
  log_debug(function()
    return {
      action = "cert_gen_selfsigned_success",
      cn = cn,
      sans_count = #sans,
      key_size = #key_pem,
      cert_size = #cert_pem
    }
  end)
  return key_pem, cert_pem, true, nil
end
return {
  generate_rsa_key = generate_rsa_key,
  generate_self_signed = generate_self_signed
}
