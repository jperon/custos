local ssl = require("ssl")
local CERT_DAYS = 3650
local CERT_KEY_BITS = 2048
local generate_self_signed
generate_self_signed = function(key_path, cert_path)
  local cmd = string.format("openssl req -x509 -newkey rsa:%d -keyout '%s' -out '%s'" .. " -days %d -nodes -subj '/CN=custos' 2>&1", CERT_KEY_BITS, key_path, cert_path, CERT_DAYS)
  local fh = io.popen(cmd)
  local out = fh:read("*a")
  local ok = fh:close()
  return ok, out
end
local make_context
make_context = function(key_path, cert_path)
  local ctx, err = ssl.newcontext({
    mode = "server",
    protocol = "any",
    key = key_path,
    certificate = cert_path,
    options = {
      "all",
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
  if not (file_exists(key_path) and file_exists(cert_path)) then
    local ok, out = generate_self_signed(key_path, cert_path)
    if not (ok) then
      error("Impossible de générer le certificat TLS :\n" .. tostring(out))
    end
  end
  return make_context(key_path, cert_path)
end
return {
  load_or_generate = load_or_generate,
  generate_self_signed = generate_self_signed,
  make_context = make_context
}
