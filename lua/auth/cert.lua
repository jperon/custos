local ssl = require("ssl")
local CERT_DAYS = 3650
local CERT_KEY_BITS = 2048
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
local generate_self_signed
generate_self_signed = function(key_path, cert_path, sans)
  local cnf_path = "tmp/auth.cnf"
  local san_str = table.concat(sans, ",")
  local config = " [ req ]\n" .. " distinguished_name = req_distinguished_name\n" .. " x509_extensions = v3_req\n" .. " prompt = no\n\n" .. " [ req_distinguished_name ]\n" .. " CN = custos\n\n" .. " [ v3_req ]\n" .. " basicConstraints = CA:FALSE\n" .. " keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n" .. " extendedKeyUsage = serverAuth\n" .. " subjectKeyIdentifier = hash\n" .. " authorityKeyIdentifier = keyid:always,issuer:always\n" .. " subjectAltName = " .. tostring(san_str) .. "\n"
  local ok_w, err_w = pcall(function()
    local fh = io.open(cnf_path, "w")
    fh:write(config)
    return fh:close()
  end)
  if not (ok_w) then
    return false, "Échec écriture config SAN : " .. tostring(err_w)
  end
  local cmd = string.format("openssl req -x509 -newkey rsa:%d -keyout '%s' -out '%s' " .. "-days %d -nodes -config '%s' 2>&1", CERT_KEY_BITS, key_path, cert_path, CERT_DAYS, cnf_path)
  local fh = io.popen(cmd)
  local out = fh:read("*a")
  local ok_close = fh:close()
  pcall(os.remove, cnf_path)
  return (ok_close ~= nil and ok_close ~= false), out
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
  if (key_path == "tmp/auth.key" or key_path == nil) and (cert_path == "tmp/auth.crt" or cert_path == nil) then
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
return {
  load_or_generate = load_or_generate,
  generate_self_signed = generate_self_signed,
  make_context = make_context
}
