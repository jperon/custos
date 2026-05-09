local log_debug, log_warn
do
  local _obj_0 = require("log")
  log_debug, log_warn = _obj_0.log_debug, _obj_0.log_warn
end
local extract_cn_from_subject
extract_cn_from_subject = function(subject)
  if not (subject and #subject > 0) then
    return nil
  end
  for part in subject:gmatch("CN=([^,]+)") do
    return part:gsub('\\(.)', '%1')
  end
  return nil
end
local extract_sans
extract_sans = function(cert_data)
  local sans = { }
  if not (cert_data and cert_data.subject_alt_name) then
    return sans
  end
  local san_string = cert_data.subject_alt_name
  for dns_name in san_string:gmatch("DNS:([^,]+)") do
    table.insert(sans, dns_name)
  end
  return sans
end
local extract_username
extract_username = function(cert_data, cn_field)
  if not (cert_data) then
    return nil
  end
  cn_field = cn_field or "subject"
  local subject_str = cert_data[cn_field]
  local cn
  if subject_str then
    cn = extract_cn_from_subject(subject_str)
  end
  if cn and #cn > 0 then
    return cn
  end
  local sans = extract_sans(cert_data)
  if #sans > 0 then
    return sans[1]
  end
  return nil
end
local validate_username
validate_username = function(username)
  if not (username and #username > 0) then
    return false
  end
  if #username > 256 then
    return false
  end
  return username:match("^[a-zA-Z0-9_.-]+$") ~= nil
end
local parse_certificate
parse_certificate = function(raw_cert_data)
  if not (raw_cert_data) then
    return nil
  end
  local parsed = {
    subject = raw_cert_data.subject or "",
    subject_alt_name = raw_cert_data.subject_alt_name or "",
    issuer = raw_cert_data.issuer or "",
    valid_from = raw_cert_data.notBefore or 0,
    valid_to = raw_cert_data.notAfter or 0
  }
  return parsed
end
return {
  extract_cn_from_subject = extract_cn_from_subject,
  extract_sans = extract_sans,
  extract_username = extract_username,
  validate_username = validate_username,
  parse_certificate = parse_certificate
}
