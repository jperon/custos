-- src/auth/cert_parser.moon
-- Certificate parsing utilities to extract user information (CN/SAN).

{ :log_debug, :log_warn } = require "log"

--- Extract Common Name (CN) from certificate subject.
-- Parses X.509 subject string format: "C=XX,O=org,CN=username,..."
-- @tparam string subject Subject string from certificate
-- @treturn string|nil Common Name value or nil if not found
extract_cn_from_subject = (subject) ->
  return nil unless subject and #subject > 0
  
  for part in subject\gmatch "CN=([^,]+)"
    return part\gsub('\\(.)', '%1')  -- Handle escaped characters
  
  nil

--- Extract Subject Alternative Names from certificate.
-- Returns DNS names from SAN extension (if available).
-- @tparam table cert_data Certificate data with subject_alt_name field (optional)
-- @treturn table List of SANs (e.g., {"example.com", "www.example.com"})
extract_sans = (cert_data) ->
  sans = {}
  return sans unless cert_data and cert_data.subject_alt_name
  
  san_string = cert_data.subject_alt_name
  for dns_name in san_string\gmatch "DNS:([^,]+)"
    table.insert sans, dns_name
  
  sans

--- Extract username from certificate.
-- Attempts to extract username from CN or first DNS SAN.
-- @tparam table cert_data Certificate data with subject and optional subject_alt_name
-- @tparam string cn_field Field to use for CN extraction (default: "subject")
-- @treturn string|nil Username extracted from certificate
extract_username = (cert_data, cn_field) ->
  return nil unless cert_data
  
  cn_field = cn_field or "subject"
  subject_str = cert_data[cn_field]
  
  -- Try to extract CN from subject
  cn = extract_cn_from_subject subject_str if subject_str
  return cn if cn and #cn > 0
  
  -- Fallback: try to extract from SAN
  sans = extract_sans cert_data
  if #sans > 0
    -- Return first SAN as fallback username
    return sans[1]
  
  nil

--- Validate extracted username format.
-- Username should be alphanumeric + underscore/hyphen.
-- @tparam string username Username to validate
-- @treturn boolean true if valid format
validate_username = (username) ->
  return false unless username and #username > 0
  return false if #username > 256  -- Reasonable length limit
  
  -- Allow alphanumeric, underscore, hyphen, and dot
  username\match("^[a-zA-Z0-9_.-]+$") ~= nil

--- Parse certificate response data.
-- Converts raw certificate data into a structured format.
-- @tparam table raw_cert_data Raw certificate data from TLS handshake
-- @treturn table|nil Parsed certificate data or nil if parsing fails
parse_certificate = (raw_cert_data) ->
  return nil unless raw_cert_data
  
  parsed = {
    subject: raw_cert_data.subject or ""
    subject_alt_name: raw_cert_data.subject_alt_name or ""
    issuer: raw_cert_data.issuer or ""
    valid_from: raw_cert_data.notBefore or 0
    valid_to: raw_cert_data.notAfter or 0
  }
  
  parsed

{
  :extract_cn_from_subject
  :extract_sans
  :extract_username
  :validate_username
  :parse_certificate
}
