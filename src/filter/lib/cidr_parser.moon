-- src/filter/lib/cidr_parser.moon
-- CIDR notation parsing and validation for subnet-based rules.
-- Supports IPv4 (x.x.x.x/y) and IPv6 (::1/128) notation.
-- Validates network addresses and prefix lengths.

bit = require "bit"

--- Parses an IPv4 CIDR string and validates the network address.
-- @tparam string cidr_str IPv4 CIDR notation (e.g., "192.168.0.0/24")
-- @treturn table|nil {cidr: string, net: string, prefix: number, family: "inet", is_valid: true} or nil
parse_ipv4_cidr = (cidr_str) ->
  return nil unless cidr_str
  s = tostring(cidr_str)\match "^%s*(.-)%s*$"
  return nil unless s and #s > 0
  return nil if s\find ":"  -- IPv6

  addr_part, prefix_part = s\match "^([^/]+)/?(.*)$"
  return nil unless addr_part

  prefix = tonumber(prefix_part)
  prefix = 32 unless prefix_part and #prefix_part > 0
  return nil unless prefix >= 0 and prefix <= 32

  -- Validate IP format (simple check)
  parts = {}
  for p in addr_part\gmatch "[0-9]+"
    parts[#parts + 1] = tonumber(p)
  return nil unless #parts == 4
  for p in *parts
    return nil unless p >= 0 and p <= 255

  {
    cidr: s
    net: addr_part
    prefix: prefix
    family: "inet"
    is_valid: true
  }

--- Parses an IPv6 CIDR string and validates the network address.
-- @tparam string cidr_str IPv6 CIDR notation (e.g., "fc00::/7")
-- @treturn table|nil {cidr: string, net: string, prefix: number, family: "inet6", is_valid: true} or nil
parse_ipv6_cidr = (cidr_str) ->
  return nil unless cidr_str
  s = tostring(cidr_str)\match "^%s*(.-)%s*$"
  return nil unless s and #s > 0
  return nil unless s\find ":"

  addr_part, prefix_part = s\match "^([^/]+)/?(.*)$"
  return nil unless addr_part

  prefix = tonumber(prefix_part)
  prefix = 128 unless prefix_part and #prefix_part > 0
  return nil unless prefix >= 0 and prefix <= 128

  -- Basic validation: has IPv6 components (simplified)
  -- Real validation done by inet_pton in conditions layer
  return nil unless addr_part\find ":" 

  {
    cidr: s
    net: addr_part
    prefix: prefix
    family: "inet6"
    is_valid: true
  }

--- Parses a CIDR string and detects address family (IPv4 or IPv6).
-- @tparam string cidr_str CIDR notation string
-- @treturn table|nil Parsed CIDR object {cidr, net, prefix, family, is_valid} or nil if invalid
parse_cidr = (cidr_str) ->
  return nil unless cidr_str
  s = tostring(cidr_str)

  if s\find ":", 1, true
    return parse_ipv6_cidr s
  else
    return parse_ipv4_cidr s

--- Validates that a CIDR string is well-formed and represents a valid network.
-- @tparam string cidr_str CIDR notation string
-- @treturn boolean, string|nil (is_valid, error_reason)
validate_cidr = (cidr_str) ->
  parsed = parse_cidr cidr_str
  return false, "Invalid CIDR notation: #{cidr_str}" unless parsed
  return true, nil

--- Formats a parsed CIDR back to standard notation.
-- @tparam table parsed Parsed CIDR object from parse_cidr()
-- @treturn string CIDR notation string (e.g., "192.168.0.0/24")
format_cidr = (parsed) ->
  return nil unless parsed
  return nil unless parsed.net and parsed.prefix
  
  if parsed.family == "inet6"
    "#{parsed.net}/#{parsed.prefix}"
  else
    "#{parsed.net}/#{parsed.prefix}"

{ :parse_cidr, :parse_ipv4_cidr, :parse_ipv6_cidr, :validate_cidr, :format_cidr }
