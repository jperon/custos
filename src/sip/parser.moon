-- src/sip/parser.moon
-- Lightweight SIP/SDP parser for worker_sip.
-- Extracts method/status, CSeq, Content-Type, and SDP media IPs.
-- v1: no TCP reassembly; best-effort on fragmented messages.

--- Parse a SIP message string into its components.
-- Handles both CRLF and LF line endings.
-- @tparam string raw  Raw SIP payload bytes
-- @treturn table|nil  {method, status_code, call_id, cseq_method,
--                       content_type, sdp_ips} or nil if not a SIP message
parse = (raw) ->
  return nil unless raw and #raw > 4

  -- Normalise: strip CR so we can split on LF only.
  norm = raw\gsub "\r", ""

  -- Split headers / body on first blank line.
  headers_part, body = norm\match "^(.-)\n\n(.*)"
  headers_part = headers_part or norm

  lines = {}
  for line in headers_part\gmatch "[^\n]+"
    table.insert lines, line
  return nil if #lines == 0

  -- First line: SIP request or response.
  first = lines[1]
  method, status_code = nil, nil
  if first\find "^SIP/2%.0 "
    code = first\match "SIP/2%.0 (%d+)"
    status_code = tonumber code
  elseif first\find "SIP/2%.0$"
    -- Request: "METHOD target SIP/2.0"
    method = first\match "^(%u+)%s"

  return nil unless method or status_code

  -- Parse headers (compact forms per RFC 3261 §20).
  call_id, cseq_method, content_type = nil, nil, nil

  for i = 2, #lines
    line = lines[i]
    continue if #line == 0

    colon_pos = line\find ":"
    continue unless colon_pos

    k = (line\sub 1, colon_pos - 1)\lower!\match "^%s*(.-)%s*$"
    v = (line\sub colon_pos + 1)\match "^%s*(.-)%s*$"
    continue unless k and v and #k > 0

    if k == "call-id" or k == "i"
      call_id = v
    elseif k == "cseq"
      -- "1 INVITE" → cseq_method = "INVITE"
      cseq_method = v\match "%d+%s+(%u+)"
    elseif k == "content-type" or k == "c"
      -- Strip parameters: "application/sdp; charset=UTF-8" → "application/sdp"
      content_type = (v\lower!)\match "^[^;%s]+"

  -- Parse SDP body if Content-Type is application/sdp.
  sdp_ips = {}
  seen_ips = {}
  add_sdp_ip = (ip, family) ->
    return unless ip and family
    return if seen_ips[ip]
    seen_ips[ip] = true
    table.insert sdp_ips, { :ip, :family }

  if body and content_type and content_type\find "application/sdp"
    for sdp_line in body\gmatch "[^\n]+"
      -- c=IN IP4 x.x.x.x
      ip4 = sdp_line\match "^c=IN IP4 (%d+%.%d+%.%d+%.%d+)"
      if ip4
        add_sdp_ip ip4, "ip4"
        continue
      -- c=IN IP6 addr (skip "::" null address)
      ip6 = sdp_line\match "^c=IN IP6 (%S+)"
      if ip6 and (ip6\find ":") and ip6 != "::"
        add_sdp_ip ip6, "ip6"
        continue

      -- a=rtcp:<port> IN IP4 <ip>
      rtcp_ip4 = sdp_line\match "^a=rtcp:%d+ IN IP4 (%d+%.%d+%.%d+%.%d+)"
      if rtcp_ip4
        add_sdp_ip rtcp_ip4, "ip4"
        continue

      -- a=rtcp:<port> IN IP6 <ip>
      rtcp_ip6 = sdp_line\match "^a=rtcp:%d+ IN IP6 (%S+)"
      if rtcp_ip6 and (rtcp_ip6\find ":") and rtcp_ip6 != "::"
        add_sdp_ip rtcp_ip6, "ip6"
        continue

      -- ICE candidate (RFC 5245): a=candidate:<...> <ip> <port> typ <...>
      cand_ip4 = sdp_line\match "^a=candidate:%S+%s+%d+%s+%S+%s+%d+%s+(%d+%.%d+%.%d+%.%d+)%s+%d+%s+typ%s+%S+"
      if cand_ip4
        add_sdp_ip cand_ip4, "ip4"
        continue

      cand_ip6 = sdp_line\match "^a=candidate:%S+%s+%d+%s+%S+%s+%d+%s+(%S+)%s+%d+%s+typ%s+%S+"
      if cand_ip6 and (cand_ip6\find ":") and cand_ip6 != "::"
        add_sdp_ip cand_ip6, "ip6"

  { :method, :status_code, :call_id, :cseq_method, :content_type, :sdp_ips }

{ :parse }
