local parse
parse = function(raw)
  if not (raw and #raw > 4) then
    return nil
  end
  local norm = raw:gsub("\r", "")
  local headers_part, body = norm:match("^(.-)\n\n(.*)")
  headers_part = headers_part or norm
  local lines = { }
  for line in headers_part:gmatch("[^\n]+") do
    table.insert(lines, line)
  end
  if #lines == 0 then
    return nil
  end
  local first = lines[1]
  local method, status_code = nil, nil
  if first:find("^SIP/2%.0 ") then
    local code = first:match("SIP/2%.0 (%d+)")
    status_code = tonumber(code)
  elseif first:find("SIP/2%.0$") then
    method = first:match("^(%u+)%s")
  end
  if not (method or status_code) then
    return nil
  end
  local call_id, cseq_method, content_type = nil, nil, nil
  for i = 2, #lines do
    local _continue_0 = false
    repeat
      local line = lines[i]
      if #line == 0 then
        _continue_0 = true
        break
      end
      local colon_pos = line:find(":")
      if not (colon_pos) then
        _continue_0 = true
        break
      end
      local k = (line:sub(1, colon_pos - 1)):lower():match("^%s*(.-)%s*$")
      local v = (line:sub(colon_pos + 1)):match("^%s*(.-)%s*$")
      if not (k and v and #k > 0) then
        _continue_0 = true
        break
      end
      if k == "call-id" or k == "i" then
        call_id = v
      elseif k == "cseq" then
        cseq_method = v:match("%d+%s+(%u+)")
      elseif k == "content-type" or k == "c" then
        content_type = (v:lower()):match("^[^;%s]+")
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  local sdp_ips = { }
  local seen_ips = { }
  local add_sdp_ip
  add_sdp_ip = function(ip, family)
    if not (ip and family) then
      return 
    end
    if seen_ips[ip] then
      return 
    end
    seen_ips[ip] = true
    return table.insert(sdp_ips, {
      ip = ip,
      family = family
    })
  end
  if body and content_type and content_type:find("application/sdp") then
    for sdp_line in body:gmatch("[^\n]+") do
      local _continue_0 = false
      repeat
        local ip4 = sdp_line:match("^c=IN IP4 (%d+%.%d+%.%d+%.%d+)")
        if ip4 then
          add_sdp_ip(ip4, "ip4")
          _continue_0 = true
          break
        end
        local ip6 = sdp_line:match("^c=IN IP6 (%S+)")
        if ip6 and (ip6:find(":")) and ip6 ~= "::" then
          add_sdp_ip(ip6, "ip6")
          _continue_0 = true
          break
        end
        local rtcp_ip4 = sdp_line:match("^a=rtcp:%d+ IN IP4 (%d+%.%d+%.%d+%.%d+)")
        if rtcp_ip4 then
          add_sdp_ip(rtcp_ip4, "ip4")
          _continue_0 = true
          break
        end
        local rtcp_ip6 = sdp_line:match("^a=rtcp:%d+ IN IP6 (%S+)")
        if rtcp_ip6 and (rtcp_ip6:find(":")) and rtcp_ip6 ~= "::" then
          add_sdp_ip(rtcp_ip6, "ip6")
          _continue_0 = true
          break
        end
        local cand_ip4 = sdp_line:match("^a=candidate:%S+%s+%d+%s+%S+%s+%d+%s+(%d+%.%d+%.%d+%.%d+)%s+%d+%s+typ%s+%S+")
        if cand_ip4 then
          add_sdp_ip(cand_ip4, "ip4")
          _continue_0 = true
          break
        end
        local cand_ip6 = sdp_line:match("^a=candidate:%S+%s+%d+%s+%S+%s+%d+%s+(%S+)%s+%d+%s+typ%s+%S+")
        if cand_ip6 and (cand_ip6:find(":")) and cand_ip6 ~= "::" then
          add_sdp_ip(cand_ip6, "ip6")
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
  end
  return {
    method = method,
    status_code = status_code,
    call_id = call_id,
    cseq_method = cseq_method,
    content_type = content_type,
    sdp_ips = sdp_ips
  }
end
return {
  parse = parse
}
