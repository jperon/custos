local socket = require("lib.socket")
local ssl = require("auth.ffi_wolfssl")
local bit = require("bit")
local fork_child, reap_one
do
  local _obj_0 = require("lib.process")
  fork_child, reap_one = _obj_0.fork_child, _obj_0.reap_one
end
local load_or_generate_sni, load_static
do
  local _obj_0 = require("auth.cert")
  load_or_generate_sni, load_static = _obj_0.load_or_generate_sni, _obj_0.load_static
end
local log_info, log_warn, log_error, log_debug, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error, log_debug, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error, _obj_0.log_debug, _obj_0.set_action_prefix
end
local read_request, send_response, apply_io_timeouts
do
  local _obj_0 = require("lib.http")
  read_request, send_response, apply_io_timeouts = _obj_0.read_request, _obj_0.send_response, _obj_0.apply_io_timeouts
end
local get_mac, get_vlan
do
  local _obj_0 = require("mac_learner_ipc")
  get_mac, get_vlan = _obj_0.get_mac, _obj_0.get_vlan
end
local process_query
process_query = require("doh.query").process_query
local parse, types, rcodes
do
  local _obj_0 = require("ipparse.l7.dns")
  parse, types, rcodes = _obj_0.parse, _obj_0.types, _obj_0.rcodes
end
local upstream_mod = require("doh.upstream")
local upstream_select = require("doh.upstream_select")
local hpack = require("doh.hpack")
local b64_chars = { }
do
  local s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  for i = 1, #s do
    b64_chars[s:sub(i, i)] = i - 1
  end
  b64_chars["-"] = 62
  b64_chars["_"] = 63
end
local b64url_decode
b64url_decode = function(s)
  local pad = (4 - #s % 4) % 4
  s = s .. string.rep("=", pad)
  local out = { }
  local i = 1
  while i <= #s do
    local c1 = b64_chars[s:sub(i, i)] or -1
    local c2 = b64_chars[s:sub(i + 1, i + 1)] or -1
    local c3 = b64_chars[s:sub(i + 2, i + 2)] or -1
    local c4 = b64_chars[s:sub(i + 3, i + 3)] or -1
    if c1 < 0 or c2 < 0 then
      break
    end
    local v = c1 * 0x40000 + c2 * 0x1000 + (c3 >= 0 and c3 or 0) * 0x40 + (c4 >= 0 and c4 or 0)
    out[#out + 1] = string.char(bit.band(bit.rshift(v, 16), 0xFF))
    if c3 >= 0 then
      out[#out + 1] = string.char(bit.band(bit.rshift(v, 8), 0xFF))
    end
    if c4 >= 0 then
      out[#out + 1] = string.char(bit.band(v, 0xFF))
    end
    i = i + 4
  end
  return table.concat(out)
end
local url_decode
url_decode = function(s)
  if not (s) then
    return ""
  end
  s = s:gsub("%+", " ")
  return s:gsub("%%(%x%x)", function(h)
    return string.char(tonumber(h, 16))
  end)
end
local query_param
query_param = function(path, name)
  local val = path:match("[?&]" .. tostring(name) .. "=([^&]+)")
  if val then
    return url_decode(val)
  end
end
local is_doh_path
is_doh_path = function(path)
  if not (type(path) == "string") then
    return false
  end
  return path == "/dns-query" or (path:match("^/dns%-query%?")) ~= nil
end
local is_dns_message_content_type
is_dns_message_content_type = function(content_type)
  if not (type(content_type) == "string") then
    return false
  end
  return (content_type:match("application/dns%-message")) ~= nil
end
local dns_from_query
dns_from_query = function(path)
  if not (type(path) == "string") then
    return nil
  end
  local dns_param = path:match("[?&]dns=([^&]+)")
  return dns_param and b64url_decode(dns_param)
end
local json_escape
json_escape = function(s)
  if not (s) then
    return ""
  end
  s = tostring(s)
  s = s:gsub("\\", "\\\\")
  s = s:gsub("\"", "\\\"")
  s = s:gsub("\n", "\\n")
  s = s:gsub("\r", "\\r")
  s = s:gsub("\t", "\\t")
  return s
end
local json_quote
json_quote = function(s)
  return "\"" .. json_escape(s) .. "\""
end
local qtype_from_name
qtype_from_name = function(name)
  if not (name) then
    return 1
  end
  local n = tonumber(name)
  if n then
    return n
  end
  return types[name:upper()] or 1
end
local encode_qname
encode_qname = function(name)
  if not (name and #name > 0) then
    return nil
  end
  name = name:gsub("%.$", "")
  local parts = { }
  for label in name:gmatch("[^%.]+") do
    if #label > 63 then
      return nil
    end
    parts[#parts + 1] = string.char(#label) .. label
  end
  return table.concat(parts) .. "\0"
end
local u16
u16 = function(n)
  return string.char(bit.band(bit.rshift(n, 8), 0xFF)) .. string.char(bit.band(n, 0xFF))
end
local build_dns_query
build_dns_query = function(name, qtype)
  local qname = encode_qname(name)
  if not (qname) then
    return nil
  end
  local id = os.time() % 65536
  return table.concat({
    u16(id),
    u16(0x0100),
    u16(1),
    u16(0),
    u16(0),
    u16(0),
    qname,
    u16(qtype),
    u16(1)
  })
end
local rr_data_json
rr_data_json = function(rr)
  if rr.rtype == 1 and #rr.rdata == 4 then
    return tostring(rr.rdata:byte(1)) .. "." .. tostring(rr.rdata:byte(2)) .. "." .. tostring(rr.rdata:byte(3)) .. "." .. tostring(rr.rdata:byte(4))
  end
  if rr.rtype == 28 and #rr.rdata == 16 then
    local words = { }
    for i = 1, 16, 2 do
      words[#words + 1] = string.format("%x", rr.rdata:byte(i) * 256 + rr.rdata:byte(i + 1))
    end
    return table.concat(words, ":")
  end
  return rr.rdata or ""
end
local dns_response_json
dns_response_json = function(raw)
  local dns = parse(raw, 1, false)
  if not (dns) then
    return nil
  end
  local parts = {
    "{",
    "\"Status\":" .. tostring(bit.band((dns.header.ra_z_rcode or 0), 0x0f)),
    ",\"TC\":" .. tostring(dns.header.tc and true or false),
    ",\"RD\":" .. tostring(dns.header.rd and true or false),
    ",\"RA\":" .. tostring(dns.header.ra and true or false),
    ",\"Question\":["
  }
  local questions = dns.questions or { }
  for i, q in ipairs(questions) do
    if i > 1 then
      parts[#parts + 1] = ","
    end
    parts[#parts + 1] = "{\"name\":" .. json_quote(q.name or "") .. ",\"type\":" .. tostring(q.qtype or 1) .. "}"
  end
  parts[#parts + 1] = "],\"Answer\":["
  local answers = dns.answers or { }
  local n = 0
  for _index_0 = 1, #answers do
    local rr = answers[_index_0]
    if rr.rtype == 1 or rr.rtype == 28 then
      n = n + 1
      if n > 1 then
        parts[#parts + 1] = ","
      end
      parts[#parts + 1] = "{\"name\":" .. json_quote(rr.name or "") .. ",\"type\":" .. tostring(rr.rtype) .. ",\"TTL\":" .. tostring(rr.ttl or 0) .. ",\"data\":" .. json_quote(rr_data_json(rr)) .. "}"
    end
  end
  parts[#parts + 1] = "]}"
  return table.concat(parts)
end
local handshake_should_continue
handshake_should_continue = function(done, attempts, now, deadline)
  return not done and attempts < 50 and now <= deadline
end
local make_server4
make_server4 = function(port)
  local srv = socket.tcp()
  srv:setoption("reuseaddr", true)
  local ok, err = srv:bind("0.0.0.0", port)
  if not (ok) then
    srv:close()
    return nil, err
  end
  srv:listen(32)
  srv:settimeout(1)
  return srv
end
local make_server6
make_server6 = function(port)
  local ok6, srv6 = pcall(socket.tcp6)
  if not (ok6 and srv6) then
    return nil
  end
  srv6:setoption("reuseaddr", true)
  srv6:setoption("ipv6-v6only", true)
  local ok62, _ = pcall(srv6.bind, srv6, "::", port)
  if not (ok62) then
    srv6:close()
    return nil
  end
  srv6:listen(32)
  srv6:settimeout(1)
  return srv6
end
local H2_FRAME_DATA, H2_FRAME_HEADERS, H2_FRAME_SETTINGS, H2_FRAME_PING, H2_FRAME_GOAWAY, H2_FRAME_WINDOW_UPDATE, H2_FRAME_CONTINUATION, H2_FLAG_END_STREAM, H2_FLAG_END_HEADERS, H2_FLAG_ACK, H2_FLAG_PADDED, H2_FLAG_PRIORITY, H2_DEFAULT_MAX_FRAME_SIZE, h2_read_frame, h2_write_frame
do
  local _obj_0 = require("doh.h2_frames")
  H2_FRAME_DATA, H2_FRAME_HEADERS, H2_FRAME_SETTINGS, H2_FRAME_PING, H2_FRAME_GOAWAY, H2_FRAME_WINDOW_UPDATE, H2_FRAME_CONTINUATION, H2_FLAG_END_STREAM, H2_FLAG_END_HEADERS, H2_FLAG_ACK, H2_FLAG_PADDED, H2_FLAG_PRIORITY, H2_DEFAULT_MAX_FRAME_SIZE, h2_read_frame, h2_write_frame = _obj_0.H2_FRAME_DATA, _obj_0.H2_FRAME_HEADERS, _obj_0.H2_FRAME_SETTINGS, _obj_0.H2_FRAME_PING, _obj_0.H2_FRAME_GOAWAY, _obj_0.H2_FRAME_WINDOW_UPDATE, _obj_0.H2_FRAME_CONTINUATION, _obj_0.H2_FLAG_END_STREAM, _obj_0.H2_FLAG_END_HEADERS, _obj_0.H2_FLAG_ACK, _obj_0.H2_FLAG_PADDED, _obj_0.H2_FLAG_PRIORITY, _obj_0.H2_DEFAULT_MAX_FRAME_SIZE, _obj_0.h2_read_frame, _obj_0.h2_write_frame
end
local h2_encode_response_headers
h2_encode_response_headers = function(content_type)
  return hpack.encode({
    {
      ":status",
      "200"
    },
    {
      "content-type",
      content_type
    }
  })
end
local H2_PROTOCOL_ERROR = 0x1
local H2_FRAME_SIZE_ERROR = 0x6
local H2_COMPRESSION_ERROR = 0x9
local H2_MAX_BODY = 65535
local H2_MAX_HEADER_BLOCK = 65535
local H2_MAX_CONTINUATION = 64
local h2_goaway
h2_goaway = function(conn, code)
  return h2_write_frame(conn, H2_FRAME_GOAWAY, 0, 0, "\x00\x00\x00\x00\x00\x00\x00" .. string.char(code))
end
local read_header_block
read_header_block = function(conn, sid, flags, payload)
  local pos = 1
  local last = #payload
  if bit.band(flags, H2_FLAG_PADDED) ~= 0 then
    if pos > last then
      return nil, false, "h2_headers_invalid"
    end
    local pad_len = payload:byte(pos)
    pos = pos + 1
    if pad_len > last - pos + 1 then
      return nil, false, "h2_headers_invalid"
    end
    last = last - pad_len
  end
  if bit.band(flags, H2_FLAG_PRIORITY) ~= 0 then
    if last - pos + 1 < 5 then
      return nil, false, "h2_headers_invalid"
    end
    pos = pos + 5
  end
  local end_stream = bit.band(flags, H2_FLAG_END_STREAM) ~= 0
  local parts = {
    payload:sub(pos, last)
  }
  local size = #parts[1]
  local continuations = 0
  while bit.band(flags, H2_FLAG_END_HEADERS) == 0 do
    continuations = continuations + 1
    if continuations > H2_MAX_CONTINUATION then
      return nil, end_stream, "h2_headers_invalid"
    end
    local ctype, cflags, csid, cpayload = h2_read_frame(conn, H2_DEFAULT_MAX_FRAME_SIZE)
    if not ctype then
      if cflags == "frame_too_large" then
        return nil, end_stream, "frame_too_large"
      end
      return nil, end_stream, "h2_headers_invalid"
    end
    if ctype ~= H2_FRAME_CONTINUATION or csid ~= sid then
      return nil, end_stream, "h2_headers_invalid"
    end
    size = size + #cpayload
    if size > H2_MAX_HEADER_BLOCK then
      return nil, end_stream, "h2_headers_too_large"
    end
    parts[#parts + 1] = cpayload
    flags = cflags
  end
  return table.concat(parts), end_stream, nil
end
local h2_reject
h2_reject = function(conn, sid, status)
  local block = hpack.encode({
    {
      ":status",
      status
    }
  })
  local ok_w, w_err = h2_write_frame(conn, H2_FRAME_HEADERS, bit.bor(H2_FLAG_END_HEADERS, H2_FLAG_END_STREAM), sid, block)
  if not (ok_w) then
    return nil, w_err
  end
  return nil, "h2_status_" .. tostring(status)
end
local handle_h2
handle_h2 = function(conn, peer_ip, peer_mac, upstream, peer_vlan)
  conn:receive("*l")
  conn:receive("*l")
  local ok_w, w_err = h2_write_frame(conn, H2_FRAME_SETTINGS, 0, 0, "")
  if not (ok_w) then
    return nil, w_err
  end
  local decoder = hpack.new_decoder()
  local stream_id = nil
  local method = nil
  local path = nil
  local accept = nil
  local req_content_type = nil
  local json_mode = false
  local dns_chunks = { }
  local dns_bytes = 0
  local end_stream = false
  for _ = 1, 30 do
    local ftype, flags, sid, payload = h2_read_frame(conn, H2_DEFAULT_MAX_FRAME_SIZE)
    if not ftype then
      if flags == "frame_too_large" then
        h2_goaway(conn, H2_FRAME_SIZE_ERROR)
        return nil, "h2_frame_too_large"
      end
      break
    end
    if ftype == H2_FRAME_SETTINGS and bit.band(flags, H2_FLAG_ACK) == 0 then
      ok_w, w_err = h2_write_frame(conn, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0, "")
      if not (ok_w) then
        return nil, w_err
      end
    elseif ftype == H2_FRAME_HEADERS and not stream_id then
      if sid == 0 then
        h2_goaway(conn, H2_PROTOCOL_ERROR)
        return nil, "h2_protocol_error"
      end
      stream_id = sid
      local block, headers_end_stream, herr = read_header_block(conn, sid, flags, payload)
      if not (block) then
        if herr == "frame_too_large" then
          h2_goaway(conn, H2_FRAME_SIZE_ERROR)
          return nil, "h2_frame_too_large"
        end
        h2_goaway(conn, H2_PROTOCOL_ERROR)
        return nil, herr
      end
      local headers, derr = hpack.decode(decoder, block)
      if not (headers) then
        log_debug(function()
          return {
            action = "h2_hpack_error",
            peer = peer_ip,
            err = derr
          }
        end)
        h2_goaway(conn, H2_COMPRESSION_ERROR)
        return nil, "h2_compression_error"
      end
      method = hpack.header_value(headers, ":method")
      path = hpack.header_value(headers, ":path")
      accept = hpack.header_value(headers, "accept")
      req_content_type = hpack.header_value(headers, "content-type")
      end_stream = headers_end_stream
      if end_stream then
        break
      end
    elseif ftype == H2_FRAME_DATA and sid == stream_id then
      if #payload > 0 then
        dns_bytes = dns_bytes + #payload
        if dns_bytes > H2_MAX_BODY then
          h2_goaway(conn, H2_FRAME_SIZE_ERROR)
          return nil, "h2_data_too_large"
        end
        dns_chunks[#dns_chunks + 1] = payload
      end
      if bit.band(flags, H2_FLAG_END_STREAM) ~= 0 then
        end_stream = true
        break
      end
    elseif ftype == H2_FRAME_PING and bit.band(flags, H2_FLAG_ACK) == 0 then
      ok_w, w_err = h2_write_frame(conn, H2_FRAME_PING, H2_FLAG_ACK, 0, payload)
      if not (ok_w) then
        return nil, w_err
      end
    end
  end
  if not (end_stream and stream_id) then
    h2_goaway(conn, H2_PROTOCOL_ERROR)
    return nil, "h2_incomplete"
  end
  local dns_raw = nil
  if method == "POST" then
    if not (is_doh_path(path)) then
      return h2_reject(conn, stream_id, "404")
    end
    if not (is_dns_message_content_type(req_content_type)) then
      return h2_reject(conn, stream_id, "415")
    end
    dns_raw = table.concat(dns_chunks)
    if not (#dns_raw > 0) then
      return h2_reject(conn, stream_id, "400")
    end
  elseif method == "GET" then
    if not (is_doh_path(path)) then
      return h2_reject(conn, stream_id, "404")
    end
    dns_raw = dns_from_query(path)
    if not (dns_raw and #dns_raw > 0) then
      if dns_raw == nil and accept and accept:match("application/dns%-json") then
        local name = query_param(path, "name")
        local qtype = qtype_from_name(query_param(path, "type"))
        dns_raw = build_dns_query(name, qtype)
        if dns_raw then
          json_mode = true
        end
      end
      if not (dns_raw and #dns_raw > 0) then
        return h2_reject(conn, stream_id, "400")
      end
    end
  else
    return h2_reject(conn, stream_id, "405")
  end
  local resp_raw, q_err = process_query(dns_raw, peer_ip, peer_mac, upstream, peer_vlan)
  if not (resp_raw) then
    log_warn(function()
      return {
        action = "h2_query_error",
        peer = peer_ip,
        err = q_err
      }
    end)
    h2_goaway(conn, 0x2)
    return nil, "h2_query_error"
  end
  local resp_block = nil
  local body = resp_raw
  local content_type = "application/dns-message"
  if json_mode then
    body = dns_response_json(resp_raw)
    body = body or "{\"Status\":2}"
    content_type = "application/dns-json"
  end
  resp_block = h2_encode_response_headers(content_type)
  ok_w, w_err = h2_write_frame(conn, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, stream_id, resp_block)
  if not (ok_w) then
    return nil, w_err
  end
  ok_w, w_err = h2_write_frame(conn, H2_FRAME_DATA, H2_FLAG_END_STREAM, stream_id, body)
  if not (ok_w) then
    return nil, w_err
  end
  h2_goaway(conn, 0x0)
  return resp_raw
end
local handle_doh_client
handle_doh_client = function(args)
  local client = args.client
  local state = args.state
  local peer_ip = args.peer_ip or "unknown"
  local ok, err = pcall(function()
    local local_ip = client:getsockname() or "custos-doh"
    local tls_ctx = nil
    if state.static_cert_paths then
      local ctx, ctx_err = load_static(state.static_cert_paths.key, state.static_cert_paths.cert)
      if ctx then
        tls_ctx = ctx
      else
        log_error(function()
          return {
            action = "static_cert_child_failed",
            err = ctx_err
          }
        end)
        error("Cannot load static cert: " .. tostring(ctx_err))
      end
    else
      local ok_c, ctx_or_err = pcall(function()
        return load_or_generate_sni(local_ip, state.cert_cache)
      end)
      if not (ok_c) then
        log_error(function()
          return {
            action = "cert_gen_failed",
            local_ip = local_ip,
            err = ctx_or_err
          }
        end)
        error("Cannot generate cert: " .. tostring(ctx_or_err))
      end
      tls_ctx = ctx_or_err
    end
    if not (tls_ctx) then
      local cert_type
      if state.static_cert_paths then
        cert_type = "static"
      else
        cert_type = "sni"
      end
      log_error(function()
        return {
          action = "cert_null",
          local_ip = local_ip,
          cert_type = cert_type
        }
      end)
      error("Certificate context is nil")
    end
    tls_ctx.alpn_protocols = ssl.ALPN_PROTOCOLS
    client:settimeout(nil)
    local client_timeout = (state.client_timeout and tonumber(state.client_timeout)) or 15
    apply_io_timeouts(client, client_timeout)
    local tls_client, tls_err = ssl.wrap(client, tls_ctx)
    if not (tls_client) then
      log_warn(function()
        return {
          action = "tls_wrap_failed",
          peer = peer_ip,
          err = tls_err
        }
      end)
      client:close()
      return 
    end
    local done = false
    local attempts = 0
    local hs_err = nil
    local handshake_deadline = os.time() + client_timeout
    while handshake_should_continue(done, attempts, os.time(), handshake_deadline) do
      attempts = attempts + 1
      local ok_hs, hs_ret, hs_ret2 = pcall(function()
        return tls_client:dohandshake()
      end)
      if not ok_hs then
        hs_err = tostring(hs_ret)
        log_warn(function()
          return {
            action = "handshake_error",
            peer = peer_ip,
            attempts = attempts,
            err = hs_err
          }
        end)
        break
      end
      if hs_ret then
        done = true
      elseif hs_ret2 then
        hs_err = hs_ret2
        break
      end
    end
    if not (done) then
      log_warn(function()
        return {
          action = "handshake_failed",
          peer = peer_ip,
          attempts = attempts,
          err = hs_err or "max_attempts"
        }
      end)
      tls_client:close()
      return 
    end
    local selected_alpn
    if tls_client.selected_alpn then
      selected_alpn = tls_client:selected_alpn()
    else
      selected_alpn = nil
    end
    log_debug(function()
      return {
        action = "tls_handshake_ok",
        peer = peer_ip,
        attempts = attempts,
        alpn = selected_alpn or "none"
      }
    end)
    local peer_mac = get_mac(peer_ip)
    local peer_vlan = get_vlan(peer_ip)
    log_debug(function()
      return {
        action = "mac_lookup",
        peer = peer_ip,
        mac = peer_mac or "unknown",
        vlan = peer_vlan or "unknown"
      }
    end)
    local req, req_err = read_request(tls_client, {
      timeout = client_timeout,
      max_body = 65535
    })
    if not (req) then
      log_warn(function()
        return {
          action = "request_read_failed",
          peer = peer_ip,
          err = req_err
        }
      end)
      if req_err == "body_too_large" then
        send_response(tls_client, 413, { }, "Payload Too Large")
      end
      tls_client:close()
      return 
    end
    log_debug(function()
      return {
        action = "request",
        peer = peer_ip,
        method = req.method,
        path = req.path
      }
    end)
    if req.method == "PRI" then
      log_debug(function()
        return {
          action = "h2_request",
          peer = peer_ip
        }
      end)
      local h2_resp, h2_err = handle_h2(tls_client, peer_ip, peer_mac, state.upstream, peer_vlan)
      if h2_err then
        if h2_err:match("^h2_status_") then
          log_debug(function()
            return {
              action = "h2_rejected",
              peer = peer_ip,
              err = h2_err
            }
          end)
        else
          log_warn(function()
            return {
              action = "h2_failed",
              peer = peer_ip,
              err = h2_err
            }
          end)
        end
      else
        log_debug(function()
          return {
            action = "h2_ok",
            peer = peer_ip,
            resp_bytes = h2_resp and #h2_resp or 0
          }
        end)
      end
      tls_client:close()
      return 
    end
    local dns_raw = nil
    local json_mode = false
    if is_doh_path(req.path) then
      local ct = req.headers["content-type"] or ""
      local accept = req.headers["accept"] or ""
      if req.method == "POST" and is_dns_message_content_type(ct) then
        log_debug(function()
          return {
            action = "post",
            peer = peer_ip,
            body_bytes = #req.body
          }
        end)
        dns_raw = req.body
      elseif req.method == "GET" then
        dns_raw = dns_from_query(req.path)
        if dns_raw then
          log_debug(function()
            return {
              action = "get",
              peer = peer_ip,
              decoded_bytes = #dns_raw
            }
          end)
        elseif accept:match("application/dns%-json") then
          local name = query_param(req.path, "name")
          local qtype = qtype_from_name(query_param(req.path, "type"))
          dns_raw = build_dns_query(name, qtype)
          if dns_raw then
            json_mode = true
          end
          log_debug(function()
            return {
              action = "get_json",
              peer = peer_ip,
              name = name or "",
              qtype = qtype,
              query_bytes = dns_raw and #dns_raw or 0
            }
          end)
        else
          log_debug(function()
            return {
              action = "get_no_param",
              peer = peer_ip,
              path = req.path
            }
          end)
        end
      else
        log_debug(function()
          return {
            action = "unsupported_method",
            peer = peer_ip,
            method = req.method,
            ct = ct
          }
        end)
        send_response(tls_client, 415, { }, "Unsupported Media Type")
        tls_client:close()
        return 
      end
    else
      log_debug(function()
        return {
          action = "unknown_path",
          peer = peer_ip,
          path = req.path
        }
      end)
    end
    if not (dns_raw and #dns_raw > 0) then
      log_debug(function()
        return {
          action = "bad_request",
          peer = peer_ip,
          path = req.path
        }
      end)
      send_response(tls_client, 400, { }, "Bad Request")
      tls_client:close()
      return 
    end
    local resp_raw, q_err = process_query(dns_raw, peer_ip, peer_mac, state.upstream, peer_vlan)
    if resp_raw then
      log_debug(function()
        return {
          action = "response_ok",
          peer = peer_ip,
          resp_bytes = #resp_raw
        }
      end)
      if json_mode then
        local json = dns_response_json(resp_raw)
        send_response(tls_client, 200, {
          ["Content-Type"] = "application/dns-json"
        }, json or "{\"Status\":2}")
      else
        send_response(tls_client, 200, {
          ["Content-Type"] = "application/dns-message"
        }, resp_raw)
      end
    else
      log_warn(function()
        return {
          action = "query_error",
          peer = peer_ip,
          err = q_err
        }
      end)
      send_response(tls_client, 502, { }, "Bad Gateway")
    end
    return tls_client:close()
  end)
  if not (ok) then
    log_error(function()
      return {
        action = "conn_failed",
        peer = peer_ip,
        err = tostring(err)
      }
    end)
    return pcall(function()
      return client:close()
    end)
  end
end
local run
run = function(doh_cfg, filter_data)
  set_action_prefix("doh_")
  local nft_q = require("nft_queue")
  if doh_cfg.nft_wfd then
    nft_q.set_wfd(doh_cfg.nft_wfd)
  end
  if doh_cfg.ack_rfd and doh_cfg.worker_idx ~= nil then
    nft_q.set_ack_rfd(doh_cfg.ack_rfd, doh_cfg.worker_idx)
  end
  if filter_data then
    local filter = require("filter")
    filter.rules = filter_data.rules
    filter.auth_cfg_cache = filter_data.auth_cfg_cache
    filter.decision_cfg = filter_data.decision_cfg
    local set_wildcard_rules, set_captive
    do
      local _obj_0 = require("doh.query")
      set_wildcard_rules, set_captive = _obj_0.set_wildcard_rules, _obj_0.set_captive
    end
    set_wildcard_rules(filter_data.rules and filter_data.rules.rules_metadata)
    local detect, domain_from_url
    do
      local _obj_0 = require("captive_ips")
      detect, domain_from_url = _obj_0.detect, _obj_0.domain_from_url
    end
    local auth = filter.get_auth_cfg()
    local cap_domain = domain_from_url(auth.redirect_url)
    local cap_ip4, cap_ip6 = detect(auth)
    set_captive(cap_domain, cap_ip4, cap_ip6)
  end
  if not (doh_cfg.enabled) then
    log_info(function()
      return {
        action = "worker_disabled"
      }
    end)
    return 
  end
  local port = doh_cfg.port
  local upstream_ip = doh_cfg.upstream_ip
  local upstream_port = doh_cfg.upstream_port
  local timeout_ms = doh_cfg.timeout_ms
  log_info(function()
    return {
      action = "worker_start",
      port = port,
      upstream_ip = upstream_ip,
      upstream_port = upstream_port
    }
  end)
  local cert_cache_mod = require("auth.cert_cache")
  local cert_cache = cert_cache_mod.create_cache(500, 7776000, (doh_cfg.cert_dir or cert_cache_mod.DEFAULT_CERT_DIR))
  local static_cert_paths = nil
  if doh_cfg.cert and doh_cfg.key then
    log_info(function()
      return {
        action = "loading_static_cert",
        cert = doh_cfg.cert
      }
    end)
    local ok, ctx = load_static(doh_cfg.key, doh_cfg.cert)
    if ok then
      static_cert_paths = {
        cert = doh_cfg.cert,
        key = doh_cfg.key
      }
      log_info(function()
        return {
          action = "static_cert_loaded"
        }
      end)
    else
      log_warn(function()
        return {
          action = "static_cert_load_failed",
          cert = doh_cfg.cert,
          key = doh_cfg.key,
          err = ctx
        }
      end)
    end
  end
  local listen4, err4 = make_server4(port)
  if not (listen4) then
    error("DoH: cannot bind port " .. tostring(port) .. ": " .. tostring(err4))
  end
  local listen6 = make_server6(port)
  local all_servers = {
    listen4
  }
  if listen6 then
    all_servers[#all_servers + 1] = listen6
  end
  log_info(function()
    return {
      action = "server_listening",
      port = port,
      ipv4 = "0.0.0.0",
      ipv6 = listen6 and "::" or nil
    }
  end)
  local make_upstream = nil
  local close_upstream = nil
  if doh_cfg.upstream_doh_url then
    local desc, sel_err = upstream_select.select({
      url = doh_cfg.upstream_doh_url,
      timeout_ms = timeout_ms,
      verify_tls = doh_cfg.upstream_doh_tls_verify ~= false,
      fallback_insecure = doh_cfg.upstream_fallback_insecure == true,
      ca_file = doh_cfg.upstream_fallback_ca_file,
      role = "upstream"
    })
    if desc then
      make_upstream = function()
        return desc.make_client(doh_cfg.upstream_doh_url, timeout_ms, desc.verify_tls)
      end
      close_upstream = desc.close
    else
      log_warn(function()
        return {
          action = "upstream_doh_unavailable_udp",
          err = sel_err,
          detail = "aucun transport DoH amont : repli UDP/53"
        }
      end)
    end
  end
  if not (make_upstream) then
    make_upstream = function()
      return upstream_mod.new_client(upstream_ip, upstream_port, timeout_ms)
    end
    close_upstream = upstream_mod.close
  end
  local state = {
    cert_cache = cert_cache,
    static_cert_paths = static_cert_paths,
    make_upstream = make_upstream,
    close_upstream = close_upstream,
    client_timeout = doh_cfg.client_timeout,
    upstream = nil
  }
  while true do
    while true do
      local dead_pid = reap_one()
      if not (dead_pid and dead_pid > 0) then
        break
      end
    end
    local readable, _ = socket.select(all_servers, nil, 0.1)
    if readable then
      for _index_0 = 1, #readable do
        local srv = readable[_index_0]
        local client = srv:accept()
        if client then
          local peer_ip = client:getpeername() or "unknown"
          local conn_state = {
            cert_cache = state.cert_cache,
            static_cert_paths = state.static_cert_paths,
            make_upstream = state.make_upstream,
            close_upstream = state.close_upstream,
            client_timeout = state.client_timeout
          }
          local conn_arg = {
            client = client,
            peer_ip = peer_ip,
            state = conn_state
          }
          local child_fn
          child_fn = function(args)
            local up, up_err = args.state.make_upstream()
            if not (up) then
              log_warn(function()
                return {
                  action = "upstream_open_failed",
                  peer = args.peer_ip,
                  err = up_err
                }
              end)
              args.client:close()
              return 
            end
            args.state.upstream = up
            handle_doh_client(args)
            return args.state.close_upstream(up)
          end
          local pid = fork_child("DOH-conn", child_fn, conn_arg, {
            log_start = false
          })
          log_debug(function()
            return {
              action = "conn_started",
              pid = pid,
              peer = peer_ip
            }
          end)
          client:close()
        end
      end
    end
  end
end
return {
  run = run,
  b64url_decode = b64url_decode,
  query_param = query_param,
  build_dns_query = build_dns_query,
  handshake_should_continue = handshake_should_continue,
  handle_h2 = handle_h2,
  url_decode = url_decode,
  encode_qname = encode_qname,
  qtype_from_name = qtype_from_name,
  json_escape = json_escape,
  json_quote = json_quote,
  rr_data_json = rr_data_json,
  dns_response_json = dns_response_json,
  handle_doh_client = handle_doh_client
}
