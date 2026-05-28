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
local read_request, send_response
do
  local _obj_0 = require("lib.http")
  read_request, send_response = _obj_0.read_request, _obj_0.send_response
end
local get_mac
get_mac = require("mac_learner_ipc").get_mac
local process_query
process_query = require("doh.query").process_query
local parse, types, rcodes
do
  local _obj_0 = require("ipparse.l7.dns")
  parse, types, rcodes = _obj_0.parse, _obj_0.types, _obj_0.rcodes
end
local upstream_mod = require("doh.upstream")
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
  s = s:gsub("%-", ("-"):gsub("_", "_"))
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
    "\"Status\":" .. tostring(dns.header.rcode or 0),
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
local H2_FRAME_DATA = 0x0
local H2_FRAME_HEADERS = 0x1
local H2_FRAME_SETTINGS = 0x4
local H2_FRAME_PING = 0x6
local H2_FRAME_GOAWAY = 0x7
local H2_FRAME_WINDOW_UPDATE = 0x8
local H2_FLAG_END_STREAM = 0x1
local H2_FLAG_END_HEADERS = 0x4
local H2_FLAG_ACK = 0x1
local h2_recv_exact
h2_recv_exact = function(conn, n)
  local buf = ""
  while #buf < n do
    local chunk, err = conn:receive(n - #buf)
    if not (chunk and #chunk > 0) then
      return nil, err
    end
    buf = buf .. chunk
  end
  return buf
end
local h2_read_frame
h2_read_frame = function(conn)
  local hdr, err = h2_recv_exact(conn, 9)
  if not (hdr) then
    return nil, err
  end
  local len = hdr:byte(1) * 65536 + hdr:byte(2) * 256 + hdr:byte(3)
  local ftype = hdr:byte(4)
  local flags = hdr:byte(5)
  local sid = bit.band(bit.bor(bit.lshift(hdr:byte(6), 24), bit.lshift(hdr:byte(7), 16), bit.lshift(hdr:byte(8), 8), hdr:byte(9)), 0x7FFFFFFF)
  local payload
  if len > 0 then
    local p, perr = h2_recv_exact(conn, len)
    if not (p) then
      return nil, perr
    end
    payload = p
  else
    payload = ""
  end
  return ftype, flags, sid, payload
end
local h2_write_frame
h2_write_frame = function(conn, ftype, flags, sid, payload)
  payload = payload or ""
  local n = #payload
  local frame = string.char(bit.band(bit.rshift(n, 16), 0xFF), bit.band(bit.rshift(n, 8), 0xFF), bit.band(n, 0xFF), ftype, flags, bit.band(bit.rshift(sid, 24), 0xFF), bit.band(bit.rshift(sid, 16), 0xFF), bit.band(bit.rshift(sid, 8), 0xFF), bit.band(sid, 0xFF)) .. payload
  return conn:send(frame)
end
local h2_encode_response_headers
h2_encode_response_headers = function()
  return "\x88\x5f\x17application/dns-message"
end
local handle_h2
handle_h2 = function(conn, peer_ip, peer_mac, upstream)
  conn:receive("*l")
  conn:receive("*l")
  h2_write_frame(conn, H2_FRAME_SETTINGS, 0, 0, "")
  local stream_id = nil
  local dns_chunks = { }
  local done = false
  for _ = 1, 30 do
    local ftype, flags, sid, payload = h2_read_frame(conn)
    if not (ftype) then
      break
    end
    if ftype == H2_FRAME_SETTINGS and bit.band(flags, H2_FLAG_ACK) == 0 then
      h2_write_frame(conn, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0, "")
    elseif ftype == H2_FRAME_HEADERS and not stream_id then
      stream_id = sid
    elseif ftype == H2_FRAME_DATA and sid == stream_id then
      if #payload > 0 then
        dns_chunks[#dns_chunks + 1] = payload
      end
      if bit.band(flags, H2_FLAG_END_STREAM) ~= 0 then
        done = true
        break
      end
    elseif ftype == H2_FRAME_PING and bit.band(flags, H2_FLAG_ACK) == 0 then
      h2_write_frame(conn, H2_FRAME_PING, H2_FLAG_ACK, 0, payload)
    end
  end
  if not (done and stream_id) then
    h2_write_frame(conn, H2_FRAME_GOAWAY, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x01")
    return nil, "h2_incomplete"
  end
  local dns_raw = table.concat(dns_chunks)
  if not (#dns_raw > 0) then
    h2_write_frame(conn, H2_FRAME_GOAWAY, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x01")
    return nil, "h2_empty_body"
  end
  local resp_raw, q_err = process_query(dns_raw, peer_ip, peer_mac, upstream)
  if not (resp_raw) then
    log_warn(function()
      return {
        action = "h2_query_error",
        peer = peer_ip,
        err = q_err
      }
    end)
    h2_write_frame(conn, H2_FRAME_GOAWAY, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x02")
    return nil, "h2_query_error"
  end
  local hpack = h2_encode_response_headers()
  h2_write_frame(conn, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, stream_id, hpack)
  h2_write_frame(conn, H2_FRAME_DATA, H2_FLAG_END_STREAM, stream_id, resp_raw)
  h2_write_frame(conn, H2_FRAME_GOAWAY, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x00")
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
    client:settimeout(nil)
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
    while not done and attempts < 50 do
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
    if selected_alpn == "h2" then
      log_warn(function()
        return {
          action = "http2_not_supported",
          peer = peer_ip
        }
      end)
      tls_client:close()
      return 
    end
    local peer_mac = get_mac(peer_ip)
    log_debug(function()
      return {
        action = "mac_lookup",
        peer = peer_ip,
        mac = peer_mac or "unknown"
      }
    end)
    local req, req_err = read_request(tls_client)
    if not (req) then
      log_warn(function()
        return {
          action = "request_read_failed",
          peer = peer_ip,
          err = req_err
        }
      end)
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
      local h2_resp, h2_err = handle_h2(tls_client, peer_ip, peer_mac, state.upstream)
      if h2_err then
        log_warn(function()
          return {
            action = "h2_failed",
            peer = peer_ip,
            err = h2_err
          }
        end)
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
    if req.path == "/dns-query" or req.path:match("^/dns%-query%?") then
      local ct = req.headers["content-type"] or ""
      local accept = req.headers["accept"] or ""
      if req.method == "POST" and ct:match("application/dns%-message") then
        log_debug(function()
          return {
            action = "post",
            peer = peer_ip,
            body_bytes = #req.body
          }
        end)
        dns_raw = req.body
      elseif req.method == "GET" then
        local dns_param = req.path:match("[?&]dns=([^&]+)")
        if dns_param then
          dns_raw = b64url_decode(dns_param)
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
    local resp_raw, q_err = process_query(dns_raw, peer_ip, peer_mac, state.upstream)
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
  local cert_cache = cert_cache_mod.create_cache(500, 7776000)
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
  local state = {
    cert_cache = cert_cache,
    static_cert_paths = static_cert_paths,
    upstream_ip = upstream_ip,
    upstream_port = upstream_port,
    timeout_ms = timeout_ms,
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
            upstream_ip = upstream_ip,
            upstream_port = upstream_port,
            timeout_ms = timeout_ms
          }
          local conn_arg = {
            client = client,
            peer_ip = peer_ip,
            state = conn_state
          }
          local child_fn
          child_fn = function(args)
            local up, up_err = upstream_mod.new_client(args.state.upstream_ip, args.state.upstream_port, args.state.timeout_ms)
            if not (up) then
              log_warn(function()
                return {
                  action = "upstream_socket_failed",
                  peer = args.peer_ip,
                  upstream_ip = args.state.upstream_ip,
                  upstream_port = args.state.upstream_port,
                  err = up_err
                }
              end)
              args.client:close()
              return 
            end
            args.state.upstream = up
            handle_doh_client(args)
            return upstream_mod.close(up)
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
  build_dns_query = build_dns_query
}
