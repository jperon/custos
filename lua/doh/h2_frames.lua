local bit = require("bit")
local send_all
send_all = require("lib.http").send_all
local H2_FRAME_DATA = 0x0
local H2_FRAME_HEADERS = 0x1
local H2_FRAME_RST_STREAM = 0x3
local H2_FRAME_SETTINGS = 0x4
local H2_FRAME_PING = 0x6
local H2_FRAME_GOAWAY = 0x7
local H2_FRAME_WINDOW_UPDATE = 0x8
local H2_FRAME_CONTINUATION = 0x9
local H2_FLAG_END_STREAM = 0x1
local H2_FLAG_END_HEADERS = 0x4
local H2_FLAG_ACK = 0x1
local H2_FLAG_PADDED = 0x8
local H2_FLAG_PRIORITY = 0x20
local H2_DEFAULT_MAX_FRAME_SIZE = 16384
local h2_recv_exact
h2_recv_exact = function(conn, n)
  local chunks = { }
  local got = 0
  while got < n do
    local chunk, err = nil, nil
    for _ = 1, 50 do
      chunk, err = conn:receive(n - got)
      if chunk then
        break
      end
      if err ~= "want_read_write" then
        break
      end
    end
    if not (chunk and #chunk > 0) then
      return nil, err
    end
    chunks[#chunks + 1] = chunk
    got = got + #chunk
  end
  return table.concat(chunks)
end
local h2_read_frame
h2_read_frame = function(conn, max_frame_size)
  max_frame_size = max_frame_size or H2_DEFAULT_MAX_FRAME_SIZE
  local hdr, err = h2_recv_exact(conn, 9)
  if not (hdr) then
    return nil, err
  end
  local len = hdr:byte(1) * 65536 + hdr:byte(2) * 256 + hdr:byte(3)
  if len > max_frame_size then
    return nil, "frame_too_large"
  end
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
local h2_data_payload
h2_data_payload = function(flags, payload)
  if bit.band(flags, H2_FLAG_PADDED) == 0 then
    return payload, nil
  end
  if #payload < 1 then
    return nil, "h2_data_invalid"
  end
  local pad_len = payload:byte(1)
  if pad_len > #payload - 1 then
    return nil, "h2_data_invalid"
  end
  return payload:sub(2, #payload - pad_len)
end
local h2_read_header_block
h2_read_header_block = function(conn, sid, flags, payload, max_block, max_continuation)
  max_block = max_block or 65535
  max_continuation = max_continuation or 64
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
    if continuations > max_continuation then
      return nil, end_stream, "h2_headers_invalid"
    end
    local ctype, cflags, csid, cpayload = h2_read_frame(conn, H2_DEFAULT_MAX_FRAME_SIZE)
    if not (ctype) then
      return nil, end_stream, "h2_headers_invalid"
    end
    if ctype ~= H2_FRAME_CONTINUATION or csid ~= sid then
      return nil, end_stream, "h2_headers_invalid"
    end
    size = size + #cpayload
    if size > max_block then
      return nil, end_stream, "h2_headers_too_large"
    end
    parts[#parts + 1] = cpayload
    flags = cflags
  end
  return table.concat(parts), end_stream, nil
end
local h2_write_frame
h2_write_frame = function(conn, ftype, flags, sid, payload)
  payload = payload or ""
  local n = #payload
  local frame = string.char(bit.band(bit.rshift(n, 16), 0xFF), bit.band(bit.rshift(n, 8), 0xFF), bit.band(n, 0xFF), ftype, flags, bit.band(bit.rshift(sid, 24), 0xFF), bit.band(bit.rshift(sid, 16), 0xFF), bit.band(bit.rshift(sid, 8), 0xFF), bit.band(sid, 0xFF)) .. payload
  return send_all(conn, frame)
end
local h2_window_update
h2_window_update = function(conn, sid, increment)
  local n = bit.band(increment, 0x7FFFFFFF)
  local payload = string.char(bit.band(bit.rshift(n, 24), 0xFF), bit.band(bit.rshift(n, 16), 0xFF), bit.band(bit.rshift(n, 8), 0xFF), bit.band(n, 0xFF))
  return h2_write_frame(conn, H2_FRAME_WINDOW_UPDATE, 0, sid, payload)
end
return {
  H2_FRAME_DATA = H2_FRAME_DATA,
  H2_FRAME_HEADERS = H2_FRAME_HEADERS,
  H2_FRAME_RST_STREAM = H2_FRAME_RST_STREAM,
  H2_FRAME_SETTINGS = H2_FRAME_SETTINGS,
  H2_FRAME_PING = H2_FRAME_PING,
  H2_FRAME_GOAWAY = H2_FRAME_GOAWAY,
  H2_FRAME_WINDOW_UPDATE = H2_FRAME_WINDOW_UPDATE,
  H2_FRAME_CONTINUATION = H2_FRAME_CONTINUATION,
  H2_FLAG_END_STREAM = H2_FLAG_END_STREAM,
  H2_FLAG_END_HEADERS = H2_FLAG_END_HEADERS,
  H2_FLAG_ACK = H2_FLAG_ACK,
  H2_FLAG_PADDED = H2_FLAG_PADDED,
  H2_FLAG_PRIORITY = H2_FLAG_PRIORITY,
  H2_DEFAULT_MAX_FRAME_SIZE = H2_DEFAULT_MAX_FRAME_SIZE,
  h2_recv_exact = h2_recv_exact,
  h2_read_frame = h2_read_frame,
  h2_write_frame = h2_write_frame,
  h2_read_header_block = h2_read_header_block,
  h2_data_payload = h2_data_payload,
  h2_window_update = h2_window_update
}
