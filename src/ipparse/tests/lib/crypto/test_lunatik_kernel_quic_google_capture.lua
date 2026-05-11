local su
su = require("ipparse.lib.pack_compat").unpack
local band
band = require("ipparse.lib.bit_compat").band
local eth_mod = require("ipparse.l2.ethernet")
local ip_mod = require("ipparse.l3.ip")
local udp_mod = require("ipparse.l4.udp")
local quic_mod = require("ipparse.l4.quic")
local keys_mod = require("ipparse.l4.quic.v1.keys")
local prot_mod = require("ipparse.l4.quic.v1.protection")
local frames_mod = require("ipparse.l4.quic.frames")
local backend = require("ipparse.lib.crypto.backend.lunatik")
local bin2hex
bin2hex = function(s)
  return s:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end)
end
local tests_passed = 0
local tests_failed = 0
local assert_test
assert_test = function(name, fn)
  local ok, err = pcall(fn)
  if ok then
    tests_passed = tests_passed + 1
    return print("PASS\tlunatik: " .. tostring(name))
  else
    tests_failed = tests_failed + 1
    print("FAIL\tlunatik: " .. tostring(name) .. "\t" .. tostring(err))
    return error(err)
  end
end
local EXPECTED = {
  dst_mac = "f2198cc26bb3",
  src_mac = "f2e9008a2acc",
  src_ip = "3ffa:e7fe:4375:16ed:e28f:4cff:fec8:91fa",
  dst_ip = "2485:ec87:7655:20de:0:0:0:8b",
  udp_spt = 35336,
  udp_dpt = 443,
  sni = "google.com"
}
local reassemble_crypto
reassemble_crypto = function(plaintext)
  local chunks = { }
  for f in frames_mod.iter_frames(plaintext) do
    local _continue_0 = false
    repeat
      if not (f and f.name == "CRYPTO" and f.data) then
        _continue_0 = true
        break
      end
      local base = f.offset or 0
      if not (chunks[base]) then
        chunks[base] = f.data
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  local offsets
  do
    local _accum_0 = { }
    local _len_0 = 1
    for off, _ in pairs(chunks) do
      _accum_0[_len_0] = off
      _len_0 = _len_0 + 1
    end
    offsets = _accum_0
  end
  if #offsets == 0 then
    return ""
  end
  table.sort(offsets)
  local out = { }
  local expected = 0
  for _index_0 = 1, #offsets do
    local _continue_0 = false
    repeat
      local off = offsets[_index_0]
      local chunk = chunks[off]
      local clen = #chunk
      local chunk_end = off + clen - 1
      if chunk_end < expected then
        _continue_0 = true
        break
      end
      if off > expected then
        break
      end
      local start_idx = expected > off and (expected - off + 1) or 1
      out[#out + 1] = chunk:sub(start_idx)
      expected = chunk_end + 1
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return table.concat(out)
end
local sni_from_tls
sni_from_tls = function(tls_data)
  if #tls_data < 5 then
    return nil
  end
  local off = 1
  while off + 3 <= #tls_data do
    local msg_type = su("B", tls_data, off)
    local b_hi = su("B", tls_data, off + 1)
    local b_lo = su(">H", tls_data, off + 2)
    local msg_len = b_hi * 65536 + b_lo
    local body_off = off + 4
    if body_off + msg_len - 1 > #tls_data then
      break
    end
    if msg_type == 0x01 then
      local body = tls_data:sub(body_off, body_off + msg_len - 1)
      local p = 1
      if #body < 39 then
        break
      end
      p = p + 2
      p = p + 32
      local sid_len = su("B", body, p)
      p = p + (1 + sid_len)
      if p + 1 > #body then
        break
      end
      local cs_len = su(">H", body, p)
      p = p + (2 + cs_len)
      if p > #body then
        break
      end
      local comp_len = su("B", body, p)
      p = p + (1 + comp_len)
      if p + 1 > #body then
        break
      end
      local ext_len = su(">H", body, p)
      p = p + 2
      local ext_end = p + ext_len - 1
      if ext_end > #body then
        break
      end
      while p + 3 <= ext_end do
        local ext_type = su(">H", body, p)
        local ext_data_len = su(">H", body, p + 2)
        p = p + 4
        if p + ext_data_len - 1 > ext_end then
          break
        end
        if ext_type == 0x0000 and ext_data_len >= 5 then
          local sn_off = p
          local sn_list_len = su(">H", body, sn_off)
          sn_off = sn_off + 2
          local sn_end = p + ext_data_len - 1
          if sn_off + sn_list_len - 1 <= sn_end then
            while sn_off + 2 <= sn_end do
              local name_type = su("B", body, sn_off)
              local name_len = su(">H", body, sn_off + 1)
              sn_off = sn_off + 3
              if sn_off + name_len - 1 > sn_end then
                break
              end
              if name_type == 0 then
                return body:sub(sn_off, sn_off + name_len - 1)
              end
              sn_off = sn_off + name_len
            end
          end
        end
        p = p + ext_data_len
      end
    end
    off = body_off + msg_len
  end
  return nil
end
local append_crypto_chunks
append_crypto_chunks = function(chunks, plaintext)
  for f in frames_mod.iter_frames(plaintext) do
    local _continue_0 = false
    repeat
      if not (f and f.name == "CRYPTO" and f.data) then
        _continue_0 = true
        break
      end
      local base = f.offset or 0
      local prev = chunks[base]
      if not (prev) then
        chunks[base] = f.data
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
end
local crypto_stream_from_chunks
crypto_stream_from_chunks = function(chunks)
  local offsets
  do
    local _accum_0 = { }
    local _len_0 = 1
    for off, _ in pairs(chunks) do
      _accum_0[_len_0] = off
      _len_0 = _len_0 + 1
    end
    offsets = _accum_0
  end
  if #offsets == 0 then
    return ""
  end
  table.sort(offsets)
  local out = { }
  local expected = 0
  for _index_0 = 1, #offsets do
    local _continue_0 = false
    repeat
      local off = offsets[_index_0]
      local chunk = chunks[off]
      local chunk_end = off + #chunk - 1
      if chunk_end < expected then
        _continue_0 = true
        break
      end
      if off > expected then
        break
      end
      local start_idx = expected > off and (expected - off + 1) or 1
      out[#out + 1] = chunk:sub(start_idx)
      expected = chunk_end + 1
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return table.concat(out)
end
local bruteforce_decrypt_initial
bruteforce_decrypt_initial = function(quic_packet, q_pkt, key, iv, expected_pn)
  local pn_off = q_pkt.pn_off
  local prefix = (pn_off > 2 and quic_packet:sub(2, pn_off - 1) or "")
  local protected_first = string.byte(quic_packet, 1)
  local first_top = band(protected_first, 0xF0)
  local try_full_pn
  try_full_pn = function(first_byte, pn_len, payload_off, full_pn)
    if full_pn < 0 then
      return nil
    end
    local pn_space = 1
    for _ = 1, pn_len do
      pn_space = pn_space * 256
    end
    local truncated = full_pn % pn_space
    local pn_bytes = { }
    local i = pn_len
    while i >= 1 do
      local b = truncated % 256
      pn_bytes[i] = string.char(b)
      truncated = (truncated - b) / 256
      i = i - 1
    end
    local aad = string.char(first_byte) .. prefix .. table.concat(pn_bytes)
    local plaintext, dec_err = prot_mod.decrypt_payload(quic_packet, payload_off, key, iv, full_pn, aad, backend)
    if not (plaintext) then
      return nil
    end
    return {
      plaintext = plaintext,
      pn = full_pn
    }
  end
  local reserved_bits = 0
  while reserved_bits <= 3 do
    local pn_len = 1
    while pn_len <= 4 do
      local first_nibble = reserved_bits * 4 + (pn_len - 1)
      local first_byte = first_top + first_nibble
      local payload_off = pn_off + pn_len
      if payload_off <= #quic_packet then
        local max_delta = pn_len == 1 and 255 or 4096
        local delta = 0
        while delta <= max_delta do
          local fwd = expected_pn + delta
          local dec = try_full_pn(first_byte, pn_len, payload_off, fwd)
          if dec then
            return dec
          end
          if delta > 0 and expected_pn >= delta then
            local back = expected_pn - delta
            dec = try_full_pn(first_byte, pn_len, payload_off, back)
            if dec then
              return dec
            end
          end
          delta = delta + 1
        end
      end
      pn_len = pn_len + 1
    end
    reserved_bits = reserved_bits + 1
  end
  return nil
end
local resolve_capture_path
resolve_capture_path = function()
  local candidates = {
    "/lib/modules/lua/ipparse/quic_google.pcapng",
    "ipparse/quic_google.pcapng",
    "quic_google.pcapng"
  }
  for _index_0 = 1, #candidates do
    local path = candidates[_index_0]
    local f = io.open(path, "rb")
    if f then
      f:close()
      return path
    end
  end
  return error("quic_google.pcapng not found (tried: " .. tostring(table.concat(candidates, ', ')) .. ")")
end
local for_each_epb
for_each_epb = function(capture_path, cb)
  local file = io.open(capture_path, "rb")
  if not (file) then
    error("Could not open file: " .. tostring(capture_path))
  end
  local endian = nil
  local epb_count = 0
  while true do
    local hdr = file:read(8)
    if not (hdr and #hdr == 8) then
      break
    end
    local block_type_le = su("<I4", hdr, 1)
    local block_type_be = su(">I4", hdr, 1)
    local shb = (block_type_le == 0x0A0D0D0A) or (block_type_be == 0x0A0D0D0A)
    if shb then
      local bom_bytes = file:read(4)
      if not (bom_bytes and #bom_bytes == 4) then
        break
      end
      local bom_le = su("<I4", bom_bytes, 1)
      local bom_be = su(">I4", bom_bytes, 1)
      if bom_le == 0x1A2B3C4D then
        endian = "<"
      elseif bom_be == 0x1A2B3C4D then
        endian = ">"
      else
        error("Invalid SHB byte-order magic in " .. tostring(capture_path))
      end
      local block_len = su(tostring(endian) .. "I4", hdr, 5)
      if block_len < 12 then
        break
      end
      local rest = block_len - 12
      if rest > 0 then
        local chunk = file:read(rest)
        if not (chunk and #chunk == rest) then
          break
        end
      end
    else
      if not (endian) then
        error("PCAPNG section header missing before first non-SHB block")
      end
      local block_len = su(tostring(endian) .. "I4", hdr, 5)
      if block_len < 12 then
        break
      end
      local payload_len = block_len - 8
      local payload = file:read(payload_len)
      if not (payload and #payload == payload_len) then
        break
      end
      local block_type = su(tostring(endian) .. "I4", hdr, 1)
      if block_type == 0x00000006 then
        epb_count = epb_count + 1
        local interface_id, timestamp_high, timestamp_low, captured_len, original_len = su(tostring(endian) .. "I4I4I4I4I4", payload, 1)
        local packet_start = 21
        local packet_end = packet_start + captured_len - 1
        if packet_end <= #payload then
          local should_stop = cb(payload, packet_start, packet_end, epb_count)
          if should_stop then
            break
          end
        end
      end
    end
  end
  file:close()
  return epb_count
end
local scan_first_initial
scan_first_initial = function(capture_path)
  local first = nil
  local initial_dcid = nil
  local epb_count = for_each_epb(capture_path, function(payload, packet_start, packet_end, epb_idx)
    local e, l3_off = eth_mod.parse(payload, packet_start)
    if not (e) then
      return false
    end
    local ip_pkt, l4_off = ip_mod.parse(payload, l3_off)
    if not (ip_pkt and ip_pkt.protocol == ip_mod.proto.UDP) then
      return false
    end
    local udp_dgram, l7_off = udp_mod.parse(payload, l4_off)
    if not (udp_dgram) then
      return false
    end
    local q, _ = quic_mod.parse(payload, l7_off)
    if not (q and q.long_header and q.pkt_type == 0x00 and q.dst_connection_id and #q.dst_connection_id > 0) then
      return false
    end
    first = {
      e = e,
      ip_pkt = ip_pkt,
      udp_dgram = udp_dgram,
      q = q,
      epb_idx = epb_idx
    }
    initial_dcid = q.dst_connection_id
    return true
  end)
  assert(first ~= nil, "no QUIC Initial packet found in " .. tostring(capture_path))
  return {
    first = first,
    initial_dcid = initial_dcid,
    epb_count = epb_count
  }
end
local extract_sni
extract_sni = function(capture_path, initial_dcid)
  print("INFO\tlunatik: extract_sni stage=derive_initial_secrets")
  local ok_secret, client_secret, server_secret_or_err = pcall(keys_mod.derive_initial_secrets, initial_dcid)
  assert(ok_secret, "derive_initial_secrets_failed: " .. tostring(server_secret_or_err))
  print("INFO\tlunatik: extract_sni stage=derive_keys")
  local key, iv, _ = keys_mod.derive_keys(client_secret)
  local expected_pn = 0
  local crypto_chunks = { }
  local pushed = 0
  local sni = nil
  for_each_epb(capture_path, function(payload, packet_start, packet_end, epb_idx)
    local e, l3_off = eth_mod.parse(payload, packet_start)
    if not (e) then
      return false
    end
    local ip_pkt, l4_off = ip_mod.parse(payload, l3_off)
    if not (ip_pkt and ip_pkt.protocol == ip_mod.proto.UDP) then
      return false
    end
    local udp_dgram, l7_off = udp_mod.parse(payload, l4_off)
    if not (udp_dgram) then
      return false
    end
    local q
    q, _ = quic_mod.parse(payload, l7_off)
    if not (q and q.long_header and q.pkt_type == 0x00 and q.dst_connection_id and #q.dst_connection_id > 0) then
      return false
    end
    if not (q.dst_connection_id == initial_dcid) then
      return false
    end
    local quic_packet = payload:sub(l7_off, packet_end)
    print("INFO\tlunatik: extract_sni stage=decrypt epb=" .. tostring(epb_idx))
    local q_pkt
    q_pkt, _ = quic_mod.parse(quic_packet, 1)
    assert(q_pkt and q_pkt.pn_off, "invalid QUIC packet for decryption")
    print("INFO\tlunatik: extract_sni parsed_quic packet_len=" .. tostring(#quic_packet) .. " pn_off=" .. tostring(q_pkt.pn_off) .. " pkt_length=" .. tostring(tostring(q_pkt.pkt_length)) .. " expected_pn=" .. tostring(expected_pn))
    if q_pkt.pkt_length and q_pkt.pn_off then
      local logical_end = (q_pkt.pn_off - 1) + q_pkt.pkt_length
      if logical_end > 0 and logical_end < #quic_packet then
        quic_packet = quic_packet:sub(1, logical_end)
        print("INFO\tlunatik: extract_sni trimmed_quic packet_len=" .. tostring(#quic_packet))
      end
    end
    local dec = bruteforce_decrypt_initial(quic_packet, q_pkt, key, iv, expected_pn)
    if not (dec) then
      return false
    end
    local plaintext = dec.plaintext
    if dec.pn >= expected_pn then
      expected_pn = dec.pn + 1
    end
    pushed = pushed + 1
    print("INFO\tlunatik: extract_sni stage=sni_from_plaintext plaintext_len=" .. tostring(#plaintext))
    append_crypto_chunks(crypto_chunks, plaintext)
    local tls_stream = crypto_stream_from_chunks(crypto_chunks)
    sni = sni_from_tls(tls_stream)
    return sni ~= nil
  end)
  assert(pushed > 0, "no client Initial datagrams pushed for selected DCID")
  return {
    pushed = pushed,
    sni = sni
  }
end
local capture_path = resolve_capture_path()
local flow = scan_first_initial(capture_path)
print("INFO\tlunatik: backend=lunatik capture=" .. tostring(capture_path))
print("INFO\tlunatik: epb_blocks_seen=" .. tostring(flow.epb_count) .. " first_initial_epb=" .. tostring(flow.first.epb_idx))
assert_test("Kernel QUIC Google capture parses expected L2/L3/L4 metadata", function()
  local f = flow.first
  assert(bin2hex(f.e.dst) == EXPECTED.dst_mac, "dst mac mismatch: " .. tostring(bin2hex(f.e.dst)))
  assert(bin2hex(f.e.src) == EXPECTED.src_mac, "src mac mismatch: " .. tostring(bin2hex(f.e.src)))
  assert(ip_mod.ip2s(f.ip_pkt.src) == EXPECTED.src_ip, "src ip mismatch: " .. tostring(ip_mod.ip2s(f.ip_pkt.src)))
  assert(ip_mod.ip2s(f.ip_pkt.dst) == EXPECTED.dst_ip, "dst ip mismatch: " .. tostring(ip_mod.ip2s(f.ip_pkt.dst)))
  assert(f.udp_dgram.spt == EXPECTED.udp_spt, "udp source port mismatch: " .. tostring(f.udp_dgram.spt))
  assert(f.udp_dgram.dpt == EXPECTED.udp_dpt, "udp destination port mismatch: " .. tostring(f.udp_dgram.dpt))
  assert(f.q.long_header == true, "expected QUIC long header")
  assert(f.q.pkt_type == 0x00, "expected QUIC Initial packet")
  print("INFO\tlunatik: L2 src_mac=" .. tostring(bin2hex(f.e.src)) .. " dst_mac=" .. tostring(bin2hex(f.e.dst)))
  print("INFO\tlunatik: L3 src_ip=" .. tostring(ip_mod.ip2s(f.ip_pkt.src)) .. " dst_ip=" .. tostring(ip_mod.ip2s(f.ip_pkt.dst)))
  print("INFO\tlunatik: L4 udp_src=" .. tostring(f.udp_dgram.spt) .. " udp_dst=" .. tostring(f.udp_dgram.dpt))
  return print("INFO\tlunatik: QUIC dcid=" .. tostring(bin2hex(f.q.dst_connection_id)) .. " version=" .. tostring(f.q.version))
end)
assert_test("Kernel QUIC Google capture extracts SNI using lunatik backend", function()
  local sni_flow = extract_sni(capture_path, flow.initial_dcid)
  local extracted_sni = sni_flow.sni
  assert(extracted_sni == EXPECTED.sni, "expected SNI " .. tostring(EXPECTED.sni) .. ", got " .. tostring(tostring(extracted_sni)))
  return print("INFO\tlunatik: pushed_initial_packets=" .. tostring(sni_flow.pushed) .. " expected_sni=" .. tostring(EXPECTED.sni) .. " extracted_sni=" .. tostring(extracted_sni))
end)
return print("  --> lib.crypto.lunatik.kernel.quic_google_capture: " .. tostring(tests_passed) .. "/" .. tostring(tests_passed + tests_failed))
