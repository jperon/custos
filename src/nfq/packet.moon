--- Packet parser using pure LuaJIT FFI pointer arithmetic.
-- Parses L3/L4/L7 headers (IPv4/IPv6, UDP/TCP, DNS).
-- Includes TCP stream reassembly for multi-segment DNS/TCP.
-- @module parse.ndpi

{ :ffi } = require "ffi_defs"
{ :AF_INET, :AF_INET6 } = require "config"
bit = require "bit"

-- ── Constants ──────────────────────────────────────────────────
PROTO_UDP = 17
PROTO_TCP = 6

--- Qtype numeric-to-name mapping.
QTYPE = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15
  TXT: 16, AAAA: 28, SRV: 33, ANY: 255
}
QTYPE_NAME = {}
for k, v in pairs QTYPE
  QTYPE_NAME[v] = k

--- RCODE constants.
RCODE = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5 }

-- ── TCP stream reassembly buffers ──────────────────────────────

-- TCP stream reassembly buffers: "src_ip|src_port|dst_ip|dst_port" → accumulated payload string.
-- Keyed by 4-tuple; cleared on FIN/RST; consumed when a complete DNS message is assembled.
-- Each entry tracks { data: payload, init_seq: uint32, timestamp: os.time() } for garbage collection.
tcp_buffers = {}

--- Purge expired TCP reassembly buffers.
-- Removes entries older than max_age seconds to prevent unbounded memory growth.
-- @tparam number max_age Maximum age in seconds (default: 300).
purge_tcp_buffers = (max_age = 300) ->
  now = os.time()
  for key, entry in pairs tcp_buffers
    if now - entry.timestamp > max_age
      tcp_buffers[key] = nil

-- ── Pre-allocated buffers ──────────────────────────────────────

ipv6_str = ffi.new "char[46]"

-- ── Byte-level helpers (0-based FFI pointer, big-endian) ───────

--- Read big-endian uint16 from FFI pointer at 0-based offset.
-- @tparam cdata p uint8_t pointer.
-- @tparam number o 0-based byte offset.
-- @treturn number uint16 value.
r16 = (p, o) ->
  bit.bor bit.lshift(p[o], 8), p[o + 1]

--- Read big-endian uint32 from FFI pointer at 0-based offset.
-- @tparam cdata p uint8_t pointer.
-- @tparam number o 0-based byte offset.
-- @treturn number uint32 value.
r32 = (p, o) ->
  tonumber ffi.cast "uint32_t",
    bit.bor(
      bit.lshift(p[o],   24),
      bit.lshift(p[o+1], 16),
      bit.lshift(p[o+2],  8),
      p[o+3])

--- Write big-endian uint32 into FFI pointer at 0-based offset.
-- @tparam cdata p Mutable uint8_t pointer.
-- @tparam number o 0-based byte offset.
-- @tparam number v uint32 value to write.
w32 = (p, o, v) ->
  p[o]   = bit.band bit.rshift(v, 24), 0xFF
  p[o+1] = bit.band bit.rshift(v, 16), 0xFF
  p[o+2] = bit.band bit.rshift(v,  8), 0xFF
  p[o+3] = bit.band v, 0xFF

--- Write big-endian uint16 into FFI pointer at 0-based offset.
-- @tparam cdata p Mutable uint8_t pointer.
-- @tparam number o 0-based byte offset.
-- @tparam number v uint16 value to write.
w16 = (p, o, v) ->
  p[o]   = bit.band bit.rshift(v, 8), 0xFF
  p[o+1] = bit.band v, 0xFF

-- ── IP address formatting ──────────────────────────────────────

--- Format 4 bytes starting at ptr+off as dotted-quad IPv4.
-- @tparam cdata p uint8_t pointer.
-- @tparam number o 0-based offset.
-- @treturn string "a.b.c.d".
fmt_ipv4 = (p, o) ->
  string.format "%d.%d.%d.%d", p[o], p[o+1], p[o+2], p[o+3]

--- Format 16 bytes starting at ptr+off as IPv6 string.
-- @tparam cdata p uint8_t pointer.
-- @tparam number o 0-based offset.
-- @treturn string IPv6 address.
fmt_ipv6 = (p, o) ->
  ffi.C.inet_ntop AF_INET6, p + o, ipv6_str, 46
  ffi.string ipv6_str

-- ── DNS name decompression (RFC 1035 §4.1.4) ──────────────────

--- Decode a DNS name with compression-pointer support.
-- @tparam cdata dns uint8_t* to the start of the DNS message.
-- @tparam number len Total DNS message length.
-- @tparam number off 0-based offset of the name.
-- @treturn string|nil Decoded dotted name, or nil on error.
-- @treturn number Bytes consumed in the main (non-jumped) stream.
decode_name = (dns, len, off) ->
  labels   = {}
  pos      = off
  consumed = 0
  jumped   = false
  safety   = 0

  while pos < len
    safety += 1
    return nil, 0 if safety > 128

    label_len = dns[pos]

    if label_len == 0
      consumed += 1 unless jumped
      break

    elseif bit.band(label_len, 0xC0) == 0xC0
      return nil, 0 if pos + 1 >= len
      ptr = bit.bor bit.lshift(bit.band(label_len, 0x3F), 8), dns[pos + 1]
      consumed += 2 unless jumped
      jumped = true
      pos = ptr

    else
      return nil, 0 if pos + 1 + label_len > len
      labels[#labels + 1] = ffi.string dns + pos + 1, label_len
      pos += 1 + label_len
      consumed += 1 + label_len unless jumped

  table.concat(labels, "."), consumed

-- ── L3 parsing ─────────────────────────────────────────────────

--- Parse IPv4 header from an FFI pointer.
-- @tparam cdata p uint8_t* raw packet.
-- @tparam number len Packet length.
-- @treturn table|nil Parsed IP fields.
parse_l3_v4 = (p, len) ->
  return nil if len < 20
  ver = bit.rshift p[0], 4
  return nil if ver != 4
  ihl = bit.band(p[0], 0x0F) * 4
  return nil if len < ihl
  {
    version: 4, :ihl
    total_len: r16(p, 2)
    protocol:  p[9]
    src_ip:     fmt_ipv4 p, 12
    dst_ip:     fmt_ipv4 p, 16
    src_ip_raw: ffi.string p + 12, 4
    dst_ip_raw: ffi.string p + 16, 4
    af: AF_INET
  }

-- IPv6 extension header type → skip formula:
--   true  = standard: (len_field+1)*8 bytes
--   false = AH (RFC 4302): (len_field+2)*4 bytes
-- ESP (50) is intentionally absent: payload is encrypted, L4 unreachable.
IPV6_EXT_HDRS = {
  [0]:   true   -- Hop-by-Hop Options
  [43]:  true   -- Routing
  [44]:  true   -- Fragment
  [51]:  false  -- Authentication Header
  [60]:  true   -- Destination Options
  [135]: true   -- Mobility
  [139]: true   -- HIP
  [140]: true   -- Shim6
}

--- Walk IPv6 extension headers and return the transport protocol + L4 offset.
-- Skips all RFC-known extension headers (Hop-by-Hop, Routing, Fragment, AH,
-- Destination Options, Mobility, HIP, Shim6).  ESP is not skippable (encrypted).
-- @tparam cdata p uint8_t* pointer to start of IPv6 fixed header.
-- @tparam number len Total packet length in bytes.
-- @tparam number first_nh Next Header value from the IPv6 fixed header (p[6]).
-- @treturn number|nil Transport protocol (17=UDP, 6=TCP, …) or nil on error.
-- @treturn number|nil 0-based byte offset of the L4 header, or nil on error.
skip_ipv6_ext_hdrs = (p, len, first_nh) ->
  nh  = first_nh
  off = 40  -- 0-based offset of the current extension header
  while IPV6_EXT_HDRS[nh] != nil
    return nil, nil if off + 2 > len   -- need at least NH + Len bytes
    next_nh  = p[off]
    ext_size = if nh == 51
      (p[off + 1] + 2) * 4            -- AH: (Payload Len + 2) × 4
    else
      (p[off + 1] + 1) * 8            -- standard: (Hdr Ext Len + 1) × 8
    return nil, nil if ext_size < 8 or off + ext_size > len
    off += ext_size
    nh   = next_nh
  nh, off

--- Parse IPv6 fixed header from an FFI pointer, skipping any extension headers.
-- @tparam cdata p uint8_t* raw packet.
-- @tparam number len Packet length.
-- @treturn table|nil Parsed IP fields (ihl = actual L4 offset, including ext headers).
parse_l3_v6 = (p, len) ->
  return nil if len < 40
  ver = bit.rshift p[0], 4
  return nil if ver != 6
  proto, l4_off = skip_ipv6_ext_hdrs p, len, p[6]
  return nil unless proto
  {
    version: 6, ihl: l4_off
    total_len: 40 + r16(p, 4)
    protocol:  proto
    src_ip:     fmt_ipv6 p, 8
    dst_ip:     fmt_ipv6 p, 24
    src_ip_raw: ffi.string p + 8,  16
    dst_ip_raw: ffi.string p + 24, 16
    af: AF_INET6
  }

-- ── Checksum helpers ───────────────────────────────────────────

--- Recalculate IPv4 header checksum in-place.
-- @tparam cdata buf Mutable uint8_t* packet.
-- @tparam number ihl IP header length in bytes.
fix_ip4_cksum = (buf, ihl) ->
  buf[10] = 0
  buf[11] = 0
  sum = 0
  for i = 0, ihl - 1, 2
    sum += bit.bor bit.lshift(buf[i], 8), buf[i + 1]
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  cksum = bit.band bit.bnot(sum), 0xFFFF
  w16 buf, 10, cksum

--- Recalculate UDP checksum in-place (IPv4 pseudo-header, RFC 768).
-- @tparam cdata buf Mutable uint8_t* packet.
-- @tparam number pkt_len Total packet length.
-- @tparam number ihl IP header length in bytes.
fix_udp4_cksum = (buf, pkt_len, ihl) ->
  udp_off = ihl
  return if pkt_len < udp_off + 8
  udp_len = r16 buf, udp_off + 4
  buf[udp_off + 6] = 0
  buf[udp_off + 7] = 0
  sum = 0
  -- IPv4 pseudo-header: src(4) + dst(4).
  for i = 12, 18, 2
    sum += r16 buf, i
  sum += PROTO_UDP
  sum += udp_len
  -- UDP segment.
  udp_end = udp_off + udp_len
  udp_end = pkt_len if udp_end > pkt_len
  cksum_off = udp_off + 6
  i = udp_off
  while i < udp_end
    word = if i == cksum_off
      0
    elseif i + 1 < udp_end
      r16 buf, i
    else
      bit.lshift buf[i], 8
    sum += word
    i += 2
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  cksum = bit.band bit.bnot(sum), 0xFFFF
  cksum = 0xFFFF if cksum == 0
  w16 buf, udp_off + 6, cksum

--- Recalculate UDP checksum in-place (IPv6 pseudo-header, RFC 2460 §8.1).
-- IPv6 has no IP-level checksum; UDP checksum is mandatory.
-- Pseudo-header: src(16B) + dst(16B) + upper-layer length(32b) + next-header(8b).
-- For IPv6 fixed header: src at offset 8, dst at offset 24 (0-based).
-- @tparam cdata buf Mutable uint8_t* packet (IPv6).
-- @tparam number pkt_len Total packet length.
-- @tparam number l4_off 0-based offset of the UDP header (= ihl, includes ext headers).
fix_udp6_cksum = (buf, pkt_len, l4_off) ->
  udp_off = l4_off
  return if pkt_len < udp_off + 8
  udp_len = r16 buf, udp_off + 4
  buf[udp_off + 6] = 0
  buf[udp_off + 7] = 0
  sum = 0
  -- IPv6 pseudo-header: src(16B) at offsets 8–23, dst(16B) at offsets 24–39.
  -- Loop covers both in one pass (16 words = 32 bytes).
  for i = 8, 38, 2
    sum += r16 buf, i
  -- Upper-layer packet length (32-bit): high word = 0, low word = udp_len.
  sum += udp_len
  -- Next header = UDP (17).
  sum += PROTO_UDP
  -- UDP segment.
  udp_end = udp_off + udp_len
  udp_end = pkt_len if udp_end > pkt_len
  cksum_off = udp_off + 6
  i = udp_off
  while i < udp_end
    word = if i == cksum_off
      0
    elseif i + 1 < udp_end
      r16 buf, i
    else
      bit.lshift buf[i], 8
    sum += word
    i += 2
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  cksum = bit.band bit.bnot(sum), 0xFFFF
  cksum = 0xFFFF if cksum == 0
  w16 buf, udp_off + 6, cksum

--- Recalculate TCP checksum in-place (IPv4 pseudo-header, RFC 793).
-- @tparam cdata buf Mutable uint8_t* packet.
-- @tparam number pkt_len Total packet length.
-- @tparam number ihl IP header length in bytes.
fix_tcp4_cksum = (buf, pkt_len, ihl) ->
  tcp_off = ihl
  return if pkt_len < tcp_off + 20
  tcp_len = pkt_len - tcp_off
  buf[tcp_off + 16] = 0
  buf[tcp_off + 17] = 0
  sum = 0
  -- IPv4 pseudo-header: src(4B) at buf[12..15], dst(4B) at buf[16..19].
  for i = 12, 18, 2
    sum += r16 buf, i
  sum += PROTO_TCP
  sum += tcp_len
  -- TCP segment.
  tcp_end = tcp_off + tcp_len
  tcp_end = pkt_len if tcp_end > pkt_len
  cksum_off = tcp_off + 16
  i = tcp_off
  while i < tcp_end
    word = if i == cksum_off
      0
    elseif i + 1 < tcp_end
      r16 buf, i
    else
      bit.lshift buf[i], 8
    sum += word
    i += 2
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  cksum = bit.band bit.bnot(sum), 0xFFFF
  cksum = 0xFFFF if cksum == 0
  w16 buf, tcp_off + 16, cksum

--- Recalculate TCP checksum in-place (IPv6 pseudo-header, RFC 2460 §8.1).
-- @tparam cdata buf Mutable uint8_t* packet (IPv6).
-- @tparam number pkt_len Total packet length.
-- @tparam number l4_off 0-based offset of the TCP header (= ihl, includes ext headers).
fix_tcp6_cksum = (buf, pkt_len, l4_off) ->
  tcp_off = l4_off
  return if pkt_len < tcp_off + 20
  tcp_len = pkt_len - tcp_off
  buf[tcp_off + 16] = 0
  buf[tcp_off + 17] = 0
  sum = 0
  -- IPv6 pseudo-header: src(16B) at offsets 8–23, dst(16B) at offsets 24–39.
  for i = 8, 38, 2
    sum += r16 buf, i
  sum += tcp_len
  sum += PROTO_TCP
  -- TCP segment.
  tcp_end = tcp_off + tcp_len
  tcp_end = pkt_len if tcp_end > pkt_len
  cksum_off = tcp_off + 16
  i = tcp_off
  while i < tcp_end
    word = if i == cksum_off
      0
    elseif i + 1 < tcp_end
      r16 buf, i
    else
      bit.lshift buf[i], 8
    sum += word
    i += 2
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  cksum = bit.band bit.bnot(sum), 0xFFFF
  cksum = 0xFFFF if cksum == 0
  w16 buf, tcp_off + 16, cksum

-- ── Public API ─────────────────────────────────────────────────

--- Parse a raw IP packet (L3 + L4 + L7) in a single call.
-- In the nftables bridge table, nfq_get_payload() delivers the packet
-- starting at the IP header (no Ethernet). The optional eth_offset
-- parameter is kept for synthetic test fixtures that prepend an L2 header.
-- @tparam string raw Raw packet (Lua string from nfq_get_payload).
-- @tparam[opt] number eth_offset Byte offset to IP header (default 0).
-- @treturn table|nil Parsed packet info, or nil on error.
-- @treturn string|nil Parse status ("buffering", "tcp_control") on nil return.
parse_packet = (raw, eth_offset = 0) ->
  len = #raw
  return nil if len < eth_offset + 20
  p_base = ffi.cast "const uint8_t*", raw
  p = p_base + eth_offset
  len = len - eth_offset

  -- L3
  ver = bit.rshift p[0], 4
  ip = if ver == 4
    parse_l3_v4 p, len
  elseif ver == 6
    parse_l3_v6 p, len
  return nil unless ip

  -- L4
  proto = ip.protocol
  l4 = nil
  if proto == PROTO_UDP
    udp_off = ip.ihl
    return nil if len < udp_off + 8
    l4 = {
      src_port:    r16 p, udp_off
      dst_port:    r16 p, udp_off + 2
      len:          r16 p, udp_off + 4
      off:         udp_off + 8
      payload_len: len - udp_off - 8
      proto:       "udp"
    }
  elseif proto == PROTO_TCP
    tcp_off = ip.ihl
    return nil if len < tcp_off + 20
    data_off = tcp_off + (bit.rshift(p[tcp_off + 12], 4) * 4)
    return nil if len < data_off
    tcp_payload_len = len - data_off
    l4 = {
      src_port:    r16 p, tcp_off
      dst_port:    r16 p, tcp_off + 2
      len:         tcp_payload_len
      off:         data_off
      payload_len: tcp_payload_len
      proto:       "tcp"
    }
    -- Accumulate TCP payload for DNS stream reassembly.
    -- Buffer key: "src_ip|src_port|dst_ip|dst_port".
    bk_tcp = "#{ip.src_ip}|#{l4.src_port}|#{ip.dst_ip}|#{l4.dst_port}"
    -- Clear buffer on FIN (0x01) or RST (0x04).
    if bit.band(p[tcp_off + 13], 0x05) != 0
      tcp_buffers[bk_tcp] = nil
    -- Append this segment's payload data to the reassembly buffer.
    if tcp_payload_len > 0
      seg   = ffi.string p + data_off, tcp_payload_len
      entry = tcp_buffers[bk_tcp]
      if entry
        entry.data = entry.data .. seg
      else
        tcp_buffers[bk_tcp] = { data: seg, init_seq: r32(p, tcp_off + 4), timestamp: os.time() }
  else
    return nil

  -- L7 — DNS header (12 bytes minimum).
  -- For TCP: read from the reassembly buffer (handles multi-segment streams).
  -- For UDP: read directly from the raw packet.
  dns_p        = nil
  dns_len      = 0
  dns_raw_ref  = nil  -- GC anchor for the TCP reassembly Lua string
  dns_single   = true -- false when DNS assembled from multiple TCP segments
  tcp_init_seq = nil  -- seq of the first TCP segment in the DNS stream
  if l4.proto == "tcp"
    bk    = "#{ip.src_ip}|#{l4.src_port}|#{ip.dst_ip}|#{l4.dst_port}"
    entry = tcp_buffers[bk]
    buf     = (entry and entry.data) or ""
    buf_len = #buf
    -- Wait until we have the 2-byte TCP DNS length prefix.
    -- For TCP control packets (SYN-ACK, pure ACK, FIN) with no payload,
    -- return nil without "buffering" so workers pass them through unchanged.
    if buf_len < 2
      return nil, "buffering" if l4.payload_len > 0
      return nil, "tcp_control"
    dns_msg_len = bit.bor bit.lshift(buf\byte(1), 8), buf\byte(2)
    -- Wait until the complete DNS message is in the buffer.
    if buf_len < 2 + dns_msg_len
      return nil, "buffering" if l4.payload_len > 0
      return nil, "tcp_control"
    -- Complete message assembled; consume it from the buffer.
    dns_raw_ref = buf\sub 3, 2 + dns_msg_len
    if buf_len > 2 + dns_msg_len
      entry.data = buf\sub 2 + dns_msg_len + 1
    else
      tcp_buffers[bk] = nil
    dns_p        = ffi.cast "const uint8_t*", dns_raw_ref
    dns_len      = dns_msg_len
    dns_single   = (l4.payload_len == 2 + dns_msg_len)
    tcp_init_seq = entry and entry.init_seq or nil
  else
    dns_p   = p + l4.off
    dns_len = l4.payload_len

  return nil if dns_len < 12
  flags_hi = dns_p[2]
  flags_lo = dns_p[3]
  dns = {
    txid:        r16 dns_p, 0
    is_response: bit.band(flags_hi, 0x80) != 0
    opcode:      bit.band(bit.rshift(flags_hi, 3), 0x0F)
    aa:          bit.band(flags_hi, 0x04) != 0
    tc:          bit.band(flags_hi, 0x02) != 0
    rd:          bit.band(flags_hi, 0x01) != 0
    ra:          bit.band(flags_lo, 0x80) != 0
    rcode:       bit.band(flags_lo, 0x0F)
    qdcount:     r16 dns_p, 4
    ancount:     r16 dns_p, 6
    nscount:     r16 dns_p, 8
    arcount:     r16 dns_p, 10
  }

  -- DNS questions.
  questions = {}
  qpos = 12
  for _ = 1, dns.qdcount
    break if qpos >= dns_len
    qname, consumed = decode_name dns_p, dns_len, qpos
    break unless qname
    qpos += consumed
    break if qpos + 4 > dns_len
    qtype  = r16 dns_p, qpos
    qclass = r16 dns_p, qpos + 2
    qpos += 4
    questions[#questions + 1] = {
      :qname, :qtype, :qclass
      qtype_name: QTYPE_NAME[qtype] or "TYPE#{qtype}"
    }

  answers_off = qpos

  {
    ip: ip, l4: l4, dns: dns, questions: questions
    answers_off: answers_off
    tcp_dns_raw:        dns_raw_ref  -- reassembled DNS payload (TCP only, nil for UDP)
    tcp_single_segment: dns_single   -- true iff DNS arrived in a single TCP segment
    tcp_init_seq:       tcp_init_seq -- seq of first segment; used for coalesced reinject
  }


--- Parse DNS answer RRs from a raw IP packet.
-- @tparam string raw Raw IP packet.
-- @tparam table pkt Result from parse_packet.
-- @treturn table Array of parsed answer records.
parse_answers = (raw, pkt) ->
  return {} unless pkt.dns.is_response and pkt.dns.ancount > 0
  -- Use the reassembled TCP DNS payload when available (handles multi-segment streams).
  dns_p   = nil
  dns_len = 0
  if pkt.tcp_dns_raw
    dns_p   = ffi.cast "const uint8_t*", pkt.tcp_dns_raw
    dns_len = #pkt.tcp_dns_raw
  else
    p       = ffi.cast "const uint8_t*", raw
    dns_off = pkt.l4.off
    dns_off += 2 if pkt.l4.proto == "tcp"
    dns_p   = p + dns_off
    dns_len = pkt.l4.payload_len
    dns_len -= 2 if pkt.l4.proto == "tcp"
  pos     = pkt.answers_off
  answers = {}

  for _ = 1, pkt.dns.ancount
    break if pos >= dns_len
    name, consumed = decode_name dns_p, dns_len, pos
    break unless name
    pos += consumed
    break if pos + 10 > dns_len

    rtype    = r16 dns_p, pos
    rclass   = r16 dns_p, pos + 2
    ttl      = r32 dns_p, pos + 4
    ttl_off  = pos + 4
    rdlength = r16 dns_p, pos + 8
    pos += 10
    break if pos + rdlength > dns_len

    rdata_str = if rtype == QTYPE.A and rdlength == 4
      fmt_ipv4 dns_p, pos
    elseif rtype == QTYPE.AAAA and rdlength == 16
      fmt_ipv6 dns_p, pos
    elseif rtype == QTYPE.CNAME
      cname, _ = decode_name dns_p, dns_len, pos
      cname or "?"
    else
      "(rdata #{rdlength}B)"

    rdata_raw_len = if rtype == QTYPE.A then 4
    elseif rtype == QTYPE.AAAA then 16
    else 0
    rdata_raw = if rdata_raw_len > 0
      ffi.string dns_p + pos, rdata_raw_len
    else
      ""

    answers[#answers + 1] = {
      :name, :rtype, :rclass, :ttl, :rdlength, :rdata_str, :rdata_raw
      rtype_name: QTYPE_NAME[rtype] or "TYPE#{rtype}"
      ttl_offset: ttl_off
    }
    pos += rdlength

  answers


--- Patch DNS response TTLs and fix checksums, return the modified packet.
-- @tparam string raw Raw IP packet (Lua string).
-- @tparam table pkt Result from parse_packet.
-- @tparam table answers Result from parse_answers.
-- @tparam number new_ttl TTL value to write.
-- @treturn string Modified packet as a Lua string.
patch_and_checksum = (raw, pkt, answers, new_ttl) ->
  -- Multi-segment TCP: reconstruct a coalesced segment with patched TTLs.
  -- The intermediate segments were DROPped in Q1 so the client never ACKed them;
  -- resetting seq to tcp_init_seq lets the client TCP stack accept the coalesced packet.
  if pkt.l4.proto == "tcp" and not pkt.tcp_single_segment
    -- Patch TTLs in an FFI copy of the reassembled DNS buffer.
    dns_len = #pkt.tcp_dns_raw
    dns_buf = ffi.new "uint8_t[?]", dns_len
    dns_ptr = ffi.cast "const uint8_t*", pkt.tcp_dns_raw
    ffi.copy dns_buf, dns_ptr, dns_len
    for ans in *answers
      w32 dns_buf, ans.ttl_offset, new_ttl
    -- Reconstruct packet: copy IP+TCP headers from the last segment, replace payload.
    p_tmpl      = ffi.cast "const uint8_t*", raw
    ip_ihl      = pkt.ip.ihl
    tcp_hdr_len = bit.rshift(p_tmpl[ip_ihl + 12], 4) * 4
    hdr_len     = ip_ihl + tcp_hdr_len
    new_pkt_len = hdr_len + 2 + dns_len
    new_buf = ffi.new "uint8_t[?]", new_pkt_len
    ffi.copy new_buf, p_tmpl, hdr_len
    -- Write 2-byte DNS length prefix, then patched DNS payload.
    w16 new_buf, hdr_len, dns_len
    ffi.copy new_buf + hdr_len + 2, dns_buf, dns_len
    -- Restore seq to init_seq: client never ACKed the DROPped intermediate segments.
    w32 new_buf, ip_ihl + 4, pkt.tcp_init_seq
    -- Force PSH|ACK flags (0x18) on the coalesced segment.
    new_buf[ip_ihl + 13] = 0x18
    -- Fix length fields and checksums.
    if pkt.ip.version == 4
      w16 new_buf, 2, new_pkt_len
      fix_tcp4_cksum new_buf, new_pkt_len, ip_ihl
      fix_ip4_cksum  new_buf, ip_ihl
    elseif pkt.ip.version == 6
      -- IPv6 payload length = ext_headers + TCP header + 2-byte prefix + DNS.
      w16 new_buf, 4, (ip_ihl - 40) + tcp_hdr_len + 2 + dns_len
      fix_tcp6_cksum new_buf, new_pkt_len, ip_ihl
    return ffi.string new_buf, new_pkt_len

  pkt_len = #raw
  buf = ffi.new "uint8_t[?]", pkt_len
  ffi.copy buf, raw, pkt_len

  dns_off = pkt.l4.off
  if pkt.l4.proto == "tcp"
    dns_off += 2

  for ans in *answers
    w32 buf, dns_off + ans.ttl_offset, new_ttl

  if pkt.ip.version == 4
    if pkt.l4.proto == "udp"
      fix_udp4_cksum buf, pkt_len, pkt.ip.ihl
    elseif pkt.l4.proto == "tcp"
      fix_tcp4_cksum buf, pkt_len, pkt.ip.ihl
    fix_ip4_cksum  buf, pkt.ip.ihl
  elseif pkt.ip.version == 6
    if pkt.l4.proto == "udp"
      fix_udp6_cksum buf, pkt_len, pkt.ip.ihl
    elseif pkt.l4.proto == "tcp"
      fix_tcp6_cksum buf, pkt_len, pkt.ip.ihl

  ffi.string buf, pkt_len

--- Extrait le payload DNS brut d'un paquet analysé, sous forme de Lua string.
-- Pour TCP, utilise pkt.tcp_dns_raw (déjà réassemblé par le parseur).
-- Pour UDP, découpe raw à l'offset L4 + longueur payload.
-- @tparam string raw Paquet IP brut
-- @tparam table  pkt Résultat de parse_packet
-- @treturn string|nil Payload DNS (Lua string), nil si manquant
extract_dns_payload = (raw, pkt) ->
  if pkt.l4.proto == "tcp"
    return pkt.tcp_dns_raw
  raw\sub pkt.l4.off + 1, pkt.l4.off + pkt.l4.payload_len

--- Réécrit les TTL des réponses DNS dans une copie de la string DNS.
-- Contrairement à patch_ttl (FFI in-place), opère sur une Lua string et retourne
-- une nouvelle string. ttl_offset est 0-based depuis le début du payload DNS.
-- @tparam string  dns_str  Payload DNS (Lua string)
-- @tparam table   answers  Résultat de parse_answers (champs ttl_offset 0-based)
-- @tparam number  new_ttl  Valeur TTL à écrire (uint32)
-- @treturn string Nouveau payload DNS avec TTLs réécrits
patch_ttl_in_dns = (dns_str, answers, new_ttl) ->
  dns_len = #dns_str
  buf = ffi.new "uint8_t[?]", dns_len
  ffi.copy buf, dns_str, dns_len
  for ans in *answers
    w32 buf, ans.ttl_offset, new_ttl
  ffi.string buf, dns_len

--- Reconstruit un paquet IP complet avec un nouveau payload DNS (taille différente).
-- Réutilise les en-têtes IP/L4 du paquet original. Met à jour les champs de longueur
-- et recalcule les checksums. Pour TCP, restaure tcp_init_seq et force PSH|ACK.
-- @tparam string raw     Paquet IP brut original
-- @tparam table  pkt     Résultat de parse_packet
-- @tparam string new_dns Nouveau payload DNS (Lua string, sans préfixe TCP)
-- @treturn string|nil    Nouveau paquet IP complet, nil si proto inconnu
replace_dns_payload = (raw, pkt, new_dns) ->
  p       = ffi.cast "const uint8_t*", raw
  ip_ihl  = pkt.ip.ihl
  dns_len = #new_dns

  if pkt.l4.proto == "udp"
    udp_len     = 8 + dns_len
    new_pkt_len = ip_ihl + udp_len
    new_buf = ffi.new "uint8_t[?]", new_pkt_len
    ffi.copy new_buf, p, ip_ihl + 8     -- IP + UDP headers
    w16 new_buf, ip_ihl + 4, udp_len   -- UDP length
    ffi.copy new_buf + ip_ihl + 8, new_dns, dns_len
    if pkt.ip.version == 4
      w16 new_buf, 2, new_pkt_len
      fix_udp4_cksum new_buf, new_pkt_len, ip_ihl
      fix_ip4_cksum  new_buf, ip_ihl
    elseif pkt.ip.version == 6
      w16 new_buf, 4, (ip_ihl - 40) + udp_len   -- ext headers + UDP
      fix_udp6_cksum new_buf, new_pkt_len, ip_ihl
    return ffi.string new_buf, new_pkt_len

  elseif pkt.l4.proto == "tcp"
    tcp_hdr_len = bit.rshift(p[ip_ihl + 12], 4) * 4
    hdr_len     = ip_ihl + tcp_hdr_len
    new_pkt_len = hdr_len + 2 + dns_len
    new_buf = ffi.new "uint8_t[?]", new_pkt_len
    ffi.copy new_buf, p, hdr_len
    w16 new_buf, hdr_len, dns_len          -- 2-byte DNS length prefix
    ffi.copy new_buf + hdr_len + 2, new_dns, dns_len
    w32 new_buf, ip_ihl + 4, pkt.tcp_init_seq   -- restaure seq initial
    new_buf[ip_ihl + 13] = 0x18                  -- PSH|ACK
    if pkt.ip.version == 4
      w16 new_buf, 2, new_pkt_len
      fix_tcp4_cksum new_buf, new_pkt_len, ip_ihl
      fix_ip4_cksum  new_buf, ip_ihl
    elseif pkt.ip.version == 6
      w16 new_buf, 4, (ip_ihl - 40) + tcp_hdr_len + 2 + dns_len
      fix_tcp6_cksum new_buf, new_pkt_len, ip_ihl
    return ffi.string new_buf, new_pkt_len

  nil   -- protocole inconnu

--- Release resources (cleanup).
-- No-op for current implementation.
cleanup = ->
  nil

{ :parse_packet, :parse_answers, :patch_and_checksum, :cleanup
  :extract_dns_payload, :patch_ttl_in_dns, :replace_dns_payload
  :purge_tcp_buffers, :QTYPE, :QTYPE_NAME, :RCODE }
