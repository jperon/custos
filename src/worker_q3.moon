-- src/worker_q3.moon
-- Worker Q3: forge reject (bridge mode).
--
-- Receives all silently-dropped packets from NFQUEUE 3.
-- The payload starts at the IP header (nftables bridge NFQUEUE delivers
-- no Ethernet header). For each packet:
--   1. Parse IP (+ TCP for RST).
--   2. TCP  → forge TCP RST/ACK back to sender (IP payload, src/dst swapped).
--   3. UDP/other → forge ICMP admin-prohibited (v4 type 3/13, v6 type 1/1).
--   4. Set verdict NF_ACCEPT with the forged IP packet as replacement payload.
--   5. Structured log.

{ :ffi, :libnfq } = require "ffi_defs"
{ :QUEUE_REJECT } = require "config"
{ :run_queue, :NF_ACCEPT, :NF_DROP, :VERDICT_DONE } = require "nfq_loop"
{ :log_info, :log_warn } = require "log"
parse: parse_ip, new: new_ip, proto: ip_proto = require "ipparse.l3.ip"
parse: parse_tcp = require "ipparse.l4.tcp"
parse: parse_udp = require "ipparse.l4.udp"
{ :flags } = require "ipparse.l4.tcp"
{ :RST, :ACK } = flags
{ :ip2s } = require "ipparse.l3.ip"
pack: sp = require "ipparse.lib.pack_compat"
:checksum = require "ipparse.l3.lib"

PROTO_TCP   = ip_proto.TCP    -- 6
PROTO_UDP   = ip_proto.UDP    -- 17
PROTO_ICMP  = ip_proto.ICMP   -- 1
PROTO_ICMPv6 = ip_proto.ICMPv6 -- 58 (0x3A)

-- ICMPv4 type 3 (Destination Unreachable), code 13 (Communication Administratively Prohibited)
ICMP4_TYPE = 3
ICMP4_CODE = 13

-- ICMPv6 type 1 (Destination Unreachable), code 1 (Communication with Destination Administratively Prohibited)
ICMP6_TYPE = 1
ICMP6_CODE = 1

-- Maximum bytes of the original IP packet quoted in the ICMP error body.
-- RFC 792 requires at least IP header + 8 bytes of original datagram.
-- We quote up to 576 bytes to stay within a safe ICMP payload size.
ICMP_QUOTE_MAX = 576

--- Forge a TCP RST/ACK IP packet in response to any TCP packet from the client.
-- Swaps src/dst addresses at L3 and L4. Returns raw IP payload (no Ethernet header)
-- since nftables bridge NFQUEUE payloads contain no Ethernet framing.
-- @tparam table  ip   Parsed IP header (v4 or v6).
-- @tparam table  tcp  Parsed TCP header.
-- @treturn string Raw IP packet containing the RST, or nil on error.
forge_tcp_rst = (ip, tcp) ->
  -- Build RST/ACK TCP segment.
  -- ack_n = (seq_n + 1) so the peer knows we received the SYN/data.
  -- seq_n = 0 (RST does not carry meaningful sequence data).
  rst = {
    spt:    tcp.dpt
    dpt:    tcp.spt
    seq_n:  0
    ack_n:  (tcp.seq_n + 1) % 0x100000000
    header_len: 0x50   -- 5 × 4 = 20 bytes, no options
    flags:  RST + ACK
    window: 0
    checksum: 0
    urg_ptr:  0
    options:  ""
    data:     ""
  }
  rst_obj = (require "ipparse.l4.tcp").new rst

  -- Build IP header (swap src/dst).
  local ip_obj
  if ip.version == 6
    ip_obj = new_ip {
      version:     6
      hop_limit:   64
      next_header: PROTO_TCP
      src:         ip.dst
      dst:         ip.src
      options:     ""
      data:        rst_obj
    }
  else
    ip_obj = new_ip {
      version:  4
      ttl:      64
      protocol: PROTO_TCP
      src:      ip.dst
      dst:      ip.src
      options:  ""
      data:     rst_obj
    }

  "#{ip_obj}"

--- Forge an ICMP admin-prohibited error IP packet.
-- Quotes the first ICMP_QUOTE_MAX bytes of the original IP+transport payload.
-- Returns raw IP payload (no Ethernet header).
-- @tparam string  raw  Raw IP payload as received from NFQUEUE.
-- @tparam table   ip   Parsed IP header (v4 or v6).
-- @treturn string Raw IP packet containing the ICMP error, or nil on error.
forge_icmp_reject = (raw, ip) ->
  -- The ICMP body quotes the original IP datagram.
  -- raw starts at the IP header (offset 1, Lua 1-based).
  original_ip_bytes = raw\sub 1, ICMP_QUOTE_MAX

  if ip.version == 6
    -- ICMPv6 admin-prohibited (type 1, code 1)
    -- Header: type(1) + code(1) + checksum(2) + unused(4) + quoted original
    icmp6_body = sp(">BBH I4", ICMP6_TYPE, ICMP6_CODE, 0, 0) .. original_ip_bytes

    -- Compute ICMPv6 checksum over pseudo-header (RFC 8200 §8.1)
    icmp6_len  = #icmp6_body
    pseudo     = sp(">c16 c16 I4 xxx B", ip.dst, ip.src, icmp6_len, PROTO_ICMPv6)
    cksum      = checksum pseudo .. icmp6_body
    icmp6_body = sp(">BBH I4", ICMP6_TYPE, ICMP6_CODE, cksum, 0) .. original_ip_bytes

    ip_obj = new_ip {
      version:     6
      hop_limit:   64
      next_header: PROTO_ICMPv6
      src:         ip.dst
      dst:         ip.src
      options:     ""
      data:        icmp6_body
    }
    "#{ip_obj}"
  else
    -- ICMPv4 admin-prohibited (type 3, code 13)
    -- Header: type(1) + code(1) + checksum(2) + unused(4) + quoted original
    icmp4_body_nocsum = sp(">BBH I4", ICMP4_TYPE, ICMP4_CODE, 0, 0) .. original_ip_bytes
    cksum = checksum icmp4_body_nocsum
    icmp4_body = sp(">BBH I4", ICMP4_TYPE, ICMP4_CODE, cksum, 0) .. original_ip_bytes

    ip_obj = new_ip {
      version:  4
      ttl:      64
      protocol: PROTO_ICMP
      src:      ip.dst
      dst:      ip.src
      options:  ""
      data:     icmp4_body
    }
    "#{ip_obj}"

-- ── Main callback ─────────────────────────────────────────────────
--- Handle a packet from NFQUEUE 3 (forge reject).
-- Parses the packet, forges RST or ICMP admin-prohibited, and injects
-- the forged frame via nfq_set_verdict with replacement payload.
-- @tparam cdata  qh_ptr  nfq_q_handle pointer.
-- @tparam cdata  nfad    nfq_data pointer.
-- @tparam number pkt_id  NFQUEUE packet id.
-- @treturn number VERDICT_DONE always (verdict set inside).
handle_reject = (qh_ptr, nfad, pkt_id) ->
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  if payload_len <= 0
    libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_DROP, 0, nil
    return VERDICT_DONE

  raw = ffi.string payload_ptr[0], payload_len

  -- In nftables bridge table, NFQUEUE payload starts directly at the IP header
  -- (no Ethernet header), unlike ebtables. Parse IP at offset 1 (Lua 1-based).
  ip, l4_off = parse_ip raw, 1
  unless ip
    libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_DROP, 0, nil
    return VERDICT_DONE

  proto = ip.protocol or ip.next_header
  src_ip = ip2s ip.src
  dst_ip = ip2s ip.dst
  sport, dport = nil, nil

  if proto == PROTO_TCP
    tcp = parse_tcp raw, l4_off
    if tcp
      sport, dport = tcp.spt, tcp.dpt
  elseif proto == PROTO_UDP
    udp = parse_udp raw, l4_off
    if udp
      sport, dport = udp.spt, udp.dpt

  local forged, response_type
  ok, err_or_frame = pcall ->
    if proto == PROTO_TCP
      tcp = parse_tcp raw, l4_off
      unless tcp
        return nil
      response_type = "rst"
      forge_tcp_rst ip, tcp
    else
      response_type = "icmp"
      forge_icmp_reject raw, ip

  unless ok
    log_warn { action: "q3_forge_error", src: src_ip, dst: dst_ip, proto: proto, err: tostring(err_or_frame) }
    libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_DROP, 0, nil
    return VERDICT_DONE

  forged = err_or_frame

  unless forged
    -- parse failure inside pcall (returned nil without error)
    libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_DROP, 0, nil
    return VERDICT_DONE

  -- Inject forged frame as the verdict payload.
  -- NF_ACCEPT with a replacement payload re-injects the forged frame into the
  -- bridge in place of the original packet (NF_DROP + payload does not work).
  forged_ptr = ffi.cast "const unsigned char*", forged
  libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_ACCEPT, #forged, forged_ptr

  log_info {
    action:   "q3_reject"
    queue:    3
    src:      src_ip
    dst:      dst_ip
    sport:    sport
    dport:    dport
    proto:    proto
    response: response_type
  }

  VERDICT_DONE

-- ── Entry point ───────────────────────────────────────────────────
--- Start the Q3 forge-reject worker.
-- Opens NFQUEUE 3 and enters the packet processing loop.
-- @tparam table _cfg  Ignored (reserved for future use).
-- @treturn nil
run = (_cfg) ->
  log_info { action: "q3_worker_start", queue: QUEUE_REJECT }
  run_queue QUEUE_REJECT, handle_reject

{ :run }
