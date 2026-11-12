-- tests/unit/worker_sip_core_spec.moon
-- Couverture du handler SIP/STUN, des insertions nft et du cache IP→MAC,
-- hors du spec limité à classify_direction/resolve_outbound_mac.
--
-- Le module est rechargé avec des stubs locaux (ffi_defs, nfq_loop,
-- nfq/ethernet, nft_queue, mac_learner_ipc) restaurés en fin de fichier.

ffi = require "ffi"
sp = require("ipparse.lib.pack_compat").pack
{ :s2ip } = require "ipparse.l3.ip"

STUB_KEYS = {
  "worker_sip", "ffi_defs", "nfq_loop", "nfq/ethernet", "nft_queue", "mac_learner_ipc"
}
saved = {}
save_all = -> saved[k] = package.loaded[k] for k in *STUB_KEYS
restore_all = ->
  for k in *STUB_KEYS
    package.loaded[k] = saved[k]

payload_raw = nil
payload_state = {}
l2_result = nil
nft_calls = {}
nft_ok = true
mac_lookup = "unknown"
run_cb = nil
run_opts = nil
set_wfd_calls = 0
set_ack_calls = 0

install_stubs = ->
  package.loaded["ffi_defs"] = {
    :ffi
    libc: ffi.C
    libnfq: {
      nfq_get_payload: (nfad, ptr) ->
        return 0 unless payload_raw
        buf = ffi.new "uint8_t[?]", #payload_raw
        ffi.copy buf, payload_raw, #payload_raw
        payload_state.buf = buf
        ptr[0] = ffi.cast "unsigned char*", buf
        #payload_raw
    }
  }
  package.loaded["nfq_loop"] = {
    NF_ACCEPT: 1
    run_queue: (q, cb) ->
      run_cb = cb
      nil
  }
  package.loaded["nfq/ethernet"] = { get_l2: -> l2_result }
  package.loaded["nft_queue"] = {
    add_mac4: (mac, ip, ctx, ttl, reason) ->
      nft_calls[#nft_calls + 1] = { kind: "mac4", :mac, :ip, :reason }
      nft_ok
    add_mac6: (mac, ip, ctx, ttl, reason) ->
      nft_calls[#nft_calls + 1] = { kind: "mac6", :mac, :ip, :reason }
      nft_ok
    add_sip4: (ip, ctx, ttl, reason) ->
      nft_calls[#nft_calls + 1] = { kind: "sip4", :ip, :reason }
      true
    add_sip6: (ip, ctx, ttl, reason) ->
      nft_calls[#nft_calls + 1] = { kind: "sip6", :ip, :reason }
      true
    get_last_seq: -> 7
    wait_ack: (seq, reason) ->
      nft_calls[#nft_calls + 1] = { kind: "ack", seq: seq, :reason }
      true
    set_wfd: -> set_wfd_calls += 1
    set_ack_rfd: -> set_ack_calls += 1
  }
  package.loaded["mac_learner_ipc"] = {
    get_mac: (ip) -> mac_lookup
  }

load_sip = ->
  package.loaded["worker_sip"] = nil
  require "worker_sip"

-- ── Trames ─────────────────────────────────────────────────────────
ipv4 = (proto, l4, opts={}) ->
  total = 20 + #l4
  hdr = sp(">B B H H H B B H", 0x45, 0, total, 0x1234, 0, 64, proto, 0) ..
    s2ip(opts.src or "10.35.3.6") .. s2ip(opts.dst or "83.136.161.35")
  hdr .. l4

udp = (payload, sport, dport) ->
  sp(">H H H H", sport, dport, 8 + #payload, 0) .. payload

tcp = (payload, sport, dport, opts={}) ->
  header_len = opts.header_len or 0x50
  options = string.rep "\0", opts.tcp_options or 0
  sp(">H H I4 I4 B B H H H", sport, dport, 1000, 0, header_len, 0x18, 8192, 0, 0) ..
    options .. payload

udp_pkt = (payload, sport, dport, opts={}) -> ipv4 17, udp(payload, sport, dport), opts
tcp_pkt = (payload, sport, dport, opts={}) -> ipv4 6, tcp(payload, sport, dport, opts), opts

SIP_SDP = [[INVITE sip:bob@83.136.161.35 SIP/2.0
Via: SIP/2.0/UDP 10.35.3.6:5060;branch=z9hG4bK1
Call-ID: call-1@10.35.3.6
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 120

v=0
o=- 1 2 IN IP4 83.136.164.102
s=-
c=IN IP4 83.136.164.102
t=0 0
m=audio 61348 RTP/AVP 0
]]

SIP_NO_SDP = [[REGISTER sip:83.136.161.35 SIP/2.0
Via: SIP/2.0/UDP 10.35.3.6:5060;branch=z9hG4bK2
Call-ID: call-2@10.35.3.6
CSeq: 2 REGISTER
Content-Length: 0

]]

SIP_RESP_SDP = [[SIP/2.0 200 OK
Via: SIP/2.0/UDP 10.35.3.6:5060;branch=z9hG4bK3
Call-ID: call-3@10.35.3.6
CSeq: 3 INVITE
Content-Type: application/sdp
Content-Length: 100

v=0
c=IN IP4 83.136.162.33
m=audio 61348 RTP/AVP 0
]]

-- Sélecteurs de test.
select_kind = (kind) ->
  for c in *nft_calls
    return c if c.kind == kind
  nil

select_sip_media = ->
  [c for c in *nft_calls when c.reason == "sip_media"]

describe "worker_sip cœur", ->
  w = nil

  lazy_setup ->
    save_all!
    l2_result = { mac_src: "aa:bb:cc:dd:ee:ff" }
    install_stubs!
    w = load_sip!

  lazy_teardown ->
    restore_all!

  before_each ->
    payload_raw = nil
    payload_state.buf = nil
    l2_result = { mac_src: "aa:bb:cc:dd:ee:ff" }
    nft_calls = {}
    nft_ok = true
    mac_lookup = "unknown"
    run_cb = nil
    run_opts = nil
    set_wfd_calls = 0
    set_ack_calls = 0
    install_stubs!
    w = load_sip!
    -- Vide le cache IP→MAC sans réassigner la table capturée par le module.
    for ip in pairs w.ip_to_mac
      w.ip_to_mac[ip] = nil

  invoke = -> w.handle_packet nil, nil, 1
  kinds = -> [c.kind for c in *nft_calls]

  describe "format_ip, is_lan_ip, cache IP→MAC", ->
    it "format_ip gère v4, v6 et les entrées invalides", ->
      assert.is_nil w.format_ip 4, nil
      assert.equals "10.0.0.1", w.format_ip 4, "\10\0\0\1"
      assert.equals "2001:db8::1", w.format_ip 6, (s2ip "2001:db8::1")
      assert.is_nil w.format_ip 3, "\1\2\3\4"

    it "is_lan_ip reconnaît les plages privées et ULA", ->
      for ip in *{ "10.1.2.3", "192.168.1.1", "172.16.0.1", "172.31.255.1", "fc00::1", "fd42::1" }
        assert.is_true w.is_lan_ip ip
      for ip in *{ "172.15.0.1", "172.32.0.1", "8.8.8.8", nil }
        assert.is_false w.is_lan_ip ip

    it "cache_ip_to_mac ignore unknown puis mémorise et évince au plafond", ->
      w.cache_ip_to_mac "10.0.0.1", "unknown"
      assert.is_nil w.known_phone_mac "10.0.0.1"
      w.cache_ip_to_mac "10.0.0.1", "aa:bb:cc:dd:ee:ff"
      assert.equals "aa:bb:cc:dd:ee:ff", w.known_phone_mac "10.0.0.1"
      -- Un second enregistrement de la même IP ne remplace pas la MAC.
      w.cache_ip_to_mac "10.0.0.1", "11:22:33:44:55:66"
      assert.equals "aa:bb:cc:dd:ee:ff", w.known_phone_mac "10.0.0.1"
      -- Plafond 256 : l'insertion suivante évince une entrée.
      for i = 1, 260
        w.cache_ip_to_mac "10.1.0.#{i}", "02:00:00:00:01:#{string.format '%02x', i % 256}"
      count = 0
      count += 1 for _ in pairs w.ip_to_mac
      assert.equals 256, count

    it "query_phone_mac interroge le learner pour une IP LAN", ->
      mac_lookup = "02:00:00:00:00:42"
      assert.equals "02:00:00:00:00:42", w.query_phone_mac "10.0.0.42"
      assert.equals "02:00:00:00:00:42", w.known_phone_mac "10.0.0.42"
      assert.is_nil w.query_phone_mac "8.8.8.8"
      mac_lookup = "unknown"
      assert.is_nil w.query_phone_mac "10.0.0.43"

    it "resolve_outbound_mac distingue cache, paquet, learner et échec", ->
      w.remember_phone_ip "10.0.0.50", "cache-mac"
      mac, src = w.resolve_outbound_mac "10.0.0.50", "pkt-mac"
      assert.equals "cache-mac", mac
      assert.equals "cache", src
      mac, src = w.resolve_outbound_mac "10.0.0.51", "pkt-mac"
      assert.equals "pkt-mac", mac
      assert.equals "packet", src
      mac_lookup = "learner-mac"
      mac, src = w.resolve_outbound_mac "10.0.0.52", "unknown"
      assert.equals "learner-mac", mac
      assert.equals "learner", src
      mac_lookup = "unknown"
      mac, src = w.resolve_outbound_mac "8.8.8.8", "unknown"
      assert.is_nil mac
      assert.equals "none", src

    it "classify_direction départage les deux côtés sur 5060", ->
      w.remember_phone_ip "10.0.0.60", "phone"
      -- sport=dport=5060 : la IP dst connue désigne l'entrant.
      outbound, inbound = w.classify_direction 5060, 5060, "8.8.8.8", "10.0.0.60"
      assert.is_false outbound
      assert.is_true inbound
      -- sport=5060 seul mais source connue : sortant.
      outbound, inbound = w.classify_direction 5060, 40000, "10.0.0.60", "8.8.8.8"
      assert.is_true outbound
      assert.is_false inbound

  describe "insertions nft (allow_mac_ip / allow_sip_peer)", ->
    it "insère MAC+IP ip4 puis attend l'ACK", ->
      assert.is_true w.allow_mac_ip "aa:bb", "1.2.3.4", "ip4", "test"
      assert.same { "mac4", "ack" }, kinds!
      assert.equals "1.2.3.4", nft_calls[1].ip

    it "insère MAC+IP ip6", ->
      assert.is_true w.allow_mac_ip "aa:bb", "2001:db8::1", "ip6", "test"
      assert.same { "mac6", "ack" }, kinds!

    it "ignore les entrées incomplètes et remonte l'échec add_mac", ->
      assert.is_nil w.allow_mac_ip nil, "1.2.3.4", "ip4", "x"
      assert.is_nil w.allow_mac_ip "aa:bb", nil, "ip4", "x"
      assert.is_nil w.allow_mac_ip "aa:bb", "1.2.3.4", nil, "x"
      nft_ok = false
      assert.is_false w.allow_mac_ip "aa:bb", "1.2.3.4", "ip4", "x"

    it "allow_sip_peer insère une IP ip4 ou ip6, sans ACK", ->
      assert.is_true w.allow_sip_peer "1.2.3.4", "ip4", "peer"
      assert.is_true w.allow_sip_peer "2001:db8::1", "ip6", "peer"
      assert.same { "sip4", "sip6" }, kinds!
      assert.is_nil w.allow_sip_peer nil, "ip4", "peer"
      assert.is_nil w.allow_sip_peer "1.2.3.4", nil, "peer"

  describe "handle_packet", ->
    it "payload vide, IP illisible ou L4 absent → NF_ACCEPT", ->
      assert.equals 1, invoke!                       -- payload nil
      payload_raw = "\255\0\0\0" .. string.rep("\0", 40)
      assert.equals 1, invoke!                       -- version IP inconnue
      payload_raw = ipv4 1, string.rep("\0", 8)      -- ICMP : ni UDP ni TCP
      assert.equals 1, invoke!

    it "trafic non SIP (port haut) → NF_ACCEPT sans insertion", ->
      payload_raw = udp_pkt "hello", 40000, 40001
      assert.equals 1, invoke!
      assert.equals 0, #nft_calls

    it "STUN requête (dport 3478) → whitelist MAC+IP destination", ->
      payload_raw = udp_pkt "\0\1\0\0", 50000, 3478, dst: "83.136.161.35"
      assert.equals 1, invoke!
      assert.same { "mac4", "ack" }, kinds!
      assert.equals "83.136.161.35", nft_calls[1].ip
      assert.equals "sip_stun", nft_calls[1].reason

    it "STUN réponse (sport 3478) → pairs source et destination", ->
      payload_raw = udp_pkt "\0\1\0\0", 3478, 50000, src: "83.136.161.35", dst: "10.35.3.6"
      assert.equals 1, invoke!
      assert.same { "sip4", "sip4" }, kinds!
      assert.equals "stun_src", nft_calls[1].reason
      assert.equals "stun_dst", nft_calls[2].reason

    it "SIP/TLS (5061) → accepté sans parsing", ->
      payload_raw = tcp_pkt "\22\3\3\0\1x", 40000, 5061
      assert.equals 1, invoke!
      assert.equals 0, #nft_calls

    it "SIP sortant avec SDP → proxy, pairs, puis IP média", ->
      payload_raw = udp_pkt SIP_SDP, 5060, 5060, src: "10.35.3.6", dst: "83.136.161.35"
      assert.equals 1, invoke!
      -- mac4 proxy + ACK, sip4 src/dst, puis mac4 + sip4 pour l'IP média.
      assert.equals "mac4", nft_calls[1].kind
      assert.equals "83.136.161.35", nft_calls[1].ip
      assert.equals "sip_signal", nft_calls[1].reason
      assert.equals "sip_peer_src", nft_calls[3].reason
      assert.equals "sip_peer_dst", nft_calls[4].reason
      assert.equals "sip_media", nft_calls[5].reason
      assert.equals "83.136.164.102", nft_calls[5].ip
      assert.equals "sip_media", nft_calls[6].reason

    it "SIP sortant sans SDP → pairs connus mais aucune IP média", ->
      payload_raw = udp_pkt SIP_NO_SDP, 5060, 5060, src: "10.35.3.6", dst: "83.136.161.35"
      assert.equals 1, invoke!
      assert.equals 0, #select_sip_media()
      assert.equals "mac4", nft_calls[1].kind
      assert.equals "sip_peer_src", nft_calls[3].reason

    it "SIP entrant vers un téléphone connu → IP média pour sa MAC", ->
      w.remember_phone_ip "10.35.3.6", "48:25:67:f7:96:52"
      payload_raw = udp_pkt SIP_RESP_SDP, 5060, 6000, src: "83.136.161.35", dst: "10.35.3.6"
      assert.equals 1, invoke!
      media = select_sip_media!
      mac = select_kind "mac4"
      assert.is_true #media >= 1
      assert.equals "48:25:67:f7:96:52", mac.mac
      assert.equals "83.136.162.33", mac.ip

    it "SIP entrant sans MAC de téléphone connue → accepté sans insertion média", ->
      payload_raw = udp_pkt SIP_RESP_SDP, 5060, 6000, src: "83.136.161.35", dst: "10.35.3.99"
      assert.equals 1, invoke!
      assert.is_nil select_kind "mac4"
      assert.is_nil select_kind "sip_media"

    it "SIP sortant sans MAC résolue → accepté sans insertion", ->
      l2_result = { mac_src: "unknown" }
      payload_raw = udp_pkt SIP_SDP, 50000, 5060, src: "83.136.164.1", dst: "83.136.161.35"
      assert.equals 1, invoke!
      -- Les pairs sont enregistrés avant la résolution de la MAC ; aucune
      -- insertion MAC+IP n'a lieu sans téléphone identifié.
      assert.is_nil select_kind "mac4"
      assert.equals 2, #nft_calls

    it "paquet TCP SIP (sans réassemblage) est classifié comme SIP", ->
      payload_raw = tcp_pkt SIP_NO_SDP, 5060, 5060, src: "10.35.3.6", dst: "83.136.161.35"
      assert.equals 1, invoke!
      assert.equals "mac4", nft_calls[1].kind

  describe "run()", ->
    it "configure nft_queue avec les fd fournis puis arme handle_packet", ->
      w.run "3", { nft_wfd: 10, ack_rfd: 11, worker_idx: 2 }
      assert.equals 1, set_wfd_calls
      assert.equals 1, set_ack_calls
      assert.is_not_nil run_cb
      payload_raw = nil
      assert.equals 1, run_cb nil, nil, 1

    it "tolère l'absence de fds", ->
      w.run 3, nil
      assert.is_not_nil run_cb

