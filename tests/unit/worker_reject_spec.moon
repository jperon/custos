describe "worker_reject RTP helpers", ->
  worker_reject = require "worker_reject"

  describe "ip classification", ->
    it "identifies private and public IPv4", ->
      assert.is_true worker_reject.is_private_ipv4 "10.35.3.6"
      assert.is_true worker_reject.is_private_ipv4 "192.168.1.2"
      assert.is_false worker_reject.is_private_ipv4 "83.136.163.31"
      assert.is_true worker_reject.is_public_ipv4 "83.136.163.31"
      assert.is_false worker_reject.is_public_ipv4 "10.35.3.6"

    it "plage 172.16.0.0/12 est privée", ->
      assert.is_true worker_reject.is_private_ipv4 "172.16.0.1"
      assert.is_true worker_reject.is_private_ipv4 "172.31.255.255"
      assert.is_false worker_reject.is_private_ipv4 "172.15.0.1"
      assert.is_false worker_reject.is_private_ipv4 "172.32.0.1"

    it "loopback et link-local ne sont pas publics", ->
      assert.is_false worker_reject.is_public_ipv4 "127.0.0.1"
      assert.is_false worker_reject.is_public_ipv4 "169.254.1.1"

    it "nil et format invalide → false", ->
      assert.is_false worker_reject.is_private_ipv4 nil
      assert.is_false worker_reject.is_private_ipv4 "not_an_ip"
      assert.is_false worker_reject.is_public_ipv4 nil
      assert.is_false worker_reject.is_public_ipv4 ""

  describe "RTP payload detector", ->
    it "accepts RTP v2-like UDP payload", ->
      udp_header = string.rep "\0", 8
      rtp_payload = string.char 0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78
      raw = udp_header .. rtp_payload
      assert.is_true worker_reject.looks_like_rtp_payload raw, 1

    it "rejects STUN magic-cookie payload", ->
      udp_header = string.rep "\0", 8
      stun_like = string.char 0x80, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x00, 0x00, 0x00
      raw = udp_header .. stun_like
      assert.is_false worker_reject.looks_like_rtp_payload raw, 1

    it "payload trop court → false", ->
      raw = string.rep "\0", 10  -- moins de 8+11=19 octets avec l4_off=1
      assert.is_false worker_reject.looks_like_rtp_payload raw, 1

    it "version bits ≠ 2 → false", ->
      udp_header = string.rep "\0", 8
      -- Premier octet du payload : version = 0 (bits 7..6 = 00)
      bad_rtp = string.char 0x40, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78
      raw = udp_header .. bad_rtp
      assert.is_false worker_reject.looks_like_rtp_payload raw, 1

  describe "RTP tuple tracker", ->
    it "tracks private->public high-port RTP-like UDP only", ->
      udp_header = string.rep "\0", 8
      rtp_payload = string.char 0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78
      raw = udp_header .. rtp_payload

      sip_ports = { [5060]: true }
      assert.is_true worker_reject.should_track_rtp_udp 17, 4, "10.35.3.6", "83.136.163.31", 16440, 57044, raw, 1
      assert.is_false worker_reject.should_track_rtp_udp 17, 4, "10.35.3.6", "10.35.3.7", 16440, 57044, raw, 1
      assert.is_false worker_reject.should_track_rtp_udp 17, 4, "10.35.3.6", "83.136.163.31", 5060, 57044, raw, 1, sip_ports

    it "rejet si proto != UDP (TCP)", ->
      udp_header = string.rep "\0", 8
      rtp_payload = string.char 0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78
      raw = udp_header .. rtp_payload
      assert.is_false worker_reject.should_track_rtp_udp 6, 4, "10.35.3.6", "83.136.163.31", 16440, 57044, raw, 1

    it "rejet si version IPv6", ->
      udp_header = string.rep "\0", 8
      rtp_payload = string.char 0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78
      raw = udp_header .. rtp_payload
      assert.is_false worker_reject.should_track_rtp_udp 17, 6, "10.35.3.6", "83.136.163.31", 16440, 57044, raw, 1

    it "rejet si sport < 1024", ->
      udp_header = string.rep "\0", 8
      rtp_payload = string.char 0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78
      raw = udp_header .. rtp_payload
      assert.is_false worker_reject.should_track_rtp_udp 17, 4, "10.35.3.6", "83.136.163.31", 53, 57044, raw, 1

    it "rejet si port exclu", ->
      udp_header = string.rep "\0", 8
      rtp_payload = string.char 0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78
      raw = udp_header .. rtp_payload
      excluded = { [16440]: true }
      assert.is_false worker_reject.should_track_rtp_udp 17, 4, "10.35.3.6", "83.136.163.31", 16440, 57044, raw, 1, excluded
