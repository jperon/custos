describe "worker_reject RTP helpers", ->
  worker_reject = require "worker_reject"

  describe "ip classification", ->
    it "identifies private and public IPv4", ->
      assert.is_true worker_reject.is_private_ipv4 "10.35.3.6"
      assert.is_true worker_reject.is_private_ipv4 "192.168.1.2"
      assert.is_false worker_reject.is_private_ipv4 "83.136.163.31"
      assert.is_true worker_reject.is_public_ipv4 "83.136.163.31"
      assert.is_false worker_reject.is_public_ipv4 "10.35.3.6"

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

  describe "RTP tuple tracker", ->
    it "tracks private->public high-port RTP-like UDP only", ->
      udp_header = string.rep "\0", 8
      rtp_payload = string.char 0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78
      raw = udp_header .. rtp_payload

      sip_ports = { [5060]: true }
      assert.is_true worker_reject.should_track_rtp_udp 17, 4, "10.35.3.6", "83.136.163.31", 16440, 57044, raw, 1
      assert.is_false worker_reject.should_track_rtp_udp 17, 4, "10.35.3.6", "10.35.3.7", 16440, 57044, raw, 1
      assert.is_false worker_reject.should_track_rtp_udp 17, 4, "10.35.3.6", "83.136.163.31", 5060, 57044, raw, 1, sip_ports
