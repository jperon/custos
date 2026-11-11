-- tests/unit/worker_auth_queue_spec.moon
-- T4 : message 22 octets (ip16 + mac6) envoyé au serveur d'authentification,
-- et verdicts du callback. Stubs locaux (libc.write, libnfq, nfq_loop,
-- nfq/ethernet) restaurés en teardown.

ffi = require "ffi"
sp  = require("ipparse.lib.pack_compat").pack
{ :s2ip } = require "ipparse.l3.ip"

STUB_KEYS = { "ffi_defs", "worker_auth_queue", "nfq_loop", "nfq/ethernet" }
saved = {}

MAC = "\170\187\204\221\238\255"

ipv4_packet = (src="192.0.2.10", dst="198.51.100.1") ->
  sp(">B B H H H B B H", 0x45, 0, 20, 0x1234, 0, 64, 17, 0) ..
    s2ip(src) .. s2ip(dst)

describe "worker_auth_queue", ->

  wq = nil
  payload = ""
  l2 = nil
  write_calls = {}
  write_ret = nil

  before_each ->
    saved[k] = package.loaded[k] for k in *STUB_KEYS
    payload = ""
    l2 = { mac_raw: MAC, mac_src: "aa:bb:cc:dd:ee:ff" }
    write_calls = {}
    write_ret = nil

    package.loaded["ffi_defs"] = {
      :ffi
      libc: {
        write: (fd, buf, len) ->
          write_calls[#write_calls + 1] = { :fd, :len, data: ffi.string(buf, len) }
          write_ret or len
      }
      libnfq: {
        nfq_get_payload: (nfad, out) ->
          return 0 if #payload == 0
          buf = ffi.new "uint8_t[?]", #payload
          ffi.copy buf, payload
          out[0] = ffi.cast "unsigned char*", buf
          #payload
      }
    }
    package.loaded["nfq_loop"] = {
      NF_ACCEPT: 1
      NF_DROP: 0
      run_queue: (queue, cb) -> nil
    }
    package.loaded["nfq/ethernet"] = { get_l2: -> l2 }

    package.loaded["worker_auth_queue"] = nil
    wq = require "worker_auth_queue"
    wq.run 0, 1234

  after_each ->
    for k in *STUB_KEYS
      package.loaded[k] = saved[k]

  invoke = (raw) ->
    payload = raw
    wq.handle_auth_packet nil, nil, 7

  -- ── send_to_auth_server ───────────────────────────────────────────────────
  describe "send_to_auth_server", ->
    it "IPv4 : 4 octets d'IP, 12 zéros de padding, puis la MAC", ->
      ok = wq.send_to_auth_server 4, "\192\0\2\10", MAC
      assert.is_true ok
      assert.equals 1, #write_calls
      call = write_calls[1]
      assert.equals 1234, call.fd
      assert.equals 22, call.len
      assert.equals "\192\0\2\10" .. string.rep("\0", 12) .. MAC, call.data

    it "IPv6 : les 16 octets d'IP puis la MAC", ->
      ip6 = s2ip "2001:db8::cafe"
      ok = wq.send_to_auth_server 6, ip6, MAC
      assert.is_true ok
      assert.equals ip6 .. MAC, write_calls[1].data
      assert.equals 22, write_calls[1].len

    it "refuse une MAC de longueur invalide sans écrire", ->
      assert.is_false wq.send_to_auth_server 4, "\192\0\2\10", "\1\2\3"
      assert.equals 0, #write_calls

    it "refuse une IP de longueur invalide sans écrire", ->
      assert.is_false wq.send_to_auth_server 4, "\192\0\2", MAC
      assert.equals 0, #write_calls

    it "écriture partielle → false", ->
      write_ret = 10
      assert.is_false wq.send_to_auth_server 4, "\192\0\2\10", MAC
      assert.equals 1, #write_calls

  -- ── handle_auth_packet ────────────────────────────────────────────────────
  describe "handle_auth_packet", ->
    it "accepte le paquet et envoie l'IP source et la MAC", ->
      rc = invoke ipv4_packet!
      assert.equals 1, rc
      assert.equals 1, #write_calls
      assert.equals "\192\0\2\10" .. string.rep("\0", 12) .. MAC,
        write_calls[1].data

    it "payload vide → NF_DROP sans écriture", ->
      payload = ""
      rc = wq.handle_auth_packet nil, nil, 7
      assert.equals 0, rc
      assert.equals 0, #write_calls

    it "paquet IP illisible → NF_ACCEPT sans écriture", ->
      rc = invoke "\x45"
      assert.equals 1, rc
      assert.equals 0, #write_calls

    it "l2 absent → NF_ACCEPT sans écriture", ->
      l2 = nil
      rc = invoke ipv4_packet!
      assert.equals 1, rc
      assert.equals 0, #write_calls

    it "MAC absente des métadonnées → NF_ACCEPT sans écriture", ->
      l2 = { mac_raw: nil, mac_src: "unknown" }
      rc = invoke ipv4_packet!
      assert.equals 1, rc
      assert.equals 0, #write_calls
