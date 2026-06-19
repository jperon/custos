-- tests/unit/worker_doh_vlan_spec.moon
-- Tests du worker NFQUEUE de détection VLAN pour les clients DoH.
-- encode_vlan_msg est pur ; handle_packet est exercé avec des stubs ffi/nfq.

ffi = require "ffi"

-- ── Stubs des dépendances lourdes (avant require) ────────────────────────────
logged_actions = {}
eval_log = (f) ->
  r = (type(f) == "function") and f!
  if type(r) == "table" and r.action
    logged_actions[#logged_actions + 1] = r.action
  r
has_action = (name) ->
  for a in *logged_actions
    return true if a == name
  false
package.loaded["log"] = {
  log_info: eval_log, log_warn: eval_log, log_debug: eval_log
  set_action_prefix: (->)
}

-- get_l2 contrôlable : renvoie la table l2 courante (vlan tagué ou nil).
l2_result = nil
package.loaded["nfq/ethernet"] = { get_l2: (nfad) -> l2_result }

-- ipparse.l3.ip contrôlable (parse + ip2s).
ip_result = nil
ip_err    = nil
package.loaded["ipparse.l3.ip"] = {
  parse: (raw, off) -> ip_result, ip_err
  ip2s:  (raw) -> "10.0.0.1"
}

-- mac_learner_ipc contrôlable : get_mac renvoie la MAC connue de l'IP.
get_mac_result = "unknown"
package.loaded["mac_learner_ipc"] = { get_mac: (ip_str) -> get_mac_result }

-- nfq_loop : constantes + run_queue inerte.
package.loaded["nfq_loop"] = {
  run_queue: (->), NF_ACCEPT: 1, NF_DROP: 0
}

-- ffi_defs : ffi réel, libc.write capturé, libnfq.nfq_get_payload contrôlable.
payload_raw = nil
package.loaded["ffi_defs"] = {
  ffi: ffi
  libc: { write: (fd, buf, n) -> n }
  libnfq: {
    nfq_get_payload: (nfad, ptr) ->
      return 0 unless payload_raw
      buf = ffi.new "unsigned char[?]", #payload_raw, payload_raw
      ptr[0] = ffi.cast "unsigned char*", buf
      #payload_raw
  }
}

w = require "worker_doh_vlan"

describe "worker_doh_vlan.encode_vlan_msg", ->
  it "IPv4 : 4 octets paddés à 16 + vlan BE = 18 octets", ->
    msg = w.encode_vlan_msg 4, "\10\0\0\1", 100
    assert.equals 18, #msg
    assert.equals "\10\0\0\1", msg\sub 1, 4
    assert.equals string.rep("\0", 12), msg\sub 5, 16
    assert.equals 0, msg\byte 17        -- 100 = 0x0064
    assert.equals 100, msg\byte 18

  it "untagged (vlan 0) encodé explicitement, pas ignoré", ->
    msg = w.encode_vlan_msg 4, "\192\168\1\1", 0
    assert.equals 18, #msg
    assert.equals 0, msg\byte 17
    assert.equals 0, msg\byte 18

  it "VLAN haut (> 255) en big-endian", ->
    msg = w.encode_vlan_msg 4, "\10\0\0\1", 4094   -- 0x0FFE
    assert.equals 0x0F, msg\byte 17
    assert.equals 0xFE, msg\byte 18

  it "IPv6 : 16 octets directs", ->
    ip6 = string.rep "\32", 16
    msg = w.encode_vlan_msg 6, ip6, 10
    assert.equals 18, #msg
    assert.equals ip6, msg\sub 1, 16

  it "ip_raw nil ou trop court → nil", ->
    assert.is_nil w.encode_vlan_msg 4, nil, 1
    assert.is_nil w.encode_vlan_msg 4, "\1\2", 1   -- < 4 octets
    assert.is_nil w.encode_vlan_msg 6, "\1\2\3", 1 -- < 16 octets

describe "worker_doh_vlan.should_learn_untagged", ->
  it "apprend si MAC connue inconnue/nil (fallback anti-stale)", ->
    assert.is_true w.should_learn_untagged "aa:bb:cc:dd:ee:ff", nil
    assert.is_true w.should_learn_untagged "aa:bb:cc:dd:ee:ff", "unknown"
    assert.is_true w.should_learn_untagged "aa:bb:cc:dd:ee:ff", ""

  it "apprend si MAC trame inconnue/nil (pas de discriminant)", ->
    assert.is_true w.should_learn_untagged nil, "aa:bb:cc:dd:ee:ff"
    assert.is_true w.should_learn_untagged "unknown", "aa:bb:cc:dd:ee:ff"

  it "apprend si MAC trame == MAC connue (adjacent ou usurpateur)", ->
    assert.is_true w.should_learn_untagged "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"

  it "ignore si MAC trame != MAC connue (boucle routée : MAC passerelle)", ->
    assert.is_false w.should_learn_untagged "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"

describe "worker_doh_vlan.handle_packet", ->
  before_each ->
    l2_result = nil
    ip_result = nil
    payload_raw = nil
    get_mac_result = "unknown"
    logged_actions = {}

  it "tagué : extrait VLAN + IP, renvoie NF_ACCEPT", ->
    l2_result   = { vlan: 100 }
    payload_raw = string.rep "\0", 28
    ip_result   = { version: 4, src: "\10\0\0\1" }
    v = w.handle_packet nil, nil, 1
    assert.equals 1, v        -- NF_ACCEPT

  it "untagged adjacent (MAC trame == MAC connue) : apprend 0, NF_ACCEPT", ->
    l2_result      = { vlan: nil, mac_src: "aa:bb:cc:dd:ee:ff" }
    get_mac_result = "aa:bb:cc:dd:ee:ff"
    payload_raw    = string.rep "\0", 28
    ip_result      = { version: 4, src: "\10\0\0\1" }
    v = w.handle_packet nil, nil, 1
    assert.equals 1, v        -- NF_ACCEPT
    assert.is_true has_action "vlan_learned"
    assert.is_false has_action "untagged_skip_nonadjacent"

  it "untagged MAC connue inconnue : fallback apprend 0", ->
    l2_result      = { vlan: nil, mac_src: "aa:bb:cc:dd:ee:ff" }
    get_mac_result = "unknown"
    payload_raw    = string.rep "\0", 28
    ip_result      = { version: 4, src: "\10\0\0\1" }
    v = w.handle_packet nil, nil, 1
    assert.equals 1, v
    assert.is_true has_action "vlan_learned"

  it "untagged boucle routée (MAC trame != MAC connue) : ignore, NF_ACCEPT sans apprendre", ->
    l2_result      = { vlan: nil, mac_src: "00:11:22:33:44:55" }  -- passerelle
    get_mac_result = "aa:bb:cc:dd:ee:ff"                          -- vraie MAC du client
    payload_raw    = string.rep "\0", 28
    ip_result      = { version: 4, src: "\10\0\0\1" }
    v = w.handle_packet nil, nil, 1
    assert.equals 1, v             -- NF_ACCEPT (fail-open)
    assert.is_true  has_action "untagged_skip_nonadjacent"
    assert.is_false has_action "vlan_learned"

  it "tagué (vlan > 0) : apprend inconditionnellement même si MAC diffère", ->
    l2_result      = { vlan: 99, mac_src: "00:11:22:33:44:55" }
    get_mac_result = "aa:bb:cc:dd:ee:ff"
    payload_raw    = string.rep "\0", 28
    ip_result      = { version: 4, src: "\10\0\0\1" }
    v = w.handle_packet nil, nil, 1
    assert.equals 1, v
    assert.is_true  has_action "vlan_learned"
    assert.is_false has_action "untagged_skip_nonadjacent"

  it "payload absent → NF_ACCEPT (fail-open, filtrage délégué au serveur DoH)", ->
    l2_result   = { vlan: 100 }
    payload_raw = nil
    v = w.handle_packet nil, nil, 1
    assert.equals 1, v        -- NF_ACCEPT toujours

  it "parse IP échoué → NF_ACCEPT (fail-open)", ->
    l2_result   = { vlan: 100 }
    payload_raw = string.rep "\0", 28
    ip_result   = nil
    v = w.handle_packet nil, nil, 1
    assert.equals 1, v
