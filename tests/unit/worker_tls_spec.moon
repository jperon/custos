-- Stubs nft pour tester apply_nft_allow sans infrastructure réseau
package.loaded["nft_queue"] or= {
  cmd_for: (kind, src, dst, rule_id, timeout) ->
    "add element bridge dns-filter-bridge #{kind}_allowed { #{src} . #{dst} timeout #{timeout} }"
}
package.loaded["nft"] or= {
  run_cmd: (cmd, opts) -> true, nil
}

describe "worker_tls helpers", ->
  sni_logger = require "worker_tls"

  describe "normalize_sni", ->
    it "met en minuscules et retire les points finaux", ->
      assert.equals "example.com", sni_logger.normalize_sni "ExAmPle.CoM."
      assert.equals "example.com", sni_logger.normalize_sni "example.com.."

    it "retourne nil si entrée vide", ->
      assert.is_nil sni_logger.normalize_sni nil
      assert.is_nil sni_logger.normalize_sni ""

  describe "protocol_in_scope", ->
    it "accepte both pour tcp et quic(udp)", ->
      policy = { protocols: "both" }
      assert.is_true sni_logger.protocol_in_scope policy, "tcp"
      assert.is_true sni_logger.protocol_in_scope policy, "udp"

    it "filtre selon tcp-only/quic-only", ->
      assert.is_true sni_logger.protocol_in_scope { protocols: "tcp-only" }, "tcp"
      assert.is_false sni_logger.protocol_in_scope { protocols: "tcp-only" }, "udp"
      assert.is_true sni_logger.protocol_in_scope { protocols: "quic-only" }, "udp"
      assert.is_false sni_logger.protocol_in_scope { protocols: "quic-only" }, "tcp"

    it "nil policy → false", ->
      assert.is_false sni_logger.protocol_in_scope nil, "tcp"

    it "protocole inconnu → false", ->
      assert.is_false sni_logger.protocol_in_scope { protocols: "tcp-only" }, "quic"

  describe "apply_nft_allow", ->
    it "IPv4 pair valide → true", ->
      ok, err = sni_logger.apply_nft_allow "192.168.1.1", "8.8.8.8", nil, {}, "r_test"
      assert.is_true ok

    it "IPv4 avec MAC valide → true", ->
      ok, _ = sni_logger.apply_nft_allow "192.168.1.1", "8.8.8.8", "aa:bb:cc:dd:ee:ff", {}, "r_test"
      assert.is_true ok

    it "src_ip nil → false (invalid_ip_pair)", ->
      ok, err = sni_logger.apply_nft_allow nil, "8.8.8.8", nil, {}, "r_test"
      assert.is_false ok

    it "dst_ip nil → false (invalid_ip_pair)", ->
      ok, err = sni_logger.apply_nft_allow "192.168.1.1", nil, nil, {}, "r_test"
      assert.is_false ok

    it "src_ip 'unknown' → false (invalid_ip_pair)", ->
      ok, err = sni_logger.apply_nft_allow "unknown", "8.8.8.8", nil, {}, "r_test"
      assert.is_false ok

    it "mélange IPv4/IPv6 → false (family_mismatch)", ->
      ok, err = sni_logger.apply_nft_allow "192.168.1.1", "2001:db8::1", nil, {}, "r_test"
      assert.is_false ok

    it "IPv6 pair valide → true", ->
      ok, _ = sni_logger.apply_nft_allow "2001:db8::1", "2001:db8::2", nil, {}, "r_test"
      assert.is_true ok

    it "MAC 'unknown' ignoré (pas de commande MAC)", ->
      ok, _ = sni_logger.apply_nft_allow "192.168.1.1", "8.8.8.8", "unknown", {}, "r_test"
      assert.is_true ok

    it "MAC 00:00:00:00:00:00 ignoré", ->
      ok, _ = sni_logger.apply_nft_allow "192.168.1.1", "8.8.8.8", "00:00:00:00:00:00", {}, "r_test"
      assert.is_true ok
