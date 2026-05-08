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
