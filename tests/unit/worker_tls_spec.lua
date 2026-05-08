return describe("worker_tls helpers", function()
  local sni_logger = require("worker_tls")
  describe("normalize_sni", function()
    it("met en minuscules et retire les points finaux", function()
      assert.equals("example.com", sni_logger.normalize_sni("ExAmPle.CoM."))
      return assert.equals("example.com", sni_logger.normalize_sni("example.com.."))
    end)
    return it("retourne nil si entrée vide", function()
      assert.is_nil(sni_logger.normalize_sni(nil))
      return assert.is_nil(sni_logger.normalize_sni(""))
    end)
  end)
  return describe("protocol_in_scope", function()
    it("accepte both pour tcp et quic(udp)", function()
      local policy = {
        protocols = "both"
      }
      assert.is_true(sni_logger.protocol_in_scope(policy, "tcp"))
      return assert.is_true(sni_logger.protocol_in_scope(policy, "udp"))
    end)
    return it("filtre selon tcp-only/quic-only", function()
      assert.is_true(sni_logger.protocol_in_scope({
        protocols = "tcp-only"
      }, "tcp"))
      assert.is_false(sni_logger.protocol_in_scope({
        protocols = "tcp-only"
      }, "udp"))
      assert.is_true(sni_logger.protocol_in_scope({
        protocols = "quic-only"
      }, "udp"))
      return assert.is_false(sni_logger.protocol_in_scope({
        protocols = "quic-only"
      }, "tcp"))
    end)
  end)
end)
