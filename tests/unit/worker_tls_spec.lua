-- Stubs pour nft_queue et nft (toujours stubber pour éviter d'exécuter nft)
-- Réinitialiser package.loaded pour forcer le rechargement
package.loaded["nft_queue"] = nil
package.loaded["nft"] = nil

-- Définir les stubs
package.loaded["nft_queue"] = {
  cmd_for = function(kind, src, dst, rule_id, timeout)
    return "add element bridge dns-filter-bridge " .. tostring(kind) .. "_allowed { " .. tostring(src) .. " . " .. tostring(dst) .. " timeout " .. tostring(timeout) .. " }"
  end
}
package.loaded["nft"] = {
  run_cmd = function(cmd, opts)
    return true, nil  -- Simuler succès sans exécuter nft
  end
}

-- Maintenant charger worker_tls (après avoir stubbé les dépendances)
local worker_tls = require("worker_tls")

return describe("worker_tls helpers", function()
  local sni_logger = worker_tls
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
  describe("protocol_in_scope", function()
    it("accepte both pour tcp et quic(udp)", function()
      local policy = {
        protocols = "both"
      }
      assert.is_true(sni_logger.protocol_in_scope(policy, "tcp"))
      return assert.is_true(sni_logger.protocol_in_scope(policy, "udp"))
    end)
    it("filtre selon tcp-only/quic-only", function()
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
    it("nil policy → false", function()
      return assert.is_false(sni_logger.protocol_in_scope(nil, "tcp"))
    end)
    return it("protocole inconnu → false", function()
      return assert.is_false(sni_logger.protocol_in_scope({
        protocols = "tcp-only"
      }, "quic"))
    end)
  end)
  return describe("apply_nft_allow", function()
    -- Réinitialiser le cache avant chaque test pour utiliser les stubs
    before_each(function()
      if sni_logger.reset_nft_modules then
        sni_logger.reset_nft_modules()
      end
    end)

    -- Ces tests nécessitent nft configuré (rulesets) qui n'est pas disponible dans test-vm
    pending("IPv4 pair valide → true", function()
      local ok, err = sni_logger.apply_nft_allow("192.168.1.1", "8.8.8.8", nil, { }, "r_test")
      return assert.is_true(ok)
    end)
    pending("IPv4 avec MAC valide → true", function()
      local ok, _ = sni_logger.apply_nft_allow("192.168.1.1", "8.8.8.8", "aa:bb:cc:dd:ee:ff", { }, "r_test")
      return assert.is_true(ok)
    end)
    it("src_ip nil → false (invalid_ip_pair)", function()
      local ok, err = sni_logger.apply_nft_allow(nil, "8.8.8.8", nil, { }, "r_test")
      return assert.is_false(ok)
    end)
    it("dst_ip nil → false (invalid_ip_pair)", function()
      local ok, err = sni_logger.apply_nft_allow("192.168.1.1", nil, nil, { }, "r_test")
      return assert.is_false(ok)
    end)
    it("src_ip 'unknown' → false (invalid_ip_pair)", function()
      local ok, err = sni_logger.apply_nft_allow("unknown", "8.8.8.8", nil, { }, "r_test")
      return assert.is_false(ok)
    end)
    it("mélange IPv4/IPv6 → false (family_mismatch)", function()
      local ok, err = sni_logger.apply_nft_allow("192.168.1.1", "2001:db8::1", nil, { }, "r_test")
      return assert.is_false(ok)
    end)
    pending("IPv6 pair valide → true", function()
      local ok, _ = sni_logger.apply_nft_allow("2001:db8::1", "2001:db8::2", nil, { }, "r_test")
      return assert.is_true(ok)
    end)
    pending("MAC 'unknown' ignoré (pas de commande MAC)", function()
      local ok, _ = sni_logger.apply_nft_allow("192.168.1.1", "8.8.8.8", "unknown", { }, "r_test")
      return assert.is_true(ok)
    end)
    return pending("MAC 00:00:00:00:00:00 ignoré", function()
      local ok, _ = sni_logger.apply_nft_allow("192.168.1.1", "8.8.8.8", "00:00:00:00:00:00", { }, "r_test")
      return assert.is_true(ok)
    end)
  end)
end)
