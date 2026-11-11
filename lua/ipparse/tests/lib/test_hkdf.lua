local util = require("ipparse.lib.util")
local test
test = util.test
local hkdf, hkdf_extract, hkdf_expand, hkdf_expand_label, hkdf_expand_bin, hkdf_expand_label_bin, hex_to_bin
do
  local _obj_0 = require("ipparse.lib.hkdf")
  hkdf, hkdf_extract, hkdf_expand, hkdf_expand_label, hkdf_expand_bin, hkdf_expand_label_bin, hex_to_bin = _obj_0.hkdf, _obj_0.hkdf_extract, _obj_0.hkdf_expand, _obj_0.hkdf_expand_label, _obj_0.hkdf_expand_bin, _obj_0.hkdf_expand_label_bin, _obj_0.hex_to_bin
end
local bin_to_hex
bin_to_hex = function(s)
  return (s:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end))
end
test("hkdf: RFC 5869 test case 1", function()
  local result = hkdf(hex_to_bin("000102030405060708090a0b0c"), hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), hex_to_bin("f0f1f2f3f4f5f6f7f8f9"), 42)
  local expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
  return assert(result == expected, "TC1 mismatch:\ngot: " .. tostring(result) .. "\nexp: " .. tostring(expected))
end)
test("hkdf: RFC 5869 test case 3 (no salt/info)", function()
  local result = hkdf("", hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), "", 42)
  local expected = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
  return assert(result == expected, "TC3 mismatch")
end)
local dcid_hex = "8394c8f03e515708"
local quic_salt = hex_to_bin("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
test("hkdf: QUIC initial_secret (RFC 9001 §A.1)", function()
  local init_secret = hkdf_extract(quic_salt, hex_to_bin(dcid_hex))
  local csecret = hkdf_expand_label(init_secret, "client in", "", 32)
  local expected = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
  return assert(csecret == expected, "client_initial_secret mismatch:\ngot: " .. tostring(csecret) .. "\nexp: " .. tostring(expected))
end)
test("hkdf: QUIC client quic key (RFC 9001 §A.1)", function()
  local init_secret = hkdf_extract(quic_salt, hex_to_bin(dcid_hex))
  local csecret = hkdf_expand_label(init_secret, "client in", "", 32)
  local key = hkdf_expand_label(hex_to_bin(csecret), "quic key", "", 16)
  local expected = "1f369613dd76d5467730efcbe3b1a22d"
  return assert(key == expected, "client quic key mismatch:\ngot: " .. tostring(key) .. "\nexp: " .. tostring(expected))
end)
test("hkdf: QUIC client quic iv (RFC 9001 §A.1)", function()
  local init_secret = hkdf_extract(quic_salt, hex_to_bin(dcid_hex))
  local csecret = hkdf_expand_label(init_secret, "client in", "", 32)
  local iv = hkdf_expand_label(hex_to_bin(csecret), "quic iv", "", 12)
  local expected = "fa044b2f42a3fd3b46fb255c"
  return assert(iv == expected, "client quic iv mismatch:\ngot: " .. tostring(iv) .. "\nexp: " .. tostring(expected))
end)
test("hkdf: QUIC client hp key (RFC 9001 §A.1)", function()
  local init_secret = hkdf_extract(quic_salt, hex_to_bin(dcid_hex))
  local csecret = hkdf_expand_label(init_secret, "client in", "", 32)
  local hp = hkdf_expand_label(hex_to_bin(csecret), "quic hp", "", 16)
  local expected = "9f50449e04a0e810283a1e9933adedd2"
  return assert(hp == expected, "client hp key mismatch:\ngot: " .. tostring(hp) .. "\nexp: " .. tostring(expected))
end)
test("hkdf: QUIC server quic key (RFC 9001 §A.1)", function()
  local init_secret = hkdf_extract(quic_salt, hex_to_bin(dcid_hex))
  local ssecret = hkdf_expand_label(init_secret, "server in", "", 32)
  local key = hkdf_expand_label(hex_to_bin(ssecret), "quic key", "", 16)
  local expected = "cf3a5331653c364c88f0f379b6067e37"
  return assert(key == expected, "server quic key mismatch:\ngot: " .. tostring(key) .. "\nexp: " .. tostring(expected))
end)
local sha_mod = nil
local sha_is_hex = false
local ok, m = pcall(require, "ipparse.lib.sha")
if ok and m and m.hmac and m.sha256 then
  sha_mod = m
else
  ok, m = pcall(require, "ipparse.lib.sha2")
  if ok and m and m.hmac and m.sha256 then
    sha_mod = m
    sha_is_hex = true
  end
end
if sha_mod then
  local ref_hmac_bin
  ref_hmac_bin = function(key, msg)
    local d = sha_mod.hmac(sha_mod.sha256, key, msg)
    if sha_is_hex then
      return sha_mod.hex_to_bin(d)
    else
      return d
    end
  end
  test("hkdf: shash-only backend expands RFC 5869 test case 1", function()
    local loaded_before = {
      crypto = package.loaded["crypto"],
      crypto_hkdf = package.loaded["crypto.hkdf"],
      hkdf = package.loaded["ipparse.lib.hkdf"]
    }
    local preload_before = {
      crypto = package.preload["crypto"],
      crypto_hkdf = package.preload["crypto.hkdf"]
    }
    local run
    run = function()
      package.loaded["crypto.hkdf"] = nil
      package.preload["crypto.hkdf"] = function()
        return error("absent")
      end
      package.loaded["crypto"] = {
        shash = function(alg)
          assert(alg == "hmac(sha256)", "unexpected shash algorithm: " .. tostring(alg))
          local key = nil
          return {
            setkey = function(self, k)
              key = k
            end,
            digest = function(self, msg)
              return ref_hmac_bin(key, msg)
            end
          }
        end
      }
      package.loaded["ipparse.lib.hkdf"] = nil
      local shash_hkdf = require("ipparse.lib.hkdf")
      local result = shash_hkdf.hkdf(shash_hkdf.hex_to_bin("000102030405060708090a0b0c"), shash_hkdf.hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), shash_hkdf.hex_to_bin("f0f1f2f3f4f5f6f7f8f9"), 42)
      local expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
      return assert(result == expected, "shash TC1 mismatch:\ngot: " .. tostring(result) .. "\nexp: " .. tostring(expected))
    end
    local err
    ok, err = pcall(run)
    package.loaded["crypto"] = loaded_before.crypto
    package.loaded["crypto.hkdf"] = loaded_before.crypto_hkdf
    package.loaded["ipparse.lib.hkdf"] = loaded_before.hkdf
    package.preload["crypto"] = preload_before.crypto
    package.preload["crypto.hkdf"] = preload_before.crypto_hkdf
    if not (ok) then
      return error(err)
    end
  end)
  test("hkdf: crypto.hkdf transform is created once", function()
    local loaded_before = {
      crypto = package.loaded["crypto"],
      crypto_hkdf = package.loaded["crypto.hkdf"],
      hkdf = package.loaded["ipparse.lib.hkdf"]
    }
    local preload_before = {
      crypto = package.preload["crypto"],
      crypto_hkdf = package.preload["crypto.hkdf"]
    }
    local new_count = 0
    local make_stub
    make_stub = function()
      new_count = new_count + 1
      local obj = { }
      obj.extract = function(self, salt, ikm)
        return ref_hmac_bin(salt, ikm)
      end
      obj.expand = function(self, prk, info, len)
        local parts, t, i, total = { }, "", 1, 0
        while total < len do
          t = ref_hmac_bin(prk, t .. info .. string.char(i))
          parts[i] = t
          total = total + #t
          i = i + 1
        end
        return table.concat(parts):sub(1, len)
      end
      obj.hkdf = function(self, salt, ikm, info, len)
        local prk = self:extract(salt, ikm)
        return self:expand(prk, info, len)
      end
      return obj
    end
    local run
    run = function()
      package.loaded["crypto.hkdf"] = nil
      package.preload["crypto.hkdf"] = function()
        return {
          new = make_stub
        }
      end
      package.loaded["ipparse.lib.hkdf"] = nil
      local h = require("ipparse.lib.hkdf")
      local prk = h.hkdf_extract(h.hex_to_bin("000102030405060708090a0b0c"), h.hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
      h.hkdf_expand(prk, "", 32)
      h.hkdf_expand_label(prk, "label", "", 16)
      return assert(new_count == 1, "crypto.hkdf.new should be called once, got " .. tostring(new_count))
    end
    local err
    ok, err = pcall(run)
    package.loaded["crypto"] = loaded_before.crypto
    package.loaded["crypto.hkdf"] = loaded_before.crypto_hkdf
    package.loaded["ipparse.lib.hkdf"] = loaded_before.hkdf
    package.preload["crypto"] = preload_before.crypto
    package.preload["crypto.hkdf"] = preload_before.crypto_hkdf
    if not (ok) then
      return error(err)
    end
  end)
  test("hkdf: shash transform is created once", function()
    local loaded_before = {
      crypto = package.loaded["crypto"],
      crypto_hkdf = package.loaded["crypto.hkdf"],
      hkdf = package.loaded["ipparse.lib.hkdf"]
    }
    local preload_before = {
      crypto = package.preload["crypto"],
      crypto_hkdf = package.preload["crypto.hkdf"]
    }
    local shash_count = 0
    local run
    run = function()
      package.loaded["crypto.hkdf"] = nil
      package.preload["crypto.hkdf"] = function()
        return error("absent")
      end
      package.loaded["crypto"] = {
        shash = function(alg)
          assert(alg == "hmac(sha256)", "unexpected shash algorithm: " .. tostring(alg))
          shash_count = shash_count + 1
          local key = nil
          return {
            setkey = function(self, k)
              key = k
            end,
            digest = function(self, msg)
              return ref_hmac_bin(key, msg)
            end
          }
        end
      }
      package.loaded["ipparse.lib.hkdf"] = nil
      local h = require("ipparse.lib.hkdf")
      local prk = h.hkdf_extract(h.hex_to_bin("000102030405060708090a0b0c"), h.hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
      h.hkdf_expand(prk, "", 32)
      h.hkdf_expand_label(prk, "label", "", 16)
      return assert(shash_count == 1, "crypto.shash should be constructed once, got " .. tostring(shash_count))
    end
    local err
    ok, err = pcall(run)
    package.loaded["crypto"] = loaded_before.crypto
    package.loaded["crypto.hkdf"] = loaded_before.crypto_hkdf
    package.loaded["ipparse.lib.hkdf"] = loaded_before.hkdf
    package.preload["crypto"] = preload_before.crypto
    package.preload["crypto.hkdf"] = preload_before.crypto_hkdf
    if not (ok) then
      return error(err)
    end
  end)
end
test("hkdf: RFC 5869 test case 2", function()
  local result = hkdf(hex_to_bin("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"), hex_to_bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"), hex_to_bin("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), 82)
  local expected = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
  return assert(result == expected, "TC2 mismatch:\ngot: " .. tostring(result) .. "\nexp: " .. tostring(expected))
end)
test("hkdf: QUIC test vector with DCID 0001020304050607", function()
  local salt = hex_to_bin("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
  local dcid = hex_to_bin("0001020304050607")
  local init_secret = hkdf_extract(salt, dcid)
  local csecret = hkdf_expand_label(init_secret, "client in", "", 32)
  local key = hkdf_expand_label(hex_to_bin(csecret), "quic key", "", 16)
  local expected = "b14b918124fda5c8d79847602fa3520b"
  return assert(key == expected, "quic key mismatch:\ngot: " .. tostring(key) .. "\nexp: " .. tostring(expected))
end)
test("hkdf: hkdf_expand_bin matches hkdf_expand", function()
  local prk = hkdf_extract(quic_salt, hex_to_bin(dcid_hex))
  local info = hex_to_bin("f0f1f2f3f4f5f6f7f8f9")
  local bin = hkdf_expand_bin(prk, info, 42)
  assert(#bin == 42, "binary output must be 42 bytes, got " .. tostring(#bin))
  return assert(bin_to_hex(bin) == hkdf_expand(prk, info, 42), "binary/hex expand mismatch")
end)
test("hkdf: hkdf_expand_label_bin matches hkdf_expand_label", function()
  local prk = hkdf_extract(quic_salt, hex_to_bin(dcid_hex))
  local bin = hkdf_expand_label_bin(prk, "client in", "", 32)
  assert(#bin == 32, "binary output must be 32 bytes, got " .. tostring(#bin))
  return assert(bin_to_hex(bin) == hkdf_expand_label(prk, "client in", "", 32), "binary/hex label mismatch")
end)
return util.summary("hkdf")
