local util = require("ipparse.lib.util")
local test, summary
test, summary = util.test, util.summary
local hex_to_bin
hex_to_bin = require("ipparse.lib.hkdf").hex_to_bin
local calls = {
  aead_new = 0,
  aead_close = 0,
  ecb_new = 0,
  ecb_close = 0
}
local mk_aead
mk_aead = function()
  local key, authsize = nil, nil
  return {
    setkey = function(self, k)
      key = k
    end,
    setauthsize = function(self, n)
      authsize = n
    end,
    encrypt = function(self, nonce, plaintext, aad)
      if aad == nil then
        aad = ""
      end
      assert(key == string.rep("\x11", 16), "unexpected test key")
      assert(authsize == 16, "authsize must be 16")
      assert(#nonce == 12, "nonce length should be 12")
      return "ct:" .. plaintext .. "|aad:" .. aad .. "|tag:" .. string.rep("T", 16)
    end,
    decrypt = function(self, nonce, ciphertext_with_tag, aad)
      if aad == nil then
        aad = ""
      end
      if ciphertext_with_tag:sub(1, 8) == "AUTHFAIL" then
        error("EBADMSG")
      end
      if ciphertext_with_tag:sub(1, 6) == "BROKEN" then
        error("EINVAL")
      end
      return "pt:" .. ciphertext_with_tag .. "|aad:" .. aad
    end,
    __close = function(self)
      calls.aead_close = calls.aead_close + 1
    end
  }
end
local mk_ecb
mk_ecb = function()
  local key = nil
  return {
    setkey = function(self, k)
      key = k
    end,
    encryptblock = function(self, block)
      assert(key == string.rep("\x22", 16), "unexpected ECB key")
      assert(#block == 16, "ECB block must be 16 bytes")
      return "Z" .. block:sub(2)
    end,
    __close = function(self)
      calls.ecb_close = calls.ecb_close + 1
    end
  }
end
package.preload.crypto = function()
  return {
    aead = function(name)
      assert(name == "gcm(aes)", "unexpected AEAD algorithm: " .. tostring(name))
      calls.aead_new = calls.aead_new + 1
      return mk_aead()
    end
  }
end
package.preload["crypto.ecb"] = function()
  return {
    new = function()
      calls.ecb_new = calls.ecb_new + 1
      return mk_ecb()
    end
  }
end
package.loaded["ipparse.lib.crypto.backend.lunatik"] = nil
local b = require("ipparse.lib.crypto.backend.lunatik")
test("lunatik: construct_nonce pn=0 returns iv unchanged", function()
  local iv = hex_to_bin("fa044b2f42a3fd3b46fb255c")
  return assert(b.construct_nonce(iv, 0) == iv, "nonce should equal iv when pn=0")
end)
test("lunatik: construct_nonce pn=1 XORs last byte", function()
  local iv = hex_to_bin("fa044b2f42a3fd3b46fb255c")
  local nonce = b.construct_nonce(iv, 1)
  assert(nonce:sub(1, 11) == iv:sub(1, 11), "first 11 bytes unchanged")
  return assert(nonce:byte(12) == 0x5d, "last byte 0x5c XOR 0x01 = 0x5d")
end)
test("lunatik: AES-128-GCM encrypt uses crypto.aead", function()
  local key = string.rep("\x11", 16)
  local nonce = string.rep("\x00", 12)
  local out = b.aes_128_gcm_encrypt(key, nonce, "hello", "aad")
  return assert(out == ("ct:hello|aad:aad|tag:" .. string.rep("T", 16)), "unexpected ciphertext")
end)
test("lunatik: AES-128-GCM decrypt returns plaintext", function()
  local key = string.rep("\x11", 16)
  local nonce = string.rep("\x00", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("cipher" .. string.rep("T", 16)), "aad")
  assert(err == nil, "unexpected decrypt error: " .. tostring(tostring(err)))
  return assert(pt == ("pt:cipher" .. string.rep("T", 16) .. "|aad:aad"), "unexpected plaintext")
end)
test("lunatik: AES-128-GCM decrypt maps EBADMSG to nil,error", function()
  local key = string.rep("\x11", 16)
  local nonce = string.rep("\x00", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("AUTHFAIL" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on auth failure")
  return assert(err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM ciphertext too short returns nil", function()
  local key = string.rep("\x11", 16)
  local nonce = string.rep("\x00", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, "short", "")
  assert(pt == nil, "pt should be nil")
  return assert(err ~= nil, "err should be provided")
end)
test("lunatik: AES-128-GCM decrypt raises on non-auth error", function()
  local key = string.rep("\x11", 16)
  local nonce = string.rep("\x00", 12)
  local ok, err = pcall(b.aes_128_gcm_decrypt, key, nonce, ("BROKEN" .. string.rep("T", 16)), "")
  assert(not ok, "decrypt should raise on non-auth failure")
  return assert(tostring(err):find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-ECB encrypt uses crypto.ecb", function()
  local key = string.rep("\x22", 16)
  local block = string.rep("\x33", 16)
  local out = b.aes_128_ecb_block(key, block)
  assert(#out == 16, "output must be 16 bytes")
  return assert(out:byte(1) == string.byte("Z"), "first byte should be transformed by stub")
end)
return summary("lib.crypto.lunatik")
