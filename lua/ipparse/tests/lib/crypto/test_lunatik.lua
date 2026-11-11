local util = require("ipparse.lib.util")
local test, summary
test, summary = util.test, util.summary
local hex_to_bin
hex_to_bin = require("ipparse.lib.hkdf").hex_to_bin
local preload_before = {
  crypto = package.preload.crypto,
  crypto_ecb = package.preload["crypto.ecb"]
}
local loaded_before = {
  crypto = package.loaded["crypto"],
  crypto_ecb = package.loaded["crypto.ecb"],
  backend = package.loaded["ipparse.lib.crypto.backend.lunatik"]
}
local loaded_keys_before = { }
for k in pairs(package.loaded) do
  loaded_keys_before[k] = true
end
local calls = {
  aead_new = 0,
  aead_close = 0,
  aead_setkey = 0,
  ecb_new = 0,
  ecb_close = 0
}
local mk_aead
mk_aead = function()
  local key, authsize = nil, nil
  return {
    setkey = function(self, k)
      calls.aead_setkey = calls.aead_setkey + 1
      key = k
    end,
    setauthsize = function(self, n)
      authsize = n
    end,
    encrypt = function(self, nonce, plaintext, aad)
      if aad == nil then
        aad = ""
      end
      assert(key == string.rep("\017", 16), "unexpected test key")
      assert(authsize == 16, "authsize must be 16")
      assert(#nonce == 12, "nonce length should be 12")
      return "ct:" .. plaintext .. "|aad:" .. aad .. "|tag:" .. string.rep("T", 16)
    end,
    decrypt = function(self, nonce, ciphertext_with_tag, aad)
      if aad == nil then
        aad = ""
      end
      local prefix = ciphertext_with_tag:sub(1, 8)
      if prefix == "AUTHFAIL" then
        error("EBADMSG")
      end
      if prefix == "AUTHMIN1" then
        error("-EBADMSG")
      end
      if prefix == "AUTHNUM1" then
        error("-74")
      end
      if prefix == "AUTHNUM3" then
        error("-174")
      end
      if prefix == "AUTHNUM4" then
        error("-740")
      end
      if prefix == "NOTAUTH2" then
        error("-22")
      end
      if ciphertext_with_tag:sub(1, 6) == "BROKEN" then
        error("EINVAL")
      end
      if prefix == "PLAINBAD" then
        return "EBADMSG"
      end
      if prefix == "NEWFAIL1" then
        return nil, "EBADMSG"
      end
      if prefix == "NEWFAIL2" then
        return nil, "-EBADMSG"
      end
      if prefix == "NEWFAIL3" then
        return nil, "-74"
      end
      if prefix == "NEWFAIL4" then
        return nil, "unknown"
      end
      if prefix == "NEWERR01" then
        return nil, "EINVAL"
      end
      if prefix == "NEWERR02" then
        return nil, "-174"
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
    encrypt = function(self, iv, block)
      assert(key == string.rep("\034", 16), "unexpected ECB key")
      assert(iv == "", "ECB expects an empty IV")
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
    end,
    skcipher = function(name)
      assert(name == "ecb(aes)", "unexpected skcipher algorithm: " .. tostring(name))
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
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local out = b.aes_128_gcm_encrypt(key, nonce, "hello", "aad")
  return assert(out == ("ct:hello|aad:aad|tag:" .. string.rep("T", 16)), "unexpected ciphertext")
end)
test("lunatik: AES-128-GCM decrypt returns plaintext", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("cipher" .. string.rep("T", 16)), "aad")
  assert(err == nil, "unexpected decrypt error: " .. tostring(tostring(err)))
  return assert(pt == ("pt:cipher" .. string.rep("T", 16) .. "|aad:aad"), "unexpected plaintext")
end)
test("lunatik: AES-128-GCM decrypt maps EBADMSG to nil,error", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("AUTHFAIL" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on auth failure")
  return assert(err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt maps -EBADMSG (pre-6.7 symbolic) to nil,error", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("AUTHMIN1" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on auth failure")
  return assert(err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt maps -74 (pre-6.7 numeric) to nil,error", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("AUTHNUM1" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on auth failure")
  return assert(err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt maps v5.1 nil,EBADMSG to nil,error", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("NEWFAIL1" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on auth failure")
  return assert(err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt maps v5.1 nil,-EBADMSG to nil,error", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("NEWFAIL2" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on auth failure")
  return assert(err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt maps v5.1 nil,-74 to nil,error", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("NEWFAIL3" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on auth failure")
  return assert(err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt maps v5.1 nil,unknown to decrypt failed", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("NEWFAIL4" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on failure")
  assert(err ~= "AES-128-GCM authentication failed (tag mismatch)", "unexpected auth error: " .. tostring(tostring(err)))
  return assert(tostring(err):find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt maps v5.1 nil,EINVAL to decrypt failed", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("NEWERR01" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on failure")
  assert(err ~= "AES-128-GCM authentication failed (tag mismatch)", "unexpected auth error: " .. tostring(tostring(err)))
  return assert(tostring(err):find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt does not treat v5.1 nil,-174 as EBADMSG", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("NEWERR02" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on failure")
  assert(err ~= "AES-128-GCM authentication failed (tag mismatch)", "unexpected auth error: " .. tostring(tostring(err)))
  return assert(tostring(err):find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt does not treat -174 as EBADMSG", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("AUTHNUM3" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on failure")
  assert(err ~= "AES-128-GCM authentication failed (tag mismatch)", "unexpected auth error: " .. tostring(tostring(err)))
  return assert(tostring(err):find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt does not treat -740 as EBADMSG", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("AUTHNUM4" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on failure")
  assert(err ~= "AES-128-GCM authentication failed (tag mismatch)", "unexpected auth error: " .. tostring(tostring(err)))
  return assert(tostring(err):find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt maps -22 (numeric EINVAL) to nil,error", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("NOTAUTH2" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on failure")
  assert(err ~= "AES-128-GCM authentication failed (tag mismatch)", "unexpected auth error: " .. tostring(tostring(err)))
  return assert(tostring(err):find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt returns plaintext equal to EBADMSG verbatim", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("PLAINBAD" .. string.rep("T", 16)), "")
  assert(err == nil, "unexpected decrypt error: " .. tostring(tostring(err)))
  return assert(pt == "EBADMSG", "plaintext should be returned verbatim, got: " .. tostring(tostring(pt)))
end)
test("lunatik: AES-128-GCM ciphertext too short returns nil", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, "short", "")
  assert(pt == nil, "pt should be nil")
  return assert(err ~= nil, "err should be provided")
end)
test("lunatik: AES-128-GCM decrypt returns nil,error on non-auth error", function()
  local key = string.rep("\017", 16)
  local nonce = string.rep("\000", 12)
  local pt, err = b.aes_128_gcm_decrypt(key, nonce, ("BROKEN" .. string.rep("T", 16)), "")
  assert(pt == nil, "pt should be nil on non-auth failure")
  return assert(tostring(err):find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: " .. tostring(tostring(err)))
end)
test("lunatik: AES-128-GCM decrypt reuses transform for same key", function()
  local key_a = string.rep("\020", 16)
  local key_b = string.rep("\021", 16)
  local nonce = string.rep("\000", 12)
  local before = calls.aead_setkey
  b.aes_128_gcm_decrypt(key_a, nonce, ("first" .. string.rep("T", 16)), "")
  b.aes_128_gcm_decrypt(key_a, nonce, ("second" .. string.rep("T", 16)), "")
  assert(calls.aead_setkey == before + 1, "same key should call setkey once, got " .. tostring(calls.aead_setkey - before))
  b.aes_128_gcm_decrypt(key_b, nonce, ("third" .. string.rep("T", 16)), "")
  return assert(calls.aead_setkey == before + 2, "a new key should call setkey once more, got " .. tostring(calls.aead_setkey - before))
end)
test("lunatik: AES-128-ECB encrypt uses crypto.skcipher", function()
  local key = string.rep("\034", 16)
  local block = string.rep("\051", 16)
  local out = b.aes_128_ecb_block(key, block)
  assert(#out == 16, "output must be 16 bytes")
  return assert(out:byte(1) == string.byte("Z"), "first byte should be transformed by stub")
end)
local leaked = { }
for k in pairs(package.loaded) do
  if not (loaded_keys_before[k]) then
    leaked[#leaked + 1] = k
  end
end
for _index_0 = 1, #leaked do
  local k = leaked[_index_0]
  package.loaded[k] = nil
end
package.preload.crypto = preload_before.crypto
package.preload["crypto.ecb"] = preload_before.crypto_ecb
package.loaded["crypto"] = loaded_before.crypto
package.loaded["crypto.ecb"] = loaded_before.crypto_ecb
package.loaded["ipparse.lib.crypto.backend.lunatik"] = loaded_before.backend
return summary("lib.crypto.lunatik")
