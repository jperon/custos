local backend = require("ipparse.lib.crypto.backend.lunatik")
local bin2hex
bin2hex = function(s)
  return s:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end)
end
local hex_to_bin
hex_to_bin = function(hex)
  return hex:gsub("..", function(cc)
    return string.char(tonumber(cc, 16))
  end)
end
local pass = 0
local total = 0
local test
test = function(name, fn)
  total = total + 1
  local ok, err = pcall(fn)
  if ok then
    pass = pass + 1
    print("PASS\t" .. tostring(name))
    return 
  end
  print("FAIL\t" .. tostring(name) .. "\t" .. tostring(err))
  return error(err)
end
test("lunatik-kernel: construct_nonce pn=2 (RFC 9001 A.3)", function()
  local iv = hex_to_bin("fa044b2f42a3fd3b46fb255c")
  local nonce = backend.construct_nonce(iv, 2)
  return assert(bin2hex(nonce) == "fa044b2f42a3fd3b46fb255e", "nonce mismatch: " .. tostring(bin2hex(nonce)))
end)
test("lunatik-kernel: GCM encrypt empty plaintext (NIST)", function()
  local key = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  local nonce = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  local ct = backend.aes_128_gcm_encrypt(key, nonce, "", "")
  assert(#ct == 16, "ciphertext should be 16-byte tag only")
  return assert(bin2hex(ct) == "58e2fccefa7e3061367f1d57a4e7455a", "tag mismatch: " .. tostring(bin2hex(ct)))
end)
test("lunatik-kernel: GCM decrypt empty plaintext (NIST)", function()
  local key = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  local nonce = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  local tag = hex_to_bin("58e2fccefa7e3061367f1d57a4e7455a")
  local pt, err = backend.aes_128_gcm_decrypt(key, nonce, tag, "")
  assert(err == nil, "unexpected decrypt error: " .. tostring(tostring(err)))
  return assert(pt == "", "plaintext should be empty")
end)
test("lunatik-kernel: GCM decrypt fails on bad tag", function()
  local key = "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42"
  local nonce = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  local ct = backend.aes_128_gcm_encrypt(key, nonce, "test data...!!!!", "aad")
  local bad_ct = ct:sub(1, #ct - 1) .. string.char((string.byte(ct, #ct) + 1) % 256)
  local pt, err = backend.aes_128_gcm_decrypt(key, nonce, bad_ct, "aad")
  assert(pt == nil, "expected nil on bad tag")
  return assert(err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: " .. tostring(tostring(err)))
end)
return print("  --> lib.crypto.lunatik.kernel: " .. tostring(pass) .. "/" .. tostring(total))
