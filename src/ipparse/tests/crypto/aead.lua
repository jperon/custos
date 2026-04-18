--
-- SPDX-FileCopyrightText: (c) 2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--
local aead = require"crypto.aead"
local util = require("util")
local test = util.test
local hex2bin = util.hex2bin


test("AEAD AES-128-GCM encrypt", function()
	local c = aead.new"gcm(aes)"
	c:setkey"0123456789abcdef"
	c:setauthsize(16)

	local expected = hex2bin"95be1ddc3dd13cdd2d8ffcc391561ade661d5b696ede5a918e"
	-- The encrypt method returns ciphertext_with_tag, tag_length. We only need the first one for this assertion.
	local result = c:encrypt("abcdefghijkl", "plaintext", "0123456789abcdef")
	assert(result == expected)
end)

test("AEAD AES-128-GCM decrypt", function()
	local c = aead.new"gcm(aes)"
	c:setkey"0123456789abcdef"
	c:setauthsize(16)

	local ciphertext = hex2bin"95be1ddc3dd13cdd2d8ffcc391561ade661d5b696ede5a918e"
	local expected = "plaintext"
	local result = c:decrypt("abcdefghijkl", ciphertext, "0123456789abcdef")
	assert(result == expected)
end)

test("AEAD AES-128-GCM ivsize and authsize", function()
	local c = aead.new"gcm(aes)"
	c:setauthsize(16)
	assert(c:authsize() == 16, "Auth size for AES-128-GCM should be 16 bytes")
end)

test("AEAD AES-128-GCM with AAD", function()
	local c = aead.new"gcm(aes)"
	c:setkey"0123456789abcdef"
	c:setauthsize(16)

	local aad = "additional authenticated data"
	local expected = hex2bin"95be1ddc3dd13cdd2d8ffcc391561ade661d5b696ede5a918e"
	-- The encrypt method returns ciphertext_with_tag, tag_length. We only need the first one for this assertion.
	local result = c:encrypt("abcdefghijkl", "plaintext", "0123456789abcdef", aad)
	assert(result == expected, "Ciphertext with AAD mismatch: " .. util.bin2hex(result) .. " expected: " .. util.bin2hex(expected))
end)
