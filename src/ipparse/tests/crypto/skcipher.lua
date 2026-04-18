--
-- SPDX-FileCopyrightText: (c) 2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

local skcipher = require("crypto.skcipher")
local util = require("util")
local test = util.test
local hex2bin = util.hex2bin
local bin2hex = util.bin2hex

test("SKCIPHER AES-128-CBC encrypt", function()
	local c = skcipher.new"cbc(aes)"
	-- The plaintext must be a multiple of the block size (16 bytes for AES-128)
	-- If the plaintext is not a multiple of the block size, it should be padded.
	local plaintext = "This is a test!!"
	local ciphertext = hex2bin"d05e07d91a4b4cd10951f8cf195f27b5"
	c:setkey"0123456789abcdef"

	local result = c:encrypt("fedcba9876543210", plaintext)
	assert(result == ciphertext, "Cipher text mismatch: " .. bin2hex(result) .. " expected: " .. bin2hex(ciphertext))
end)

test("SKCIPHER AES-128-CBC decrypt", function()
	local c = skcipher.new"cbc(aes)"
	local plaintext = "This is a test!!"
	local ciphertext = hex2bin"d05e07d91a4b4cd10951f8cf195f27b5"
	c:setkey"0123456789abcdef"

	local result = c:decrypt("fedcba9876543210", ciphertext)
	assert(result == plaintext, "Plain text mismatch: " .. tostring(result) .. " expected: " .. plaintext)
end)

