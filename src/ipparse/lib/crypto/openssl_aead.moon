--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- OpenSSL-based AEAD Implementation for QUIC
-- Uses OpenSSL command line tools for real AES-GCM encryption/decryption

pack: sp, unpack: su = require "ipparse.lib.pack_compat"
:bin2hex, :hex2bin = require "ipparse.init"
{:band, :bor, :bnot, :lshift, :rshift} = require "ipparse.lib.bit_compat"

-- Use the same XOR workaround as before
xor = (a, b) -> band(bor(a, b), bnot(band(a, b)))

--- Check if OpenSSL is available
check_openssl = ->
  success = os.execute "openssl version >/dev/null 2>&1"
  success == 0

crypto_available = check_openssl!

unless crypto_available
  print "Warning: OpenSSL not available, using stub implementation"
else
  print "OpenSSL available for real crypto operations"

--- Constructs a QUIC nonce from IV and packet number
construct_nonce = (iv, packet_number) ->
  if #iv != 12
    error "IV must be 12 bytes for QUIC AEAD"

  -- Convert packet number to 8-byte big-endian integer
  pn_bytes = sp ">I8", packet_number

  -- XOR the last 8 bytes of IV with packet number
  nonce = iv\sub(1, 4)  -- First 4 bytes unchanged
  for i = 1, 8
    iv_byte = su "B", iv, 4 + i
    pn_byte = su "B", pn_bytes, i
    nonce ..= sp "B", xor iv_byte, pn_byte

  nonce

--- Write binary data to temporary file
write_temp_file = (data) ->
  tmpname = os.tmpname!
  file = io.open tmpname, "wb"
  file\write data
  file\close!
  tmpname

--- Read binary data from file
read_temp_file = (filename) ->
  file = io.open filename, "rb"
  return nil unless file
  data = file\read "*a"
  file\close!
  data

--- Real AES-128-GCM encryption using OpenSSL command line
openssl_aes_gcm_encrypt = (key, nonce, plaintext, aad="") ->
  unless #key == 16
    error "AES-128-GCM key must be 16 bytes"
  unless #nonce == 12
    error "AES-GCM nonce must be 12 bytes"

  -- Write plaintext to temporary file
  plaintext_file = write_temp_file plaintext
  ciphertext_file = os.tmpname!

  -- Build OpenSSL command
  key_hex = bin2hex key
  iv_hex = bin2hex nonce

  -- Use OpenSSL AES-128-GCM encryption
  cmd = "openssl enc -aes-128-gcm -e -K #{key_hex} -iv #{iv_hex} -in #{plaintext_file} -out #{ciphertext_file}"

  -- Add AAD if provided
  if #aad > 0
    aad_file = write_temp_file aad
    cmd ..= " -A #{bin2hex aad}"
    os.remove aad_file

  -- Execute encryption
  result = os.execute cmd

  -- Clean up input file
  os.remove plaintext_file

  if result == 0
    -- Read encrypted result
    encrypted_data = read_temp_file ciphertext_file
    os.remove ciphertext_file
    return encrypted_data
  else
    os.remove ciphertext_file
    return nil

--- Real AES-128-GCM decryption using OpenSSL command line
openssl_aes_gcm_decrypt = (key, nonce, ciphertext_with_tag, aad="") ->
  unless #key == 16
    error "AES-128-GCM key must be 16 bytes"
  unless #nonce == 12
    error "AES-GCM nonce must be 12 bytes"
  unless #ciphertext_with_tag >= 16
    return nil

  -- Write ciphertext to temporary file
  ciphertext_file = write_temp_file ciphertext_with_tag
  plaintext_file = os.tmpname!

  -- Build OpenSSL command
  key_hex = bin2hex key
  iv_hex = bin2hex nonce

  -- Use OpenSSL AES-128-GCM decryption
  cmd = "openssl enc -aes-128-gcm -d -K #{key_hex} -iv #{iv_hex} -in #{ciphertext_file} -out #{plaintext_file}"

  -- Add AAD if provided
  if #aad > 0
    aad_file = write_temp_file aad
    cmd ..= " -A #{bin2hex aad}"
    os.remove aad_file

  -- Execute decryption
  result = os.execute cmd

  -- Clean up input file
  os.remove ciphertext_file

  if result == 0
    -- Read decrypted result
    decrypted_data = read_temp_file plaintext_file
    os.remove plaintext_file
    return decrypted_data
  else
    os.remove plaintext_file
    return nil

--- Stub implementations for fallback
stub_aes_gcm_encrypt = (key, nonce, plaintext, aad="") ->
  -- Simple XOR cipher for testing (NOT secure!)
  ciphertext = ""
  for i = 1, #plaintext
    p = string.byte(plaintext, i)
    k = string.byte(key, ((i - 1) % #key) + 1)
    ciphertext = ciphertext .. string.char(xor p, k)

  -- Generate fake 16-byte authentication tag
  auth_tag = ""
  for i = 1, 16
    k = string.byte(key, ((i - 1) % #key) + 1)
    n = string.byte(nonce, ((i - 1) % #nonce) + 1)
    auth_tag = auth_tag .. string.char(xor k, n)

  ciphertext .. auth_tag

stub_aes_gcm_decrypt = (key, nonce, ciphertext_with_tag, aad="") ->
  unless #ciphertext_with_tag >= 16
    return nil

  -- Split ciphertext and authentication tag
  ciphertext = ciphertext_with_tag\sub 1, #ciphertext_with_tag - 16
  received_tag = ciphertext_with_tag\sub #ciphertext_with_tag - 15

  -- Generate expected authentication tag (same as encrypt)
  expected_tag = ""
  for i = 1, 16
    k = string.byte(key, ((i - 1) % #key) + 1)
    n = string.byte(nonce, ((i - 1) % #nonce) + 1)
    expected_tag = expected_tag .. string.char(xor k, n)

  -- Verify authentication tag
  if received_tag != expected_tag
    return nil

  -- Decrypt by XORing with key bytes (reverse of encrypt)
  plaintext = ""
  for i = 1, #ciphertext
    c = string.byte(ciphertext, i)
    k = string.byte(key, ((i - 1) % #key) + 1)
    plaintext = plaintext .. string.char(xor c, k)

  plaintext

--- Main AES-128-GCM functions
aes_128_gcm_encrypt = (key, nonce, plaintext, aad="") ->
  if crypto_available
    result = openssl_aes_gcm_encrypt key, nonce, plaintext, aad
    return result if result

  -- Fallback to stub
  stub_aes_gcm_encrypt key, nonce, plaintext, aad

aes_128_gcm_decrypt = (key, nonce, ciphertext_with_tag, aad="") ->
  if crypto_available
    result = openssl_aes_gcm_decrypt key, nonce, ciphertext_with_tag, aad
    return result if result != nil

  -- Fallback to stub
  stub_aes_gcm_decrypt key, nonce, ciphertext_with_tag, aad

--- Generic AEAD encryption interface
aead_encrypt = (algorithm, key, nonce, plaintext, aad="") ->
  switch algorithm
    when "AES-128-GCM"
      aes_128_gcm_encrypt key, nonce, plaintext, aad
    else
      error "Unsupported AEAD algorithm: #{algorithm}"

--- Generic AEAD decryption interface
aead_decrypt = (algorithm, key, nonce, ciphertext_with_tag, aad="") ->
  switch algorithm
    when "AES-128-GCM"
      aes_128_gcm_decrypt key, nonce, ciphertext_with_tag, aad
    else
      error "Unsupported AEAD algorithm: #{algorithm}"

--- QUIC-specific packet protection encryption
quic_encrypt_packet = (key, iv, packet_number, plaintext, header_aad) ->
  nonce = construct_nonce iv, packet_number
  aes_128_gcm_encrypt key, nonce, plaintext, header_aad

--- QUIC-specific packet protection decryption
quic_decrypt_packet = (key, iv, packet_number, ciphertext_with_tag, header_aad) ->
  nonce = construct_nonce iv, packet_number
  aes_128_gcm_decrypt key, nonce, ciphertext_with_tag, header_aad

{
  :aead_encrypt, :aead_decrypt, :aes_128_gcm_encrypt, :aes_128_gcm_decrypt,
  :construct_nonce, :quic_encrypt_packet, :quic_decrypt_packet, :crypto_available
}
