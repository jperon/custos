local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local quic_mod = require("ipparse.l4.quic")
local prot_mod = require("ipparse.l4.quic.v1.protection")
local ch_mod = require("ipparse.l7.tls.handshake.client_hello")
local ext_mod = require("ipparse.l7.tls.handshake.extension")
local sn_mod = require("ipparse.l7.tls.handshake.extension.server_name")
local iter_frames
iter_frames = require("ipparse.l4.quic.frames").iter_frames
local keys_mod = nil
local load_keys_module
load_keys_module = function()
  if keys_mod then
    return keys_mod
  end
  local mod_name = "ipparse.l4.quic.v1.keys"
  package.loaded[mod_name] = nil
  local ok, mod_or_err = pcall(require, mod_name)
  if not (ok and mod_or_err) then
    return nil, "quic_keys_load_failed: " .. tostring(mod_or_err)
  end
  keys_mod = mod_or_err
  return keys_mod
end
local derive_quic_keyset
derive_quic_keyset = function(keys, dcid)
  local client_secret, server_secret = keys.derive_initial_secrets(dcid)
  local ckey, civ, chp = keys.derive_keys(client_secret)
  local skey, siv, shp = keys.derive_keys(server_secret)
  return {
    client_secret = client_secret,
    server_secret = server_secret,
    client_keys = {
      key = ckey,
      iv = civ,
      hp_key = chp
    },
    server_keys = {
      key = skey,
      iv = siv,
      hp_key = shp
    }
  }
end
local load_backend
load_backend = function()
  local errs = { }
  local _list_0 = {
    "ipparse.lib.crypto.backend.lunatik",
    "ipparse.lib.crypto.backend.ffi_wolfssl",
    "ipparse.lib.crypto.backend.ffi_mbedtls",
    "ipparse.lib.crypto.backend.ffi_openssl"
  }
  for _index_0 = 1, #_list_0 do
    local mod = _list_0[_index_0]
    package.loaded[mod] = nil
    local ok, backend = pcall(require, mod)
    if ok and backend then
      return backend
    end
    errs[#errs + 1] = tostring(mod) .. ": " .. tostring(backend)
  end
  return nil, "crypto backend not available (" .. table.concat(errs, " | ") .. ")"
end
local reassemble_stream
reassemble_stream = function(chunks)
  local offsets
  do
    local _accum_0 = { }
    local _len_0 = 1
    for off, _ in pairs(chunks) do
      _accum_0[_len_0] = off
      _len_0 = _len_0 + 1
    end
    offsets = _accum_0
  end
  if #offsets == 0 then
    return ""
  end
  table.sort(offsets)
  local out = { }
  local expected = 0
  for _index_0 = 1, #offsets do
    local _continue_0 = false
    repeat
      local off = offsets[_index_0]
      local chunk = chunks[off]
      local clen = #chunk
      local chunk_end = off + clen - 1
      if chunk_end < expected then
        _continue_0 = true
        break
      end
      if off > expected then
        break
      end
      local start_idx = expected > off and (expected - off + 1) or 1
      out[#out + 1] = chunk:sub(start_idx)
      expected = chunk_end + 1
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return table.concat(out)
end
local sni_from_tls
sni_from_tls = function(tls_data)
  if #tls_data < 4 then
    return nil
  end
  local off = 1
  while off + 3 <= #tls_data do
    local msg_type = su("B", tls_data, off)
    local b_hi = su("B", tls_data, off + 1)
    local b_lo = su(">H", tls_data, off + 2)
    local msg_len = b_hi * 65536 + b_lo
    local body_off = off + 4
    if body_off + msg_len - 1 > #tls_data then
      return nil
    end
    if msg_type == 0x01 then
      local ch, _ = ch_mod.parse(tls_data, body_off)
      if ch and ch.extensions and #ch.extensions > 0 then
        local ext_off = 1
        while ext_off <= #ch.extensions do
          local ext, next_off = ext_mod.parse(ch.extensions, ext_off)
          if ext.type == 0x0000 then
            local sn
            sn, _ = sn_mod.parse(ext.data, 1)
            if sn and sn.name and #sn.name > 0 then
              return sn.name
            end
          end
          ext_off = next_off
        end
      end
    end
    off = body_off + msg_len
  end
  return nil
end
local session_mt = { }
local append_crypto_frame
append_crypto_frame = function(self, frame)
  local base = frame.offset or 0
  local data = frame.data or ""
  local prev = self.crypto_chunks[base]
  if prev and prev == data then
    return true
  end
  if prev and prev ~= data then
    return nil, "conflicting CRYPTO frame at offset " .. tostring(base)
  end
  local data_end = base + #data - 1
  for off, chunk in pairs(self.crypto_chunks) do
    local chunk_end = off + #chunk - 1
    local overlap_start = math.max(base, off)
    local overlap_end = math.min(data_end, chunk_end)
    if overlap_start <= overlap_end then
      for pos = overlap_start, overlap_end do
        local a = string.byte(data, (pos - base + 1))
        local b = string.byte(chunk, (pos - off + 1))
        if a ~= b then
          return nil, "conflicting CRYPTO byte at offset " .. tostring(pos)
        end
      end
    end
  end
  self.crypto_chunks[base] = data
  return true
end
local direction_from_header
direction_from_header = function(self, q, meta)
  if meta == nil then
    meta = { }
  end
  if meta.direction then
    return meta.direction
  end
  if not (self.initial_dcid) then
    return "client"
  end
  if q.dst_connection_id == self.initial_dcid then
    return "client"
  elseif q.src_connection_id == self.initial_dcid then
    return "server"
  else
    return "client"
  end
end
local ensure_keys
ensure_keys = function(self, q, direction)
  self.initial_dcid = self.initial_dcid or q.dst_connection_id
  if direction == "client" then
    if not self.client_keys then
      local keys, kerr = load_keys_module()
      if not (keys) then
        return nil, kerr
      end
      if not self.client_secret then
        self.client_secret, self.server_secret = keys.derive_initial_secrets(self.initial_dcid)
      end
      local key, iv, hp = keys.derive_keys(self.client_secret)
      self.client_keys = {
        key = key,
        iv = iv,
        hp_key = hp
      }
    end
  else
    if not self.server_keys then
      local keys, kerr = load_keys_module()
      if not (keys) then
        return nil, kerr
      end
      if not self.server_secret then
        self.client_secret, self.server_secret = keys.derive_initial_secrets(self.initial_dcid)
      end
      local key, iv, hp = keys.derive_keys(self.server_secret)
      self.server_keys = {
        key = key,
        iv = iv,
        hp_key = hp
      }
    end
  end
  return true, nil
end
local decrypt_initial
decrypt_initial = function(self, quic_packet, q, direction, keys_override)
  if keys_override == nil then
    keys_override = nil
  end
  local keys = keys_override or (direction == "server" and self.server_keys or self.client_keys)
  local expected = (self.pn_largest[direction] or -1) + 1
  if q.pkt_length and q.pn_off then
    local packet_end = (q.pn_off - 1) + q.pkt_length
    if packet_end > 0 and packet_end <= #quic_packet then
      quic_packet = quic_packet:sub(1, packet_end)
    end
  end
  local pn_off = q.pn_off
  local aad, pn, pn_len = prot_mod.unprotect_header(quic_packet, pn_off, keys.hp_key, true, expected, self.backend)
  if not (aad) then
    return nil, pn
  end
  local payload_off = pn_off + pn_len
  local plaintext, err = prot_mod.decrypt_payload(quic_packet, payload_off, keys.key, keys.iv, pn, aad, self.backend)
  if not (plaintext) then
    return nil, err
  end
  if pn > (self.pn_largest[direction] or -1) then
    self.pn_largest[direction] = pn
  end
  return plaintext
end
local bootstrap_initial
bootstrap_initial = function(self, quic_packet, q)
  local keys, kerr = load_keys_module()
  if not (keys) then
    return nil, kerr
  end
  local probes = { }
  local seen = { }
  local add_probe
  add_probe = function(dcid, direction)
    if not (dcid and #dcid > 0) then
      return 
    end
    local key = tostring(direction) .. ":" .. tostring(dcid)
    if seen[key] then
      return 
    end
    seen[key] = true
    probes[#probes + 1] = {
      dcid = dcid,
      direction = direction
    }
  end
  add_probe(q.dst_connection_id, "client")
  add_probe(q.src_connection_id, "server")
  add_probe(q.dst_connection_id, "server")
  add_probe(q.src_connection_id, "client")
  local errs = { }
  for _index_0 = 1, #probes do
    local probe = probes[_index_0]
    local keyset = derive_quic_keyset(keys, probe.dcid)
    local probe_keys = probe.direction == "server" and keyset.server_keys or keyset.client_keys
    local plaintext, derr = decrypt_initial(self, quic_packet, q, probe.direction, probe_keys)
    if plaintext then
      self.initial_dcid = probe.dcid
      self.client_secret = keyset.client_secret
      self.server_secret = keyset.server_secret
      self.client_keys = keyset.client_keys
      self.server_keys = keyset.server_keys
      return plaintext
    end
    errs[#errs + 1] = tostring(probe.direction) .. "/dcid_len=" .. tostring(#probe.dcid) .. ": " .. tostring(derr)
  end
  return nil, "decrypt failed: bootstrap could not determine initial direction/DCID (" .. table.concat(errs, " | ") .. ")"
end
session_mt.__index = {
  push = function(self, quic_packet, meta)
    if meta == nil then
      meta = { }
    end
    local q, _ = quic_mod.parse(quic_packet, 1)
    if not (q) then
      return nil, "not a QUIC packet"
    end
    if not (q.long_header) then
      return nil, "only QUIC long headers are supported"
    end
    if not (q.pn_off) then
      return nil, "missing packet number offset"
    end
    if not (q.pkt_type == 0x00) then
      return nil, "only QUIC Initial is supported"
    end
    local plaintext = nil
    if not self.initial_dcid then
      local err
      plaintext, err = bootstrap_initial(self, quic_packet, q)
      if not (plaintext) then
        return nil, err
      end
    else
      local direction = direction_from_header(self, q, meta)
      local ok, key_err = ensure_keys(self, q, direction)
      if not (ok) then
        return nil, (key_err or "could not derive QUIC keys")
      end
      local err
      plaintext, err = decrypt_initial(self, quic_packet, q, direction)
      if not (plaintext) then
        return nil, "decrypt failed: " .. tostring(err)
      end
    end
    for f in iter_frames(plaintext) do
      local _continue_0 = false
      repeat
        if not (f and f.name == "CRYPTO" and f.data) then
          _continue_0 = true
          break
        end
        local ok_append, append_err = append_crypto_frame(self, f)
        if not (ok_append) then
          return nil, append_err
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
    self.last_plaintext = plaintext
    self.sni_dirty = true
    return true
  end,
  sni = function(self)
    if self.sni_dirty then
      self.cached_sni = sni_from_tls(reassemble_stream(self.crypto_chunks))
      self.sni_dirty = false
    end
    return self.cached_sni
  end,
  crypto_stream = function(self)
    return reassemble_stream(self.crypto_chunks)
  end,
  plaintext = function(self)
    return self.last_plaintext
  end
}
local new
new = function(opts)
  if opts == nil then
    opts = { }
  end
  local backend = opts.backend
  if not (backend) then
    local err
    backend, err = load_backend()
    if not (backend) then
      error(err)
    end
  end
  return setmetatable({
    backend = backend,
    initial_dcid = opts.initial_dcid,
    client_secret = opts.client_secret,
    server_secret = opts.server_secret,
    client_keys = opts.client_keys,
    server_keys = opts.server_keys,
    pn_largest = {
      client = -1,
      server = -1
    },
    crypto_chunks = { },
    last_plaintext = nil,
    cached_sni = nil,
    sni_dirty = true
  }, session_mt)
end
return {
  new = new
}
