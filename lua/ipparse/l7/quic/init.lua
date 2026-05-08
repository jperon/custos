local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local frames_mod = require("ipparse.l4.quic.frames")
local ch_mod = require("ipparse.l7.tls.handshake.client_hello")
local ext_mod = require("ipparse.l7.tls.handshake.extension")
local sn_mod = require("ipparse.l7.tls.handshake.extension.server_name")
local reassemble_crypto
reassemble_crypto = function(frames)
  local crypto
  do
    local _accum_0 = { }
    local _len_0 = 1
    for _index_0 = 1, #frames do
      local f = frames[_index_0]
      if f.name == "CRYPTO" and f.data then
        _accum_0[_len_0] = {
          offset = f.offset or 0,
          data = f.data
        }
        _len_0 = _len_0 + 1
      end
    end
    crypto = _accum_0
  end
  if #crypto == 0 then
    return ""
  end
  table.sort(crypto, function(a, b)
    return a.offset < b.offset
  end)
  local bytes_by_pos = { }
  local highest = -1
  for _index_0 = 1, #crypto do
    local f = crypto[_index_0]
    local data = f.data
    local base = f.offset
    for i = 1, #data do
      local pos = base + i - 1
      local v = string.byte(data, i)
      local prev = bytes_by_pos[pos]
      if not (prev and prev ~= v) then
        bytes_by_pos[pos] = v
      end
      if pos > highest then
        highest = pos
      end
    end
  end
  if highest < 0 then
    return ""
  end
  local out = { }
  for pos = 0, highest do
    if not (bytes_by_pos[pos]) then
      break
    end
    out[#out + 1] = string.char(bytes_by_pos[pos])
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
local sni_from_frames
sni_from_frames = function(frames)
  return sni_from_tls(reassemble_crypto(frames))
end
local sni_from_plaintext
sni_from_plaintext = function(plaintext)
  local collected = { }
  for f in frames_mod.iter_frames(plaintext) do
    collected[#collected + 1] = f
  end
  return sni_from_frames(collected)
end
local Session = require("ipparse.l7.quic.session")
return {
  reassemble_crypto = reassemble_crypto,
  sni_from_tls = sni_from_tls,
  sni_from_frames = sni_from_frames,
  sni_from_plaintext = sni_from_plaintext,
  Session = Session
}
