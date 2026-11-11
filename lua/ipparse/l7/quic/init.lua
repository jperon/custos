require("ipparse")
local frames_mod = require("ipparse.l4.quic.frames")
local Session = require("ipparse.l7.quic.session")
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
local sni_from_tls = Session.sni_from_tls
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
return {
  reassemble_crypto = reassemble_crypto,
  sni_from_tls = sni_from_tls,
  sni_from_frames = sni_from_frames,
  sni_from_plaintext = sni_from_plaintext,
  Session = Session
}
