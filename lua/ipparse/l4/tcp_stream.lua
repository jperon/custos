local band
band = require("ipparse.lib.bit_compat").band
local new
new = function(check_complete)
  if check_complete == nil then
    check_complete = (function()
      return true
    end)
  end
  local sessions = { }
  return {
    feed = function(key, payload, flags, init_seq)
      if band(flags, 0x05) ~= 0 then
        sessions[key] = nil
        return nil
      end
      if payload == "" then
        return nil
      end
      local first_seg = sessions[key] == nil
      if first_seg then
        sessions[key] = {
          buf = payload,
          init_seq = init_seq,
          timestamp = os.time()
        }
      else
        local _update_0 = key
        sessions[_update_0].buf = sessions[_update_0].buf .. payload
      end
      local entry = sessions[key]
      if check_complete(entry.buf) then
        local stored_seq = entry.init_seq
        local buf = entry.buf
        sessions[key] = nil
        return buf, stored_seq, first_seg
      end
      return nil
    end,
    clear = function(key)
      sessions[key] = nil
    end,
    reset = function()
      for k in pairs(sessions) do
        sessions[k] = nil
      end
    end,
    purge = function(max_age)
      if max_age == nil then
        max_age = 300
      end
      local now = os.time()
      for key, entry in pairs(sessions) do
        if now - entry.timestamp > max_age then
          sessions[key] = nil
        end
      end
    end
  }
end
return {
  new = new
}
