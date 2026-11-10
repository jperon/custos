local band
band = require("ipparse.lib.bit_compat").band
local concat
concat = table.concat
local new
new = function(check_complete, opts)
  if check_complete == nil then
    check_complete = (function()
      return true
    end)
  end
  if opts == nil then
    opts = { }
  end
  local max_buf = opts.max_buf or 0x100000
  local max_sessions = opts.max_sessions or 1024
  local clock = opts.clock
  local clock_hz = opts.clock_hz
  if clock then
    clock_hz = clock_hz or 1
  else
    if clock_hz then
      error("tcp_stream: opts.clock_hz requires opts.clock")
    end
    if os and os.time then
      clock = os.time
      clock_hz = 1
    else
      local ok, linux = pcall(require, "linux")
      if ok and linux and linux.time then
        clock = linux.time
        clock_hz = 1000000000
      else
        error("tcp_stream: no clock available (pass opts.clock/opts.clock_hz)")
      end
    end
  end
  if not clock_hz then
    clock_hz = 1
  end
  local sessions = { }
  local count = 0
  local drop
  drop = function(key)
    if sessions[key] ~= nil then
      sessions[key] = nil
      count = count - 1
    end
  end
  local drop_oldest
  drop_oldest = function()
    local oldest_key, oldest_ts = nil, nil
    for key, entry in pairs(sessions) do
      if not oldest_ts or entry.timestamp < oldest_ts then
        oldest_key, oldest_ts = key, entry.timestamp
      end
    end
    if oldest_key then
      return drop(oldest_key)
    end
  end
  return {
    feed = function(key, payload, flags, init_seq)
      if band(flags, 0x05) ~= 0 then
        drop(key)
        return nil
      end
      if payload == "" then
        return nil
      end
      local entry = sessions[key]
      local first_seg = entry == nil
      if first_seg then
        if count >= max_sessions then
          drop_oldest()
        end
        entry = {
          segments = {
            payload
          },
          total = #payload,
          init_seq = init_seq,
          timestamp = clock()
        }
        sessions[key] = entry
        count = count + 1
      else
        entry.segments[#entry.segments + 1] = payload
        entry.total = entry.total + #payload
      end
      if entry.total > max_buf then
        drop(key)
        return nil
      end
      local buf = concat(entry.segments)
      if check_complete(buf) then
        local stored_seq = entry.init_seq
        drop(key)
        return buf, stored_seq, first_seg
      end
      entry.segments = {
        buf
      }
      return nil
    end,
    clear = function(key)
      return drop(key)
    end,
    reset = function()
      for k in pairs(sessions) do
        sessions[k] = nil
      end
      count = 0
    end,
    purge = function(max_age)
      if max_age == nil then
        max_age = 300
      end
      local now = clock()
      local threshold = max_age * clock_hz
      for key, entry in pairs(sessions) do
        if now - entry.timestamp > threshold then
          drop(key)
        end
      end
    end
  }
end
return {
  new = new
}
