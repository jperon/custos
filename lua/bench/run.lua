local micro = require("bench.micro")
local load = require("bench.load")
local report = require("bench.report")
local BENCH_DIR = "tmp/bench"
local BASELINE = BENCH_DIR .. "/baseline.lua"
local parse_args
parse_args = function(argv)
  local o = {
    micro = true,
    load = false,
    target = nil,
    port = 53,
    duration = 5,
    rate = nil,
    iters = 1e6,
    max_queries = nil,
    domains_file = nil,
    save_baseline = false
  }
  local explicit_micro = false
  local i = 1
  local next_val
  next_val = function()
    i = i + 1
    return argv[i]
  end
  while i <= #argv do
    local a = argv[i]
    local _exp_0 = a
    if "--micro" == _exp_0 then
      o.micro = true
      explicit_micro = true
    elseif "--load" == _exp_0 then
      o.load = true
    elseif "--all" == _exp_0 then
      o.micro = true
      o.load = true
      explicit_micro = true
    elseif "--target" == _exp_0 then
      local host = next_val()
      if host then
        local h, p = host:match("^(.+):(%d+)$")
        if h then
          o.target = h
          o.port = tonumber(p)
        else
          o.target = host
        end
      end
    elseif "--duration" == _exp_0 then
      o.duration = tonumber(next_val())
    elseif "--rate" == _exp_0 then
      o.rate = tonumber(next_val())
    elseif "--iters" == _exp_0 then
      o.iters = tonumber(next_val())
    elseif "--max-queries" == _exp_0 then
      o.max_queries = tonumber(next_val())
    elseif "--domains" == _exp_0 then
      o.domains_file = next_val()
    elseif "--save-baseline" == _exp_0 then
      o.save_baseline = true
    end
    i = i + 1
  end
  if o.load and not explicit_micro then
    o.micro = false
  end
  return o
end
local load_domains
load_domains = function(path)
  if not (path) then
    return nil
  end
  local f = io.open(path, "r")
  if not (f) then
    return nil
  end
  local out = { }
  for line in f:lines() do
    local _continue_0 = false
    repeat
      line = line:gsub("%s+$", ""):gsub("^%s+", "")
      if line == "" or line:sub(1, 1) == "#" then
        _continue_0 = true
        break
      end
      out[#out + 1] = line
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  f:close()
  return out
end
local _write_file
_write_file = function(path, content)
  local f = io.open(path, "w")
  if not (f) then
    return false
  end
  f:write(content)
  f:close()
  return true
end
local main
main = function(argv)
  local o = parse_args(argv)
  os.execute("mkdir -p " .. BENCH_DIR)
  local ts = os.date("%Y-%m-%dT%H:%M:%S")
  local result = {
    ts = ts
  }
  if o.micro then
    io.write("[bench] micro-bench (iters=" .. tostring(o.iters) .. ")...\n")
    result.micro = micro.run({
      iters = o.iters
    })
  end
  if o.load then
    if not (o.target) then
      io.write("[bench] --load requiert --target host[:port]\n")
      os.exit(1)
    end
    io.write("[bench] charge DNS → " .. tostring(o.target) .. ":" .. tostring(o.port) .. " (durée=" .. tostring(o.duration) .. "s)...\n")
    result.load = load.run({
      target = o.target,
      port = o.port,
      duration = o.duration,
      rate = o.rate,
      max_queries = o.max_queries or (o.rate and o.rate * o.duration) or 1e5,
      domains = load_domains(o.domains_file)
    })
  end
  local baseline = nil
  if not o.save_baseline then
    do
      local bf = io.open(BASELINE, "r")
      if bf then
        local content = bf:read("*a")
        bf:close()
        baseline = report.deserialize(content)
      end
    end
  end
  io.write("\n" .. report.format(result, baseline) .. "\n")
  _write_file(tostring(BENCH_DIR) .. "/report-" .. tostring(ts) .. ".txt", report.format(result, baseline))
  _write_file(tostring(BENCH_DIR) .. "/result-" .. tostring(ts) .. ".lua", report.serialize(result))
  if o.save_baseline then
    _write_file(BASELINE, report.serialize(result))
    io.write("\n[bench] baseline sauvegardée dans " .. tostring(BASELINE) .. "\n")
  end
  return result
end
return {
  parse_args = parse_args,
  load_domains = load_domains,
  main = main
}
