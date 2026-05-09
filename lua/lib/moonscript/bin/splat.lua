local argparse = require("argparse")
local normalize
normalize = function(path)
  return path:match("(.-)/*$") .. "/"
end
local parser = argparse("splat.moon", "Concatenate a collection of Lua modules into a single file")
parser:option("--load -l", "Module names that will be load on require"):count("*")
parser:flag("--strip-prefix -s", "Strip directory prefix from module names")
parser:argument("directories", "Directories to scan for Lua modules"):args("+")
local args = parser:parse((function()
  local _accum_0 = { }
  local _len_0 = 1
  for _, v in ipairs(_G.arg) do
    _accum_0[_len_0] = v
    _len_0 = _len_0 + 1
  end
  return _accum_0
end)())
local dirs = args.directories
local strip_prefix = args.strip_prefix
local lfs = require("lfs")
local scan_directory
scan_directory = function(root, patt, collected)
  if collected == nil then
    collected = { }
  end
  root = normalize(root)
  for fname in lfs.dir(root) do
    if not fname:match("^%.") then
      local full_path = root .. fname
      if lfs.attributes(full_path, "mode") == "directory" then
        scan_directory(full_path, patt, collected)
      else
        if full_path:match(patt) then
          table.insert(collected, full_path)
        end
      end
    end
  end
  return collected
end
local path_to_module_name
path_to_module_name = function(path, prefix)
  if prefix and path:sub(1, #prefix) == prefix then
    path = path:sub(#prefix + 1)
  end
  return (path:match("(.-)%.lua"):gsub("/", "."))
end
local each_line
each_line = function(text)
  return coroutine.wrap(function()
    local start = 1
    while true do
      local pos, after = text:find("\n", start, true)
      if not pos then
        break
      end
      coroutine.yield(text:sub(start, pos - 1))
      start = after + 1
    end
    coroutine.yield(text:sub(start, #text))
    return nil
  end)
end
local write_module
write_module = function(name, text)
  print("package.preload['" .. name .. "'] = function()")
  for line in each_line(text) do
    print("  " .. line)
  end
  return print("end")
end
local modules = { }
for _index_0 = 1, #dirs do
  local dir = dirs[_index_0]
  local files = scan_directory(dir, "%.lua$")
  local prefix = strip_prefix and normalize(dir) or nil
  local chunks
  do
    local _accum_0 = { }
    local _len_0 = 1
    for _index_1 = 1, #files do
      local path = files[_index_1]
      local module_name = path_to_module_name(path, prefix)
      local content = io.open(path):read("*a")
      modules[module_name] = true
      local _value_0 = {
        module_name,
        content
      }
      _accum_0[_len_0] = _value_0
      _len_0 = _len_0 + 1
    end
    chunks = _accum_0
  end
  for _index_1 = 1, #chunks do
    local chunk = chunks[_index_1]
    local name, content = unpack(chunk)
    local base = name:match("(.-)%.init")
    if base and not modules[base] then
      modules[base] = true
      name = base
    end
    write_module(name, content)
  end
end
local _list_0 = args.load
for _index_0 = 1, #_list_0 do
  local module_name = _list_0[_index_0]
  if modules[module_name] then
    print(([[package.preload["%s"]()]]):format(module_name))
  end
end
