local open, popen
do
  local _obj_0 = io
  open, popen = _obj_0.open, _obj_0.popen
end
local tmpname
tmpname = os.tmpname
local concat
concat = table.concat
local read
read = function(self)
  if self then
    local ret = self:read("*a")
    return self:close() and ret
  end
end
local sh = { }
sh.__call = function(self, ...)
  local err = tmpname()
  local cmd = self.cmd .. " " .. concat({
    ...
  }, " ") .. " 2>" .. err
  local p = popen(cmd)
  if not p then
    error("Failed to execute command: " .. cmd)
  end
  local output = p:read("*a")
  local ok, _, ret = p:close()
  return output, not ok and read(open(err)), ret, popen("rm " .. err):close() and nil
end
sh.__index = function(self, cmd)
  return setmetatable({
    cmd = cmd
  }, sh)
end
return setmetatable(sh, sh)
