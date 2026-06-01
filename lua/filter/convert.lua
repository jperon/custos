local bin48 = require("filter.lib.bin48")
if #arg < 2 then
  io.stderr:write("Usage: luajit lua/filter/convert.lua <input.domains> <output.bin>\n")
  os.exit(1)
end
local input_path = arg[1]
local output_path = arg[2]
local fh = io.open(input_path, "r")
if not fh then
  io.stderr:write("Impossible d'ouvrir : " .. tostring(input_path) .. "\n")
  os.exit(1)
end
local domains = { }
for line in fh:lines() do
  local domain = line:match("^%s*(.-)%s*$")
  domain = domain:match("^([^#]*)" or "")
  domain = domain:match("^%s*(.-)%s*$")
  if domain ~= "" then
    domains[#domains + 1] = domain
  end
end
fh:close()
local payload, n = bin48.pack_domains(domains)
if n == 0 then
  io.stderr:write("Aucun domaine valide dans " .. tostring(input_path) .. "\n")
  os.exit(1)
end
local out = io.open(output_path, "wb")
if not out then
  io.stderr:write("Impossible d'écrire : " .. tostring(output_path) .. "\n")
  os.exit(1)
end
out:write(payload)
out:close()
return io.stderr:write(tostring(n) .. " domaines → " .. tostring(output_path) .. " (" .. tostring(#payload) .. " octets)\n")
