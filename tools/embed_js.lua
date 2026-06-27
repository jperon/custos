-- tools/embed_js.lua — embarque un fichier JS dans un module Lua qui le retourne.
-- Usage : luajit tools/embed_js.lua <in.js> <out.lua>
-- Choisit un niveau de long-bracket non présent dans le contenu (robuste).
local inp, out = ...
assert(inp and out, "usage: embed_js.lua <in.js> <out.lua>")
local f = assert(io.open(inp, "r"))
local s = f:read("*a")
f:close()
local lvl = 0
while s:find("]" .. string.rep("=", lvl) .. "]", 1, true) do lvl = lvl + 1 end
local eq = string.rep("=", lvl)
local o = assert(io.open(out, "w"))
o:write("-- GENERATED from " .. inp .. " by tools/embed_js.lua — DO NOT EDIT.\n")
o:write("return [" .. eq .. "[\n")
o:write(s)
o:write("\n]" .. eq .. "]\n")
o:close()
