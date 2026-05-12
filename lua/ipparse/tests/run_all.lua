local util = require("ipparse.lib.util")
local total_pass, total_all = 0, 0
local is_luajit = type(jit) == "table"
local lua_major, lua_minor = (_VERSION or ""):match("Lua (%d+)%.(%d+)")
lua_major = tonumber(lua_major) or 5
lua_minor = tonumber(lua_minor) or 1
local is_pre53 = lua_major < 5 or (lua_major == 5 and lua_minor < 3)
local mods = {
  "ipparse.tests.test_fun",
  "ipparse.tests.test_init",
  "ipparse.tests.l2.test_ethernet",
  "ipparse.tests.l3.test_checksum",
  "ipparse.tests.l3.test_ip4",
  "ipparse.tests.l3.test_ip6",
  "ipparse.tests.l3.test_ip",
  "ipparse.tests.l4.test_tcp",
  "ipparse.tests.l4.test_udp",
  "ipparse.tests.l7.test_dns",
  "ipparse.tests.lib.test_hkdf",
  "ipparse.tests.lib.crypto.test_ffi_wolfssl",
  "ipparse.tests.lib.crypto.test_ffi_mbedtls",
  "ipparse.tests.l4.quic.test_varint",
  "ipparse.tests.l4.quic.test_header",
  "ipparse.tests.l4.quic.test_frames",
  "ipparse.tests.l4.quic.test_keys",
  "ipparse.tests.l4.quic.test_protection",
  "ipparse.tests.l4.quic.test_integration",
  "ipparse.tests.l7.quic.test_sni",
  "ipparse.tests.l7.quic.test_session",
  "ipparse.tests.l7.quic.test_google_capture_backends"
}
if is_luajit or is_pre53 then
  print("SKIP\tipparse.tests.lib.crypto.test_lunatik (requires Lua >= 5.3 non-LuaJIT runtime)")
else
  table.insert(mods, 12, "ipparse.tests.lib.crypto.test_lunatik")
end
for _index_0 = 1, #mods do
  local mod = mods[_index_0]
  local ok, err = pcall(require, mod)
  if ok then
    total_pass = total_pass + util._last_pass
    total_all = total_all + util._last_total
  else
    print("ERROR loading " .. tostring(mod) .. ": " .. tostring(err))
  end
end
return print("\n==> Total: " .. tostring(total_pass) .. "/" .. tostring(total_all))
