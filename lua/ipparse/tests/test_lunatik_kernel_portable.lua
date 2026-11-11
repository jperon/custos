local util = require("ipparse.lib.util")
require("ipparse.fun")
local mods = {
  "ipparse.tests.test_fun",
  "ipparse.tests.test_init",
  "ipparse.tests.l2.test_ethernet",
  "ipparse.tests.l3.test_checksum",
  "ipparse.tests.l3.test_ip4",
  "ipparse.tests.l3.test_fragmented_ip4",
  "ipparse.tests.l3.test_ip6",
  "ipparse.tests.l3.test_ip",
  "ipparse.tests.l4.test_tcp",
  "ipparse.tests.l4.test_udp",
  "ipparse.tests.l4.test_tcp_stream",
  "ipparse.tests.l7.test_dns",
  "ipparse.tests.l7.tls.test_handshake",
  "ipparse.tests.test_malformed",
  "ipparse.tests.lib.test_sha",
  "ipparse.tests.lib.test_hkdf",
  "ipparse.tests.lib.test_bit_compat",
  "ipparse.tests.lib.test_pack_compat",
  "ipparse.tests.l4.quic.test_varint",
  "ipparse.tests.l4.quic.test_header",
  "ipparse.tests.l4.quic.test_frames",
  "ipparse.tests.l4.quic.test_keys",
  "ipparse.tests.l4.quic.test_protection",
  "ipparse.tests.l4.quic.test_integration",
  "ipparse.tests.l7.quic.test_session"
}
local total_pass, total_all = 0, 0
local load_errors = 0
for _index_0 = 1, #mods do
  local mod = mods[_index_0]
  local ok, err = pcall(require, mod)
  if ok then
    total_pass = total_pass + util._last_pass
    total_all = total_all + util._last_total
  else
    load_errors = load_errors + 1
    print("ERROR loading " .. tostring(mod) .. ": " .. tostring(err))
  end
end
print("\n==> Kernel portable total: " .. tostring(total_pass) .. "/" .. tostring(total_all))
local failed = total_pass ~= total_all or load_errors > 0
if failed then
  print("FAIL kernel portable suite: " .. tostring(load_errors) .. " load error(s), " .. tostring(total_pass) .. "/" .. tostring(total_all) .. " passed")
  return error("kernel portable suite failed")
end
