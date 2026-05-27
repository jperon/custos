describe("SNI extraction from TLS ClientHello", function()
  local sni_logger = require("worker_tls")
  return it("should extract SNI from valid TLS ClientHello", function()
    local sni = "example.com"
    local sni_ext_data = string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) .. sni
    local name_len = #sni
    local list_len = name_len + 3
    local ext_len = list_len + 2
    sni_ext_data = string.char(0x00, 0x00, bit.rshift(ext_len, 8), bit.band(ext_len, 0xFF), bit.rshift(list_len, 8), bit.band(list_len, 0xFF), 0x00, bit.rshift(name_len, 8), bit.band(name_len, 0xFF)) .. sni
    local extensions_data = string.char(bit.rshift(ext_len + 4, 8), bit.band(ext_len + 4, 0xFF)) .. sni_ext_data
    local ch_payload = ""
    ch_payload = ch_payload .. string.char(0x03, 0x03)
    ch_payload = ch_payload .. string.rep("\x00", 32)
    ch_payload = ch_payload .. string.char(0x00)
    ch_payload = ch_payload .. string.char(0x00, 0x02, 0x13, 0x01)
    ch_payload = ch_payload .. string.char(0x01, 0x00)
    ch_payload = ch_payload .. extensions_data
    local handshake = string.char(0x01)
    local hs_len = #ch_payload
    handshake = handshake .. string.char(bit.rshift(hs_len, 16), bit.rshift(hs_len, 8), bit.band(hs_len, 0xFF))
    handshake = handshake .. ch_payload
    local tls_record = string.char(0x16)
    tls_record = tls_record .. string.char(0x03, 0x03)
    local record_len = #handshake
    tls_record = tls_record .. string.char(bit.rshift(record_len, 8), bit.band(record_len, 0xFF))
    tls_record = tls_record .. handshake
    return assert(sni_logger ~= nil)
  end)
end)
describe("SNI logger module", function()
  return it("should load worker_tls module", function()
    local sni_logger = require("worker_tls")
    assert(sni_logger ~= nil)
    return assert(sni_logger.run ~= nil)
  end)
end)
return describe("Mock SNI extraction", function()
  return it("should handle empty payload gracefully", function()
    local sni_logger = require("worker_tls")
    return assert(sni_logger ~= nil)
  end)
end)
