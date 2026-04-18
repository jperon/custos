local bidirectional, zero_indexed
do
  local _obj_0 = require("ipparse.fun")
  bidirectional, zero_indexed = _obj_0.bidirectional, _obj_0.zero_indexed
end
local sp, su, sub
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su, sub = _obj_0.pack, _obj_0.unpack, _obj_0.sub
end
local concat
concat = table.concat
local band, bor, bnot, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, lshift, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.lshift, _obj_0.rshift
end
local pack_header
pack_header = function(self)
  return (self.size and sp(">H", self.size) or "") .. sp(">H B B H H H H", self.id, self.qr_opcode_aa_tc_rd, self.ra_z_rcode, self.qdcount, self.ancount, self.nscount, self.arcount)
end
local _header_mt = {
  __tostring = pack_header,
  __index = function(self, flag)
    local _exp_0 = flag
    if "qr" == _exp_0 then
      return band(self.qr_opcode_aa_tc_rd, 0x80) ~= 0
    elseif "opcode" == _exp_0 then
      return band(rshift(self.qr_opcode_aa_tc_rd, 3), 0xf) ~= 0
    elseif "aa" == _exp_0 then
      return band(self.qr_opcode_aa_tc_rd, 0x04) ~= 0
    elseif "tc" == _exp_0 then
      return band(self.qr_opcode_aa_tc_rd, 0x02) ~= 0
    elseif "rd" == _exp_0 then
      return band(self.qr_opcode_aa_tc_rd, 0x01) ~= 0
    elseif "ra" == _exp_0 then
      return band(self.ra_z_rcode, 0x80) ~= 0
    elseif "z" == _exp_0 then
      return band(rshift(self.ra_z_rcode, 4), 0x07) ~= 0
    elseif "rcode" == _exp_0 then
      return band(self.ra_z_rcode, 0x0f) ~= 0
    end
  end,
  __newindex = function(self, flag, val)
    local _exp_0 = flag
    if "qr" == _exp_0 then
      if val then
        self.qr_opcode_aa_tc_rd = bor(self.qr_opcode_aa_tc_rd, 0x80)
      else
        self.qr_opcode_aa_tc_rd = band(self.qr_opcode_aa_tc_rd, bnot(0x80))
      end
    elseif "opcode" == _exp_0 then
      self.qr_opcode_aa_tc_rd = bor(band(self.qr_opcode_aa_tc_rd, bnot(0x78)), lshift(band(val, 0xf), 3))
    elseif "aa" == _exp_0 then
      if val then
        self.qr_opcode_aa_tc_rd = bor(self.qr_opcode_aa_tc_rd, 0x04)
      else
        self.qr_opcode_aa_tc_rd = band(self.qr_opcode_aa_tc_rd, bnot(0x04))
      end
    elseif "tc" == _exp_0 then
      if val then
        self.qr_opcode_aa_tc_rd = bor(self.qr_opcode_aa_tc_rd, 0x02)
      else
        self.qr_opcode_aa_tc_rd = band(self.qr_opcode_aa_tc_rd, bnot(0x02))
      end
    elseif "rd" == _exp_0 then
      if val then
        self.qr_opcode_aa_tc_rd = bor(self.qr_opcode_aa_tc_rd, 0x01)
      else
        self.qr_opcode_aa_tc_rd = band(self.qr_opcode_aa_tc_rd, bnot(0x01))
      end
    elseif "z" == _exp_0 then
      self.ra_z_rcode = bor(band(self.ra_z_rcode, bnot(0x70)), lshift(band(val, 0x07), 4))
    elseif "rcode" == _exp_0 then
      self.ra_z_rcode = bor(band(self.ra_z_rcode, bnot(0x0f)), band(val, 0x0f))
    end
  end
}
local parse_header
parse_header = function(self, off, is_tcp)
  local len = #self - off
  local size
  if is_tcp then
    if len < 2 then
      return nil, "No DNS data"
    end
    size, off = su(">H", self, off)
    len = len - 2
  end
  if len < 12 then
    return nil, "No DNS data"
  end
  local id, qr_opcode_aa_tc_rd, ra_z_rcode, qdcount, ancount, nscount, arcount, data_off = su(">H B B H H H H", self, off)
  return setmetatable({
    id = id,
    qr_opcode_aa_tc_rd = qr_opcode_aa_tc_rd,
    ra_z_rcode = ra_z_rcode,
    qdcount = qdcount,
    ancount = ancount,
    nscount = nscount,
    arcount = arcount,
    off = off,
    data_off = data_off,
    size = size
  }, _header_mt), data_off
end
local labels
local label
label = function(self, off, l7_off)
  if l7_off == nil then
    l7_off = 1
  end
  if off + 2 > #self then
    return nil
  end
  local size, pos, _off = su("B B", self, off)
  if size == 0 then
    return nil, off + 1
  end
  if band(size, 0xC0) == 0 then
    return su("s1", self, off)
  end
  off = lshift(band(size, 0x3F), 8) + pos
  local lbls
  lbls, _off = labels(self, l7_off + off, l7_off)
  return concat(lbls, "."), _off, true
end
labels = function(self, off, l7_off)
  local lbls = { }
  for i = 1, 1024 do
    local lbl_segment, next_parse_off, is_from_pointer = label(self, off, l7_off)
    if not lbl_segment then
      off = next_parse_off
      break
    end
    lbls[i] = lbl_segment
    off = next_parse_off
    if is_from_pointer then
      break
    end
  end
  return lbls, off
end
local pack_question
pack_question = function(self)
  return self.qname .. sp(">H H", self.qtype, self.qclass)
end
local _question_mt = {
  __tostring = pack_question
}
local parse_question
parse_question = function(self, off, l7_off)
  local lbls, _off = labels(self, off, l7_off)
  local qname = sub(self, off, _off - 1)
  local qtype, qclass
  qtype, qclass, _off = su(">H H", self, _off)
  return setmetatable({
    name = concat(lbls, "."),
    qname = qname,
    qtype = qtype,
    qclass = qclass,
    off = off,
    end_off = _off - 1
  }, _question_mt), _off
end
local parse_questions
parse_questions = function(self, off, qdcount, l7_off)
  local res = { }
  for i = 1, qdcount do
    local q
    q, off = parse_question(self, off, l7_off)
    res[i] = q
  end
  return res, off
end
local pack_rr
pack_rr = function(self)
  return self.rname .. sp(">H H I4 s2", self.rtype, self.rclass, self.ttl, self.rdata)
end
local _rr_mt = {
  __tostring = pack_rr
}
local parse_rr
parse_rr = function(self, off, l7_off)
  local lbls, _off = labels(self, off, l7_off)
  local rname = sub(self, off, _off - 1)
  local rtype, rclass, ttl, rdata
  rtype, rclass, ttl, rdata, _off = su(">H H I4 s2", self, _off)
  return setmetatable({
    name = concat(lbls, "."),
    rname = rname,
    rtype = rtype,
    rclass = rclass,
    ttl = ttl,
    rdata = rdata,
    off = off,
    end_off = _off - 1
  }, _rr_mt), _off
end
local parse_rrs
parse_rrs = function(self, off, count, l7_off)
  local res = { }
  for i = 1, count do
    local r
    r, off = parse_rr(self, off, l7_off)
    res[i] = r
  end
  return res, off
end
local pack_opt
pack_opt = function(self)
  return sp(">Hs2", self.code, tostring(self.data))
end
local edns_opts = {
  [8] = {
    "client_subnet",
    {
      "family",
      "source_netmask",
      "scope_netmask",
      "subnet"
    },
    ">H B B "
  },
  [65001] = {
    "requestor_mac",
    {
      "mac"
    }
  },
  [65073] = {
    "requestor_mac_str",
    {
      "macstr"
    }
  }
}
for k, v in pairs(edns_opts) do
  if type(k) == "number" then
    edns_opts[v[1]] = k
  end
end
local _opt_mt = {
  __tostring = pack_opt
}
local parse_opt
parse_opt = function(self, off)
  if off == nil then
    off = 1
  end
  local code, data, _off = su(">Hs2", self, off)
  local len = #data
  do
    local opt_parser = edns_opts[code]
    if opt_parser then
      local typ, fields, fmt
      typ, fields, fmt = opt_parser[1], opt_parser[2], opt_parser[3]
      if fmt then
        local _data = {
          su(fmt, data)
        }
        _data[#_data] = sub(data, _data[#_data])
        data = _data
      else
        data = {
          data
        }
      end
      data.type = typ
      for i = 1, #fields do
        data[fields[i]] = data[i]
      end
      setmetatable(data, {
        __tostring = function(self)
          return fmt and sp(fmt, unpack((function()
            local _accum_0 = { }
            local _len_0 = 1
            for _index_0 = 1, #fields do
              local field = fields[_index_0]
              _accum_0[_len_0] = data[field]
              _len_0 = _len_0 + 1
            end
            return _accum_0
          end)())) or self[1]
        end
      })
    else
      setmetatable({
        data
      }, {
        __tostring = function(self)
          return self[1]
        end
      })
    end
  end
  return setmetatable({
    code = code,
    len = len,
    data = data
  }, _opt_mt), _off
end
local parse_opts
parse_opts = function(self)
  local opts, off = { }, 1
  while off < #self do
    opts[#opts + 1], off = parse_opt(self, off)
  end
  return opts
end
local pack
pack = function(self)
  self.header.qdcount = #self.questions
  self.header.ancount = #self.answers
  self.header.nscount = #self.authorities
  self.header.arcount = #self.additionals
  local questions = concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    local _list_0 = self.questions
    for _index_0 = 1, #_list_0 do
      local q = _list_0[_index_0]
      _accum_0[_len_0] = pack_question(q)
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)())
  local answers = concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    local _list_0 = self.answers
    for _index_0 = 1, #_list_0 do
      local r = _list_0[_index_0]
      _accum_0[_len_0] = pack_rr(r)
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)())
  local authorities = concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    local _list_0 = self.authorities
    for _index_0 = 1, #_list_0 do
      local r = _list_0[_index_0]
      _accum_0[_len_0] = pack_rr(r)
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)())
  local additionals = concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    local _list_0 = self.additionals
    for _index_0 = 1, #_list_0 do
      local r = _list_0[_index_0]
      _accum_0[_len_0] = pack_rr(r)
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)())
  local body = questions .. answers .. authorities .. additionals
  self.header.size = 12 + #body
  return pack_header(self.header) .. body
end
local _mt = {
  __tostring = pack,
  __index = function(self, k)
    return self.header[k]
  end
}
local parse
parse = function(self, l7_off, is_tcp)
  local header, _off = parse_header(self, l7_off, is_tcp)
  if not header then
    return nil, l7_off, "No DNS data"
  end
  local questions
  questions, _off = parse_questions(self, _off, header.qdcount, l7_off)
  local answers
  answers, _off = parse_rrs(self, _off, header.ancount, l7_off)
  local authorities
  authorities, _off = parse_rrs(self, _off, header.nscount, l7_off)
  local additionals
  additionals, _off = parse_rrs(self, _off, header.arcount, l7_off)
  return setmetatable({
    header = header,
    question = questions[1],
    questions = questions,
    answers = answers,
    authorities = authorities,
    additionals = additionals
  }, _mt), _off
end
local classes = bidirectional({
  "IN",
  "CS",
  "CH",
  "HS",
  "NONE"
})
local rcodes = bidirectional(zero_indexed({
  "NOERROR",
  "FORMERR",
  "SERVFAIL",
  "NXDOMAIN",
  "NOTIMP",
  "REFUSED"
}))
local types = bidirectional({
  "A",
  "NS",
  "MD",
  "MF",
  "CNAME",
  "SOA",
  "MB",
  "MG",
  "MR",
  "NULL",
  "WKS",
  "PTR",
  "HINFO",
  "MINFO",
  "MX",
  "TXT",
  "RP",
  "AFSDB",
  "X25",
  "ISDN",
  "RT",
  "NSAP",
  "NSAP-PTR",
  "SIG",
  "KEY",
  "PX",
  "GPOS",
  "AAAA",
  "LOC",
  "NXT",
  "EID",
  "NIMLOC",
  "SRV",
  "ATMA",
  "NAPTR",
  "KX",
  "CERT",
  "A6",
  "DNAME",
  "SINK",
  "OPT",
  "APL",
  "DS",
  "SSHFP",
  "IPSECKEY",
  "RRSIG",
  "NSEC",
  "DNSKEY",
  "DHCID",
  "NSEC3",
  "NSEC3PARAM",
  "TLSA",
  "SMIMEA",
  "Unassigned",
  "HIP",
  "NINFO",
  "RKEY",
  "TALINK",
  "CDS",
  "CDNSKEY",
  "OPENPGPKEY",
  "CSYNC",
  "ZONEMD",
  "SVCB",
  "HTTPS",
  "DSYNC",
  [99] = "SPF",
  [108] = "EUI48",
  [109] = "EUI64",
  [249] = "TKEY",
  [250] = "TSIG",
  [251] = "IXFR",
  [252] = "AXFR",
  [253] = "MAILB",
  [254] = "MAILA",
  [255] = "ANY",
  [256] = "URI",
  [257] = "CAA",
  [258] = "AVC",
  [259] = "DOA",
  [260] = "AMTRELAY",
  [32768] = "TA",
  [32769] = "DLV"
})
local ede_codes = bidirectional(zero_indexed({
  "Other",
  "Unsupported_DNSKEY_Algorithm",
  "Unsupported_DS_Digest_Type",
  "Stale_Answer",
  "Forged_Answer",
  "DNSSEC_Indeterminate",
  "DNSSEC_Bogus",
  "Signature_Expired",
  "Signature_Not_Yet_Valid",
  "DNSKEY_Missing",
  "RRSIGs_Missing",
  "No_Zone_Key_Bit_Set",
  "NSEC_Missing",
  "Cached_Error",
  "Not_Ready",
  "Blocked",
  "Censored",
  "Filtered",
  "Prohibited",
  "Stale_NXDOMAIN_Answer",
  "Not_Authoritative",
  "Not_Supported",
  "No_Reachable_Authority",
  "Network_Error",
  "Invalid_Data"
}))
return {
  parse = parse,
  pack = pack,
  parse_header = parse_header,
  pack_header = pack_header,
  label = label,
  labels = labels,
  parse_question = parse_question,
  pack_question = pack_question,
  parse_questions = parse_questions,
  classes = classes,
  parse_rr = parse_rr,
  pack_rr = pack_rr,
  parse_rrs = parse_rrs,
  rcodes = rcodes,
  parse_opt = parse_opt,
  parse_opts = parse_opts,
  edns_opts = edns_opts,
  types = types,
  ede_codes = ede_codes
}
