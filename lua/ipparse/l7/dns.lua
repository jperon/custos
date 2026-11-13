local need_bytes
need_bytes = require("ipparse").need_bytes
local bidirectional, zero_indexed
do
  local _obj_0 = require("ipparse.fun.tables")
  bidirectional, zero_indexed = _obj_0.bidirectional, _obj_0.zero_indexed
end
local sp, su, sub
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su, sub = _obj_0.pack, _obj_0.unpack, _obj_0.sub
end
local concat
concat = table.concat
local byte
byte = string.byte
local band, bor, bnot, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, lshift, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.lshift, _obj_0.rshift
end
local u16
u16 = function(s, off)
  local a, b = byte(s, off, off + 1)
  return a * 256 + b
end
local u32
u32 = function(s, off)
  local a, b, c, d = byte(s, off, off + 3)
  return a * 16777216 + b * 65536 + c * 256 + d
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
      return band(rshift(self.qr_opcode_aa_tc_rd, 3), 0xf)
    elseif "aa" == _exp_0 then
      return band(self.qr_opcode_aa_tc_rd, 0x04) ~= 0
    elseif "tc" == _exp_0 then
      return band(self.qr_opcode_aa_tc_rd, 0x02) ~= 0
    elseif "rd" == _exp_0 then
      return band(self.qr_opcode_aa_tc_rd, 0x01) ~= 0
    elseif "ra" == _exp_0 then
      return band(self.ra_z_rcode, 0x80) ~= 0
    elseif "z" == _exp_0 then
      return band(rshift(self.ra_z_rcode, 4), 0x07)
    elseif "rcode" == _exp_0 then
      return band(self.ra_z_rcode, 0x0f)
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
    elseif "ra" == _exp_0 then
      if val then
        self.ra_z_rcode = bor(self.ra_z_rcode, 0x80)
      else
        self.ra_z_rcode = band(self.ra_z_rcode, bnot(0x80))
      end
    elseif "z" == _exp_0 then
      self.ra_z_rcode = bor(band(self.ra_z_rcode, bnot(0x70)), lshift(band(val, 0x07), 4))
    elseif "rcode" == _exp_0 then
      self.ra_z_rcode = bor(band(self.ra_z_rcode, bnot(0x0f)), band(val, 0x0f))
    else
      return rawset(self, flag, val)
    end
  end
}
local parse_header
parse_header = function(self, off, is_tcp)
  local len = #self - off + 1
  local size
  if is_tcp then
    if len < 2 then
      return nil, "No DNS data"
    end
    size = u16(self, off)
    off = off + 2
    len = len - 2
  end
  if len < 12 then
    return nil, "No DNS data"
  end
  local id = u16(self, off)
  local qr_opcode_aa_tc_rd = byte(self, off + 2)
  local ra_z_rcode = byte(self, off + 3)
  local qdcount = u16(self, off + 4)
  local ancount = u16(self, off + 6)
  local nscount = u16(self, off + 8)
  local arcount = u16(self, off + 10)
  local data_off = off + 12
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
local new_header
new_header = function(opts)
  local h = setmetatable({
    id = 0,
    qr_opcode_aa_tc_rd = 0,
    ra_z_rcode = 0,
    qdcount = 0,
    ancount = 0,
    nscount = 0,
    arcount = 0
  }, _header_mt)
  if opts then
    for k, v in pairs(opts) do
      h[k] = v
    end
  end
  return h
end
local labels, label_parts, walk_name
label_parts = function(self, off, l7_off, parts, visited, depth, seed)
  local data_len = #self
  if off < 1 or off > data_len then
    return nil, nil, "invalid label offset " .. tostring(off), off, false
  end
  local size = byte(self, off)
  local _off = off + 1
  if size == 0 then
    return _off, nil, nil, nil, false
  end
  if band(size, 0xC0) == 0xC0 then
    if _off > data_len then
      return nil, nil, "truncated DNS compression pointer", off, false
    end
    local pos = byte(self, _off)
    local ptr = lshift(band(size, 0x3F), 8) + pos
    local target_off = l7_off + ptr
    if target_off < l7_off or target_off > data_len then
      return nil, nil, "DNS compression pointer out of bounds (" .. tostring(ptr) .. ")", _off + 1, false
    end
    if depth >= 32 then
      return nil, nil, "DNS compression pointer recursion limit reached", _off + 1, false
    end
    if (visited and visited[target_off]) or seed == target_off then
      return nil, nil, "DNS compression pointer loop at " .. tostring(ptr), _off + 1, false
    end
    local v_next, seed_next = visited, seed
    if not v_next and seed_next then
      v_next = {
        [seed_next] = true
      }
      seed_next = nil
    end
    if v_next then
      v_next[target_off] = true
    else
      seed_next = target_off
    end
    local target_parts = parts
    local joined = nil
    if not (target_parts) then
      target_parts = { }
      joined = true
    end
    local n0 = #target_parts
    local _, err = walk_name(self, target_off, l7_off, target_parts, v_next, depth + 1, seed_next)
    if err then
      return nil, nil, err, _off + 1, false
    end
    if #target_parts == n0 then
      target_parts[#target_parts + 1] = ""
    end
    if joined then
      return _off + 1, concat(target_parts, "."), nil, nil, true
    end
    return _off + 1, nil, nil, nil, true
  end
  if band(size, 0xC0) == 0 then
    if off + size > data_len then
      return nil, nil, "truncated DNS label (len=" .. tostring(size) .. ")", off, false
    end
    return off + size + 1, sub(self, off + 1, off + size), nil, nil, false
  end
  return nil, nil, "invalid DNS label prefix at offset " .. tostring(off), off, false
end
walk_name = function(self, off, l7_off, parts, visited, depth, seed)
  local cur = off
  local n = #parts
  for i = 1, 1024 do
    local next_off, seg, err, _, from_ptr = label_parts(self, cur, l7_off, parts, visited, depth, seed)
    if err then
      return nil, err, cur
    end
    if seg then
      n = n + 1
      parts[n] = seg
    elseif not from_ptr then
      return next_off, nil, nil
    end
    cur = next_off
    if from_ptr then
      break
    end
  end
  return cur, nil, nil
end
local label
label = function(self, off, l7_off, visited, depth)
  if l7_off == nil then
    l7_off = 1
  end
  if visited == nil then
    visited = nil
  end
  if depth == nil then
    depth = 0
  end
  local next_off, seg, err, err_off, from_ptr = label_parts(self, off, l7_off, nil, visited, depth, nil)
  if err then
    return nil, err_off, nil, err
  end
  if not (seg or from_ptr) then
    return nil, next_off
  end
  if from_ptr then
    return seg, next_off, true
  end
  return seg, next_off
end
labels = function(self, off, l7_off, visited, depth)
  if visited == nil then
    visited = nil
  end
  if depth == nil then
    depth = 0
  end
  local lbls = { }
  local cur = off
  for i = 1, 1024 do
    local lbl_segment, next_parse_off, is_from_pointer, err = label(self, cur, l7_off, visited, depth)
    if err then
      return nil, cur, err
    end
    if not lbl_segment then
      cur = next_parse_off
      break
    end
    lbls[i] = lbl_segment
    cur = next_parse_off
    if is_from_pointer then
      break
    end
  end
  return lbls, cur
end
local name_string
name_string = function(self, off, l7_off, cache)
  local target = nil
  if cache then
    local size = byte(self, off)
    if off >= 1 and off + 1 <= #self and band(size, 0xC0) == 0xC0 then
      local t = l7_off + lshift(band(size, 0x3F), 8) + byte(self, off + 1)
      if t >= l7_off and t <= #self then
        target = t
        local hit = cache[t]
        if hit then
          return hit, off + 2
        end
      end
    end
  end
  local parts = { }
  local next_off, err, fail_off = walk_name(self, off, l7_off, parts, nil, 0, nil)
  if err then
    return nil, fail_off, err
  end
  local name = concat(parts, ".")
  if cache then
    cache[off] = name
    if target then
      cache[target] = name
    end
  end
  return name, next_off
end
local pack_question
pack_question = function(self)
  return self.qname .. sp(">H H", self.qtype, self.qclass)
end
local _question_mt = {
  __tostring = pack_question
}
local parse_question
parse_question = function(self, off, l7_off, cache)
  local lbls, _off, err = labels(self, off, l7_off)
  if not (lbls) then
    return nil, off, err
  end
  if not (need_bytes(self, _off, 4)) then
    return nil, off, "truncated DNS question fields"
  end
  local qname = sub(self, off, _off - 1)
  local qtype = u16(self, _off)
  local qclass = u16(self, _off + 2)
  _off = _off + 4
  local name = concat(lbls, ".")
  if cache then
    cache[off] = name
  end
  return setmetatable({
    name = name,
    qname = qname,
    qtype = qtype,
    qclass = qclass,
    off = off,
    end_off = _off - 1
  }, _question_mt), _off
end
local parse_questions
parse_questions = function(self, off, qdcount, l7_off, cache)
  local res = { }
  for i = 1, qdcount do
    local q, err
    q, off, err = parse_question(self, off, l7_off, cache)
    if not (q) then
      return nil, off, err
    end
    res[i] = q
  end
  return res, off
end
local pack_rr
pack_rr = function(self)
  local _rclass = self.rclass or (self.rtype == 0x29 and 0 or 1)
  local _ttl = self.ttl or 0
  return self.rname .. sp(">H H I4 s2", self.rtype, _rclass, _ttl, self.rdata)
end
local _rr_mt = {
  __tostring = pack_rr
}
local parse_rr
parse_rr = function(self, off, l7_off, cache)
  local name_str, _off, err = name_string(self, off, l7_off, cache)
  if not (name_str) then
    return nil, off, err
  end
  if not (need_bytes(self, _off, 10)) then
    return nil, off, "truncated DNS resource record header"
  end
  local rname = sub(self, off, _off - 1)
  local rtype = u16(self, _off)
  local rclass = u16(self, _off + 2)
  local ttl = u32(self, _off + 4)
  local rdlen = u16(self, _off + 8)
  _off = _off + 10
  if not (need_bytes(self, _off, rdlen)) then
    return nil, off, "truncated DNS resource record data"
  end
  local rdata = sub(self, _off, _off + rdlen - 1)
  _off = _off + rdlen
  return setmetatable({
    name = name_str,
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
parse_rrs = function(self, off, count, l7_off, cache)
  local res = { }
  for i = 1, count do
    local r, err
    r, off, err = parse_rr(self, off, l7_off, cache)
    if not (r) then
      return nil, off, err
    end
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
local _raw_opt_data_mt = {
  __tostring = function(self)
    return self[1]
  end
}
local _ecs_data_mt = {
  __tostring = function(self)
    return sp(">H B B ", self.family, self.source_netmask, self.scope_netmask) .. self.subnet
  end
}
local parse_opt
parse_opt = function(self, off)
  if off == nil then
    off = 1
  end
  if not (need_bytes(self, off, 4)) then
    return nil, off, "truncated EDNS option header"
  end
  local code, len, _off = su(">H H", self, off)
  if not (need_bytes(self, _off, len)) then
    return nil, off, "truncated EDNS option data"
  end
  local raw_data = sub(self, _off, _off + len - 1)
  _off = _off + len
  local data = nil
  do
    local opt_parser = edns_opts[code]
    if opt_parser then
      local typ, fields, fmt
      typ, fields, fmt = opt_parser[1], opt_parser[2], opt_parser[3]
      if fmt and code == 8 then
        if not (need_bytes(raw_data, 1, 4)) then
          return nil, off, "truncated EDNS client_subnet option"
        end
        local family, source_netmask, scope_netmask, data_off = su(fmt, raw_data)
        local _data = {
          family,
          source_netmask,
          scope_netmask,
          sub(raw_data, data_off)
        }
        data = _data
      else
        data = {
          raw_data
        }
      end
      data.type = typ
      for i = 1, #fields do
        data[fields[i]] = data[i]
      end
      setmetatable(data, (fmt and code == 8 and _ecs_data_mt or _raw_opt_data_mt))
    else
      data = setmetatable({
        raw_data
      }, _raw_opt_data_mt)
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
  while off <= #self do
    local opt, err
    opt, off, err = parse_opt(self, off)
    if not (opt) then
      return nil, off, err
    end
    opts[#opts + 1] = opt
  end
  return opts
end
local pack
pack = function(self)
  self.header.qdcount = #self.questions
  self.header.ancount = #self.answers
  self.header.nscount = #self.authorities
  self.header.arcount = #self.additionals
  local parts = { }
  local n = 1
  local body_len = 0
  local _list_0 = self.questions
  for _index_0 = 1, #_list_0 do
    local q = _list_0[_index_0]
    local s = pack_question(q)
    n = n + 1
    parts[n] = s
    body_len = body_len + #s
  end
  local _list_1 = self.answers
  for _index_0 = 1, #_list_1 do
    local r = _list_1[_index_0]
    local s = pack_rr(r)
    n = n + 1
    parts[n] = s
    body_len = body_len + #s
  end
  local _list_2 = self.authorities
  for _index_0 = 1, #_list_2 do
    local r = _list_2[_index_0]
    local s = pack_rr(r)
    n = n + 1
    parts[n] = s
    body_len = body_len + #s
  end
  local _list_3 = self.additionals
  for _index_0 = 1, #_list_3 do
    local r = _list_3[_index_0]
    local s = pack_rr(r)
    n = n + 1
    parts[n] = s
    body_len = body_len + #s
  end
  if rawget(self.header, "size") then
    self.header.size = 12 + body_len
  end
  parts[1] = pack_header(self.header)
  return concat(parts)
end
local _mt = {
  __tostring = pack,
  __index = function(self, k)
    return self.header[k]
  end
}
local parse
parse = function(self, l7_off, is_tcp)
  local header, _off_or_err = parse_header(self, l7_off, is_tcp)
  if not header then
    return nil, l7_off, _off_or_err or "No DNS data"
  end
  local _off = _off_or_err
  local cache = nil
  if header.ancount + header.nscount + header.arcount > 0 then
    cache = { }
  end
  local questions, err
  questions, _off, err = parse_questions(self, _off, header.qdcount, l7_off, cache)
  if not (questions) then
    return nil, _off, err
  end
  local answers
  answers, _off, err = parse_rrs(self, _off, header.ancount, l7_off, cache)
  if not (answers) then
    return nil, _off, err
  end
  local authorities
  authorities, _off, err = parse_rrs(self, _off, header.nscount, l7_off, cache)
  if not (authorities) then
    return nil, _off, err
  end
  local additionals
  additionals, _off, err = parse_rrs(self, _off, header.arcount, l7_off, cache)
  if not (additionals) then
    return nil, _off, err
  end
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
  [254] = "NONE",
  [255] = "ANY"
})
local rcodes = bidirectional(zero_indexed({
  "NOERROR",
  "FORMERR",
  "SERVFAIL",
  "NXDOMAIN",
  "NOTIMP",
  "REFUSED"
}))
local opcodes = bidirectional(zero_indexed({
  "QUERY",
  "IQUERY",
  "STATUS",
  "UNASSIGNED",
  "NOTIFY",
  "UPDATE"
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
local new
new = function(self)
  self.header = self.header or new_header()
  self.questions = self.questions or { }
  self.answers = self.answers or { }
  self.authorities = self.authorities or { }
  self.additionals = self.additionals or { }
  return setmetatable(self, _mt)
end
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
  opcodes = opcodes,
  parse_opt = parse_opt,
  parse_opts = parse_opts,
  edns_opts = edns_opts,
  types = types,
  ede_codes = ede_codes,
  new_header = new_header,
  new = new
}
