local util = require("ipparse.lib.util")
local test
test = util.test
local dns = require("ipparse.l7.dns")
local need_bytes
need_bytes = require("ipparse").need_bytes
local byte, sub
do
  local _obj_0 = string
  byte, sub = _obj_0.byte, _obj_0.sub
end
local concat
concat = table.concat
local band, lshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, lshift = _obj_0.band, _obj_0.lshift
end
local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local hex2bin
hex2bin = require("ipparse.init").hex2bin
local ref_labels
local ref_label
ref_label = function(s, off, l7_off, visited, depth)
  if l7_off == nil then
    l7_off = 1
  end
  if visited == nil then
    visited = nil
  end
  if depth == nil then
    depth = 0
  end
  if not (need_bytes(s, off, 1)) then
    return nil, off, nil, "invalid label offset " .. tostring(off)
  end
  local size = byte(s, off)
  local _off = off + 1
  if size == 0 then
    return nil, off + 1
  end
  if band(size, 0xC0) == 0xC0 then
    if not (need_bytes(s, off, 2)) then
      return nil, off, nil, "truncated DNS compression pointer"
    end
    local pos = byte(s, off + 1)
    local ptr = lshift(band(size, 0x3F), 8) + pos
    local target_off = l7_off + ptr
    if not (target_off >= l7_off and target_off <= #s) then
      return nil, _off + 1, nil, "DNS compression pointer out of bounds (" .. tostring(ptr) .. ")"
    end
    if depth >= 32 then
      return nil, _off + 1, nil, "DNS compression pointer recursion limit reached"
    end
    if visited and visited[target_off] then
      return nil, _off + 1, nil, "DNS compression pointer loop at " .. tostring(ptr)
    end
    visited = visited or { }
    visited[target_off] = true
    local pointed_labels, _, err = ref_labels(s, target_off, l7_off, visited, depth + 1)
    if not (pointed_labels) then
      return nil, _off + 1, nil, err
    end
    return concat(pointed_labels, "."), _off + 1, true
  end
  if band(size, 0xC0) == 0 then
    if not (need_bytes(s, off + 1, size)) then
      return nil, off, nil, "truncated DNS label (len=" .. tostring(size) .. ")"
    end
    return sub(s, off + 1, off + size), off + size + 1
  end
  return nil, off, nil, "invalid DNS label prefix at offset " .. tostring(off)
end
ref_labels = function(s, off, l7_off, visited, depth)
  if visited == nil then
    visited = nil
  end
  if depth == nil then
    depth = 0
  end
  local lbls = { }
  for i = 1, 1024 do
    local lbl_segment, next_parse_off, is_from_pointer, err = ref_label(s, off, l7_off, visited, depth)
    if err then
      return nil, off, err
    end
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
local ref_parse_question
ref_parse_question = function(s, off, l7_off)
  local lbls, _off, err = ref_labels(s, off, l7_off)
  if not (lbls) then
    return nil, off, err
  end
  if not (need_bytes(s, _off, 4)) then
    return nil, off, "truncated DNS question fields"
  end
  local qname = sub(s, off, _off - 1)
  local qtype, qclass
  qtype, qclass, _off = su(">H H", s, _off)
  return {
    name = concat(lbls, "."),
    qname = qname,
    qtype = qtype,
    qclass = qclass,
    off = off,
    end_off = _off - 1
  }, _off
end
local ref_parse_rr
ref_parse_rr = function(s, off, l7_off)
  local lbls, _off, err = ref_labels(s, off, l7_off)
  if not (lbls) then
    return nil, off, err
  end
  if not (need_bytes(s, _off, 10)) then
    return nil, off, "truncated DNS resource record header"
  end
  local rname = sub(s, off, _off - 1)
  local rtype, rclass, ttl, rdlen
  rtype, rclass, ttl, rdlen, _off = su(">H H I4 H", s, _off)
  if not (need_bytes(s, _off, rdlen)) then
    return nil, off, "truncated DNS resource record data"
  end
  local rdata = sub(s, _off, _off + rdlen - 1)
  _off = _off + rdlen
  return {
    name = concat(lbls, "."),
    rname = rname,
    rtype = rtype,
    rclass = rclass,
    ttl = ttl,
    rdata = rdata,
    off = off,
    end_off = _off - 1
  }, _off
end
local ref_parse_section
ref_parse_section = function(s, off, count, l7_off)
  local res = { }
  for i = 1, count do
    local r, err
    r, off, err = ref_parse_rr(s, off, l7_off)
    if not (r) then
      return nil, off, err
    end
    res[i] = r
  end
  return res, off
end
local ref_parse_questions
ref_parse_questions = function(s, off, qdcount, l7_off)
  local res = { }
  for i = 1, qdcount do
    local q, err
    q, off, err = ref_parse_question(s, off, l7_off)
    if not (q) then
      return nil, off, err
    end
    res[i] = q
  end
  return res, off
end
local ref_parse
ref_parse = function(s, l7_off, is_tcp)
  local header, _off_or_err = dns.parse_header(s, l7_off, is_tcp)
  if not (header) then
    return nil, l7_off, _off_or_err or "No DNS data"
  end
  local _off = _off_or_err
  local questions, err
  questions, _off, err = ref_parse_questions(s, _off, header.qdcount, l7_off)
  if not (questions) then
    return nil, _off, err
  end
  local answers
  answers, _off, err = ref_parse_section(s, _off, header.ancount, l7_off)
  if not (answers) then
    return nil, _off, err
  end
  local authorities
  authorities, _off, err = ref_parse_section(s, _off, header.nscount, l7_off)
  if not (authorities) then
    return nil, _off, err
  end
  local additionals
  additionals, _off, err = ref_parse_section(s, _off, header.arcount, l7_off)
  if not (additionals) then
    return nil, _off, err
  end
  return {
    header = header,
    question = questions[1],
    questions = questions,
    answers = answers,
    authorities = authorities,
    additionals = additionals
  }, _off
end
local fmt
fmt = function(v)
  if type(v) == "string" then
    return "\"" .. tostring(v) .. "\""
  else
    return tostring(v)
  end
end
local query_hex = "123401000001000000000000076578616d706c6503636f6d0000010001"
local resp_hex = "123481800001000100000000" .. "076578616d706c6503636f6d00" .. "00010001" .. "c00c" .. "00010001" .. "00000e10" .. "0004" .. "5db8d822"
local chain_hex = "123481800001000300000000" .. "03777777076578616d706c6503636f6d00" .. "00010001" .. "c00c" .. "00050001" .. "0000012c" .. "0012" .. "076578616d706c6503636f6d00" .. "c01e" .. "00010001" .. "0000012c" .. "0004" .. "5db8d822" .. "c00c" .. "00010001" .. "0000012c" .. "0004" .. "01020304"
local loop_hex = "000101000001000000000000" .. "c00c" .. "00010001"
local loop2_hex = "000101000001000000000000" .. "c00e" .. "c00c" .. "00010001"
local oob_hex = "000101000001000000000000" .. "c0ff" .. "00010001"
local bad_prefix_hex = "000101000001000000000000" .. "8003616263" .. "00010001"
local trunc_hex = "000101000001000000000000" .. "056162"
local chain_parts = { }
for i = 1, 40 do
  local ptr = 12 + 2 * i
  chain_parts[#chain_parts + 1] = sp(">B B", 0xC0 + math.floor(ptr / 256), ptr % 256)
end
chain_parts[#chain_parts + 1] = "\000"
local chain40_hex = "000101000001000000000000" .. (table.concat(chain_parts))
local long_parts = { }
for i = 1, 1100 do
  long_parts[#long_parts + 1] = "01" .. "61"
end
long_parts[#long_parts + 1] = "00"
local long_name_hex = "000101000001000000000000" .. (table.concat(long_parts)) .. "00010001"
local _pattern = { }
for i = 0, 255 do
  _pattern[#_pattern + 1] = string.char(i)
end
local PATTERN = table.concat(_pattern)
local packets = {
  hex2bin(query_hex),
  hex2bin(resp_hex),
  hex2bin(chain_hex),
  hex2bin(loop_hex),
  hex2bin(loop2_hex),
  hex2bin(oob_hex),
  hex2bin(bad_prefix_hex),
  hex2bin(trunc_hex),
  hex2bin(chain40_hex),
  hex2bin(long_name_hex),
  (PATTERN .. PATTERN):sub(3, 130),
  (PATTERN .. PATTERN):sub(100, 240),
  (PATTERN .. PATTERN):sub(200, 256)
}
local same
same = function(a, b, msg)
  return assert(a == b, tostring(msg) .. ": " .. tostring(fmt(a)) .. " != " .. tostring(fmt(b)))
end
local same_label
same_label = function(s, off, pi)
  local a1, a2, a3, a4 = dns.label(s, off, 1)
  local b1, b2, b3, b4 = ref_label(s, off, 1)
  local where = "label p" .. tostring(pi) .. " off=" .. tostring(off)
  same(a1, b1, tostring(where) .. " segment")
  same(a2, b2, tostring(where) .. " offset suivant")
  same(a3, b3, tostring(where) .. " pointeur")
  return same(a4, b4, tostring(where) .. " erreur")
end
local same_labels
same_labels = function(s, off, pi)
  local t1, o1, e1 = dns.labels(s, off, 1)
  local t2, o2, e2 = ref_labels(s, off, 1)
  local where = "labels p" .. tostring(pi) .. " off=" .. tostring(off)
  if type(t1) == "table" then
    assert(type(t2) == "table", tostring(where) .. ": la référence renvoie " .. tostring(fmt(t2)))
    same(#t1, #t2, tostring(where) .. " nombre de segments")
    for i = 1, #t1 do
      same(t1[i], t2[i], tostring(where) .. " segment " .. tostring(i))
    end
  else
    same(t1, t2, tostring(where) .. " résultat")
  end
  same(o1, o2, tostring(where) .. " offset suivant")
  return same(e1, e2, tostring(where) .. " erreur")
end
local same_q
same_q = function(a, b, msg)
  if a == nil or b == nil then
    same(a, b, msg)
    return 
  end
  local _list_0 = {
    "name",
    "qname",
    "qtype",
    "qclass",
    "off",
    "end_off"
  }
  for _index_0 = 1, #_list_0 do
    local k = _list_0[_index_0]
    same(a[k], b[k], tostring(msg) .. "." .. tostring(k))
  end
end
local same_rr
same_rr = function(a, b, msg)
  if a == nil or b == nil then
    same(a, b, msg)
    return 
  end
  local _list_0 = {
    "name",
    "rname",
    "rtype",
    "rclass",
    "ttl",
    "rdata",
    "off",
    "end_off"
  }
  for _index_0 = 1, #_list_0 do
    local k = _list_0[_index_0]
    same(a[k], b[k], tostring(msg) .. "." .. tostring(k))
  end
end
local same_msg
same_msg = function(a, b, msg)
  if a == nil or b == nil then
    same(a, b, msg)
    return 
  end
  local _list_0 = {
    "id",
    "qdcount",
    "ancount",
    "nscount",
    "arcount",
    "off",
    "data_off"
  }
  for _index_0 = 1, #_list_0 do
    local k = _list_0[_index_0]
    same(a.header[k], b.header[k], tostring(msg) .. ".header." .. tostring(k))
  end
  same(#a.questions, #b.questions, tostring(msg) .. " #questions")
  for i = 1, #a.questions do
    same_q(a.questions[i], b.questions[i], tostring(msg) .. ".q" .. tostring(i))
  end
  local _list_1 = {
    "answers",
    "authorities",
    "additionals"
  }
  for _index_0 = 1, #_list_1 do
    local sec = _list_1[_index_0]
    same(#a[sec], #b[sec], tostring(msg) .. " #" .. tostring(sec))
    for i = 1, #a[sec] do
      same_rr(a[sec][i], b[sec][i], tostring(msg) .. "." .. tostring(sec) .. tostring(i))
    end
  end
end
test("label: identique au code d'origine à chaque offset du corpus", function()
  for pi, s in ipairs(packets) do
    for off = 1, #s + 1 do
      same_label(s, off, pi)
    end
  end
end)
test("labels: identique au code d'origine à chaque offset du corpus", function()
  for pi, s in ipairs(packets) do
    for off = 1, #s + 1 do
      same_labels(s, off, pi)
    end
  end
end)
test("parse_question: identique au code d'origine à chaque offset", function()
  for pi, s in ipairs(packets) do
    for off = 1, #s + 1 do
      local a, ao, ae = dns.parse_question(s, off, 1)
      local b, bo, be = ref_parse_question(s, off, 1)
      local where = "parse_question p" .. tostring(pi) .. " off=" .. tostring(off)
      same_q(a, b, where)
      same(ao, bo, tostring(where) .. " offset suivant")
      same(ae, be, tostring(where) .. " erreur")
    end
  end
end)
test("parse_rr: identique au code d'origine à chaque offset", function()
  for pi, s in ipairs(packets) do
    for off = 1, #s + 1 do
      local a, ao, ae = dns.parse_rr(s, off, 1)
      local b, bo, be = ref_parse_rr(s, off, 1)
      local where = "parse_rr p" .. tostring(pi) .. " off=" .. tostring(off)
      same_rr(a, b, where)
      same(ao, bo, tostring(where) .. " offset suivant")
      same(ae, be, tostring(where) .. " erreur")
    end
  end
end)
test("parse: messages entiers identiques au code d'origine", function()
  for pi, s in ipairs(packets) do
    for _, is_tcp in ipairs({
      false,
      true
    }) do
      local a, ao, ae = dns.parse(s, 1, is_tcp)
      local b, bo, be = ref_parse(s, 1, is_tcp)
      local where = "parse p" .. tostring(pi) .. " tcp=" .. tostring(is_tcp)
      same_msg(a, b, where)
      same(ao, bo, tostring(where) .. " offset suivant")
      same(ae, be, tostring(where) .. " erreur")
    end
  end
end)
test("noms compressés: un seul table de segments résolue (pas de régression)", function()
  local s = hex2bin(resp_hex)
  local a = dns.parse_rr(s, 13 + #hex2bin("076578616d706c6503636f6d0000010001"), 1)
  local b = ref_parse_rr(s, 13 + #hex2bin("076578616d706c6503636f6d0000010001"), 1)
  same(a.name, b.name, "nom de l'answer compressé")
  local empty_ptr = hex2bin("000101000001000000000000" .. "c010" .. "0000" .. "00010001")
  local a2, _, ae2 = dns.parse_rr(empty_ptr, 13, 1)
  local b2, be2
  b2, _, be2 = ref_parse_rr(empty_ptr, 13, 1)
  if a2 then
    return same(a2.name, b2.name, "nom vide via pointeur")
  else
    return same(ae2, be2, "erreur sur nom vide via pointeur")
  end
end)
return util.summary("l7/dns_names")
