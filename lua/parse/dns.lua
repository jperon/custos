local read_u8, read_u16, read_u32
do
  local _obj_0 = require("parse/ip")
  read_u8, read_u16, read_u32 = _obj_0.read_u8, _obj_0.read_u16, _obj_0.read_u32
end
local bit = require("bit")
local QR_BIT = 0x80
local OPCODE_MASK = 0x78
local QTYPE = {
  A = 1,
  NS = 2,
  CNAME = 5,
  SOA = 6,
  MX = 15,
  AAAA = 28,
  TXT = 16,
  SRV = 33,
  ANY = 255
}
local QTYPE_NAME = { }
for k, v in pairs(QTYPE) do
  QTYPE_NAME[v] = k
end
local RCODE = {
  NOERROR = 0,
  FORMERR = 1,
  SERVFAIL = 2,
  NXDOMAIN = 3,
  REFUSED = 5
}
local QTYPE_OPT = 41
local EDE_FILTERED = 15
local EDE_OTHER = 0
local EDE_EXTRA_TEXT = "Ne intretis."
local EDE_TTL_TEXT = "Custos vigilat."
local EDNS_OPT_EDE = 0x000F
local EDNS_OPT_LANG = 0
local EDNS_OPT_FORG = 0
local FILTER_LANG = "la"
local FILTER_ORG = "custos"
local parse_header
parse_header = function(buf)
  if #buf < 12 then
    return nil
  end
  local flags_hi = read_u8(buf, 3)
  local flags_lo = read_u8(buf, 4)
  return {
    txid = read_u16(buf, 1),
    is_response = bit.band(flags_hi, QR_BIT) ~= 0,
    opcode = bit.rshift(bit.band(flags_hi, OPCODE_MASK), 3),
    aa = bit.band(flags_hi, 0x04) ~= 0,
    tc = bit.band(flags_hi, 0x02) ~= 0,
    rd = bit.band(flags_hi, 0x01) ~= 0,
    ra = bit.band(flags_lo, 0x80) ~= 0,
    rcode = bit.band(flags_lo, 0x0F),
    qdcount = read_u16(buf, 5),
    ancount = read_u16(buf, 7),
    nscount = read_u16(buf, 9),
    arcount = read_u16(buf, 11)
  }
end
local decode_name
decode_name = function(buf, offset)
  local labels = { }
  local pos = offset
  local consumed = 0
  local jumped = false
  local safety = 0
  while pos <= #buf do
    safety = safety + 1
    if safety > 64 then
      return nil, 0
    end
    local len = read_u8(buf, pos)
    if len == 0 then
      if not (jumped) then
        consumed = consumed + 1
      end
      break
    elseif bit.band(len, 0xC0) == 0xC0 then
      if pos + 1 > #buf then
        return nil, 0
      end
      local high = bit.band(len, 0x3F)
      local low = read_u8(buf, pos + 1)
      local ptr = bit.bor(bit.lshift(high, 8), low) + 1
      if not (jumped) then
        consumed = consumed + 2
      end
      jumped = true
      pos = ptr
    else
      local label_end = pos + len
      if label_end > #buf then
        return nil, 0
      end
      table.insert(labels, buf:sub(pos + 1, label_end))
      pos = label_end + 1
      if not (jumped) then
        consumed = consumed + (len + 1)
      end
    end
  end
  return table.concat(labels, "."), consumed
end
local parse_questions
parse_questions = function(buf, qdcount)
  local questions = { }
  local pos = 13
  for _ = 1, qdcount do
    if pos > #buf then
      break
    end
    local qname, consumed = decode_name(buf, pos)
    if not (qname) then
      return nil, nil
    end
    pos = pos + consumed
    if pos + 3 > #buf then
      return nil, nil
    end
    local qtype = read_u16(buf, pos)
    local qclass = read_u16(buf, pos + 2)
    pos = pos + 4
    table.insert(questions, {
      qname = qname,
      qtype = qtype,
      qclass = qclass,
      qtype_name = QTYPE_NAME[qtype] or ("TYPE" .. tostring(qtype))
    })
  end
  return questions, pos
end
local parse_answers
parse_answers = function(buf, ancount, start_offset)
  local answers = { }
  local pos = start_offset
  for _ = 1, ancount do
    if pos > #buf then
      break
    end
    local name, consumed = decode_name(buf, pos)
    if not (name) then
      break
    end
    pos = pos + consumed
    if pos + 9 > #buf then
      break
    end
    local rtype = read_u16(buf, pos)
    local rclass = read_u16(buf, pos + 2)
    local ttl = read_u32(buf, pos + 4)
    local ttl_offset = pos + 4
    local rdlength = read_u16(buf, pos + 8)
    pos = pos + 10
    if pos + rdlength - 1 > #buf then
      break
    end
    local rdata_str
    local _exp_0 = rtype
    if QTYPE.A == _exp_0 then
      rdata_str = tostring(buf:byte(pos)) .. "." .. tostring(buf:byte(pos + 1)) .. "." .. tostring(buf:byte(pos + 2)) .. "." .. tostring(buf:byte(pos + 3))
    elseif QTYPE.AAAA == _exp_0 then
      local groups
      do
        local _accum_0 = { }
        local _len_0 = 1
        for g = 0, 7 do
          _accum_0[_len_0] = string.format("%x", read_u16(buf, pos + g * 2))
          _len_0 = _len_0 + 1
        end
        groups = _accum_0
      end
      rdata_str = table.concat(groups, ":")
    elseif QTYPE.CNAME == _exp_0 then
      local cname
      cname, _ = decode_name(buf, pos)
      rdata_str = cname or "?"
    else
      rdata_str = "(rdata " .. tostring(rdlength) .. "B)"
    end
    table.insert(answers, {
      name = name,
      rtype = rtype,
      rtype_name = QTYPE_NAME[rtype] or "TYPE" .. tostring(rtype),
      ttl = ttl,
      ttl_offset = ttl_offset,
      rdlength = rdlength,
      rdata_str = rdata_str,
      rclass = rclass,
      rdata_raw = buf:sub(pos, pos + rdlength - 1)
    })
    pos = pos + rdlength
  end
  return answers
end
local parse_dns
parse_dns = function(buf)
  local hdr = parse_header(buf)
  if not (hdr) then
    return nil
  end
  local questions, ans_offset = parse_questions(buf, hdr.qdcount)
  if not (questions) then
    return nil
  end
  local answers = { }
  if hdr.is_response and hdr.ancount > 0 then
    answers = parse_answers(buf, hdr.ancount, ans_offset)
  end
  return {
    hdr = hdr,
    questions = questions,
    answers = answers
  }
end
local patch_ttl
patch_ttl = function(buf_ptr, answers, dns_offset, new_ttl)
  for _index_0 = 1, #answers do
    local ans = answers[_index_0]
    local abs_off = dns_offset + ans.ttl_offset - 1
    buf_ptr[abs_off] = bit.rshift(bit.band(new_ttl, 0xFF000000), 24)
    buf_ptr[abs_off + 1] = bit.rshift(bit.band(new_ttl, 0x00FF0000), 16)
    buf_ptr[abs_off + 2] = bit.rshift(bit.band(new_ttl, 0x0000FF00), 8)
    buf_ptr[abs_off + 3] = bit.band(new_ttl, 0x000000FF)
  end
end
local build_opt_rdata
build_opt_rdata = function(options)
  local parts = { }
  for _index_0 = 1, #options do
    local _continue_0 = false
    repeat
      local opt = options[_index_0]
      if opt.code == 0 then
        _continue_0 = true
        break
      end
      local data = opt.data
      local dlen = #data
      parts[#parts + 1] = string.char(bit.rshift(bit.band(opt.code, 0xFF00), 8), bit.band(opt.code, 0xFF), bit.rshift(bit.band(dlen, 0xFF00), 8), bit.band(dlen, 0xFF)) .. data
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return table.concat(parts)
end
local skip_name_bytes
skip_name_bytes = function(buf, pos)
  local len = #buf
  local consumed = 0
  local safety = 0
  while pos <= len do
    safety = safety + 1
    if safety > 128 then
      return 0
    end
    local b = buf:byte(pos)
    if b == 0 then
      consumed = consumed + 1
      break
    elseif bit.band(b, 0xC0) == 0xC0 then
      if pos + 1 > len then
        return 0
      end
      consumed = consumed + 2
      break
    elseif bit.band(b, 0xC0) ~= 0x00 then
      return 0
    else
      if pos + b > len then
        return 0
      end
      consumed = consumed + (b + 1)
      pos = pos + (b + 1)
    end
  end
  return consumed
end
local skip_rr
skip_rr = function(buf, pos)
  local name_bytes = skip_name_bytes(buf, pos)
  local name_end = pos + name_bytes
  if name_end + 9 > #buf then
    return nil
  end
  local rdlength = bit.bor(bit.lshift(buf:byte(name_end + 8), 8), buf:byte(name_end + 9))
  return name_bytes + 10 + rdlength
end
local append_ede_to_dns
append_ede_to_dns = function(dns_payload, options)
  local len = #dns_payload
  if len < 12 then
    return nil
  end
  local qdcount = read_u16(dns_payload, 5)
  local ancount = read_u16(dns_payload, 7)
  local nscount = read_u16(dns_payload, 9)
  local arcount = read_u16(dns_payload, 11)
  local new_rdata = build_opt_rdata(options)
  if #new_rdata == 0 then
    return dns_payload
  end
  local pos = 13
  for _ = 1, qdcount do
    local nb = skip_name_bytes(dns_payload, pos)
    if nb == 0 then
      return nil
    end
    pos = pos + (nb + 4)
    if pos > len + 1 then
      return nil
    end
  end
  for _ = 1, ancount + nscount do
    local nb = skip_rr(dns_payload, pos)
    if not (nb) then
      return nil
    end
    pos = pos + nb
  end
  local opt_start = nil
  local tmp_pos = pos
  for _ = 1, arcount do
    local nb = skip_rr(dns_payload, tmp_pos)
    if not (nb) then
      return nil
    end
    local name_bytes = skip_name_bytes(dns_payload, tmp_pos)
    if name_bytes == 0 and (dns_payload:byte(tmp_pos) ~= 0) then
      return nil
    end
    local type_pos = tmp_pos + name_bytes
    if type_pos + 1 > len then
      return nil
    end
    local rtype = read_u16(dns_payload, type_pos)
    if rtype == QTYPE_OPT then
      opt_start = tmp_pos
      break
    end
    tmp_pos = tmp_pos + nb
  end
  if not (opt_start) then
    return nil
  end
  local name_bytes = skip_name_bytes(dns_payload, opt_start)
  local rdlen_pos = opt_start + name_bytes + 8
  if rdlen_pos + 1 > len then
    return nil
  end
  local old_rdlen = read_u16(dns_payload, rdlen_pos)
  local rdata_start = rdlen_pos + 2
  local rdata_end = rdata_start + old_rdlen - 1
  if rdata_end > len then
    return nil
  end
  local new_rdlen = old_rdlen + #new_rdata
  local rdlen_hi = bit.rshift(bit.band(new_rdlen, 0xFF00), 8)
  local rdlen_lo = bit.band(new_rdlen, 0xFF)
  return dns_payload:sub(1, rdlen_pos - 1) .. string.char(rdlen_hi, rdlen_lo) .. dns_payload:sub(rdata_start, rdata_end) .. new_rdata .. dns_payload:sub(rdata_end + 1)
end
local build_refused
build_refused = function(dns, orig_buf)
  if not (dns and orig_buf) then
    return nil
  end
  local txid = dns.hdr.txid
  local qdcount = dns.hdr.qdcount
  local txid_hi = bit.rshift(bit.band(txid, 0xFF00), 8)
  local txid_lo = bit.band(txid, 0xFF)
  local qd_hi = bit.rshift(bit.band(qdcount, 0xFF00), 8)
  local qd_lo = bit.band(qdcount, 0xFF)
  local hdr = string.char(txid_hi, txid_lo, 0x81, 0x05, qd_hi, qd_lo, 0, 0, 0, 0, 0, 1)
  local _, ans_offset = parse_questions(orig_buf, qdcount)
  local qs_raw
  if ans_offset and ans_offset > 13 then
    qs_raw = orig_buf:sub(13, ans_offset - 1)
  else
    qs_raw = ""
  end
  local ede_data = string.char(0x00, EDE_FILTERED) .. EDE_EXTRA_TEXT
  local rdata = build_opt_rdata({
    {
      code = EDNS_OPT_EDE,
      data = ede_data
    },
    {
      code = EDNS_OPT_LANG,
      data = FILTER_LANG
    },
    {
      code = EDNS_OPT_FORG,
      data = FILTER_ORG
    }
  })
  local rdlen = #rdata
  local opt_hdr = string.char(0x00, 0x00, 0x29, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, bit.rshift(bit.band(rdlen, 0xFF00), 8), bit.band(rdlen, 0xFF))
  return hdr .. qs_raw .. opt_hdr .. rdata
end
local build_nxdomain
build_nxdomain = function(dns, orig_buf)
  if not (dns and orig_buf) then
    return nil
  end
  local txid = dns.hdr.txid
  local qdcount = dns.hdr.qdcount
  local qtype
  if dns.questions and #dns.questions > 0 then
    qtype = dns.questions[1].qtype
  else
    qtype = QTYPE.A
  end
  local txid_hi = bit.rshift(bit.band(txid, 0xFF00), 8)
  local txid_lo = bit.band(txid, 0xFF)
  local qd_hi = bit.rshift(bit.band(qdcount, 0xFF00), 8)
  local qd_lo = bit.band(qdcount, 0xFF)
  local hdr = string.char(txid_hi, txid_lo, 0x81, 0x03, qd_hi, qd_lo, 0, 1, 0, 0, 0, 1)
  local _, ans_offset = parse_questions(orig_buf, qdcount)
  local qs_raw
  if ans_offset and ans_offset > 13 then
    qs_raw = orig_buf:sub(13, ans_offset - 1)
  else
    qs_raw = ""
  end
  local ans_name_ptr = string.char(0xC0, 0x0C)
  local rdata = nil
  if qtype == QTYPE.A then
    rdata = string.char(0, 0, 0, 0)
  elseif qtype == QTYPE.AAAA then
    rdata = string.char(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
  else
    rdata = string.char(0, 0, 0, 0)
  end
  local rdlen = #rdata
  local qtype_hi = bit.rshift(bit.band(qtype, 0xFF00), 8)
  local qtype_lo = bit.band(qtype, 0xFF)
  local ttl_bytes = string.char(bit.rshift(bit.band(60, 0xFF000000), 24), bit.rshift(bit.band(60, 0x00FF0000), 16), bit.rshift(bit.band(60, 0x0000FF00), 8), bit.band(60, 0x000000FF))
  local rdlen_hi = bit.rshift(bit.band(rdlen, 0xFF00), 8)
  local rdlen_lo = bit.band(rdlen, 0xFF)
  local ans_rr = ans_name_ptr .. string.char(qtype_hi, qtype_lo, 0, 1) .. ttl_bytes .. string.char(rdlen_hi, rdlen_lo) .. rdata
  local ede_data = string.char(0x00, EDE_FILTERED) .. EDE_EXTRA_TEXT
  local opt_rdata = build_opt_rdata({
    {
      code = EDNS_OPT_EDE,
      data = ede_data
    },
    {
      code = EDNS_OPT_LANG,
      data = FILTER_LANG
    },
    {
      code = EDNS_OPT_FORG,
      data = FILTER_ORG
    }
  })
  local opt_rdlen = #opt_rdata
  local opt_hdr = string.char(0x00, 0x00, 0x29, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, bit.rshift(bit.band(opt_rdlen, 0xFF00), 8), bit.band(opt_rdlen, 0xFF))
  return hdr .. qs_raw .. ans_rr .. opt_hdr .. opt_rdata
end
return {
  parse_dns = parse_dns,
  parse_header = parse_header,
  parse_questions = parse_questions,
  parse_answers = parse_answers,
  decode_name = decode_name,
  patch_ttl = patch_ttl,
  build_refused = build_refused,
  build_nxdomain = build_nxdomain,
  build_opt_rdata = build_opt_rdata,
  skip_name_bytes = skip_name_bytes,
  skip_rr = skip_rr,
  append_ede_to_dns = append_ede_to_dns,
  QTYPE = QTYPE,
  QTYPE_NAME = QTYPE_NAME,
  QTYPE_OPT = QTYPE_OPT,
  RCODE = RCODE,
  EDE_FILTERED = EDE_FILTERED,
  EDE_EXTRA_TEXT = EDE_EXTRA_TEXT,
  EDE_OTHER = EDE_OTHER,
  EDE_TTL_TEXT = EDE_TTL_TEXT,
  EDNS_OPT_EDE = EDNS_OPT_EDE,
  EDNS_OPT_LANG = EDNS_OPT_LANG,
  EDNS_OPT_FORG = EDNS_OPT_FORG,
  FILTER_LANG = FILTER_LANG,
  FILTER_ORG = FILTER_ORG
}
