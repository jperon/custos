#!/usr/bin/env moon
-- tests/sip/test_parser.moon
-- Unit tests for src/sip/parser.moon
-- Run: cd /path/to/custos && moonc src/sip/parser.moon && moon tests/sip/test_parser.moon

package.path = package.path .. ";./src/?.lua;./src/?/init.lua"

parser = require "sip.parser"
parse  = parser.parse

-- ── Helpers ───────────────────────────────────────────────────────────────────

pass = 0
fail = 0

check = (name, cond, got, expected) ->
  if cond
    pass += 1
    -- io.stdout\write "  OK  #{name}\n"
  else
    fail += 1
    io.stderr\write "FAIL #{name}\n"
    io.stderr\write "     got:      #{tostring got}\n"
    io.stderr\write "     expected: #{tostring expected}\n"

eq = (a, b) -> a == b

-- ── Test data ─────────────────────────────────────────────────────────────────

INVITE = [[INVITE sip:+33123456789@prx1.sip.keyyo.net SIP/2.0
Via: SIP/2.0/UDP 10.35.3.2:5060;branch=z9hG4bK1234
From: <sip:5001@10.35.3.1>;tag=abc
To: <sip:+33123456789@prx1.sip.keyyo.net>
Call-ID: call-1234@10.35.3.2
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 143

v=0
o=- 123 456 IN IP4 10.35.3.2
s=-
c=IN IP4 10.35.3.2
t=0 0
m=audio 10020 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
]]

OK_200 = [[SIP/2.0 200 OK
Via: SIP/2.0/UDP 10.35.3.2:5060;branch=z9hG4bK1234
From: <sip:5001@10.35.3.1>;tag=abc
To: <sip:+33123456789@prx1.sip.keyyo.net>;tag=xyz
Call-ID: call-1234@10.35.3.2
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 141

v=0
o=- 789 012 IN IP4 83.136.164.72
s=-
c=IN IP4 83.136.164.72
t=0 0
m=audio 20010 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
]]

OPTIONS = [[OPTIONS sip:prx1.sip.keyyo.net SIP/2.0
Via: SIP/2.0/UDP 10.35.3.2:5060;branch=z9hG4bKping
From: <sip:5001@10.35.3.1>;tag=keepalive
To: <sip:prx1.sip.keyyo.net>
Call-ID: keepalive-42@10.35.3.2
CSeq: 42 OPTIONS
Content-Length: 0

]]

NOT_SIP = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

CRLF_200 = OK_200\gsub "\n", "\r\n"

MULTI_C = [[SIP/2.0 183 Session Progress
Via: SIP/2.0/UDP 10.35.3.2:5060;branch=z9hG4bK5678
Call-ID: call-5678@10.35.3.2
CSeq: 2 INVITE
Content-Type: application/sdp
Content-Length: 200

v=0
o=- 111 222 IN IP4 83.136.161.72
s=-
c=IN IP4 83.136.161.72
t=0 0
m=audio 22000 RTP/AVP 0
c=IN IP4 83.136.163.72
m=video 22002 RTP/AVP 96
]]

IPV6_200 = [[SIP/2.0 200 OK
Via: SIP/2.0/UDP 10.35.3.2:5060;branch=z9hG4bK9999
Call-ID: call-ipv6@10.35.3.2
CSeq: 3 INVITE
Content-Type: application/sdp
Content-Length: 80

v=0
o=- 1 2 IN IP6 2001:db8::1
s=-
c=IN IP6 2001:db8::1
t=0 0
m=audio 5004 RTP/AVP 0
]]

ICE_SDP = [[SIP/2.0 183 Session Progress
Via: SIP/2.0/UDP 10.35.3.6:5060;branch=z9hG4bKice
Call-ID: call-ice@10.35.3.6
CSeq: 4 INVITE
Content-Type: application/sdp
Content-Length: 320

v=0
o=- 1 2 IN IP4 83.136.164.102
s=-
c=IN IP4 83.136.164.102
t=0 0
m=audio 61348 RTP/AVP 0 8
a=rtcp:61349 IN IP4 83.136.162.33
a=candidate:1 1 UDP 2130706431 83.136.162.33 61348 typ host
a=candidate:2 1 UDP 2130706431 83.136.164.102 61348 typ host
]]

-- ── Tests ─────────────────────────────────────────────────────────────────────

-- 1. Returns nil for non-SIP input
msg = parse NOT_SIP
check "nil for non-SIP", msg == nil, msg, nil

-- 2. Parses INVITE request
msg = parse INVITE
check "INVITE: not nil", msg != nil, msg, "table"
if msg
  check "INVITE: method",       eq(msg.method, "INVITE"),             msg.method, "INVITE"
  check "INVITE: no status",    msg.status_code == nil,               msg.status_code, nil
  check "INVITE: cseq_method",  eq(msg.cseq_method, "INVITE"),       msg.cseq_method, "INVITE"
  check "INVITE: call_id",      msg.call_id != nil,                   msg.call_id, "not nil"
  check "INVITE: content_type", eq(msg.content_type, "application/sdp"), msg.content_type, "application/sdp"
  check "INVITE: sdp_ips count", #msg.sdp_ips == 1,                  #msg.sdp_ips, 1
  if #msg.sdp_ips >= 1
    check "INVITE: sdp ip4",    eq(msg.sdp_ips[1].ip, "10.35.3.2"),  msg.sdp_ips[1].ip, "10.35.3.2"
    check "INVITE: sdp family", eq(msg.sdp_ips[1].family, "ip4"),    msg.sdp_ips[1].family, "ip4"

-- 3. Parses 200 OK response with SDP
msg = parse OK_200
check "200 OK: not nil", msg != nil, msg, "table"
if msg
  check "200 OK: no method",    msg.method == nil,                    msg.method, nil
  check "200 OK: status_code",  eq(msg.status_code, 200),            msg.status_code, 200
  check "200 OK: cseq_method",  eq(msg.cseq_method, "INVITE"),       msg.cseq_method, "INVITE"
  check "200 OK: sdp_ips count", #msg.sdp_ips == 1,                  #msg.sdp_ips, 1
  if #msg.sdp_ips >= 1
    check "200 OK: sdp ip",     eq(msg.sdp_ips[1].ip, "83.136.164.72"), msg.sdp_ips[1].ip, "83.136.164.72"

-- 4. Parses CRLF-terminated message
msg = parse CRLF_200
check "CRLF 200 OK: not nil",     msg != nil,                         msg, "table"
check "CRLF 200 OK: status_code", msg and eq(msg.status_code, 200),  msg and msg.status_code, 200
check "CRLF 200 OK: sdp ip",      msg and #msg.sdp_ips == 1,         msg and #msg.sdp_ips, 1

-- 5. OPTIONS (no SDP)
msg = parse OPTIONS
check "OPTIONS: method",       msg and eq(msg.method, "OPTIONS"),     msg and msg.method, "OPTIONS"
check "OPTIONS: no sdp_ips",   msg and #msg.sdp_ips == 0,            msg and #msg.sdp_ips, 0
check "OPTIONS: cseq_method",  msg and eq(msg.cseq_method, "OPTIONS"), msg and msg.cseq_method, "OPTIONS"

-- 6. Multiple c= lines in SDP
msg = parse MULTI_C
check "183: status_code",      msg and eq(msg.status_code, 183),     msg and msg.status_code, 183
check "183: sdp_ips count 2",  msg and #msg.sdp_ips == 2,            msg and #msg.sdp_ips, 2
if msg and #msg.sdp_ips >= 2
  check "183: sdp ip[1]",  eq(msg.sdp_ips[1].ip, "83.136.161.72"),  msg.sdp_ips[1].ip, "83.136.161.72"
  check "183: sdp ip[2]",  eq(msg.sdp_ips[2].ip, "83.136.163.72"),  msg.sdp_ips[2].ip, "83.136.163.72"

-- 7. IPv6 SDP
msg = parse IPV6_200
check "IPv6 200: not nil",     msg != nil,                            msg, "table"
check "IPv6 200: sdp count 1", msg and #msg.sdp_ips == 1,            msg and #msg.sdp_ips, 1
if msg and #msg.sdp_ips >= 1
  check "IPv6 200: family",    eq(msg.sdp_ips[1].family, "ip6"),     msg.sdp_ips[1].family, "ip6"
  check "IPv6 200: ip",        eq(msg.sdp_ips[1].ip, "2001:db8::1"), msg.sdp_ips[1].ip, "2001:db8::1"

-- 8. Returns nil for empty/short input
check "nil for empty",  parse("") == nil,   nil, nil
check "nil for nil",    parse(nil) == nil,   nil, nil
check "nil for short",  parse("abc") == nil, nil, nil

-- 9. ICE/RTCP SDP extraction
msg = parse ICE_SDP
check "ICE: status_code", msg and eq(msg.status_code, 183), msg and msg.status_code, 183
check "ICE: sdp_ips count 2", msg and #msg.sdp_ips == 2, msg and #msg.sdp_ips, 2
if msg and #msg.sdp_ips >= 2
  check "ICE: ip[1] c-line", eq(msg.sdp_ips[1].ip, "83.136.164.102"), msg.sdp_ips[1].ip, "83.136.164.102"
  check "ICE: ip[2] rtcp/candidate", eq(msg.sdp_ips[2].ip, "83.136.162.33"), msg.sdp_ips[2].ip, "83.136.162.33"

-- ── Summary ───────────────────────────────────────────────────────────────────

total = pass + fail
io.stdout\write "#{pass}/#{total} tests passed"
if fail > 0
  io.stdout\write " (#{fail} failed)\n"
  os.exit 1
else
  io.stdout\write " — all OK\n"
