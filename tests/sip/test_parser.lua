package.path = package.path .. ";./src/?.lua;./src/?/init.lua"
local parser = require("sip.parser")
local parse = parser.parse
local pass = 0
local fail = 0
local check
check = function(name, cond, got, expected)
  if cond then
    pass = pass + 1
  else
    fail = fail + 1
    io.stderr:write("FAIL " .. tostring(name) .. "\n")
    io.stderr:write("     got:      " .. tostring(tostring(got)) .. "\n")
    return io.stderr:write("     expected: " .. tostring(tostring(expected)) .. "\n")
  end
end
local eq
eq = function(a, b)
  return a == b
end
local INVITE = [[INVITE sip:+33123456789@prx1.sip.keyyo.net SIP/2.0
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
local OK_200 = [[SIP/2.0 200 OK
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
local OPTIONS = [[OPTIONS sip:prx1.sip.keyyo.net SIP/2.0
Via: SIP/2.0/UDP 10.35.3.2:5060;branch=z9hG4bKping
From: <sip:5001@10.35.3.1>;tag=keepalive
To: <sip:prx1.sip.keyyo.net>
Call-ID: keepalive-42@10.35.3.2
CSeq: 42 OPTIONS
Content-Length: 0

]]
local NOT_SIP = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
local CRLF_200 = OK_200:gsub("\n", "\r\n")
local MULTI_C = [[SIP/2.0 183 Session Progress
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
local IPV6_200 = [[SIP/2.0 200 OK
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
local msg = parse(NOT_SIP)
check("nil for non-SIP", msg == nil, msg, nil)
msg = parse(INVITE)
check("INVITE: not nil", msg ~= nil, msg, "table")
if msg then
  check("INVITE: method", eq(msg.method, "INVITE"), msg.method, "INVITE")
  check("INVITE: no status", msg.status_code == nil, msg.status_code, nil)
  check("INVITE: cseq_method", eq(msg.cseq_method, "INVITE"), msg.cseq_method, "INVITE")
  check("INVITE: call_id", msg.call_id ~= nil, msg.call_id, "not nil")
  check("INVITE: content_type", eq(msg.content_type, "application/sdp"), msg.content_type, "application/sdp")
  check("INVITE: sdp_ips count", #msg.sdp_ips == 1, #msg.sdp_ips, 1)
  if #msg.sdp_ips >= 1 then
    check("INVITE: sdp ip4", eq(msg.sdp_ips[1].ip, "10.35.3.2"), msg.sdp_ips[1].ip, "10.35.3.2")
    check("INVITE: sdp family", eq(msg.sdp_ips[1].family, "ip4"), msg.sdp_ips[1].family, "ip4")
  end
end
msg = parse(OK_200)
check("200 OK: not nil", msg ~= nil, msg, "table")
if msg then
  check("200 OK: no method", msg.method == nil, msg.method, nil)
  check("200 OK: status_code", eq(msg.status_code, 200), msg.status_code, 200)
  check("200 OK: cseq_method", eq(msg.cseq_method, "INVITE"), msg.cseq_method, "INVITE")
  check("200 OK: sdp_ips count", #msg.sdp_ips == 1, #msg.sdp_ips, 1)
  if #msg.sdp_ips >= 1 then
    check("200 OK: sdp ip", eq(msg.sdp_ips[1].ip, "83.136.164.72"), msg.sdp_ips[1].ip, "83.136.164.72")
  end
end
msg = parse(CRLF_200)
check("CRLF 200 OK: not nil", msg ~= nil, msg, "table")
check("CRLF 200 OK: status_code", msg and eq(msg.status_code, 200), msg and msg.status_code, 200)
check("CRLF 200 OK: sdp ip", msg and #msg.sdp_ips == 1, msg and #msg.sdp_ips, 1)
msg = parse(OPTIONS)
check("OPTIONS: method", msg and eq(msg.method, "OPTIONS"), msg and msg.method, "OPTIONS")
check("OPTIONS: no sdp_ips", msg and #msg.sdp_ips == 0, msg and #msg.sdp_ips, 0)
check("OPTIONS: cseq_method", msg and eq(msg.cseq_method, "OPTIONS"), msg and msg.cseq_method, "OPTIONS")
msg = parse(MULTI_C)
check("183: status_code", msg and eq(msg.status_code, 183), msg and msg.status_code, 183)
check("183: sdp_ips count 2", msg and #msg.sdp_ips == 2, msg and #msg.sdp_ips, 2)
if msg and #msg.sdp_ips >= 2 then
  check("183: sdp ip[1]", eq(msg.sdp_ips[1].ip, "83.136.161.72"), msg.sdp_ips[1].ip, "83.136.161.72")
  check("183: sdp ip[2]", eq(msg.sdp_ips[2].ip, "83.136.163.72"), msg.sdp_ips[2].ip, "83.136.163.72")
end
msg = parse(IPV6_200)
check("IPv6 200: not nil", msg ~= nil, msg, "table")
check("IPv6 200: sdp count 1", msg and #msg.sdp_ips == 1, msg and #msg.sdp_ips, 1)
if msg and #msg.sdp_ips >= 1 then
  check("IPv6 200: family", eq(msg.sdp_ips[1].family, "ip6"), msg.sdp_ips[1].family, "ip6")
  check("IPv6 200: ip", eq(msg.sdp_ips[1].ip, "2001:db8::1"), msg.sdp_ips[1].ip, "2001:db8::1")
end
check("nil for empty", parse("") == nil, nil, nil)
check("nil for nil", parse(nil) == nil, nil, nil)
check("nil for short", parse("abc") == nil, nil, nil)
local total = pass + fail
io.stdout:write(tostring(pass) .. "/" .. tostring(total) .. " tests passed")
if fail > 0 then
  io.stdout:write(" (" .. tostring(fail) .. " failed)\n")
  return os.exit(1)
else
  return io.stdout:write(" — all OK\n")
end
