describe "sip.parser", ->
  parser = require "sip.parser"

  it "extracts media IPs from c=, a=rtcp and ICE candidates without duplicates", ->
    msg = parser.parse [[SIP/2.0 183 Session Progress
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

    assert.is_not_nil msg
    assert.are.equal 183, msg.status_code
    assert.are.equal 2, #msg.sdp_ips
    assert.are.equal "83.136.164.102", msg.sdp_ips[1].ip
    assert.are.equal "83.136.162.33", msg.sdp_ips[2].ip
