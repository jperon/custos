local ethernet = require("ipparse.l2.ethernet")
local ip = require("ipparse.l3.ip")
local udp = require("ipparse.l4.udp")
local dns = require("ipparse.l7.dns")
local ip_utils = require("ipparse")
local dnsquestion = "000102030405060708090a0b0800" .. "4500" .. string.format("%04x", 57) .. "abcd0000" .. "4011" .. "0000" .. "c0a80002" .. "c0a80001" .. "c0030035" .. string.format("%04x", 37) .. "0000" .. "1234" .. "0100" .. "0001" .. "0000" .. "0000" .. "0000" .. "076578616d706c6503636f6d00" .. "0001" .. "0001"
local dnsanswer = "060708090a0b0001020304050800" .. "4500" .. string.format("%04x", 74) .. "dcba0000" .. "4011" .. "0000" .. "c0a80001" .. "c0a80002" .. "0035c003" .. string.format("%04x", 54) .. "0000" .. "1234" .. "8180" .. "0001" .. "0001" .. "0000" .. "0000" .. "076578616d706c6503636f6d00" .. "0001" .. "0001" .. "c00c" .. "0001" .. "0001" .. "000000e1" .. "0004" .. "5db8d822"
local raw_data_query = ip_utils.hex2bin(dnsquestion)
local raw_data_answer = ip_utils.hex2bin(dnsanswer)
print("--- Parsing DNS Query from Raw Packet ---")
local eth_frame, l3_offset = ethernet.parse(raw_data_query)
if not (eth_frame) then
  print("Error: Failed to parse Ethernet frame.")
  return 
end
print("\n-- Layer 2: Ethernet --")
print("Destination MAC: " .. tostring(ethernet.mac2s(eth_frame.dst)))
print("Source MAC: " .. tostring(ethernet.mac2s(eth_frame.src)))
print("EtherType: 0x" .. tostring(string.format("%04x", eth_frame.protocol)) .. " (" .. tostring(ethernet.proto[eth_frame.protocol] or "Unknown") .. ")")
assert(eth_frame.protocol == ethernet.proto.IP4, "Expected IPv4 packet")
local ip_packet, l4_offset = ip.parse(raw_data_query, l3_offset, eth_frame.protocol)
if not (ip_packet) then
  print("Error: Failed to parse IP packet.")
  return 
end
print("\n-- Layer 3: IP --")
print("Version: " .. tostring(ip_packet.version))
print("Source IP: " .. tostring(ip.ip2s(ip_packet.src)))
print("Destination IP: " .. tostring(ip.ip2s(ip_packet.dst)))
print("Protocol: 0x" .. tostring(string.format("%02x", ip_packet.protocol)) .. " (" .. tostring(ip.proto[ip_packet.protocol] or "Unknown") .. ")")
assert(ip_packet.protocol == ip.proto.UDP, "Expected UDP packet for DNS query")
local udp_dgram, l7_offset = udp.parse(raw_data_query, l4_offset)
if not (udp_dgram) then
  print("Error: Failed to parse UDP datagram.")
  return 
end
print("\n-- Layer 4: UDP --")
print("Source Port: " .. tostring(udp_dgram.spt))
print("Destination Port: " .. tostring(udp_dgram.dpt))
print("Length: " .. tostring(udp_dgram.len))
assert(udp_dgram.dpt == 53, "Expected UDP Destination Port 53 for DNS")
print("\n-- Layer 7: DNS --")
local dns_msg_query, _ = dns.parse(raw_data_query, l7_offset, false)
if not (dns_msg_query) then
  print("Error: Failed to parse DNS message.")
  return 
end
print("DNS Transaction ID: 0x" .. tostring(string.format("%04x", dns_msg_query.header.id)))
print("DNS Flags: 0x" .. tostring(string.format("%04x", (dns_msg_query.header.qr_opcode_aa_tc_rd << 8) | dns_msg_query.header.ra_z_rcode)))
print("  Query/Response: " .. tostring(dns_msg_query.header.qr and "Response" or "Query"))
print("  Recursion Desired: " .. tostring(dns_msg_query.header.rd and "Yes" or "No"))
print("Number of Questions: " .. tostring(dns_msg_query.header.qdcount))
print("Number of Answers: " .. tostring(dns_msg_query.header.ancount))
if dns_msg_query.questions and #dns_msg_query.questions > 0 then
  local question1_query = dns_msg_query.questions[1]
  print("  Question 1:")
  print("    Name: " .. tostring(question1_query.name))
  print("    Type: " .. tostring(dns.types[question1_query.qtype] or "Unknown") .. " (0x" .. tostring(string.format("%04x", question1_query.qtype)) .. ")")
  print("    Class: " .. tostring(dns.classes[question1_query.qclass] or "Unknown") .. " (0x" .. tostring(string.format("%04x", question1_query.qclass)) .. ")")
else
  print("  No questions found in DNS message.")
end
print("\n--- End of DNS Query Parsing Tutorial ---")
print("\n--- Running Assertions for DNS Query ---")
assert(eth_frame, "Query L2: Ethernet frame should be parsed")
assert(ethernet.mac2s(eth_frame.dst) == "00:01:02:03:04:05", "Query L2: Dst MAC mismatch")
assert(eth_frame.protocol == ethernet.proto.IP4, "Query L2: EtherType should be IP4")
assert(ip_packet, "Query L3: IP packet should be parsed")
assert(ip_packet.protocol == ip.proto.UDP, "Query L3: Protocol should be UDP")
assert(udp_dgram, "Query L4: UDP datagram should be parsed")
assert(udp_dgram.dpt == 53, "Query L4: UDP Destination Port should be 53")
assert(dns_msg_query, "Query L7: DNS message should be parsed")
assert(dns_msg_query.header.id == 0x1234, "Query L7: DNS Transaction ID mismatch")
assert(dns_msg_query.header.qr == false, "Query L7: DNS QR flag should indicate Query")
assert(dns_msg_query.header.rd == true, "Query L7: DNS RD flag should be true")
assert(dns_msg_query.header.qdcount == 1, "Query L7: DNS QDCOUNT mismatch")
assert(dns_msg_query.header.ancount == 0, "Query L7: DNS ANCOUNT mismatch")
assert(dns_msg_query.questions and #dns_msg_query.questions == 1, "Query L7: DNS should have one question")
local dns_q1_query = dns_msg_query.questions[1]
assert(dns_q1_query, "Query L7: DNS Question 1 object should exist")
assert(dns_q1_query.name == "example.com", "Query L7: DNS Question Name mismatch")
assert(dns_q1_query.qtype == dns.types.A, "Query L7: DNS Question Type should be A")
assert(dns_q1_query.qclass == dns.classes.IN, "Query L7: DNS Question Class should be IN")
print("All DNS Query assertions passed successfully!")
print("\n\n--- Parsing DNS Answer from Raw Packet ---")
local eth_frame_ans, l3_offset_ans = ethernet.parse(raw_data_answer)
if not (eth_frame_ans) then
  print("Error: Failed to parse Ethernet frame for DNS answer.")
  return 
end
print("\n-- Layer 2: Ethernet (Answer) --")
print("Destination MAC: " .. tostring(ethernet.mac2s(eth_frame_ans.dst)))
print("Source MAC: " .. tostring(ethernet.mac2s(eth_frame_ans.src)))
local ip_packet_ans, l4_offset_ans = ip.parse(raw_data_answer, l3_offset_ans, eth_frame_ans.protocol)
if not (ip_packet_ans) then
  print("Error: Failed to parse IP packet for DNS answer.")
  return 
end
print("\n-- Layer 3: IP (Answer) --")
print("Source IP: " .. tostring(ip.ip2s(ip_packet_ans.src)))
print("Destination IP: " .. tostring(ip.ip2s(ip_packet_ans.dst)))
local udp_dgram_ans, l7_offset_ans = udp.parse(raw_data_answer, l4_offset_ans)
if not (udp_dgram_ans) then
  print("Error: Failed to parse UDP datagram for DNS answer.")
  return 
end
print("\n-- Layer 4: UDP (Answer) --")
print("Source Port: " .. tostring(udp_dgram_ans.spt))
print("Destination Port: " .. tostring(udp_dgram_ans.dpt))
print("\n-- Layer 7: DNS (Answer) --")
local dns_msg_answer
dns_msg_answer, _ = dns.parse(raw_data_answer, l7_offset_ans, false)
assert(dns_msg_answer, "Error: Failed to parse DNS answer message.")
print("DNS Transaction ID: 0x" .. tostring(string.format("%04x", dns_msg_answer.header.id)))
print("  Query/Response: " .. tostring(dns_msg_answer.header.qr and "Response" or "Query"))
print("  Authoritative Answer: " .. tostring(dns_msg_answer.header.aa and "Yes" or "No"))
print("  Recursion Available: " .. tostring(dns_msg_answer.header.ra and "Yes" or "No"))
print("Number of Questions: " .. tostring(dns_msg_answer.header.qdcount))
print("Number of Answers: " .. tostring(dns_msg_answer.header.ancount))
if dns_msg_answer.answers and #dns_msg_answer.answers > 0 then
  local answer1 = dns_msg_answer.answers[1]
  print("  Answer 1:")
  print("    Name: " .. tostring(answer1.name))
  print("    Type: " .. tostring(dns.types[answer1.rtype] or "Unknown") .. " (0x" .. tostring(string.format("%04x", answer1.rtype)) .. ")")
  print("    Class: " .. tostring(dns.classes[answer1.rclass] or "Unknown") .. " (0x" .. tostring(string.format("%04x", answer1.rclass)) .. ")")
  print("    TTL: " .. tostring(answer1.ttl))
  print("    RDLENGTH: " .. tostring(#answer1.rdata))
  if answer1.rtype == dns.types.A then
    print("    RDATA (IP Address): " .. tostring(ip.ip2s(answer1.rdata)))
  else
    print("    RDATA (Hex): " .. tostring(ip_utils.bin2hex(answer1.rdata)))
  end
end
print("\n--- End of DNS Answer Parsing Tutorial ---")
print("\n--- Running Assertions for DNS Answer ---")
assert(dns_msg_answer, "Answer L7: DNS message should be parsed")
assert(dns_msg_answer.header.id == 0x1234, "Answer L7: DNS Transaction ID mismatch")
assert(dns_msg_answer.header.qr == true, "Answer L7: DNS QR flag should indicate Response")
assert(dns_msg_answer.header.ancount == 1, "Answer L7: DNS ANCOUNT mismatch")
assert(dns_msg_answer.answers and #dns_msg_answer.answers == 1, "Answer L7: DNS should have one answer")
local dns_ans1 = dns_msg_answer.answers[1]
assert(dns_ans1, "Answer L7: DNS Answer 1 object should exist")
assert(dns_ans1.name == "example.com", "Answer L7: DNS Answer Name mismatch")
assert(dns_ans1.rtype == dns.types.A, "Answer L7: DNS Answer Type should be A")
assert(dns_ans1.rclass == dns.classes.IN, "Answer L7: DNS Answer Class should be IN")
assert(dns_ans1.ttl == 225, "Answer L7: DNS Answer TTL mismatch")
assert(#dns_ans1.rdata == 4, "Answer L7: DNS Answer RDLENGTH mismatch for A record")
assert(ip.ip2s(dns_ans1.rdata) == "93.184.216.34", "Answer L7: DNS Answer RDATA IP mismatch")
return print("All DNS Answer assertions passed successfully!")
