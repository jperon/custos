#!/usr/bin/env moon

--- Debug SNI Parsing Issue
-- Isolate and test the exact SNI parsing logic

:bin2hex, :hex2bin = require "ipparse.init"
pack: sp, unpack: su = string

print "🔍 Debugging SNI Parsing Issue"
print ""

-- Test the parse_sni_extension method directly
test_sni_parsing = (hostname) ->
  print "=== Testing SNI parsing for: #{hostname} ==="

  -- Create SNI extension data exactly as in working example
  sni_name_list = sp(">H", #hostname + 3) .. string.char(0x00) .. sp(">H", #hostname) .. hostname

  print "Created SNI extension data:"
  print "  Hostname: #{hostname}"
  print "  Hostname length: #{#hostname}"
  print "  SNI data length: #{#sni_name_list}"
  print "  SNI data hex: #{bin2hex sni_name_list}"
  print ""

  -- Parse it manually step by step
  print "Manual parsing:"
  offset = 1

  list_len = su ">H", sni_name_list, offset
  offset += 2
  print "  Server name list length: #{list_len} (should be #{#hostname + 3})"

  name_type = su "B", sni_name_list, offset
  offset += 1
  print "  Name type: #{name_type} (should be 0)"

  name_len = su ">H", sni_name_list, offset
  offset += 2
  print "  Name length: #{name_len} (should be #{#hostname})"

  print "  Data available from offset #{offset}: #{#sni_name_list - offset + 1} bytes"
  print "  Need #{name_len} bytes"

  if offset + name_len - 1 <= #sni_name_list
    extracted = sni_name_list\sub offset, offset + name_len - 1
    print "  ✅ Extracted hostname: '#{extracted}'"

    if extracted == hostname
      print "  ✅ SUCCESS!"
      return true
    else
      print "  ❌ Mismatch!"
  else
    print "  ❌ Not enough data!"

  print ""
  false

-- Test with different hostnames
test_cases = {"google.com", "example.org", "a.com"}
successes = 0

for hostname in *test_cases
  if test_sni_parsing hostname
    successes += 1

print "Results: #{successes}/#{#test_cases} successful"
