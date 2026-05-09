-- tests/unit/auth/cert_parser_spec.moon
-- Unit tests for certificate parsing and username extraction.

describe "auth.cert_parser", ->
  { :extract_cn_from_subject, :extract_sans, :extract_username, :validate_username, :parse_certificate } = require "auth.cert_parser"
  
  describe "extract_cn_from_subject", ->
    it "extracts CN from standard X.509 subject", ->
      subject = "C=US,O=Example,CN=alice,emailAddress=alice@example.com"
      cn = extract_cn_from_subject subject
      assert.equals "alice", cn
    
    it "extracts CN with special characters", ->
      subject = "CN=john-doe,O=Company"
      cn = extract_cn_from_subject subject
      assert.equals "john-doe", cn
    
    it "handles escaped characters in CN", ->
      subject = "CN=user\\=name,O=Company"
      cn = extract_cn_from_subject subject
      assert.equals "user=name", cn
    
    it "returns nil if CN not present", ->
      subject = "C=US,O=Example"
      cn = extract_cn_from_subject subject
      assert.is_nil cn
    
    it "returns nil for empty subject", ->
      cn = extract_cn_from_subject ""
      assert.is_nil cn
    
    it "returns nil for nil subject", ->
      cn = extract_cn_from_subject nil
      assert.is_nil cn
  
  describe "extract_sans", ->
    it "extracts DNS SANs from SAN string", ->
      cert_data = {
        subject_alt_name: "DNS:example.com,DNS:www.example.com,IP:192.168.1.1"
      }
      sans = extract_sans cert_data
      assert.equals 2, #sans
      assert.equals "example.com", sans[1]
      assert.equals "www.example.com", sans[2]
    
    it "handles empty SAN list", ->
      cert_data = {
        subject_alt_name: "IP:192.168.1.1"
      }
      sans = extract_sans cert_data
      assert.equals 0, #sans
    
    it "returns empty list when no SAN extension", ->
      cert_data = { subject: "CN=example.com" }
      sans = extract_sans cert_data
      assert.equals 0, #sans
  
  describe "extract_username", ->
    it "extracts username from CN when available", ->
      cert_data = {
        subject: "C=US,O=Example,CN=alice"
        subject_alt_name: "DNS:example.com"
      }
      username = extract_username cert_data
      assert.equals "alice", username
    
    it "falls back to first DNS SAN if CN missing", ->
      cert_data = {
        subject: "C=US,O=Example"
        subject_alt_name: "DNS:bob,DNS:bob-alt"
      }
      username = extract_username cert_data
      assert.equals "bob", username
    
    it "prefers CN over SAN", ->
      cert_data = {
        subject: "C=US,CN=alice"
        subject_alt_name: "DNS:bob"
      }
      username = extract_username cert_data
      assert.equals "alice", username
    
    it "returns nil when no CN or SAN", ->
      cert_data = { subject: "C=US" }
      username = extract_username cert_data
      assert.is_nil username
  
  describe "validate_username", ->
    it "accepts valid alphanumeric usernames", ->
      assert.is_true validate_username "alice"
      assert.is_true validate_username "user123"
      assert.is_true validate_username "alice_bob"
      assert.is_true validate_username "alice-bob"
      assert.is_true validate_username "alice.bob"
    
    it "rejects invalid characters", ->
      assert.is_false validate_username "alice@bob"
      assert.is_false validate_username "alice bob"
      assert.is_false validate_username "alice/bob"
      assert.is_false validate_username "alice\\bob"
    
    it "rejects empty username", ->
      assert.is_false validate_username ""
      assert.is_false validate_username nil
    
    it "rejects excessively long usernames", ->
      long_name = string.rep "a", 300
      assert.is_false validate_username long_name
    
    it "accepts reasonable length usernames", ->
      reasonable = string.rep "a", 50
      assert.is_true validate_username reasonable
  
  describe "parse_certificate", ->
    it "parses certificate with all fields", ->
      raw_cert = {
        subject: "CN=alice"
        subject_alt_name: "DNS:example.com"
        issuer: "CN=CA"
        notBefore: 1234567890
        notAfter: 1234567890 + 31536000
      }
      
      parsed = parse_certificate raw_cert
      assert.is_not_nil parsed
      assert.equals "CN=alice", parsed.subject
      assert.equals "DNS:example.com", parsed.subject_alt_name
      assert.equals "CN=CA", parsed.issuer
      assert.equals 1234567890, parsed.valid_from
    
    it "handles missing optional fields", ->
      raw_cert = {
        subject: "CN=alice"
      }
      
      parsed = parse_certificate raw_cert
      assert.is_not_nil parsed
      assert.equals "CN=alice", parsed.subject
      assert.equals "", parsed.subject_alt_name
      assert.equals "", parsed.issuer
    
    it "returns nil for nil input", ->
      parsed = parse_certificate nil
      assert.is_nil parsed
