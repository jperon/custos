return describe("auth.cert_parser", function()
  local extract_cn_from_subject, extract_sans, extract_username, validate_username, parse_certificate
  do
    local _obj_0 = require("auth.cert_parser")
    extract_cn_from_subject, extract_sans, extract_username, validate_username, parse_certificate = _obj_0.extract_cn_from_subject, _obj_0.extract_sans, _obj_0.extract_username, _obj_0.validate_username, _obj_0.parse_certificate
  end
  describe("extract_cn_from_subject", function()
    it("extracts CN from standard X.509 subject", function()
      local subject = "C=US,O=Example,CN=alice,emailAddress=alice@example.com"
      local cn = extract_cn_from_subject(subject)
      return assert.equals("alice", cn)
    end)
    it("extracts CN with special characters", function()
      local subject = "CN=john-doe,O=Company"
      local cn = extract_cn_from_subject(subject)
      return assert.equals("john-doe", cn)
    end)
    it("handles escaped characters in CN", function()
      local subject = "CN=user\\=name,O=Company"
      local cn = extract_cn_from_subject(subject)
      return assert.equals("user=name", cn)
    end)
    it("returns nil if CN not present", function()
      local subject = "C=US,O=Example"
      local cn = extract_cn_from_subject(subject)
      return assert.is_nil(cn)
    end)
    it("returns nil for empty subject", function()
      local cn = extract_cn_from_subject("")
      return assert.is_nil(cn)
    end)
    return it("returns nil for nil subject", function()
      local cn = extract_cn_from_subject(nil)
      return assert.is_nil(cn)
    end)
  end)
  describe("extract_sans", function()
    it("extracts DNS SANs from SAN string", function()
      local cert_data = {
        subject_alt_name = "DNS:example.com,DNS:www.example.com,IP:192.168.1.1"
      }
      local sans = extract_sans(cert_data)
      assert.equals(2, #sans)
      assert.equals("example.com", sans[1])
      return assert.equals("www.example.com", sans[2])
    end)
    it("handles empty SAN list", function()
      local cert_data = {
        subject_alt_name = "IP:192.168.1.1"
      }
      local sans = extract_sans(cert_data)
      return assert.equals(0, #sans)
    end)
    return it("returns empty list when no SAN extension", function()
      local cert_data = {
        subject = "CN=example.com"
      }
      local sans = extract_sans(cert_data)
      return assert.equals(0, #sans)
    end)
  end)
  describe("extract_username", function()
    it("extracts username from CN when available", function()
      local cert_data = {
        subject = "C=US,O=Example,CN=alice",
        subject_alt_name = "DNS:example.com"
      }
      local username = extract_username(cert_data)
      return assert.equals("alice", username)
    end)
    it("falls back to first DNS SAN if CN missing", function()
      local cert_data = {
        subject = "C=US,O=Example",
        subject_alt_name = "DNS:bob,DNS:bob-alt"
      }
      local username = extract_username(cert_data)
      return assert.equals("bob", username)
    end)
    it("prefers CN over SAN", function()
      local cert_data = {
        subject = "C=US,CN=alice",
        subject_alt_name = "DNS:bob"
      }
      local username = extract_username(cert_data)
      return assert.equals("alice", username)
    end)
    return it("returns nil when no CN or SAN", function()
      local cert_data = {
        subject = "C=US"
      }
      local username = extract_username(cert_data)
      return assert.is_nil(username)
    end)
  end)
  describe("validate_username", function()
    it("accepts valid alphanumeric usernames", function()
      assert.is_true(validate_username("alice"))
      assert.is_true(validate_username("user123"))
      assert.is_true(validate_username("alice_bob"))
      assert.is_true(validate_username("alice-bob"))
      return assert.is_true(validate_username("alice.bob"))
    end)
    it("rejects invalid characters", function()
      assert.is_false(validate_username("alice@bob"))
      assert.is_false(validate_username("alice bob"))
      assert.is_false(validate_username("alice/bob"))
      return assert.is_false(validate_username("alice\\bob"))
    end)
    it("rejects empty username", function()
      assert.is_false(validate_username(""))
      return assert.is_false(validate_username(nil))
    end)
    it("rejects excessively long usernames", function()
      local long_name = string.rep("a", 300)
      return assert.is_false(validate_username(long_name))
    end)
    return it("accepts reasonable length usernames", function()
      local reasonable = string.rep("a", 50)
      return assert.is_true(validate_username(reasonable))
    end)
  end)
  return describe("parse_certificate", function()
    it("parses certificate with all fields", function()
      local raw_cert = {
        subject = "CN=alice",
        subject_alt_name = "DNS:example.com",
        issuer = "CN=CA",
        notBefore = 1234567890,
        notAfter = 1234567890 + 31536000
      }
      local parsed = parse_certificate(raw_cert)
      assert.is_not_nil(parsed)
      assert.equals("CN=alice", parsed.subject)
      assert.equals("DNS:example.com", parsed.subject_alt_name)
      assert.equals("CN=CA", parsed.issuer)
      return assert.equals(1234567890, parsed.valid_from)
    end)
    it("handles missing optional fields", function()
      local raw_cert = {
        subject = "CN=alice"
      }
      local parsed = parse_certificate(raw_cert)
      assert.is_not_nil(parsed)
      assert.equals("CN=alice", parsed.subject)
      assert.equals("", parsed.subject_alt_name)
      return assert.equals("", parsed.issuer)
    end)
    return it("returns nil for nil input", function()
      local parsed = parse_certificate(nil)
      return assert.is_nil(parsed)
    end)
  end)
end)
