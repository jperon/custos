local generate_self_signed
generate_self_signed = require("auth.cert_generator").generate_self_signed
return describe("auth/cert_generator", function()
  it("paramètres invalides → ok=false", function()
    local cert, key, ok, err = generate_self_signed("", { }, 365)
    assert.is_false(ok)
    return assert.is_not_nil(err)
  end)
  return it("génération avec px5g si disponible #px5g", function()
    local f = io.popen("which px5g 2>/dev/null")
    local has_px5g = f and (f:read("*l") ~= nil) or false
    if f then
      f:close()
    end
    if not (has_px5g) then
      pending("px5g non installé")
    end
    local cert, key, ok, err = generate_self_signed("test.example.com", { }, 365)
    assert.is_true(ok, tostring(err))
    assert.is_not_nil(cert)
    assert.is_not_nil(key)
    assert.truthy(cert:find("BEGIN CERTIFICATE", 1, true))
    return assert.truthy(key:find("BEGIN", 1, true))
  end)
end)
