local hash_string
hash_string = require("auth.cert").hash_string
return describe("auth/cert", function()
  it("hash_string est déterministe", function()
    return assert.equals(hash_string("hello"), hash_string("hello"))
  end)
  return it("hash_string produit des valeurs différentes pour des entrées différentes", function()
    return assert.not_equals(hash_string("a"), hash_string("b"))
  end)
end)
