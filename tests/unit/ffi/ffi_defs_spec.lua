local ffi = require("ffi")
package.loaded["ffi_defs"] = nil
local ffi_defs_ok, ffi_defs_or_err = pcall(require, "ffi_defs")
if not ffi_defs_ok then
  package.loaded["ffi_defs"] = {
    ffi = ffi,
    libc = ffi.C,
    libnfq = { },
    libnft = { }
  }
end
return describe("ffi_defs #ffi", function()
  it("chargement réussi ou redéfinition bénigne", function()
    if not ffi_defs_ok then
      local err_str = tostring(ffi_defs_or_err)
      return assert.truthy(err_str:find("redefine", 1, true), "erreur inattendue de ffi_defs : " .. err_str)
    else
      return assert.is_not_nil(ffi_defs_or_err.libc)
    end
  end)
  it("fonctions socket disponibles dans ffi.C", function()
    assert.is_not_nil(ffi.C.socket)
    assert.is_not_nil(ffi.C.bind)
    assert.is_not_nil(ffi.C.listen)
    assert.is_not_nil(ffi.C.accept)
    return assert.is_not_nil(ffi.C.connect)
  end)
  it("struct pollfd instanciable", function()
    return assert.has_no.errors(function()
      return ffi.new("struct pollfd")
    end)
  end)
  it("struct sockaddr_in instanciable", function()
    return assert.has_no.errors(function()
      return ffi.new("struct sockaddr_in")
    end)
  end)
  it("struct sockaddr_in6 instanciable", function()
    return assert.has_no.errors(function()
      return ffi.new("struct sockaddr_in6")
    end)
  end)
  it("struct sockaddr_un instanciable", function()
    return assert.has_no.errors(function()
      return ffi.new("struct sockaddr_un")
    end)
  end)
  it("struct timeval instanciable", function()
    return assert.has_no.errors(function()
      return ffi.new("struct timeval")
    end)
  end)
  return it("struct fd_set instanciable", function()
    return assert.has_no.errors(function()
      return ffi.new("struct fd_set")
    end)
  end)
end)
