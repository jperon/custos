if string.unpack then
  return string
end
return require("ipparse.lib.pack_compat_lib")
