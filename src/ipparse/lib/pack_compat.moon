-- pack_compat.moon
-- Parse-safe entrypoint for runtimes that reject some fallback syntax/operators.

return string if string.unpack
require "ipparse.lib.pack_compat_lib"
