-- tests/test_ffi_defs_syntax.moon
-- Validation that ffi_defs.lua compiles and its FFI definitions are valid.
-- This test ensures syntax errors in FFI.cdef() are caught early.

describe "FFI Definitions Syntax", ->
  it "ffi_defs requires without errors", ->
    -- This will fail if ffi_defs.lua has any FFI syntax errors
    ffi_defs = require "ffi_defs"
    assert.is_not_nil ffi_defs

  it "FFI definitions are accessible", ->
    ffi_defs = require "ffi_defs"
    C = ffi_defs.C
    assert.is_not_nil C
    -- Verify key socket functions exist
    assert.is_not_nil C.socket
    assert.is_not_nil C.bind
    assert.is_not_nil C.listen
    assert.is_not_nil C.accept
    assert.is_not_nil C.connect

  it "socket structures are defined", ->
    ffi_defs = require "ffi_defs"
    ffi = require "ffi"
    -- These should not throw if structures are properly defined
    addr = ffi.new "struct sockaddr"
    addr4 = ffi.new "struct sockaddr_in"
    addr6 = ffi.new "struct sockaddr_in6"
    addr_un = ffi.new "struct sockaddr_un"
    addr_ll = ffi.new "struct sockaddr_ll"
    assert.is_not_nil addr
    assert.is_not_nil addr4
    assert.is_not_nil addr6
    assert.is_not_nil addr_un
    assert.is_not_nil addr_ll

  it "pollfd structure is defined", ->
    ffi_defs = require "ffi_defs"
    ffi = require "ffi"
    pfd = ffi.new "struct pollfd"
    assert.is_not_nil pfd

  it "timeval and fd_set structures are defined", ->
    ffi_defs = require "ffi_defs"
    ffi = require "ffi"
    tv = ffi.new "struct timeval"
    fds = ffi.new "struct fd_set"
    assert.is_not_nil tv
    assert.is_not_nil fds
