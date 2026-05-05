local bit = require("bit")
local ffi = require("ffi")
local tf = require("test_framework")
local test, run_suite, assert_eq, assert_ne, assert_true, assert_false, assert_nil, assert_not_nil, assert_contains, assert_matches, assert_throws, with_stubs
test, run_suite, assert_eq, assert_ne, assert_true, assert_false, assert_nil, assert_not_nil, assert_contains, assert_matches, assert_throws, with_stubs = tf.test, tf.run_suite, tf.assert_eq, tf.assert_ne, tf.assert_true, tf.assert_false, tf.assert_nil, tf.assert_not_nil, tf.assert_contains, tf.assert_matches, tf.assert_throws, tf.with_stubs
package.loaded["log"] = {
  log_debug = function() end,
  log_warn = function() end,
  log_error = function() end,
  log_info = function() end
}
local orig_ffi = require("ffi")
local proxy_C = setmetatable({
  __errno_location = function()
    return orig_ffi.new("int[1]", 2)
  end
}, {
  __index = function(self, k)
    return orig_ffi.C[k]
  end
})
local ffi_proxy = setmetatable({
  C = proxy_C,
  load = function(...)
    return orig_ffi.load(...)
  end,
  cdef = function(...)
    return orig_ffi.cdef(...)
  end,
  new = function(...)
    return orig_ffi.new(...)
  end,
  sizeof = function(...)
    return orig_ffi.sizeof(...)
  end,
  string = function(...)
    return orig_ffi.string(...)
  end,
  copy = function(...)
    return orig_ffi.copy(...)
  end,
  fill = function(...)
    return orig_ffi.fill(...)
  end,
  cast = function(...)
    return orig_ffi.cast(...)
  end,
  typeof = function(...)
    return orig_ffi.typeof(...)
  end,
  istype = function(...)
    return orig_ffi.istype(...)
  end,
  errno = function(...)
    return orig_ffi.errno(...)
  end
}, {
  __index = function(self, k)
    return orig_ffi[k]
  end
})
package.loaded["ffi"] = ffi_proxy
local pbkdf2, hash_password, verify_password, load_secrets, valid_username, register_user
do
  local _obj_0 = require("auth.credentials")
  pbkdf2, hash_password, verify_password, load_secrets, valid_username, register_user = _obj_0.pbkdf2, _obj_0.hash_password, _obj_0.verify_password, _obj_0.load_secrets, _obj_0.valid_username, _obj_0.register_user
end
local credentials_tests = {
  {
    "pbkdf2 avec vecteur connu",
    function()
      local hash = pbkdf2("password", "73616c74", 1)
      return assert_eq(hash, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    end
  },
  {
    "pbkdf2 et verify_password round-trip",
    function()
      local stored = hash_password("testpass")
      assert_true(verify_password("testpass", stored))
      return assert_false(verify_password("wrong", stored))
    end
  },
  {
    "verify_password correct",
    function()
      local stored = hash_password("mypassword")
      return assert_true(verify_password("mypassword", stored), "password correct")
    end
  },
  {
    "verify_password incorrect",
    function()
      local stored = hash_password("mypassword")
      return assert_false(verify_password("wrongpassword", stored), "password incorrect")
    end
  },
  {
    "verify_password mauvais format",
    function()
      assert_false(verify_password("x", "badformat"))
      return assert_false(verify_password("x", "md5:1000:salt:hash"))
    end
  },
  {
    "valid_username OK",
    function()
      assert_true(valid_username("user@domain.com"))
      return assert_true(valid_username("a.b-c+d@sub.domain.co.uk"))
    end
  },
  {
    "valid_username KO",
    function()
      assert_false(valid_username("nodomain"))
      assert_false(valid_username("@nodomain"))
      assert_false(valid_username("a@b"))
      assert_false(valid_username((string.rep("x", 65)) .. "@d.com"))
      return assert_false(valid_username("ab"))
    end
  },
  {
    "load_secrets lecture",
    function()
      local path = "tmp/test_secrets_" .. os.time() .. ".txt"
      local fh = io.open(path, "w")
      fh:write("alice:pbkdf2-sha256:100000:deadbeef:cafebabe\n")
      fh:write("bob:pbkdf2-sha256:100001:beefdead:babecafe\n")
      fh:write("# comment\n")
      fh:write("\n")
      fh:write("charlie:pbkdf2-sha256:100002:c0ffee:badfood\n")
      fh:close()
      local secrets, err = load_secrets(path)
      assert_not_nil(secrets, "load failed: " .. tostring(err or 'nil'))
      assert_eq(secrets["alice"], "pbkdf2-sha256:100000:deadbeef:cafebabe")
      assert_eq(secrets["bob"], "pbkdf2-sha256:100001:beefdead:babecafe")
      assert_eq(secrets["charlie"], "pbkdf2-sha256:100002:c0ffee:badfood")
      return os.remove(path)
    end
  },
  {
    "load_secrets fichier absent",
    function()
      local secrets, err = load_secrets("/nonexistent/path")
      assert_nil(secrets)
      return assert_not_nil(err)
    end
  },
  {
    "register_user succès",
    function()
      local path = "tmp/test_register_" .. os.time() .. ".txt"
      local secrets, err = register_user("newuser@domain.com", "password123", path, { })
      assert_not_nil(secrets, "register failed: " .. tostring(err or 'nil'))
      assert_true(verify_password("password123", secrets["newuser@domain.com"]))
      return os.remove(path)
    end
  },
  {
    "register_user doublon",
    function()
      local path = "tmp/test_register2_" .. os.time() .. ".txt"
      register_user("dup@domain.com", "password123", path, { })
      local secrets, err = register_user("dup@domain.com", "otherpass", path, {
        ["dup@domain.com"] = "dummy"
      })
      assert_nil(secrets)
      assert_contains(err, "déjà pris")
      return os.remove(path)
    end
  }
}
local extract_sni
extract_sni = require("auth.sni_extractor").extract_sni
local make_clienthello_sni
make_clienthello_sni = function(hostname)
  local ver = string.char(0x03, 0x03)
  local random = string.rep("\x00", 32)
  local session_id_len = string.char(0x00)
  local cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  local compression = string.char(0x01, 0x00)
  local sni_name = hostname
  local sni_entry = string.char(0x00) .. string.char(bit.rshift(#sni_name, 8), bit.band(#sni_name, 0xFF)) .. sni_name
  local sni_list = string.char(bit.rshift(#sni_entry, 8), bit.band(#sni_entry, 0xFF)) .. sni_entry
  local sni_ext = string.char(0x00, 0x00) .. string.char(bit.rshift(#sni_list, 8), bit.band(#sni_list, 0xFF)) .. sni_list
  local extensions = sni_ext
  local ext_len = #extensions
  local ch_body = ver .. random .. session_id_len .. cipher_suites .. compression .. string.char(bit.rshift(ext_len, 8), bit.band(ext_len, 0xFF)) .. extensions
  local ch_len = #ch_body
  local handshake = string.char(0x01) .. string.char(bit.rshift(ch_len, 16), bit.rshift(bit.band(ch_len, 0xFF00), 8), bit.band(ch_len, 0xFF)) .. ch_body
  local rec_len = #handshake
  local record = string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
  return record
end
local sni_tests = {
  {
    "extract_sni trop court",
    function()
      assert_nil(extract_sni(""))
      return assert_nil(extract_sni("short"))
    end
  },
  {
    "extract_sni pas un handshake",
    function()
      return assert_nil(extract_sni(string.rep("\x00", 50)))
    end
  },
  {
    "extract_sni pas ClientHello",
    function()
      local rec = string.char(0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00)
      return assert_nil(extract_sni(rec))
    end
  },
  {
    "extract_sni handshake valide avec SNI",
    function()
      local ch = make_clienthello_sni("example.com")
      local sni = extract_sni(ch)
      return assert_eq(sni, "example.com")
    end
  },
  {
    "extract_sni hostname avec tiret",
    function()
      local ch = make_clienthello_sni("my-host.example.co.uk")
      local sni = extract_sni(ch)
      return assert_eq(sni, "my-host.example.co.uk")
    end
  },
  {
    "extract_sni hostname invalide (caractère interdit)",
    function()
      local ch = make_clienthello_sni("bad!host.com")
      local sni = extract_sni(ch)
      return assert_nil(sni)
    end
  },
  {
    "extract_sni sans extension SNI",
    function()
      local ver = string.char(0x03, 0x03)
      local random = string.rep("\x00", 32)
      local session_id_len = string.char(0x00)
      local cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
      local compression = string.char(0x01, 0x00)
      local ext_len = 0
      local ch_body = ver .. random .. session_id_len .. cipher_suites .. compression .. string.char(0x00, 0x00)
      local ch_len = #ch_body
      local handshake = string.char(0x01) .. string.char(bit.rshift(ch_len, 16), bit.rshift(bit.band(ch_len, 0xFF00), 8), bit.band(ch_len, 0xFF)) .. ch_body
      local rec_len = #handshake
      local record = string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
      return assert_nil(extract_sni(record))
    end
  }
}
local session_for_mac, load_sessions, add_session, write_sessions
do
  local _obj_0 = require("auth.sessions")
  session_for_mac, load_sessions, add_session, write_sessions = _obj_0.session_for_mac, _obj_0.load_sessions, _obj_0.add_session, _obj_0.write_sessions
end
local sessions_tests = {
  {
    "load_sessions fichier absent",
    function()
      local s = load_sessions("/nonexistent/path")
      return assert_eq(s, { })
    end
  },
  {
    "add_session + write + read",
    function()
      local path = "tmp/test_sessions_" .. os.time() .. ".lua"
      local sessions = { }
      add_session(sessions, "aa:bb:cc:dd:ee:ff", "192.168.1.10", "alice", 3600, 0)
      local ok, err = write_sessions(sessions, path)
      assert_true(ok, err)
      local loaded = load_sessions(path)
      assert_eq(loaded["aa:bb:cc:dd:ee:ff"].user, "alice")
      assert_eq(loaded["aa:bb:cc:dd:ee:ff"].ips.ipv4, "192.168.1.10")
      return os.remove(path)
    end
  },
  {
    "session_for_mac trouve existant",
    function()
      local path = "tmp/test_sessions2_" .. os.time() .. ".lua"
      local sessions = { }
      add_session(sessions, "aa:bb:cc:dd:ee:ff", "192.168.1.10", "alice", 3600, 0)
      write_sessions(sessions, path)
      local s = session_for_mac("aa:bb:cc:dd:ee:ff", nil, path)
      assert_not_nil(s)
      assert_eq(s.user, "alice")
      return os.remove(path)
    end
  },
  {
    "session_for_mac inconnu retourne nil",
    function()
      local path = "tmp/test_sessions3_" .. os.time() .. ".lua"
      local sessions = { }
      write_sessions(sessions, path)
      local s = session_for_mac("00:00:00:00:00:00", nil, path)
      assert_nil(s)
      return os.remove(path)
    end
  }
}
local h = require("auth.html")
local html_tests = {
  {
    "html.tag simple",
    function()
      return assert_eq(h.div("hello"), "<div>hello</div>")
    end
  },
  {
    "html.tag avec attributs",
    function()
      return assert_eq(h.div({
        id = "test"
      }, "hello"), '<div id="test">hello</div>')
    end
  },
  {
    "html.tag self-closing",
    function()
      return assert_eq(h.br(), "<br/>")
    end
  },
  {
    "html.tag imbriqués",
    function()
      local result = h.div({
        id = "outer"
      }, h.p("paragraph"))
      assert_contains(result, "<div id=\"outer\">")
      assert_contains(result, "<p>paragraph</p>")
      return assert_contains(result, "</div>")
    end
  },
  {
    "html.escape via tag",
    function()
      local result = h.escape("<script>alert('xss')</script>")
      assert_contains(result, "<escape>")
      assert_contains(result, "<script>alert('xss')</script>")
      return assert_contains(result, "</escape>")
    end
  }
}
run_suite("auth/credentials", credentials_tests)
run_suite("auth/sni_extractor", sni_tests)
run_suite("auth/sessions", sessions_tests)
run_suite("auth/html", html_tests)
tf.summary()
package.loaded["ffi"] = orig_ffi
return os.exit((tf.failed > 0) and 1 or 0)
