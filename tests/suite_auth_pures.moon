-- tests/suite_auth_pures.moon
-- Tests unitaires pour les modules AUTH purs (pas de FFI/root requis).

bit = require "bit"
ffi = require "ffi"

tf = require "test_framework"
{ :test, :run_suite, :assert_eq, :assert_ne, :assert_true, :assert_false,
  :assert_nil, :assert_not_nil, :assert_contains, :assert_matches,
  :assert_throws, :with_stubs } = tf

-- ── Stubs globaux ─────────────────────────────────────────────────
package.loaded["log"] = {
  log_debug: ->
  log_warn:  ->
  log_error: ->
  log_info:  ->
}

-- ── credentials ───────────────────────────────────────────────────
-- Stub ffi AVANT require pour que credentials charge le proxy
orig_ffi = require "ffi"

-- Proxy FFI : délègue tout au vrai, sauf ffi.C.__errno_location
proxy_C = setmetatable {
  __errno_location: -> orig_ffi.new("int[1]", 2)
}, __index: (k) => orig_ffi.C[k]

ffi_proxy = setmetatable {
  C: proxy_C
  load: (...) -> orig_ffi.load ...
  cdef: (...) -> orig_ffi.cdef ...
  new: (...) -> orig_ffi.new ...
  sizeof: (...) -> orig_ffi.sizeof ...
  string: (...) -> orig_ffi.string ...
  copy: (...) -> orig_ffi.copy ...
  fill: (...) -> orig_ffi.fill ...
  cast: (...) -> orig_ffi.cast ...
  typeof: (...) -> orig_ffi.typeof ...
  istype: (...) -> orig_ffi.istype ...
  errno: (...) -> orig_ffi.errno ...
}, __index: (k) => orig_ffi[k]

package.loaded["ffi"] = ffi_proxy

{ :pbkdf2, :hash_password, :verify_password,
  :load_secrets, :valid_username, :register_user } = require "auth.credentials"

credentials_tests = {
  { "pbkdf2 avec vecteur connu", ->
    -- Vecteur test : password="password", salt="salt", iter=1
    -- SHA256 HMAC PBKDF2 avec 1 itération → hash connu :
    -- https://www.ietf.org/rfc/rfc6070.txt
    hash = pbkdf2 "password", "73616c74", 1  -- "salt" en hex
    assert_eq hash, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
  }

  { "pbkdf2 et verify_password round-trip", ->
    stored = hash_password "testpass"
    assert_true verify_password("testpass", stored)
    assert_false verify_password("wrong", stored)
  }

  { "verify_password correct", ->
    stored = hash_password "mypassword"
    assert_true verify_password("mypassword", stored), "password correct"
  }

  { "verify_password incorrect", ->
    stored = hash_password "mypassword"
    assert_false verify_password("wrongpassword", stored), "password incorrect"
  }

  { "verify_password mauvais format", ->
    assert_false verify_password("x", "badformat")
    assert_false verify_password("x", "md5:1000:salt:hash")
  }

  { "valid_username OK", ->
    assert_true valid_username "user@domain.com"
    assert_true valid_username "a.b-c+d@sub.domain.co.uk"
  }

  { "valid_username KO", ->
    assert_false valid_username "nodomain"
    assert_false valid_username "@nodomain"
    assert_false valid_username "a@b"
    assert_false valid_username (string.rep "x", 65) .. "@d.com"
    assert_false valid_username "ab"
  }

  { "load_secrets lecture", ->
    path = "tmp/test_secrets_" .. os.time! .. ".txt"
    fh = io.open path, "w"
    fh\write "alice:pbkdf2-sha256:100000:deadbeef:cafebabe\n"
    fh\write "bob:pbkdf2-sha256:100001:beefdead:babecafe\n"
    fh\write "# comment\n"
    fh\write "\n"
    fh\write "charlie:pbkdf2-sha256:100002:c0ffee:badfood\n"
    fh\close!

    secrets, err = load_secrets path
    assert_not_nil secrets, "load failed: #{err or 'nil'}"
    assert_eq secrets["alice"], "pbkdf2-sha256:100000:deadbeef:cafebabe"
    assert_eq secrets["bob"],   "pbkdf2-sha256:100001:beefdead:babecafe"
    assert_eq secrets["charlie"], "pbkdf2-sha256:100002:c0ffee:badfood"

    os.remove path
  }

  { "load_secrets fichier absent", ->
    secrets, err = load_secrets "/nonexistent/path"
    assert_nil secrets
    assert_not_nil err
  }

  { "register_user succès", ->
    path = "tmp/test_register_" .. os.time! .. ".txt"
    secrets, err = register_user "newuser@domain.com", "password123", path, {}
    assert_not_nil secrets, "register failed: #{err or 'nil'}"
    assert_true verify_password("password123", secrets["newuser@domain.com"])
    os.remove path
  }

  { "register_user doublon", ->
    path = "tmp/test_register2_" .. os.time! .. ".txt"
    register_user "dup@domain.com", "password123", path, {}
    secrets, err = register_user "dup@domain.com", "otherpass", path, { ["dup@domain.com"]: "dummy" }
    assert_nil secrets
    assert_contains err, "déjà pris"
    os.remove path
  }
}

-- ── sni_extractor ─────────────────────────────────────────────────

{ :extract_sni } = require "auth.sni_extractor"

-- Construit un TLS ClientHello minimal avec SNI
make_clienthello_sni = (hostname) ->
  ver = string.char 0x03, 0x03  -- TLS 1.2
  random = string.rep "\x00", 32
  session_id_len = string.char 0x00

  -- cipher suites: 1 suite
  cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)

  -- compression methods: null
  compression = string.char(0x01, 0x00)

  -- SNI extension
  sni_name = hostname
  sni_entry = string.char(0x00) ..  -- name_type = host_name
    string.char(bit.rshift(#sni_name, 8), bit.band(#sni_name, 0xFF)) ..
    sni_name
  sni_list = string.char(bit.rshift(#sni_entry, 8), bit.band(#sni_entry, 0xFF)) .. sni_entry
  sni_ext = string.char(0x00, 0x00) ..  -- extension_type = server_name
    string.char(bit.rshift(#sni_list, 8), bit.band(#sni_list, 0xFF)) ..
    sni_list

  -- extensions list
  extensions = sni_ext
  ext_len = #extensions

  -- ClientHello body
  ch_body = ver .. random .. session_id_len .. cipher_suites .. compression ..
    string.char(bit.rshift(ext_len, 8), bit.band(ext_len, 0xFF)) ..
    extensions

  ch_len = #ch_body
  handshake = string.char(0x01) ..  -- ClientHello
    string.char(bit.rshift(ch_len, 16), bit.rshift(bit.band(ch_len, 0xFF00), 8), bit.band(ch_len, 0xFF)) ..
    ch_body

  rec_len = #handshake
  record = string.char(0x16, 0x03, 0x01) ..  -- Handshake, TLS 1.0
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

  record

sni_tests = {
  { "extract_sni trop court", ->
    assert_nil extract_sni ""
    assert_nil extract_sni "short"
  }

  { "extract_sni pas un handshake", ->
    assert_nil extract_sni string.rep("\x00", 50)
  }

  { "extract_sni pas ClientHello", ->
    -- Handshake mais pas ClientHello (type 0x02 = ServerHello)
    rec = string.char(0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00)
    assert_nil extract_sni rec
  }

  { "extract_sni handshake valide avec SNI", ->
    ch = make_clienthello_sni "example.com"
    sni = extract_sni ch
    assert_eq sni, "example.com"
  }

  { "extract_sni hostname avec tiret", ->
    ch = make_clienthello_sni "my-host.example.co.uk"
    sni = extract_sni ch
    assert_eq sni, "my-host.example.co.uk"
  }

  { "extract_sni hostname invalide (caractère interdit)", ->
    ch = make_clienthello_sni "bad!host.com"
    sni = extract_sni ch
    assert_nil sni
  }

  { "extract_sni sans extension SNI", ->
    -- Handshake valide mais sans extension SNI
    ver = string.char(0x03, 0x03)
    random = string.rep "\x00", 32
    session_id_len = string.char 0x00
    cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
    compression = string.char(0x01, 0x00)
    -- pas d'extensions
    ext_len = 0
    ch_body = ver .. random .. session_id_len .. cipher_suites .. compression ..
      string.char(0x00, 0x00)
    ch_len = #ch_body
    handshake = string.char(0x01) ..
      string.char(bit.rshift(ch_len, 16), bit.rshift(bit.band(ch_len, 0xFF00), 8), bit.band(ch_len, 0xFF)) ..
      ch_body
    rec_len = #handshake
    record = string.char(0x16, 0x03, 0x01) ..
      string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
      handshake
    assert_nil extract_sni record
  }
}

-- ── sessions ──────────────────────────────────────────────────────

{ :session_for_mac, :load_sessions, :add_session, :write_sessions } = require "auth.sessions"

sessions_tests = {
  { "load_sessions fichier absent", ->
    s = load_sessions "/nonexistent/path"
    assert_eq s, {}
  }

  { "add_session + write + read", ->
    path = "tmp/test_sessions_" .. os.time! .. ".lua"
    sessions = {}
    add_session sessions, "aa:bb:cc:dd:ee:ff", "192.168.1.10", "alice", 3600, 0
    ok, err = write_sessions sessions, path
    assert_true ok, err

    loaded = load_sessions path
    assert_eq loaded["aa:bb:cc:dd:ee:ff"].user, "alice"
    assert_eq loaded["aa:bb:cc:dd:ee:ff"].ips.ipv4, "192.168.1.10"
    os.remove path
  }

  { "session_for_mac trouve existant", ->
    path = "tmp/test_sessions2_" .. os.time! .. ".lua"
    sessions = {}
    add_session sessions, "aa:bb:cc:dd:ee:ff", "192.168.1.10", "alice", 3600, 0
    write_sessions sessions, path

    s = session_for_mac "aa:bb:cc:dd:ee:ff", nil, path
    assert_not_nil s
    assert_eq s.user, "alice"
    os.remove path
  }

  { "session_for_mac inconnu retourne nil", ->
    path = "tmp/test_sessions3_" .. os.time! .. ".lua"
    sessions = {}
    write_sessions sessions, path

    s = session_for_mac "00:00:00:00:00:00", nil, path
    assert_nil s
    os.remove path
  }
}

-- ── html ──────────────────────────────────────────────────────────

h = require "auth.html"

html_tests = {
  { "html.tag simple", ->
    assert_eq h.div("hello"), "<div>hello</div>"
  }

  { "html.tag avec attributs", ->
    assert_eq h.div({ id: "test" }, "hello"), '<div id="test">hello</div>'
  }

  { "html.tag self-closing", ->
    assert_eq h.br!, "<br/>"
  }

  { "html.tag imbriqués", ->
    result = h.div id: "outer",
      h.p "paragraph"
    assert_contains result, "<div id=\"outer\">"
    assert_contains result, "<p>paragraph</p>"
    assert_contains result, "</div>"
  }

  { "html.escape via tag", ->
    result = h.escape "<script>alert('xss')</script>"
    assert_contains result, "<escape>"
    assert_contains result, "<script>alert('xss')</script>"
    assert_contains result, "</escape>"
  }
}

-- ── Exécution ─────────────────────────────────────────────────────

run_suite "auth/credentials", credentials_tests
run_suite "auth/sni_extractor", sni_tests
run_suite "auth/sessions", sessions_tests
run_suite "auth/html", html_tests

tf.summary!
package.loaded["ffi"] = orig_ffi
os.exit (tf.failed > 0) and 1 or 0
