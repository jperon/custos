-- tests/unit/webui/admin_auth_spec.moon
-- Tests de webui/handlers/admin_auth : check_admin_session et forbidden_page.

token = require "auth.token"
{ :check_admin_session, :forbidden_page } = require "webui.handlers.admin_auth"
{ :write_sessions } = require "auth.sessions"

SESS_FILE = "tmp/admin_auth_sessions.lua"

-- Clé de test (32 octets arbitraires)
TEST_KEY = string.rep "\x42", 32

-- Génère un cookie "custos_session=<token>" valide
make_cookie = (user, mac) ->
  expires = os.time! + 3600
  tok = token.generate "user", user, mac or "aa:bb:cc:dd:ee:ff", expires, TEST_KEY
  "custos_session=" .. tok

-- État serveur de base
make_state = (admin_users, allow_all) ->
  {
    token_key:                TEST_KEY
    admin_users:              admin_users or {}
    admin_allow_all_when_empty: allow_all or false
    sessions_file:            SESS_FILE
  }

describe "webui/handlers/admin_auth", ->

  before_each ->
    write_sessions { ["aa:bb:cc:dd:ee:ff"]: { user: "alice", expires: os.time! + 3600 } }, SESS_FILE

  after_each ->
    os.remove SESS_FILE

  -- ── check_admin_session ───────────────────────────────────────────────────

  describe "check_admin_session", ->

    it "retourne nil+unauth si pas de cookie", ->
      req   = { headers: { cookie: "" } }
      state = make_state { "alice" }
      p, reason = check_admin_session req, state
      assert.is_nil p
      assert.equals "unauth", reason

    it "retourne nil+unauth si le cookie est absent du header", ->
      req   = { headers: {} }
      state = make_state { "alice" }
      p, reason = check_admin_session req, state
      assert.is_nil p
      assert.equals "unauth", reason

    it "retourne nil+unauth si le token est invalide", ->
      req   = { headers: { cookie: "custos_session=invalidtoken" } }
      state = make_state { "alice" }
      p, reason = check_admin_session req, state
      assert.is_nil p
      assert.equals "unauth", reason

    it "retourne nil+forbidden si l'utilisateur n'est pas dans admin_users", ->
      req   = { headers: { cookie: make_cookie "bob" } }
      state = make_state { "alice" }
      p, reason = check_admin_session req, state
      assert.is_nil p
      assert.equals "forbidden", reason

    it "retourne le payload si l'utilisateur est dans admin_users", ->
      req   = { headers: { cookie: make_cookie "alice" } }
      state = make_state { "alice", "bob" }
      p, reason = check_admin_session req, state
      assert.not_nil p
      assert.is_nil reason
      assert.equals "alice", p.user

    it "accepte le deuxième admin dans la liste", ->
      req   = { headers: { cookie: make_cookie "bob" } }
      state = make_state { "alice", "bob" }
      p, reason = check_admin_session req, state
      assert.not_nil p
      assert.equals "bob", p.user

    it "admin_allow_all_when_empty=true + liste vide → tout utilisateur est admin", ->
      req   = { headers: { cookie: make_cookie "carol" } }
      state = make_state {}, true
      p, reason = check_admin_session req, state
      assert.not_nil p
      assert.is_nil reason
      assert.equals "carol", p.user

    it "admin_allow_all_when_empty=false + liste vide → forbidden", ->
      req   = { headers: { cookie: make_cookie "carol" } }
      state = make_state {}, false
      p, reason = check_admin_session req, state
      assert.is_nil p
      assert.equals "forbidden", reason

    it "admin_allow_all_when_empty=true + liste NON vide → vérifie quand même la liste", ->
      req   = { headers: { cookie: make_cookie "stranger" } }
      state = make_state { "alice" }, true
      p, reason = check_admin_session req, state
      assert.is_nil p
      assert.equals "forbidden", reason

    it "token de type 'device' non accepté (doit être 'user')", ->
      -- Génère un token de type device (non-user)
      expires = os.time! + 3600
      tok = token.generate "device", "mydevice", "aa:bb:cc:dd:ee:ff", expires, TEST_KEY
      req   = { headers: { cookie: "custos_session=" .. tok } }
      state = make_state { "mydevice" }, true
      p, reason = check_admin_session req, state
      assert.is_nil p
      assert.equals "unauth", reason

  -- ── session vivante obligatoire ────────────────────────────────────────────

    it "token valide mais session supprimée (logout) → refusé", ->
      req = { headers: { cookie: make_cookie "alice" } }
      write_sessions {}, SESS_FILE
      state = make_state { "alice" }
      p, reason = check_admin_session req, state
      assert.is_nil p
      assert.equals "unauth", reason

    it "token valide mais session d'une autre MAC → refusé", ->
      req = { headers: { cookie: make_cookie "alice", "99:88:77:66:55:44" } }
      state = make_state { "alice" }
      p, reason = check_admin_session req, state
      assert.is_nil p
      assert.equals "unauth", reason

    it "token à MAC inconnue (\"unknown\") → accepté (token seul)", ->
      -- Comportement d'avant la branche : une MAC nil/"unknown" n'a pas de
      -- session attendue, le token valide suffit.
      req = { headers: { cookie: make_cookie "alice", "unknown" } }
      state = make_state { "alice" }
      p, reason = check_admin_session req, state
      assert.not_nil p
      assert.is_nil reason
      assert.equals "alice", p.user

    it "state.sessions_file nil → accepté (token seul)", ->
      req = { headers: { cookie: make_cookie "alice" } }
      state = make_state { "alice" }
      state.sessions_file = nil
      p, reason = check_admin_session req, state
      assert.not_nil p
      assert.is_nil reason

  -- ── forbidden_page ────────────────────────────────────────────────────────

  describe "forbidden_page", ->

    it "retourne du HTML contenant le nom d'utilisateur", ->
      html = forbidden_page "alice"
      assert.truthy html\find("alice", 1, true)

    it "contient un lien de déconnexion", ->
      html = forbidden_page "bob"
      assert.truthy html\find("/logout", 1, true)

    it "commence par '<!DOCTYPE html>'", ->
      html = forbidden_page "x"
      assert.truthy html\find("<!DOCTYPE html>", 1, true)

    it "mentionne 'Accès refusé' ou 'administrateur'", ->
      html = forbidden_page "alice"
      assert.truthy html\find("refus", 1, true) or html\find("administrateur", 1, true)
