-- tests/unit/webui/admin_auth_spec.moon
-- Tests de webui/handlers/admin_auth : check_admin_session et forbidden_page.

token = require "auth.token"
{ :check_admin_session, :forbidden_page } = require "webui.handlers.admin_auth"

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
  }

describe "webui/handlers/admin_auth", ->

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
