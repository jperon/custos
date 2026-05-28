-- tests/unit/webui/router_spec.moon
-- Tests du dispatch du routeur /admin/*.

token = require "auth.token"

TEST_KEY  = string.rep "\x42", 32
CFG_PATH  = "tmp/router_spec_cfg.lua"

-- Config minimale sur disque
write_min_cfg = ->
  fh = assert io.open CFG_PATH, "w"
  fh\write "return { filter = { rules = {} } }\n"
  fh\close!

make_admin_cookie = (user) ->
  expires = os.time! + 3600
  tok = token.generate "user", user, "aa:bb:cc:dd:ee:ff", expires, TEST_KEY
  "custos_session=" .. tok

make_state = (admin_users) ->
  {
    token_key:                TEST_KEY
    admin_users:              admin_users or { "admin" }
    admin_allow_all_when_empty: false
    config_path:              CFG_PATH
    started_at:               os.time!
  }

make_req = (method, path, user, body) ->
  {
    method:  method
    path:    path
    headers: { cookie: make_admin_cookie user or "admin" }
    body:    body or ""
  }

-- Recharge le routeur à chaque test pour éviter le cache module
get_dispatch = ->
  package.loaded["webui.router"] = nil
  (require "webui.router").dispatch

describe "webui/router.dispatch", ->

  before_each ->
    write_min_cfg!

  after_each ->
    os.remove CFG_PATH

  -- ── Contrôle d'accès ─────────────────────────────────────────────────────

  it "redirige vers /login si aucune session", ->
    dispatch = get_dispatch!
    req = { method: "GET", path: "/admin/", headers: {}, body: "" }
    status, hdrs, _ = dispatch req, make_state!
    assert.equals 302, status
    assert.equals "/login", hdrs["Location"]

  it "retourne 403 si session valide mais pas admin", ->
    dispatch = get_dispatch!
    req = make_req "GET", "/admin/", "stranger"
    state = make_state { "alice" }  -- stranger n'est pas dans la liste
    status, _, body = dispatch req, state
    assert.equals 403, status
    assert.truthy body\find("stranger", 1, true)

  -- ── Dashboard ────────────────────────────────────────────────────────────

  it "GET /admin/ → 200", ->
    dispatch = get_dispatch!
    status, hdrs, body = dispatch make_req("GET", "/admin/"), make_state!
    assert.equals 200, status
    assert.truthy body\find("Dashboard", 1, true)

  it "GET /admin (sans slash) → 200 dashboard", ->
    dispatch = get_dispatch!
    status, _, body = dispatch make_req("GET", "/admin"), make_state!
    assert.equals 200, status
    assert.truthy body\find("Dashboard", 1, true)

  -- ── Système ──────────────────────────────────────────────────────────────

  it "GET /admin/system/status → 200", ->
    dispatch = get_dispatch!
    status, _, _ = dispatch make_req("GET", "/admin/system/status"), make_state!
    assert.equals 200, status

  -- NOTE: POST /admin/system/reload envoie SIGHUP au processus parent —
  -- ce test ne peut pas s'exécuter en unitaire sans tuer le runner de tests.
  -- Il est couvert par les tests E2E homelab.

  -- ── Config index ─────────────────────────────────────────────────────────

  it "GET /admin/config/ → 200", ->
    dispatch = get_dispatch!
    status, _, _ = dispatch make_req("GET", "/admin/config/"), make_state!
    assert.equals 200, status

  it "GET /admin/config (sans slash) → 200", ->
    dispatch = get_dispatch!
    status, _, _ = dispatch make_req("GET", "/admin/config"), make_state!
    assert.equals 200, status

  -- ── Sections scalaires ────────────────────────────────────────────────────

  for _, section in ipairs { "runtime", "nfqueue", "dns", "nft", "ipc", "clients",
                              "mac_learner", "auth", "doh", "events", "metrics", "rtp" }
    do
      it "GET /admin/config/#{section} → 200", ->
        dispatch = get_dispatch!
        status, _, _ = dispatch make_req("GET", "/admin/config/#{section}"), make_state!
        assert.equals 200, status

  it "GET /admin/config/unknown_section → 302 fallback (section non dans SCALAR_SECTIONS)", ->
    dispatch = get_dispatch!
    status, hdrs, _ = dispatch make_req("GET", "/admin/config/unknown_section"), make_state!
    -- Le routeur ne connaît pas cette section → fallback 302 vers /admin/
    assert.equals 302, status
    assert.equals "/admin/", hdrs["Location"]

  it "POST /admin/config/runtime → 302", ->
    dispatch = get_dispatch!
    body = "log_level=INFO&benchmark_present=1"
    status, hdrs, _ = dispatch make_req("POST", "/admin/config/runtime", "admin", body), make_state!
    assert.equals 302, status
    assert.truthy hdrs["Location"]\find("runtime", 1, true)

  -- ── Filtre DNS — redirect ─────────────────────────────────────────────────

  it "GET /admin/config/filter → 302 vers /admin/config/filter/rules", ->
    dispatch = get_dispatch!
    status, hdrs, _ = dispatch make_req("GET", "/admin/config/filter"), make_state!
    assert.equals 302, status
    assert.equals "/admin/config/filter/rules", hdrs["Location"]

  it "GET /admin/config/filter/ → 302 vers /admin/config/filter/rules", ->
    dispatch = get_dispatch!
    status, hdrs, _ = dispatch make_req("GET", "/admin/config/filter/"), make_state!
    assert.equals 302, status
    assert.equals "/admin/config/filter/rules", hdrs["Location"]

  -- ── Dictionnaires nommés ──────────────────────────────────────────────────

  for _, dict in ipairs { "nets", "macs", "users", "times", "decision" }
    do
      it "GET /admin/config/filter/#{dict} → 200", ->
        dispatch = get_dispatch!
        status, _, _ = dispatch make_req("GET", "/admin/config/filter/#{dict}"), make_state!
        assert.equals 200, status

  -- ── Règles ────────────────────────────────────────────────────────────────

  it "GET /admin/config/filter/rules → 200", ->
    dispatch = get_dispatch!
    status, _, _ = dispatch make_req("GET", "/admin/config/filter/rules"), make_state!
    assert.equals 200, status

  it "GET /admin/config/filter/rules/new → 200", ->
    dispatch = get_dispatch!
    status, _, _ = dispatch make_req("GET", "/admin/config/filter/rules/new"), make_state!
    assert.equals 200, status

  it "GET /admin/config/filter/rules/1/edit → 404 (règle inexistante)", ->
    dispatch = get_dispatch!
    status, _, _ = dispatch make_req("GET", "/admin/config/filter/rules/1/edit"), make_state!
    assert.equals 404, status

  it "POST /admin/config/filter/rules/1/delete → 404 (règle inexistante)", ->
    dispatch = get_dispatch!
    status, _, _ = dispatch make_req("POST", "/admin/config/filter/rules/1/delete"), make_state!
    assert.equals 404, status

  it "POST /admin/config/filter/rules/abc/delete → 400 (numéro invalide)", ->
    dispatch = get_dispatch!
    -- "abc" ne match pas %d+ donc le routeur ne reconnaît pas
    -- la route reste inconnue → fallback 302
    status, _, _ = dispatch make_req("POST", "/admin/config/filter/rules/abc/delete"), make_state!
    assert.equals 302, status

  -- ── Listes ────────────────────────────────────────────────────────────────

  it "GET /admin/config/filter/lists → 200", ->
    dispatch = get_dispatch!
    status, _, _ = dispatch make_req("GET", "/admin/config/filter/lists"), make_state!
    assert.equals 200, status

  it "GET /admin/config/filter/lists/ → 200", ->
    dispatch = get_dispatch!
    status, _, _ = dispatch make_req("GET", "/admin/config/filter/lists/"), make_state!
    assert.equals 200, status

  -- ── Fallback ──────────────────────────────────────────────────────────────

  it "chemin inconnu → 302 vers /admin/", ->
    dispatch = get_dispatch!
    status, hdrs, _ = dispatch make_req("GET", "/admin/unknown/path"), make_state!
    assert.equals 302, status
    assert.equals "/admin/", hdrs["Location"]
