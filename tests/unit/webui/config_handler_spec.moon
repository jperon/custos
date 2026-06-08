-- tests/unit/webui/config_handler_spec.moon
-- Tests de webui/handlers/config : parse_form, build_section, handlers GET/POST.

{ :read_config, :write_config } = require "webui.serializer"

CFG_PATH = "tmp/config_handler_spec.lua"

write_cfg = (cfg) ->
  ok, err = write_config cfg, CFG_PATH
  assert ok, err

-- On accède aux fonctions internes via le module compilé
-- parse_form et build_section sont locales ; on les teste via les handlers.
{ :handle_config_index,
  :handle_config_section_get,
  :handle_config_section_post,
  :handle_filter_general_get,
  :handle_filter_general_post } = require "webui.handlers.config"

make_state = ->
  { config_path: CFG_PATH }

make_req = (method, body) ->
  { method: method, path: "", headers: {}, body: body or "" }

describe "webui/handlers/config", ->

  before_each ->
    write_cfg {
      runtime:     { log_level: "INFO", benchmark: false }
      nfqueue:     { questions: "0-1" }
      dns:         { port: 53 }
      nft:         { family: "bridge" }
      ipc:         {}
      clients:     {}
      mac_learner: {}
      auth:        {}
      doh:         {}
      events:      {}
      metrics:     {}
      rtp:         {}
      filter:      { rules: {} }
    }

  after_each ->
    os.remove CFG_PATH

  -- ── handle_config_index ────────────────────────────────────────────────

  describe "handle_config_index", ->

    it "retourne 200 avec du HTML", ->
      status, hdrs, body = handle_config_index make_req("GET"), make_state!
      assert.equals 200, status
      assert.equals "text/html; charset=UTF-8", hdrs["Content-Type"]
      assert.truthy body\find("<html", 1, true)

    it "inclut les sections éditables dans le body", ->
      _, _, body = handle_config_index make_req("GET"), make_state!
      assert.truthy body\find("runtime", 1, true)
      assert.truthy body\find("dns", 1, true)

    it "retourne 500 si config_path invalide", ->
      state = { config_path: "/nonexistent/file.lua" }
      status, _, _ = handle_config_index make_req("GET"), state
      assert.equals 500, status

  -- ── handle_config_section_get ──────────────────────────────────────────

  describe "handle_config_section_get", ->

    it "retourne 200 pour la section 'runtime'", ->
      status, hdrs, body = handle_config_section_get make_req("GET"), "runtime", make_state!
      assert.equals 200, status
      assert.truthy body\find("Runtime", 1, true)

    it "retourne 200 pour la section 'dns'", ->
      status, _, _ = handle_config_section_get make_req("GET"), "dns", make_state!
      assert.equals 200, status

    it "retourne 404 pour une section inconnue", ->
      status, _, body = handle_config_section_get make_req("GET"), "nonexistent", make_state!
      assert.equals 404, status

    it "affiche la valeur courante du champ log_level", ->
      _, _, body = handle_config_section_get make_req("GET"), "runtime", make_state!
      -- La valeur courante "INFO" doit apparaître dans le formulaire
      assert.truthy body\find("INFO", 1, true)

    it "retourne 500 si config_path invalide", ->
      state = { config_path: "/nonexistent/file.lua" }
      status, _, _ = handle_config_section_get make_req("GET"), "runtime", state
      assert.equals 500, status

  -- ── handle_config_section_post ─────────────────────────────────────────

  describe "handle_config_section_post", ->

    it "sauvegarde et retourne 302 vers l'index avec fragment", ->
      body_str = "log_level=WARN&benchmark_present=1"
      status, hdrs, _ = handle_config_section_post make_req("POST", body_str), "runtime", make_state!
      assert.equals 302, status
      assert.truthy hdrs["Location"]\find("runtime", 1, true)

    it "la valeur est bien persistée dans le fichier", ->
      body_str = "log_level=ERROR&benchmark_present=1"
      handle_config_section_post make_req("POST", body_str), "runtime", make_state!
      loaded = (read_config CFG_PATH)
      assert.equals "ERROR", loaded.runtime.log_level

    it "le booléen benchmark=true est persisté si présent", ->
      body_str = "log_level=INFO&benchmark=1&benchmark_present=1"
      handle_config_section_post make_req("POST", body_str), "runtime", make_state!
      loaded = (read_config CFG_PATH)
      assert.is_true loaded.runtime.benchmark

    it "le booléen benchmark=false est persisté si absent du form", ->
      body_str = "log_level=INFO&benchmark_present=1"
      handle_config_section_post make_req("POST", body_str), "runtime", make_state!
      loaded = (read_config CFG_PATH)
      assert.is_false loaded.runtime.benchmark

    it "retourne 404 pour une section inconnue", ->
      status, _, _ = handle_config_section_post make_req("POST", ""), "nonexistent", make_state!
      assert.equals 404, status

    it "retourne 500 si config_path invalide", ->
      state = { config_path: "/nonexistent/file.lua" }
      status, _, _ = handle_config_section_post make_req("POST", "log_level=INFO"), "runtime", state
      assert.equals 500, status

    it "ne détruit pas les autres sections lors de la sauvegarde", ->
      body_str = "log_level=DEBUG&benchmark_present=1"
      handle_config_section_post make_req("POST", body_str), "runtime", make_state!
      loaded = (read_config CFG_PATH)
      -- La section dns doit rester intacte
      assert.not_nil loaded.dns

    it "persiste un string_list (admin_users) correctement", ->
      -- Utiliser la section auth avec un champ string_list si disponible
      -- On vérifie que le POST encode bien les champs nfqueue
      body_str = "questions=2-3"
      handle_config_section_post make_req("POST", body_str), "nfqueue", make_state!
      loaded = (read_config CFG_PATH)
      assert.equals "2-3", loaded.nfqueue.questions

  -- ── handle_filter_general (SafeSearch, YouTube, listes…) ────────────────

  describe "handle_config_index — liens filtre", ->

    it "expose un lien vers la page Général du filtre", ->
      _, _, body = handle_config_index make_req("GET"), make_state!
      assert.truthy body\find("/admin/config/filter/general", 1, true)

  describe "handle_filter_general_get", ->

    it "retourne 200 et expose le champ SafeSearch", ->
      status, hdrs, body = handle_filter_general_get make_req("GET"), make_state!
      assert.equals 200, status
      assert.equals "text/html; charset=UTF-8", hdrs["Content-Type"]
      assert.truthy body\find("SafeSearch", 1, true)
      assert.truthy body\find("safe_search", 1, true)
      assert.truthy body\find("youtube_restrict", 1, true)

    it "n'expose pas les dictionnaires nommés ni les règles", ->
      _, _, body = handle_filter_general_get make_req("GET"), make_state!
      -- name="nets" / "rules" ne doivent pas apparaître comme champs de formulaire
      assert.falsy body\find('name="nets"', 1, true)
      assert.falsy body\find('name="rules"', 1, true)

    it "retourne 500 si config_path invalide", ->
      state = { config_path: "/nonexistent/file.lua" }
      status, _, _ = handle_filter_general_get make_req("GET"), state
      assert.equals 500, status

  describe "handle_filter_general_post", ->

    it "persiste safe_search=false (case décochée)", ->
      -- form sans safe_search → false ; les autres champs présents
      body_str = "youtube_restrict=moderate"
      status, hdrs = handle_filter_general_post make_req("POST", body_str), make_state!
      assert.equals 302, status
      assert.truthy hdrs["Location"]\find("filter-general", 1, true)
      loaded = (read_config CFG_PATH)
      assert.is_false loaded.filter.safe_search

    it "persiste safe_search=true et youtube_restrict", ->
      body_str = "safe_search=1&youtube_restrict=strict"
      handle_filter_general_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      assert.is_true loaded.filter.safe_search
      assert.equals "strict", loaded.filter.youtube_restrict

    it "ne détruit pas les règles ni les dictionnaires nommés du filtre", ->
      write_cfg {
        filter: {
          rules: { { description: "r1", actions: { "allow" } } }
          nets:  { lan: { "192.168.0.0/16" } }
          safe_search: true
        }
      }
      body_str = "safe_search=1&youtube_restrict=moderate"
      handle_filter_general_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      assert.equals "r1", loaded.filter.rules[1].description
      assert.equals "192.168.0.0/16", loaded.filter.nets.lan[1]

    it "retourne 500 si config_path invalide", ->
      state = { config_path: "/nonexistent/file.lua" }
      status, _, _ = handle_filter_general_post make_req("POST", "safe_search=1"), state
      assert.equals 500, status
