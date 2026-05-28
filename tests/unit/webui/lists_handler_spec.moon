-- tests/unit/webui/lists_handler_spec.moon
-- Tests de webui/handlers/lists : CRUD et renommage de listes, update_config_refs.

{ :read_config, :write_config } = require "webui.serializer"
{
  :handle_lists_index
  :handle_lists_type
  :handle_list_get,     :handle_list_post
  :handle_list_new_get, :handle_list_new_post
} = require "webui.handlers.lists"

CFG_PATH   = "tmp/lists_handler_spec_cfg.lua"
LISTS_DIR  = "tmp/lists_handler_spec_lists"

write_cfg = (cfg) ->
  ok, err = write_config cfg, CFG_PATH
  assert ok, err

make_state = ->
  { config_path: CFG_PATH }

make_req = (method, body) ->
  { method: method, path: "", headers: {}, body: body or "" }

-- Crée le répertoire de listes de test et y met des fichiers
setup_lists_dir = ->
  os.execute "mkdir -p '#{LISTS_DIR}/domain'"
  os.execute "mkdir -p '#{LISTS_DIR}/net'"
  fh = io.open "#{LISTS_DIR}/domain/famille.txt", "w"
  fh\write "example.com\ntest.org\n"
  fh\close!

cleanup_lists_dir = ->
  os.execute "rm -rf '#{LISTS_DIR}'"

describe "webui/handlers/lists", ->

  before_each ->
    setup_lists_dir!
    write_cfg {
      filter: {
        lists_dir: LISTS_DIR
        rules: {}
      }
    }

  after_each ->
    os.remove CFG_PATH
    cleanup_lists_dir!

  -- ── handle_lists_index ───────────────────────────────────────────────

  describe "handle_lists_index", ->

    it "retourne 200", ->
      status, _, _ = handle_lists_index make_req("GET"), make_state!
      assert.equals 200, status

    it "liste les types trouvés", ->
      _, _, body = handle_lists_index make_req("GET"), make_state!
      assert.truthy body\find("domain", 1, true)
      assert.truthy body\find("net", 1, true)

  -- ── handle_lists_type ────────────────────────────────────────────────

  describe "handle_lists_type", ->

    it "retourne 200 pour un type valide", ->
      status, _, _ = handle_lists_type make_req("GET"), "domain", make_state!
      assert.equals 200, status

    it "liste les fichiers du type", ->
      _, _, body = handle_lists_type make_req("GET"), "domain", make_state!
      assert.truthy body\find("famille", 1, true)

    it "retourne 400 pour un type invalide", ->
      status, _, _ = handle_lists_type make_req("GET"), "INVALID!", make_state!
      assert.equals 400, status

    it "affiche 'Aucune liste' si le type est vide", ->
      _, _, body = handle_lists_type make_req("GET"), "net", make_state!
      assert.truthy body\find("Aucune", 1, true)

  -- ── handle_list_get ───────────────────────────────────────────────────

  describe "handle_list_get", ->

    it "retourne 200 et affiche le contenu du fichier", ->
      status, _, body = handle_list_get make_req("GET"), "domain", "famille", make_state!
      assert.equals 200, status
      assert.truthy body\find("example.com", 1, true)
      assert.truthy body\find("test.org", 1, true)

    it "retourne 400 pour un type invalide", ->
      status, _, _ = handle_list_get make_req("GET"), "BAD!", "famille", make_state!
      assert.equals 400, status

    it "retourne 400 pour un nom invalide", ->
      status, _, _ = handle_list_get make_req("GET"), "domain", "has space", make_state!
      assert.equals 400, status

    it "retourne 200 même si le fichier n'existe pas (contenu vide)", ->
      status, _, _ = handle_list_get make_req("GET"), "domain", "inexistant", make_state!
      assert.equals 200, status

  -- ── handle_list_post — save ───────────────────────────────────────────

  describe "handle_list_post — save", ->

    it "écrit le contenu et redirige", ->
      body_str = "action=save&content=new1.com%0Anew2.com"
      status, hdrs, _ = handle_list_post make_req("POST", body_str), "domain", "famille", make_state!
      assert.equals 302, status
      assert.truthy hdrs["Location"]\find("famille", 1, true)

    it "le contenu est bien persisté", ->
      body_str = "action=save&content=updated.com"
      handle_list_post make_req("POST", body_str), "domain", "famille", make_state!
      fh = io.open "#{LISTS_DIR}/domain/famille.txt", "r"
      assert.not_nil fh
      content = fh\read "*a"
      fh\close!
      assert.truthy content\find("updated.com", 1, true)

    it "retourne 400 pour un type invalide", ->
      body_str = "action=save&content=x"
      status, _, _ = handle_list_post make_req("POST", body_str), "BAD!", "famille", make_state!
      assert.equals 400, status

  -- ── handle_list_post — delete ─────────────────────────────────────────

  describe "handle_list_post — delete", ->

    it "supprime le fichier et redirige vers le type", ->
      body_str = "action=delete"
      status, hdrs, _ = handle_list_post make_req("POST", body_str), "domain", "famille", make_state!
      assert.equals 302, status
      assert.truthy hdrs["Location"]\find("domain", 1, true)
      assert.falsy hdrs["Location"]\find("famille", 1, true)

    it "le fichier est bien supprimé", ->
      body_str = "action=delete"
      handle_list_post make_req("POST", body_str), "domain", "famille", make_state!
      fh = io.open "#{LISTS_DIR}/domain/famille.txt", "r"
      assert.is_nil fh

  -- ── handle_list_post — rename ─────────────────────────────────────────

  describe "handle_list_post — rename", ->

    it "renomme le fichier et redirige vers le nouveau nom", ->
      body_str = "action=rename&new_name=newfamille"
      status, hdrs, _ = handle_list_post make_req("POST", body_str), "domain", "famille", make_state!
      assert.equals 302, status
      assert.truthy hdrs["Location"]\find("newfamille", 1, true)

    it "le fichier porte le nouveau nom", ->
      body_str = "action=rename&new_name=renamedlist"
      handle_list_post make_req("POST", body_str), "domain", "famille", make_state!
      fh = io.open "#{LISTS_DIR}/domain/renamedlist.txt", "r"
      assert.not_nil fh
      fh\close! if fh

    it "l'ancien fichier n'existe plus", ->
      body_str = "action=rename&new_name=renamedlist"
      handle_list_post make_req("POST", body_str), "domain", "famille", make_state!
      fh = io.open "#{LISTS_DIR}/domain/famille.txt", "r"
      assert.is_nil fh

    it "même nom → redirection sans erreur", ->
      body_str = "action=rename&new_name=famille"
      status, hdrs, _ = handle_list_post make_req("POST", body_str), "domain", "famille", make_state!
      assert.equals 302, status
      assert.truthy hdrs["Location"]\find("famille", 1, true)

    it "retourne 400 si le nouveau nom est invalide", ->
      body_str = "action=rename&new_name=invalid+name"
      status, _, _ = handle_list_post make_req("POST", body_str), "domain", "famille", make_state!
      assert.equals 400, status

    it "met à jour les références dans les règles", ->
      write_cfg {
        filter: {
          lists_dir: LISTS_DIR
          rules: {
            {
              description: "règle avec liste"
              conditions: { from_domain_list: "famille" }
              actions: { "allow" }
            }
          }
        }
      }
      body_str = "action=rename&new_name=amis"
      handle_list_post make_req("POST", body_str), "domain", "famille", make_state!
      loaded = (read_config CFG_PATH)
      assert.equals "amis", loaded.filter.rules[1].conditions.from_domain_list

  -- ── handle_list_new_get ───────────────────────────────────────────────

  describe "handle_list_new_get", ->

    it "retourne 200 avec un formulaire", ->
      status, _, body = handle_list_new_get make_req("GET"), "domain", make_state!
      assert.equals 200, status
      assert.truthy body\find("form", 1, true)

    it "retourne 400 pour un type invalide", ->
      status, _, _ = handle_list_new_get make_req("GET"), "BAD!", make_state!
      assert.equals 400, status

  -- ── handle_list_new_post ──────────────────────────────────────────────

  describe "handle_list_new_post", ->

    it "crée une nouvelle liste et redirige", ->
      body_str = "name=nouvliste&content=google.com%0Afacebook.com"
      status, hdrs, _ = handle_list_new_post make_req("POST", body_str), "domain", make_state!
      assert.equals 302, status
      assert.truthy hdrs["Location"]\find("nouvliste", 1, true)

    it "le fichier est bien créé", ->
      body_str = "name=malist&content=example.com"
      handle_list_new_post make_req("POST", body_str), "domain", make_state!
      fh = io.open "#{LISTS_DIR}/domain/malist.txt", "r"
      assert.not_nil fh
      fh\close! if fh

    it "retourne 400 si le nom est invalide", ->
      body_str = "name=invalid%20name&content=x"
      status, _, _ = handle_list_new_post make_req("POST", body_str), "domain", make_state!
      assert.equals 400, status

    it "retourne 400 pour un type invalide", ->
      body_str = "name=ok&content=x"
      status, _, _ = handle_list_new_post make_req("POST", body_str), "BAD!", make_state!
      assert.equals 400, status
