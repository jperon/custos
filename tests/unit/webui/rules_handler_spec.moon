-- tests/unit/webui/rules_handler_spec.moon
-- Tests de webui/handlers/rules : CRUD et déplacement de règles.

{ :read_config, :write_config } = require "webui.serializer"
{
  :handle_rules_list
  :handle_rules_new_get,  :handle_rules_new_post
  :handle_rules_edit_get, :handle_rules_edit_post
  :handle_rules_delete,   :handle_rules_move
} = require "webui.handlers.rules"

CFG_PATH = "tmp/rules_handler_spec.lua"

write_cfg = (cfg) ->
  ok, err = write_config cfg, CFG_PATH
  assert ok, err

make_state = ->
  { config_path: CFG_PATH }

make_req = (method, body) ->
  { method: method, path: "", headers: {}, body: body or "" }

base_cfg_with_rules = (rules) ->
  { filter: { rules: rules or {} } }

describe "webui/handlers/rules", ->

  before_each ->
    write_cfg base_cfg_with_rules {
      { description: "règle A", conditions: { from_domain: "example.com" }, actions: { "allow" } }
      { description: "règle B", conditions: {}, actions: { "block" } }
    }

  after_each ->
    os.remove CFG_PATH

  -- ── handle_rules_list ─────────────────────────────────────────────────

  describe "handle_rules_list", ->

    it "retourne 200", ->
      status, _, _ = handle_rules_list make_req("GET"), make_state!
      assert.equals 200, status

    it "affiche les descriptions des règles", ->
      _, _, body = handle_rules_list make_req("GET"), make_state!
      assert.truthy body\find("règle A", 1, true)
      assert.truthy body\find("règle B", 1, true)

    it "affiche des boutons edit/delete/move pour chaque règle", ->
      _, _, body = handle_rules_list make_req("GET"), make_state!
      assert.truthy body\find("edit", 1, true) or body\find("diter", 1, true)
      assert.truthy body\find("delete", 1, true) or body\find("Supprimer", 1, true)

    it "le bouton de suppression est dans le formulaire", ->
      _, _, body = handle_rules_list make_req("GET"), make_state!
      pos_btn = body\find("✕", 1, true)
      pos_form = body\find("</form>", pos_btn, true)
      assert.truthy pos_btn
      assert.truthy pos_form

    it "retourne 500 si config_path invalide", ->
      state = { config_path: "/nonexistent/file.lua" }
      status, _, _ = handle_rules_list make_req("GET"), state
      assert.equals 500, status

    it "affiche 'toujours' pour une règle sans conditions", ->
      _, _, body = handle_rules_list make_req("GET"), make_state!
      assert.truthy body\find("toujours", 1, true)

  -- ── handle_rules_new_get ──────────────────────────────────────────────

  describe "handle_rules_new_get", ->

    it "retourne 200 avec un formulaire vide", ->
      status, _, body = handle_rules_new_get make_req("GET"), make_state!
      assert.equals 200, status
      assert.truthy body\find("form", 1, true)
      assert.truthy body\find("Nouvelle", 1, true)

  -- ── handle_rules_new_post ─────────────────────────────────────────────

  describe "handle_rules_new_post", ->

    it "ajoute une nouvelle règle et redirige vers la liste", ->
      body_str = "description=test+rule&action%5Btype%5D=allow"
      status, hdrs, _ = handle_rules_new_post make_req("POST", body_str), make_state!
      assert.equals 302, status
      assert.truthy hdrs["Location"]\find("rules", 1, true)

    it "la règle est bien persistée", ->
      body_str = "description=ma+regle&action%5Btype%5D=block"
      handle_rules_new_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      rules = loaded.filter.rules
      -- On doit avoir 3 règles maintenant (2 initiales + 1 nouvelle)
      assert.equals 3, #rules
      assert.equals "ma regle", rules[3].description

    it "la nouvelle règle a l'action correcte", ->
      body_str = "description=bloc&action%5Btype%5D=block"
      handle_rules_new_post make_req("POST", body_str), make_state!
      loaded = (read_config CFG_PATH)
      rules = loaded.filter.rules
      assert.equals "block", rules[3].actions[1]

    it "retourne 500 si config_path invalide", ->
      state = { config_path: "/nonexistent/file.lua" }
      status, _, _ = handle_rules_new_post make_req("POST", "description=x"), state
      assert.equals 500, status

  -- ── handle_rules_edit_get ─────────────────────────────────────────────

  describe "handle_rules_edit_get", ->

    it "retourne 200 pour une règle existante", ->
      status, _, body = handle_rules_edit_get make_req("GET"), 1, make_state!
      assert.equals 200, status
      assert.truthy body\find("règle A", 1, true) or body\find("r\232gle A", 1, true)

    it "retourne 404 pour un numéro hors plage", ->
      status, _, _ = handle_rules_edit_get make_req("GET"), 99, make_state!
      assert.equals 404, status

  -- ── handle_rules_edit_post ────────────────────────────────────────────

  describe "handle_rules_edit_post", ->

    it "modifie la règle et redirige", ->
      body_str = "description=updated&action%5Btype%5D=allow"
      status, hdrs, _ = handle_rules_edit_post make_req("POST", body_str), 1, make_state!
      assert.equals 302, status

    it "la modification est bien persistée", ->
      body_str = "description=nouvelle+desc&action%5Btype%5D=allow"
      handle_rules_edit_post make_req("POST", body_str), 1, make_state!
      loaded = (read_config CFG_PATH)
      assert.equals "nouvelle desc", loaded.filter.rules[1].description

    it "retourne 404 si la règle n'existe pas", ->
      body_str = "description=x&action%5Btype%5D=allow"
      status, _, _ = handle_rules_edit_post make_req("POST", body_str), 99, make_state!
      assert.equals 404, status

  -- ── conditions à deux dropdowns (base + forme) ────────────────────────

  describe "conditions base+forme", ->

    it "recompose le nom de condition depuis base + forme=lists", ->
      body_str = "description=r&cond_0%5Bbase%5D=to_domain&cond_0%5Bform%5D=lists" ..
        "&cond_0%5Bvalue%5D=malware%0Aads&action%5Btype%5D=allow"
      handle_rules_edit_post make_req("POST", body_str), 1, make_state!
      loaded = (read_config CFG_PATH)
      conds = loaded.filter.rules[1].conditions
      assert.same { "malware", "ads" }, conds.to_domain_lists

    it "forme=base donne la condition racine avec valeur scalaire", ->
      body_str = "description=r&cond_0%5Bbase%5D=to_domain&cond_0%5Bform%5D=base" ..
        "&cond_0%5Bvalue%5D=example.com&action%5Btype%5D=allow"
      handle_rules_edit_post make_req("POST", body_str), 1, make_state!
      loaded = (read_config CFG_PATH)
      assert.equals "example.com", loaded.filter.rules[1].conditions.to_domain

    it "to_domainlist + forme=list donne to_domainlist_list (groupe, scalaire)", ->
      body_str = "description=r&cond_0%5Bbase%5D=to_domainlist&cond_0%5Bform%5D=list" ..
        "&cond_0%5Bvalue%5D=mon_groupe&action%5Btype%5D=allow"
      handle_rules_edit_post make_req("POST", body_str), 1, make_state!
      loaded = (read_config CFG_PATH)
      assert.equals "mon_groupe", loaded.filter.rules[1].conditions.to_domainlist_list

    it "présélectionne base et forme à l'édition d'un groupe de domainlists", ->
      write_cfg base_cfg_with_rules {
        { description: "r", conditions: { to_domainlist_list: "mon_groupe" }, actions: { "allow" } }
      }
      _, _, body = handle_rules_edit_get make_req("GET"), 1, make_state!
      assert.truthy body\find("to_domainlist", 1, true)
      assert.truthy body\find("mon_groupe", 1, true)

    it "présélectionne base et forme à l'édition (round-trip)", ->
      write_cfg base_cfg_with_rules {
        { description: "r", conditions: { to_domain_lists: { "x" } }, actions: { "allow" } }
      }
      _, _, body = handle_rules_edit_get make_req("GET"), 1, make_state!
      -- le formulaire propose bien les deux dropdowns
      assert.truthy body\find("cond-a", 1, true)
      assert.truthy body\find("cond-b", 1, true)
      -- la racine to_domain et l'option lists sont présentes
      assert.truthy body\find("to_domain", 1, true)

  -- ── handle_rules_delete ───────────────────────────────────────────────

  describe "handle_rules_delete", ->

    it "supprime la règle 1 et redirige", ->
      status, hdrs, _ = handle_rules_delete make_req("POST"), 1, make_state!
      assert.equals 302, status

    it "la règle est bien supprimée", ->
      handle_rules_delete make_req("POST"), 1, make_state!
      loaded = (read_config CFG_PATH)
      assert.equals 1, #loaded.filter.rules
      -- Règle B devient règle 1
      assert.equals "règle B", loaded.filter.rules[1].description

    it "retourne 404 si la règle n'existe pas", ->
      status, _, _ = handle_rules_delete make_req("POST"), 99, make_state!
      assert.equals 404, status

  -- ── handle_rules_move ────────────────────────────────────────────────

  describe "handle_rules_move", ->

    it "déplace la règle 1 vers le bas", ->
      body_str = "dir=down"
      handle_rules_move make_req("POST", body_str), 1, make_state!
      loaded = (read_config CFG_PATH)
      -- Règle A doit être en position 2
      assert.equals "règle B", loaded.filter.rules[1].description
      assert.equals "règle A", loaded.filter.rules[2].description

    it "déplace la règle 2 vers le haut", ->
      body_str = "dir=up"
      handle_rules_move make_req("POST", body_str), 2, make_state!
      loaded = (read_config CFG_PATH)
      assert.equals "règle B", loaded.filter.rules[1].description
      assert.equals "règle A", loaded.filter.rules[2].description

    it "ne bouge pas si la règle est déjà en première position (move up)", ->
      body_str = "dir=up"
      handle_rules_move make_req("POST", body_str), 1, make_state!
      loaded = (read_config CFG_PATH)
      -- Ordre inchangé
      assert.equals "règle A", loaded.filter.rules[1].description

    it "ne bouge pas si la règle est déjà en dernière position (move down)", ->
      body_str = "dir=down"
      handle_rules_move make_req("POST", body_str), 2, make_state!
      loaded = (read_config CFG_PATH)
      assert.equals "règle B", loaded.filter.rules[2].description

    it "redirige après déplacement", ->
      body_str = "dir=down"
      status, hdrs, _ = handle_rules_move make_req("POST", body_str), 1, make_state!
      assert.equals 302, status
      assert.truthy hdrs["Location"]\find("rules", 1, true)

    it "retourne 404 si la règle n'existe pas", ->
      body_str = "dir=up"
      status, _, _ = handle_rules_move make_req("POST", body_str), 99, make_state!
      assert.equals 404, status
