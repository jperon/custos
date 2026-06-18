-- tests/unit/webui/schema/registry_spec.moon
-- Vérifie l'auto-génération des familles de conditions et les overrides de
-- libellé de forme (s.forms), notamment le « groupe de domainlists »
-- (to_domainlist_list).

registry = require "webui.schema.registry"

-- Retrouve une famille par sa racine.
fam_by_root = (fams, root) ->
  for f in *fams
    return f if f.root == root
  nil

-- Retrouve une forme par sa clé dans une famille.
form_by_key = (fam, key) ->
  for fm in *fam.forms
    return fm if fm.key == key
  nil

describe "webui.schema.registry condition_families", ->
  fams = registry.condition_families!
  dl   = fam_by_root fams, "to_domainlist"

  it "expose to_domainlist comme racine (et non to_domainlists)", ->
    assert.is_not_nil dl
    assert.is_nil (fam_by_root fams, "to_domainlists")

  it "to_domainlist a les 4 formes base/plural/list/lists", ->
    for key in *{"base", "plural", "list", "lists"}
      assert.is_not_nil (form_by_key dl, key), "forme manquante : #{key}"

  it "la forme `list` porte l'override « Groupe de listes »", ->
    lf = form_by_key dl, "list"
    assert.are.equal "Groupe de listes (fichier nommé)", lf.label
    assert.are.equal "domainlist", lf.list_type
    assert.is_not_nil (lf.hint\find "domainlist", 1, true)

  it "la forme `lists` porte l'override « Plusieurs groupes de listes »", ->
    lf = form_by_key dl, "lists"
    assert.are.equal "Plusieurs groupes de listes", lf.label

  it "une condition sans override garde les libellés génériques", ->
    net = fam_by_root fams, "from_net"
    assert.is_not_nil net
    lf = form_by_key net, "list"
    assert.are.equal "Une liste nommée (fichier)", lf.label

describe "webui.schema.registry resolve_condition", ->
  it "to_domainlist_list → (to_domainlist, list)", ->
    root, form = registry.resolve_condition "to_domainlist_list"
    assert.are.equal "to_domainlist", root
    assert.are.equal "list", form

  it "to_domainlist_lists → (to_domainlist, lists)", ->
    root, form = registry.resolve_condition "to_domainlist_lists"
    assert.are.equal "to_domainlist", root
    assert.are.equal "lists", form

  it "to_domainlists → (to_domainlist, plural)", ->
    root, form = registry.resolve_condition "to_domainlists"
    assert.are.equal "to_domainlist", root
    assert.are.equal "plural", form
