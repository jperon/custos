-- tests/unit/filter/rule_id_spec.moon
-- Spec direct de filter.rule_id : translittération, normalisation d'identifiant
-- et génération stable/unique des rule_id (source de vérité partagée par le
-- compilateur, le serveur d'auth et les workers).

{ :sanitize_ascii, :sanitize_id, :generate, :generate_unique } = require "filter.rule_id"

describe "filter.rule_id.sanitize_ascii", ->
  it "translittère les accents et ligatures", ->
    assert.equals "Cafe Nandu", sanitize_ascii "Café Ñandú"
    assert.equals "ss ae OE", sanitize_ascii "ß æ Œ"

  it "normalise espaces, tabulations et retours à la ligne", ->
    assert.equals "a b c", sanitize_ascii "a  b   c"
    assert.equals "a b c", sanitize_ascii "a\tb\nc"

  it "remplace guillemets et antislash par une espace", ->
    assert.equals "a b c", sanitize_ascii "a\"b\\c"

  it "supprime les octets non ASCII restants", ->
    assert.equals "ab", sanitize_ascii "a€b"

  it "nil ou vide → chaîne vide", ->
    assert.equals "", sanitize_ascii nil
    assert.equals "", sanitize_ascii ""

describe "filter.rule_id.sanitize_id", ->
  it "minuscule, accents translitérés, caractères spéciaux en « _ »", ->
    assert.equals "regle_ete", sanitize_id "Règle Été!"
    assert.equals "cafe_nandu", sanitize_id "Café Ñandú"

  it "tirets convertis en « _ » (après trim des underscores)", ->
    assert.equals "_foo_bar_", sanitize_id "  ---Foo---Bar---  "

  it "espaces multiples fusionnés en un seul « _ »", ->
    assert.equals "a_b_c", sanitize_id "a  b   c"

  it "tronque à 128 caractères", ->
    s = sanitize_id string.rep "a", 200
    assert.equals 128, #s

  it "chaîne vide → chaîne vide", ->
    assert.equals "", sanitize_id "!!!"
    assert.equals "", sanitize_id nil

describe "filter.rule_id.generate", ->
  it "préfère rule_id, normalisé et préfixé r_", ->
    assert.equals "r_mon_id", generate { rule_id: "Mon ID!" }, 3

  it "replie sur description si rule_id absent ou blanc", ->
    assert.equals "r_ma_regle", generate { description: "Ma règle" }, 3
    assert.equals "r_7", generate { rule_id: "   ", description: "  " }, 7

  it "replie sur l'index quand aucune métadonnée exploitable", ->
    assert.equals "r_3", generate {}, 3
    assert.equals "r_12", generate nil, 12

describe "filter.rule_id.generate_unique", ->
  it "suffixe les collisions et marque les identifiants utilisés", ->
    used = {}
    rule = { rule_id: "x" }
    assert.equals "r_x", generate_unique rule, 1, used
    assert.equals "r_x_2", generate_unique rule, 1, used
    assert.equals "r_x_3", generate_unique rule, 1, used
    assert.is_true used["r_x"]
    assert.is_true used["r_x_2"]
    assert.is_true used["r_x_3"]

  it "sans table used_ids : pas de suffixe et aucun marquage", ->
    rule = { rule_id: "x" }
    assert.equals "r_x", generate_unique rule, 1
    assert.equals "r_x", generate_unique rule, 1
