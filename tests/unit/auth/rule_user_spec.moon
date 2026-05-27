-- tests/unit/auth/rule_user_spec.moon
-- Tests unitaires pour auth/rule_user : user_qualifies_for_rule + matches_user.
-- Régression pour le bug 1 : wildcard "_any" non reconnu.

{ :user_qualifies_for_rule, :matches_user } = require "auth.rule_user"

describe "auth/rule_user", ->

  -- ── matches_user ────────────────────────────────────────────────────────────
  describe "matches_user", ->

    it "_any correspond à tout utilisateur", ->
      assert.is_true  matches_user "_any", "alice@test.lan"
      assert.is_true  matches_user "_any", "bob"
      assert.is_true  matches_user "_any", ""

    it "correspondance exacte", ->
      assert.is_true  matches_user "alice@test.lan", "alice@test.lan"

    it "pas de correspondance", ->
      assert.is_false matches_user "alice@test.lan", "bob@test.lan"

  -- ── user_qualifies_for_rule : format table (implicit AND) ───────────────────
  describe "user_qualifies_for_rule (format table)", ->

    it "wildcard _any : tout utilisateur qualifie (régression bug 1)", ->
      rule = { conditions: { from_users: "_any" } }
      assert.is_true user_qualifies_for_rule "alice@test.lan", rule

    it "utilisateur exact correspondant qualifie", ->
      rule = { conditions: { from_users: "alice@test.lan" } }
      assert.is_true user_qualifies_for_rule "alice@test.lan", rule

    it "utilisateur non correspondant ne qualifie pas", ->
      rule = { conditions: { from_users: "alice@test.lan" } }
      assert.is_false user_qualifies_for_rule "bob@test.lan", rule

    it "liste de plusieurs utilisateurs : correspondance si présent", ->
      rule = { conditions: { from_users: {"alice@test.lan", "charlie@test.lan"} } }
      assert.is_true  user_qualifies_for_rule "charlie@test.lan", rule
      assert.is_false user_qualifies_for_rule "dave@test.lan", rule

    it "absence de from_users → qualifie (règle ouverte)", ->
      rule = { conditions: { to_domain: "example.lan" } }
      assert.is_true user_qualifies_for_rule "alice@test.lan", rule

    it "from_userlists : correspondance via la table fournie", ->
      rule = { conditions: { from_userlists: "staff" } }
      userlists = { staff: { "alice@test.lan", "bob@test.lan" } }
      assert.is_true  user_qualifies_for_rule "alice@test.lan", rule, userlists
      assert.is_false user_qualifies_for_rule "eve@test.lan",   rule, userlists

    it "from_userlists absente de la config → ne qualifie pas", ->
      rule = { conditions: { from_userlists: "staff" } }
      assert.is_false user_qualifies_for_rule "alice@test.lan", rule

  -- ── user_qualifies_for_rule : format tableau (ancien format) ────────────────
  describe "user_qualifies_for_rule (format array)", ->

    it "wildcard _any dans format array qualifie", ->
      rule = { conditions: { { from_users: "_any" } } }
      assert.is_true user_qualifies_for_rule "alice@test.lan", rule

    it "utilisateur exact dans format array qualifie", ->
      rule = { conditions: { { from_users: "alice@test.lan" } } }
      assert.is_true user_qualifies_for_rule "alice@test.lan", rule

    it "utilisateur absent dans format array ne qualifie pas", ->
      rule = { conditions: { { from_users: "alice@test.lan" } } }
      assert.is_false user_qualifies_for_rule "bob@test.lan", rule

  -- ── cas limites ─────────────────────────────────────────────────────────────
  describe "cas limites", ->

    it "rule nil → false", ->
      assert.is_false user_qualifies_for_rule "alice@test.lan", nil

    it "rule sans conditions → false", ->
      assert.is_false user_qualifies_for_rule "alice@test.lan", {}
