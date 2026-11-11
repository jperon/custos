-- tests/unit/worker_questions_aggregate_spec.moon
-- Agrégation des décisions de plusieurs questions d'un même paquet DNS :
-- response_rule_ids ne doit plus être écrasé par la dernière question.

-- ip_whitelist appelle libnft au chargement ; sous le stub FFI des tests il
-- faut le neutraliser (même contournement que tests/unit/filter/rule_spec).
package.loaded["ip_whitelist"] = { init: -> }

wq = require "worker_questions"

describe "worker_questions.aggregate_decisions", ->
  it "fusionne les response_rule_ids de deux décisions dans l'ordre", ->
    out = wq.aggregate_decisions {
      { response_rule_ids: { "a" } }
      { response_rule_ids: { "b" } }
    }
    assert.same { "a", "b" }, out.response_rule_ids

  it "déduplique un id présent dans deux décisions", ->
    out = wq.aggregate_decisions {
      { response_rule_ids: { "a", "b" } }
      { response_rule_ids: { "b", "c" } }
    }
    assert.same { "a", "b", "c" }, out.response_rule_ids

  it "décision sans ids → liste inchangée", ->
    out = wq.aggregate_decisions {
      { response_rule_ids: { "a" } }
      { verdict: true }
      nil
    }
    assert.same { "a" }, out.response_rule_ids
    assert.equals 0, out.dropped_ids

  it "plafonne à MAX_RESPONSE_RULE_IDS et compte les dépassements", ->
    many = {}
    for i = 1, wq.MAX_RESPONSE_RULE_IDS + 3
      many[i] = "r#{i}"
    out = wq.aggregate_decisions { { response_rule_ids: many } }
    assert.equals wq.MAX_RESPONSE_RULE_IDS, #out.response_rule_ids
    assert.equals 3, out.dropped_ids

  it "fusionne les allow_modifiers (dernière valeur gagnante)", ->
    out = wq.aggregate_decisions {
      { allow_modifiers: { validate: "1.1.1.1", log: true } }
      { allow_modifiers: { validate: "9.9.9.9" } }
    }
    assert.equals "9.9.9.9", out.allow_modifiers.validate
    assert.is_true out.allow_modifiers.log
