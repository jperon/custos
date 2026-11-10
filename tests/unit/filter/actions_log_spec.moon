-- tests/unit/filter/actions_log_spec.moon
-- Action log : convention de factory (cfg) -> (rule) -> (req) et message
-- provenant de rule.log.log_msg (forme table écrite par la webui).

package.loaded["ipc"] or= { register_modifier: -> nil }
package.loaded["dns_ede"] or= {
  strip_dns_rr:     (raw, _t) -> raw
  add_ede_modified: (raw, _r) -> raw
  clear_ad_bit:     (raw) -> raw
}

describe "filter.actions.log", ->
  factory  = (require "filter.actions.log").factory
  rule_mod = require "filter.rule"
  log_mod  = require "log"
  orig_log_info = log_mod.log_info
  captured = {}

  before_each ->
    captured = {}
    log_mod.log_info = (thunk) -> captured[#captured + 1] = thunk!

  after_each ->
    log_mod.log_info = orig_log_info

  last_message = ->
    captured[#captured] and captured[#captured].message

  it "message par défaut si rule.log absent", ->
    act = (factory {}) { description: "r" }
    v, msg = act { domain: "example.test" }
    assert.is_nil v
    assert.equals "Log action triggered by rule", msg
    assert.equals msg, last_message!

  it "message pris dans rule.log.log_msg", ->
    act = (factory {}) { log: { log_msg: "bonjour" }, description: "r" }
    v, msg = act { domain: "example.test" }
    assert.is_nil v
    assert.equals "bonjour", msg
    assert.equals "bonjour", last_message!

  it "log_msg vide → message par défaut", ->
    act = (factory {}) { log: { log_msg: "" }, description: "r" }
    _, msg = act { domain: "example.test" }
    assert.equals "Log action triggered by rule", msg

  it "compile_rules avec { log: { log_msg } } + allow → autorise et logue", ->
    compiled = rule_mod.compile_rules {
      nft: { ip_timeout: "2m" }
      macs: {}
      rules: {
        {
          description: "log table"
          actions:     { { log: { log_msg: "bonjour" } }, "allow" }
        }
      }
    }
    v = rule_mod.decide compiled, { domain: "example.test" }
    assert.is_true v
    assert.equals "bonjour", last_message!
