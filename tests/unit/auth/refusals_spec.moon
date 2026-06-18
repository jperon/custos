-- tests/unit/auth/refusals_spec.moon
-- Tests de handle_refusals : filtrage par MAC, sérialisation JSON,
-- fichier absent → [], token invalide → 401.

token = require "auth.token"
{ :handle_refusals, :handle_request } = require "auth.handlers"

KEY = token.load_key "tmp/refusals_spec.key"
DIR = "tmp/refusals_spec_events"
MAC = "aa:bb:cc:44:55:66"
IP  = "10.42.0.70"
USER = "alice@test.lan"

make_state = -> { token_key: KEY, events_dir: DIR }

req_with = (tok) -> { headers: { cookie: tok and "custos_session=#{tok}" or "" } }

valid_token = -> token.generate "user", USER, MAC, os.time! + 300, KEY

-- Format recent-verdicts.tsv :
--   mac\tip\tuser\tqname\tdecision\treason\tcount\tfirst_ts\tlast_ts
verdict_line = (mac, qname, decision, reason, count, ts) ->
  "#{mac}\t-\t-\t#{qname}\t#{decision}\t#{reason}\t#{count}\t#{ts}\t#{ts}\n"

write_recent = (lines) ->
  os.execute "mkdir -p '#{DIR}'"
  fh = io.open "#{DIR}/recent-verdicts.tsv", "w"
  fh\write lines
  fh\close!

describe "handle_refusals", ->
  after_each ->
    os.remove "#{DIR}/recent-verdicts.tsv"

  it "token absent/invalide → 401", ->
    status = handle_refusals (req_with nil), IP, MAC, make_state!
    assert.equals 401, status
    bad = (valid_token!)\sub(1, 10) .. "0000"
    assert.equals 401, (handle_refusals (req_with bad), IP, MAC, make_state!)

  it "fichier absent → 200 []", ->
    status, headers, body = handle_refusals (req_with valid_token!), IP, MAC, make_state!
    assert.equals 200, status
    assert.equals "application/json", headers["Content-Type"]
    assert.equals "[]", body

  it "ne retourne que les refus de la MAC du client", ->
    write_recent (verdict_line MAC, "ads.com", "block", "blocklist", 2, 100) ..
      (verdict_line "11:22:33:44:55:66", "other.com", "block", "r", 1, 101)
    status, _, body = handle_refusals (req_with valid_token!), IP, MAC, make_state!
    assert.equals 200, status
    assert.truthy body\find("ads.com", 1, true)
    assert.falsy body\find("other.com", 1, true)

  it "ignore les verdicts allow (seulement les block)", ->
    write_recent (verdict_line MAC, "ok.com", "allow", "", 5, 100) ..
      (verdict_line MAC, "ads.com", "block", "blocklist", 1, 101)
    _, _, body = handle_refusals (req_with valid_token!), IP, MAC, make_state!
    assert.truthy body\find("ads.com", 1, true)
    assert.falsy body\find("ok.com", 1, true)

  it "sérialise qname/reason/count/ts en JSON", ->
    write_recent (verdict_line MAC, "ads.com", "block", "Matched blocklist", 3, 150)
    _, _, body = handle_refusals (req_with valid_token!), IP, MAC, make_state!
    assert.truthy body\find('"qname":"ads.com"', 1, true)
    assert.truthy body\find('"reason":"Matched blocklist"', 1, true)
    assert.truthy body\find('"count":3', 1, true)
    assert.truthy body\find('"ts":150', 1, true)

  it "échappe les caractères spéciaux JSON dans reason", ->
    write_recent (verdict_line MAC, "x.com", "block", "say \"hi\"", 1, 1)
    _, _, body = handle_refusals (req_with valid_token!), IP, MAC, make_state!
    assert.truthy body\find('say \\"hi\\"', 1, true)

  it "handle_request route GET /refusals vers handle_refusals", ->
    write_recent (verdict_line MAC, "ads.com", "block", "r", 1, 1)
    req = { path: "/refusals", method: "GET", headers: { cookie: "custos_session=#{valid_token!}" } }
    status, _, body = handle_request req, IP, MAC, make_state!
    assert.equals 200, status
    assert.truthy body\find("ads.com", 1, true)

  it "filtrage MAC insensible à la casse", ->
    write_recent (verdict_line MAC\upper!, "ads.com", "block", "r", 1, 1)
    _, _, body = handle_refusals (req_with valid_token!), IP, MAC, make_state!
    assert.truthy body\find("ads.com", 1, true)
