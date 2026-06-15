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

write_recent = (lines) ->
  os.execute "mkdir -p '#{DIR}'"
  fh = io.open "#{DIR}/recent-blocks.tsv", "w"
  fh\write lines
  fh\close!

describe "handle_refusals", ->
  after_each ->
    os.remove "#{DIR}/recent-blocks.tsv"

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
    write_recent "#{MAC}\tads.com\tblocklist\t2\t100\n11:22:33:44:55:66\tother.com\tr\t1\t101\n"
    status, _, body = handle_refusals (req_with valid_token!), IP, MAC, make_state!
    assert.equals 200, status
    assert.truthy body\find("ads.com", 1, true)
    assert.falsy body\find("other.com", 1, true)

  it "sérialise qname/reason/count/ts en JSON", ->
    write_recent "#{MAC}\tads.com\tMatched blocklist\t3\t150\n"
    _, _, body = handle_refusals (req_with valid_token!), IP, MAC, make_state!
    assert.truthy body\find('"qname":"ads.com"', 1, true)
    assert.truthy body\find('"reason":"Matched blocklist"', 1, true)
    assert.truthy body\find('"count":3', 1, true)
    assert.truthy body\find('"ts":150', 1, true)

  it "échappe les caractères spéciaux JSON dans reason", ->
    write_recent "#{MAC}\tx.com\tsay \"hi\"\t1\t1\n"
    _, _, body = handle_refusals (req_with valid_token!), IP, MAC, make_state!
    assert.truthy body\find('say \\"hi\\"', 1, true)

  it "handle_request route GET /refusals vers handle_refusals", ->
    write_recent "#{MAC}\tads.com\tr\t1\t1\n"
    req = { path: "/refusals", method: "GET", headers: { cookie: "custos_session=#{valid_token!}" } }
    status, _, body = handle_request req, IP, MAC, make_state!
    assert.equals 200, status
    assert.truthy body\find("ads.com", 1, true)

  it "filtrage MAC insensible à la casse", ->
    write_recent "#{MAC\upper!}\tads.com\tr\t1\t1\n"
    _, _, body = handle_refusals (req_with valid_token!), IP, MAC, make_state!
    assert.truthy body\find("ads.com", 1, true)
