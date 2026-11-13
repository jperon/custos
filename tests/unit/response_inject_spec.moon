-- tests/unit/response_inject_spec.moon
-- Couvre le noyau d'injection nft partagé worker_responses ⇄ doh/query.

package.loaded["config"] or= {
  dns: { ttl_grace: { grace: 600, min: 60, max: 2592000 } }
  nft: { ip_timeout: "2m", add_failure_policy: "fail-closed" }
}

ri = require "response_inject"

-- Fabrique une fonction d'ajout nft groupée factice qui enregistre ses appels.
-- Contrat (cf. nft_queue.add_ip4_many) : reçoit la liste des adresses et rend
-- le nombre d'adresses acceptées.
make_add = (result=true) ->
  calls = {}
  fn = (key, addrs, rule_id, timeout, corr) ->
    calls[#calls + 1] = { :key, :addrs, :rule_id, :timeout, :corr }
    if result then #addrs else 0
  fn, calls

-- Adresses d'un appel (pratique pour les assertions).
dest_of = (call) -> table.concat call.addrs, " "

mac_valid = (m) -> m and m != "unknown" and m != "00:00:00:00:00:00"

describe "response_inject.rr_timeout", ->
  it "applique grace et borne dans [min, max]", ->
    str, sec = ri.rr_timeout 100
    assert.equals 700, sec        -- 100 + 600 grace
    assert.equals "700s", str

  it "borne au minimum pour un TTL nul", ->
    _, sec = ri.rr_timeout 0
    assert.equals 600, sec        -- 0 + 600, ≥ min 60

  it "TTL négatif traité comme 0", ->
    _, sec = ri.rr_timeout -5
    assert.equals 600, sec

describe "response_inject.detect_wildcards", ->
  it "détecte from_users sans to_domain* (wildcard d'auth)", ->
    ids = ri.detect_wildcards {
      { rule_id: "r_wild", conditions: { { name: "from_users" } } }
    }
    assert.same { "r_wild" }, ids

  it "ignore une règle from_users AVEC to_domains", ->
    ids = ri.detect_wildcards {
      { rule_id: "r_scoped", conditions: { { name: "from_users" }, { name: "to_domains" } } }
    }
    assert.same {}, ids

  it "détecte aussi from_userlists", ->
    ids = ri.detect_wildcards {
      { rule_id: "r_wl", conditions: { { name: "from_userlists" } } }
    }
    assert.same { "r_wl" }, ids

  it "ignore une règle sans condition d'auth", ->
    ids = ri.detect_wildcards {
      { rule_id: "r_net", conditions: { { name: "from_net" } } }
    }
    assert.same {}, ids

describe "response_inject.inject", ->
  base_opts = (over) ->
    add_ip4, c4 = make_add true
    add_mac4, cm4 = make_add true
    add_ip6, c6 = make_add true
    add_mac6, cm6 = make_add true
    opts = {
      client_addr:  (fam) -> fam == "ipv4" and "10.0.0.1" or "fd00::1"
      client_mac:   "aa:bb:cc:dd:ee:ff"
      user:         nil
      rule_id:      "r_test"
      wildcard_ids: {}
      ack_corr:     "corr"
      inject_nft:   true
      :mac_valid
      add_ip:  { ipv4: add_ip4, ipv6: add_ip6 }
      add_mac: { ipv4: add_mac4, ipv6: add_mac6 }
    }
    if over
      for k, v in pairs over
        opts[k] = v
    opts, { :c4, :cm4, :c6, :cm6 }

  it "no-op comptable si inject_nft=false", ->
    opts = base_opts { inject_nft: false }
    res = ri.inject { { family: "ipv4", addr: "1.2.3.4", ttl: 60 } }, opts
    assert.equals 0, res.records_to_add
    assert.is_false res.success_any

  it "injecte A (ip4 + mac4), compte records_to_add et ip_count", ->
    opts, calls = base_opts!
    res = ri.inject { { family: "ipv4", addr: "1.2.3.4", ttl: 60 } }, opts
    assert.equals 1, res.records_to_add
    assert.equals 1, res.ip_count
    assert.is_true res.success_any
    assert.equals "1.2.3.4", dest_of calls.c4[1]
    assert.equals "1.2.3.4", dest_of calls.cm4[1]

  it "8 A d'un même timeout → une ligne par set (ip4 + mac4), 2 appels", ->
    opts, calls = base_opts!
    answers = [ { family: "ipv4", addr: "1.2.3.#{i}", ttl: 60 } for i = 1, 8 ]
    res = ri.inject answers, opts
    assert.equals 8, res.records_to_add
    assert.equals 8, res.ip_count
    assert.is_true res.success_any
    -- Une insertion groupée par set : le set de la règle (IP client) et le set
    -- MAC du client, au lieu d'une ligne par enregistrement.
    assert.equals 1, #calls.c4
    assert.equals 8, #calls.c4[1].addrs
    assert.equals "1.2.3.1", calls.c4[1].addrs[1]
    assert.equals "1.2.3.8", calls.c4[1].addrs[8]
    assert.equals 1, #calls.cm4
    assert.equals 8, #calls.cm4[1].addrs

  it "timeouts distincts → une insertion groupée par timeout et par set", ->
    opts, calls = base_opts!
    answers = {
      { family: "ipv4", addr: "1.2.3.1", ttl: 0 }
      { family: "ipv4", addr: "1.2.3.2", ttl: 0 }
      { family: "ipv4", addr: "1.2.3.3", ttl: 3600 }
    }
    ri.inject answers, opts
    assert.equals 2, #calls.c4
    assert.equals 2, #calls.c4[1].addrs
    assert.equals 1, #calls.c4[2].addrs
    assert.equals "600s", calls.c4[1].timeout
    assert.equals "4200s", calls.c4[2].timeout

  it "client_addr nil → addr listée dans no_v4, mac quand même injectée", ->
    opts, calls = base_opts { client_addr: (fam) -> fam == "ipv6" and "fd00::1" or nil }
    res = ri.inject { { family: "ipv4", addr: "9.9.9.9", ttl: 60 } }, opts
    assert.equals 0, res.records_to_add
    assert.same { "9.9.9.9" }, res.no_v4
    assert.equals 1, #calls.cm4          -- mac injectée malgré l'absence d'IP client

  it "échec d'insertion IP → success_any false mais records_to_add compté", ->
    add_ip4_fail = make_add false
    add_mac4_fail = make_add false
    opts = base_opts { add_ip: { ipv4: add_ip4_fail, ipv6: make_add true }, add_mac: { ipv4: add_mac4_fail, ipv6: make_add true } }
    res = ri.inject { { family: "ipv4", addr: "1.2.3.4", ttl: 60 } }, opts
    assert.equals 1, res.records_to_add
    assert.is_false res.success_any
    assert.equals 0, res.ip_count

  it "wildcard : injecte aussi dans les règles wildcard si user présent", ->
    wfn, wcalls = make_add true
    -- add_ip4 partagé entre rule_id principal et wildcard pour observer les 2 appels
    opts = base_opts { user: "alice", wildcard_ids: { "r_wild" }, add_ip: { ipv4: wfn, ipv6: make_add true }, add_mac: { ipv4: make_add true, ipv6: make_add true } }
    ri.inject { { family: "ipv4", addr: "1.2.3.4", ttl: 60 } }, opts
    -- 2 appels add_ip4 : règle principale + règle wildcard
    rule_ids = [ c.rule_id for c in *wcalls ]
    assert.equals 2, #wcalls
    assert.same { "r_test", "r_wild" }, rule_ids

  it "wildcard ignoré sans user", ->
    wfn, wcalls = make_add true
    opts = base_opts { user: nil, wildcard_ids: { "r_wild" }, add_ip: { ipv4: wfn, ipv6: make_add true }, add_mac: { ipv4: make_add true, ipv6: make_add true } }
    ri.inject { { family: "ipv4", addr: "1.2.3.4", ttl: 60 } }, opts
    assert.equals 1, #wcalls             -- règle principale uniquement
