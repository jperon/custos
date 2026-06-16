-- tests/unit/bench/load_spec.moon
-- Tests du générateur de charge DNS : encodage de requête (pur, reparsé via
-- ipparse) et boucle de run avec un client mocké (aucun réseau réel).

floor = math.floor
load_mod = require "bench.load"
{ :encode_query, :run } = load_mod
{ parse: parse_dns } = require "ipparse.l7.dns"

describe "bench/load", ->

  describe "encode_query", ->
    it "produit une requête DNS reparsable avec le bon txid et qname", ->
      raw = encode_query 0x1234, "www.example.com", 1
      msg = parse_dns raw, 1, false
      assert.is_truthy msg
      assert.equal 0x1234, msg.header.id
      assert.equal "www.example.com", msg.questions[1].name
      assert.equal 1, msg.questions[1].qtype

    it "encode des txid distincts", ->
      a = encode_query 1, "a.com", 1
      b = encode_query 2, "a.com", 1
      assert.not_equal a, b

  describe "run", ->
    -- Client mocké : répond immédiatement avec un écho du txid envoyé.
    make_mock_client = (opts = {}) ->
      sent = {}
      pending = {}
      {
        send: (raw) =>
          txid = raw\byte(1) * 256 + raw\byte(2)
          sent[#sent + 1] = txid
          pending[#pending + 1] = txid unless opts.drop
          true
        poll_response: =>
          return nil unless #pending > 0
          txid = table.remove pending, 1
          -- réponse minimale : 2 octets de txid suffisent au corrélateur
          string.char floor(txid / 256), txid % 256
        close: => nil
        _sent: sent
      }

    it "agrège qps/sent/received et latences avec un client qui répond", ->
      r = run {
        max_queries: 5
        duration: 0
        domains: { "a.com", "b.com" }
        client_factory: -> make_mock_client!
      }
      assert.equal 5, r.sent
      assert.equal 5, r.received
      assert.equal 0, r.dropped
      assert.is_number r.p50
      assert.is_number r.qps

    it "s'arrête sur la durée (now injecté) en mode rate", ->
      -- now avance de 0.5 s par appel : la borne de durée (1 s) est franchie vite.
      t = 0
      fake_now = ->
        t += 0.5
        t
      r = run {
        max_queries: 1000000
        duration: 1
        rate: 100
        domains: { "a.com" }
        now: fake_now
        timeout_ms: 0
        client_factory: -> make_mock_client!
      }
      assert.is_true r.sent < 1000000
      assert.is_number r.qps

    it "comptabilise les pertes quand le client ne répond pas", ->
      r = run {
        max_queries: 3
        duration: 0
        timeout_ms: 5
        domains: { "a.com" }
        client_factory: -> make_mock_client drop: true
      }
      assert.equal 3, r.sent
      assert.equal 0, r.received
      assert.equal 3, r.dropped
