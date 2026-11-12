-- tests/unit/nft_dns_queues_spec.moon
-- Rendu des règles DNS (questions/réponses) dans le ruleset bridge :
--   * une seule file  → `queue num X` (comportement historique, inchangé) ;
--   * une plage       → une règle par famille (IPv4/IPv6) avec
--     `queue to jhash <IP client> . <port client> mod N offset <première file>`,
--     pour répartir les paquets par (IP, port) du client plutôt que par couple
--     d'adresses symétrique (docs/agents/perf.md §11.1).
-- Vérifie aussi le contrat avec le template réel
-- (`nft-rules/dns-filter-bridge.nft`) : les deux ancres y sont présentes.

ffi_local = require "ffi"
fake_ctx  = ffi_local.new "char[1]"
package.loaded["ffi_defs"] = {
  ffi: ffi_local, libc: ffi_local.C, libnfq: {}
  libnft: {
    nft_ctx_new:              -> fake_ctx
    nft_run_cmd_from_buffer:  -> 0
    nft_ctx_get_error_buffer: -> nil
  }
}
package.loaded["log"] or= do
  nop = ->
  {
    log_debug: nop, log_warn: nop, log_error: nop, log_info: nop
    get_log_level_num: -> 0, set_action_prefix: nop
  }

package.loaded["filter.nft_compiler"]     or= { compile: -> nil, render: -> "", render_sets_only: -> "" }
package.loaded["filter.nft_dynamic_sets"] or= { generate_set_creation_commands: -> {} }
package.loaded["filter.rule"]             or= { compile_rules: -> { rules_metadata: {} } }

-- Config mutable rechargée à chaque test (substitute fait require "config").
make_cfg = (questions, responses) ->
  {
    nfqueue: { :questions, :responses, captive: "20", reject: "10-11",
               auth: "5", sni: "6", sip: nil, doh_vlan: nil }
    nft:     { ip_timeout: "2m", family: "bridge", table: "dns-filter-bridge",
               extra_rules: {} }
    runtime: { log_level: "INFO" }
    filter:  { rules: {} }
    doh:     { port: 8443, enabled: false }
    sni:     { placement: "residual" }
  }

load_module = (questions, responses) ->
  package.loaded["config"] = make_cfg questions, responses
  package.loaded["nft_rules"] = nil
  { :_test } = require "nft_rules"
  _test

-- Extrait dns-filter-bridge.nft : les deux ancres des règles DNS de la
-- chaîne forward (une seule file → les lignes sont générées à l'identique).
TEMPLATE = table.concat {
  "{DNS_QUESTIONS_RULES}"
  "{DNS_RESPONSES_RULES}"
}, "\n"

-- Contrat du template réel : ancres présentes, et les règles littérales ne
-- sont plus écrites en dur (c'est nft_rules qui les génère).
read_template = ->
  fh = io.open "nft-rules/dns-filter-bridge.nft", "r"
  return nil unless fh
  content = fh\read "*a"
  fh\close!
  content

describe "nft_rules : files DNS", ->
  it "une seule file (\"0\"/\"4\") : queue num à l'identique, sans jhash", ->
    _test = load_module "0", "4"
    out = _test.substitute TEMPLATE
    assert.truthy out\match 'queue num 4 comment "DNS responses'
    assert.truthy out\match 'queue num 0 comment "DNS questions'
    assert.is_nil out\match "jhash"
    assert.is_nil out\match "{DNS_QUESTIONS_RULES}"
    assert.is_nil out\match "{DNS_RESPONSES_RULES}"

  it "plage de questions (\"0-1\") : jhash ip saddr . th sport, v4 et v6", ->
    _test = load_module "0-1", "4"
    out = _test.substitute TEMPLATE
    -- une règle par famille
    assert.truthy out\match 'th dport 53 ip version 4 log level debug prefix "custos question: " counter queue to jhash ip saddr %. th sport mod 2 offset 0'
    assert.truthy out\match 'th dport 53 ip6 version 6 log level debug prefix "custos question: " counter queue to jhash ip6 saddr %. th sport mod 2 offset 0'
    -- plus de répartition par couple d'adresses
    assert.is_nil out\match "queue num 0%-1"
    assert.is_nil out\match "{DNS_QUESTIONS_RULES}"

  it "plage de réponses (\"14-15\") : jhash ip daddr . th dport, v4 et v6", ->
    _test = load_module "0-1", "14-15"
    out = _test.substitute TEMPLATE
    assert.truthy out\match 'th sport 53 ip version 4 log level debug prefix "custos response: " counter queue to jhash ip daddr %. th dport mod 2 offset 14'
    assert.truthy out\match 'th sport 53 ip6 version 6 log level debug prefix "custos response: " counter queue to jhash ip6 daddr %. th dport mod 2 offset 14'
    assert.is_nil out\match "queue num 14%-15"
    assert.is_nil out\match "{DNS_RESPONSES_RULES}"

  it "mod N = taille de la plage, offset = première file (\"2-4\" → mod 3 offset 2)", ->
    _test = load_module "2-4", "14-15"
    out = _test.substitute TEMPLATE
    assert.truthy out\match "queue to jhash ip saddr %. th sport mod 3 offset 2"
    assert.truthy out\match "queue to jhash ip6 saddr %. th sport mod 3 offset 2"
    -- les deux familles, pas de sélecteur ether type (VLAN : ethertype 0x8100)
    assert.is_nil out\match "ether type ip"
    assert.truthy out\match "ip6 version 6"

  it "conserve sélecteurs, log, compteur et commentaire de la règle existante", ->
    _test = load_module "0-1", "14-15"
    out = _test.substitute TEMPLATE
    assert.truthy out\match 'meta l4proto {udp, tcp} th dport 53 ip version 4 log level debug prefix "custos question: " counter queue to jhash'
    assert.truthy out\match 'counter queue to jhash ip6 daddr %. th dport mod 2 offset 14 comment "DNS responses → NFQUEUE"'
    assert.truthy out\match 'comment "DNS questions → NFQUEUE"'
    -- pas de bypass : comme la règle historique, un paquet sans listener est
    -- droppé (sinon il contournerait le filtre DNS)
    assert.is_nil out\match "bypass"

  it "les deux règles DNS restent ordonnées questions puis réponses", ->
    _test = load_module "0-1", "14-15"
    out = _test.substitute TEMPLATE
    q_pos = out\find "DNS questions"
    r_pos = out\find "DNS responses"
    assert.truthy q_pos
    assert.truthy r_pos
    assert.is_true q_pos < r_pos

  it "liste discontinue (\"0,2\") : deux queue num, jamais de faux jhash", ->
    -- `mod N offset premier` ne couvrirait que [0,1] : la file 2 serait privée
    -- de ses paquets. Chaque segment contigu devient donc sa propre règle.
    _test = load_module "0,2", "4"
    out = _test.substitute TEMPLATE
    assert.truthy out\match 'counter queue num 0 comment "DNS questions'
    assert.truthy out\match 'counter queue num 2 comment "DNS questions'
    assert.is_nil out\match "jhash"

  it "génère bien le bloc v4 puis v6 dans l'ordre (questions)", ->
    _test = load_module "0-1", "4"
    block = _test.dns_queue_rules "0-1", "questions"
    v4 = block\find "ip version 4"
    v6 = block\find "ip6 version 6"
    assert.truthy v4
    assert.truthy v6
    assert.is_true v4 < v6
    assert.truthy block\match "^    meta l4proto"

  it "template réel : les deux ancres sont présentes et remplacées", ->
    content = read_template!
    assert.truthy content, "nft-rules/dns-filter-bridge.nft introuvable (cwd = racine du projet ?)"
    assert.truthy content\match "{DNS_QUESTIONS_RULES}"
    assert.truthy content\match "{DNS_RESPONSES_RULES}"
    _test = load_module "0-1", "14-15"
    out = _test.substitute content
    assert.is_nil out\match "{DNS_QUESTIONS_RULES}"
    assert.is_nil out\match "{DNS_RESPONSES_RULES}"
    assert.truthy out\match "queue to jhash ip saddr %. th sport mod 2 offset 0"
    assert.truthy out\match "queue to jhash ip daddr %. th dport mod 2 offset 14"
