# dns_strip contextuel à la chaîne CNAME — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stripper un type de RR (ex. AAAA) non seulement sur la question d'un domaine buggé, mais aussi sur les requêtes **terminales** que les résolveurs (systemd-resolved) émettent en suivant eux-mêmes la chaîne CNAME — sans jamais stripper les usages **directs légitimes** de ces noms terminaux.

**Architecture :** Quand `worker_responses` strippe la réponse d'un domaine buggé (règle `dns_strip` avec `follow_cname: true`), il enregistre les **noms cibles CNAME** de la chaîne dans une table à TTL court hébergée par le worker partagé `mac_learner` (process unique, donc correct quel que soit le fan-out `nfqueue.responses`). À chaque réponse ultérieure, `worker_responses` interroge cette table par le nom de question ; si le nom y figure (donc atteint récemment via une chaîne buggée), il applique le strip. Un nom interrogé **sans** contexte de chaîne récent n'est jamais strippé → usages directs préservés.

**Tech Stack :** MoonScript → LuaJIT, FFI (libc, pipes, sockets Unix), nftables (inchangé ici), busted (tests unitaires), homelab libvirt (e2e).

## Global Constraints

- **Jamais `class`/`extends`/`end`/`local`/`require "moon"`** — MoonScript pur, code compilé indépendant (cf. AGENTS.md « Interdictions absolues »).
- **Chaque `.moon` doit être compilé** vers son `.lua` jumeau : `moonc -o lua/<path>.lua src/<path>.moon`. Ne **jamais** laisser un `.lua` périmé sous `src/` (cf. mémoire `feedback-stale-src-lua`).
- **Appels de fonctions de module avec `.`**, jamais `\` (sinon la table passe en 1ᵉʳ argument).
- **Concaténation en boucle** : accumuler dans une table + `table.concat`, jamais `..=`.
- **Hot-path** : pas de `require` par paquet (mémoïser à la construction) ; garder les logs DEBUG derrière `log.level_enabled` si thunk alloué par paquet.
- **Definition of Done** (AGENTS.md) : tout code couvert par des tests ; doc à jour (`AGENTS.md`, `doc/CONFIG.md`) ; `make test` **et** `make test-e2e` à 100 % ; `make coverage` vérifié en fin de chantier.
- **Opt-in** : la feature ne s'active que si une règle porte `dns_strip.follow_cname = true`. Sans cela : **aucun** pipe créé, **aucune** requête IPC, **zéro** coût (parité de comportement avec l'existant).
- Fichiers temporaires uniquement sous `./tmp/`.

**Format du message learn (pipe `strip_learn`)** : 10 octets = `name_hash` (8 octets, FNV-1a 64 bits big-endian) + `rr_code` (uint16 big-endian, code DNS du type à stripper, ex. 28 = AAAA).

**Protocole requête (socket Unix `mac_learner`)** : `"strip:<name>\n"` → `"<rr_code>\n"` (ex. `"28\n"`) si le nom est une cible récente, sinon `"unknown\n"`.

---

### Task 1 : Module codec partagé `strip_codec`

Module pur partagé par l'émetteur (`worker_responses`), le store (`mac_learner`) et le client IPC. Garantit que le **même** hash de nom est calculé partout.

**Files:**
- Create: `src/strip_codec.moon`
- Compile: `lua/strip_codec.lua`
- Test: `tests/unit/strip_codec_spec.moon`

**Interfaces:**
- Produces:
  - `normalize(name) -> string` — minuscule, point(s) final/aux retiré(s).
  - `name_hash(name) -> string` — 8 octets (FNV-1a 64 bits, big-endian) du nom normalisé.
  - `encode(name, rr_code) -> string` — message learn 10 octets (`name_hash(name)` + uint16 BE `rr_code`).
  - `decode(msg) -> hash8, rr_code` — extrait les 8 octets de hash bruts + le `rr_code` ; `nil` si `#msg < 10`.
  - `STRIP_MSG_SIZE = 10` (constante exportée).

- [ ] **Step 1 : Écrire le test qui échoue**

```moonscript
-- tests/unit/strip_codec_spec.moon
codec = require "strip_codec"

describe "strip_codec", ->
  it "normalise (casse + point final)", ->
    assert.are.equal codec.normalize("ATM.Outlook.MIRA.tm."), "atm.outlook.mira.tm"

  it "hash stable et identique pour des formes équivalentes", ->
    a = codec.name_hash "atm.outlook.mira.tm.svc.cloud.microsoft"
    b = codec.name_hash "ATM.outlook.mira.tm.svc.cloud.microsoft."
    assert.are.equal 8, #a
    assert.are.equal a, b

  it "hash distinct pour des noms différents", ->
    assert.are_not.equal codec.name_hash("a.example"), codec.name_hash("b.example")

  it "encode/decode round-trip", ->
    msg = codec.encode "atm.outlook.mira.tm.svc.cloud.microsoft", 28
    assert.are.equal codec.STRIP_MSG_SIZE, #msg
    hash8, rr = codec.decode msg
    assert.are.equal codec.name_hash("atm.outlook.mira.tm.svc.cloud.microsoft"), hash8
    assert.are.equal 28, rr

  it "decode renvoie nil sur message tronqué", ->
    assert.is_nil (codec.decode "short")
```

- [ ] **Step 2 : Lancer le test (échec attendu)**

Run: `busted tests/unit/strip_codec_spec.moon`
Expected: FAIL (`module 'strip_codec' not found`).

- [ ] **Step 3 : Implémenter le module**

```moonscript
-- src/strip_codec.moon
-- Codec partagé pour la table de cibles de strip CNAME (mac_learner).
-- name_hash : FNV-1a 64 bits sur le nom normalisé, sérialisé en 8 octets BE.
-- Le hash (au lieu du nom variable) garde des messages pipe à taille fixe.

ffi = require "ffi"

STRIP_MSG_SIZE = 10   -- 8 octets hash + 2 octets rr_code (uint16 BE)

FNV_OFFSET = 0xcbf29ce484222325ULL
FNV_PRIME  = 0x100000001b3ULL

normalize = (name) ->
  return "" unless name and name != ""
  (tostring name)\lower!\gsub "%.+$", ""

--- FNV-1a 64 bits → 8 octets big-endian.
name_hash = (name) ->
  h = FNV_OFFSET
  s = normalize name
  for i = 1, #s
    h = ffi.cast "uint64_t", bit_xor_byte(h, s\byte i)
    h = h * FNV_PRIME
  u = ffi.cast "uint64_t", h
  out = {}
  for shift = 56, 0, -8
    out[#out + 1] = string.char tonumber((u / (2ULL ^ shift)) % 256)
  table.concat out

-- xor d'un octet dans un uint64 sans dépendre de bit (qui est 32 bits).
bit_xor_byte = (h, b) ->
  lo = ffi.cast("uint64_t", h) % 256
  xored = require("bit").bxor(tonumber(lo), b)
  (ffi.cast("uint64_t", h) - lo) + xored

encode = (name, rr_code) ->
  rr = tonumber(rr_code) or 0
  name_hash(name) .. string.char(math.floor(rr / 256) % 256, rr % 256)

decode = (msg) ->
  return nil unless msg and #msg >= STRIP_MSG_SIZE
  hash8 = msg\sub 1, 8
  rr = msg\byte(9) * 256 + msg\byte(10)
  hash8, rr

{ :normalize, :name_hash, :encode, :decode, :STRIP_MSG_SIZE }
```

> **Note d'implémentation** : `bit_xor_byte` doit être défini **avant** `name_hash` dans le fichier compilé (MoonScript déclare les locals à l'usage). Réordonner si `moonc` produit un nil-call. Vérifier le hash sur LuaJIT (arithmétique `uint64_t` via FFI, pas `bit` qui est 32 bits).

- [ ] **Step 4 : Compiler et relancer**

Run: `moonc -o lua/strip_codec.lua src/strip_codec.moon && busted tests/unit/strip_codec_spec.moon`
Expected: PASS (5 succès).

- [ ] **Step 5 : Commit**

```bash
git add src/strip_codec.moon lua/strip_codec.lua tests/unit/strip_codec_spec.moon
git commit -m "feat(strip): codec partagé hash/encode pour cibles CNAME"
```

---

### Task 2 : Table de cibles de strip dans `mac_learner`

**Files:**
- Modify: `src/mac_learner.moon` (tables, `process_strip_learn`, `strip_lookup`, `start_query`, `run`, purge, exports)
- Compile: `lua/mac_learner.lua`
- Test: `tests/unit/mac_learner_strip_spec.moon`

**Interfaces:**
- Consumes: `strip_codec.decode`, `strip_codec.name_hash` (Task 1).
- Produces:
  - `process_strip_learn(msg)` — décode et stocke `strip_table[hash8] = { rr_code, deadline }`.
  - `strip_lookup(name) -> rr_code|nil` — `name_hash(name)` → entrée valide (TTL) → `rr_code`, sinon `nil` (et purge paresseuse).
  - `run(learn_rfd, ifname, vlan_learn_rfd, strip_learn_rfd)` — 4ᵉ paramètre optionnel : fd du pipe `strip_learn`.
  - Requête socket : ligne `"strip:<name>"` → `"<rr_code>\n"` ou `"unknown\n"`.

- [ ] **Step 1 : Écrire le test qui échoue**

```moonscript
-- tests/unit/mac_learner_strip_spec.moon
ml = require "mac_learner"
codec = require "strip_codec"

describe "mac_learner strip_table", ->
  it "apprend une cible et la retrouve par nom (insensible à la casse)", ->
    ml.process_strip_learn codec.encode("atm.outlook.mira.tm.svc.cloud.microsoft", 28)
    assert.are.equal 28, ml.strip_lookup "ATM.outlook.mira.tm.svc.cloud.microsoft."

  it "renvoie nil pour un nom jamais appris", ->
    assert.is_nil ml.strip_lookup "example.org"

  it "expire après le TTL", ->
    real = os.time
    ml.process_strip_learn codec.encode("ephemere.example", 28)
    os.time = -> real! + 10000
    assert.is_nil ml.strip_lookup "ephemere.example"
    os.time = real
```

- [ ] **Step 2 : Lancer le test (échec attendu)**

Run: `busted tests/unit/mac_learner_strip_spec.moon`
Expected: FAIL (`process_strip_learn` nil / non exporté).

- [ ] **Step 3 : Implémenter dans `src/mac_learner.moon`**

3a. Ajouter le require codec en tête (avec les autres `require`) :
```moonscript
strip_codec = require "strip_codec"
```

3b. Déclarer la table + TTL près de `vlan_table` (≈ ligne 67) :
```moonscript
-- strip_table : { hash8 → { rr_code, expires_epoch } }, alimenté par worker_responses
-- (cibles CNAME de chaînes buggées). Clé = hash FNV-1a du nom (cf. strip_codec).
strip_table = {}
STRIP_TTL = mac_cfg.strip_ttl or 120
```

3c. Ajouter le traitement + lookup après `vlan_lookup` (≈ ligne 158) :
```moonscript
--- Traite un message learn de cible de strip (10 octets, cf. strip_codec).
process_strip_learn = (msg) ->
  hash8, rr_code = strip_codec.decode msg
  return unless hash8
  strip_table[hash8] = { rr_code, os.time! + STRIP_TTL }

--- Recherche le rr_code à stripper pour un nom de question.
-- @treturn number|nil code DNS du type à stripper, ou nil si non cible/expiré.
strip_lookup = (name) ->
  entry = strip_table[strip_codec.name_hash name]
  return nil unless entry
  if os.time! <= entry[2]
    entry[1]
  else
    strip_table[strip_codec.name_hash name] = nil
    nil
```

3d. Dans `start_query`, après le bloc `vlan:` (≈ ligne 209), ajouter le préfixe `strip:` :
```moonscript
  -- Requête strip : "strip:<name>\n" → "<rr_code>\n" ou "unknown\n".
  strip_name = req\match "^strip:([^\n\r]+)"
  if strip_name
    rr = strip_lookup strip_name
    if rr
      resp = rr .. "\n"
      libc.send client_fd, resp, #resp, 0
    else
      libc.send client_fd, "unknown\n", 8, 0
    libc.close client_fd
    return
```

3e. `run` : 4ᵉ paramètre `strip_learn_rfd` ; câbler dans la boucle poll en miroir exact de `vlan_learn` (index suivant `vlan_idx`). Étendre `pfds` à `struct pollfd[6]` (ligne 315). Ajouter :
```moonscript
run = (learn_rfd, ifname, vlan_learn_rfd, strip_learn_rfd) ->
  ...
  pfds = ffi.new "struct pollfd[6]"
  ...
  -- (après le bloc vlan_idx)
  strip_idx = -1
  if strip_learn_rfd
    strip_idx = nfds
    pfds[strip_idx].fd     = strip_learn_rfd
    pfds[strip_idx].events = POLLIN
    nfds += 1
  ...
  strip_buf = ffi.new "uint8_t[?]", strip_codec.STRIP_MSG_SIZE
  ...
  -- dans la boucle, après le drain vlan_learn :
  if strip_idx >= 0 and bit.band(pfds[strip_idx].revents, POLLIN) ~= 0
    while true
      n = libc.read strip_learn_rfd, strip_buf, strip_codec.STRIP_MSG_SIZE
      break if n <= 0
      process_strip_learn ffi.string(strip_buf, strip_codec.STRIP_MSG_SIZE) if n == strip_codec.STRIP_MSG_SIZE
  ...
  -- dans la purge périodique, ajouter :
  for h, entry in pairs strip_table
    strip_table[h] = nil if now_epoch > entry[2]
```

3f. Exports :
```moonscript
{ :run, :process_vlan_learn, :vlan_lookup, :process_strip_learn, :strip_lookup }
```

- [ ] **Step 4 : Compiler et relancer**

Run: `moonc -o lua/mac_learner.lua src/mac_learner.moon && busted tests/unit/mac_learner_strip_spec.moon`
Expected: PASS (3 succès).

- [ ] **Step 5 : Vérifier la non-régression mac_learner**

Run: `busted tests/unit/ -p 'mac_learner.*spec'`
Expected: PASS (tous).

- [ ] **Step 6 : Commit**

```bash
git add src/mac_learner.moon lua/mac_learner.lua tests/unit/mac_learner_strip_spec.moon
git commit -m "feat(strip): table de cibles CNAME à TTL dans mac_learner"
```

---

### Task 3 : Client IPC `mac_learner_ipc.strip_target`

**Files:**
- Modify: `src/mac_learner_ipc.moon` (nouvelle fonction `strip_target`, export)
- Compile: `lua/mac_learner_ipc.lua`
- Test: `tests/unit/mac_learner_ipc_strip_spec.moon`

**Interfaces:**
- Produces : `strip_target(name) -> number|nil` — interroge le socket Unix `"strip:<name>\n"`, renvoie le `rr_code` (number) ou `nil`.

- [ ] **Step 1 : Écrire le test qui échoue** (serveur Unix bouchon, motif des specs ipc existantes)

```moonscript
-- tests/unit/mac_learner_ipc_strip_spec.moon
-- Démarre un mini-serveur Unix qui répond "28\n" à "strip:hit", "unknown\n" sinon.
ffi = require "ffi"
{ :libc } = require "ffi_defs"

SOCK = "./tmp/test_strip_ipc.sock"

start_stub = ->
  os.execute "rm -f #{SOCK}"
  -- fork un serveur trivial via socat-like en Lua n'est pas trivial ;
  -- à la place on teste la couche parsing en injectant un faux recv.
  nil

describe "mac_learner_ipc.strip_target", ->
  it "parse un rr_code numérique", ->
    ipc = require "mac_learner_ipc"
    -- Test du parseur de réponse via la fonction exposée parse_strip_resp.
    assert.are.equal 28, ipc.parse_strip_resp "28\n"
    assert.is_nil ipc.parse_strip_resp "unknown\n"
    assert.is_nil ipc.parse_strip_resp ""
```

> **Note** : pour rester unitaire et déterministe (pas de socket réel fragile), on extrait le **parseur de réponse** `parse_strip_resp` et on le teste isolément ; la boucle connect/send/recv est identique à `get_vlan` (déjà couverte e2e). Couvrir le chemin socket complet en e2e (Task 8).

- [ ] **Step 2 : Lancer le test (échec attendu)**

Run: `busted tests/unit/mac_learner_ipc_strip_spec.moon`
Expected: FAIL (`parse_strip_resp` nil).

- [ ] **Step 3 : Implémenter dans `src/mac_learner_ipc.moon`**

```moonscript
--- Parse la réponse du learner à une requête strip.
-- @treturn number|nil rr_code si numérique, nil sinon ("unknown"/vide).
parse_strip_resp = (resp) ->
  return nil unless resp and resp != ""
  id = resp\match "^(%d+)"
  id and tonumber(id) or nil

--- Retourne le rr_code à stripper pour un nom de question, ou nil.
-- Mirroir exact de get_vlan avec le préfixe "strip:".
strip_target = (name) ->
  return nil unless name and name != "" and name != "unknown"
  sock = libc.socket AF_UNIX, SOCK_STREAM, 0
  return nil unless sock >= 0
  addr = ffi.new "struct sockaddr_un"
  addr.sun_family = AF_UNIX
  ffi.copy addr.sun_path, QUERY_SOCK
  addr_len = ffi.offsetof("struct sockaddr_un", "sun_path") + #QUERY_SOCK + 1
  if libc.connect(sock, ffi.cast("struct sockaddr*", addr), addr_len) ~= 0
    libc.close sock
    return nil
  req = "strip:" .. name .. "\n"
  libc.send sock, req, #req, 0
  buf = ffi.new "char[64]"
  n = libc.recv sock, buf, 63, 0
  libc.close sock
  return nil if n <= 0
  parse_strip_resp ffi.string buf, n
```

Export :
```moonscript
{ :get_mac, :get_vlan, :mac_from_eui64, :strip_target, :parse_strip_resp }
```

- [ ] **Step 4 : Compiler et relancer**

Run: `moonc -o lua/mac_learner_ipc.lua src/mac_learner_ipc.moon && busted tests/unit/mac_learner_ipc_strip_spec.moon`
Expected: PASS.

- [ ] **Step 5 : Commit**

```bash
git add src/mac_learner_ipc.moon lua/mac_learner_ipc.lua tests/unit/mac_learner_ipc_strip_spec.moon
git commit -m "feat(strip): mac_learner_ipc.strip_target (requête par nom)"
```

---

### Task 4 : Option `follow_cname` de l'action `dns_strip`

**Files:**
- Modify: `src/filter/actions/dns_strip.moon`
- Compile: `lua/filter/actions/dns_strip.lua`
- Test: `tests/unit/filter/dns_strip_spec.moon` (créer si absent ; sinon étendre le spec existant)

**Interfaces:**
- Produces : quand `rule.dns_strip.follow_cname == true`, l'`on_response` pose `ctx.chain_strip_rr = <rr_code numérique>` (en plus du strip déjà effectué). `worker_responses` lit ce champ pour enregistrer les endpoints. Sans `follow_cname`, le champ reste absent (comportement inchangé).

- [ ] **Step 1 : Écrire le test qui échoue**

```moonscript
-- tests/unit/filter/dns_strip_spec.moon
factory = require("filter.actions.dns_strip").factory
dns_mod = require "ipparse.l7.dns"

describe "dns_strip follow_cname", ->
  it "pose ctx.chain_strip_rr quand follow_cname=true", ->
    act = factory({})({ dns_strip: { rr_type: "AAAA", follow_cname: true }, description: "x" })
    ctx = { dns_raw: "fake", reason: "r" }
    act.on_response ctx
    assert.are.equal dns_mod.types.AAAA, ctx.chain_strip_rr

  it "ne pose rien sans follow_cname", ->
    act = factory({})({ dns_strip: { rr_type: "AAAA" }, description: "x" })
    ctx = { dns_raw: "fake", reason: "r" }
    act.on_response ctx
    assert.is_nil ctx.chain_strip_rr
```

- [ ] **Step 2 : Lancer le test (échec attendu)**

Run: `busted tests/unit/filter/dns_strip_spec.moon`
Expected: FAIL (`chain_strip_rr` nil dans le 1ᵉʳ cas).

- [ ] **Step 3 : Implémenter** — dans `_factory`, après calcul de `rr_type`, dériver le code et le flag, puis le poser dans `on_response` :

```moonscript
_factory = (cfg) ->
  (rule) ->
    rr_type = "A"
    if rule.dns_strip and rule.dns_strip.rr_type
      rr_type = rule.dns_strip.rr_type
    follow_cname = not not (rule.dns_strip and rule.dns_strip.follow_cname)
    dns_mod  = require "ipparse.l7.dns"   -- mémoïsé à la construction (hors hot-path)
    rr_code  = dns_mod.types[rr_type]

    {
      capabilities: { worker: true, nft: false }
      eval: (req) -> true, "Strip #{rr_type} by rule: #{rule.description or '?'}"
      on_response: (ctx) ->
        stripped = strip_dns_rr ctx.dns_raw, rr_type
        if stripped != ctx.dns_raw
          stripped = add_ede_modified(stripped, ctx.reason) or stripped
          ctx.dns_raw  = clear_ad_bit stripped
          ctx.modified = true
        ctx.skip_nft     = true
        ctx.action_label = "response_strip_#{rr_type}"
        ctx.chain_strip_rr = rr_code if follow_cname and rr_code
      compile_nft: ->
      verdict: -> "accept"
    }
```

Mettre à jour `_schema.arg_fields` pour exposer `follow_cname` (booléen) dans la webui :
```moonscript
arg_fields: {
  { name: "rr_type", label: "Type RR", type: "enum", values: {"A","AAAA","CNAME","MX","TXT"}, required: true, default: "A" }
  { name: "follow_cname", label: "Suivre la chaîne CNAME", type: "bool", default: false }
}
```

- [ ] **Step 4 : Compiler et relancer**

Run: `moonc -o lua/filter/actions/dns_strip.lua src/filter/actions/dns_strip.moon && busted tests/unit/filter/dns_strip_spec.moon`
Expected: PASS (2 succès).

- [ ] **Step 5 : Commit**

```bash
git add src/filter/actions/dns_strip.moon lua/filter/actions/dns_strip.lua tests/unit/filter/dns_strip_spec.moon
git commit -m "feat(strip): option follow_cname expose chain_strip_rr"
```

---

### Task 5 : Émission + application dans `worker_responses`

Cœur de la feature. Deux helpers **purs** testables, branchés dans `finalize_a`.

**Files:**
- Modify: `src/worker_responses.moon`
- Compile: `lua/worker_responses.lua`
- Test: `tests/unit/worker_responses_chain_strip_spec.moon`

**Interfaces:**
- Consumes : `dns_classify.cname_targets` (déjà requis), `strip_codec.encode` (Task 1), `mac_learner_ipc.strip_target` (Task 3), `dns_ede.strip_dns_rr`/`add_ede_modified`/`clear_ad_bit`.
- Produces (helpers exportés pour tests) :
  - `record_chain_targets(dns, dns_raw, rr_code, send_fn)` — pour chaque cible CNAME, `send_fn(strip_codec.encode(target, rr_code))`.
  - `maybe_dynamic_strip(qname, dns_raw, lookup_fn) -> dns_raw2, modified` — si `lookup_fn(qname)` renvoie un rr_code, applique `strip_dns_rr` (+ EDE + clear AD) ; sinon retourne l'entrée inchangée. Inclut un cache module-local `strip_query_cache[qname]` (TTL `os.time` + 2 s, positif **et** négatif) pour borner les RTT.

**État module + gating** : `worker_responses.run` reçoit deux nouveaux éléments dans `fds`/params :
- `strip_learn_wfd` (fd d'écriture du pipe) ;
- `chain_strip_enabled` (booléen calculé par `main.moon`, Task 6).
Stockés en upvalues module ; les helpers ne s'activent que si `chain_strip_enabled`.

- [ ] **Step 1 : Écrire le test qui échoue**

```moonscript
-- tests/unit/worker_responses_chain_strip_spec.moon
wr = require "worker_responses"
codec = require "strip_codec"
dns_ede = require "dns_ede"
dns_mod = require "ipparse.l7.dns"

-- Construit une réponse AAAA pour qname avec une chaîne CNAME → target portant un AAAA.
build_resp = (qname, target) ->
  -- réutilise un helper de test existant ou forge via dns_ede ; ici on s'appuie
  -- sur une fixture wire pré-enregistrée office365 (cf. tests/fixtures).
  require("tests.fixtures.office365_aaaa") qname, target

describe "worker_responses chain strip", ->
  it "record_chain_targets émet un message encodé par cible CNAME", ->
    sent = {}
    dns_raw = build_resp "smtp.office365.com", "atm.outlook.mira.tm.svc.cloud.microsoft"
    dns = dns_mod.parse dns_raw, 1, false
    wr.record_chain_targets dns, dns_raw, dns_mod.types.AAAA, (m) -> sent[#sent+1] = m
    -- au moins la cible terminale est encodée
    want = codec.encode "atm.outlook.mira.tm.svc.cloud.microsoft", dns_mod.types.AAAA
    found = false
    for m in *sent
      found = true if m == want
    assert.is_true found

  it "maybe_dynamic_strip strippe quand lookup renvoie un rr_code", ->
    dns_raw = build_resp "atm.outlook.mira.tm.svc.cloud.microsoft", nil  -- réponse AAAA directe
    out, modified = wr.maybe_dynamic_strip "atm.outlook.mira.tm.svc.cloud.microsoft", dns_raw, (-> dns_mod.types.AAAA)
    assert.is_true modified
    assert.are_not.equal dns_raw, out
    -- plus aucun AAAA dans la sortie
    parsed = dns_mod.parse out, 1, false
    n = 0
    for rr in *parsed.answers
      n += 1 if rr.rtype == dns_mod.types.AAAA
    assert.are.equal 0, n

  it "maybe_dynamic_strip ne touche rien quand lookup renvoie nil", ->
    dns_raw = build_resp "atm.outlook.mira.tm.svc.cloud.microsoft", nil
    out, modified = wr.maybe_dynamic_strip "legit.example", dns_raw, (-> nil)
    assert.is_false modified
    assert.are.equal dns_raw, out
```

> **Fixture** : créer `tests/fixtures/office365_aaaa.moon` exportant une fonction qui forge (ou rejoue) un message DNS wire : chaîne CNAME `qname → … → target` plus, si `target`, des RR `AAAA` sur `target`. S'appuyer sur `dns_ede`/`ipparse.l7.dns` pour la construction, ou capturer un `.bin` via `kdig +tcp` et le charger. Garder le helper minimal et déterministe.

- [ ] **Step 2 : Lancer le test (échec attendu)**

Run: `busted tests/unit/worker_responses_chain_strip_spec.moon`
Expected: FAIL (`record_chain_targets`/`maybe_dynamic_strip` nil).

- [ ] **Step 3 : Implémenter les helpers + branchements**

3a. Requires mémoïsés en tête de `worker_responses.moon` :
```moonscript
strip_codec = require "strip_codec"
mac_ipc     = require "mac_learner_ipc"
```
(`dns_classify`, `strip_dns_rr`, `add_ede_modified`, `clear_ad_bit` sont déjà disponibles ; vérifier les imports de `dns_ede` en tête et compléter si besoin.)

3b. Upvalues module + cache :
```moonscript
chain_strip_enabled = false
strip_learn_wfd     = nil
strip_query_cache   = {}   -- { qname → { rr_code|false, expires_epoch } }
STRIP_QUERY_TTL     = 2
```

3c. Helpers purs (près des autres fonctions de module) :
```moonscript
--- Émet un message learn par cible CNAME de la réponse.
-- @tparam table  dns     Message DNS parsé (answers).
-- @tparam string dns_raw Payload brut (décompression des noms).
-- @tparam number rr_code Type DNS à stripper (ex. 28).
-- @tparam function send_fn Reçoit chaque message encodé (écriture pipe en prod).
record_chain_targets = (dns, dns_raw, rr_code, send_fn) ->
  return unless dns and dns_raw and rr_code and send_fn
  for target in *dns_classify.cname_targets dns, dns_raw, 1
    send_fn strip_codec.encode target, rr_code

--- Applique un strip dynamique si qname est une cible apprise.
-- @treturn string dns_raw (modifié ou non), boolean modified
maybe_dynamic_strip = (qname, dns_raw, lookup_fn) ->
  return dns_raw, false unless qname and dns_raw and lookup_fn
  now = os.time!
  cached = strip_query_cache[qname]
  rr_code = if cached and now <= cached[2]
    cached[1]
  else
    v = lookup_fn qname
    strip_query_cache[qname] = { v or false, now + STRIP_QUERY_TTL }
    v
  return dns_raw, false unless rr_code
  stripped = strip_dns_rr dns_raw, rr_code
  return dns_raw, false if stripped == dns_raw
  stripped = add_ede_modified(stripped, "Strip by CNAME chain context") or stripped
  (clear_ad_bit stripped), true
```

3d. Branchement **émission** dans `finalize_a`, juste après le re-parse `answers_dns` (≈ ligne 480) :
```moonscript
  if chain_strip_enabled and strip_learn_wfd and resp_ctx.chain_strip_rr
    record_chain_targets answers_dns, dns_raw, resp_ctx.chain_strip_rr,
      (m) -> libc.write strip_learn_wfd, m, #m
```

3e. Branchement **application** dans `finalize_a`, juste **avant** le re-parse (entre lignes 476 et 478), pour que l'injection nft et le patch voient la réponse strippée :
```moonscript
  if chain_strip_enabled and not resp_ctx.chain_strip_rr
    qname0 = dns_msg.questions[1] and dns_msg.questions[1].name
    new_raw, dyn_mod = maybe_dynamic_strip qname0, dns_raw, mac_ipc.strip_target
    if dyn_mod
      dns_raw          = new_raw
      payload_modified = true
      resp_ctx.action_label or= "response_chain_strip"
```

3f. `run` : accepter `chain_strip_enabled` et `strip_learn_wfd` (via `fds` ou paramètres ; suivre la signature existante de `run q_num, fds, rules_metadata, ...`). Affecter les upvalues au démarrage :
```moonscript
chain_strip_enabled = fds.chain_strip_enabled or false
strip_learn_wfd     = fds.strip_learn_wfd
```

- [ ] **Step 4 : Compiler et relancer le spec**

Run: `moonc -o lua/worker_responses.lua src/worker_responses.moon && busted tests/unit/worker_responses_chain_strip_spec.moon`
Expected: PASS (3 succès).

- [ ] **Step 5 : Non-régression worker_responses**

Run: `busted tests/unit/ -p 'worker_responses.*spec'`
Expected: PASS.

- [ ] **Step 6 : Commit**

```bash
git add src/worker_responses.moon lua/worker_responses.lua tests/unit/worker_responses_chain_strip_spec.moon tests/fixtures/office365_aaaa.moon
git commit -m "feat(strip): worker_responses émet et applique le strip contextuel CNAME"
```

---

### Task 6 : Câblage superviseur (`main.moon`)

**Files:**
- Modify: `src/main.moon` (pipe `strip_learn`, scan d'activation, fork mac_learner + responses, close fds)
- Compile: `lua/main.lua`
- Test: couverture e2e (Task 8) + un test unitaire du scan d'activation.

**Interfaces:**
- Produces : pipe `strip_learn` créé **uniquement** si `chain_strip_enabled`. `mac_learner.run` reçoit `strip_learn.rfd` ; chaque `worker_responses` reçoit `{ strip_learn_wfd: strip_learn.wfd, chain_strip_enabled: true }` dans `fds`.
- `chain_strip_active(config) -> boolean` — vrai si une règle `filter.rules` a `dns_strip.follow_cname == true`.

- [ ] **Step 1 : Écrire le test qui échoue**

```moonscript
-- tests/unit/main_chain_strip_spec.moon
main = require "main"
describe "chain_strip_active", ->
  it "vrai si une règle a follow_cname", ->
    cfg = { filter: { rules: { { dns_strip: { follow_cname: true } } } } }
    assert.is_true main.chain_strip_active cfg
  it "faux sinon", ->
    cfg = { filter: { rules: { { dns_strip: { rr_type: "AAAA" } } } } }
    assert.is_false main.chain_strip_active cfg
```

> Si `main` n'expose pas de table requérable proprement (effets de bord au require), extraire `chain_strip_active` dans un petit module `src/lib/chain_strip.moon` et le tester là, puis l'appeler depuis `main`. Choisir cette voie si `require "main"` exécute le superviseur.

- [ ] **Step 2 : Lancer (échec attendu)** — `busted tests/unit/main_chain_strip_spec.moon` → FAIL.

- [ ] **Step 3 : Implémenter**

3a. `chain_strip_active` (dans `main.moon` ou `src/lib/chain_strip.moon`) :
```moonscript
chain_strip_active = (config) ->
  rules = config and config.filter and config.filter.rules
  return false unless type(rules) == "table"
  for r in *rules
    return true if r.dns_strip and r.dns_strip.follow_cname
  false
```

3b. Dans `create_pipes` (≈ ligne 115), ajouter conditionnellement (ou toujours créer mais ne câbler que si actif — préférer conditionnel pour zéro coût) :
```moonscript
    strip_learn: create_pipe "strip_learn"
```
N'appeler la création que si `chain_strip_active config` ; sinon laisser `pipes.strip_learn = nil`.

3c. Au fork `mac_learner` (≈ ligne 274), passer le 4ᵉ argument :
```moonscript
require("mac_learner").run pipes.learn.rfd, bridge_ifname, pipes.vlan_learn.rfd,
  (pipes.strip_learn and pipes.strip_learn.rfd)
```

3d. Au fork des `worker_responses` (≈ ligne 423-429), injecter dans `fds` :
```moonscript
strip_learn_wfd:     (pipes.strip_learn and pipes.strip_learn.wfd)
chain_strip_enabled: (pipes.strip_learn ~= nil)
```

3e. `close_supervisor_fds` (≈ ligne 168) : fermer `pipes.strip_learn.rfd`/`.wfd` si présent (miroir de `vlan_learn`/`learn`).

- [ ] **Step 4 : Compiler et relancer** — `moonc -o lua/main.lua src/main.moon && busted tests/unit/main_chain_strip_spec.moon` → PASS.

- [ ] **Step 5 : Commit**

```bash
git add src/main.moon lua/main.lua tests/unit/main_chain_strip_spec.moon
git commit -m "feat(strip): câblage superviseur pipe strip_learn (opt-in)"
```

---

### Task 7 : Documentation + config

**Files:**
- Modify: `AGENTS.md` (section dns_strip / système de conditions)
- Modify: `doc/CONFIG.md` (option `dns_strip.follow_cname`, clé `mac_learner.strip_ttl`)
- Modify: la config de la règle office365 (dépôt sync `base/config.moon` ou config routeur — confirmer avec le mainteneur)
- Create: `memory/project-dns-strip-cname-chain.md` (+ ligne dans `MEMORY.md`)

- [ ] **Step 1 : AGENTS.md** — sous « Modules DoH » ou une nouvelle sous-section « Strip DNS contextuel à la chaîne CNAME », documenter : le problème (résolveurs qui chasent les CNAME en requêtes séparées → la question terminale échappe à `to_domains`), la solution (table de cibles à TTL dans `mac_learner`, alimentée par `worker_responses`, opt-in via `dns_strip.follow_cname`), le contrat (usages directs hors chaîne non strippés), et le format des messages (`strip_codec`, 10 octets ; requête `"strip:<name>"`).

- [ ] **Step 2 : doc/CONFIG.md** — ajouter :
  - `filter.rules[].dns_strip.follow_cname` (bool, défaut false) — strip aussi les requêtes terminales de la chaîne CNAME (cibles apprises dynamiquement, TTL court).
  - `mac_learner.strip_ttl` (number, défaut 120) — durée de vie (s) d'une cible CNAME apprise.

- [ ] **Step 3 : Activer sur la règle office365** — ajouter `follow_cname: true` au bloc `dns_strip` de la règle « Bugfix smtp office365 (IPv6) ». **Ne pas** ajouter `mira.tm.svc.cloud.microsoft` à `to_domains` (la feature rend cet ajout inutile et préserve les usages directs).

- [ ] **Step 4 : Mémoire** — créer `memory/project-dns-strip-cname-chain.md` (type project) résumant la feature, le contrat et les modules, avec liens `[[…]]` ; ajouter la ligne d'index dans `MEMORY.md`.

- [ ] **Step 5 : Commit**

```bash
git add AGENTS.md doc/CONFIG.md
git commit -m "docs(strip): documente follow_cname et le strip contextuel CNAME"
```

---

### Task 8 : Validation e2e + couverture

**Files:**
- Create/Modify: un cas e2e sous `tests/e2e/` reproduisant le scénario (résolveur chasant les CNAME → question terminale strippée ; question directe hors contexte non strippée). Suivre les patterns de `tests/e2e/` et `.agents/testing.md`.

- [ ] **Step 1 : Écrire le test e2e** — sur le homelab : configurer une règle `dns_strip { rr_type: "AAAA", follow_cname: true }` sur un domaine de test à chaîne CNAME ; émettre (a) une requête sur le domaine racine, vérifier l'EDE + absence d'AAAA ; (b) une requête **directe** sur le nom terminal **après** (a), vérifier qu'elle est strippée (cible apprise) ; (c) une requête directe sur le nom terminal **sans** (a) préalable (TTL expiré / nom jamais vu), vérifier qu'elle **n'est pas** strippée.

- [ ] **Step 2 : `make test`**

Run: `make test`
Expected: `0 failed`.

- [ ] **Step 3 : `make test-e2e`** (homelab provisionné, sans relancer libvirt au préalable)

Run: `make test-e2e`
Expected: `0 failed`. Si échec : consulter `.agents/testing.md` (flaky DNS warmup connu, cf. mémoire `feedback-e2e-dns-warmup-flaky`) et distinguer régression vs flakiness.

- [ ] **Step 4 : `make coverage`** (lent — fin de chantier uniquement)

Run: `make coverage`
Expected: rapport `tmp/coverage/` ; les nouveaux modules `strip_codec`, helpers `mac_learner`/`worker_responses` couverts. Compléter les tests pour les branches non couvertes (ex. message tronqué, cache hit/miss, TTL expiré).

- [ ] **Step 5 : Commit final**

```bash
git add tests/e2e/ memory/ MEMORY.md
git commit -m "test(strip): e2e du strip contextuel CNAME + mémoire"
```

---

## Self-Review

**Couverture du spec :**
- Émission des endpoints (writer) → Task 5 (3d) + Task 2 (store). ✓
- Consultation + strip terminal (reader) → Task 5 (3e) + Task 3 (IPC). ✓
- État partagé multi-process correct sous fan-out → store dans `mac_learner` (Task 2), câblage Task 6. ✓
- Préservation des usages directs légitimes → TTL court (Task 2) + pas d'ajout à `to_domains` (Task 7-3). ✓
- Opt-in / zéro coût par défaut → `follow_cname` (Task 4) + gating pipe (Task 6). ✓
- DoD (tests + doc + make test/e2e/coverage) → Tasks 1-8. ✓

**Cohérence des types :** `name_hash → 8 octets`, `rr_code` numérique partout (encode/decode/strip_lookup/strip_target/maybe_dynamic_strip), `STRIP_MSG_SIZE = 10` constant. `cname_targets(dns, raw, 1)` signature respectée. `strip_dns_rr` accepte un code numérique (vérifié : `resolve` accepte `type==number`).

**Points à valider en cours d'implémentation (signalés inline) :**
- Ordre de déclaration `bit_xor_byte`/`name_hash` dans le `.lua` compilé (Task 1).
- `require "main"` peut avoir des effets de bord → extraire `chain_strip_active` dans `lib/chain_strip` si besoin (Task 6).
- Forme exacte de `fds` au fork `worker_responses` (Task 5/6) — relire la signature `run` au moment du câblage.
- Fixture DNS wire déterministe (Task 5) — forger via `dns_ede`/`ipparse` ou rejouer un `.bin` capturé.
