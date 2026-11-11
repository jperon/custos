# Filtre (conditions, captive, SNI, strip CNAME)

## Système de conditions du filtre

### Interface standard d'une condition

```moonscript
-- src/filter/conditions/from_xxx.moon
(cfg) ->
  (args) ->
    {
      capabilities: { worker: true, nft: true|false, nft_dynamic: false }
      eval: (req) -> ok, msg
      compile_nft: (family) -> expr, err   -- si nft: true
    }
```

### Variantes auto-générées

Définir uniquement `from_xxx.moon` suffit. `compiler_api.load_condition` génère
automatiquement les variantes :

| Condition demandée | Dérivée de | Comportement |
|--------------------|-----------|--------------|
| `from_xxxs {…}` | `from_xxx` | OR sur table Lua |
| `from_xxx_list "nom"` | `from_xxx` | Lit `{lists_dir}/{xxx}/{nom}.txt` |
| `from_xxx_lists {…}` | `from_xxx` | OR sur plusieurs fichiers |

Format fichiers : 1 item/ligne, ignores vides et `#commentaires`.
`lists_dir` se configure via `cfg.lists_dir` ou `cfg.filter.lists_dir` (défaut
effectif de `compiler_api` : `/tmp/custos/lists`).
`{xxx}` est le type dérivé du nom de base après le premier `_` :
`from_net`→`net`, `from_mac`→`mac`, `from_vlan`→`vlan`, `from_user`→`user`,
`in_time`→`time`, `to_domainlist`→`domainlist`. L'orthographe sans tiret bas
(`from_netlist`, `from_maclists`…) n'est pas reconnue : `load_condition`
renvoie `nil, "Condition '…' not found"`.

Conséquence utile : `to_domainlist_list "groupe"` est un **groupe de domainlists**
(le fichier `{lists_dir}/domainlist/groupe.txt` liste des **noms de domainlists**,
une par ligne ; chacune réside sous `domainlists_dir`). Évite de répéter
`to_domainlists {a,b,c}` entre règles. Un `_schema.forms` (table `{ list:{label,
hint,description}, lists:{…} }`) permet à une condition de personnaliser les
libellés de ces variantes dans l'UI (cf. `to_domainlist`, lu par
`webui.schema.registry` `condition_families`).

### Alias de réseaux (`filter.nets`)

`from_net` et `to_net` résolvent un nom de `cfg.nets` quand leur argument n'est
ni `_any`/`_none` ni un CIDR/IP littéral (testé via `Net`) : la condition est
un OU sur le ou les CIDRs du groupe (`net_match.build_net_arg_condition`). Les
variantes `from_nets`, `from_net_list` et `from_net_lists` en héritent — une
entrée de table ou une ligne de fichier peut donc être un alias. Un alias vers
un seul CIDR garde `capabilities.nft = true` ; un groupe de plusieurs CIDRs est
déclaré worker-only (`nft: false`) car `compiler_api.make_plural` produit une
expression déjà groupée (`ip saddr { … }`) que le merge du niveau supérieur ne
sait pas recombiner. Un nom inconnu garde le comportement « CIDR invalide »
(ne matche jamais) et émet une seule fois `filter_net_unknown` à la
construction, jamais dans `eval`.

### Actions "modifiantes" (dns_strip, cname…)

Une action qui modifie la réponse sans se substituer à la décision d'accès
(`dns_strip`, `cname`) doit avoir `eval` renvoyant un verdict **nil** (effet
de bord pur), jamais `true`/`false` : sinon elle gagne le
« premier verdict non-nil » (`first_match_wins`, cf. `filter.rule`) et empêche
la vraie règle d'autorisation/deny (souvent gardée par une condition d'auth)
d'être évaluée.

Une entrée de `rule.actions` accepte deux formes : la chaîne `"nom"` (options
éventuelles au niveau de la règle, ex. `rule.dns_strip`), et la table à une
seule clé `{ nom: options }` (forme écrite par la webui, ex. `{ log: { log_msg:
… } }`). Le moteur normalise via `compiler_api.action_name_of` /
`action_options_of` ; pour la forme table, la factory reçoit une copie
superficielle de la règle où `[nom] = options`. Les factories d'action suivent
la convention `(cfg) -> (rule) -> (req) -> …` et `actions_meta[].name` est
toujours le nom (chaîne).

### `requires_auth` dans les capabilities

Pour qu'une condition déclenche les sous-chaînes nft d'authentification
(sets `_auth_mac`, `_auth_ip4`, `_auth_ip6`), déclarer dans ses capabilities :

```moonscript
capabilities: { worker: true, nft: false, requires_auth: true }
```

`nft_compiler` lit ce flag dans `conditions_meta` — aucun nom hardcodé n'est
nécessaire. `from_user.moon` le déclare nativement ; tout nouveau type d'auth
suit la même convention sans toucher à `nft_compiler`.

### Ajouter un nouveau type de condition

1. Créer `src/filter/conditions/from_mytype.moon` (interface standard ci-dessus)
2. Compiler : `moonc -o lua/filter/conditions/from_mytype.lua src/filter/conditions/from_mytype.moon`
3. Les variantes `from_mytypes`, `from_mytype_list`, `from_mytype_lists` sont
   disponibles immédiatement via l'auto-génération — aucun autre fichier à créer.

---

## Anti-rafale des redirections captives (`src/worker_captive.moon`)

Chaque SYN/80 bloqué déclenche une redirection HTTP 302 forgée vers le portail
HTTPS (`https://<filtre>:33443/`) — y compris pour les **sous-ressources**
(images, scripts, trackers…), car à ce stade seul le SYN TCP est visible, sans
en-tête HTTP permettant de distinguer une navigation top-level d'un sous-chargement.
Une page chargeant plusieurs domaines bloqués génère donc une rafale de
redirections, et le navigateur ouvre en retour autant de connexions TLS vers
le portail en peu de temps.

**Symptôme observé** : cette rafale peut dépasser le backlog d'écoute du
serveur AUTH (`src/auth/server.moon`, `listen 128`, historiquement `32`), que
la connexion échoue silencieusement côté noyau (RST avant `accept()`, sans
aucune trace applicative) — y compris pour une connexion **légitime**
concurrente (ex. le vrai `POST /login` de l'utilisateur, observé en HAR comme
`status=0` juste après un `POST /challenge` réussi, sans corrélat dans
`logread`). Confirmé par `/proc/net/netstat` (`ListenOverflows`/`ListenDrops`
non nuls sur le routeur affecté).

**Fix** : `should_throttle_redirect` (pure, testée) supprime l'**envoi effectif**
des frames de redirection (pas seulement le log) au-delà d'une par IP cliente
et par fenêtre (`captive_redirect_rl_window`, défaut 5 s) — le SYN reste
toujours droppé (`NF_DROP`) dans tous les cas, seule la redirection HTTP
répétée est supprimée. Complète le backlog `listen 128` (défense en profondeur,
insuffisante seule face à une rafale non bornée).

**Piège corrigé en passant** : le rate-limit du *log* lui-même
(`log.RL_CONFIG.captive_redirect`) ne s'appliquait jamais, par mismatch de nom
d'action — l'action loggée était `redirect_captive` puis préfixée `captive_` en
`captive_redirect_captive`, qui ne matchait pas la clé configurée
`captive_redirect` ; `check_rl` retournait toujours `nil` (pas de config) et ne
supprimait donc aucune ligne. L'action a été renommée `redirect` (→
`captive_redirect` après préfixe, cohérent) et la clé `RL_CONFIG` corrigée
(`{"ip"}`, `"path"` n'existant pas dans ces champs).

---

## Enforcement SNI (`src/worker_tls.moon`)

`worker_tls` applique au SNI **exactement** la décision de `filter.decide_meta`
(pas seulement le booléen verdict). Fonction pure pivot : `sni_action_for(meta)`
→ `accept|block|dnsonly|allow|redirect|validate`.

- `redirect` (action `cname`/SafeSearch, `meta.redirects_destination`) : on ne
  peut pas rediriger un flux TLS/QUIC déjà établi → **block**, sauf si l'IP dst
  est déjà une cible légitime du CNAME (`dst_matches_cname`, réutilise
  `filter.actions.cname.resolve_target_rrs`). Cible injoignable → fail-closed.
- `validate` (`meta.allow_modifiers.validate`) : second avis **synchrone** via
  `doh.validator.query_verdict` sur une requête A wire (`build_validator_query`),
  avec **cache de verdict par domaine** (`second_opinion.verdict_ttl_s`, défaut
  60 s) car le fast-path ne fait monter que le 1ᵉʳ paquet de flux. Fail-open.
- `meta.redirects_destination` + `meta.cname_target` sont exposés par
  `filter.rule` (accumulés sur **toutes** les règles matchées, comme
  `response_rule_ids` : l'action `cname` a un verdict nil, l'allow vient souvent
  d'une autre règle). Seule l'action `cname` les pose ; `dns_strip` est ignoré
  au SNI (anti-ECH, ne change pas la destination).
- Ferme le contournement DoH-externe + `curl --http3-only --connect-to`.

---

## Strip DNS contextuel à la chaîne CNAME (`dns_strip.follow_cname`)

`dns_strip` matche sur le **nom de la question**. Les résolveurs qui chasent
les CNAME eux-mêmes (systemd-resolved notamment) n'émettent pas une seule
requête sur le domaine racine : ils suivent la chaîne en émettant des requêtes
**séparées** dont la question est le **nom terminal** (ex.
`atm.outlook.mira.tm.svc.cloud.microsoft` pour `smtp.office365.com`). Ce nom
n'étant pas couvert par `to_domains`, le strip est contourné. Ajouter le nom
terminal à `to_domains` re-stripperait aussi ses **usages directs légitimes** —
indésirable. La solution est **stateful**, pilotée par `dns_strip.follow_cname`,
**active par défaut** dès qu'une règle `dns_strip` existe (opt-out explicite via
`follow_cname: false` pour retrouver l'ancien comportement strictement coût-nul).

**Flux (état partagé dans `mac_learner`, donc correct quel que soit le fan-out
`nfqueue.responses`) :**
- L'action `dns_strip` (`follow_cname` non `false`, défaut actif) pose
  `ctx.chain_strip_rr = <rr_code numérique>` dans le contexte `on_response`
  (cf. `from_*`/actions).
- `worker_responses.finalize_a`, quand `resp_ctx.chain_strip_rr` est posé,
  **enregistre** les cibles CNAME de la réponse (`dns_classify.cname_targets`)
  en envoyant `strip_codec.encode(name, rr_code)` (message 10 octets = hash
  FNV-1a 64 bits du nom + uint16 rr_code) au worker `mac_learner` via le pipe
  dédié `strip_learn`.
- `mac_learner` stocke `strip_table[hash] = { rr_code, deadline }` (TTL
  `mac_learner.strip_ttl`, défaut 120 s), en **miroir exact** de `vlan_table` /
  `vlan_learn` (même pattern pipe + socket de requête).
- À chaque réponse, `worker_responses` interroge `mac_learner_ipc.strip_target(qname)`
  (socket Unix, requête `"strip:<name>"`), gardée par `chain_strip_enabled` et
  **mémoïsée localement** (`strip_query_cache`, TTL 2 s, positif **et** négatif)
  pour borner les RTT sur le plan de données. Un hit applique `strip_dns_rr` +
  EDE **avant** le re-parse / l'injection nft (sinon nft injecterait les IP
  qu'on strippe). Garde anti-double-strip : `not resp_ctx.chain_strip_rr`.

**Contrat :** un nom interrogé **sans** contexte de chaîne récent (table vide /
TTL expiré) n'est **jamais** strippé → usages directs hors chaîne préservés.

**Défaut actif / opt-out `follow_cname: false`** : `main.moon` ne crée le pipe
`strip_learn` que si `lib.chain_strip.chain_strip_active config`, désormais vrai
dès qu'une règle `dns_strip` existe **sans** `follow_cname: false`. Sans aucune
règle `dns_strip` (ou avec `follow_cname: false` partout) : aucun pipe,
`chain_strip_enabled = false` partout, zéro requête IPC, comportement strictement
coût-nul. Motivation du défaut : recevoir un RR qu'on a justement demandé à
stripper est contre-intuitif.

**Câblage du pipe `strip_learn` (piège résolu)** : le `rfd` de `strip_learn`
doit être passé à `mac_learner.run` comme **4ᵉ argument** (`run = (learn_rfd,
ifname, vlan_learn_rfd, strip_learn_rfd)`). Dans `main.moon`, l'appel est imbriqué
dans `fork_worker name, worker_fn, worker_arg` : `pipes.learn.rfd` est le
`worker_arg` (reçu comme `rfd` dans la closure), tandis que `pipes.strip_learn.rfd`
doit être **capturé dans la closure** et passé à `run`. Une virgule mal placée le
rattachait par erreur à la liste d'arguments de `fork_worker` (4ᵉ arg ignoré) au
lieu de `run` → `strip_learn_rfd = nil`, pipe jamais ajouté au poll de `mac-lrn`,
`strip_table` jamais alimentée, `strip_target` toujours « unknown » → le nom
terminal n'était **jamais** strippé malgré l'apprentissage côté `worker_responses`.
Forme correcte : `fork_worker "mac-lrn", ((rfd) -> ...run rfd, bridge_ifname,
pipes.vlan_learn.rfd, (pipes.strip_learn and pipes.strip_learn.rfd)), pipes.learn.rfd`.

**Modules** : `strip_codec` (codec hash/encode partagé), `mac_learner`
(`strip_table`/`process_strip_learn`/`strip_lookup`), `mac_learner_ipc`
(`strip_target`), `filter.actions.dns_strip` (`follow_cname`),
`worker_responses` (`record_chain_targets`/`maybe_dynamic_strip`),
`lib.chain_strip` (`chain_strip_active`).

**Périmètre** : plan UDP (`worker_responses`) uniquement. Le plan DoH
(`doh.query`) applique `run_on_response` mais **pas** l'apprentissage/consultation
des cibles de chaîne — parité DoH non implémentée (hors périmètre actuel).

---

