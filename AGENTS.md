# AGENTS.md — CustosVirginum

## Projet

**CustosVirginum** est un filtre DNS inline sur pont Linux (bridge), écrit en
MoonScript et exécuté par LuaJIT. Il bloque tout le trafic DNS sauf les domaines
explicitement autorisés, logue les informations L2/L3/L4/L7, et construit
dynamiquement des allowlists nftables au fil des résolutions DNS.

Voir [README.md](README.md) pour l'architecture complète.

---

## Règles agent

- **Ne jamais écrire en dehors du dossier du projet.** Toutes les sorties
  temporaires (fichiers de debug, redirections, captures) doivent être placées
  dans `./tmp/`. Ne jamais utiliser `/tmp/`, `~/.cache/` ou tout autre chemin
  extérieur au projet.

### Definition of Done (obligatoire avant de conclure une tâche)

Une tâche n'est **jamais** terminée tant que les trois conditions suivantes ne
sont pas vérifiées et constatées (pas supposées) :

1. **Couverture de tests.** Tout code ajouté ou modifié doit être couvert par des
   tests. En toute fin d’un développement important, vérifier avec `make
   coverage-quick` (rapport dans `tmp/coverage_quick/`, ordre de grandeur par
   échantillonnage, ~20 min sur toute la suite). `make coverage` (luacov,
   ligne-par-ligne exhaustif) est réservé à un chiffre exact sur un module
   isolé (`tests/unit/<module>` ciblé) : sur la suite complète il est ~4x plus
   lent et a déjà échoué à écrire ses stats en fin de run (cf. § Corrections
   d'audit 2026-07-16). Une branche d'erreur non couvrable en unitaire doit
   l'être par un mock (cf. `tests/unit/auth/cert_generator_spec.moon`) ou par
   les tests e2e.
2. **Documentation à jour.** Mettre à jour la doc impactée par le changement
   (`AGENTS.md`, `.agents/*`, `README.md`, `doc/CONFIG.md`, `doc/CHEATSHEET.md`,
   etc.). Du code sans sa doc à jour n'est pas livrable.
3. **`make test` ET `make test-e2e` à 100 %.** Les deux suites doivent passer
   intégralement (`0 failed`). Lancer effectivement les commandes et lire le
   total ; ne jamais déclarer un succès non exécuté. `make test-e2e` exige le
   homelab libvirt provisionné (cf. [.agents/testing.md](.agents/testing.md) et
   [libvirt/README.md](libvirt/README.md)) ; quand le provisioning est déjà fait,
   il ne nécessite pas root. Toujours essayer `make test-e2e` à la fin des modifications,
   sans utiliser au préalable les outils de libvirt, mais signaler si cela échoue.

---

## Documentation détaillée

| Sujet | Fichier |
|-------|---------|
| Architecture, workers, queues, pipes, nft sets, superviseur | [.agents/architecture.md](.agents/architecture.md) |
| I/O par worker et formats de messages IPC | [.agents/workers.md](.agents/workers.md) |
| Syntaxe MoonScript, LDoc, pièges de refactoring | [.agents/skills/moonscript/SKILL.md](.agents/skills/moonscript/SKILL.md) |
| Suites de tests et pièges OpenWrt | [.agents/testing.md](.agents/testing.md) |
| Harnais de benchmark / stress test (`make bench`, `bench-load`) | [src/bench/README.md](src/bench/README.md) |
| Référence complète de toutes les clés de configuration | [doc/CONFIG.md](doc/CONFIG.md) |
| Aide-mémoire rapide pour les mainteneurs | [doc/CHEATSHEET.md](doc/CHEATSHEET.md) |
| Homelab libvirt (3 VMs OpenWrt : via/custos/servus) pour tests E2E | [libvirt/README.md](libvirt/README.md) |

---

## ipparse (sous-module moontastik)

La bibliothèque de parsing L2/L3/L4/L7 `ipparse` n'est plus une copie vendue :
c'est le sous-module git `src/lib/moontastik`
(https://github.com/luainkernel/moontastik), et `src/ipparse` est un **lien
symbolique relatif** vers `lib/moontastik/ipparse`. Le code custos continue de
faire `require "ipparse.…"` sans changement.

- **Cloner/initialiser** : `git clone --recursive` ou
  `git submodule update --init` (idem pour `src/lib/moonscript`).
- **Mettre à jour** : `git -C src/lib/moontastik fetch`,
  `git -C src/lib/moontastik checkout <commit>`, puis `make all && make test`,
  et committer le nouveau pointeur de sous-module (`git add src/lib/moontastik`).
  Vérifier que `git -C src/lib/moontastik status --short` reste vide après
  compilation (aucun `.lua` généré dans le sous-module).
- **Piège `find`** : `find src/ipparse …` ne descend pas dans un lien
  symbolique donné comme point de départ. Le `Makefile` utilise donc
  `find -H $(SRC)/ipparse` pour `IPPARSE_MOONS`, et élague
  `$(MOONTASTIK_SUBMODULE)` du `find $(SRC)` global (sinon des
  `lua/lib/moontastik/…` parasites apparaissent).

## Aide-mémoire rapide

| Besoin | Approche |
|--------|----------|
| Fonctions pures | Module exportant des fonctions |
| Objet avec état | Fonction factory + `setmetatable` |
| Documentation | LDoc `@tparam`/`@treturn` |
| Lib C externe | `ffi.load` + `ffi.cdef` (pas de bridge C) |
| Struct C opaque | `ffi.new("uint8_t[?]", size)` + `ffi.cast` |
| Parsing de paquets | `ffi.cast("const uint8_t*", raw)` + `bit` |
| `$` dans une string | Écrire `$` directement — `\$` est invalide en Lua |
| Rate-limiting de logs | `log.moon` : une entrée par fenêtre de burst pour un même (action, key) |
| Concaténer en boucle | Accumuler dans une table puis `table.concat` (jamais `..=` en boucle) |
| Log DEBUG dans un hot-path | Garder avec `log.level_enabled "DEBUG"` au call-site : sans ça la closure (thunk) est allouée par paquet même quand le niveau est filtré |
| `require` dans un hot-path | Mémoïser le module à la construction (factory/startup), jamais un `require` par paquet (≈150 ns/appel) |
| Piège `a\match "x" or b` | Parenthéser : `(a\match "x") or b` — sans ça l'`or` est avalé par l'argument et le repli ne s'applique jamais |
| Détecter l'interface bridge | `lib.bridge_detect` (sysfs `/sys/class/net/*/bridge`, busybox-compatible ; choix du bridge le plus peuplé). **Jamais** `ip … type bridge` (non supporté par busybox). `auth.bridge_ifname`/env `BRIDGE_IFNAME` priment (env validé par `valid_name`, valeur invalide ignorée avec warn → détection sysfs) ; `main.moon` warn `bridge_ifname_not_found` si la config force une interface absente |

---

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
`lists_dir` se configure via `cfg.lists_dir` ou `cfg.filter.lists_dir` (défaut : `/etc/custos/lists`).

Conséquence utile : `to_domainlist_list "groupe"` est un **groupe de domainlists**
(le fichier `{lists_dir}/domainlist/groupe.txt` liste des **noms de domainlists**,
une par ligne ; chacune réside sous `domainlists_dir`). Évite de répéter
`to_domainlists {a,b,c}` entre règles. Un `_schema.forms` (table `{ list:{label,
hint,description}, lists:{…} }`) permet à une condition de personnaliser les
libellés de ces variantes dans l'UI (cf. `to_domainlist`, lu par
`webui.schema.registry` `condition_families`).

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

## Modules DoH (`src/doh/`)

| Module | Rôle |
|--------|------|
| `doh.upstream` | Client UDP/53 — new_client / query / close |
| `doh.upstream_doh` | Client DoH HTTP/1.1 wolfSSL — même contrat |
| `doh.upstream_doh_curl` | Client DoH **HTTP/2** via libcurl FFI — même contrat. Chargé si `doh.upstream_doh_url` est défini. `ffi.load` essaie `"curl"` puis `"libcurl.so.4"` pour compat OpenWrt. Les args `const char *` vers les varargs `curl_easy_setopt` **doivent** être castés via `ffi.cast "const char *"` (LuaJIT ne convertit pas automatiquement en varargs). |
| `doh.h2_frames` | Utilitaires frames HTTP/2 partagés (constantes, `h2_read_frame`, `h2_write_frame`) |
| `doh.validator` | Second avis DNS synchrone pour `worker_doh`. Interroge `second_opinion.resolvers` (ou per-règle) en UDP ou DoH. Timeout distinct `budget_ms` (UDP) / `doh_budget_ms` (DoH). `query_classified` renvoie un **override classifié** (`block`/`sinkhole`/`redirect`/`nil`) via `dns_classify.classify` (REFUSED → `block` explicite, comme l'ancien `query_verdict` booléen, toujours exposé en wrapper). |
| `doh.query` | Cœur de traitement DoH : vol captif + `filter.decide` + `doh.validator` + upstream + nft |

### Parité UDP/DoH : vol captif et overrides du second avis

`doh.query` réplique deux comportements du plan de données UDP (sinon le résolveur
DoH divergeait de l'intercepteur `worker_questions`) :

- **Vol DNS du portail captif.** `set_captive(domain, ip4, ip6)` (appelé par
  `worker_doh` au démarrage/reload via `filter.get_auth_cfg!` +
  `captive_ips.detect`/`domain_from_url`) arme l'interception : une question
  A/AAAA portant sur `captive_domain` reçoit directement une réponse vers l'IP
  locale (`dns_ede.build_captive_response` : NOERROR, AA, TTL 0), sans filtre ni
  upstream. Miroir de `worker_questions.moon` (forge AF_PACKET). `domain_from_url`
  est factorisé dans `captive_ips`.
- **Overrides `sinkhole`/`redirect`/`block` du validateur.** La branche `validate`
  interroge d'abord l'upstream réel (`doh.upstream.query`), puis appelle
  `query_classified` et applique l'override comme `worker_responses.finalize_a` :
  `block` → `build_nxdomain_response`, `sinkhole` → `build_sinkhole_response`,
  `redirect` → `build_cname_response` **plus** injection nft des cibles
  (`override.a`/`aaaa`) pour que le client les joigne. Fail-open (`nil`) si tous
  les validateurs sont muets.
- **Garde-fou anti-CDN sur `redirect`.** `dns_classify.classify` qualifie en
  `redirect` toute présence de CNAME dans la réponse du validateur — y compris
  les CNAME de CDN (Cloudflare, Akamai…) qui n'ont rien d'un blocage. Avant
  d'appliquer l'override `redirect`, on vérifie via `dns_classify.has_cname_target`
  que la **vraie réponse upstream** (`resp_raw`, obtenue avant le second avis)
  ne porte pas déjà ce même CNAME ; si c'est le cas, l'override est ignoré
  (passthrough). Logique partagée avec `worker_responses.finalize_a:447-448` —
  sans ce garde-fou côté DoH, tout site derrière un CDN répondant en CNAME se
  retrouvait réécrit en réorientation, y compris pour la requête HTTPS RR
  (type 65), ce qui cassait la résolution DNS sécurisée de Chromium
  (`DNS_PROBE_FINISHED_BAD_SECURE_CONFIG`).

### Pièges FFI libcurl

- `ffi.load "curl"` échoue sur OpenWrt → essayer `"libcurl.so.4"` en fallback.
- Les fonctions variadiques FFI (`curl_easy_setopt`, …) ne convertissent **pas** les strings Lua en `char *` automatiquement → `ffi.cast("const char *", str)` obligatoire.
- Les callbacks LuaJIT FFI (`ffi.cast "fn_ptr_type", lua_fn`) capturent les upvalues par référence ; réassigner l'upvalue (`recv_buf = {}`) met à jour le slot partagé.

### `from_vlan` en DoH (détection via file dédiée)

La condition `from_vlan` lit `req.vlan`, renseigné en UDP via le tag 802.1Q du
paquet L2 (recopié dans le nfmark par nft). Le worker DoH écoute sur un port
TCP/TLS local et ne dispose pas de ce nfmark. Un mécanisme dédié comble l'écart,
calqué sur la topologie `worker_auth_queue` → `mac_learner` :

- `nft_rules` apprend l'association IP→VLAN à **deux endroits**, tous deux rendus
  seulement si `doh.enabled` et `nfqueue.doh_vlan`, vers la file `nfqueue.doh_vlan`
  (en recopiant le tag 802.1Q dans le mark) :
  - **Hook `forward`** (placeholder `{DOH_VLAN_FORWARD_RULES}`, **source
    autoritative du tag**) : règles taguées `vlan id != 0 tcp dport <doh> ip[6]
    daddr @filter_ips…`, placées **avant** la règle « UniFi mgmt local » (qui
    accepte tcp/8443) sinon la SYN serait acceptée avant tout apprentissage.
    Indispensable en **topologie routée** : custos n'a souvent qu'une IP de
    management ; la SYN DoH d'un client d'un autre sous-réseau a pour MAC dst sa
    passerelle → elle **transite le forward taguée** puis est routée et **revient
    untagged** sur l'IP du filtre (hook input). Sans la règle forward, seule la
    boucle untagged serait vue → `vlan` jamais loggué.
  - **Chaîne `input` du bridge** (`{DOH_VLAN_INPUT_CHAIN}`) : trafic host-bound
    vers le port DoH, **tagué ET untagged**. Sert le cas d'un client DoH
    réellement **untagged adjacent** (et l'anti-spoofing untagged, ci-dessous).
- `worker_doh_vlan` lit le VLAN (`get_l2` → `nfq_get_nfmark`) + l'IP source,
  transmet l'association IP→VLAN au `mac_learner` via le pipe `vlan_learn`
  (message 18 octets ip16+vlan16), et renvoie **toujours `NF_ACCEPT`**.
- `mac_learner` stocke `vlan_table[ip]` (TTL `entry_ttl`) et répond aux requêtes
  `vlan:<ip>` ; `mac_learner_ipc.get_vlan(ip)` est interrogé par le worker DoH
  après `getpeername`, comme `get_mac`.

**Précédence forward-tagué vs input-untagged (boucle routée).** La même connexion
produit d'abord l'observation **forward taguée** (VLAN réel), puis la **boucle
routée untagged** (input) qui, en last-writer-wins, **écraserait** le VLAN. Pour
l'éviter sans casser l'anti-spoofing, `worker_doh_vlan.should_learn_untagged`
n'apprend une observation **untagged** que si la **MAC source de la trame
correspond à la MAC connue de l'IP** (`get_mac`) : la boucle routée a la MAC de la
**passerelle** (≠ MAC du client) → ignorée ; un vrai client untagged — ou un
usurpateur IP+MAC — présente la MAC connue → apprise (`0` écrase). Fallback : si la
MAC connue est inconnue/nil, on apprend (anti-stale). Les observations **taguées
(`vlan > 0`)** sont apprises inconditionnellement.

**Anti-spoofing.** L'écrasement untagged ci-dessus reste la défense : un client
usurpant IP+MAC en untagged ne doit pas hériter du VLAN d'un appareil légitime
sous `from_vlan <id> AND from_mac …`. Côté `req.vlan`, `0` est ramené à `nil`
(parité UDP : `from_vlan _none` matche, `from_vlan <id>` non). **Caveat** :
association par IP via cache TTL (comme `get_mac`) → défense en profondeur, pas
garantie dure ; pour un enforcement strict, s'appuyer sur le plan UDP ou une
segmentation L2.

`from_nets` (sous-réseaux IP) reste utilisable pour les règles devant s'appliquer
aux deux workers sans dépendre du VLAN.

---

## Interdictions absolues

- **`class`, `extends`** (syntaxe MoonScript orientée objet) → jamais : utiliser `setmetatable`
- **`end`, `local`, `then\n`...** (syntaxe Lua, fautive en Moonscript) → jamais
- **`require "moon"`** → le code compilé doit être indépendant de la lib MoonScript
- **`socket.bind "*"`** dans le worker AUTH → ne bind qu'IPv4 ; utiliser deux
  sockets distincts + `socket.select`
- **`\` au lieu de `.`** pour appeler des fonctions de module (ex. `nft_sessions`) →
  injecte la table comme premier argument

---

## Structure du worker AUTH (`src/auth/`)

Le serveur HTTPS est découpé pour isoler les responsabilités :

- `auth/server.moon` — machinerie réseau/TLS/fork uniquement (`run`, `handle_client`,
  `dispatch_connection`, `resolve_tls_ctx`, `replay_sessions_to_nft`). N'expose plus
  les handlers HTTP. Chaque connexion est bornée par `auth.client_timeout` (15 s
  défaut) : SO_RCVTIMEO/SO_SNDTIMEO sur le socket + échéance de handshake +
  budget total de `read_request` — sans quoi une connexion muette (préconnexion
  spéculative de navigateur) suspendrait l'enfant AUTH-conn indéfiniment.
- `auth/handlers.moon` — handlers HTTP du portail (`handle_login/ping/logout/register`
  + `handle_challenge`/`handle_password_change`)
  + routage `handle_request` + helpers de présentation/formulaire (cookies, `parse_form`,
  pages login/register). C'est `server.handle_client` qui appelle `handle_request`.
  `/ping` tolère un token **authentique mais expiré** (3ᵉ retour de `token.verify`)
  si la session de la MAC est encore vivante : un ping retardé par le navigateur
  arrivant après le ping suivant reçoit 204 **no-op** (ni refresh nft, ni nouveau
  cookie) au lieu d'un 401 trompeur ; côté client, la page success n'alerte
  qu'après deux 401 consécutifs (retry de confirmation à 2 s).
  `handle_refusals` sert `GET /refusals` : liste JSON **en lecture seule** des
  derniers domaines refusés pour la MAC du client (token vérifié, ni session ni
  nft ni cookie touchés). Source : `recent-verdicts.tsv` écrit par `worker_events`
  dans `events.dir` (filtré sur `decision == "block"`). La page de succès l'interroge toutes les
  `auth.refusals_poll_interval` s (défaut 5) et affiche une liste défilante,
  indépendamment du `/ping`.
  **Important** : les blocages décidés par le *second avis DNS* (validateur amont)
  sont appliqués dans `worker_responses.finalize_a` (override `block`/`sinkhole`),
  **après** la décision `decide` de `worker_questions` qui a déjà loggé la requête
  en `allow`. Ces blocages n'apparaîtraient donc jamais dans les events/`recent-verdicts`.
  Pour les rendre visibles, `worker_responses` reçoit `events_wfd` (via `main.moon`)
  et émet une ligne d'événement `block` (`format_block_event`, raison
  « Filtered by upstream validator ») dans ces deux branches d'override.
- `auth/challenge.moon` — challenge-réponse sans état pour le portail. Le mot de
  passe n'est **jamais** transmis en clair : `GET /` sert un formulaire dont le JS
  (`auth/pages.moon`, constantes `CRYPTO_JS`/`LOGIN_JS`/…) demande un nonce à
  `POST /challenge`, calcule `response = HMAC(PBKDF2(password, salt, iter), nonce)`
  (WebCrypto, **repli JS pur** si `crypto.subtle` absent — mini-navigateur captif),
  puis poste `{user, nonce, response}` à `/login`. Le serveur réutilise le hash
  PBKDF2 déjà stocké comme clé HMAC (`credentials.verify_response`) → SCRAM-lite.
  `make_nonce`/`verify_nonce` : nonce signé (HMAC `session.key`), borné par
  `auth.challenge_ttl` (120 s) et **lié à la MAC** du client. `salt_iter_for`
  renvoie un salt factice déterministe pour les users inconnus (anti-énumération).
  Repli plaintext (JS désactivé) accepté seulement si `auth.allow_plaintext_login`
  (défaut true, recommandé false). **Conséquence** : la migration transparente de
  hash au login (`needs_rehash`) disparaît — le serveur n'a plus le mot de passe ;
  la migration se fait à l'inscription et au changement de mot de passe
  (`POST /password`, hash calculé côté client, `credentials.set_record`). Le
  changement de mot de passe **exige l'ancien mot de passe** (challenge-réponse,
  jamais transmis en clair) : une session ouverte ne suffit pas. `GET /`
  sert la page de succès si un cookie de session est valide (login → `location='/'`,
  rafraîchissement sans renvoi de formulaire).
- `auth/nft_auth_sets.moon` — sous-chaînes nft d'authentification par règle
  (`refresh_rule_auth_sets`, `delete_rule_auth_sets`, `refresh_nft`,
  `for_qualifying_auth_rules`). `refresh_nft` rafraîchit **les deux** familles
  de sets (globaux `add_authenticated*` ET per-règle `_auth_mac`/`_auth_ip*`)
  avec le même TTL : c'est lui qu'appellent login, ping, replay et `/bye`.

## Interface admin web (`src/webui/`)

Servie par le worker AUTH (`src/auth/server.moon` `require "webui.router"`) sous
`/admin/*`, derrière le portail captif **et** une vérification de session admin
(`auth.admin_users`, `admin_auth.moon`). Permet d'éditer la config (`config.moon`
relu/réécrit via `webui/serializer.moon`), les règles, les dictionnaires nommés
(`nets`/`macs`/`users`/`times`), les listes, et de déclencher un reload SIGHUP.

**Reload SIGHUP — cible obligatoire : le superviseur.** Seul le superviseur
(`main.moon`) traite SIGHUP pour le hot-reload de la config (relecture +
recompilation des règles + kill/refork des workers DNS/resp/captive/reject/DoH/SNI ;
il ne fait que **transmettre** SIGHUP au worker AUTH pour relire les secrets). La
webui s'exécute dans un enfant `AUTH-conn` (petit-enfant du superviseur), donc
`getppid()` viserait le **worker AUTH** → seuls les secrets seraient relus, jamais
les règles (bug du bouton « Recharger maintenant »). Le PID cible provient donc du
**pidfile** `/var/run/custos.pid`, écrit par le superviseur au démarrage et supprimé
à l'arrêt (`src/lib/pidfile.moon`, chemin surchargeable via `runtime.pid_file` ou
env `CUSTOS_PID_FILE`). `handle_reload` (`system.moon`) et `default_reload`
(`devices.moon`) lisent ce pidfile ; `custos-update` l'utilise déjà. `handle_reload`
accepte `state.kill_fn` injectable (tests).

**POST de section = fusion sur les clés du schéma.** `handle_config_section_post`
(`handlers/config.moon`) ne remplace que les clés non `_` déclarées dans
`config_schema[section]` ; les clés hors schéma de la section existante sont
préservées telles quelles (`auth.admin_users`/`admin_allow_all_when_empty`,
`dns.upstream_retry`, `nft.extra_rules`…). Une clé du schéma rendue `nil` par
`build_section` reste supprimée. Ne jamais revenir à un remplacement de section
entier : effacer `admin_users` le fait retomber sur `{}` + `admin_allow_all_when_empty
= true` au rechargement, rendant tout utilisateur authentifié admin.

**Échappement HTML : `webui.util` est la source unique.** Le DSL `auth.html`
n'échappe ni le texte ni les attributs ; `webui.util.esc` (`&`, `<`, `>`, `"`,
`'`, nil → `""`) doit être appliqué à **toute** valeur de config ou de requête
injectée dans du HTML (règles, champs de section, titres `page`), et
`webui.util.parse_form` est le décodeur urlencodé commun des handlers.

Les champs scalaires de `filter` (SafeSearch, YouTube Restricted, `allow_localnets`,
`captive_portal`, `domainlists_dir`, `dest_whitelist`, `allowed_domains`…) sont
édités par `handle_filter_general_get/post` : ils parcourent `config_schema.filter`
en ignorant les types `named_map`/`rules_list` et la sous-table `decision`, et ne
réécrivent que ces clés sans toucher au reste de `filter`. Dans l'index config
(`/admin/config/`) ils s'affichent comme un `<details>` replié inline
(`#section-filter-general`), cohérent avec les autres sections scalaires ; la
page autonome `/admin/config/filter/general` reste accessible. Les éditeurs
spécialisés (règles, listes, décision, nets, macs, users, times) gardent des
pages dédiées car ils ont leurs propres formulaires multi-lignes — l'index les
liste sous « Filtre DNS — éditeurs dédiés ».

- Routeur + dispatch : `src/webui/router.moon`
- Handlers : `src/webui/handlers/{dashboard,system,config,filter,rules,lists,devices,admin_auth}.moon`
- Sérialisation MoonScript : `src/webui/serializer.moon` (+ `schema/`). `serializer`
  écrit du **MoonScript** (`{ clé: valeur }`), pas du Lua, pour rester cohérent
  avec les `config.moon` écrits à la main.

### Éditeur de règles — réordonnancement drag-and-drop (`handlers/rules.moon`)

`handle_rules_list` rend chaque ligne `draggable` avec `data-idx` (index 1-based
d'origine) et une poignée `⠿`. Un `H.script RULES_REORDER_JS` (JS vanilla inline,
sans dépendance, motif `MODAL_JS`) réordonne les `<tr>` du `<tbody id="rules-tbody">`
au glisser-déposer puis soumet `#reorder-form` (POST
`/admin/config/filter/rules/reorder`, champ `order` = permutation des `data-idx`
séparés par virgule). `handle_rules_reorder` **valide une permutation exacte de
`1..#rules`** (longueur, bornes, pas de doublon → sinon `400` sans écriture),
reconstruit `cfg.filter.rules` dans le nouvel ordre et `write_config`. Les boutons
↑/↓ (`handle_rules_move`) restent le repli sans JavaScript.

**Désactivation de règle (`enabled = false`).** Une règle peut porter `enabled =
false` (défaut `true`/absent = active) pour la neutraliser sans la supprimer :
`filter.rule.compile_rule` la compile en **entité inerte** (eval ne matche
jamais, métadonnées vides marquées `metadata.enabled = false`) plutôt que de la
sauter — l'alignement des index `rules_metadata[idx]`, des `rule_id` et du
réordonnancement est ainsi préservé. `nft_compiler.compile` la **saute** via le
même drapeau (`rules_cfg[idx].enabled == false`) : aucune sortie `action_map`,
sets dynamiques ni `plan_rules`. Côté webui, `handle_rules_toggle` (POST
`/admin/config/filter/rules/:n/toggle`) bascule la clé (false ↔ retirée) ;
`handle_rules_edit_post` **préserve** `enabled = false` (rebuild_rule ne connaît
pas cette clé hors formulaire) ; la liste marque la ligne `(désactivée)`.

### Page « Appareils » (`src/webui/handlers/devices.moon`)

`GET/POST /admin/config/devices` facilite l'enregistrement des clients réseau.
Elle lit `recent-verdicts.tsv` (ring-buffer unique écrit par `worker_events`, cf.
[.agents/workers.md](.agents/workers.md)) via `read_devices`, qui **agrège les
verdicts par MAC** (1ʳᵉ occurrence = dernier verdict, `count` sommé, `first_ts`
min / `last_ts` max), et affiche un tableau
triable/filtrable (JS inline, sans dépendance) des appareils vus : Nom, MAC, IP,
user, dernier domaine, décision, vus, dernière activité. La colonne **Nom** est
remplie par recoupement avec `filter.macs` (`mac_name_index`, map inverse
MAC→nom) ; une mini-form POST `{mac, name}` (champ texte pré-rempli si déjà
nommé, bouton « + ») permet de l'ajouter **ou de renommer** un appareil existant.
`handle_devices_post` valide la MAC, retire d'abord tout nom string pointant déjà
vers cette MAC (renommage idempotent), écrit
`cfg.filter.macs[name] = mac` (**string unique**, pas une liste) puis recharge via
`state.reload` (SIGHUP ; injectable pour les tests). Le DSL `auth.html`
n'échappant rien, `devices.moon` échappe lui-même les valeurs (`esc`).

**Contrat `filter.macs` = nom→MAC unique** (pas une liste) : `from_mac.moon` fait
`(mac_map[alias] or alias)\lower!`, qui plante sur une table. L'éditeur
`MACs nommées` (`handle_macs_post`, `is_list_value=false`) et le schéma
(`config_schema.macs.value_type = "string"`) sont alignés sur ce contrat. Un alias
ainsi défini est résoluble dans `from_macs {…}` / `from_mac_list` (chaque entrée
passe par `from_mac` via `make_plural`), mélangeable avec des MAC brutes.

### Page « Verdicts » (`src/webui/handlers/verdicts.moon`)

`GET /admin/config/verdicts` (lecture seule, pas de POST) liste **tous** les
derniers verdicts DNS (allow ET block) lus depuis `recent-verdicts.tsv` via
`read_verdicts` (une ligne par verdict, **sans** agrégation, contrairement à la
page Appareils). Même UX que « Appareils » : recherche plein-texte + tri par clic
d'en-tête (JS inline, ids `verdtbl`/`verdfilter`), valeurs échappées via `esc`.
Colonnes : **MAC / IP** (fusionnées dans une cellule à deux lignes via `mac_cell`,
+ le nom de l'appareil sur une 3ᵉ ligne s'il est défini), User, Domaine, Décision,
Raison, Vus, Première, Dernière. Le nom est résolu par `name_by_mac_for` qui
applique `bidirectional` (ipparse.fun) à `filter.macs` (nom→MAC) pour obtenir
l'accès inverse MAC→nom sans construire d'index explicite. Classe CSS `.muted`
(`webui/css.moon`) pour l'IP secondaire. La cellule MAC/IP porte aussi un
**mini-formulaire d'édition du nom** (`name_form`, pré-rempli si la MAC est déjà
nommée) qui **réutilise `handle_devices_post`** : il poste vers
`/admin/config/devices` avec un champ caché `redirect=/admin/config/verdicts`.
`handle_devices_post` ne redirige que vers une cible de sa `REDIRECT_WHITELIST`
(`/admin/config/devices` ou `/admin/config/verdicts`, anti open-redirect), défaut
`devices`. Aucune route POST propre à Verdicts n'est donc nécessaire.

**Détail par appareil (modale / popup).** Dans les deux tableaux (Appareils ET
Verdicts), chaque ligne porte `data-mac` et une cellule « Détails » (lien
`a.vdetail` → `GET /admin/config/verdicts?mac=<MAC>`, `target="_blank"`). Avec ce
paramètre `mac`, `handle_verdicts_get` rend une **vue détail** (`detail_section`,
conteneur `#verd-detail`) listant uniquement les verdicts de cette MAC. `MODAL_JS`
(JS partagé, défini dans `devices.moon` avec `detail_cell`/`modal_dialog` —
`verdicts.moon` en dépend déjà, pas de cycle) intercepte le clic sur la ligne (hors
formulaire de nom) ou sur le lien, `fetch` cette URL et injecte `#verd-detail`
dans un `<dialog id="vmodal">` (modale). **Sans JS**, le lien ouvre simplement la
page filtrée (popup `_blank`). Le routeur (`webui/router.moon`) sépare désormais la
query string du chemin (`webui.util.parse_form`) et expose `req.query` aux handlers ; le
matching de route reste sur le **chemin nu**.

**Déconnexion admin.** Le lien « Déconnexion » de `dashboard.moon` pointe vers
`/logout` (route GET du portail, `auth/handlers.moon`) : `/admin/logout` n'existe
pas et retombait sur la redirection du routeur webui.

**Listes — pas d'écrasement silencieux.** `handle_list_new_post` et le
renommage de `handle_list_post` (`handlers/lists.moon`) répondent **409** si le
fichier cible existe déjà (hors renommage vers le même nom) : la cible n'est
jamais écrasée.

## Résilience du portail captif aux blips réseau (`src/auth/portal_client.js`)

La logique de connexion de la **page de succès** (heartbeat `/ping`, polling
`/refusals`, bandeau d'état, beacon `/bye`) vit dans `src/auth/portal_client.js`
(JS pur ES5, **source unique**), embarqué dans `lua/auth/portal_client_js.lua`
(généré par `tools/embed_js.lua` via `make all`, jamais édité à la main) et injecté
inline par `auth.pages.success_page`. Testée sous Node (`tests/unit/auth/portal_client.test.js`,
cible `make test-js`).

- **Machine à états** `online`/`reconnecting`/`expired` (`createPortalClient`) :
  une panne réseau passe en `reconnecting` (backoff 2→4→8 s, plafond
  `heartbeat_interval`) sans jamais éjecter ; seul un **401 confirmé** (2 pings)
  passe en `expired` → `alert()` (si onglet visible) + redirection `/`.
- **Anti-tempête** (corrige aussi le bug « login impossible après déconnexion ») :
  chaque fetch est borné par `AbortController` + timeout (≈ 9 s) pour ne pas laisser
  de socket gelée saturer le pool de connexions du navigateur ; un seul ping en vol ;
  `/refusals` suspendu hors état `online`, et un seul `/refusals` en vol à la fois
  (`refusalsInflight`) : sans cette garde (absente jusqu'au 2026-07-17, présente sur
  `ping` mais oubliée sur `refusalsTick`), une réponse plus lente que
  `refusals_poll_interval` (défaut 5 s) laissait les ticks suivants relancer un
  nouveau fetch par-dessus le précédent — chevauchement qui s'auto-aggrave sous
  charge et se traduisait par une rafale de `NS_BINDING_ABORTED` (abort côté
  client au bout des 9 s) dans le panneau réseau du navigateur.
- **Wiring navigateur** (`mountPortalClient`) : heartbeat via Web Worker (non
  throttlé en arrière-plan, repli `setInterval`), événements `online`/`offline`
  (ping immédiat au retour) et `visibilitychange`, beacon `/bye` sur `pagehide`.
- **Formulaires login/register/password aussi bornés** (`auth/pages.moon`) :
  `CRYPTO_JS` définit `fetchT` (AbortController + timeout 10 s) et
  `LOGIN_JS`/`REGISTER_JS`/`PASSWORD_JS` n'utilisent que lui — jamais `fetch` nu.
  Sans cela (bug HAR 2026-07-17), un `POST /login` dont la connexion TCP n'est
  **jamais établie** (pool de connexions Firefox gelé après une mise en veille :
  entrée HAR `connection: null`, timings vides, aucun `conn_started` côté
  serveur) laissait la promesse pendante et le bouton bloqué sur « Connexion… »
  jusqu'au rechargement manuel. Le timeout rend la main au `catch` ; pour le
  login, la séquence **challenge+login est rejouée automatiquement** (nouveau
  nonce, `LOGIN_RETRIES=3`, délai 1 s) avant d'alerter et de réactiver le
  bouton. Register/password gardent le réessai manuel (rejouer une écriture au
  résultat inconnu serait risqué). Test :
  `tests/unit/auth/login_page_js_spec.moon`.
- **Filtrage inchangé** : aucune modification des durées token/session/nft ni de la
  sémantique serveur. Voir
  [docs/superpowers/specs/2026-06-27-portail-resilience-blip-reseau-design.md](docs/superpowers/specs/2026-06-27-portail-resilience-blip-reseau-design.md).

## Synchronisation de configuration (`sync/`)

Déploiement multi-routeurs depuis un dépôt git central.

- `sync/apply.moon` (→ `lua/sync/apply.lua`) : fusionne `base/config.moon` +
  `devices/<hostname>/config.moon` → `/etc/custos/config.moon` (`--reload` envoie SIGHUP).
- `sync/custos-sync.sh` : pull-only depuis `CUSTOS_CONFIG_REPO` (`/etc/custos/sync.conf`), cron */15.
- `sync/custos-sync-push.sh` : publie la config d'un filtre de référence vers le dépôt.
- Init : `make sync-init HOST=… REPO=…` (pull) / `make sync-push-init HOST=… REPO=…` (push).

## UI d'installation redbean (`.init.moon`)

Mini serveur web local (redbean) pour installer/désinstaller/synchroniser Custos
sur un routeur sans CLI. `make redbean-ui` empaquète `.init.lua` dans `redbean.com`.
Voir [doc/CHEATSHEET.md](doc/CHEATSHEET.md) § « UI d'installation (redbean) ».

## px5g Migration — Dynamic TLS Certificate Generation

See [.agents/px5g_migration.md](.agents/px5g_migration.md) for full documentation on the migration from static (openssl-based) to dynamic (px5g-based) certificate generation with LRU/TTL caching.

**New modules**:
- `src/auth/cert_generator.moon` — px5g wrapper for dynamic cert generation
- `src/auth/cert_cache.moon` — LRU cache with TTL for generated certs
- `src/auth/sni_extractor.moon` — TLS ClientHello SNI parser (RFC 5246/6066)

**Modified modules**:
- `src/auth/cert.moon` — Added `load_or_generate_sni()` for SNI-aware certs, and
  `load_or_generate_static()` : si `auth.cert`/`auth.key` sont configurés mais
  absents (installation fraîche), génère un auto-signé à ces chemins (mkdir -p,
  clé 0600) au lieu d'échouer. Sans ce fix, `static_cert_paths` restait posé
  après l'échec du chargement parent et **chaque enfant AUTH-conn levait**
  « Cannot load static certificate in child » → portail inutilisable au premier
  lancement (observé sur 10.35.1.17, 2026-07-18).
- `src/auth/server.moon` — Cache initialization on AUTH server startup ;
  `static_cert_paths` n'est posé que si le contexte statique parent a été
  chargé (sinon repli SNI dynamique, jamais de hard-error par connexion)

## Compatibilité `os.execute` (Lua 5.1 / Lua 5.2+ `LUA52COMPAT`)

Le retour de `os.execute` dépend de la build de LuaJIT :

| Build | Succès | Échec |
|-------|--------|-------|
| Lua 5.1 / LuaJIT standard | `0` (number) | code ≠ 0 (number) |
| Lua 5.2+ / LuaJIT `LUA52COMPAT` (ex. Ubuntu 26.04) | `true, "exit", 0` | `nil, "exit", code` (ou `"signal"`) |

Conséquence : **ne jamais tester `ret == 0` seul** — sous `LUA52COMPAT` un
succès (`true`) est alors traité comme un échec. Utiliser `lib.os_exec.exec_ok`
(`src/lib/os_exec.moon`), qui teste `ret == 0 or ret == true`, ou le test
inline équivalent.

Sites concernés (statut de retour testé) : `filter/updater_io.moon`
(`download_file`, `ensure_dir`, `ensure_parent_dir` — le bug initial : tout
téléchargement réussi finissait en « curl échoué » et l'updater sortait en
code 1), `nft_rules.apply` (application du template via `nft -f`),
`nft_extra_rules.apply_from_config` (sonde de la chaîne `forward`, sinon
ré-application systématique), `sync/apply.moon` (`--reload`), `auth/cert_generator`,
`webui/handlers/lists` (`write_list_file`) et `tools/classifier/common` (commit
git). Les helpers I/O de l'updater sont isolés dans `filter/updater_io.moon`
(le script `filter/updater.moon` s'exécute au chargement, donc n'est pas
testable directement) et couverts par `tests/unit/filter/updater_io_spec.moon`
dans les deux sémantiques via un stub de `os.execute`.

## Corrections d'audit (2026-07-16)

Audit global qualité/perf/stabilité (4 volets parallèles : dataplane, filter,
auth/webui, DoH+tests). Corrections appliquées, par ordre de sévérité :

- **Contournement de blocage par la casse DNS (0x20-encoding).**
  `req.domain` n'était jamais lowercasé après parsing alors que les `.bin` de
  domainlists sont construits en minuscules : `MALWARE.Example.COM` échappait
  à `to_domain`/`to_domainlist`. Fix centralisé dans
  `filter.rule.details_of` (une seule normalisation `\lower!` pour tous les
  chemins UDP/DoH ; le SNI a déjà la sienne via `worker_tls.normalize_sni`).
- **Fuite mémoire `ipc.moon` (table `pending`).** Purgée seulement en lecture
  paresseuse ; une question jamais répondue (paquet perdu, upstream muet)
  restait en mémoire indéfiniment dans le worker le plus sollicité. Ajout de
  `ipc.purge_pending`, appelé par `worker_responses` au même point que
  `tcp_state.purge!`/`purge_mac_clients` (tous les 1000 paquets).
- **TLS non vérifié sur le second avis DoH.** `doh.validator.open_client`
  omettait `verify_tls` à `new_client` (défaut `false` chez
  `upstream_doh_curl`) : un attaquant on-path pouvait forger un verdict
  block/sinkhole/redirect sans MITM détectable. Fix : `verify_tls=true`
  explicite.
- **XSS stockés dans la webui admin.** `webui.handlers.filter`
  (`render_kv_editor`/`render_times_editor` : nets/macs/users/times) et
  `webui.handlers.lists` (`handle_list_get`, contenu de fichier dans un
  `<textarea>`) réinjectaient des valeurs admin sans échappement (le DSL
  `auth.html` n'échappe rien par conception). Fix : même helper `esc` que
  `webui.handlers.devices`/`verdicts`.
- **Collision PRNG dans `cert_generator.moon`.** Noms de fichiers temporaires
  dérivés de `os.time!/math.random`, sans `math.randomseed` nulle part dans le
  projet : des enfants forkés par connexion héritant du même état PRNG
  pouvaient produire le même chemin temporaire et s'écraser mutuellement leur
  cert/clé en cours de génération. Fix : suffixe basé sur le PID
  (`ffi.C.getpid!`, unique entre enfants concurrents) + compteur local.
- **`purge_expired` du cache de certificats jamais appelé.** Le SNI client
  (charset filtré mais sans limite de nombre) permettait de forcer un fichier
  `.crt/.key` par SNI distinct, jamais purgé (épuisement de la flash à moyen
  terme). Fix : purge périodique (`auth_cfg.cert_cache_purge_interval`,
  défaut 3600s) dans la boucle principale de `auth.server.run`, seule à vivre
  assez longtemps (chaque enfant forké par connexion n'a qu'une copie COW
  figée du cache). Logique de décision extraite en fonction pure testable
  `should_purge_cert_cache`.
- **Fuites mémoire additionnelles, même schéma que `ipc.pending`** (purge
  uniquement en lecture, jamais en balayage périodique) : verdicts du second
  avis (`second_opinion.purge_verdicts`), cache de lookup strip CNAME
  (`worker_responses.purge_strip_query_cache`), throttle anti-rafale captif
  (`worker_captive.purge_redirect_rl`, gaté par le temps car appelé seulement
  sur SYN/80). Toutes branchées sur un point de purge périodique existant
  (`worker_responses`) ou nouveau mais peu coûteux (`worker_captive`).
- **Cache de verdict SNI keyé par domaine seul.** Deux règles `validate`
  ciblant le même domaine avec des `validate_resolvers` per-règle différents
  partageaient le même verdict pendant `verdict_ttl_s` : le verdict du
  premier résolveur interrogé s'appliquait à tort au second. Fix :
  `worker_tls.validate_sni` inclut les résolveurs dans la clé de cache quand
  ils sont per-règle (table).

**Non-bugs vérifiés** (rapportés par l'audit initial, invalidés à la
relecture du code complet) :
- *"`mac_learner` meurt silencieusement si le bind échoue, sans refork."*
  Faux : `main.moon` reforke déjà inconditionnellement tout worker mort
  (`waitpid` + `restart_fn`), et `create_server` fait déjà `unlink` du socket
  stale avant bind — le refork réussit donc au tour suivant.
- *"`cname_target` ambigu si plusieurs règles `redirect` matchent."* Le code
  accumule en réalité le dernier `cname_target` non-nil jusqu'à la règle
  gagnante incluse (`first_match_wins` arrête la boucle dès le verdict
  trouvé) : le cas nominal (1 règle `cname` + 1 règle `allow`, pattern
  SafeSearch documenté) est correct. Le bug théorique ne se manifeste qu'avec
  plusieurs règles `cname`-only à cibles différentes chevauchant les mêmes
  conditions — mauvaise configuration plutôt que bug du chemin nominal.
  Non corrigé (déprioritisé) ; un fix correct lierait `cname_target` au
  `rule_id` gagnant plutôt qu'à un `cname_target_any` global.

**Vérification (2026-07-16)** : `make test` (1885 tests unitaires + 10 JS) et
`make test-e2e` (94 scénarios G0-G18, homelab libvirt) 100% verts. `make
coverage` (luacov) échoue à écrire son fichier de stats sur run complet
(limite d'infra observée, pas un défaut du projet) ; palliée par un sampler
alternatif maison (`tests/helpers/quick_coverage_setup.lua`, hook `debug.sethook`
en mode *count* plutôt que *line* — même limitation JIT que luacov mais bien
moins d'appels de hook, donc ~4x plus rapide). A permis d'identifier un vrai
gap de test préexistant, corrigé dans la foulée :

- **`filter/init.moon` n'était jamais testé directement** (0 ligne touchée par
  le sampler). Cause : ce module `require`s transitivement `ip_whitelist.moon`,
  dont l'appel `libnft.nft_ctx_new 0` au chargement du module plante
  immédiatement sous le stub FFI de `busted_setup.lua` (`libnft = {}`) — donc
  tout spec qui aurait tenté de `require "filter.init"` échouait au chargement,
  d'où l'absence totale de spec pour ce module (tous les tests existants
  passent par `filter.rule`, la couche sous-jacente, en la court-circuitant).
  Fix : `tests/unit/filter/init_spec.moon` stub `package.loaded["ip_whitelist"]`
  (même pattern que les stubs `ipc`/`dns_ede`/`auth.sessions` déjà en place dans
  `rule_spec.moon`) et couvre `load`/`decide`/`decide_meta`/`get_auth_cfg`/
  `get_sni_cfg`/`get_rules`/`get_rule_on_response`/`run_on_response`, y compris
  l'état "non chargé" et le fallback `allowed_domains` sans règles configurées.

**Déploiement (2026-07-16, 10.35.1.254)** : avant le déploiement réel, un
**bug actif d'installateur** a été détecté en dry-run et corrigé : `detect_cmd`
de `patch_bridge_ifname` (`install-owrt.moon`) utilise la détection sysfs sûre,
mais `ssh_capture`/`capture` fusionnent stdout+stderr (`2>&1`) — et
`UserKnownHostsFile=/dev/null` ne persistant jamais la clé, `ssh` imprime à
**chaque appel** `Warning: Permanently added '<host>' (...) to the list of
known hosts.` sur stderr. Ce bandeau devenait la première ligne captée, et
`detected\match "^%S+"` y lisait `"Warning:"` au lieu du vrai nom d'interface —
**exactement l'incident déjà vécu sur 10.35.1.70** (`bridge_ifname="Warning:"`
→ crash-loop arp/captive ENODEV, cf. plus haut). Fix : `-o LogLevel=ERROR`
ajouté à `ssh_prefix` (supprime le bandeau sans toucher
`StrictHostKeyChecking`) + garde-fou de validation du nom d'interface
(`^[%w%-_.]+$`) dans `patch_bridge_ifname` avant tout patch, en défense en
profondeur. Tests de régression dans `tests/unit/install_owrt_spec.moon`.
Déploiement réel ensuite effectué avec succès (bridge détecté correctement
`"br"`, service sain, aucune régression sur le trafic DNS en cours).

## Corrections d'audit (2026-11-11)

- **Politique SNI perdue après un rechargement SIGHUP.** `main.moon` construisait
  `filter_data` à deux endroits, et la reconstruction post-SIGHUP omettait
  `sni_cfg_cache` : `worker_tls` retombait alors sur les défauts (`strict-443`,
  `enabled`, `both`, fail-closed) au lieu de la section `sni` de la config.
  Correctif : construction unique extraite dans `lib.filter_data.build_filter_data`
  (règles, auth, sni, décision), utilisée aux deux emplacements ; test
  `tests/unit/lib/filter_data_spec.moon`.
- **`worker_nft` : déduplication de lot ignorant `rule_id`.** La clé de
  `try_add_pending` omettait `rule_id` alors que le nom du set nft en dépend
  (`#{rule_id}_#{kind}`) : deux règles autorisant le même couple (client, IP)
  dans un lot voyaient la seconde insertion jetée, son set restant vide.
  Correctif : `rule_id` (tostring, nil toléré) ajouté à la clé ;
  `tests/unit/worker_nft_spec.moon` couvre deux `rule_id` distincts.
- **`mac_learner` : sonde ARP en échec sans réponse ni fermeture.** Dans
  `start_query`, la branche « envoi échoué » posait le cache négatif sans
  répondre `"unknown\n"` ni fermer `client_fd` : fuite de descripteur et
  `mac_learner_ipc.get_mac` bloqué en `recv`. Correctif : helper `reply_unknown`
  (send+close, utilisé à tous les sites) et décision extraite en
  `probe_request` (exportée, testée par `tests/unit/mac_learner_probe_spec.moon`).
- **`worker_responses` : `ip_to_mac` effacé pour le nouveau propriétaire d'une
  IP.** Quand l'entrée d'une ancienne MAC expirait (ou qu'elle changeait d'IP),
  `ip_to_mac[ip] = nil` supprimait le mapping déjà réattribué à une autre MAC.
  Correctif : helper `forget_ip_mapping` qui n'efface que si `ip_to_mac[ip]`
  appartient encore à cette MAC, aux quatre sites ; test dans
  `tests/unit/worker_responses_spec.moon`.
- **Fichier de sessions : cycle lire-modifier-écrire non sérialisé entre enfants
  AUTH.** `handle_login`/`handle_ping`/`handle_logout`/`handle_bye` faisaient
  `load_sessions` puis `write_sessions` sans verrou : deux enfants partis de la
  même photo écrasaient mutuellement leurs sessions (401 intempestif au ping
  suivant), et le temporaire `.new` à nom fixe pouvait être écrit par deux
  processus à la fois. Correctif : helper générique `lib.filelock.with_lock`
  (flock `LOCK_EX` sur `<path>.lock`, ouvert après le fork), exposé par
  `auth.sessions.with_sessions_lock` et utilisé autour des quatre cycles, plus
  par `enrich_session_ip`/`bind_session_mac` ; temporaire de `write_sessions`
  suffixé par le PID. Tests dans `tests/unit/auth/sessions_spec.moon`, dont une
  concurrence réelle à deux processus (20+20 sessions → 40 conservées).
- **Fichier de secrets : temporaire `.new` fixe et écriture non verrouillée.**
  `register_user`/`update_user_hash`/`set_record` (`auth/credentials.moon`)
  copiaient le fichier vers `secrets.new` puis `rename`, sans verrou : deux
  inscriptions concurrentes pouvaient perdre un compte, et le temporaire fixe
  être écrit par deux processus à la fois. Correctif : les trois fonctions
  partagent `rewrite_secrets_file`, qui réécrit le fichier sous
  `lib.filelock.with_lock` avec un temporaire suffixé par le PID (permissions
  0600 conservées avant rename). `update_user_hash` n'a aucun appelant hors du
  module (audit confirmé) mais reste exporté. Tests dans
  `tests/unit/auth/credentials_spec.moon` (inscriptions successives et
  concurrentes, temporaire fixe piégé par un répertoire, mode 0600).
- **Session admin non revalidée après déconnexion.** `check_admin_session`
  (`webui/handlers/admin_auth.moon`) ne vérifiait que signature/expiration du
  token : après `/logout`, un cookie copié restait accepté sur `/admin/*`
  jusqu'à son expiration. Correctif : vérification de session vivante
  factorisée dans `auth.sessions.session_alive`, utilisée par le ping, la page
  de succès `GET /` et l'authentification admin (source unique). Tests dans
  `tests/unit/webui/admin_auth_spec.moon` (session supprimée / MAC différente).
- **Cookie de session sans attribut `Secure`.** Le portail n'est servi qu'en
  HTTPS (`auth.port`) ; le port captif (`auth.captive_port`) ne fait que forger
  des redirections 302 vers le portail, sans jamais poser de cookie. Ajout de
  `Secure` au cookie de session et au cookie d'effacement
  (`auth/handlers.moon`), tests dans `tests/unit/auth/challenge_login_spec.moon`.
- **Garde `nft_sess` redondante entre login et ping.** `refresh_nft`
  (`auth/nft_auth_sets.moon`) retourne immédiatement si `nft_sess` est nil :
  la garde conditionnelle de `handle_login` (et son log
  `server_nft_sess_missing`) était redondante avec l'appel direct de
  `handle_ping`. Garde supprimée côté login pour un comportement unique ;
  `refresh_nft nil` est couvert par `tests/unit/auth/nft_auth_sets_spec.moon`.
- **Index du cache de certificats exécuté sans restriction.** `cert_cache`
  relisait `tmp/cert_cache_index.lua` via `loadstring` + exécution, sans
  environnement isolé : un fichier altéré pouvait appeler n'importe quelle
  fonction globale. Correctif : `setfenv(fn, {})` puis validation stricte du
  résultat (table de `{expires_at=number, accessed_at=number}`, autres entrées
  écartées) ; le log `entries` compte désormais les clés (`#` valait toujours 0
  sur une table associative). L'emplacement relatif n'est pas modifié : le
  service n'appelle aucun `chdir`, donc `tmp/…` se résout dans le répertoire
  courant de procd (typiquement `/`, soit `/tmp/…`). Tests dans
  `tests/unit/auth/cert_cache_spec.moon` (index valide, `os.execute`/boucle
  avec effet de bord rejetés sans marqueur, entrée mal typée écartée).
