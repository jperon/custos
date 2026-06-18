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
   tests. En toute fin d’un développement important, vérifier avec `make coverage`
   (rapport dans `tmp/coverage/`) ; attention, pas trop tôt (car lent). Une
   branche d'erreur non couvrable en unitaire doit l'être par un mock (cf.
   `tests/unit/auth/cert_generator_spec.moon`) ou par les tests e2e.
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
  appelle `query_classified` et applique l'override comme `worker_responses.finalize_a` :
  `block` → `build_nxdomain_response`, `sinkhole` → `build_sinkhole_response`,
  `redirect` → `build_cname_response` **plus** injection nft des cibles
  (`override.a`/`aaaa`) pour que le client les joigne. Fail-open (`nil`) si tous
  les validateurs sont muets.

### Pièges FFI libcurl

- `ffi.load "curl"` échoue sur OpenWrt → essayer `"libcurl.so.4"` en fallback.
- Les fonctions variadiques FFI (`curl_easy_setopt`, …) ne convertissent **pas** les strings Lua en `char *` automatiquement → `ffi.cast("const char *", str)` obligatoire.
- Les callbacks LuaJIT FFI (`ffi.cast "fn_ptr_type", lua_fn`) capturent les upvalues par référence ; réassigner l'upvalue (`recv_buf = {}`) met à jour le slot partagé.

### Limite `from_vlan` en DoH

La condition `from_vlan` lit `req.vlan`, renseigné en UDP via le tag 802.1Q du
paquet L2. En DoH (connexion TCP/TLS), les tags VLAN sont supprimés par les
switches amont → `req.vlan` est toujours `nil` → la condition ne matche jamais.
Utiliser `from_nets` (sous-réseaux IP) pour les règles qui doivent s'appliquer
aux deux workers.

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
- `src/auth/cert.moon` — Added `load_or_generate_sni()` for SNI-aware certs
- `src/auth/server.moon` — Cache initialization on AUTH server startup
