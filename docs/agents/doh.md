# Modules DoH

## Modules DoH (`src/doh/`)

| Module | Rôle |
|--------|------|
| `doh.upstream` | Client UDP/53 — new_client / query / close |
| `doh.upstream_doh` | Client DoH HTTP/1.1 wolfSSL — même contrat |
| `doh.upstream_doh_curl` | Client DoH **HTTP/2** via libcurl FFI — même contrat. Chargé si `doh.upstream_doh_url` est défini. `ffi.load` essaie `"curl"` puis `"libcurl.so.4"` pour compat OpenWrt. Les args `const char *` vers les varargs `curl_easy_setopt` **doivent** être castés via `ffi.cast "const char *"` (LuaJIT ne convertit pas automatiquement en varargs). |
| `doh.h2_frames` | Utilitaires frames HTTP/2 partagés (constantes, `h2_read_frame`, `h2_write_frame`) |
| `doh.validator` | Second avis DNS synchrone pour `worker_doh`. Interroge `second_opinion.resolvers` (ou per-règle) en UDP ou DoH. Timeout distinct `budget_ms` (UDP) / `doh_budget_ms` (DoH). `query_classified` renvoie un **override classifié** (`block`/`sinkhole`/`redirect`/`nil`) via `dns_classify.classify` (REFUSED → `block` explicite, comme l'ancien `query_verdict` booléen, toujours exposé en wrapper). |
| `doh.query` | Cœur de traitement DoH : vol captif + `filter.decide` + `doh.validator` + upstream + nft |

### Limites connues du serveur HTTP/2

`worker_doh.handle_h2` implémente un sous-ensemble minimal de HTTP/2 et ne
décode **pas HPACK** : il ne lit ni `:method` ni `:path`, et ne termine le flux
que sur une frame DATA portant END_STREAM. Conséquences assumées, figées par
`tests/unit/worker_doh_spec.moon` :

- un **GET RFC 8484 en HTTP/2** (HEADERS + END_STREAM, sans DATA) est rejeté
  (`nil, "h2_incomplete"` + GOAWAY) ;
- tout **POST HTTP/2**, quel que soit son chemin, est traité comme une requête
  DoH (aucun routage par `:path`).

Les clients HTTP/1.1 (`POST /dns-query`, `GET /dns-query?dns=…`) ne sont pas
concernés. Ne pas s'appuyer sur le HTTP/2 serveur pour du routage ou du GET
RFC 8484 tant qu'HPACK n'est pas implémenté.

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

### Sérialisation de la section critique ACK nft entre enfants `DOH-conn`

`main.moon` alloue **un seul tube ACK nft par worker** (`alloc_ack_pipe`), et
`worker_doh` le transmet à tous les enfants `DOH-conn` (un par connexion) via
`nft_queue.set_ack_rfd`. `worker_nft` n'écrit qu'**un octet par (flush ×
worker_idx)**, sans corrélation au `seq` : deux enfants qui exécutent en même
temps `drain_ack` → injections nft → `wait_ack` se volent les octets. L'un
repart avant que ses IP soient réellement insérées (réponse DNS livrée alors que
le default-deny bloque encore le SYN du client), l'autre attend le timeout.

Correctif : `doh.query.inject_nft_and_wait` (helper unique utilisé par
l'injection de la réponse **et** par les cibles d'override `redirect`) exécute
la séquence sous `lib.filelock.with_lock` :

- verrou **par worker** (`custos-doh-nft-ack-<worker_idx>.lock`, index exposé
  par `nft_queue.get_worker_idx`), dans le répertoire du pidfile du superviseur
  (`/var/run` par défaut) — deux workers DoH distincts ne se sérialisent pas ;
- le fichier est ouvert **après le fork**, à chaque appel (exigence de
  `lib.filelock` : un descripteur hérité partagerait le verrou) ;
- section réduite à `drain_ack` → `inject` → `wait_ack` : ni la résolution
  upstream ni l'écriture de la réponse au client n'y figurent ;
- `wait_ack` est borné par `ACK_TIMEOUT_MS` (150 ms) : un enfant ne peut pas
  tenir le verrou indéfiniment ;
- si l'ouverture du verrou échoue (`with_lock` lève), repli sur l'exécution
  sans verrou (comportement antérieur) avec `log_warn`
  `doh_ack_lock_failed_fallback`, jamais de plantage de l'enfant ;
- une erreur survenue **dans** la section critique (drapeau `started` positionné
  en première ligne) est propagée telle quelle, sans repli : ré-exécuter la
  section après une injection partielle doublerait les insertions nft et
  journaliserait à tort un « échec de verrou ».

Les options passées au helper portent `ack_corr` (`txid:ip_client`), utilisé à
la fois pour les insertions et pour `wait_ack`, y compris sur le chemin
`redirect`.

Le chemin UDP (`worker_responses`, un processus par tube) n'est pas concerné :
il n'appelle pas ce helper et garde son tube privé.

Tests : `tests/unit/doh/query_ack_lock_spec.moon` (ordre sous verrou, repli,
`inject_nft=false`, et non-entrelacement réel de `flock` entre deux processus).

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

