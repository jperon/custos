# Modules DoH

## Modules DoH (`src/doh/`)

| Module | Rôle |
|--------|------|
| `doh.upstream` | Client UDP/53 — new_client / query / close |
| `doh.upstream_doh` | Client DoH wolfSSL **HTTP/1.1, et HTTP/2 si ALPN négocie h2** — même contrat. **Repli** chargé via `doh.upstream_select` quand `doh.upstream_doh_curl` ne peut être chargé/initialisé ; vérifie certificat + nom d'hôte par défaut (`verify_tls=true`), sinon refuse de fonctionner sauf `doh.upstream_fallback_insecure=true`. |
| `doh.upstream_doh_curl` | Client DoH **HTTP/2** via libcurl FFI — même contrat. Transport normal, chargé si `doh.upstream_doh_url` est défini. `ffi.load` essaie `"curl"`, `"libcurl.so.4"` puis `"libcurl.so.4.8.0"` pour compat OpenWrt ; `probe` valide en plus `curl_easy_init` une seule fois. Les args `const char *` vers les varargs `curl_easy_setopt` **doivent** être castés via `ffi.cast "const char *"` (LuaJIT ne convertit pas automatiquement en varargs). |
| `doh.upstream_select` | Sélection unique du transport DoH amont : curl si utilisable, sinon repli wolfSSL (vérifié, non vérifié explicitement autorisé, ou refusé). Ne bascule jamais sur une erreur de requête. |
| `doh.h2_frames` | Utilitaires frames HTTP/2 partagés (constantes, `h2_read_frame`, `h2_write_frame`) |
| `doh.validator` | Second avis DNS synchrone pour `worker_doh`. Interroge `second_opinion.resolvers` (ou per-règle) en UDP ou DoH. Timeout distinct `budget_ms` (UDP) / `doh_budget_ms` (DoH). Le transport DoH est choisi une fois via `doh.upstream_select` avec `role="validator"` : **jamais** de repli non vérifié. `query_classified` renvoie un **override classifié** (`block`/`sinkhole`/`redirect`/`nil`) via `dns_classify.classify` (REFUSED → `block` explicite, comme l'ancien `query_verdict` booléen, toujours exposé en wrapper). |
| `doh.query` | Cœur de traitement DoH : vol captif + `filter.decide` + `doh.validator` + upstream + nft |

### Repli du transport DoH amont : curl → wolfSSL

`doh.upstream_select.select` est appelé par `worker_doh` au démarrage et par
`doh.validator` à la première ouverture d'un endpoint `https://`. Il choisit
**une seule fois** :

- **curl** (`doh.upstream_doh_curl`, HTTP/2) si le module se charge (`ffi.load`
  `curl` → `libcurl.so.4` → `libcurl.so.4.8.0`) et si `probe`
  (`curl_easy_init`) réussit ;
- sinon **`doh.upstream_doh`** (wolfSSL, HTTP/1.1), avec un unique `log_warn`
  `doh_upstream_fallback_wolfssl` portant la raison et le niveau de
  vérification effectif.

Une erreur de requête (timeout, 5xx, refus TLS) ne rebascule jamais : le
descripteur `{transport, verify_tls, make_client, close}` est figé. Si le module
wolfSSL lui-même ne se charge pas, `worker_doh` revient à UDP/53 et loggue
`upstream_doh_unavailable_udp`. Si wolfSSL se charge mais que la vérification
est impossible avec `upstream_fallback_insecure=false`, le repli **refuse**
(chaque ouverture échoue avec `tls_verify_unavailable`) au lieu de contourner la
politique DoH par UDP.

Le repli est **vérifié par défaut** : magasin de CA (`SSL_CERT_FILE`, chemins
usuels, ou `doh.upstream_fallback_ca_file`), SNI (`wolfSSL_UseSNI`, sauf IP
littérale, RFC 6066) et `wolfSSL_check_domain_name`. `verification_available`
teste par `pcall` que la libwolfssl chargée résout les symboles nécessaires
(OpenWrt peut compiler sans) et qu'un magasin est lisible ; sinon `new_client`
vérifié renvoie `tls_verify_unavailable`. Avec
`doh.upstream_fallback_insecure = false` (défaut), le repli **refuse de
fonctionner** ; à `true`, il fonctionne non vérifié avec un `log_warn` explicite.
Le validateur impose `verify_tls=true` et n'accepte jamais le mode non vérifié.

Contrat inchangé : `new_client` / `query` / `close` + champ `_mod`, identiques à
`doh.upstream` et `doh.upstream_doh_curl`, donc `doh.query` n'a pas changé.

Robustesse HTTP/1.1 : `parse_url` accepte IPv6 littéral (crochets retirés pour
`getaddrinfo`/SNI) et `host:port` sans chemin ; `query` borne `Content-Length`
(≤ 65535), gère les écritures partielles, les `WANT_*` bornés, rejette un
statut ≠ 200, un corps tronqué, une réponse courte et corrèle le `txid`.
Tests : `tests/unit/doh/upstream_select_spec.moon`,
`tests/unit/doh/upstream_doh_spec.moon`, `tests/unit/auth/wolfssl_spec.moon`,
`tests/unit/doh_config_spec.moon`.

### Client HTTP/2 du repli wolfSSL (ALPN h2)

`doh.upstream_doh.new_client` propose `h2,http/1.1`
(`CLIENT_ALPN_PROTOCOLS`, `src/auth/ffi_wolfssl.moon`) sur l'objet SSL via
`wolfSSL_UseALPN`, avec l'unique option `WOLFSSL_ALPN_CONTINUE_ON_MISMATCH =
0x02` (attendue par wolfSSL 5.x ; `0x01` vaut `MATCH` et est refusée). Un
serveur sans ALPN laisse le handshake se poursuivre. Le protocole réellement
négocié est lu par `selected_alpn` (`wolfSSL_ALPN_GetProtocol` rend
`WOLFSSL_SUCCESS = 1`) et stocké dans le handle (`alpn`, `h2`). Sans ALPN dans
libwolfssl, ou si le serveur choisit `http/1.1`, `query` garde le chemin
HTTP/1.1 existant, inchangé.

Quand `h2` est vrai, `query` délègue à `query_h2` (`src/doh/upstream_doh.moon`) :
préface client, SETTINGS, POST sur le flux impair 1 (`:method POST`,
`:scheme https`, `:authority`, `:path`, `content-type` et `accept`
`application/dns-message`, `content-length`), DATA découpée à
`SETTINGS_MAX_FRAME_SIZE` (16384). La lecture est bornée : `H2_MAX_FRAMES`,
`H2_MAX_TOTAL_BYTES`, bloc d'en-têtes ≤ 65535, ≤ 64 CONTINUATION. HEADERS +
CONTINUATION sont décodés par `doh.hpack` ; les SETTINGS et PING reçoivent un
ACK ; chaque DATA intermédiaire rend sa fenêtre (`WINDOW_UPDATE` connexion +
flux, sans effet sur la DATA END_STREAM dont la réponse est complète) ;
`:status` 200 est exigé, le corps est plafonné par `MAX_DNS_BODY` et les
trailers (HEADERS sans `:status`) sont ignorés. GOAWAY, RST_STREAM, trame
tronquée, flux inattendu, second `:status` ou corps trop gros → erreur propre
(`h2_goaway`, `h2_rst_stream`, `h2_frame_read_*`, `body_too_large`…) et
connexion fermée ; le prochain appel reconnecte, comme en HTTP/1.1. Les délais
restent ceux de `set_timeouts`.

Helpers partagés ajoutés à `doh.h2_frames` : `h2_read_header_block`,
`h2_data_payload`, `h2_window_update` et la constante `H2_FRAME_RST_STREAM` ;
aucune logique HPACK ni de trame n'est dupliquée.

Tests : `tests/unit/doh/upstream_doh_h2_spec.moon` (faux TLS : réponse
normale, CONTINUATION, trailers, statut ≠ 200, GOAWAY, RST_STREAM, corps trop
gros, trame tronquée, PING et WINDOW_UPDATE, en-têtes de requête) et
`tests/unit/doh/upstream_doh_alpn_spec.moon` (vraie libwolfssl en boucle locale
127.0.0.1 avec certificat px5g dans `./tmp/` : serveur configuré comme
`worker_doh` ↔ client du repli, `get_alpn` vaut `h2` des deux côtés ; client
n'offrant que `http/1.1` → `http/1.1` sans échec ; POST DoH HTTP/2 à travers
`handle_doh_client`/`handle_h2` réels → 200 et réponse DNS ; `pending` si ALPN
ou px5g manque).

### Serveur HTTP/2 : HPACK et routage DoH

`worker_doh.handle_h2` implémente un serveur HTTP/2 (RFC 7540) avec HPACK
(RFC 7541) et le profil DoH (RFC 8484) :

- **Décodage HPACK** (`src/doh/hpack.moon`) : entiers à préfixe, chaînes
  littérales brutes ou Huffman (annexe B), table statique (annexe A), table
  dynamique par connexion avec éviction et `dynamic table size update`, champs
  indexés et littéraux avec/sans indexation ou jamais indexés. Bornes strictes :
  table dynamique ≤ 4096 octets (ou valeur négociée), liste d'en-têtes décodés
  ≤ 16 ko, entiers et chaînes bornés ; toute anomalie (index hors table,
  Huffman invalide, EOS, padding > 7 bits ou non composé de 1, `size update`
  tardif ou trop grand) renvoie `nil, "raison"` sans exception.
- **Frames HEADERS** : `CONTINUATION` (jusqu'à `END_HEADERS`, plafond 64 ko),
  `PADDED` et `PRIORITY` sont gérés ; un bloc indécodable produit
  `GOAWAY COMPRESSION_ERROR` (0x9).
- **Routage** : `:method` et `:path` sont lus dans HPACK. `POST` sur le chemin
  DoH (`/dns-query`, même règle `is_doh_path` que HTTP/1.1) traite le corps
  DATA ; `GET /dns-query?dns=<base64url>` décode la requête (`dns_from_query`).
  Le GET JSON HTTP/1.1 (`?name=…&type=…` + `Accept: application/dns-json`) est
  conservé à l'identique. Autre chemin → `:status 404`, autre méthode → `405`,
  chemin DoH sans paramètre/corps → `400`, sans traiter de DNS. Ces réponses
  n'émettent que HEADERS (END_STREAM), pas de corps.
- **ALPN serveur** (`src/auth/ffi_wolfssl.moon`) : le contexte du worker DoH
  demande `h2,http/1.1` (`ssl.ALPN_PROTOCOLS`), annoncé via
  `wolfSSL_CTX_UseALPN` quand le symbole existe, sinon via `wolfSSL_UseALPN`
  par objet SSL dans `wrap` (libwolfssl 5.8.4 sur OpenWrt n'expose que ce
  dernier). Le portail AUTH garde `http/1.1`
  (`DEFAULT_ALPN_PROTOCOLS`) : la liste est stockée par contexte
  (`alpn_protocols`) et `wrap` ne réapplique que si elle a changé. Aucun
  symbole ALPN → aucun changement de comportement ; les contextes client ne
  sont pas concernés (côté client, voir « Client HTTP/2 du repli wolfSSL »).
  L'option passée est `WOLFSSL_ALPN_CONTINUE_ON_MISMATCH = 0x02` (wolfSSL 5.x
  refuse `0x01`, qui vaut `WOLFSSL_ALPN_MATCH`) pour les trois helpers
  contexte/objet/client ; un échec d'annonce alors que le symbole existe est
  journalisé en `log_warn` (`alpn_ssl_failed`, `alpn_ctx_update_failed`,
  `alpn_context_failed`). Après le handshake, `handle_doh_client` ne refuse
  plus les connexions `h2` : la préface PRI est lue puis routée vers
  `handle_h2`. Détail : `docs/agents/audits.md` § « Client HTTP/2 du repli
  DoH ».

Limites restantes, assumées :

- **un seul flux par connexion** : seul le premier stream portant HEADERS est
  traité ; pas de multiplexage, pas de trailers, et la connexion est fermée
  (`GOAWAY NO_ERROR`) après la réponse. Les clients HTTP/1.1 restent servis par
  le chemin existant ;
- **pas de contrôle de flux** : `WINDOW_UPDATE` est ignoré et le cumul DATA est
  plafonné à 65535 octets (taille maximale d'un message DNS) ;
- **réponse encodée minimalement** : `:status` (index statique) et
  `content-type` (`application/dns-message` ou `application/dns-json`) en
  littéral sans indexation ni Huffman ; pas de table dynamique côté encodeur ;
- **POST HTTP/2 sans contrôle du `content-type`** : le corps est traité comme
  une requête DNS dès lors que le chemin est `/dns-query` (HTTP/1.1 exige
  `application/dns-message` et répond 415 sinon).

Tests : `tests/unit/doh/hpack_spec.moon` (annexe C.2 à C.6 et cas d'erreur),
`tests/unit/worker_doh_spec.moon` (GET binaire et JSON, POST, 404/405/400,
PADDED, PRIORITY, CONTINUATION, padding invalide, stream 0, COMPRESSION_ERROR,
plafonds DATA et frame existants), `tests/unit/auth/wolfssl_spec.moon` (choix
contexte/objet SSL, défaut AUTH http/1.1).

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
`nft_queue.set_ack_rfd`. `worker_nft` n'écrit qu'**un ACK par (flush ×
worker_idx)**, portant le plus grand `seq` appliqué pour ce worker, et non
corrélé au processus émetteur : deux enfants qui exécutent en même temps
`drain_ack` → injections nft → `wait_ack` peuvent encore se voler un ACK
(tous deux partent d'un compteur `seq` identique hérité du fork), même si le
`seq` protège désormais contre un ACK de batch antérieur au sein d'un enfant.

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

