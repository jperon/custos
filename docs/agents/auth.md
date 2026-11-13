# Worker AUTH (structure, portail captif)

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
- `auth/rate_limit.moon` — limiteur de débit **partagé entre les enfants AUTH
  forké**, utilisé par `handle_register` (`POST /register`). Fenêtre **fixe** par
  client, la clé étant la MAC si elle est connue, sinon l'IP. Il autorise
  `auth.register_rate_limit` tentatives par fenêtre de
  `auth.register_rate_window` secondes ; la suivante reçoit `429` +
  `Retry-After` (secondes restantes), sans créer de compte ni toucher au fichier
  de secrets. L'état vit dans `<sessions_file>.ratelimit` : format texte non
  exécutable (une ligne `clé<TAB>compteur<TAB>reset_at`), cycle
  lecture-modification-écriture sous `lib.filelock.with_lock`, purge des entrées
  expirées à chaque écriture et plafond `MAX_ENTRIES` (4096, éviction des
  fenêtres dont l'expiration est la plus proche). Un fichier absent, tronqué ou
  corrompu repart de zéro ; toute erreur interne (verrou, I/O) échoue **ouvert**
  pour ne jamais bloquer une inscription. `register_rate_limit = 0` désactive la
  limitation. Horloge injectable (`check(..., now)`), donc testable sans `sleep`.
- `auth/nft_auth_sets.moon` — sous-chaînes nft d'authentification par règle
  (`refresh_rule_auth_sets`, `delete_rule_auth_sets`, `refresh_nft`,
  `for_qualifying_auth_rules`). `refresh_nft` rafraîchit **les deux** familles
  de sets (globaux `add_authenticated*` ET per-règle `_auth_mac`/`_auth_ip*`)
  avec le même TTL : c'est lui qu'appellent login, ping, replay et `/bye`.

## Certificat TLS : nom SNI demandé, repli sur l'IP locale

Le certificat dynamique du portail suit désormais le nom demandé par le client,
et non plus seulement l'IP locale du socket :

- **Lecture sans consommation** (`src/auth/sni_peek.moon`) : avant `ssl.wrap`,
  `handle_client` observe le ClientHello avec `recv(MSG_PEEK | MSG_DONTWAIT)`
  sur le descripteur brut ; les octets restent dans la file et WolfSSL les relit
  pour le handshake. L'attente se fait par `select`, avec une échéance
  (`client_deadline`) partagée avec la boucle de handshake : le budget total de
  la phase TLS reste `auth.client_timeout`, peek compris. Le préfixe est
  réobservé tant que l'enregistrement annoncé n'est pas complet, plafonné à
  `PEEK_MAX_BYTES` (8192) ; un ClientHello tronqué, non-TLS ou sans extension
  SNI donne `nil`. Le parsing réutilise `auth.sni_extractor.extract_sni`
  (RFC 5246/6066, lui-même basé sur `ipparse`). Aucune exception ne remonte :
  `extract_client_sni` enveloppe lecture + parsing dans un `pcall`.
- **Choix du nom** (`server.cert_name_for`) : le SNI brut est validé et
  normalisé par `auth.cert_name.sanitize_hostname` (longueur ≤ 253, labels
  ≤ 63, `[a-z0-9.-]`, minuscules, pas de point en tête/queue, pas de `..`, pas
  de tiret en bord de label, pas de joker/underscore, pas d'IP littérale, ni
  NUL ni caractère de contrôle). Un nom valide n'est retenu que si
  `cert_cache.can_store` l'accepte ; sinon repli sur l'IP locale **sans
  générer**. Un échec de génération pour le nom SNI est également rattrapé par
  un second essai sur l'IP locale. Un certificat statique configuré
  (`auth.cert`/`auth.key`) reste prioritaire et **le ClientHello n'est même pas
  observé** dans ce cas.
- **Chaîne complète** : `auth.cert.load_static` → `ssl.newcontext` charge le
  fichier configuré (`auth.cert`) avec
  `wolfSSL_CTX_use_certificate_chain_file` quand le symbole existe, avec repli
  sur `wolfSSL_CTX_use_certificate_file`. Un `fullchain.pem` est donc servi en
  entier (feuille + intermédiaires), pour AUTH comme pour DoH.
- **Expiration** : après le chargement du certificat statique,
  `auth.server.run` appelle `auth.cert_expiry.check_cert` et émet un `log_warn`
  `cert_expired` / `cert_expires_soon` (seuil 14 jours). AUTH ne recharge pas
  son certificat sur SIGHUP (seuls les secrets le sont) : le contrôle a lieu au
  démarrage du worker. Tests : `tests/unit/auth/cert_chain_spec.moon`,
  `tests/unit/auth/cert_expiry_spec.moon`.
- **Plafond de noms** : `SNI_CERT_MAX_NAMES = 128` (`server.moon`) est passé à
  `cert_cache.create_cache` ; au-delà, un nom inconnu n'est ni généré ni stocké
  (le nom déjà connu reste servi). `can_store` relit `tmp/cert_cache_index.lua`
  avant de compter : les enfants AUTH sont forqués après le chargement parent,
  leur copie RAM de l'index est figée, et sans relecture le plafond ne
  s'appliquerait jamais. Les noms expirés sont purgés par le parent
  (`cert_cache_purge_interval`, défaut 3600 s).
- **Nom de fichier sûr** (`auth.cert_name.safe_cert_name`) : `cert.load_or_generate_sni`
  n'accepte que des noms DNS validés ou l'IP locale (`getsockname`, IPv6
  comprise) ; tout le reste retombe sur le CN générique `custos`. Le nom ne
  peut donc pas composer de chemin hors de `tmp/`.
- **Écriture atomique et course entre enfants** (`src/auth/cert_files.moon`) :
  chaque fichier `.key`/`.crt` est écrit dans un temporaire propre au PID
  (`<path>.tmp.<pid>_<n>`) puis `os.rename`-é. La paire complète est écrite et
  relue sous un verrou `flock` (`tmp/auth_sni_<nom>_<année>.crt.lock`) : le
  premier enfant écrit les deux fichiers, les suivants voient la paire complète
  et la réutilisent. Comme la paire n'est plus jamais réécrite une fois
  complète, un contexte WolfSSL ne peut pas être construit sur une clé d'une
  génération et un certificat d'une autre ; en cas d'échec du rename du
  certificat, la clé est retirée pour ne pas laisser de paire partielle.
  `cert_cache` applique la même règle à `tmp/certs/<nom>.{crt,key}` (écriture
  atomique + verrou, lecture sous le même verrou) : les PEM relus depuis le
  cache disque sont eux aussi toujours cohérents.

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

## Rechargement des secrets sur SIGHUP (`src/lib/sighup.moon`)

Le superviseur ne transmet SIGHUP qu'à AUTH (`src/main.moon:606-610`) ; AUTH
relit son fichier de secrets (jamais son certificat). L'enfant de connexion qui
vient d'écrire les secrets envoie aussi SIGHUP à son parent
(`src/auth/handlers.moon:36-40`).

Ce signal **ne doit pas** être capté par `ffi.C.signal` + `ffi.cast
"sighandler_t"` d'une fonction Lua : un callback FFI appelé pendant du code
JIT-compilé fait sortir LuaJIT en `PANIC: unprotected error in call to Lua API
(bad callback)` puis `exit(EXIT_FAILURE)` (`lj_ccallback.c:726-730`, condition
`jit_base` non nul), donc `worker_died exit_code=1` et redémarrage par le
superviseur (observé sur custos.lan le 2026-11-13, cf.
[docs/agents/audits.md](docs/agents/audits.md) § « Worker AUTH : SIGHUP sans
callback FFI »).

Le motif retenu est celui du superviseur (`src/main.moon:95-112`) et de
`worker_events` (`src/worker_events.moon:59-73`) : `lib.sighup.create_watcher`
bloque SIGHUP (`sigprocmask(SIG_BLOCK)`) puis ouvre un `signalfd` non bloquant.
`watcher:pending()` vide la file et retourne `true` si au moins un SIGHUP y
était ; `reload_fn` l'appelle à chaque tour de la boucle serveur
(`src/auth/server.moon:271-274`, boucle `:417-418`), soit une latence bornée
par le timeout `socket.select` (0,1 s). Une rafale est coalescée en un seul
rechargement. Si la création du veilleur échoue, le worker logue
`sighup_watch_failed` et sert sans rechargement à chaud — il ne réinstalle
jamais de callback.

Tests : `tests/unit/lib/sighup_spec.moon` (dont « survit à un SIGHUP reçu
pendant une boucle chaude JIT », cas qui tuait le processus de test avec
l'ancien motif).
