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
- `auth/nft_auth_sets.moon` — sous-chaînes nft d'authentification par règle
  (`refresh_rule_auth_sets`, `delete_rule_auth_sets`, `refresh_nft`,
  `for_qualifying_auth_rules`). `refresh_nft` rafraîchit **les deux** familles
  de sets (globaux `add_authenticated*` ET per-règle `_auth_mac`/`_auth_ip*`)
  avec le même TTL : c'est lui qu'appellent login, ping, replay et `/bye`.

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

