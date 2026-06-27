# Résilience du portail captif aux blips réseau — design

Date : 2026-06-27
Statut : approuvé (design), à transformer en plan d'implémentation.

## Contexte et incident déclencheur

Diagnostic d'une « déconnexion » (HAR `deconnexion.har`, ~14:05 CEST = 12:05 GMT,
MAC `74:da:38:61:3b:e3`) corrélé aux logs de custos (`10.35.1.254`) :

- custos **n'a pas planté** ; il servait le DNS de tout le réseau sans interruption
  pendant l'incident (pas d'OOM, pas de watchdog, pas de respawn).
- Le **client** a subi un court blip de connectivité (~12:03:33 → ~12:05:36 GMT,
  ~123 s ; chute des requêtes DNS de ce poste : 34 → 20 → 10 par minute à 12:03–12:04).
- Pendant le blip, la connexion HTTPS de maintien du portail est restée bloquée en
  handshake TLS (`auth_server_tls_handshake_failed attempts=50`), et le navigateur a
  ouvert ~15 connexions simultanées (tempête de retries) → saturation des forks AUTH.
- Config déployée : `heartbeat_interval: 20`, `idle_timeout: 90`. Dans le code,
  `token_expires == session_expires == now + idle_timeout` (unifié volontairement,
  cf. `handlers.moon:155`). Le blip (123 s) dépassant `idle_timeout` (90 s), le
  **token a expiré** → `auth_server_ping_token_invalid err="token expiré"` → 401 →
  la page de succès a alerté puis renvoyé vers le portail (`POST /bye` à 12:05:38).

Conclusion : interruption réseau **côté client**, pas une panne de custos.

## Objectif

Améliorer l'expérience utilisateur lors de ce type d'incident **sans compromettre
le filtrage**. Décision actée : **on ne modifie pas** les durées de vie
token/session/nft (`token.moon`, `handlers.moon`, config). La posture de filtrage
reste strictement inchangée : l'accès nft expire toujours à `idle_timeout`.

Tous les changements sont **confinés au JS embarqué** de `success_page`
(`src/auth/pages.moon`). Sémantique serveur de `/ping`, `/refusals`, `/bye`
inchangée.

## Comportement cible

- **Blip plus court que `idle_timeout`** (cas courant) : aucune éjection, aucune
  alerte ; récupération quasi instantanée au retour du réseau (la session serveur
  n'a pas expiré).
- **Blip plus long que `idle_timeout`** (session réellement expirée, ré-auth
  inévitable) : message clair et **renvoi au plus tôt vers la page de connexion**
  (bandeau rouge + `alert()` si l'onglet est visible + redirection vers `/`),
  plutôt qu'une `alert()` surgissant en pleine coupure.
- **Soulagement du serveur** : suppression de la tempête de requêtes concurrentes
  (un seul ping en vol, pause du polling `/refusals` hors ligne) → moins de
  fork+handshakes TLS simultanés.

## Architecture

Remplacement de la logique ad-hoc actuelle (Worker de ping + `catch` qui redirige
après `idle`, `alert()` sur 2× 401) par une petite **machine à états** explicite
dans le `<script>` de `success_page`.

### États

- `online` : pings au rythme `heartbeat_interval` (Worker conservé), polling
  `/refusals` au rythme `refusals_poll_interval`.
- `reconnecting` : un échec réseau (status 0 / `catch`) a eu lieu. On **n'éjecte
  jamais** sur une panne réseau pure (rediriger hors ligne est inutile). Retries en
  **backoff** (2 s, 4 s, 8 s… plafonné à ~`heartbeat_interval`) au lieu d'attendre
  le prochain tick de 20 s. Polling `/refusals` **suspendu**.
- `expired` : un `401` authentique (session expirée côté serveur ou logout). On
  conserve la confirmation anti-401-isolé (un 2ᵉ ping avant de conclure). Puis :
  bandeau rouge + `alert()` si `visibilityState === 'visible'` + `location.href = '/'`
  (renvoi au plus tôt vers la connexion).

### Transitions

- `online → reconnecting` : `fetch('/ping')` rejeté (réseau).
- `reconnecting → online` : un ping réussit (204) ; reprise du polling `/refusals`.
- `online|reconnecting → expired` : 401 confirmé (2 pings consécutifs).
- `offline` (événement navigateur) : suspension des pings ; `online` (événement) :
  ping immédiat (récupération sans attendre le tick).

### Bug confirmé : login impossible juste après une déconnexion automatique

Observation utilisateur confirmée par les logs : après un retour forcé au portail,
la **première** soumission des identifiants « ne marche pas » ; un **rechargement**
de la page la fait passer.

Séquence type (27 juin 07:34–07:36, MAC `74:da:38:61:3b:e3`) :

```
07:34:42  GET /            (redirection vers le portail après expiration)
07:34:48  POST /challenge  (soumission : nonce émis)
   … aucune connexion de ce client pendant 90 s …
07:36:18  POST /login      (login enfin reçu → login_success immédiat)
```

Le `POST /login` de 07:36:18 n'est précédé d'**aucun nouveau `/challenge`** : il
réutilise le nonce de 07:34:48 (valide, `challenge_ttl` 120 s > 90 s). C'est donc
*le même* `/login`, créé aussitôt après le challenge mais **bloqué ~90 s** avant
d'atteindre le serveur. Le navigateur n'a ouvert aucune connexion pendant ce délai.

**Cause racine** (haute confiance) : la limite de connexions par hôte du navigateur
est saturée par les connexions HTTPS **restées bloquées** pendant le blip (les
pings/`/refusals` finissant en handshake TLS gelé, `attempts=50`, 70–123 s côté
serveur). Le `POST /login` est mis en file (« blocked ») derrière ces sockets
zombies et ne part qu'à leur expiration (~90 s). Le rechargement annule les
requêtes en attente et libère le pool → login immédiat. **Même cause racine que la
déconnexion** : le client laisse trop de sockets bloquées.

**Correctif** : borner **chaque** fetch du portail (`/ping`, `/refusals`) par un
`AbortController` + timeout court (≈ `client_timeout`, ex. 8–10 s), pour que les
sockets gelées soient récupérées en quelques secondes au lieu de ~90 s. Combiné à
l'anti-tempête ci-dessous (un seul ping en vol, pause `/refusals` hors ligne), le
pool de connexions reste libre → la soumission des identifiants après une
déconnexion réussit du premier coup, sans rechargement. La page de login
(`login_page`) n'a pas de polling, donc aucun changement de son code n'est requis ;
le correctif sur la page de succès suffit à ne plus saturer le pool en amont.

### Anti-tempête (protection serveur)

- **Borne de fetch** : `AbortController` + timeout sur `/ping` et `/refusals` (pas
  de socket bloquée > ~`client_timeout`). Un fetch abandonné compte comme un échec
  réseau (→ `reconnecting`), jamais comme un `expired`.
- **Un seul ping en vol** : drapeau « in-flight » ; pas de nouveau ping tant que le
  précédent n'a pas répondu/échoué.
- **Pause `/refusals` hors `online`** : pas de polling pendant `reconnecting` /
  `offline` ; reprise à la reconnexion.
- **`online`/`offline`** complètent le backoff sans le remplacer : `navigator.onLine`
  peut être optimiste, la vérité reste la réussite du ping.

## UX — bandeau d'état + alerte ciblée

Indicateur permanent en haut de la page de succès :

- `online` : « Accès actif » (vert, discret).
- `reconnecting` : « Reconnexion en cours… » (orange, **non bloquant**, page
  utilisable, aucune modale).
- `expired` : « Session expirée — reconnexion nécessaire » (rouge) + `alert()` (si
  onglet visible) + redirection immédiate vers `/`.

L'`alert()` ne se déclenche **que** sur `expired`, jamais pendant un blip réseau
transitoire.

## Cas limites

- Onglet en arrière-plan (`visibilityState !== 'visible'`) : pas de modale, pas
  d'éjection ; resynchronisation au retour au premier plan (comportement actuel
  conservé via `visibilitychange`).
- Mini-navigateur captif sans `Worker`/`navigator.onLine` : repli sur `setInterval`
  simple ; l'absence d'API ne doit jamais lever d'exception ni empêcher les pings.
- `navigator.onLine` optimiste : ne sert qu'à déclencher un ping anticipé ; ne
  décide jamais seul d'un changement d'état.

## Tests (Definition of Done)

- **Unitaire (busted)** : `success_page` contient les nouveaux hooks (machine à
  états, gestion `online`/`offline`, drapeau in-flight, pause `/refusals`,
  bandeau d'état, `alert()` conditionnée à `expired`). Vérifications sur le HTML/JS
  produit, dans la lignée des tests de présence de scripts existants.
- **E2E (Playwright)** :
  1. Portail → login → page de succès ; `context.setOffline(true)` pendant une
     durée **< `idle_timeout`** puis `setOffline(false)` → **aucune** redirection
     vers le login, l'état revient `online` sans ré-auth ; le bandeau passe
     orange puis vert.
  2. Offline pendant une durée **> `idle_timeout`** → état `expired`, bandeau rouge,
     puis redirection vers `/` au retour réseau.
  3. **Non-régression login post-déconnexion** : après l'expiration (scénario 2)
     et le retour réseau, la soumission des identifiants sur la page de login
     réussit **du premier coup** (un seul `POST /challenge` suivi d'un `POST /login`
     aboutissant), sans rechargement manuel ni délai de ~90 s.

## Hors périmètre (volontairement)

- Toute modification des durées de vie token/session/nft et de la config
  (`idle_timeout`, `heartbeat_interval`). Note opérateur : `idle_timeout: 90` avec
  heartbeat 20 s laisse une marge étroite ; l'augmenter élargirait la fenêtre
  couverte par la résilience client, mais prolongerait aussi l'accès nft après le
  départ réel d'un client → décision opérateur, pas un changement de ce design.
- Robustesse serveur du handshake TLS (boucle `attempts=50`) : non traitée ici ;
  l'anti-tempête côté client réduit déjà la pression qui la déclenchait.
- Parité DoH (le plan DoH n'a pas de page de succès / keepalive navigateur).
