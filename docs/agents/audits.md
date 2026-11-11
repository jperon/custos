# Corrections d'audit

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
- **Connexions DoH sans aucun timeout.** `worker_doh.moon` remettait le socket
  client en bloquant (`settimeout nil`) sans SO_RCVTIMEO/SO_SNDTIMEO, sans
  échéance de handshake et sans `timeout:` de `read_request` : une connexion TCP
  muette suspendait l'enfant `DOH-conn` indéfiniment (`wolfSSL_accept` ou
  `read_request`), jamais récolté → épuisement de processus/descripteurs.
  Correctif : nouvelle clé `doh.client_timeout` (défaut 15 s, documentée
  `doc/CONFIG.md`), helper partagé `lib.http.apply_io_timeouts` (utilisé aussi
  par `auth/server.moon`, comportement inchangé), échéance absolue de handshake
  (`handshake_should_continue`, pure et testée) et `read_request …, timeout:
  client_timeout`. Le chemin HTTP/2 est borné par le même SO_RCVTIMEO.
- **`Content-Length` non borné dans `lib.http.read_request`.** La longueur
  annoncée était lue telle quelle et le corps alloué/relu en entier
  (`ffi.new("uint8_t[?]", size)` côté wolfSSL) : un
  `Content-Length: 268435456` faisait allouer 256 Mo **avant toute
  authentification**, côté DoH comme côté portail AUTH. Correctif :
  `read_request` accepte `opts.max_body` (défaut 65536) et rejette sans lire un
  corps trop grand ou de longueur non entière/négative (`body_too_large`),
  ainsi que trop de lignes d'en-tête ou une ligne trop longue
  (`headers_too_large`, 100 lignes / 8192 octets par défaut). Les deux
  appelants répondent `413` et ferment ; `doh` borne à 65535 (taille DNS
  maximale), le portail via la nouvelle clé `auth.max_body` (défaut 1 Mio,
  documentée), suffisante pour l'éditeur de listes.
- **Frames HTTP/2 non bornées.** `h2_read_frame` lisait `len` (jusqu'à 16 Mo)
  et allouait le payload sans plafond ; `handle_h2` concaténait en outre les DATA
  sans limite. Correctif : `h2_read_frame` rejette `len >
  H2_DEFAULT_MAX_FRAME_SIZE` (16384) **avant** toute lecture (`frame_too_large`),
  `handle_h2` répond GOAWAY `FRAME_SIZE_ERROR` (0x6) et ferme, et le cumul DATA
  est plafonné à 65535 octets (même traitement). Tests :
  `tests/unit/doh/h2_frames_spec.moon`, `tests/unit/worker_doh_spec.moon`.
- **Écritures partielles ignorées.** `h2_write_frame` ignorait le retour de
  `conn\send`, et `send_chunk` de `lib.http` traitait tout retour non-nil comme
  un succès alors que c'est le **nombre d'octets écrits** : wolfSSL et
  `lib.socket` peuvent écrire moins que `#chunk`. Correctif : helper
  `lib.http.send_all` (boucle sur le reliquat `data\sub(n + 1)`, tentatives
  bornées sur `nil`, rend `true` ou `nil, "send_timeout"`), utilisé par
  `send_chunk`/`send_response` et `h2_write_frame`. Ce dernier propage désormais
  l'échec, et `handle_h2` cesse d'écrire après une erreur.
- **Réponses UDP amont non corrélées au txid (`doh.upstream.query`).** Le
  socket « connecté » ne filtre que l'adresse source : une réponse tardive à une
  requête précédente sur un client réutilisé — ou une injection par un tiers
  usurpant l'adresse du résolveur — était acceptée sans connaître le txid.
  `query` compare désormais les 2 premiers octets de la réponse à ceux de la
  requête et exige le bit QR (octet 3, 0x80) ; les datagrammes < 12 octets sont
  ignorés. Limite : 8 datagrammes ignorés et échéance absolue égale au
  `timeout_ms` du client (`new_client` le stocke dans le handle) → sinon
  `nil, "no matching response (txid)"`. `doh.validator` en bénéficie pour son
  transport UDP (il passe par `doh.upstream`) ; les transports DoH/curl (TLS)
  ne sont pas concernés. Tests : `tests/unit/doh/upstream_spec.moon`.
- **`mac_learner` : `recv` bloquants sans timeout (serveur et client).** Le
  serveur (`start_query`) appelait `recv` juste après `accept` sans
  `SO_RCVTIMEO` : un client connecté qui n'écrit jamais figeait l'unique boucle
  `poll` du learner, donc plus aucun `get_mac`/`get_vlan`/`strip_target` servi.
  Côté client (`mac_learner_ipc`), les trois fonctions dupliquaient
  connect/send/recv/close sans borne : un learner lent bloquait le plan de
  données (`worker_responses`/`worker_tls`/`worker_doh`). Correctif : pose de
  `SO_RCVTIMEO` (200 ms) sur le fd accepté, et factorisation client en une
  fonction `query(request)` bornée par `SO_RCVTIMEO`/`SO_SNDTIMEO` (500 ms,
  > `PROBE_TIMEOUT_MS`), timeout → valeur « inconnue » comme aujourd'hui.
  Tests dans `tests/unit/mac_learner_probe_spec.moon` (client muet borné,
  serveur muet borné).
- **`nfqueue.responses` sur plusieurs files : réponses DNS jetées.** Chaque
  worker `resp-qN` a sa propre table `pending` (`ipc.moon`, état privé au
  processus) alors que tous lisent le même pipe question→réponse : une réponse
  livrée à un autre worker que celui qui a lu la question tombait sur
  `get_pending_entry` nil → `NF_DROP`. Le défaut (`responses: "4"`, une seule
  file) n'était pas affecté. Correctif : `config.normalize` ramène
  `nfqueue.responses` à sa **première** file quand la valeur en désigne
  plusieurs, avec l'avertissement `nfqueue_responses_single_queue_only` (log_warn
  si `log` est déjà chargé, sinon stderr — config est chargée par `log.moon`).
  `doc/CONFIG.md` et le schéma webui précisent « une seule file ». Tests dans
  `tests/unit/config_spec.moon` (`"4-5"` → `"4"` + warn, `"4"` inchangé,
  `questions: "0-1"` inchangé).
- **`worker_questions` : `response_rule_ids` écrasés par la dernière question.**
  Dans la boucle `for _, q in ipairs dns_msg.questions`, `response_rule_ids`
  était **réassigné** à chaque question alors que `allow_modifiers` était
  accumulé : sur un paquet multi-questions, les règles `on_response`
  (`dns_strip`, `cname`…) des premières questions étaient perdues. Correctif :
  décisions collectées puis fusionnées par `aggregate_decisions` (déduplication
  ordonnée via `append_unique`, plafond `MAX_RESPONSE_RULE_IDS = 8` aligné sur
  `ipc.encode_msg`, dépassement loggué `response_rule_ids_truncated`). Tests
  dans `tests/unit/worker_questions_aggregate_spec.moon`.
- **`mac_learner.ip16_to_str` : heuristique de famille documentée.** Le message
  `learn` (22 octets) ne porte pas la famille IP ; `ip16_to_str` déduit « IPv4 »
  des octets 5-16 nuls. Une IPv6 à 96 derniers bits nuls (`2001::`, `fe80::`)
  serait donc lue comme une IPv4 — cas limite documenté en LDoc, sans changer le
  format du message (ces adresses ne sont pas des sources d'hôte valides).
  `ip16_to_str` est exporté et figé par un test dans
  `tests/unit/mac_learner_probe_spec.moon` (IPv4 `10.0.0.5` → `"10.0.0.5"`,
  IPv6 `2001:db8::1` → forme IPv6).

- **Tube ACK nft partagé entre enfants `DOH-conn`.** Tous les enfants forkés par
  `worker_doh` héritaient du même descripteur de lecture du tube ACK de leur
  worker (`nft_queue.set_ack_rfd`), alors que `worker_nft` n'émet qu'un octet
  par (flush × worker_idx), sans corrélation : deux enfants concurrents dans
  `drain_ack` → injections nft → `wait_ack` se volaient les ACK, l'un répondant
  avant l'insertion de ses IP (SYN dropé par le default-deny), l'autre attendant
  le timeout. Correctif : helper `doh.query.inject_nft_and_wait`, utilisé aux
  deux sites d'injection, qui tient `lib.filelock.with_lock` sur un verrou par
  `worker_idx` dérivé du répertoire du pidfile ; section bornée par `wait_ack`
  (150 ms), repli sans verrou avec `log_warn` si l'ouverture échoue. Le chemin
  UDP (un processus par tube) est inchangé. Tests :
  `tests/unit/doh/query_ack_lock_spec.moon`. Détail : `docs/agents/doh.md`.

### Outils, sync et installation (branche fix-outils)

- **`sync/apply.moon --reload` et `make reload` ne visaient pas le superviseur.**
  Ils utilisaient `pkill -SIGHUP -f 'luajit.*main'` : sous procd la cmdline est
  `/usr/bin/custos /usr/share/custos/main.lua` (aucune correspondance, donc la
  config synchronisée n'était jamais rechargée), et en lancement manuel
  `luajit lua/main.lua` le motif visait aussi tous les workers forkés (sans
  handler SIGHUP, tués puis reforkés à chaque sync). Correctif : `sync/apply.moon`
  réutilise `lib.pidfile` (`reload_supervisor`, `kill_fn`/`read_pid` injectables,
  aucun repli `pkill`) et la cible `make reload` lit
  `$${CUSTOS_PID_FILE:-/var/run/custos.pid}` ; tests dans
  `tests/unit/sync/apply_spec.moon`.
- **`install-owrt.moon` : injection shell via `--host`/`--user`/`--dest`/`--port`.**
  Seule validation existante : refus des espaces dans l'hôte. `--user
  'root;touch x;'` s'exécutait localement, `--dest '/etc;reboot'` sur le routeur.
  Correctif en deux couches : `parse_args` valide l'hôte
  (`^[%w%.%-:%[%]]+$`), l'utilisateur (`^[%w%._%-]+$`), la destination (chemin
  absolu `^/[%w%._/%-]*$`) et le port (entier 1-65535) puis renvoie
  `nil, message` ; et un helper unique `shell_quote` (apostrophes neutralisées)
  entoure ces valeurs dans `ssh_prefix`/`ssh_run`/`ssh_capture`/`scp_send`.
  Tests dans `tests/unit/install_owrt_spec.moon`.
- **`make sync-init` / `sync-push-init` : cron dupliqué et `REPO`/`HOST` non
  quotés.** La ligne cron était ajoutée à chaque exécution, et `REPO` (interpolé
  dans du shell local puis distant, puis `sync.conf` sourcé par root) permettait
  l'exécution de commandes arbitraires (`REPO='https://x/a;reboot'`). Correctif :
  `HOST`/`REPO` sont **dés-exportés** en tête du Makefile (`unexport HOST REPO`,
  avant le premier `$(shell …)` : make exporte et développe les variables de
  ligne de commande vers toute fonction `$(shell …)`, donc un `$(shell touch …)`
  s'y exécuterait avant validation) puis recopiés dans `SYNC_HOST`/`SYNC_REPO`
  (`$(value HOST)`, sans ré-expansion). Les recettes n'utilisent plus que ces
  variables d'environnement validées (jeu de caractères restreint, échec
  explicite en première ligne), valeur REPO écrite entre apostrophes simples
  dans `sync.conf`, et ligne cron ajoutée seulement si absente
  (`grep -qF … ||`).
- **`setup.sh` référençait un ruleset supprimé et des tables inexistantes.**
  `NFT_RULES` pointait vers `nft-rules/dns-filter.nft` (supprimé), et
  `down`/`status` visaient `table ip/ip6 dns-filter` alors que le ruleset réel
  est `table bridge dns-filter-bridge`. Comme `dns-filter-bridge.nft` est un
  **gabarit à placeholders** rendu par `nft_rules.apply`, `up` ne charge plus
  `nft -f` : il vérifie les dépendances et rappelle que les règles sont
  appliquées par le service au démarrage ; `down`/`status` ciblent la table
  bridge. La détection des bibliothèques capture `ldconfig -p` une fois puis
  teste en shell pur (`case`), ce qui évite un faux échec par SIGPIPE sous
  `pipefail`. `doc/CHEATSHEET.md` est aligné.
- **`install-owrt.moon --dry-run` exécutait quand même des commandes SSH.**
  `capture` (utilisé par `ssh_capture`) ignorait `dry_run` : toute la phase de
  détection (connectivité, gestionnaire de paquets, bridge, existence de
  fichiers…) lançait de vrais `io.popen`/`ssh`. Correctif : en dry-run `capture`
  n'exécute rien, affiche la commande et renvoie `"(dry-run : sortie non
  capturée)"` ; `check_connectivity` et `detect_pkg_manager` court-circuitent
  explicitement (gestionnaire supposé `apk`). Tests dans
  `tests/unit/install_owrt_spec.moon`.
- **`install-owrt.moon` ajoutait un cron quotidien en double de `init.d/custos`.**
  L'installeur écrivait `0 4 * * * /usr/sbin/custos-update` dans
  `/etc/crontabs/root` (sans marqueur, donc jamais retiré par `_cron_remove`) en
  plus du cron géré par `/etc/init.d/custos` (`_cron_add`, marqueur
  `# custos-update-lists`, planification UCI `update_lists_schedule`, défaut
  `0 3 * * *`). Source unique retenue : `init.d/custos` ; l'installeur ne fait
  plus qu'activer/relancer cron et le message « lundi 4h » (faux) est corrigé.
- **`sync/custos-sync-push.sh` : `cp`/`git add` non vérifiés.** Un échec de
  copie ou d'indexation était silencieux puis rapporté « aucun changement à
  publier » par le `git diff --cached --quiet` suivant. Chaque étape
  (`mkdir`, `cp`, `git add`) vérifie désormais son code de retour et sort en
  erreur avec un message sur stderr.
- **`sync/apply.moon` : `io.popen "uname -n"` sans contrôle du résultat.**
  Un `uname -n` vide ou indisponible produisait un chemin
  `devices//config.moon` silencieux. `resolve_hostname` (exportée, injectable)
  échoue désormais explicitement sur stderr, et `main` sort en erreur ;
  testée dans `tests/unit/sync/apply_spec.moon`.

### Portail AUTH et sessions (branche fix-auth)

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
- **Commentaires faux signalés par l'audit.** `auth/credentials.moon`
  annonçait « défaut : 100000 » pour `hash_password` alors que `DEFAULT_ITER =
  10000` (`src/auth/credentials.moon:21`, corrigé au commentaire `:163`) — le
  JS client (`auth/pages.moon` `PBKDF2_ITER = 10000`) est cohérent avec le
  code. `auth/nft_sessions.moon` décrivait `add_authenticated_mac` comme
  écrivant « les sets ip et ip6 » alors qu'elle n'écrit que
  `authenticated_macs`. Enfin `auth/server.moon` importait `extract_sni` sans
  l'utiliser et passait l'**IP locale** (`getsockname`) à `load_or_generate_sni`
  : les certificats dits « SNI » sont en réalité keyés par IP locale (SNI non
  extrait). Import retiré et commentaires/doc corrigés (`server.moon`,
  `.agents/workers.md`, `.agents/px5g_migration.md`, `doc/CONFIG.md`).
- **`lib.filelock.with_lock` : valeurs de retour tronquées.** `pcall fn`
  empaqueté dans `{ ... }` laissait un trou dès que `fn` retournait
  `nil, "erreur"` (`#results` indéfini, message perdu, cas de
  `rewrite_secrets_file`) ; le nombre exact de retours est désormais figé par
  `select "#"` et `unpack` borné. Test : `tests/unit/lib/filelock_spec.moon`.
- **`handle_ping` : MAC nil/"unknown" rejetée à tort.** `session_alive`
  retourne false pour ces MAC, ce qui les faisait passer pour des sessions
  invalidées (401) alors qu'elles n'étaient jamais rejetées avant la branche ;
  la condition d'origine (`mac and mac ~= "unknown" and not sessions[mac]`) est
  restaurée. Test : `tests/unit/auth/ping_stale_token_spec.moon`.
- **`check_admin_session` : session vivante exigée sans MAC connue.** La garde
  verrouillait dehors les tokens à MAC nil/"unknown" et tout appel avec
  `state.sessions_file` nil ; elle ne s'applique plus que si la MAC est connue
  et le fichier défini, le token seul suffisant sinon. Tests :
  `tests/unit/webui/admin_auth_spec.moon` (MAC inconnue acceptée, MAC connue
  sans session refusée, MAC connue avec session acceptée).
### Filtre : qualité de code et bugs résiduels (branche q-filter)

- **B8 (`any_of` / `not`) : `requires_auth` non propagé — non-bug, conservé.**
  Les deux méta-conditions ne publient pas `capabilities.requires_auth` dans
  leur objet enrichi, alors que `from_user` le déclare. Ce n'est pas un défaut
  à corriger en l'état : `nft_compiler` génère une sous-chaîne d'auth par règle
  qui n'accepte que les clients présents dans les sets `_auth_mac/_auth_ip4/_auth_ip6`
  de *cette* règle, et ces sets sont peuplés par `auth.rule_user.rule_requires_auth`,
  qui ne détecte que `from_users`/`from_userlists` au niveau racine de
  `rule.conditions` (pas les conditions imbriquées). Propager le drapeau depuis
  `any_of` rendrait donc une règle worker-only `any_of` impossible à matcher en
  nft (sets jamais peuplés) ; pour `not`, cela restreindrait la règle aux clients
  authentifiés alors que la négation vise l'inverse. Une correction exigerait
  une évolution coordonnée de `src/auth/` (hors périmètre de cette branche).
  Comportement figé par deux tests : `tests/unit/filter/conditions_spec.moon`
  (`any_of` + `from_user`) et `tests/unit/filter/not_spec.moon`
  (`not { from_user }`).
- **Q1 : fonctions `add_*` mortes de `src/nft.moon`.** `add_ip4`, `add_ip6`,
  `add_ip`, `add_mac4`, `add_mac6` et leurs variantes `_quiet` n'étaient
  appelées nulle part : le runtime passe par `nft_queue`/`worker_nft`
  (`run_cmd`), et `worker_tls` n'importe de `nft` que `run_cmd`. Elles
  construisaient par ailleurs des commandes avec `config.nft.set_ip4`
  (…`set_mac6`), clés absentes des `DEFAULTS` de `config.moon` (et donc
  `nil` sur une config minimale). Supprimées, ainsi que leurs quatre lignes
  dans `doc/CONFIG.md` § 5, désormais inexactes : le module n'expose plus que
  `run_cmd` et `cleanup` (`src/nft.moon:41-48`).
- **Q2 : `collect_nets` / `collect_dest_nets` ne collectaient rien.** Les deux
  fonctions (identiques, `collect_dest_nets = collect_nets`) définissaient
  `add_net`/`add_named` sans jamais les appeler et retournaient toujours deux
  tables vides : `source_ipv4/6`, `dest_ipv4/6` et `set_src4/6`, `set_dst4/6`
  étaient donc toujours vides ou `nil` dans `build_rule`. Supprimées avec les
  branches mortes associées (`match_exprs` fallback, rendu des sets src/dst
  dans `render` et `render_sets_only`). Les sets `set_subnet4/6` (alimentés par
  `collect_static_meta`, extension `nft_static`) et les sets de ports sont
  conservés à l'identique.
- **Q3 : modules entièrement morts `filter/lib/cidr_parser.moon` et
  `filter/lib/load_config.moon`.** `cidr_parser` n'était requis que par son
  propre spec ; `load_config` que par un `describe` de
  `tests/unit/filter/filter_spec.moon`. Supprimés avec leurs `.lua` compilés,
  le spec `cidr_parser_spec.moon` et le bloc `load_config` de `filter_spec`
  (la config runtime est chargée par `config.moon`, pas par ce module) ;
  arborescence `README.md` et `tests/README.md` alignées. Note : la validation
  de préfixe qu'aurait pu fournir `cidr_parser` reste absente d'`ipcalc`
  (point B4 de l'audit, hors périmètre de cette branche).
- **Q4 : `include_rule` toujours vrai.** `build_rule` pose inconditionnellement
  `set_dyn_ip4/ip6/mac4/mac6` (lignes « set_dyn_* »), donc le `or` de
  `include_rule` était toujours satisfait et le filtre annoncé par le
  commentaire (n'inclure que si condition nft / auth) ne s'appliquait jamais.
  Simplification explicite : toutes les règles actives sont ajoutées à
  `plan_rules`, avec un commentaire qui décrit le vrai mécanisme (le worker
  injecte dans les sets dynamiques de chaque règle, y compris worker-only ;
  une règle deny sans condition n'a simplement aucun élément). Aucun
  changement de sortie nft.
- **Q5 : en-tête de `src/config.moon` décrivant une forme de `conditions`
  non supportée.** L'exemple montrait `conditions` sous forme de tableau
  d'entrées à clé unique (`- to_domain: …`), alors que `filter.rule.compile_rule`
  itère `pairs condition_table` (dictionnaire, `src/filter/rule.moon:55`).
  Une config recopiée de l'exemple produisait `name=1` puis
  `require "filter.conditions.1"`. En-tête corrigé (dictionnaire, AND implicite)
  et complété par une mention de `any_of`/`not` ; aucun code exécutable changé.
- **Q6 : duplication `from_net` / `from_subnet` / `to_net`.** Les trois
  conditions réécrivaient mot pour mot le bloc `Net` + `eval` + `compile_nft`
  (seul le message différait). Extrait dans
  `src/filter/conditions/net_match.moon` (`build_cidr_condition
  { prop, nft_dir, net_cidr, subject }`), utilisé par les trois modules ; les
  cas spéciaux `_any`/`_none` (from_net/to_net) et la normalisation
  `string | {net,family}` (from_subnet) restent dans chaque module, ainsi que
  leurs messages d'erreur (`require`, autorisation, `source_ip`). Comportement
  et expressions nft identiques, couverts par
  `tests/unit/filter/conditions_spec.moon` / `filter_spec.moon`.
- **T6 : `nft_extra_rules` sans spec directe.** Ajout de
  `tests/unit/nft_extra_rules_spec.moon` : `run_cmd` (succès/échec),
  `init` (ordre UCI inversé, whitespace normalisé, fragments vides ignorés,
  suppression des occurrences existantes par handle, poursuite de l'insertion
  si une suppression échoue, échec d'insertion → `false`), `cleanup` (handles,
  fragments restants en config, état vidé) et `apply_from_config` (chaîne
  présente → populate `filter_ips4/6` + insertions, chaîne absente →
  ré-application éventuelle, ré-application échouée → `false`). Le contexte
  libnftables est stubbé le temps du `require` puis le stub `ffi_defs` partagé
  est restauré.
- **T6 : `ip_whitelist` sans spec directe.** Ajout de
  `tests/unit/ip_whitelist_spec.moon` : `init` purge bien les deux sets puis
  répartit les entrées IPv4/IPv6 (détection par `:`), supprime les espaces
  internes, ignore les entrées vides, n'émet le `add element` que pour la
  famille présente, et tolère un rc nft non nul ; `cleanup` libère le contexte.
  Contexte libnftables stubbé au `require`, stub `ffi_defs` partagé restauré.
- **T6 : `nft_add_helper` sans spec directe.** Ajout de
  `tests/unit/nft_add_helper_spec.moon` : succès immédiat, retry jusqu'au
  succès (arguments transmis intacts), épuisement → `false` avec exactement
  `#add_backoff_ms` tentatives, longueur du tableau = nombre de tentatives,
  retour falsy compté comme échec. Backoffs mis à `{0,0,…}` pour ne pas dormir.
- **T6 : `filter.rule_id` sans spec directe.** Ajout de
  `tests/unit/filter/rule_id_spec.moon` : `sanitize_ascii` (accents/ligatures,
  espaces/tabulations, guillemets/antislash, octets non ASCII, nil),
  `sanitize_id` (minuscules, tirets, fusion des séparateurs, troncature 128),
  `generate` (rule_id > description > index, valeurs blanches) et
  `generate_unique` (suffixes `_2`, `_3`, marquage de `used_ids`, absence de
  table).
- **T6 : `localnets` — parsing des routes et injection non testés.**
  `get_bridge_ifname` l'était déjà (avec le quoting de B7). Ajout dans
  `tests/unit/filter/localnets_spec.moon` de cas pour `inject_localnets` :
  extraction des CIDR `ip -4 route` (masque ≥ 8) puis `ip -6 route`
  (masque ≥ 48), routes hors seuil ignorées, lignes sans CIDR ignorées,
  whitelist existante préservée, et absence totale de commande quand
  `allow_localnets` est faux/absent.
### Dataplane : qualité, performance et tests (branche q-dataplane)

- **`metrics` : `enabled: false` ignoré au chargement.** `src/metrics.moon`
  posait `_enabled = metrics_cfg.enabled or true` : `false or true == true`, le
  drapeau était donc toujours actif (seul `init`, déjà en `!= false`, le
  respectait). Correctif : `metrics_cfg.enabled != false` ; test par
  rechargement du module avec `config.metrics` absent / `false` / `true`
  (`tests/unit/metrics_spec.moon`).
- **`log._rl` : table de rate-limiting jamais purgée.** Une entrée par
  (action, champs discriminants — typiquement MAC/domaine/type) restait en
  mémoire pour toute la vie du worker DNS. Correctif : chaque entrée porte son
  échéance (`exp`) et `_purge_rl` balaie les entrées expirées toutes les
  `RL_PURGE_EVERY` (256) insertions — coût amorti O(1) par insertion, décisions
  de rate-limiting inchangées. `check_rl` accepte un `epoch` explicite pour les
  tests (`tests/unit/log_spec.moon`).
- **`worker_auth_pipeline` et `auth.cert_parser` supprimés (code mort).** Le
  worker n'était forké par personne (`main.moon`) et `send_user_auth_to_nft`
  écrivait sur stdout au lieu du fd nft ; `cert_parser` n'avait pas d'autre
  consommateur. Suppression des deux modules, de leurs `.lua` et specs, et des
  entrées d'arborescence `README.md`. `auth.user_sessions` est conservé : lu par
  `filter/conditions/from_user.moon`.
- **`nfq_loop.set_verdict` supprimé.** Aucun appelant : `worker_responses` a sa
  copie locale et `set_verdict_marked` couvre le chemin nft. Seul l'export
  `set_verdict_marked` subsiste.
- **`parse_packet` factorisé (`packet_utils.parse_dns_packet`).** Les deux
  copies quasi identiques de `worker_questions`/`worker_responses` (IPv4/IPv6,
  extensions IPv6, UDP, réassemblage DNS-TCP, `parse_dns`) sont remplacées par
  une fonction unique retournant `ip, l4, dns_msg, dns_raw, ip_ihl` ; le
  réassembleur TCP reste un argument, donc l'état par processus est préservé.
  Tests dans `tests/unit/packet_utils_spec.moon`.
- **Helpers IPC factorisés (`lib.ipc_hex`).** `split_fields`, `from_hex`,
  `to_hex` et `is_valid_timeout` étaient définis deux fois (émetteur `ipc` vs
  récepteurs `worker_nft`/`nft_queue`), et les validateurs `is_ipv4_str`/
  `is_ipv6_str`/`is_valid_mac` d'`ipc` doublonnaient `is_ipv4`/`is_ipv6`/
  `is_mac` de `worker_nft`. Source unique dans `src/lib/ipc_hex.moon`
  (`tests/unit/lib/ipc_hex_spec.moon`).
- **`encode_ip16` factorisé.** Les quatre producteurs de messages binaires
  (`worker_questions` learn, `worker_auth_queue` auth, `worker_doh_vlan` VLAN,
  `worker_arp_sniffer` learn + branche TLLA) répétaient la convention « IPv4 +
  12 zéros / IPv6 tel quel ». `lib.ipc_hex.encode_ip16` la centralise (copie
  `ffi.copy`, même format consommé par `mac_learner.ip16_to_str`).
- **`tsv_field` factorisé (`lib.tsv`).** Le marqueur de champ vide `-` du
  protocole `worker_events` était défini trois fois (`worker_questions`,
  `worker_responses`, `worker_tls`) ; une seule définition partagée
  (`tests/unit/lib/tsv_spec.moon`).
- **`main.moon` réutilise `lib.bridge_detect.read_lines`.** La copie locale de
  lecture de lignes (`io.popen`) disparaît ; `read_lines` est exportée et
  utilisée pour `brif/` et le repli `bridge_slave`. Tests ajoutés dans
  `tests/unit/lib/bridge_detect_spec.moon`.
- **Export fantôme `dns_tcp_complete` retiré.** `worker_questions` et
  `worker_responses` exposaient cette clé sans l'importer (toujours `nil`) ; le
  vrai helper reste dans `packet_utils`.
- **`lib.ttl_set` utilisé pour `negative_cache` et les caches RTP.**
  `mac_learner.negative_cache` et les deux tables `worker_reject`
  (`rtp_passthrough`, `rtp_passthrough_dport`) ne stockaient qu'une échéance et
  étaient purgés à la main. Ils deviennent des `ttl_set` bornés (expiration
  paresseuse + élagage à l'insertion) ; `ttl_set.remaining` est ajouté pour que
  le log DEBUG RTP conserve le TTL restant, et `probe_request` reçoit le
  `ttl_set` au lieu d'un epoch explicite. Nuance : `ttl_set` expire à
  `exp <= maintenant` alors que les vérifications précédentes acceptaient
  `maintenant == exp` — écart d'au plus 1 s, sans effet observable.
- **Duplications mineures supprimées.** `mac_learner.sh_quote` → 
  `lib.shquote.shquote` ; `vlan_lookup`/`strip_lookup` partagent
  `expiring_lookup`.
- **Logs DEBUG du chemin par paquet gardés par `level_enabled`.** Chaque
  `log_debug` par paquet de `nfq_loop`, `worker_responses`, `worker_tls`,
  `worker_reject`, `worker_sip`, `worker_doh_vlan` et `worker_auth_queue`
  allouait la closure (et ses captures) avant que `write_log` ne filtre le
  niveau ; les sites sont désormais sous `if level_enabled "DEBUG"` (même garde
  que `worker_questions`), et `worker_tls.debug_tls` sort avant de construire sa
  table de métadonnées. Le stub `log` de `tests/helpers/busted_setup.moon`
  expose `level_enabled -> true` pour que les thunks continuent de s'exécuter
  sous test.
- **`worker_sip` : plus de `require` par paquet.** `format_ip` appelait
  `require("ipparse.l3.ip")` à chaque invocation (2×/paquet) et
  `allow_mac_ip`/`allow_sip_peer` `require("nft_queue")` à chaque insertion ;
  ils utilisent `ipparse_ip.ip2s` et un `nft_q` mémorisé par `run()` (repli
  paresseux pour les specs qui n'appellent pas `run`).
- **`worker_events.note_verdict` : index O(1).** Chaque verdict DNS balayait
  jusqu'à `VERDICTS_MAX` (8192) entrées puis déplaçait l'entrée en tête
  (`table.remove` + `table.insert`). L'index `mac|qname|decision` et un numéro
  de séquence rendent la déduplication O(1) ; l'ordre « plus récent d'abord »
  est reconstruit une fois par flush (tri par séquence), donc
  `recent-verdicts.tsv` garde son ordre pour `/refusals` et l'UI. À saturation,
  c'est l'entrée insérée le plus ancien qui est évincée (au lieu de la moins
  récemment vue) — écart assumé et sans effet sur la déduplication ni les
  compteurs. Tests : `tests/unit/worker_events_spec.moon`.
- **Tests `mac_learner` : plus de serveurs orphelins.** Cause racine : le client
  IPC envoie sa requête après `connect()` ; si le serveur de test a déjà fermé,
  le `send` déclenche **SIGPIPE** et tue Busted avant `after_each`, laissant le
  `luajit ./tmp/mac_server_test.lua` en vie. Le spec ignore SIGPIPE, enregistre
  chaque PID dès sa lecture et son teardown tue puis **attend** la disparition
  (`kill -0` en boucle, SIGKILL après ~2 s) ; un test vérifie qu'aucun processus
  ne survit. *Constat résiduel non corrigé (hors périmètre)* :
  `mac_learner_ipc.query` envoie sans `MSG_NOSIGNAL`, donc en production un
  learner qui ferme avant le `send` peut tuer le worker appelant par SIGPIPE.
- **Non retenus après vérification.** Q8 (`mac_learner_ipc`) était déjà réglé
  par la factorisation `query(request)` (commit 4ab5364) ; Q12 (découpage des
  fonctions monolithiques `handle_sni_packet`/`handle_response`/`finalize_a`)
  n'a pas été entrepris : refonte structurelle sans défaut fonctionnel, risque
  de régression trop élevé pour cette passe. P4 (réécriture intégrale de
  `recent-verdicts.tsv` à chaque flush) n'a pas été modifié : les deux pistes du
  rapport (seuil de changement, réduction de `VERDICTS_MAX`) changent la
  fraîcheur ou l'historique exposés, et le throttle de 5 s borne déjà la
  fréquence. Q2 (accesseurs `metrics` sans lecteur) : seul le drapeau
  `enabled` était un bug (corrigé) ; les accesseurs sont conservés.

### Portail AUTH et webui : qualité de code et couverture (branche q-auth)

Suite du volet `auth-webui` de l'audit du 2026-11-11 (rapport Q1-Q5/T1-T10).
État constaté dans le code, puis actions :

- **Q1 — déjà fait.** `webui.util` est la source unique (`esc`, `parse_form`) ;
  aucun handler ne réimplémente plus le décodage urlencodé ni l'échappement
  (`parse_form_multi` de `filter.moon` reste un décodeur distinct multi-valeurs).
- **Q2 — code mort supprimé.** `src/auth/worker_conn.moon` (jamais requis,
  `string.pack` indisponible sous LuaJIT 5.1), `credentials.update_user_hash`,
  `cert.load_or_generate`, `cert_generator.generate_rsa_key` (appelé des seuls
  tests ; le test de régression du nom temporaire unique est rejoué sur
  `generate_self_signed`) et le champ caché `<name>_present` de
  `webui.handlers.config` (jamais lu par `build_section`). L'import
  `extract_sni` de `server.moon` avait déjà été retiré (fix-auth).
- **Q3 — déjà fait**, complété : les trois points (défaut 10000, set MAC seul,
  IP locale et non SNI) étaient corrigés ; les deux dernières mentions de
  « cache SNI dynamique » de `server.moon` et `.agents/workers.md` sont
  alignées sur l'IP locale réelle.
- **Q4 — corrigé.** `serializer.is_array` ne testait que `1..#t` : une table
  mixte (`{ "a", "b", cle = "v" }`) ou à clés non contiguës perdait ses clés
  hors séquence à l'écriture. `is_array` exige maintenant que toutes les clés
  soient des entiers de `1..#t` (comptage) ; sinon forme associative `[k]: v`.
  Tests de sérialisation et de round-trip.
- **Q5 — déjà fait** (le log `entries` compte les clés). Reste non corrigé,
  hors du point tel que rapporté : `stats().size_disk = #persistent_index`
  vaut toujours 0 (table associative) ; `stats` n'a aucun appelant hors tests.
- **T1 — couvert.** `tests/unit/auth/register_spec.moon` : 9 cas sur
  `handle_register` (voie hachage client : succès/état/reload, username
  invalide 400, record invalide 400, doublon 409, échec set_record 500,
  échec de signal ; repli plaintext : succès vérifiable, politique 401,
  champs manquants 400, doublon 409). Le cas « échec set_record » a révélé
  que `with_lock` levait hors du contrat de `rewrite_secrets_file` quand le
  verrou est inouvrable : corrigé dans un commit `fix(auth.credentials)`
  (pcall + retour `nil, message`), test unitaire dans
  `credentials_spec.moon`.
- **T2 — couvert.** `is_admin_user` via `handle_login` (lien `/admin` de la
  page de succès selon liste/allow_all) et chaîne `GET /admin/` dans
  `router_spec` (liste vide + allow_all → 200 ; allow_all=false → 403).
  Aucun défaut de configuration modifié.
- **T3, T4, T5, T6, T7, T10 — déjà couverts** : XSS règles / `render_field` /
  `?mac=` (T3), conservation des clés hors schéma (T4), nom MAC→nom via
  `handle_verdicts_get` (T5), indice `1.5` au réordonnancement (T6), 409 sur
  cible de renommage/création existante (T7), lien `/logout` du dashboard
  (T10).
- **T8 — partiel.** Poison d'index déjà couvert (`setfenv` vide, marqueurs
  `os.execute`/boucle). La concurrence d'écriture des fichiers de
  certificats (B13) n'est pas couverte : les écritures directes de
  `cert.moon`/`cert_cache.save_cert_to_disk` ne sont pas atomiques et aucun
  point d'injection ne permet un test déterministe sans correction préalable.
- **T9 — adapté.** `parse_query` n'existe plus (le routeur et les handlers
  utilisent `webui.util.parse_form`) ; cas limites ajoutés à
  `util_spec.moon` : paire sans `=`, séquence `%` invalide, `&` final.

**Vérification (2026-11-11, branche q-auth)** : `make check` OK ; `make test`
= 2109 successes / 0 failures / 0 errors ; `make test-js` = 12 pass.
`make test-e2e` a été tenté mais n'est pas concluant dans cet environnement :
plusieurs suites e2e d'autres worktrees tournaient simultanément sur le même
homelab libvirt (redémarrages du service concurrents), d'où des échecs
HTTP 000 côté portail et des écarts DNS/IPv6/EDE sans rapport avec les
fichiers modifiés ici.

### Volet DoH et outils : qualité de code (branche q-doh)

Suite du volet « doh-outils » de l'audit du 2026-11-11 (rapport Q1-Q17 ;
les bugs B1-B15 ont été traités séparément). État constaté dans le code, puis
actions :

- **Q1 — corrigé.** `src/worker_doh.moon` : la ligne
  `s = s\gsub "%-", "-"\gsub "_", "_"` était sans effet (le second `gsub`
  portait sur la littérale `"-"`). Supprimée ; `-`/`_` sont déjà mappés par
  `b64_chars`, le padding est calculé juste après. Comportement inchangé
  (`tests/unit/worker_doh_spec.moon`).
- **Q2 — corrigé.** `doh.query` : la closure `famille → IP client` était
  dupliquée (bloc redirect du validateur + injection principale). Extraite en
  `client_addr_for(client_ip)`, utilisée aux deux sites ; le site
  `worker_responses` est hors périmètre de cette branche.
- **Q3 — corrigé.** `doh.query.process_query` normalise désormais `questions`
  une seule fois, avant le bloc de vol captif, et réutilise la variable dans
  la boucle d'évaluation.
- **Q4/Q5 — non modifiés (décision laissée à l'utilisateur).** Constat toujours
  exact : `idefix2filter.moon` appelle `split_conditions` (défini nulle part,
  `:120`), génère `to_domains: [local, …]` invalide en MoonScript (`:117`), et
  accumule sa sortie avec `..=` en boucle. Le script n'est référencé nulle part
  (ni Makefile, ni doc, ni test). Aucune suppression/correction faite.
- **Q6 — documentation seule.** `src/doh/upstream_doh.moon` n'est requis par
  aucun fichier de `src/` (seul `doh.upstream_doh_curl` est chargé par
  `worker_doh` et `doh.validator`). Le module et sa spec sont conservés ;
  `docs/agents/doh.md` précise désormais « non chargé en production » et le
  commentaire de `validator.moon` pointe vers `doh.upstream_doh_curl`.
- **Q7 — corrigé.** Commentaires de `tests/helpers/quick_coverage_setup.lua`
  alignés sur les constantes réelles : flush ~50 ms (`0.05`) et échantillonnage
  toutes les 50 instructions VM (et non ~3 s / 500).
- **Q8 — corrigé.** `INCLUDE_PREFIX`, `EXCLUDE_PATTERNS` et `included()` étaient
  recopiés dans le hook et le rapport. Nouveau module
  `tests/helpers/coverage_filters.moon` requis par les deux ; le rapport filtre
  en outre sa liste `find` avec `included()`, ce qui supprime la troisième copie
  des exclusions.
- **Q9/Q10/Q11 — déjà traités** (vérifiés) : `install_updater` n'ajoute plus de
  cron (géré par l'init.d, marqueur `# custos-update-lists`) et le message dit
  « cron géré par /etc/init.d/custos » ; `ssh_run_script` n'existe plus ;
  `capture()` court-circuite en dry-run (aucun `io.popen`) et
  `tests/unit/install_owrt_spec.moon` couvre `capture`, `check_connectivity` et
  `detect_pkg_manager` sans commande réelle.
- **Q12 — corrigé.** `packaging/openwrt/custos/Makefile` installe désormais
  `/usr/sbin/custos-update` et `/etc/hotplug.d/net/30-custos-rps`, tous deux
  utilisés par l'init.d/documentation mais absents du paquet.
- **Q13 — non modifié (options).** `packaging/openwrt/custos/files/etc/config.moon`
  n'est installé par aucune règle et `/etc/config.moon` n'est lu par personne
  (le runtime lit `/etc/custos/config.moon`). Deux options : supprimer le
  fichier, ou le conserver comme modèle manuel en le marquant explicitement
  dans son en-tête. La suppression ferait perdre le contenu de référence et
  l'installation serait trompeuse : décision laissée à l'utilisateur.
  **Traité depuis** (branche `d-pkgconf`) : voir « Configuration par défaut du
  paquet » plus bas — fichier orphelin supprimé après vérification clé par clé.
- **Q14 — corrigé.** Commentaire de `worker_doh.moon` sur le socket UDP amont :
  `fork(2)` duplique bien les descripteurs ; chaque enfant ouvre son socket
  pour garder l'état du flux UDP privé (une réponse ne doit pas être lue par le
  mauvais enfant).
- **Q15 — corrigé.** `tests/helpers/mini_busted.moon` compte désormais les
  échecs de `setup`, `before_each`, `after_each` et `teardown` dans `failed`
  (au lieu d'un simple `print`/`pcall` jeté) : la suite renvoie 1. Test de
  régression `tests/unit/mini_busted_spec.moon` (instance neuve chargée par
  `loadfile`). Le runner VM local (`luajit tests/run_vm_tests.lua`) ne révèle
  aucun `setup` cassé jusque-là masqué ; ses 39 échecs restants sont des écarts
  de compatibilité préexistants de `mini_busted` avec Busted (`assert.are_not`,
  `assert.same`…), sans rapport avec les hooks.
- **Q16 — déjà traité** (vérifié) : `sync/custos-sync-push.sh` teste `cp` et
  `git add` (`|| { … exit 1; }`) avant le `git diff --cached` ; `sh -n` OK sur
  les scripts `sync/`, `setup.sh` et les fichiers du paquet. `shellcheck` n'est
  pas disponible dans le flake.
- **Q17 — corrigé.** `sync/apply.moon` valide désormais le nom d'hôte
  (`valid_hostname` : `[A-Za-z0-9_.-]`, ni `.` ni `..`) pour `--hostname` comme
  pour la sortie de `uname -n` : `--hostname ../../etc` échoue en code 1 au lieu
  de lire `devices/../../etc/config.moon`. Tests dans
  `tests/unit/sync/apply_spec.moon`.

**Vérification (2026-11-11, branche q-doh)** : `make check` OK ; `make test`
= 2127 successes / 0 failures / 0 errors ; `make test-js` = 12 pass.
### Globales nil (branche fix-globals)

MoonScript rend **locale au bloc** toute variable assignée dans un bloc
(boucle, `if`, `pcall`…) : lue ensuite hors de ce bloc — ou hors de la fonction
qui l'assigne — elle compile en **lecture de globale**, donc en `nil`, sans
aucune erreur de compilation. Un balayage du bytecode (`luajit -bl`, instructions
`GGET`) a trouvé quatre cas réels, chacun corrigé avec un test qui échoue avant
et passe après ; le contrôle est désormais automatisé dans `make check`
(`tools/check_globals.sh`, cf. [.agents/testing.md](../../.agents/testing.md)).

- **`lib.socket` : `EINPROGRESS` jamais défini → tout `connect()` non bloquant
  échouait.** `connect()` testait `if errno == EINPROGRESS`, mais seule
  `EAGAIN = 11` existait : la comparaison était toujours fausse, donc un
  `connect()` non bloquant — cas normal dès que `settimeout` a posé
  `O_NONBLOCK` — levait `connect() failed: errno=115` au lieu de rendre `nil`
  (résultat à récupérer via `select()`/`SO_ERROR`). Correctif :
  `EINPROGRESS = 115` (Linux) à côté de `EAGAIN`/`EWOULDBLOCK` (tous deux déjà
  définis ; les autres codes de ce fichier — `EINTR`, `ECONNABORTED` — sont des
  littéraux). Test : `tests/unit/socket_spec.moon` (connect non bloquant vers
  `127.0.0.1:1` ; sur Linux le noyau diffère toujours le verdict, ce qui rend le
  cas déterministe).
- **`nft_add_helper` : `last_err` perdue → log d'épuisement sans l'erreur.**
  `last_err` était assignée dans la boucle de retries et lue après : la lecture
  compilait en globale nil, si bien que `nft_add_retries_exhausted` loguait
  toujours `err=""` au lieu de l'erreur de la dernière tentative (le diagnostic
  de l'échec nft était perdu). Correctif : `last_err = nil` déclarée avant la
  boucle. Test : `tests/unit/nft_add_helper_spec.moon`, qui recharge le module
  avec un `log` stub pour capturer les champs logués.
- **`auth.server` : `hs_err` perdue → log de handshake sans l'erreur.** Même
  motif dans la boucle de handshake de `handle_client` : `hs_err` était locale à
  la boucle, la lecture après la boucle (`server_tls_handshake_failed`) valait
  nil et le log affichait toujours « max attempts reached », masquant l'erreur
  réelle (`tls_error`, etc.). `ok_hs` n'était lu que dans la boucle : inchangé.
  Correctif : `hs_err = nil` avant la boucle. Test :
  `tests/unit/auth/server_handshake_log_spec.moon` (déclenche `handle_client`
  via `dispatch_connection` avec un `fork_fn` synchrone et un `ssl.wrap` stub
  dont `dohandshake` rend `(false, "tls_error")`).
- **`worker_tls` : `auth_sessions_file` nil sur le hot-path SNI.** La variable
  n'était assignée que dans `run()` (`auth_sessions_file = auth_cfg.sessions_file
  or auth_sessions_file`), donc locale à `run()` : la lecture du hot-path
  (`user: user_for_mac mac_str, ip_src_str, auth_sessions_file`, dans
  `handle_sni_packet`) compilait en globale nil. Avec un chemin nil,
  `user_for_mac` → `session_for_mac` → `read_cached nil` → `load_sessions(nil)`
  rend `{}` : aucune session trouvée, **sans erreur**, et le champ `user` de la
  requête SNI restait toujours nil. La condition `from_user` perdait donc son
  chemin rapide « utilisateur déjà connu » (le premier indice de `req.user`) et
  refaisait une lecture de sessions ; ses verdicts restaient corrects grâce à
  son repli. Correctif : chemin initialisé au niveau module depuis `config.auth`
  avec la même valeur par défaut que `worker_responses`
  (`"/tmp/sessions.lua"`), puis affiné dans `run()` par
  `filter.get_auth_cfg().sessions_file` ; exporté pour le test
  `tests/unit/worker_tls_sessions_file_spec.moon`.
- **Prévention.** `tools/check_globals.sh` (appelé par `make check`) balaie le
  bytecode de tout `lua/**.lua` (hors `lua/ipparse/` — sous-module amont — et
  hors runtime MoonScript), relève les `GGET` et échoue sur toute globale hors
  liste blanche explicite (base Lua 5.1, bibliothèques standard, `bit`/`jit` de
  LuaJIT, `arg` ; `ffi` volontairement absent car non global sous LuaJIT).

### Dataplane et synchronisation (branche fix-ackseq)

- **ACK nft non séquencé : verdict posé avant la fin des insertions d'un inject.**
  `worker_nft` n'émettait qu'un octet anonyme par (flush × worker) et
  `nft_queue.wait_ack` retournait `true` au premier octet lu, sans comparer au
  `pending_seq` (qui ne servait qu'au log). Or `MAX_BATCH = 64` coupe un `inject`
  de plus de 64 éléments : le flush du premier batch acquittait, et le producteur
  posait `NF_ACCEPT` avant l'insertion des éléments restants (premier paquet
  suivant droppé par le default-deny). Correctif : l'ACK est un enregistrement de
  taille fixe (8 octets, `uint64` natif, un seul `write` ≤ `PIPE_BUF` donc
  atomique) portant le plus grand `seq` appliqué pour ce worker ; `wait_ack`
  n'accepte un ACK que si `seq >= pending_seq`, ignore les ACK antérieurs
  (attente poursuivie dans le même budget `ACK_TIMEOUT_MS`, échéance monotone
  sans allongement), reconstitue un enregistrement lu en plusieurs morceaux et
  laisse `drain_ack` vider le tube, fragments compris. Le compteur `seq` est
  monotone par processus sans rebouclage (2^53) ; un redémarrage repart de zéro
  et les ACK résiduels sont purgés par `drain_ack` avant l'injection suivante.
  Un échec de transaction nft reste acquitté comme avant (sémantique conservée :
  l'ACK acquitte le traitement du batch, le producteur applique
  `nft.add_failure_policy`). Limite résiduelle du DoH (plusieurs enfants `fork`
  partageant un tube et un compteur `seq` initial identique) documentée dans
  `docs/agents/doh.md`. Format documenté dans `.agents/workers.md` et
  `.agents/architecture.md`. Tests : `tests/unit/nft_queue_spec.moon`
  (ACK du bon seq, ACK antérieur seul → timeout, antérieur puis bon seq, lecture
  en deux morceaux, `drain_ack` d'un ACK partiel) et
  `tests/unit/worker_nft_spec.moon` (65 éléments → deux ACK, le second portant
  le dernier `seq`).

- **`custos-sync.sh` : téléchargement de configuration non contraint en HTTPS.**
  L'archive téléchargée est fusionnée dans `/etc/custos/config.moon`, chargée et
  exécutée en root ; le `wget -q -O` (busybox) n'offrait aucune garantie explicite
  de vérification TLS et une URL `http://` était acceptée telle quelle. Correctif :
  refus de tout `CUSTOS_CONFIG_REPO` ne commençant pas par `https://` (message
  clair, exit 1, avant toute écriture) et téléchargement par `curl --fail
  --silent --show-error --location --proto '=https' --proto-redir '=https'`
  (vérification des certificats par défaut, jamais `--insecure`), avec repli
  `wget` uniquement quand `curl` est absent. Le chemin du fichier de conf reste
  `/etc/custos/sync.conf`, surchargeable par `CUSTOS_SYNC_CONF` pour les tests.
  Test : `tests/unit/sync/custos_sync_spec.moon` (PATH factice : URL `http://`
  refusée sans appel curl, arguments curl exacts, wget jamais appelé quand curl
  est présent).
### Dataplane — couverture de tests (branche t-dataplane)

Volet « qualité / trous de tests » du rapport `rapport-dataplane-qualite.md`
(points T1-T9). Le code ayant été remanié depuis (parsing partagé
`packet_utils.parse_dns_packet`, helpers `lib.ipc_hex`/`lib.tsv`), chaque point
a été revérifié dans l'arbre courant avant d'écrire un test ; les fonctions
testables uniquement depuis une fermeture ont été ajoutées à la table de
retour de leur module, sans changement de comportement.

- **T1 — worker_questions : décision couverte.** `parse_packet` était déjà
  couvert via `packet_utils.parse_dns_packet` (`tests/unit/packet_utils_spec.moon`,
  cas tronqué/`tcp_control` inclus) et l'agrégation multi-questions par
  `worker_questions_aggregate_spec.moon`. Ajout de
  `tests/unit/worker_questions_spec.moon` : `list_from_condition_reason`,
  format TSV de `write_event`, et `handle_question` avec pipes réels (messages
  `ipc.write_msg`/`write_refused_msg` décodés par `ipc.decode_msg`), verdicts
  UDP IPv4/IPv6, question acceptée même refusée (la réponse est filtrée côté
  response), `NF_DROP` sur échec d'écriture IPC (fail-closed) et sur paquet
  tronqué. Exports ajoutés : `handle_question`, `write_event`,
  `list_from_condition_reason`.
- **T2 — mac_prober : couvert.** Export de `build_arp_request`,
  `build_ns_frame`, `icmpv6_cksum`, `parse_arp_reply`, `parse_na_reply`,
  `ip4_to_bin`, `ip6_to_bin`. `tests/unit/mac_prober_spec.moon` vérifie les
  octets exacts de la trame ARP probe (42 o) et de la NS (86 o), le checksum
  ICMPv6 par recomposition indépendante (RFC 4443), et les rejets des parseurs
  (cible/op/type différents, trame courte, MAC nulle).
- **T3 — nfq/ethernet.get_l2 : couvert.** `tests/unit/nfq_ethernet_spec.moon`
  avec faux `libnfq` : MAC via `nfq_get_packet_hw` (présente, absente,
  `hw_addrlen` nul), index d'entrée et mapping `mark > 0 → vlan`.
- **T4 — worker_auth_queue : couvert.** Export de `send_to_auth_server` et
  `handle_auth_packet`. `tests/unit/worker_auth_queue_spec.moon` fige les
  22 octets (IPv4 + 12 zéros, IPv6 + MAC), l'écriture partielle, et les
  verdicts (payload vide → `NF_DROP`, IP illisible / L2 ou MAC absents →
  `NF_ACCEPT` sans écriture).
- **T5 — bridge_raw : couvert.** `tests/unit/bridge_raw_spec.moon` :
  `open_socket` appelle `socket(AF_PACKET, SOCK_RAW, 0)` (aucune capture) et
  gère l'échec ; `send` pose `ETH_P_ALL`/l'ifindex et renvoie false sur envoi
  partiel ; `read_mac` décode la MAC sysfs (absente/vide → nil). Limite
  constatée, sans correctif : un contenu sysfs non vide mais mal formé
  ferait lever `s2mac` — inatteignable avec un vrai sysfs noyau.
- **T6 — worker_responses.finalize_a : couvert.** Export de `finalize_a`.
  `tests/unit/worker_responses_finalize_spec.moon` capture `nfq_set_verdict`
  et vérifie : block (NXDOMAIN + EDE), sinkhole (0.0.0.0 + EDE), redirect
  (CNAME cible + injection des IPs), passthrough quand le CNAME est déjà
  présent, chemin pass sans payload, et fail-closed (`NF_DROP`) quand l'ajout
  nft échoue. `handle_response` (≈260 lignes) reste non couvert en unitaire :
  le point tel que proposé visait `finalize_a`.
- **T7 — worker_captive.build_response_frames : couvert.** Ajout dans
  `tests/unit/worker_captive_spec.moon` : trois trames depuis un SYN parsé
  (swap MAC/IP, ports, séquences, flags 0x12/0x18/0x11, corps HTTP 302 exact,
  longueur IP) avec checksums IPv4/TCP recomposés indépendamment. `handle_syn`
  lui-même n'est pas appelé (il dépend de NFQUEUE et du socket AF_PACKET) ;
  la forge — le risque identifié — est couverte.
- **T8 — worker_reject : couvert.** Export de `forge_tcp_rst`,
  `forge_icmp_reject`, `handle_reject`. `tests/unit/worker_reject_forge_spec.moon`
  vérifie RST IPv4/IPv6 (swap L3/L4, `ack = seq + 1`, flags RST+ACK, checksums
  sur pseudo-headers v4/v6), ICMP v4 3/13 et v6 1/1 (quote borné à 576 o,
  checksums valides) et les verdicts de `handle_reject` (`NF_ACCEPT` avec
  payload forgé, `NF_DROP` sur payload vide ou paquet illisible).
- **T9 — nfq_loop.run_queue : couvert.** `tests/unit/nfq_loop_enobufs_spec.moon`
  scripte `libc.read`/`poll` et un faux `libnfq` : ENOBUFS ne sort pas de la
  boucle (paquet suivant traité, série de 257 ENOBUFS pour le compteur
  anti-spam), EINTR en lecture et en `poll`, erreur de `poll` non-EINTR avec
  `nfq_destroy_queue`/`nfq_close`.

Les stubs `package.loaded` sont locaux à chaque spec et restaurés en
`teardown`/`after_each` ; ni le stub `log` global ni les cdef de
`tests/helpers/busted_setup.moon` ne sont modifiés. Les `*_spec.lua` compilés
sont ignorés par git (`.gitignore`) ; seuls les `.moon` sont versionnés.

**Vérification (2026-11-11, branche t-dataplane)** : `make check` OK ;
`make test` = 2195 successes / 0 failures / 0 errors ; `make test-js` = 12 pass.

### Branche t-doh — couverture de tests du volet DoH / outils

Traitement des points T1 à T6 du rapport « doh-outils » (aucun changement de
comportement, hors le bug ci-dessous).

- **T1 — fait.** `tests/unit/worker_doh_spec.moon` couvre désormais le routage
  HTTP/1.1 réel de `handle_doh_client` (GET `?dns=`, POST
  `application/dns-message`, GET JSON, 400/413/415/502, timeout client et
  `max_body` transmis à `read_request`, échec fatal de handshake) et les helpers
  JSON/DNS (`url_decode`, `encode_qname` et label > 63, `qtype_from_name`,
  `json_escape`, `rr_data_json`, `dns_response_json` sur réponses A/AAAA/
  NXDOMAIN forgées). Les dépendances sont stubées par tables d'indirection ;
  les fonctions testées sont exportées sans changement de comportement.
- **T2 — fait.** `tests/unit/doh/upstream_spec.moon` couvre en plus la détection
  IPv6, les timeouts `SO_RCVTIMEO`/`SO_SNDTIMEO`, les échecs
  `socket()`/`inet_pton`/`connect`/`send`, le datagramme vide (`recv` = 0),
  `probe_ipv6` et `close` sur handle nil ou fd négatif. Aucune I/O réseau.
- **T3 — déjà couvert, rien à modifier.** `tests/unit/sync/apply_spec.moon`
  vérifie déjà que `reload_supervisor` envoie `SIGHUP` au PID lu dans le
  pidfile, qu'il n'appelle pas `kill` sans pidfile et qu'aucun `pkill` n'est
  émis (cible unique, pas l'argv des workers).
- **T4 — fait.** `tests/unit/install_owrt_spec.moon` couvre `run` sous les deux
  sémantiques d'`os.execute` (0 et `true`), le quoting exact de
  `ssh_prefix`/`ssh_run`/`ssh_capture`/`scp_send` (apostrophes, IPv6, port),
  `build_local`, `install_pkg_deps` (apk/opkg), `upload_files`,
  `cleanup_stale_files` (manifest depuis l'archive), `start_service` et
  `health_check`. `os.execute` et `io.popen` sont restaurés en `after_each`,
  aucun SSH réel.
- **T5 — fait.** Nouveau `tests/unit/tools/scripts_spec.moon` : `embed_js.lua`
  (JS contenant `]]` et `]=]`, niveau de long-bracket, round-trip),
  `judge.moon` (exact et suffixe sur listes 6 et 8 octets, taille invalide,
  liste vide, absence de `.bin`, usage) et `quick_coverage_report.lua`
  (fichier absent, rapport nominal), plus `bash -n setup.sh`.
  `idefix2filter.moon` n'est ni testé ni modifié (code mort, décision en
  attente).
- **T6 — fait, avec un bug révélé.** `tests/unit/doh/h2_frames_spec.moon`
  couvre isolément `h2_recv_exact` (accumulation, EOF `nil, nil`, erreur non
  réessayable, 50 `want_read_write`). Le test « frame de 0xFFFFFF rejetée »
  a révélé que `handle_h2` testait `payload` alors que `h2_read_frame` renvoie
  l'erreur en deuxième position (`nil, err` → `flags`) : la branche
  `FRAME_SIZE_ERROR` était morte et le serveur répondait `GOAWAY`
  `PROTOCOL_ERROR` (`h2_incomplete`). Corrigé (test de `flags`) ; le rejet
  sans lecture du payload reste effectif.

**Vérification (2026-11-11, branche t-doh)** : `make all` et `make check` OK ;
`make test` = 2199 successes / 0 failures / 0 errors (`make test-js` inclus,
0 échec).

### Configuration par défaut du paquet (branche d-pkgconf)

Traitement du point Q13. Un seul fichier de configuration par défaut est
désormais installé par le paquet, à `/etc/custos/config.moon` : c'est le seul
chemin lu par le superviseur (`DEFAULT_CONFIG_PATH`, `src/config.moon:52`,
surchargé par `CUSTOS_CONFIG_PATH` que l'init.d du paquet exporte —
`packaging/openwrt/custos/files/etc/init.d/custos:37`, et repris par la cible
`_apply_lua_nft_rules`, `:124`). Le fichier orphelin
`packaging/openwrt/custos/files/etc/config.moon` (78 lignes, installé par
aucune règle) est supprimé ; il est déjà déclaré conffile avec la config
installée (`packaging/openwrt/custos/Makefile:34-37`), donc non écrasé à la
mise à jour.

Comparaison clé par clé avec les `DEFAULTS` de `src/config.moon:183-393` :
**aucune** valeur du fichier orphelin ne diffère des défauts actuels. C'était
une copie des défauts de l'époque (`git show e0bb25f:src/config.moon` contient
encore `sni_log`, `forced_ttl` et `entry_ttl: 300`), pas un réglage de
déploiement. Tableau des clés :

| Clé du fichier orphelin | État | Suite |
|---|---|---|
| `runtime.log_level`, `runtime.benchmark` | identiques aux défauts | écartées (redondantes) |
| `nfqueue.questions/responses/captive/reject/auth` | identiques aux défauts | écartées |
| `nfqueue.sni_log` | **obsolète** : la clé est `nfqueue.sni` (`src/config.moon:200`, lue par `src/main.moon:460` et `src/nft_rules.moon:96,163`) | écartée |
| `dns.forced_ttl: 60` | **obsolète** : remplacée par `dns.ttl_grace` ; `tests/e2e/migration_validation.moon:16-22` exige qu'elle soit absente | écartée |
| `dns.ttl_grace.grace/min/max` | identiques aux défauts (600/60/2592000) | écartées |
| `nft.ip_timeout`, `nft.add_failure_policy`, `nft.extra_rules` | identiques aux défauts | écartées |
| `ipc.pending_ttl`, `ipc.match_retry.count/sleep_ms` | identiques aux défauts | écartées |
| `ipc.match_retry.enabled` | valide (`src/worker_responses.moon:204`, documentée `doc/CONFIG.md:309`, défaut effectif `true`) mais absente de `DEFAULTS` | écartée (redondante) |
| `clients.expiry`, `auth.sessions_file`, `doh.*`, `events.*`, `filter.dest_whitelist`, `filter.decision.*` | identiques aux défauts | écartées |
| `mac_learner.entry_ttl: 300` | valide, mais c'est l'ancien défaut (900 depuis `f398956`) | écartée (pas un réglage voulu) |

Le fichier installé ne garde donc que le point d'extension `filter.rules: {}`
(déjà présent) et des exemples commentés (`auth.bridge_ifname`/`cert`/`key`,
`filter.allow_localnets`, `nets`, `rules`). **Aucun défaut de sécurité n'est
modifié** : `filter.allow_localnets` reste `false`, `nft.add_failure_policy`
reste `fail-closed`, DoH/SafeSearch/portail captif restent actifs, et copier
les défauts dans ce conffile aurait au contraire figé leurs valeurs à la
version installée.

Documentation : `.agents/architecture.md:140` annonçait `/etc/config.moon` (lu
par personne) → remplacé par `/etc/custos/config.moon` avec la variable qui le
surcharge.

Test : `tests/unit/pkg_default_config_spec.moon` charge le fichier du paquet
dans un processus `luajit` séparé (`CUSTOS_CONFIG_PATH` +
`CUSTOS_REQUIRE_EXTERNAL_CONFIG=1`, comme l'init.d) et exige
`__meta.external_loaded = true`, `load_error = nil`, au moins une règle
effective et aucune sortie `config: …`. Il vérifie en outre chaque chemin de
clé déclaré contre le miroir de `DEFAULTS`/`doc/CONFIG.md` (le chargeur ne
signale pas les clés inconnues : elles sont fusionnées silencieusement),
l'absence de `dns.forced_ttl`/`nfqueue.sni_log`/`nft.forced_ttl`, la présence de
`/etc/custos/config.moon` dans `conffiles` et l'absence de référence au fichier
orphelin.

**Vérification (2026-11-11, branche d-pkgconf)** : `make all`, `make check` OK ;
`make test` = 2298 successes / 0 failures / 0 errors / 0 pending, `make test-js`
= 12 pass / 0 fail (journal `tmp/test.log`).
