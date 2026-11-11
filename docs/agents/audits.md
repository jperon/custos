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
  Comportement changé depuis : certificat par nom SNI avec repli IP locale
  (voir « Certificat AUTH par SNI et écriture atomique (branche d-sni) »).
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
### d-ratelimit

- **B9 de l'audit `auth-webui` : `register_rate_limit` / `register_rate_window`
  déclarés mais jamais appliqués.** les clés figuraient dans
  `src/webui/schema/config_schema.moon:106-107` et `doc/CONFIG.md:439-440`, mais
  aucun code ne les lisait (`git grep register_rate_limit src/` ne renvoyait que
  le schéma) : `POST /register` acceptait un nombre illimité de tentatives
  (coût PBKDF2 côté client, remplissage de `/etc/custos/secrets`).
  Correctif (décision : implémenter) :
  - nouveau `src/auth/rate_limit.moon` : fenêtre **fixe** par client,
    `key_for` (`:37`) retenant la MAC (minuscules) si elle est connue et non
    `unknown`, sinon l'IP, avec préfixes `mac:`/`ip:` (et `unknown` si aucun
    identifiant). `check` (`:125`) autorise `limit` tentatives puis renvoie le
    nombre de secondes restantes ; `limit <= 0` court-circuite sans I/O.
  - état partagé entre les enfants AUTH forké dans `<sessions_file>.ratelimit`,
    au format texte non exécutable (`clé<TAB>compteur<TAB>reset_at`) : lecture
    tolérante (fichier absent/illisible/corrompu → table vide), cycle
    lecture-modification-écriture sous `lib.filelock.with_lock`, écriture
    atomique (temporaire `.new.<pid>` + rename), purge des entrées expirées à
    chaque écriture et plafond `MAX_ENTRIES = 4096` (`:26`). Toute erreur
    interne est absorbée et la tentative est **acceptée** (fail-open) : le
    limiteur ne fait jamais échouer une inscription.
  - `src/auth/handlers.moon:319-345` : `handle_register` consomme une tentative
    **avant** toute validation/écriture ; au-delà, réponse `429` avec en-tête
    `Retry-After` et corps explicite, sans créer de compte ni toucher au fichier
    de secrets. Logs `server_register_rate_limited` (refus) et
    `server_register_rate_check_failed` (erreur interne, fail-open).
  - `src/config.moon:297-298` : défauts `3` / `300` identiques au schéma webui ;
    `:569-574` : normalisation (conversion numérique, fenêtre absente/nulle/
    négative → 300, limite `0` préservée = désactivée).
  - Tests : `tests/unit/auth/rate_limit_spec.moon` (12 cas : N tentatives puis
    refus avec délai, expiration de fenêtre avec horloge injectée, clients
    indépendants, purge, fichier absent/corrompu, limite 0, plafond, défauts),
    `tests/unit/auth/register_spec.moon` (429 + `Retry-After` sans écriture,
    réouverture après fenêtre, indépendance de deux clients, limite 0) et
    `tests/unit/config_spec.moon` (défauts, valeurs explicites/textuelles,
    fenêtre invalide).
  - Documentation : `doc/CONFIG.md` (sémantique exacte des deux clés) et
    `docs/agents/auth.md` (module et partage entre processus).
### Métriques exposées (branche d-metrics)

> **État historique.** Cette entrée décrit l'état de la branche `d-metrics`.
> `maybe_flush` et son compteur `check_every` (32 par défaut) ont été **retirés
> en d-final** (cf. « Suppression de `metrics.maybe_flush` », plus bas) :
> l'horloge n'est plus lue que par `flush_if_due`, au point de passage
> `on_idle` de `run_queue`.

Suite du point Q2 du rapport « dataplane » : les compteurs `metrics` étaient
alimentés par `worker_questions` mais aucun accesseur n'avait de lecteur.
Décision : les exposer en lecture seule.

- **Export périodique par worker (avec `maybe_flush`, retiré en d-final).**
  `src/metrics.moon` conserve les compteurs
  `allow`/`refuse`/`dnsonly` par règle (LRU `max_rules`) et **ajoutait alors**
  `maybe_flush` (coût par paquet : un incrément et une comparaison ; l'horloge
  n'était lue qu'une fois tous les `check_every` paquets, 32 par défaut),
  `flush_if_due` (variante purement temporelle pour le point de passage
  périodique), `write_now` et `file_path`. Chaque `worker_questions` écrit
  `<répertoire d'exécution>/metrics-dns-q<N>.json` (répertoire du pidfile,
  `lib.pidfile.resolve_path` comme `src/doh/query.moon`) de façon atomique
  (temporaire `*.json.tmp.<n>` + `os.rename`), immédiatement après `init`
  (instantané à zéro), puis au plus toutes les `metrics.flush_interval`
  secondes (défaut 60), via `run_queue` (`opts.idle_ms = 1000`,
  `on_idle = flush_if_due`) et une dernière fois à la sortie de `run_queue`.
  Le superviseur (`main.moon`) appelle `metrics.purge_files` sur le répertoire
  d'exécution **avant** de forker les workers : les fichiers d'une exécution
  précédente ne sont jamais présentés comme ceux de l'exécution courante.
  `metrics.enabled = false` : `handle_question` n'appelle ni `maybe_flush`
  (retiré en d-final) ni `record_verdict` (garde locale `metrics_on`), et
  `run_queue` ne reçoit pas d'`idle_ms` — aucun coût dans le hot-path.
- **Page admin `/admin/metrics`.** Nouveau handler
  `src/webui/handlers/metrics.moon` (lecture seule, lien dans la navigation)
  qui lit `metrics-*.json`, décode via le nouveau `src/lib/json.moon` et
  **ignore sans erreur** les fichiers illisibles ou corrompus. Il affiche les
  totaux, la répartition par verdict (allow/refuse/dnsonly), les compteurs par
  règle et l'âge de chaque worker ; **aucun instantané valide n'est exclu des
  totaux** à cause de son âge (un worker à faible débit reste compté). Le
  tableau « Workers » signale seulement « aucune activité depuis N s » au-delà
  de `max(3 × flush_interval, 180 s)`. Toutes les valeurs sont échappées via
  `webui.util.esc`. Si `metrics.enabled = false`, la page l'indique. Le
  contrôle d'accès est celui du routeur (`check_admin_session`), comme les
  autres pages admin.
- **Code mort supprimé.** `flush_metrics`, `get_snapshot`, `get_rule_metrics`,
  `record_cache`, `record_ttl` (et les champs `cache`/`ttl` du snapshot) sont
  retirés : ils n'avaient aucun consommateur en production. Le module se
  limite aux compteurs de verdicts réellement exposés.
- **Tests.** `tests/unit/lib/json_spec.moon` (encode/décode, échappements,
  corruption), `tests/unit/metrics_spec.moon` (compteurs, LRU, horloge
  injectée, écriture périodique, atomicité par échec de `os.rename`, absence
  de temporaire, désactivation) et `tests/unit/webui/metrics_handler_spec.moon`
  (agrégation multi-workers, fichier corrompu, instantané périmé, échappement
  HTML, désactivation, répertoire absent) ; `tests/unit/webui/router_spec.moon`
  couvre la route et son contrôle d'accès (302 sans session, 403 non-admin).
  `tests/unit/worker_questions_metrics_spec.moon` (tests des accesseurs
  supprimés) est retiré.
- **Documentation.** `doc/CONFIG.md` §13 (sémantique de `flush_interval` et
  emplacement des instantanés), `docs/agents/webui.md` (page Métriques) et
  `.agents/workers.md` (fichier de sortie de `worker_questions`).

### Mise à jour du sous-module ipparse (branche u-ipparse)

Le sous-module `src/lib/moontastik` passe de `a77fd2f` à `265876b` (90
commits). Les `.lua` compilés suivis (dont le nouveau `lua/ipparse/fun/`) sont
régénérés au même commit ; `git -C src/lib/moontastik status --short` reste
vide après compilation.

Changements amont confrontés un par un aux usages custos :

| Changement amont | Usages custos | Impact / adaptation |
|---|---|---|
| `ip6.pack` recalcule `vtf` depuis `version`/`traffic_class`/`flow_label` (`ipparse/l3/ip6.moon:52`) | `src/dup_query.moon:48-63,79-94`, `src/forge_dns.moon:32-50` recopiaient seulement `vtf` | **Régression réelle** : TC et flow label perdus sur les paquets IPv6 forgés. Adapté : les trois sites passent `traffic_class`/`flow_label` (`src/dup_query.moon:56-57,88-89`, `src/forge_dns.moon:42-43`). Tests `tests/unit/dup_query_spec.moon`, `tests/unit/forge_dns_spec.moon` (rouges avant correctif) |
| `rcode`/`opcode`/`z` renvoient un nombre (`ipparse/l7/dns.moon:91-104`) | `src/dns_classify.moon:35-36`, `src/worker_responses.moon:586,786`, `src/worker_doh.moon:134`, `src/filter/actions/cname.moon:96`, écritures `src/dns_ede.moon:67,108,142,175,221` ; logs `src/worker_responses.moon:541,762` | Aucun test de vérité sur ces accesseurs ; le code extrayait déjà les bits de `ra_z_rcode`. Seul effet visible : les logs `rcode` passent de `true`/`false` à 0-15 (plus informatif). Commentaires seuls corrigés (`src/dns_classify.moon:32`, `src/worker_doh.moon:132-133`, spec nxdomain) |
| Classes NONE/ANY = 254/255 (`ipparse/l7/dns.moon:387`) | aucun usage de `classes` | sans impact |
| EDNS : option inconnue stockée, `client_subnet` sans `unpack`, méta `__tostring` (`ipparse/l7/dns.moon:286-312`) | `src/dns_ede.moon:41-53` fabrique ses rdata en chaîne, ne re-parse pas d'option | sans impact |
| `pack` ne pose `header.size` que s'il existe déjà (`ipparse/l7/dns.moon:357`) | custos parse toujours avec `is_tcp=false` et calcule la longueur TCP depuis `#new_dns` (`src/lib/dns_response.moon:36-39`) | sans impact |
| `ip4`/`tcp` : `parse` renvoie `nil` sous les longueurs minimales ; flags bruts supprimés ; `options` défaut `""` | `src/packet_utils.moon:86,100,109`, `src/worker_tls.moon:680-760`, `src/worker_captive.moon:44-48`, `src/worker_reject.moon:226-241`, `src/worker_sip.moon:168-190` testent `nil` ; lecture seulement de `.flags` (`tests/unit/forge_dns_spec.moon:93`) | sans impact |
| IPv6 : `pack` exporté, checksum UDP nul → `0xFFFF` (`ipparse/l3/ip6.moon:48`), `s2net6` masque | `src/forge_dns.moon` sérialise via la métaméthode ; `s2net6` inutilisé | sans impact (checksum correct RFC 768/8200) |
| TLS : `parse` renvoie `nil` sur enregistrement/handshake/ClientHello tronqué ; `message_types` corrigés | `src/worker_tls.moon:744-750`, `src/auth/sni_extractor.moon:37-48,71` : `pcall` + test `nil` ; seul `client_hello` utilisé (`src/worker_tls.moon:750`) | sans impact |
| `hex2bin` une valeur, `bin2hex`/`lbin2hex` réécrits | aucun usage custos | sans impact |
| `fun.protected` sans fuite de traceback ; façade `fun` → `fun/{tables,memo,iter,protected}` | `src/webui/handlers/verdicts.moon:11` utilise `bidirectional`, toujours réexporté par la façade | sans impact |
| `fragmented_ip4` réécrit, `pcap` corrigé, `bit_compat` backend, `hkdf`/crypto | aucun usage direct de `fragmented_ip4`/`pcap` ; QUIC couvert par `tests/unit/ipparse/l7/quic/session_spec.moon` | sans impact |
| `pack_compat` lève sur `unpack` tronqué | custos n'utilise que `pack` ; les parseurs ipparse gardent `need_bytes` avant `su` (`ipparse/l7/dns.moon:229,260,295`, `ipparse/l7/tls/init.moon:53`) | sans impact, pas d'`unpack` non protégé dans le chemin chaud |
| `lib/ffi_stub.lua` supprimé | aucune règle du `Makefile` ; seule une copie compilée d'exemple le cite (`lua/ipparse/examples/parse_real_quic.lua:20`) | sans impact (exemples exclus de la compilation et de `make check`) |

Livraison du nouveau dossier `lua/ipparse/fun/` : `find -H` du `Makefile`
(`Makefile:95`) le compile ; le paquet OpenWrt (`packaging/openwrt/custos/Makefile:26,41`,
`$(CP)` récursif), `install-owrt.moon:218` (`tar -C lua .`) et le homelab
(`libvirt/homelab.sh:424`) copient récursivement. Aucune collision
`lua/ipparse/fun.lua` / `lua/ipparse/fun/`.

**Vérification (2026-11-11, branche u-ipparse)** : `make all`, `make check`
OK (147 fichiers, aucune globale inconnue) ; `make test` = **2301 successes /
0 failures / 0 errors / 0 pending** (2298 de la base + 3 tests ajoutés par
l'adaptation IPv6), `make test-js` = 12 pass / 0 fail (journal `tmp/test.log`).
`make test-e2e` non lancé (homelab partagé, à la charge de l'orchestrateur).
### Branche d-dohfallback — repli DoH amont wolfSSL

`doh.upstream_doh` n'est plus un module mort : il devient le repli du transport
DoH amont quand libcurl est inutilisable.

- **Sélection unique (`src/doh/upstream_select.moon:135`).** `select` est appelé
  par `worker_doh` (`src/worker_doh.moon:552`) et par `doh.validator`
  (`src/doh/validator.moon:38-46`, mémoïsé). curl reste le transport normal ;
  le repli n'est choisi que si `require` échoue (`ffi.load` `curl` →
  `libcurl.so.4`, `:24`) ou si `probe` (`curl_easy_init`, module curl) échoue.
  Une erreur de requête (timeout, 5xx) ne bascule jamais : le descripteur
  `{transport, verify_tls, make_client, close}` est figé. Un unique `log_warn`
  `doh_upstream_fallback_wolfssl` porte la raison et `verify_tls` effectif
  (`:99`, `:115`, `:157`). Si le module wolfSSL ne se charge pas, `worker_doh`
  revient à UDP/53 (`upstream_doh_unavailable_udp`) ; si wolfSSL se charge mais
  que la vérification est impossible avec `upstream_fallback_insecure=false`,
  le repli refuse (chaque ouverture échoue avec `tls_verify_unavailable`) au
  lieu de contourner la politique DoH par UDP.
- **Vérification TLS (`src/auth/ffi_wolfssl.moon:148`).**
  `verification_available` exige que la libwolfssl chargée résolve par `pcall`
  les symboles `wolfSSL_CTX_load_verify_locations` / `wolfSSL_UseSNI` /
  `wolfSSL_check_domain_name` (OpenWrt peut compiler sans) et qu'un magasin de
  CA soit lisible (`find_ca_file`, `:132` : `SSL_CERT_FILE`, chemins usuels,
  ou `doh.upstream_fallback_ca_file`). `newclient_context` charge alors le
  magasin (`:222`) ; `wrap` envoie le SNI (hors IP littérale, `:248`) et active
  `wolfSSL_check_domain_name` (`:255`). `upstream_doh.new_client` vérifié
  renvoie `tls_verify_unavailable` si la sonde échoue au lieu de continuer sans
  contrôle.
- **Refus par défaut.** `doh.upstream_fallback_insecure` (défaut `false`,
  `src/config.moon`) : vérification impossible → repli refusé et erreur
  journalisée ; `true` → repli non vérifié avec `log_warn` explicite. Le
  validateur impose `role="validator"`, `verify_tls=true` et
  `fallback_insecure=false` : aucun transport non vérifié (un verdict forgé
  serait pire qu'une absence de verdict).
- **Robustesse HTTP/1.1 (`src/doh/upstream_doh.moon`).** `parse_url` (`:82`)
  gère IPv6 littéral (crochets retirés pour `getaddrinfo`/SNI) et `host:port`
  sans chemin ; l'en-tête Host réencadre l'IPv6 et porte le port. `query`
  (`:283`) borne `Content-Length` ≤ 65535 (`:322`), écrit par `send_all`
  (`:215`, écritures partielles), borne les `WANT_*`, rejette un statut ≠ 200,
  un corps tronqué (`read_response`, `:245`) et corrèle le txid
  (`txid_mismatch`, `:334`).
- **Tests.** `tests/unit/doh/upstream_select_spec.moon` (curl normal, échec de
  chargement/init simulé → repli + un seul warn, erreur de requête sans
  bascule, refus/acceptation selon `upstream_fallback_insecure`, validateur
  jamais non vérifié) ; `tests/unit/doh/upstream_doh_spec.moon` (`parse_url`
  IPv6/port/sans chemin, Content-Length énorme, 500, corps tronqué, txid
  différent, écritures partielles, vérification TLS/SNI, refus sans sonde) ;
  `tests/unit/auth/wolfssl_spec.moon` (sonde, chargement du magasin) ;
  `tests/unit/doh_config_spec.moon` (défauts et coercion des nouvelles clés).

**Vérification (2026-11-11, branche d-dohfallback)** : `make all` et
`make check` OK (225 fichiers vérifiés) ; `make test` = 2333 successes /
0 failures / 0 errors ; `make test-js` = 12 pass.
### Certificat AUTH par SNI et écriture atomique (branche d-sni)

Constat B13 du rapport `audit/rapport-auth-webui.md` (2026-11-11) : le certificat
dynamique du portail était généré pour l'IP locale du socket (`getsockname`),
jamais pour le nom SNI demandé, et `load_or_generate_sni` écrivait
`tmp/auth_sni_<nom>_<année>.{key,crt}` directement (pas de temporaire + rename),
d'où un risque de paire dépareillée entre deux enfants forqués.

- **SNI demandé, repli IP.** Nouveau `src/auth/sni_peek.moon` : lecture du
  ClientHello par `recv(MSG_PEEK | MSG_DONTWAIT)` + `select`, sans consommation,
  avant `ssl.wrap` ; parsing réutilisé de `auth.sni_extractor.extract_sni`.
  L'échéance est partagée avec la boucle de handshake (budget total
  `auth.client_timeout`, peek compris). `server.resolve_tls_ctx` reçoit le SNI
  brut (5ᵉ paramètre, rétro-compatible) et `cert_name_for` retient le nom validé
  (`auth.cert_name.sanitize_hostname`) ou l'IP locale. Un ClientHello tronqué,
  sans SNI, un nom invalide (chemin, IP littérale, longueur, joker, contrôle)
  ou un échec de génération retombent sur l'IP locale. Le certificat statique
  reste prioritaire et aucune lecture du ClientHello n'est faite dans ce cas.
- **Plafond anti-remplissage.** `SNI_CERT_MAX_NAMES = 128` (constante
  `server.moon`) passé à `cert_cache.create_cache` ; `can_store` relit
  `tmp/cert_cache_index.lua` (la copie RAM d'un enfant forqué est figée) et
  refuse un nom inconnu au-delà du quota, sans générer. Nom de fichier borné par
  `safe_cert_name` (nom DNS validé ou IP locale uniquement).
- **Écriture atomique.** Nouveau `src/auth/cert_files.moon` :
  temporaire `<path>.tmp.<pid>_<n>` + `os.rename`, paire écrite et relue sous
  `flock` (`<cert>.crt.lock`) ; le perdant réutilise la paire complète du
  gagnant, et une paire complète n'est plus jamais réécrite — donc pas de
  contexte WolfSSL construit sur une clé et un certificat de générations
  différentes. En cas d'échec du rename du certificat, la clé est retirée.
  `cert_cache.save_cert_to_disk`/`load_cert_from_disk` appliquent la même règle
  à `tmp/certs/<nom>.{crt,key}` (écriture atomique + verrou, lecture sous le
  même verrou).
- **Tests.** `tests/unit/auth/sni_peek_spec.moon` (dont une vérification réelle
  par `socketpair` que le ClientHello n'est pas consommé), `cert_name_spec.moon`,
  `cert_files_spec.moon` (échec de rename sans fichier partiel, réutilisation et
  réparation de paire), extensions de `resolve_tls_ctx_spec.moon` (SNI valide,
  absent, invalide, échec de génération, quota, statique prioritaire) et de
  `cert_cache_spec.moon` (`can_store`, relecture de l'index, `max_names`).
- **Documentation.** `docs/agents/auth.md` (nouvelle section « Certificat TLS :
  nom SNI demandé, repli sur l'IP locale »), `.agents/workers.md`,
  `.agents/px5g_migration.md`, `docs/agents/divers.md`.

### Migration Idefix3 → Custos (`idefix2filter.moon`, branche d-idefix)

Réparation du script de migration signalé en Q4/Q5 du rapport
`tmp/audit/rapport-doh-outils.md` (trois pannes plus `..=` en boucle).

- **JSON.** `require "json"` (inexistant à la racine) remplacé par
  `require "lib.json"` (`idefix2filter.moon:21`) après préfixage de
  `package.path` avec `lua/?.lua;lua/?/init.lua;lua/?/?.lua`
  (`idefix2filter.moon:14-19`). Le script s'exécute donc depuis la racine du
  dépôt, sur le `.lua` compilé (`luajit idefix2filter.lua …`), et utilise le
  décodeur `decode` de `src/lib/json.moon:274-281`.
- **`split_conditions` supprimée.** Les règles sont désormais des tables
  structurées construites par `build_rules` (`idefix2filter.moon:186-214`) ;
  plus aucune chaîne `"clé: valeur"` n'est parsée à l'exécution.
- **`[local, lan, home.arpa]` invalide.** La règle « Infrastructure » émet
  `to_domains: {"local", "lan", "home.arpa"}` (`idefix2filter.moon:197`),
  forme de `cfg/config.moon:28`.
- **Clés de condition réellement existantes.** `to_domainlist`
  (`src/filter/conditions/to_domainlist.moon`), `to_domainlists`
  (`src/filter/conditions/to_domainlists.moon`), `to_domains`
  (`src/filter/conditions/to_domains.moon`) et `from_macs`
  (`idefix2filter.moon:194,201,206,211`). `from_maclist`, utilisé par le
  script d'origine, n'existe pas dans le code : la variante plurielle
  `from_macs` est auto-générée depuis `from_mac` par
  `src/filter/compiler_api.moon:244` (résolution des alias via
  `src/filter/conditions/from_mac.moon:17-23`). Le test vérifie chaque clé
  émise avec `compiler_api.load_condition`.
- **`..=` en boucle.** Remplacé par une table de lignes + `table.concat`
  (`render_config`, `idefix2filter.moon:218-251` ; `write_lists`,
  `idefix2filter.moon:277-291`). Un test interdit la réapparition de `..=`
  dans le script.
- **Bug découvert en écrivant le test.** Le nettoyage `gsub "^%s*(.*)%s*$"`
  ne retirait pas les espaces finaux (`(.*)` greedy laisse `%s*` vide) :
  corrigé en `^%s*(.-)%s*$` (`idefix2filter.moon:66`).
- **Listes générées.** Les groupes vont dans `listes/<groupe>.domains`, les
  listes `block_yahoo`/`spotify` dans `listes/custom/*.domains`, format texte
  lu par le repli `.domains` de `to_domainlist`
  (`src/filter/conditions/to_domainlist.moon:234-241`). `config.moon` conserve
  les chemins `/etc/custos/lists[/custom]` du script d'origine : le dossier
  `listes/` produit doit être déployé à cet endroit.
- **Non modifié.** Les listes `custom/addenda_*` référencées par les règles
  Abbés/Élèves ne sont pas générées (elles venaient déjà d'ailleurs). En
  revanche l'absence de `data.maclists` n'est plus fatale : les groupes
  démarrent vides et les devices sans MAC sont ignorés.

Tests : `tests/unit/idefix2filter_spec.moon` (13 cas) couvre nettoyage,
collecte, associations de profils, rendu, compilation MoonScript
(`moonscript.base.to_lua`), chargement du `config.moon` généré par le chargeur
réel (`CUSTOS_CONFIG_PATH` + `CUSTOS_REQUIRE_EXTERNAL_CONFIG=1` dans un
processus `luajit`) et écriture des fichiers. `idefix2filter.lua` est
régénéré et suivi ; le `.lua` de la spec reste ignoré par `.gitignore:38`
(convention du dépôt).

**Vérification (2026-11-11, branche d-idefix)** : `make all`, `make check`
OK (150 fichiers) ; `make test` = **2324 successes / 0 failures / 0 errors /
0 pending** (`tmp/test.log`). `make test-e2e` non lancé (hors périmètre de la

### d-h2 — HPACK et serveur HTTP/2 DoH

Le serveur DoH HTTP/2 ne se limite plus aux POST sans routage : il décode
HPACK et applique le profil RFC 8484.

- **Module HPACK pur (`src/doh/hpack.moon`).** `decode` (`:517`) gère les
  champs indexés, les littéraux avec/sans indexation ou jamais indexés, la
  table dynamique par connexion (`new_decoder`, `:502`) avec éviction et
  `dynamic table size update` (`:517`). Les primitives `decode_integer`
  (`:410`), `decode_string` (`:435`) et `huffman_decode` (`:379`, table de
  l'annexe B) imposent les bornes : entier ≤ 2^31−1 et ≤ 5 octets de
  continuation, chaîne et liste d'en-têtes plafonnées, index hors table,
  EOS, padding Huffman > 7 bits ou non composé de 1, `size update` tardif ou
  supérieur à la limite → `nil, "raison"`. L'encodeur (`encode`, `:583`) émet
  des champs indexés de la table statique et des littéraux sans indexation ni
  Huffman.
- **Décodage des frames HEADERS (`src/worker_doh.moon`).**
  `read_header_block` (`:260`) assemble HEADERS + CONTINUATION (plafond
  `H2_MAX_HEADER_BLOCK`, `:243`), retire PADDED et PRIORITY et conserve
  END_STREAM ; `handle_h2` (`:312`) crée un décodeur HPACK par connexion, lit
  `:method`/`:path` (`:351-357`) et émet `GOAWAY COMPRESSION_ERROR` (0x9,
  `:239`, `:361`) sur bloc indécodable.
- **Routage RFC 8484.** `POST` sur le chemin DoH traite le corps DATA ; `GET`
  décode `?dns=` base64url. Les règles de chemin sont partagées avec HTTP/1.1
  (`is_doh_path`, `:79` ; `dns_from_query`, `:87`, utilisées aussi `:527-534`).
  Autre chemin → `:status 404`, autre méthode → `405`, chemin DoH sans
  paramètre/corps → `400`, sans DNS traité (`h2_reject`, `:295` ;
  `:390-402`). Les plafonds DATA (65535), SETTINGS, PING et frame trop grande
  sont conservés.
- **ALPN serveur (`src/auth/ffi_wolfssl.moon`).** `ALPN_PROTOCOLS` vaut
  `h2,http/1.1` (`:98`) ; `DEFAULT_ALPN_PROTOCOLS` reste `http/1.1` (`:99`)
  pour le portail AUTH. `newcontext` (`:223-244`) essaie
  `wolfSSL_CTX_UseALPN` puis, s'il est absent mais que `wolfSSL_UseALPN`
  existe, positionne `alpn_mode = "ssl"`. `worker_doh` demande la liste h2 sur
  son contexte (`src/worker_doh.moon:472`) ; `wrap` (`:297`) annonce alors la
  liste par objet SSL via `alpn_configure_ssl` (`:187`) ou réapplique le
  contexte via `alpn_configure_ctx` (`:173`) s'il a changé. Sans aucun symbole
  ALPN, aucun changement de comportement ; les contextes client ne sont pas
  concernés. Les deux helpers acceptent une bibliothèque factice pour les
  tests.
- **GET JSON.** Le profil JSON du HTTP/1.1 (`?name=…&type=…` +
  `Accept: application/dns-json`) est conservé en HTTP/2
  (`src/worker_doh.moon:403-409`, réponse `application/dns-json` `:424-428`)
  pour ne pas régresser les clients qui négocient h2 via ALPN.
- **Tests.** `tests/unit/doh/hpack_spec.moon` (vecteurs C.2 à C.6, erreurs,
  encodeur), `tests/unit/worker_doh_spec.moon` (GET binaire et JSON, POST,
  404/405/400, PADDED, PRIORITY, CONTINUATION, padding invalide, stream 0,
  dépassement de bloc, COMPRESSION_ERROR, tests existants de plafond DATA et
  frame trop large), `tests/unit/doh/h2_frames_spec.moon` (nouvelles
  constantes) et `tests/unit/auth/wolfssl_spec.moon` (choix contexte/objet
  SSL, défaut AUTH http/1.1).

**Vérification (2026-11-11, branche d-h2)** : `make all` et `make check` OK
(152 fichiers, aucune globale inconnue) ; `make test` = **2403 successes /
0 failures / 0 errors / 0 pending** ; `make test-js` = 12 pass / 0 fail
(journal `tmp/test.log`). `make test-e2e` non lancé (hors périmètre de la
tâche).

### Listes référencées introuvables au chargement (branche d-listwarn)

Constat sur une installation réelle : des règles ne s'appliquaient jamais, sans
aucun message, parce que leurs listes étaient introuvables.
`to_domainlist_list "custom/open_list"` cherchait
`{lists_dir}/domainlist/custom/open_list.txt` (absent) et
`to_domainlists {"custom/ferme"}` sur une règle `deny` ne chargeait ni `.bin` ni
`.domains` : la condition construite ne correspondait jamais, silencieusement.

- **Conditions `*_list`/`*_lists` (`src/filter/compiler_api.moon`).**
  `read_lines` (`:77`) retourne désormais un second statut : `"missing"`
  (fichier absent), `"empty"` (présent, mais vide ou seulement des
  commentaires) ou `nil` (lignes valides). `make_from_file` (`:167`) émet un
  unique `log_warn` à la **construction** (`:174-186`) — action
  `filter_list_missing` ou `filter_list_empty`, champs `condition`, `list` et
  `path` (chemin réellement ouvert). `make_from_files` (`:195`) transmet le nom
  de la condition, fourni par `load_condition` (`:238`, `:246`) : le log dit
  bien `from_net_list`/`from_net_lists`, etc. Le filtrage est inchangé : la
  liste reste vide, donc la condition ne correspond jamais.
- **Domainlists (`src/filter/conditions/to_domainlist.moon`).**
  `load_list` (`:100`) distingue lui aussi `"missing"` (open impossible) de
  `"empty"` (`.bin` de taille 0, ou `.domains` sans domaine) sans changer son
  contrat principal (`nil, msg`). La factory (`:223`) tente `.bin` puis
  `.domains` et, si rien ne charge, émet un `log_warn` à la construction
  (`:250-272`) avec `condition`, `list`, `path` et, pour le cas absent,
  `alt_path` (le repli `.domains` cherché). Un échec sans rapport avec le
  fichier (`libxxhash` introuvable) ne produit aucun de ces deux avertissements,
  pour ne pas accuser la liste à tort. `to_domainlists.moon:23` passe le libellé
  `"to_domainlists"` à la factory déléguée ; ce module n'a pas de chargement
  propre.
- **Avertissements et compatibilité des tests.** Le logger est lu au call-site
  (`log.log_warn`) : les specs qui remplacent `package.loaded["log"]` par une
  table partielle (sans `log_warn`) ne cassent plus, et un espion installé
  après chargement est bien vu. `tests/helpers/busted_setup.moon` transmet
  désormais les arguments supplémentaires au wrapper `__call`
  (`(...) ->`), pour que le libellé de condition de `to_domainlists` soit
  observable comme en production.
- **Combien de fois par démarrage.** `compile_rules` n'est appelé que dans le
  processus superviseur, avant le fork des workers : `nft_rules.apply!`
  (`src/nft_rules.moon:259`) puis `filter.load!` (`src/main.moon:401`). Les
  workers reçoivent les métadonnées déjà compilées, donc **deux** lignes par
  liste manquante au démarrage (même pid), plus une par SIGHUP
  (`src/main.moon:531`). Aucune déduplication inter-processus n'a été ajoutée :
  `RL_CONFIG` (`src/log.moon:57-68`) ne couvre pas ces actions, le
  rate-limiting ne les élague donc pas.
- **Tests.** `tests/unit/filter/list_warnings_spec.moon` (9 cas) : fichier
  absent → `filter_list_missing` avec le chemin attendu ; fichier vide ou
  commentaires seuls → `filter_list_empty` ; fichier valide → aucun warn ;
  `*_lists` → un warn par liste absente ; domainlist `.bin` absente,
  `.bin` vide, `.domains` vide ; `.bin` valide → aucun warn ; `to_domainlists`
  délègue avec le bon libellé. Les fichiers de test vivent sous
  `./tmp/list_warnings_spec` (jamais `/tmp` système).
- **Documentation.** `doc/CONFIG.md` § 14.1 (rôle de `domainlists_dir`,
  `lists_dir`, `custom_lists_dir` et de ce qui est lu où), `doc/CHEATSHEET.md`
  (diagnostic par `filter_list_missing`/`filter_list_empty`).

**Vérification (2026-11-11, branche d-listwarn)** : `nix develop --command bash
-c "make all && make check && make test"` OK ; `make test` = **2421
successes / 0 failures / 0 errors / 0 pending** (`tmp/test_d-listwarn.log`).
### Documentation des variantes `_list` / `_lists` (branche d-listdoc)

- **Cause.** Le commit `35c04c2` a supprimé les 18 modules dérivés
  (`from_netlist`, `from_maclist`, `from_userlist`, `from_vlanlist`,
  `in_timelist` et leurs pluriels). `compiler_api.load_condition` ne synthétise
  plus que les motifs `^(.+)_lists$`, `^(.+)_list$` et `^(.+)s$`
  (`src/filter/compiler_api.moon:208-236`). L'orthographe sans tiret bas ne
  correspond à aucun motif : `nil, "Condition '…' not found"`, et
  `src/filter/rule.moon:55-57` lève alors `Condition inconnue`.
- **Sémantique réelle.** `from_xxx_list "nom"` lit
  `{lists_dir}/{type}/{nom}.txt` via `make_from_file`
  (`src/filter/compiler_api.moon:157-170`) ; `from_xxx_lists {…}` fait un OU
  sur plusieurs fichiers (`:172-191`). `{type}` est le nom de base après le
  premier `_` (`:217,225`) : `from_net`→`net`, `from_mac`→`mac`,
  `from_vlan`→`vlan`, `from_user`→`user`, `in_time`→`time`. Ce n'est **pas**
  une référence à un groupe des dictionnaires `filter.nets` /
  `filter.macs` / `filter.users` : chaque ligne du fichier est évaluée par la
  condition de base (un alias `filter.macs` ou un nom `filter.times` y est
  résolu).
- **Documentation corrigée.** `doc/CONFIG.md` (§14.1 ajout de `lists_dir`,
  §14.2 réécrit, §16 tables et exemple `any_of`), `README.md` (table des noms,
  `from_in_time_list` → `in_time_list`, défaut `/tmp/custos/lists`,
  avertissement sur l'orthographe), `docs/agents/filtre.md` (défaut et mapping
  du type), `docs/agents/webui.md` (alias MAC), `src/config.moon:9-19`
  (commentaire), libellés `src/webui/handlers/filter.moon:109-111`,
  `src/webui/handlers/devices.moon:187` et
  `src/webui/schema/config_schema.moon:168`. `to_domainlist` /
  `to_domainlists` ne sont pas touchés (modules réels).
- **Fixture morte supprimée.** `tests/cfg.moon` et `tests/cfg.lua` n'étaient
  chargés par aucun test : aucune référence à `tests/cfg` ni à
  `require "cfg"` dans `src/`, `tests/` ou le `Makefile` ; les specs de webui
  écrivent leur propre `tmp/*_cfg.lua`. Le fixture datait du 2026-05-09
  (`e0bb25f`), antérieur à `35c04c2`, et contenait `cfg.filter.maclists` (clé
  absente des `DEFAULTS` de `src/config.moon:371-376`) ainsi que
  `from_maclist`. Supprimé plutôt que corrigé : un exemple non chargé et non
  validable n'a pas sa place sous `tests/`.
- **Test de non-régression.** `tests/unit/filter/compiler_api_spec.moon` fige
  les 10 formes avec tiret bas (résolution en fonction) et les 10 formes sans
  tiret bas (`nil` + message exact `Condition '…' not found`). Aucun alias
  n'est ajouté pour l'ancienne orthographe (décision utilisateur en attente).
- **Incohérence résiduelle (non corrigée, hors périmètre).**
  `src/auth/rule_user.moon:29,31,57,71` et `src/response_inject.moon:56`
  testent la clé brute `from_userlists` (sans tiret bas) avec la sémantique
  « groupe de `filter.userlists` », alors que cette condition n'est plus
  chargeable : une règle qui l'utiliserait échoue à la compilation
  (`src/filter/rule.moon:57`). `src/filter/nft_compiler.moon:89-94` conserve
  des clés historiques `from_netlist` / `to_netlist` dans
  `legacy_netlist_keys` ; ce chemin est inatteignable, seuls les commentaires
  ont été corrigés.
- **Limite mesurée.** `from_vlan_list` / `from_vlan_lists` se résolvent mais ne
  matchent pas : les lignes lues sont des chaînes, comparées sans conversion à
  `req.vlan` numérique (`src/filter/conditions/from_vlan.moon:21-27`).
  Documenté comme limite connue dans `doc/CONFIG.md` §14.2 ; correctif hors
  périmètre.

**Vérification (2026-11-11, branche d-listdoc)** : `make all`, `make check`
OK (154 fichiers, aucune globale inconnue) ; `make test` =
**2414 successes / 0 failures / 0 errors / 0 pending** (`tmp/test.log`).
`make test-e2e` non lancé (hors périmètre de la tâche).
### Chemins d'écriture au runtime (branche d-tmpfs)

Application du principe « `/etc` manuel, le reste en tmpfs ». Les certificats
générés (SNI/IP) étaient écrits dans des chemins relatifs (`tmp/certs`,
`tmp/cert_cache_index.lua`, `tmp/auth_sni_*`) qui ne tombaient en tmpfs que
parce que le service tourne avec `cwd=/`. Ils vivent désormais dans
`/tmp/custos/certs` (constante `DEFAULT_CERT_DIR`,
`src/auth/cert_cache.moon:21`), réglable par `auth.cert_dir`
(`src/config.moon:304`, schéma `src/webui/schema/config_schema.moon:98`,
`doc/CONFIG.md`). L'index du cache est dans le même dossier
(`src/auth/cert_cache.moon:94`) et le dossier est créé par le helper commun
`ensure_dir`. Le worker DoH partage ce dossier (`src/main.moon:171`,
`src/worker_doh.moon:658-659`). Le temporaire de `nft_rules.apply` passe de
`./tmp` à `/tmp/custos` (`src/nft_rules.moon:279-282`). Les certificats fournis
à la main (`auth.cert`/`auth.key`) restent inchangés.

Inventaire complet des autres chemins d'écriture (nature, emplacement, cas
douteux `sessions_file`, `session_key`, `filter.lists_dir`,
`load_or_generate_static`) : `docs/agents/divers.md` § « Chemins d'écriture au
runtime ». Tests : défaut de `cert_dir`, index dans le même dossier, clé
`auth.cert_dir` (défaut et surcharge) dans
`tests/unit/auth/cert_cache_spec.moon` et `tests/unit/config_spec.moon`.

### Branche d-wolfenv — wolfSSL de test aligné sur la cible

L'environnement de test construisait wolfSSL 5.6.6 **sans ALPN ni SNI**
(`wolfSSL_UseALPN` / `wolfSSL_ALPN_GetProtocol` absents) : HTTP/2
n'était pas testable, alors que la cible OpenWrt 25.12 (`libwolfssl5.8.4`)
exporte ces symboles.

- **Dérivation (`flake.nix:17-38`).** `wolfssl` passe à **5.8.4**
  (`https://github.com/wolfSSL/wolfssl/archive/v5.8.4-stable.tar.gz`, hash
  `sha256-K3AremawBnv9KEQIgnseWSiLNXsN11jQCJwGI5XypSI=` obtenu par
  `nix store prefetch-file`) et ajoute `--enable-alpn`, `--enable-sni` et
  `--enable-opensslall` (les deux derniers symboles ALPN OpenSSL
  `wolfSSL_get0_alpn_selected` et `wolfSSL_CTX_set_alpn_select_cb` sont
  conditionnés par `OPENSSL_ALL`/`HAVE_LIGHTY`, cf. `src/ssl.c:22266` de
  wolfSSL). Les options px5g (`--enable-keygen/certgen/certreq/certext/ecc`)
  et `CFLAGS = "-DWOLFSSL_ALT_NAMES -DFP_MAX_BITS=8192"` sont conservées ;
  `px5g-wolfssl` du même flake se construit toujours (binaire `px5g` présent
  dans le devShell).
- **Preuve (`nix develop`, build `nxpghs2g7imkkmk39jdsvvag09nf4yfv-wolfssl-5.8.4`).**
  `nm -D --defined-only lib/libwolfssl.so | grep -c " T <symbole>$"` donne 1
  pour chacun des symboles de la cible : `wolfSSL_UseALPN`,
  `wolfSSL_ALPN_GetProtocol`, `wolfSSL_get0_alpn_selected`,
  `wolfSSL_CTX_set_alpn_protos`, `wolfSSL_set_alpn_protos`,
  `wolfSSL_CTX_set_alpn_select_cb`, `wolfSSL_UseSNI`,
  `wolfSSL_SNI_GetRequest`, `wolfSSL_CTX_set_servername_callback`,
  `wolfSSL_check_domain_name`, `wolfSSL_CTX_load_verify_locations`.
- **Symbole absent des deux côtés : `wolfSSL_CTX_UseALPN`.** Il n'est exporté
  ni par la build 5.8.4, ni par la VM cible (comptage 0 dans les deux cas) —
  l'API a disparu de wolfSSL 5.x. Conséquence en production :
  `src/auth/ffi_wolfssl.moon:190` sonde ce symbole dans un `pcall`, qui échoue
  toujours ; `_alpn_available` vaut alors `false` (`:191`) et
  `selected_alpn` renvoie toujours `nil` (`:321`). Le serveur DoH n'annonce
  donc jamais ALPN et un client qui sélectionnerait `h2` n'est pas détecté par
  ce chemin ; `src/worker_doh.moon:379-382` journalise `alpn=none` et ne voit
  le HTTP/2 que par le préambule PRI (`:399-401`). Défaut **préexistant à la
  cible** (le symbole manque aussi sur OpenWrt), non corrigé ici : la tâche
  demandait seulement d'aligner l'environnement. Aucun test ne dépend de ce
  symbole.
- **Comportement des tests inchangé.** Aucun spec ne dépendait de l'absence
  d'ALPN : `make test` reste à **2351 successes / 0 failures / 0 errors /
  0 pending** (même total que sur `dev`), `make test-js` = 12 pass / 0 fail.
  Aucun test n'a été modifié.
- **Instabilité préexistante constatée (hors périmètre).** Environ une
  exécution sur trois de Busted meurt d'un **SIGSEGV dans `luajit` après la fin
  de tous les tests** (les 2351 succès sont écrits, le récapitulatif ne l'est
  pas ; aucune erreur ni échec de test). Le noyau est disponible via
  `coredumpctl` et la pile est entièrement dans `luajit` (fermeture/GC), pas
  dans `libwolfssl`. Le phénomène se reproduit en forçant l'ancienne
  bibliothèque 5.6.6 (`LD_LIBRARY_PATH` vers un lien `libwolfssl.so`/`.so.44`
  pointant sur 5.6.6, au prix de 6 échecs px5g dus au mélange d'ABI) : il est
  donc **antérieur** à ce changement et non causé par wolfSSL 5.8.4. Une
  relance suffit à obtenir un `make test` vert ; non corrigé ici.
- **VM e2e (lecture seule, `./libvirt/homelab.sh ssh custos`).** La VM
  `homelab-custos` a `libwolfssl5.9.1.e624513f` (`ls /usr/lib/libwolfssl*`) et
  `grep -c wolfSSL_UseALPN` = 1 : ALPN y est disponible, donc aucune
  modification de `libvirt/homelab.sh` n'est nécessaire. À noter : le paquet
  est installé non épinglé (`libvirt/homelab.sh:404`,
  `[ -e /usr/lib/libwolfssl.so ] || need_install="$need_install libwolfssl"`) ;
  si une version future retirait ALPN, c'est cette ligne qu'il faudrait
  épingler.

**Vérification (2026-11-11, branche d-wolfenv)** : `make all` et `make check`
OK ; `make test` = 2351 successes / 0 failures / 0 errors / 0 pending
(`tmp/test-wolfenv2.log`) ; `make test-js` = 12 pass / 0 fail. `make test-e2e`
non relancé (VMs seulement interrogées en lecture seule).

### Contrôle du `content-type` POST HTTP/2 et `metrics.maybe_flush` (branche d-h2ctype)

- **POST HTTP/2 : contrôle du `content-type`.** Le chemin h2 traitait le corps
  DATA dès que le chemin était `/dns-query`, quel que soit l'en-tête, alors que
  le chemin HTTP/1.1 exige `application/dns-message` et répond `415` sinon
  (`src/worker_doh.moon:566-571`, `:585-588`). Prédicat partagé
  `is_dns_message_content_type` (`src/worker_doh.moon:83-91`) appliqué aux deux
  chemins : `content-type` lu dans le bloc HPACK (`:379`) puis testé avant le
  corps (`:409-410`), réponse `:status 415` via `h2_reject`. Le comportement
  HTTP/1.1 est inchangé (le prédicat reprend la correspondance de sous-chaîne
  historique : paramètres après `;` tolérés, casse significative) ; les GET, y
  compris JSON, ne sont pas touchés. Tests : `tests/unit/worker_doh_spec.moon`
  (POST `application/dns-message` → traité, avec paramètres → traité, type non
  DNS → `415` sans traiter de DNS, type absent → `415` ; parité HTTP/1.1 pour
  le type absent).
- **`metrics.maybe_flush` : aucun appel ni fonction redondante dans le
  module.** *(`maybe_flush` a depuis été **retiré en d-final** ; ce constat
  décrit l'état de la branche `d-h2ctype`.)* Une seule définition (`src/metrics.moon:191-196`) et un seul appel
  de production (`src/worker_questions.moon:236`) ; `flush_if_due`
  (`src/metrics.moon:179-185`) a des appelants distincts (`maybe_flush`,
  `run_queue` via `on_idle`). Le constat d'audit ne se vérifie donc pas à
  l'intérieur de `src/metrics.moon` ; aucun code n'est modifié. À noter, hors
  périmètre : `run_queue` appelle `on_idle` avant chaque lecture
  (`src/nfq_loop.moon:115`) et `worker_questions` y branche `flush_if_due`
  (`src/worker_questions.moon:550-551`), ce qui rend le passage par paquet
  superflu en production ; le retirer exigerait de modifier
  `src/worker_questions.moon` et supprimerait un contrat fixé par
  `tests/unit/metrics_spec.moon` (`:139-164`, `:186-193`), donc non fait ici.
### Listes locales compilées par `custos-update` (branche d-update)

Après un redémarrage, `domainlists_dir` (tmpfs) était repeuplé uniquement par
la release `custos-lists` : les `.txt` de `custom_lists_dir` n'étaient jamais
compilés, et une liste locale homonyme d'une liste de la release était écrasée.

- **Logique de compilation déplacée dans `filter.updater_io`.** `write_bin`,
  `fetch_local` et `process_custom_dir` sont sortis de `filter/updater.moon`
  (qui s'exécute au chargement et n'est pas testable) vers
  `src/filter/updater_io.moon:83-179` ; `updater.moon` les réexporte
  (`src/filter/updater.moon:61-69`). Comportement inchangé, désormais couvert
  par `tests/unit/filter/updater_io_spec.moon` (`.txt` → `.bin` dans le
  dossier de sortie, liste vide ignorée, dossier source absent, dry-run).
- **Option `--custom-only` de l'updater.** `src/filter/updater.moon:86-92`
  (analyse) et `:238-240` : la table `filter.sources` est vidée avant la boucle
  de téléchargement, seul le scan de `custom_lists_dir` est exécuté
  (`:344-352`). Si `custom_lists_dir` est absent, message explicite et sortie
  0 (pas d'erreur). Test : `tests/unit/filter/updater_config_spec.moon`
  (source `filter.sources` ignorée, `custom/demo.bin` compilé).
- **`custos-update` compile les listes locales.** Le script
  (`packaging/openwrt/custos/files/usr/sbin/custos-update:123-143`) lance
  `custos filter/updater.lua --custom-only --config …` avec le même
  `LUA_PATH`/`LUA_CPATH`/`CUSTOS_CONFIG_PATH`/`CUSTOS_REQUIRE_EXTERNAL_CONFIG`
  que l'init.d, après l'extraction de la release et avant le SIGHUP. Les deux
  étapes sont indépendantes : `release_rc` et `custom_rc` sont accumulés, le
  SIGHUP est toujours tenté, puis le code de sortie propage l'échec de
  compilation (sinon celui de curl/extraction, pour conserver les codes
  réseau 6/7/28/35/52/56 attendus par les tests E2E). Chemins du runtime
  surchargeables par variables d'environnement (`CUSTOS_DIR`, `CUSTOS_BIN`,
  `CUSTOS_CONFIG_PATH`, `CUSTOS_UPDATER`, `CUSTOS_PID_FILE`, `CUSTOS_LUA_PATH`,
  `CUSTOS_LUA_CPATH`). Un outil manquant n'interrompt plus le script : il
  empêche seulement l'étape release.
- **`_cron_remove` retire aussi les anciennes lignes non marquées.**
  `packaging/openwrt/custos/files/etc/init.d/custos:110-118` : `sed` supprime
  les lignes du marqueur **et** toute ligne contenant
  `/usr/sbin/custos-update` (ancien `0 4 * * *` sans marqueur), sans toucher
  aux autres entrées du crontab. Test : `tests/unit/pkg_custos_update_spec.moon`
  exécute la fonction extraite de l'init.d sur un crontab factice.
- **Tests du script shell.** `tests/unit/pkg_custos_update_spec.moon` exécute
  `custos-update` avec un `PATH` truqué (`curl`, `zstd`, `tar`, `sha256sum`,
  `custos`, `pgrep`, `pkill`, `uci` factices sous `./tmp/`) : compilation
  locale après extraction (marqueur présent), appelée malgré l'échec de
  `curl` (code 7 propagé), code non nul si la compilation échoue (SIGHUP
  toujours envoyé). `sh -n` OK ; `shellcheck` et `busybox` ne sont pas
  installés dans le flake.
- **`install-owrt.moon` inchangé** (vérifié) : il copie le script tel quel, ne
  touche pas au cron (géré par l'init.d) et son `uninstall` supprime déjà
  `/usr/sbin/custos-update` et les lignes de crontab associées.
- **Documentation** : `doc/CONFIG.md` (§ 14.1) précise sortie vs source et la
  priorité du local ; `doc/CHEATSHEET.md` décrit les deux étapes et
  `--custom-only`.

**Vérification (2026-11-11, branche d-update)** : `make all`, `make check`
OK ; `make test` = **2421 successes / 0 failures / 0 errors / 0 pending**
(`tmp/test.log`). `make test-e2e` = **94 passed / 0 failed**
(`tmp/test-e2e.log`), dont G0b/T04b (téléchargement + vérification SHA256 +
extraction, exit 0) et T04c (82 `.bin` déployés dans `/tmp/e2e-lists`).
### Branche d-nets — alias `filter.nets` et défaut de `filter.lists_dir`

- **`filter.nets` ignoré par `from_net`/`to_net`.** La webui édite un
  dictionnaire nom→CIDRs (`src/webui/handlers/filter.moon:109`), mais les deux
  conditions passaient l'argument tel quel à
  `net_match.build_cidr_condition` : un nom de groupe ne correspondait jamais.
  Correctif : `net_match.build_net_arg_condition`
  (`src/filter/conditions/net_match.moon:86`) résout un argument qui n'est ni
  `_any`/`_none` ni un CIDR/IP littéral (`Net`) mais une clé de `cfg.nets` vers
  un OU sur les CIDRs du groupe (`build_alias_condition`, `:64`, via
  `compiler_api.make_plural`, désormais exporté). `from_net.moon:35` et
  `to_net.moon:37` l'utilisent ; les variantes `from_nets`,
  `from_net_list(s)` en héritent (une entrée/ligne peut être un alias). Un nom
  inconnu garde le comportement « CIDR invalide » et journalise
  `filter_net_unknown` une seule fois à la construction (`:103`), jamais dans
  `eval`. Test : `tests/unit/filter/net_alias_spec.moon`.
- **Alias multi-CIDR volontairement worker-only.** `make_plural` fusionne des
  expressions nft à préfixe identique ; une expression déjà groupée
  (`ip saddr { … }`) ne peut pas être recombinée par le pluriel supérieur
  (`from_nets`, `from_net_list…`) sans produire une règle fausse. Un alias de
  plus d'un CIDR est donc déclaré `nft: false`
  (`src/filter/conditions/net_match.moon:75-77`) ; un alias vers un seul CIDR
  reste nft-capable. Les CIDRs littéraux et `from_nets` de CIDRs gardent
  exactement leur comportement worker/nft (couvert par le même spec).
- **Libellés webui/doc rétablis.** `handle_nets_get` ne dit plus « Dictionnaire
  non consulté par from_net » mais décrit la résolution effective
  (`src/webui/handlers/filter.moon:109`) ; passages alignés dans
  `doc/CONFIG.md` (§14.2 et tableau `from_net`), `docs/agents/filtre.md`
  (§ Alias de réseaux), `docs/agents/webui.md` et `README.md`.
- **`filter.lists_dir` : défaut `/etc/custos/lists`.** Les listes-texte
  saisies à la main (`from_xxx_list/_lists`) tombaient sur un repli codé en dur
  `/tmp/custos/lists` (tmpfs) dans `compiler_api.make_from_file` et dans la
  webui, donc perdues au redémarrage. `DEFAULTS.filter.lists_dir` vaut
  désormais `/etc/custos/lists` (`src/config.moon:368`) et une seule constante
  `compiler_api.DEFAULT_LISTS_DIR` (`src/filter/compiler_api.moon:60`, exportée)
  sert de repli à `make_from_file` (`:177`) et à
  `webui/handlers/lists.moon:26`. `domainlists_dir` reste `/tmp/custos/lists`
  (`src/config.moon:363`, listes compilées régénérées par l'updater). Schéma
  webui (`src/webui/schema/config_schema.moon:161`), config par défaut du
  paquet (`packaging/openwrt/custos/files/etc/custos/config.moon:17`) et docs
  (`doc/CONFIG.md:641`, `README.md`, `docs/agents/filtre.md`,
  `docs/agents/divers.md`) alignés. `cfg/config.moon` ne contient pas la clé :
  inchangé. Tests : `config_spec` (défauts), `list_warnings_spec` (chemin de
  repli) et `webui/lists_handler_spec` (affichage du répertoire) ; tous passent
  un `lists_dir` explicite ou se contentent de lire le défaut, sans écrire
  hors de `./tmp/`.
### Client HTTP/2 du repli DoH (branche d-h2client)

Le repli DoH sur wolfSSL (`src/doh/upstream_doh.moon`) ne parlait que HTTP/1.1,
alors que le serveur DoH du projet sait déjà servir HTTP/2. Deux défauts
distincts empêchaient toute négociation ALPN, constatés dans le code source
wolfSSL 5.8.4 et dans `<wolfssl/ssl.h>` de l'environnement de test :

- `wolfSSL_UseALPN` exige l'option `CONTINUE_ON_MISMATCH` ou
  `FAILED_ON_MISMATCH` et rend `BAD_FUNC_ARG` sinon. L'énumération vaut
  `WOLFSSL_ALPN_MATCH = 1`, `CONTINUE_ON_MISMATCH = 2`,
  `FAILED_ON_MISMATCH = 4` : la constante historique
  `WOLFSSL_ALPN_CONTINUE_ON_MISMATCH = 0x01` du module est donc refusée.
- `wolfSSL_ALPN_GetProtocol` rend `WOLFSSL_SUCCESS (= 1)` et
  `WOLFSSL_ALPN_NOT_FOUND (= 0)`; `selected_alpn` testait `ret == 0` et
  rendait donc toujours `nil`.

Corrections :

- **Une seule option ALPN, correcte** (`src/auth/ffi_wolfssl.moon:94-106,210-216`).
  `WOLFSSL_ALPN_CONTINUE_ON_MISMATCH = 0x02` est désormais l'unique constante,
  utilisée par `alpn_configure_ctx`, `alpn_configure_ssl` et
  `alpn_configure_client` ; `_OPT` a disparu. `CLIENT_ALPN_PROTOCOLS =
  "h2,http/1.1"`. `alpn_configure_client` rend faux sans exception si le
  symbole manque ou si wolfSSL refuse.
- **Échec ALPN serveur visible** (`:219-278,330-348`). Si un symbole ALPN
  existe mais que la configuration échoue (contexte ou objet SSL),
  `wrap`/`newcontext` émettent un `log_warn` (`alpn_context_failed`,
  `alpn_ssl_failed`, `alpn_ctx_update_failed`) au lieu du seul `log_debug` qui
  avait masqué la régression. L'absence totale de symbole reste en debug.
- **Offre au wrap client** (`:304,351-359,378`). `newclient_context` marque
  `is_client` ; `wrap` ne propose `opts.alpn_protocols` que sur un tel
  contexte, avant le handshake, et note `alpn_offered`. Un échec n'est pas
  fatal : le handshake se poursuit et le chemin HTTP/1.1 est conservé.
- **Protocole négocié** (`:436-446`). `selected_alpn` vérifie le symbole puis
  `ret == 1` ; il n'est plus neutralisé par le global `_alpn_available`, qui
  pouvait être mis à `false` par un échec serveur dans le même processus.
- **Serveur DoH : h2 réellement servi** (`src/worker_doh.moon:512-517`). Après
  le handshake, `handle_doh_client` **fermait la connexion** quand
  `selected_alpn == "h2"` (`http2_not_supported`) : même une négociation
  réussie n'atteignait jamais `handle_h2`. La fermeture anticipée est
  supprimée ; la préface PRI est lue par `read_request` et la branche
  `req.method == "PRI"` route vers `handle_h2`, comme pour un client h2 sans
  ALPN.
- **Nouveau client** (`src/doh/upstream_doh.moon:52-60,191-198,221-238`).
  `new_client` offre `H2_CLIENT_ALPN`, lit `selected_alpn` après le handshake
  et expose `alpn` / `h2` dans le handle. Sans `selected_alpn` (stub, ancienne
  lib), `alpn` reste `nil` et `h2` faux : HTTP/1.1 comme avant.
- **Client HTTP/2** (`:314-473`). `query` délègue à `query_h2` si `h2` :
  préface, SETTINGS, HEADERS (pseudo-en-têtes RFC 7540 §8.1.2.3) + DATA
  découpée à 16384, lecture bornée (`H2_MAX_FRAMES = 256`,
  `H2_MAX_TOTAL_BYTES`, en-têtes ≤ 65535, ≤ 64 CONTINUATION), ACK SETTINGS et
  PING, `WINDOW_UPDATE` connexion + flux pour les DATA **intermédiaires**
  (ignoré, sans invalider la réponse, sur la DATA END_STREAM), `:status` 200
  exigé, corps ≤ `MAX_DNS_BODY`, trailers ignorés, GOAWAY/RST_STREAM/trame
  tronquée/flux inattendu → erreur et connexion fermée (`h2_fail`). Mêmes
  délais socket.
- **Helpers partagés** (`src/doh/h2_frames.moon:10,82-124,156-166`).
  `H2_FRAME_RST_STREAM`, `h2_data_payload` (padding), `h2_read_header_block`
  (HEADERS + CONTINUATION, PADDED/PRIORITY, plafonds) et `h2_window_update`.
- **Tests.** `tests/unit/doh/upstream_doh_h2_spec.moon` (13 cas, faux TLS :
  réponse normale, CONTINUATION, trailers, statut ≠ 200, GOAWAY, RST_STREAM,
  corps > `MAX_DNS_BODY`, trame tronquée, DATA avant HEADERS, PING,
  WINDOW_UPDATE, champs HPACK de la requête) et
  `tests/unit/doh/upstream_doh_alpn_spec.moon` (3 cas avec la vraie libwolfssl
  en boucle locale, certificat px5g dans `./tmp/`, serveur fils `fork` :
  serveur configuré comme `worker_doh` ↔ client du repli, `get_alpn` vaut `h2`
  des deux côtés ; client n'offrant que `http/1.1` → `http/1.1` ; POST DoH
  HTTP/2 à travers `handle_doh_client`/`handle_h2` réels → 200 et réponse DNS.
  `pending` seulement si ALPN ou px5g manque). `tests/unit/auth/wolfssl_spec.moon`
  gagne 6 cas (dont la constante unique = 2) et ses deux attentes `options == 1`
  passent à `2`.

Preuve de la non-régression de la constante : avec
`WOLFSSL_ALPN_CONTINUE_ON_MISMATCH` remis temporairement à `0x01`, les trois cas
de `upstream_doh_alpn_spec.moon` échouent (`h.alpn == nil` au lieu de `h2`,
rapport serveur `alpn=nil` pour `http/1.1`), journal `tmp/alpn_0x01.log` ;
rétabli à `0x02`, ils passent.

Limites assumées : **un seul flux par connexion** (pas de multiplexage, le
worker ouvre déjà un client amont par connexion cliente), pas de server push,
pas de négociation de fenêtre initiale (les `WINDOW_UPDATE` rendent la fenêtre
par défaut), pas de proxy. `doc/CONFIG.md` est inchangé (aucune clé de
configuration nouvelle).

Preuve de la négociation réelle (environnement `nix develop`, wolfSSL 5.8.4) :
le test de boucle locale observe `alpn=h2` côté serveur (rapport
`tmp/h2_alpn/server.txt`) et `h.alpn == "h2"` côté client, puis une requête DoH
POST HTTP/2 complète traverse `handle_doh_client` et `handle_h2` réels ; il est
`pending` sur une libwolfssl sans `wolfSSL_UseALPN`/`wolfSSL_ALPN_GetProtocol`.

**Vérification (2026-11-11, branche d-h2client)** : `make all` et `make check`
OK (155 fichiers, aucune globale inconnue) ; `make test` = **2501 successes /
0 failures / 0 errors / 0 pending** (`tmp/test.log`), `make test-js` = 12 pass
/ 0 fail. `make test-e2e` non lancé (hors périmètre, pas de VM sollicitée).
### Rate-limiting des logs réellement effectif (branche d-logs)

Constat en pré-production (3000 dernières lignes de `logread` au niveau INFO) :
`suppressed=` n'apparaissait **0 fois**, malgré des rafales de lignes
identiques (`auth_server_conn_started` 3206, `auth_server_request_received`
3166, `response_dns_benchmark` 2719, `auth_server_ping_success` et
`auth_server_ping_received` 657 chacun, `response_no_ipv6_for_client` 634,
`questions_dns_stolen` 350, `doh_handshake_failed` 97).

Quatre causes dans `src/log.moon` (avant correctif) :
1. `check_rl` cherchait `RL_CONFIG[fields.action or level]` : les entrées
   `INFO:`/`DEBUG:` ne s'appliquaient qu'aux messages **sans** champ `action`,
   donc à presque aucun. Toute action non listée échappait au limiteur.
2. Le préfixe worker (`set_action_prefix`, appliqué dans `write_log` avant
   `check_rl`) rendait les règles nommées inopérantes : `no_ipv6_for_client`
   était émise `response_no_ipv6_for_client` (worker responses), de même pour
   `captive_*`, `doh_*`, `doh_vlan_*`, `sip_*`, `sni_*`, `questions_*`.
3. Aucune règle par défaut pour `WARN`/`ERROR` ; ces niveaux n'étaient jamais
   limités.
4. `_rl` était une table Lua **par processus** : les workers AUTH et DoH
   forkent un enfant par connexion (915 PID distincts pour 915 lignes
   `auth_server_request_received`), chaque enfant repartait d'un état vide ;
   deux workers ne partageaient rien.

Correctif :
- **Résolution** (`src/log.moon:178-192`) : action complète, puis action sans
  le préfixe worker, puis règle par défaut du **niveau** (appliquée même quand
  `action` est présent). Les entrées mortes `captive_probe` et
  `neigh_refreshed` (aucun site d'appel) sont supprimées de `RL_CONFIG`.
- **Défauts par niveau** (`src/log.moon:79-95`) : `ERROR`/`CRIT`/`ALERT`/`EMERG`
  10 s (une erreur ne doit pas rester masquée), `WARN`/`INFO`/`NOTICE` 60 s,
  `DEBUG`/`TRACE` 30 s, `ALLOW`/`BLOCK` 30 s.
- **Champs d'identité** (`src/log.moon:60-75`) : `peer`, `peer_ip`,
  `peer_mac`, `ip`, `ip_src`, `ip_dst`, `client`, `client_ip`, `client_mac`,
  `mac`, `mac_src`, `src_ip`, `dst_ip`, `qname`, `qnames`, `domain`, `qtype`,
  `hostname`, `host`, `sni`, `cert`, `key`, `path`, `method`, `url`, `file`,
  `ifname`, `name`, `queue`, `worker`, `user`, `username`, `vlan`, `resolver`,
  `resolver_ip`, `upstream_ip`, `addr`, `protocol`, `l4_proto`, `rcode`,
  `errno`, `source`, `direction`, `version`, `verdict`, `backend`, `type`,
  `cn`, `local_ip`, `rule`, `list`, `err`, `reason`, `cmd`. Jamais `pid`,
  `txid`, ports, durées, compteurs ni tailles : deux lignes qui n'en diffèrent
  que par eux fusionnent avec `suppressed=N`. Exclusions motivées (voir
  `doc/CONFIG.md`) : `status`, `mode`, `detail`, `af`/`family`.
- **Actions de cycle de vie jamais limitées** (`src/log.moon:100-130`) :
  `worker_died`, `child_crashed`, `worker_started`, `worker_stopping`,
  `worker_start`, `supervisor_running`, `supervisor_sigterm`,
  `supervisor_sighup_reload/kill/refork/forward_auth`, `dns-filter_start`,
  `config_source`, `config_external_missing`, plus `dns_benchmark`
  (instrumentation) et `log_rl_mmap_failed`/`log_rl_saturated` (diagnostic du
  limiteur) — un crash ou un rechargement répété doit rester visible ; ces
  actions sont rares hors boucle de crash (cf. corrections de revue
  ci-dessous).
- **État partagé** (`src/log.moon:145-175`) : table de hachage à taille fixe
  (4096 slots × 4 `uint32` + en-tête de 2 mots = 64 Kio) en
  `mmap(MAP_SHARED|MAP_ANONYMOUS)`, créée au chargement du module donc dans le
  superviseur **avant** tout fork, héritée par les workers et leurs enfants.
  Slot `{hash, ts, expires, count}`, hash djb2 32 bits, sondage linéaire borné
  à 8 (`RL_PROBE_MAX`) : deux empreintes distinctes dans le même slot occupent
  des slots différents (aucune supprimée à tort) ; une entrée n'est recyclée
  que si **sa propre** échéance (`expires = ts + fenêtre`) est passée, puis
  main d'horloge (32 slots) en cas de saturation, enfin journalisation sans
  suppression + compteur `rl_stats().saturated` et avertissement
  `log_rl_saturated` (une fois par processus, émis hors du chemin limité).
  Sans verrou : accès `uint32` alignés, le hash est relu après `ts`/`expires`
  et doit être stable — jamais de décision sur un slot en cours de recyclage.
  Repli sur une table Lua par processus (purge des expirées puis vidage en
  dernier recours) si `mmap` échoue, avec `action=log_rl_mmap_failed` (une fois
  par processus) et `rl_shared()`. `MAP_ANONYMOUS` est calculé depuis
  `jit.arch` (`0x800` sur MIPS où `0x20` est `MAP_RENAME`, `0x20` ailleurs).
- **ALLOW/BLOCK et benchmark** : `action=response_dns_benchmark` est **exempté**
  de rate-limiting (règle `dns_benchmark` de `RL_NEVER_LIMIT`, comme avant le
  commit `baf5837`) : sur un banc à qname fixe, la règle `ALLOW`/`BLOCK`
  (30 s, `mac_src`/`qname`/`qtype`) ne gardait qu'un échantillon par triplet et
  perdait les mesures des autres. Aucune autre action de banc n'existe.
  `doc/CONFIG.md` §2 et le commentaire de `src/worker_responses.moon:803-806`
  sont corrigés.
- **`suppressed=N` conservé** (`src/log.moon:295-315`, `format_line`) : la
  première ligne émise après la fenêtre porte le nombre de messages supprimés.
  Le formatage est extrait dans `format_line` (fonction pure, testable).

Tests (`tests/unit/log_spec.moon`, 34 cas) : `INFO`/`WARN`/`ERROR`/`DEBUG`
avec action non listée (suppression puis réémission avec compte) ; champ
d'identité différent non fusionné (y compris les ajouts `ip_src`, `ip_dst`,
`username`, `host`, `resolver`, `protocol`, `l4_proto`, `rcode`, `errno`,
`source`, `direction`, `version`, `verdict`, `backend`), champ volatil
(`pid`, `txid`, compteur) fusionné ; action préfixée
`response_no_ipv6_for_client` → règle spécifique 120 s sur `client` ;
`ALLOW`/`BLOCK` avec `response_dns_benchmark` **jamais limités** (et une action
voisine bien limitée, pour rendre le test non tautologique) ; fork réel
(l'enfant insère, le parent voit la répétition) ; collision de slot sans
suppression à tort ; `_rl_reset` ; actions de cycle de vie jamais limitées ;
strip du préfixe worker dans `_rl_never_limited` ; `rl_shared()` et
`rl_stats()` ; repli forcé par processus ; saturation (compteur + non
suppression) ; recyclage d'un slot expiré par une autre empreinte (échéance
propre, pas `RL_MAX_WINDOW`) ; horloge en marche arrière ; purge fine du repli ;
formatage `suppressed=N` (via `format_line`) et mise entre guillemets.

Documentation : `AGENTS.md:75`, `doc/CONFIG.md` §2 (rate-limiting et
benchmark), `doc/CHEATSHEET.md` (section logs), commentaire de
`src/worker_responses.moon:803-806`.

**Vérification (2026-11-11, branche d-logs)** : `nix develop --command bash -c
"make all && make check && make test"` OK ; `make check` = 155 fichiers, aucune
globale inconnue ; `make test` = **2544 successes / 0 failures / 0 errors /
0 pending** (`tmp/test.log`) ; `make test-js` = 12 pass / 0 fail. `make
test-e2e` non lancé (hors commande de clôture de la tâche, pas de VM
sollicitée).

### Corrections de revue du rate-limiting (branche d-logs, 2026-11-11)

Deux revues de code ont relevé des défauts résiduels dans `src/log.moon` ; ce
bloc documente les correctifs et **précise** les affirmations de la section
précédente (qui resta la description du commit d'origine).

- **P1.1 — `MAP_ANONYMOUS` dépend de l'architecture** (`src/log.moon`). La
  valeur `0x20` codée en dur est la valeur générique Linux (x86, ARM), mais sur
  MIPS `0x20` est `MAP_RENAME` et l'anonymat vaut `0x800`. Sur les cibles
  ath79/ramips (`jit.arch` commence par `mips`), `mmap(fd=-1)` échouait, le
  `pcall` avalait l'erreur et le partage inter-processus disparaissait
  silencieusement. La valeur est désormais choisie à l'exécution depuis
  `jit.arch` ; `MAP_SHARED = 0x01` reste commun.
- **P1.2 — échec `mmap` muet**. `rl_shared()` expose l'état (`true` = table
  partagée), `rl_stats()` le compteur de saturation, et le repli émet une fois
  par processus `WARN action=log_rl_mmap_failed reason=… arch=… rl_shared=0`.
  La ligne est écrite directement (`_emit_line`), sans passer par
  `write_log`/`check_rl` : le limiteur étant en panne, un appel au chemin
  limité risquerait une récursion. L'action figure aussi dans `RL_NEVER_LIMIT`.
- **P1.3 — `runtime.benchmark` rendu muet**. `dns_benchmark` est de nouveau
  dans `RL_NEVER_LIMIT` (comparaison après strip du préfixe `response_`) : la
  règle `ALLOW`/`BLOCK` (30 s, `mac_src`/`qname`/`qtype`) supprimait tous les
  échantillons d'un banc à qname fixe, donc précisément les mesures que
  l'option produit. Aucune autre action d'instrumentation n'est émise.
- **P2.1 — champs d'identité incomplets**. Ajout de `ip_src`, `ip_dst`,
  `username`, `host`, `resolver`, `protocol`, `l4_proto`, `rcode`, `errno`,
  `source`, `direction`, `version`, `verdict`, `backend`, `type`, `cn`,
  `local_ip`. `ip_src`/`ip_dst` discriminENT `sni_quic_drop` et
  `sni_reject_mark_failed` par client ; `username` discrimine les sessions
  AUTH (`user_session_refreshed`/`_removed` ne fusionnent plus entre
  utilisateurs, comme `user_session_added` qui porte déjà `src_ip`) ; `host`
  discrimine les amonts DoH. Inversement, `addr` est bien utilisé
  (`src/doh/upstream.moon:49`) : conservé. Exclusions motivées (`status`,
  `mode`, `detail`, `af`/`family`) documentées dans `doc/CONFIG.md`.
- **P2.2 — saturation = fail-open silencieux**. Chaque slot stocke désormais
  `{hash, ts, expires, count}` : le recyclage d'une autre empreinte n'a lieu
  que si **sa propre** échéance est passée (plus de `RL_MAX_WINDOW`
  conservateur qui empêchait de recycler une entrée INFO expirée depuis 60 s
  tant que 120 s n'étaient pas écoulées). Sondage épuisé → main d'horloge
  (32 slots) ; si rien n'est recyclable, la ligne passe et le compteur
  partagé `rl_stats().saturated` est incrémenté, avec un avertissement
  `log_rl_saturated` une fois par processus. La propriété « jamais une ligne
  supprimée à tort » est préservée et testée.
- **P2.3 — lecture non atomique `{hash, ts}`**. Le hash est relu après
  `ts`/`expires` ; s'il a changé (slot recyclé entre deux accès), le sondage
  continue sans décider. Aucune allocation ajoutée sur le chemin chaud.
- **P2.4 — marche arrière d'horloge**. `epoch < ts` est traité comme expiré
  (repli compris), sinon un step NTP rendait toutes les entrées éternellement
  vivantes et le recyclage impossible.
- **P2.5 — tests**. Seams `_rl_force_fallback(enabled)` et
  `_rl_slot_get/_rl_slot_set` ; `format_line` extrait pour tester le formatage
  `suppressed=N`. Couverture ajoutée : repli par processus, saturation,
  recyclage d'un slot expiré par une autre empreinte, strip du préfixe worker,
  horloge en marche arrière, purge fine du repli, et test « cycle de vie
  jamais limité » non tautologique (une action voisine doit renvoyer `-1`).

**Corrections de la section précédente** : « table saturée (plus de
`RL_PROBE_MAX` slots occupés) » était impropre — `RL_PROBE_MAX` est un nombre
de **pas de sondage**, pas de slots ; la saturation est désormais comptée et
signalée. Le repli ne vide plus toute la table : il purge d'abord les entrées
expirées. `now` reste exporté et utilisé (`src/worker_responses.moon:35`),
contrairement à ce qu'une revue supposait. Les actions `EMERG`/`ALERT`/`CRIT`/
`NOTICE`/`TRACE` restent déclarées dans `RL_CONFIG` sans émetteur : elles
servent de garde-fou pour de futurs call-sites et n'ont pas été supprimées.
`worker_started` reste exempté sans borne : une boucle de crash peut donc
produire une ligne par redémarrage. Non corrigé ici (P3) : borner cette
exemption demanderait un compteur par action dans l'en-tête partagé, à faire
si le bruit en boucle de crash devient gênant.

**Vérification (2026-11-11, branche d-logs, état final)** : renseignée dans le
compte rendu de la tâche (make all / make check / make test dans
`nix develop`). `make test-e2e` et `make coverage-quick` non lancés
(VM partagées avec un autre agent) ; ils le seront après coup.

### Trois écarts doc/code : `install-owrt`, schéma DoH, `metrics.maybe_flush` (branche d-final)

- **`install-owrt` accepte `utilisateur@hôte`** (`install-owrt.moon:624-648`,
  `:705`). La doc prescrivait `luajit install-owrt.lua root@<router>`
  (`doc/CHEATSHEET.md:323,333,336`, `README.md:306`) alors que `valid_host`
  refusait le `@`. Nouvelle fonction pure `split_user_host` : la partie avant
  `@` est validée par `valid_user` (même règle que `--user`), l'hôte par
  `valid_host` ; `@host`, `user@`, un second `@` et tout caractère interdit
  sont rejetés. `--user` explicite prime, quel que soit l'ordre des arguments
  (`user_explicit`) et rend la partie utilisateur de `HOST` inutilisée, donc
  non validée (`--user admin "foo!@host"` est accepté ; la partie vide
  `--user admin "@host"` reste rejetée). `--user` seul est toujours validé en
  fin de `parse_args`. `valid_host` (`:599`) n'admet plus que deux formes :
  `[<IPv6>]` ou un jeton sans crochet (hostname/IPv4, ou IPv6 nue contenant
  `:`), d'où le rejet de `a]b`, `[[::1]]`, `:::` (`valid_ipv6`, `:587`).
  **Cibles ssh/scp** (`:75-95`) : `ssh` ne résout pas un littéral entre
  crochets (`ssh root@[::1]` → « Could not resolve hostname »), `scp` en a
  besoin pour lever l'ambiguïté sur `:`. D'où deux helpers distincts et
  idempotents : `ssh_target` (sans crochets) et `scp_target` (crochets remis
  une seule fois), utilisés par `ssh_prefix`/`scp_send` et toutes les copies
  inline (`:246,301,351,377,491,514`). Un `root@[::1]` ne produit donc plus
  `root@[[::1]]`. Tests : `tests/unit/install_owrt_spec.moon:110-232` (formes
  IPv6 nues/crochetées, `--user` explicite, crochets mal placés, cibles
  ssh/scp et commande scp finale). La doc reste inchangée : elle devient
  exacte.
- **Schéma webui DoH aligné sur `cert`/`key`**
  (`src/webui/schema/config_schema.moon:132-133`). Le nom officiel est
  `doh.cert`/`doh.key` : DEFAULTS `src/config.moon:330-331`, lecture runtime
  `src/main.moon:168-169` et `src/worker_doh.moon:677-684`, config du paquet
  (`cfg/config.moon:7-8` pour AUTH, même convention), et
  `tests/unit/doh_config_spec.moon:42-48` affirme déjà l'absence de
  `cert_path`/`key_path`. Le schéma déclarait `cert_path`/`key_path`, jamais
  lus. Corrigé en `cert`/`key` (libellés conservés) et `doc/CONFIG.md:548-549`
  aligné. Test de garde :
  `tests/unit/webui/schema/config_schema_spec.moon` vérifie que chaque clé du
  schéma `doh` est déclarée dans le bloc DEFAULTS de `src/config.moon` ou lue
  par le runtime, et qu'aucun `cert_path`/`key_path` ne subsiste.
- **Suppression de `metrics.maybe_flush`, appel par paquet superflu**
  (`src/worker_questions.moon:234` auparavant). Vérifié dans le code :
  `run_queue` appelle `on_idle` **au début de chaque tour de boucle**, avant
  `poll` (`src/nfq_loop.moon:113-115`), pas seulement au timeout. La garantie
  réelle est **au moins une fois par lecture/poll, plus une fois par `idle_ms`**
  — et non « une fois par paquet » : une lecture netlink peut contenir
  plusieurs messages NFQUEUE, drainés en un seul `nfq_handle_packet`
  (`src/nfq_loop.moon:130-131`). `worker_questions` y branche déjà
  `metrics.flush_if_due` (`src/worker_questions.moon:549-550`). L'appel
  `maybe_flush` par paquet était donc redondant, ainsi que son compteur
  `check_every`. Fonction, export, état `_pkt_count`/`_check_every` et tests
  associés retirés (`src/metrics.moon:12-17,173-179,196`,
  `tests/unit/metrics_spec.moon`) ; l'import fictif de
  `tests/unit/worker_questions_spec.moon:129-133` est nettoyé. `flush_if_due`
  reste l'unique point d'export périodique (production et tests).

- **Garde-fou du schéma DoH rendu bidirectionnel et sans sous-chaîne**
  (`tests/unit/webui/schema/config_schema_spec.moon`). L'ancien contrôle
  cherchait `".doh.#{key}"` en sous-chaîne : la clé `upstream_doh` aurait
  matché `config.doh.upstream_doh_url`, et les DEFAULTS étaient extraits par
  découpage textuel approximatif. Désormais : `reads_key` exige un
  identifiant complet (le caractère suivant ne doit pas être `[%w_]`), les
  clés des DEFAULTS sont lues par motif strict `^\s+<clé>\s*:` dans le seul
  bloc `doh: {`, et le **sens inverse** est vérifié (toute clé
  `config.doh.<x>` lue par le runtime est annoncée). Ce sens inverse a révélé
  quatre clés réelles absentes du schéma : `doh.upstream_doh_url`,
  `doh.upstream_doh_tls_verify`, `doh.upstream_fallback_insecure`,
  `doh.upstream_fallback_ca_file` (`src/main.moon:172-175`), ajoutées à
  `src/webui/schema/config_schema.moon` avec les types/défauts de
  `doc/CONFIG.md` §11. `doh.cert_dir` n'est pas une clé doh : le runtime lit
  `config.auth.cert_dir` (`src/main.moon:171`) ; un test le constate
  explicitement pour éviter une fausse garde.

**Vérification (2026-11-11, branche d-final)** : `make all && make check &&
make test` = **2551 successes / 0 failures / 0 errors / 0 pending**
(`tmp/test.log`) ; `make test-js` = 12 pass / 0 fail. `make test-e2e` non
lancé (hors périmètre : aucun changement runtime réseau/nftables).
