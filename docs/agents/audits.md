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
