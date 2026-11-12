# Workers — I/O détaillé et formats IPC

Voir [architecture.md](architecture.md) pour la vue d'ensemble et le queue map.

---

## worker_questions (`src/worker_questions.moon`)

- **In :** NFQUEUE `QUEUE_QUESTIONS` ; fd d'écriture `question_response`, `learn` et `events` injectés par `main.moon`.
- **Multi-worker :** un worker par file de `nfqueue.questions`. Chacun écrit chaque transaction dans **tous** les pipes `question_response<i>` (`ipc.write_with_retry_all`) : chaque worker réponses possède la table `pending` complète. La question n'est jetée (`NF_DROP`) que si **tous** les tubes ont refusé l'écriture ; un seul destinataire en échec ne la perd plus. Un destinataire dont le tube est resté plein (EAGAIN) est **marqué saturé** : ses messages suivants ne coûtent plus qu'une écriture non bloquante, sans `nanosleep`, jusqu'au premier succès (`WARN ipc_write_saturated`, rate-limité par `ipc_fd`, `INFO ipc_write_resumed` à la reprise). Le retry bloquant (5 × 20 ms) n'est payé que pour un destinataire non marqué — contre-pression légitime du cas à un seul worker. Cf. [perf.md](../docs/agents/perf.md) §12.
- **Lecture config :** section `filter` de `/etc/custos/config.moon` via module `src/filter/`.
- **Out :** `NF_ACCEPT`/`NF_DROP` ; messages IPC via `ipc.write_msg` / `write_refused_msg` / `write_dnsonly_msg` dans `question_response` ; association IP→MAC dans `learn` ; événement DNS dans `events` ; instantané JSON `metrics-dns-q<N>.json` dans le répertoire d'exécution (celui du pidfile), écrit atomiquement à zéro au démarrage puis toutes les `metrics.flush_interval` secondes (point de passage `run_queue` et compteur de paquets ; page admin `/admin/metrics`, cf. [webui.md](../docs/agents/webui.md)).
- **Effets de bord :** logs `log_allow`/`log_block` ; métriques par règle (`metrics`).
- **Second avis (action `validate`) :** pour chaque question UDP autorisée par une règle portant l'action `validate` (`allow_modifiers.validate`), **duplique** le paquet (dst réécrite vers une IP `resolvers` de la bonne famille via `dup_query`, src/txid/qname préservés) et l'émet via un **socket RAW routé par le noyau** (`raw_send`, `IP_HDRINCL`/`IPV6_HDRINCL`, src = IP client) : pas de MAC de passerelle à connaître, IPv6 sur tunnel géré nativement. Une famille n'est activée que si un validateur de cette famille est routable. Best-effort, ne bloque pas.

## worker_responses (`src/worker_responses.moon`)

- **In :** NFQUEUE `QUEUE_RESPONSES` ; **son** pipe `question_response<i>` (lecture via `drain_pipe`) ; pipe ACK `nft` dédié ; pipe du bus de verdicts `so_verdict<i>` ; fd d'écriture `events` (`events_wfd`, injecté par `main.moon`) ; `sessions.lua` (cache mtime).
- **Drain du tube sans paquet :** le fd de `question_response<i>` est **toujours** dans les `extra_rfds` du `poll` de `nfq_loop` (`run`, avec `so_verdict<i>` s'il existe) et `on_extra_ready` le draine avec le même `drain_pipe`/`drain_on_msg` que `handle_response`. Sans cela, le tube n'était lu qu'à l'arrivée d'un paquet sur **cette** file : une file inactive (hachage NFQUEUE par couple d'adresses) le laissait se remplir, le worker questions échouait en EAGAIN et jetait les questions — blocage définitif observé en pré-prod ([perf.md](../docs/agents/perf.md) §12). La purge d'expiration de `pending` est entretenue sur ce chemin (tous les 64 réveils, `DRAIN_PURGE_EVERY`) car celle de `handle_response` (compteur mod 1000 paquets) ne tourne jamais sur une file inactive. `POLLHUP` (worker questions arrêté) retire le fd de la surveillance.
- **Multi-worker :** un worker par file de `nfqueue.responses`. La répartition du noyau étant par flux, une réponse peut arriver dans un autre worker que celui qui a lu la question : c'est sans conséquence, chaque worker reçoit une copie de **toutes** les transactions (fan-out du pipe) et possède donc une table `pending` complète. Le coût est de `N` copies de `pending` (TTL `ipc.pending_ttl`, 5 s ; borne `ipc.pending_max`, 20 000 entrées par worker, 5 000 en RAM faible, cf. ci-dessous) et `N` écritures par question.
- **Second avis inter-workers :** quand un worker reçoit la réponse du validateur (B), il diffuse le verdict encodé (`second_opinion.encode_verdict`) sur les pipes `so_verdict<j>` des autres workers (`broadcast_verdict`). Chacun l'applique (`drain_verdict_bus`) : s'il détient la réponse d'origine (A) parquée, il la débloque immédiatement ; sinon il mémorise le verdict pour une A ultérieure. Le pipe du bus est surveillé par le `poll` de `nfq_loop` (`extra_rfds`) : réveil immédiat, sans attendre le budget de 80 ms. À un seul worker, aucun bus n'est créé (chemin inchangé).
- **Out :** `NF_ACCEPT` ou `nfq_set_verdict(NF_ACCEPT, patched_payload)` (TTL + EDE `Custos vigilat`) ou NXDOMAIN+EDE `Filtered` pour les transactions refusées.
- **Effets de bord :** demande l'ajout dans `ip4_allowed`, `ip6_allowed`, `mac4_allowed`, `mac6_allowed` **via le pipe `nft`** (timeout `nft.ip_timeout`), puis attend l'ACK de `worker_nft` avant de rendre le verdict. Depuis le correctif de perf, **une seule attente d'ACK par lot NFQUEUE** (tous les paquets d'une même lecture netlink : `settle` diffère les verdicts, `nfq_loop.run_queue` appelle `flush_deferred` en fin de lot) au lieu d'une par réponse ; rafraîchit la table de voisins (`ip neigh show`) au plus toutes les `NEIGH_REFRESH_COOLDOWN` secondes. Quand `runtime.benchmark` est actif, la ligne `action=response_dns_benchmark` porte deux mesures **µs parallèles et non additives** : `ack_wait_us` (attente `nft_queue.wait_ack`, reportée de la transaction précédente car l'ACK est postérieur au log et à `set_verdict`) et `log_write_us` (dernier `libc.write` de journal terminé, cf. `log.set_timing`). Détail et avertissement : [doc/CONFIG.md](../doc/CONFIG.md#2-section-runtime).
- **Retry upstream (`dns.upstream_retry`) :** sur une réponse transitoirement en échec (rcode ∈ `rcodes`, défaut SERVFAIL/REFUSED), ne transmet pas la réponse au client : réémet la même question vers **le même résolveur** (`build_query_from_response` reconstruit la requête QR=0 ; `dup_query.build_query` inverse src/dst + ports ; `raw_send` via socket RAW, src client spoofée) et `NF_DROP` la réponse en échec. La transaction reste **non consommée** (`entry.upstream_retries` incrémenté, `entry.expire` prolongé) : la réponse du retry repasse par le pont, est recapturée et appariée à la même `entry`. Au-delà de `max_attempts`, la réponse en échec est transmise normalement. Évite le « refusé puis OK au rafraîchissement » dû à un upstream instable (ex. dynv6) : sans RR A/AAAA, aucune IP n'entre dans l'allowlist nft. `try_upstream_retry` / `arm_retry_fds` (sockets RAW par famille armés dans `run`). `entry.upstream_retries` n'est qu'un **compteur** (aucune durée d'attente upstream n'est stockée) ; il est exposé tel quel dans la ligne `action=response_dns_benchmark` (champ `upstream_retries`, `0` si aucun retry upstream). Cette ligne porte aussi `ipc_retry_attempts` / `ipc_retry_wait_ms`, qui mesurent le **retry d'appariement IPC** (`ipc.match_retry`, réponse arrivée avant la question) et non le retry upstream — ne pas confondre les deux. Le détail par tentative reste en `DEBUG` (`action=response_upstream_retry`). **NXDOMAIN** (rcode 3) est retenté par défaut (l'autoritatif dynv6 renvoie NXDOMAIN par intermittence pour des noms qui existent, sur tous les résolveurs) ; pour ne pas pénaliser les NXDOMAIN légitimes, un nom dont **même le retry** reste NXDOMAIN entre dans un cache `nxdomain_bad` (`lib.ttl_set`, TTL `nxdomain_bad_ttl`) et n'y est plus retenté jusqu'à ce qu'il résolve de nouveau (NOERROR le réhabilite).
- **Second avis (action `validate`) :** identifie la réponse **validateur** (src ∈ `resolvers`) et l'utilise pour le verdict (`dns_classify` : NXDOMAIN→block ; **sinkhole `0.0.0.0`/`::`→sinkhole** — DNSforFamily bloque par `NOERROR + A 0.0.0.0`, pas par NXDOMAIN ; CNAME→redirect ; sinon pass) sans jamais la transmettre (NF_DROP). N'entre en jeu que si `entry.modifiers.validate` est vrai (règle portant l'action `validate`). Corrélation `(client, txid, qname)` (`second_opinion.moon`). La réponse d'origine est **parquée** (verdict NFQUEUE différé, retour `-1` sans poser de verdict) jusqu'à l'arrivée du verdict ou l'expiration de `budget_ms` (balayage via le timeout `poll` de `nfq_loop` → `sweep_parked`, fail-open). Application via `finalize_a` : `build_nxdomain_response` (block), `build_sinkhole_response` (reproduit les adresses nulles, sinkhole) ou `build_cname_response` + injection nft (redirect). L'EDE porte « Filtered by upstream validator » (pas la raison d'autorisation locale). Les overrides **block** et **sinkhole** émettent en plus une ligne d'événement `block` (`format_block_event` → `events_wfd`) pour que ces blocages apparaissent dans les events agrégés et la liste `/refusals` du portail — sinon ils resteraient invisibles, `worker_questions` ayant déjà loggé la requête en `allow`.
- **Non-appariement (réponse orpheline) :** si aucune `entry` n'est trouvée après le retry d'appariement, la réponse est **jetée** (`NF_DROP` : Custos ne relaie jamais une réponse non sollicitée) et l'événement est tracé en `INFO` sous `action=response_orphan_dropped` (champs `txid`, `dst_ip`/`dst_port` du client, `src_ip` du résolveur, `qname`, `rcode`, `client_mac`, `ipc_retry_attempts`, `ipc_retry_wait_ms`, `retry_budget_skipped`), via la fonction pure `build_orphan_fields`. C'est le **seul témoin** d'une réponse client perdue : auparavant DEBUG seulement (donc muet en production, `log_level: "INFO"`). Le détail par tentative reste en `DEBUG` (`response_no_matching_question[_after_retry]`). Débit borné par `log.moon` (`RL_CONFIG.response_orphan_dropped`, clé = action, fenêtre 10 s, état mmap partagé entre workers, occurrences dans `suppressed=N`).
- **Budget du retry d'appariement :** `retry_pending_match` fait au plus `count` × `sleep_ms` `nanosleep` **mais** chaque tentative est débitée d'un budget de sommeil global par seconde d'epoch (`ipc.match_retry.budget_ms`, défaut 100 ms, état `_retry_budget`) : budget épuisé → retry **sauté** (aucun `nanosleep`, 4ᵉ retour `budget_skipped=true`) et réponse traitée comme orpheline. Le cas nominal (réordonnancement IPC isolé) reste servi (20 ms consommés) ; le pire cas plafonne le temps de retry à 10 % au lieu de sérialiser le worker (5 × 20 ms = 100 ms par orpheline, ~10 réponses/s). L'arithmétique est isolée dans la fonction pure `plan_retry_tries`. Détails : [doc/CONFIG.md](../doc/CONFIG.md#6-section-ipc).

## worker_captive (`src/worker_captive.moon`)

- **In :** NFQUEUE `QUEUE_CAPTIVE` (TCP SYN/80 non authentifié) ; socket `AF_PACKET`/`SOCK_RAW` ouvert sur ifindex `br` (une seule fois au démarrage) ; `sessions.lua`.
- **Out :** `NF_DROP` sur le SYN ; 3 frames Ethernet injectées via `sendto()` sur le socket raw : SYN-ACK, HTTP 302, FIN-ACK.
  - MAC bridge lu depuis `/sys/class/net/br/address`.
  - AF_PACKET obligatoire : NFQUEUE ne peut pas inverser le sens ni injecter plusieurs paquets.
- **Config :** `auth_cfg.captive_ip4` / `captive_ip6` / `port` (défaut 33443) pour l'URL de redirection.
- **Skip redirect pour MAC authentifiée :** si `user_for_mac` retourne un utilisateur (session active en `sessions.lua`), le worker n'envoie **pas** les 3 frames de redirection. Il ajoute la nouvelle IP dans les sets nftables (`authenticated_ips`/`authenticated_ips6`, `authenticated_macs`) et enrichit `sessions.lua` avec la nouvelle IP (utile lors de la rotation d'adresses IPv6 temporaires / Privacy Extensions). L'action est loguée `captive_skip_authenticated`.

## worker_reject (`src/worker_reject.moon`)

- **In :** NFQUEUE `QUEUE_REJECT` (trafic drop résiduel, rate-limité par nft).
- **Out :** `nfq_set_verdict(NF_ACCEPT, forged_ip_pkt)`.
  - TCP → RST/ACK (src/dst IPs et ports inversés, seq/ack corrects).
  - Autre L4 → ICMPv4 type 3/code 13 ou ICMPv6 type 1/code 1 (admin-prohibited), citant l'en-tête IP original + 8 octets.
- Le chemin de livraison exact du paquet forgé (FDB bridge, re-hook noyau…) n'a pas été rétro-ingénié ; ne pas faire d'hypothèse dessus.

## worker_auth_queue (`src/worker_auth_queue.moon`)

- **In :** NFQUEUE `QUEUE_AUTH` (trafic port 33443) ; fd d'écriture `learn` injecté par `main.moon`.
- **Out :** `NF_ACCEPT` (laisse passer le paquet vers `auth/worker`) ; écrit le couple MAC+IP dans le pipe `learn` (22 octets) → `mac_learner`.

## worker_tls (`src/worker_tls.moon`) — optionnel (`nfqueue.sni`)

- **In :** NFQUEUE `QUEUE_SNI` (TCP/443 ACK path + UDP/443 QUIC Initial) ; pipe `events` ; pipe ACK `nft` dédié.
- **Placement nft (`sni.placement`) :** le placeholder
  `{SNI_RULES_PRE}` / `{SNI_RULES_POST}` du template `dns-filter-bridge.nft` est
  rendu par `nft_rules.substitute` selon la valeur de `placement` :
  - `"integral"` : règle posée **AVANT** `cv_rules_dispatch`/`cv_action_vmap`,
    afin que **tout** le trafic 443 soit inspecté par SNI, y compris les
    destinations déjà autorisées par DNS (aucun contournement possible) ;
  - `"residual"` (défaut) : règle posée **APRÈS** `@cv_action_vmap`, donc seul le
    trafic non déjà autorisé atteint la file SNI (filet de sécurité, moins
    intrusif).

  Dans les deux cas la règle porte le flag `bypass` : si le worker SNI est absent
  (`nfqueue.sni` non défini → file sans listener), le paquet continue vers le
  dispatch DNS au lieu d'être droppé.
- **Traitement :**
  - réassemble les ClientHello TLS fragmentés sur plusieurs segments TCP via
    `ipparse.l4.tcp_stream` (comme `worker_questions` pour le DNS/TCP) et les
    CRYPTO frames QUIC multi-datagrammes via `ipparse.l7.quic.session`,
  - extrait le SNI (TLS/QUIC) via `ipparse`,
  - applique `filter.decide` sur le SNI normalisé,
  - en mode `sni.mode = strict-443` :
    - **allow** → ajoute la paire client→destination dans les sets nft (`ip*_allowed`, `mac*_allowed`) **via le pipe `nft`**,
    - **deny/no_sni** → `NF_DROP`.
- **Out :** `NF_ACCEPT` ou `NF_DROP` selon la policy `sni` (`protocols`, `nft_failure_policy`).

## worker_sip (`src/worker_sip.moon`) — optionnel (`nfqueue.sip`)

- **In :** NFQUEUE `QUEUE_SIP` (signalisation SIP + STUN/ICE) ; pipe ACK `nft` dédié.
- **Traitement :** parse SIP/SDP (`src/sip/parser.moon`), extrait les IP de médias (RTP/RTCP) et l'IP du proxy.
- **Out :** `NF_ACCEPT` ; whiteliste les IP proxy + médias dans des sets nft par règle **via le pipe `nft`** (TTL `nft.sip_session_ttl`). Ports RTP exclus configurables (`rtp.excluded_ports`).

## worker_doh (`src/worker_doh.moon`) — optionnel (`doh.enabled`)

- **In :** serveur HTTPS **WolfSSL FFI** sur `doh.port` (défaut 8443) ; pipe ACK `nft` dédié. Pas de NFQUEUE.
- **Traitement :** reçoit les requêtes DoH RFC 8484 (HTTP/1.1 ou HTTP/2 — détection par préface `PRI *`), résout en amont, applique `filter.decide` + `doh.validator` (second avis synchrone si règle `validate`), injecte les IPs autorisées dans nft.
- **Upstream :** UDP/53 par défaut (`doh.upstream_ipv4`/`upstream_ipv6`) ; si `doh.upstream_doh_url` est défini, utilise **libcurl** (`doh.upstream_doh_curl`) pour HTTP/2 + ALPN. Sélection dans `make_upstream` au démarrage du worker.
- **Second avis DoH :** `doh.validator.query_verdict` interroge `second_opinion.resolvers` (ou `validate_resolvers` per-règle) **de façon synchrone**, en UDP (`doh.upstream`) ou DoH (`doh.upstream_doh_curl`). Timeout distinct : `budget_ms` (UDP) vs `doh_budget_ms` (DoH https://). Fail-open.
- **H2 partagé :** utilitaires frames HTTP/2 (`h2_read_frame`, `h2_write_frame`, constantes) factorisés dans `doh.h2_frames`.
- **`from_vlan` en DoH :** `req.vlan` est renseigné via `mac_learner_ipc.get_vlan(peer_ip)` (après `getpeername`, comme `get_mac`), alimenté par `worker_doh_vlan`. Untagged → `req.vlan = nil` (parité UDP). Détails et anti-spoofing : AGENTS.md « `from_vlan` en DoH ».
- **Out :** réponse DoH au client ; paires autorisées injectées dans les sets nft **via le pipe `nft`**.

## worker_doh_vlan (`src/worker_doh_vlan.moon`) — optionnel (`doh.enabled` + `nfqueue.doh_vlan`)

- **In :** NFQUEUE `nfqueue.doh_vlan` (chaîne **input du bridge**, placeholder `{DOH_VLAN_INPUT_CHAIN}` : trafic host-bound vers `doh.port`, tagué ET untagged) ; fd d'écriture `vlan_learn` injecté par `main.moon`.
- **Traitement :** lit le VLAN (`get_l2` → `nfq_get_nfmark`, recopié par nft) + l'IP source (`ipparse.l3.ip`), encode `ip16 + vlan16` (`encode_vlan_msg`).
- **Out :** `NF_ACCEPT` **toujours** (le filtrage du flux DoH reste au serveur DoH) ; écrit le couple IP+VLAN dans le pipe `vlan_learn` (18 octets) → `mac_learner`. Untagged (`vlan == 0`) émis explicitement (écrase l'entrée stale, anti-spoofing).

## worker_nft (`src/worker_nft.moon`)

- **In :** pipe `nft` (commandes d'insertion sérialisées de tous les producteurs : responses, tls, sip, doh).
- **Out :** exécute les transactions nftables, puis écrit sur le `ack_<i>` du worker producteur concerné un ACK de taille fixe (8 octets, `uint64` natif) portant le plus grand `seq` appliqué pour ce worker dans le flush. Un seul ACK par `(flush × worker)`.
- **Regroupement :** `build_batch` regroupe les éléments en attente par set et émet **une instruction `add element <table> <set> { e1, e2, … }`** (timeout par élément dans la liste) au lieu d'une instruction par élément — le coût nft est dominé par le nombre d'instructions (docs/agents/perf.md §8). Si le lot groupé est rejeté (un élément invalide suffit), repli élément par élément : les éléments valides sont quand même appliqués, comportement historique préservé.
- **Cache d'upsert (anti-réinsertion) :** `try_add_pending` consulte un cache **borné** (`new_cache`, 4096 entrées, `CACHE_MAX_ENTRIES`) dont la clé est `(famille/table, set, élément)` — soit `family|table|set_name|key|ip` (`cache_key_of`) — et la valeur l'instant **et** le timeout de la dernière insertion **appliquée avec succès** (`cache_put`, appelé par `flush_batch` sur transaction groupée réussie ou sur chaque reprise élément par élément réussie). Une ligne est **sautée** (non ajoutée à `pending`, donc aucune transaction nft) quand la même clé a été insérée il y a moins de `min(timeout/10, 5 s)` **et** que le nouveau timeout n'est pas plus long que le précédent de plus que cette même fenêtre ; sans timeout valide dans la ligne (`has_timeout`, `parse_line`) aucun saut. Les lignes sautées restent **ACKées** : `run` met le seq dans `ack_queue` avant l'appel, l'ACK du producteur couvre donc aussi les lignes sautées (l'élément existe déjà dans nft). **Invalidation** : échec de transaction nft → `cache_drop` sur les entrées du lot concerné (transaction atomique : rien n'a été appliqué) ; le seul `flush ruleset` du template n'est appliqué qu'avant le fork du worker (inventaire chiffré `tmp/nftcache_report.md` §Invalidations). **Exclusions** : kinds `auth_mac`/`auth_ip4`/`auth_ip6` et sets `authenticated_ips/ips6/macs` + `ip4/ip6_dest_whitelist`, vidés ou supprimés **hors** `worker_nft` (`src/auth/nft_sessions.moon:40,53,85` logout/bye/expiration, `src/ip_whitelist.moon:31-32` chaque SIGHUP, `src/auth/nft_auth_sets.moon:29,31` logout) — `cache_key_of` ne leur attribue aucune clé (`UNCACHEABLE_KINDS`/`UNCACHEABLE_SETS`, `cacheable_set`) : **ni saut ni enregistrement** (détail et écart de scénario : `docs/agents/audits.md` § « Exclusions du cache »). **Borne mémoire** : purge des entrées périmées (âge ≥ 5 s, inutiles au saut) puis éviction des plus anciennes jusqu'à 3/4 de la borne, uniquement sur débordement — 4096 entrées pleines mesurées à **932 Kio (233 o/entrée)**. Compteur cumulé `skipped` rapporté sur les logs `batch_ok` / `batch_ack_only` / `batch_failed` (DEBUG), champ classé volatil dans l'empreinte (`src/log.moon`). Le cache est propre au processus : tout redémarrage de `worker_nft` (refork du superviseur) le remet à zéro.
- **Rôle :** sérialise les écritures nft (évite les transactions concurrentes) et garantit la présence de l'élément dans le set avant que le producteur rende son verdict.

## worker_events (`src/worker_events.moon`)

- **In :** pipe `events` (événements DNS de `worker_questions`).
- **Out :** agrège et persiste les événements sous `events.dir` (rotation : `events.max_age_hours`, purge si espace libre < `events.min_free_pct`). Consommé par l'interface admin.
- **Ring-buffer temps réel unique** `recent-verdicts.tsv` dans `events.dir`, écrit par flush atomique throttlé (`VERDICTS_MIN_INTERVAL`) et au SIGTERM :
  - `note_verdict`/`flush_verdicts` — jusqu'à `VERDICTS_MAX` (8192) verdicts, **toutes décisions** (allow ET block), dédup LRU sur `(mac, qname, decision)` avec compteur (un verdict répété n'est gardé qu'une fois, le plus récent). Format : `mac\tip\tuser\tqname\tdecision\treason\tcount\tfirst_ts\tlast_ts`.
  - Source unique de trois UX : `/refusals` (portail captif, filtre `decision == "block"` + MAC du client, `auth/handlers.handle_refusals`) ; `/admin/config/devices` (agrégation par MAC, un appareil par ligne, `webui/handlers/devices.read_devices`) ; `/admin/config/verdicts` (liste brute, lecture seule, `webui/handlers/verdicts.moon`).

## worker_arp_sniffer (`src/worker_arp_sniffer.moon`)

- **In :** un socket `AF_PACKET/SOCK_RAW` (`ETH_P_ALL`, mode promiscuous) par interface. Un filtre **cBPF noyau** (`SO_ATTACH_FILTER`, `BPF_PROG`) ne laisse remonter que les trames ARP (`0x0806`) et IPv6/ICMPv6 NS/NA (type 135/136) — sans ce filtre le worker était réveillé (et allouait une string Lua) sur **chaque** paquet du plan de données, saturant un cœur sous charge. Le filtrage EtherType/NDP est ensuite re-vérifié en Lua (mêmes offsets).
- **Out :** écrit les associations IP→MAC découvertes dans le pipe `learn` (22 octets).
- Aucun verdict NFQUEUE, aucune modification de paquet.

## mac_learner (`src/mac_learner.moon`)

- **In :** pipe `learn` (messages binaires 22 octets, IP→MAC) ; pipe `vlan_learn` (messages 18 octets `ip16+vlan16`, IP→VLAN, depuis `worker_doh_vlan`) ; socket Unix `SOCK_STREAM` (requêtes texte : `"ip_str\n"` pour la MAC, `"vlan:ip_str\n"` pour le VLAN).
- **Out :** répond `"aa:bb:cc:dd:ee:ff\n"` ou `"unknown\n"` (MAC) ; `"<id>\n"` (VLAN, `0` = untagged observé) ou `"unknown\n"` (jamais vu) sur le socket Unix. `vlan_table` indexée par IP (TTL `entry_ttl`), untagged mémorisé tel quel (écrasement anti-stale).
- Sondage actif : si l'IP est inconnue, `mac_prober` envoie un ARP request ou Neighbor Solicitation sans bloquer. Les clients en attente sont notifiés dès la réponse ou à l'expiration de `PROBE_TIMEOUT_MS`.

## auth/worker (`src/auth/worker.moon`)

- **In :** sockets `AF_INET` + `AF_INET6` `SOCK_STREAM` sur `auth_cfg.port` (défaut 33443 ; HTTPS, **TLS via WolfSSL FFI** — `src/auth/ffi_wolfssl.moon`, certificats px5g dynamiques par **nom SNI** demandé (`recv MSG_PEEK` du ClientHello avant le handshake, `src/auth/sni_peek.moon`), avec repli sur l'**IP locale** du socket si le SNI est absent, invalide, hors quota ou si sa génération échoue) ; `/etc/custos/secrets` ; `sessions.lua` ; résolution MAC via socket Unix → `mac_learner`.
- **Out :** écrit `sessions.lua` (rename atomique) ; gère les sets nft `authenticated_macs`, `authenticated_ips`, `authenticated_ips6`.
- **Interface admin :** `src/auth/server.moon` route les requêtes `/admin/*` vers `src/webui/router.moon` (édition de config, règles, listes, dictionnaires nommés ; reload SIGHUP). Accès réservé aux sessions admin (`auth.admin_users`).
- **Signaux :** `SIGHUP` → flag positionné dans le handler, rechargement des secrets au prochain cycle.
- **IPv6 dual-stack :** deux sockets distincts + `socket.select` ; ne jamais remplacer par `socket.bind "*"` (IPv4 uniquement).
- **Fork par connexion :** chaque connexion acceptée est traitée dans un enfant via `dispatch_connection` (`server.moon`). Un échec transitoire de `fork()` (EAGAIN/ENOMEM sur routeur à faible RAM) **ne doit jamais** remonter dans la boucle `run` : `dispatch_connection` l'isole dans un `pcall`, ferme la connexion et continue. Sans cette garde, l'`error()` de `fork_child` tuait le worker AUTH → toutes les connexions refusées (status 0, pas de négociation TLS) jusqu'au redémarrage par le superviseur, d'où des « page refusée, puis OK au rechargement ».
- **Contexte TLS statique hérité :** `resolve_tls_ctx` (`server.moon`) choisit le contexte TLS par connexion. Quand un cert statique est configuré (`auth.cert`/`auth.key`), le contexte est construit **une seule fois** dans le parent (`run`) puis hérité par les enfants via `fork()` (COW) — aucune relecture disque ni reconstruction par connexion. Repli sur `load_static` (chemins dans `state.static_cert_paths`) si le contexte hérité manque, sinon génération/cache dynamique par nom SNI (`cert_name_for` : `sanitize_hostname` + quota `SNI_CERT_MAX_NAMES`) avec repli sur l'IP locale ; dans le cas statique, le ClientHello n'est pas observé. Écriture des paires `.key`/`.crt` atomique et verrouillée (`src/auth/cert_files.moon`). ⚠️ `load_static` retourne `(ctx, err)` : capturer le contexte dans la **première** valeur (l'inversion `ok, ctx = load_static …` mettait `static_tls_ctx` à `nil`, ce qui avait fait croire à tort que le contexte ne survivait pas au fork et imposé un rechargement par connexion).

---

## Format IPC question → response (`question_response` pipe)

Défini dans `src/ipc.moon` (format **texte** A4, `IPC_VERSION = "v1"`, une ligne
`|`-séparée terminée par `\n` ; le tableau binaire 43 octets qui figurait ici
était le format historique, remplacé). Écriture atomique garantie
(< `PIPE_BUF = 4096`, ligne ≤ `IPC_MAX_LINE = 1024`).

**Table `pending` (appariement).** Clé : `txid:ip_client:port_client:ip_résolveur`
(`make_key`). `set_pending` alimente l'entrée à chaque message drainé ;
`get_pending_entry` la lit (avec purge à l'expiration de `pending_ttl`) et
`consume` la supprime (one-shot). La table est **bornée** par `ipc.pending_max`
(défaut auto : 20 000 entrées par worker réponses, 5 000 en mode RAM faible,
≈ 0,84 Ko/entrée mesuré) : au-delà, l'entrée à l'activité la plus ancienne est
évincée en O(1) (liste doublement
chaînée, sans tri), `pending_stats` expose `size`/`evicted`, et un `WARN`
rate-limité `pending_evicted` est émis (clé = action, 10 s). Une réponse dont
la question a été évincée suit le chemin d'une question expirée :
`get_pending_entry` renvoie nil, la réponse est jetée comme orpheline
(`NF_DROP`, `response_orphan_dropped`) — aucun comportement nouveau.
Sur **collision de clé**, l'entrée et le
message sont comparés champ à champ (`refused`, `rule_id`, `reason`,
`timeout`, `modifiers`, `response_rule_ids`). Cas identique (retransmission UDP
dominante) : **first-wins** (`overwrite_pending`), seul `expire` est rafraîchi
et les jalons benchmark de la première question sont conservés. Cas divergent :
verdict le plus restrictif (**fail-closed**) — si l'une des questions est
refusée, l'entrée conservée est celle de la question refusée ; si les deux sont
autorisées par des règles différentes, l'entrée est marquée refusée
(`ipc_pending_conflict`), aucun choix n'étant prouvable non élargissant. La
collision est tracée en `INFO` (`ipc_pending_overwrite`) et la divergence en
`WARN` (`ipc_pending_overwrite_divergent`), tous deux rate-limités (clé =
action, 10 s, état mmap partagé). `qname`/`qtype` ne figurent pas dans le
protocole : une divergence de contenu de question à métadonnées identiques
n'est pas détectable. Détails : [doc/CONFIG.md](../doc/CONFIG.md#6-section-ipc).

## Format IPC `learn` (22 octets)

Utilisé par `worker_questions`, `worker_arp_sniffer` et `worker_auth_queue` → `mac_learner`.

| Offset | Taille | Champ |
|--------|--------|-------|
| 0–15 | 16 | IP — IPv4 paddée à gauche par `0x00`×12, ou IPv6 complète |
| 16–21 | 6 | MAC (6 octets bruts) |

## Pipes `events`, `nft`, `ack_<i>` et `so_verdict_<i>`

- `events` : événements DNS sérialisés par `worker_questions`, consommés par `worker_events` (format interne au module, longueur variable).
- `nft` : commandes d'insertion nft sérialisées (set, famille, élément, timeout, index de worker pour l'ACK), de `worker_responses`/`worker_tls`/`worker_sip`/`worker_doh` vers `worker_nft`.
- `ack_<i>` : un pipe par worker producteur. Après chaque flush de batch, `worker_nft` y écrit **un** ACK par worker présent dans le batch : un enregistrement de taille fixe (`ACK_SIZE` = 8 octets, `uint64` natif, écrit en un seul `write` donc atomique) portant le plus grand `seq` appliqué pour ce worker. `nft_queue.wait_ack` ne rend la main que si cet ACK porte un `seq` ≥ `pending_seq` (le seq de la dernière ligne enfilée par l'appel) ; un ACK antérieur — typiquement l'acquittement des 64 premiers éléments d'un inject coupé par `MAX_BATCH` — est ignoré et l'attente continue, sans dépasser le budget global `ACK_TIMEOUT_MS`. Le `worker_responses` n'appelle `wait_ack` qu'**une fois par lot NFQUEUE** (`flush_deferred` en fin de lecture netlink, verdicts différés) : `pending_seq` est alors le plus grand seq enfilé par le lot, ce qui couvre toutes ses insertions. Aucune purge d'ACK n'est faite en cours de lot (`drain_ack!` seulement hors lot) et `nft_queue` mémorise le plus grand seq déjà acquitté (`last_acked_seq`, remis à zéro par `reset_ack_state!` au démarrage du worker) : un ACK déjà lu — y compris purgé — ne fait plus expirer les 150 ms du budget, et un ACK résiduel d'un producteur précédent ne peut pas satisfaire une attente du nouveau (seq reparti de 1). Le bout du tube est drainé par `drain_ack` (enregistrements complets et fragments). Un échec de transaction nft est acquitté comme aujourd'hui (après les reprises ligne à ligne) : l'ACK signifie « batch traité », pas « insertion réussie » ; le producteur applique ensuite `nft.add_failure_policy`. Le compteur `seq` est monotone par processus et sans rebouclage (2^53 insertions) ; un redémarrage repart de zéro, les ACK résiduels étant purgés par `drain_ack` avant l'injection suivante. **Multi-worker :** le `worker_idx` voyage dans la ligne `nft` ; chaque worker réponses a son propre tube, donc un ACK ne peut pas être consommé par un autre worker.
- `so_verdict_<i>` : bus du second avis (`nfqueue.responses` en plage). Ligne texte bornée (`second_opinion.encode_verdict`, < `PIPE_BUF` : écriture atomique) : version, kind (`b`/`s`/`r`/`p`), IP client, txid, TTL (`-1` = absent), qname et cible CNAME en hexadécimal, adresses A/AAAA en CSV hexadécimal. Chaque worker réponses n'écrit **qu'aux autres** (son propre verdict est déjà appliqué en ligne) ; il ne lit que son tube, et le `poll` de `nfq_loop` le surveille (`extra_rfds`) pour débloquer sans délai une réponse parquée. Un tube plein (worker bloqué) perd le verdict : la réponse concernée expire alors en fail-open, comme avant.

## État par processus des workers DNS (compatibilité multi-worker)

Analyse menée avant d'autoriser plus d'un worker par file (question du
2026-11-12). Les éléments qui restent locaux au processus sont sans effet sur
l'appariement du fait des fan-outs ci-dessus.

| État | Où | Multi-worker |
|------|----|--------------|
| `pending` (appariement) | `src/ipc.moon` (`set_pending` / `get_pending_entry` / `consume` / `purge_pending`), privé au processus | **fan-out** : chaque worker reçoit toutes les transactions → correct |
| `mac_clients` / `ip_to_mac` (MAC du client, cross-family) | `worker_responses.moon:239-242` | alimentés par le même `pending` → complets dans chaque worker |
| `tcp_state` (réassemblage DNS/TCP) | `worker_responses.moon:175` | hachage par flux → tous les segments d'un flux au même worker |
| `deferred` (verdicts différés du lot) | `worker_responses.moon:395` | par lot, donc par processus → correct |
| `nft_queue` (`seq`, `last_acked_seq`) | `nft_queue.moon:32-51` | un tube ACK par worker (`worker_idx` dans la ligne nft) → correct |
| `so_state` (parqués + verdicts B) | `second_opinion.moon` | **bus `so_verdict`** entre workers (A et B ont des files différentes) |
| `nxdomain_bad`, `strip_query_cache` | `worker_responses.moon:69,90` | caches par processus : duplication bénigne (aucune décision élargie) |
| `_retry_budget` (budget IPC par seconde) | `worker_responses.moon:228` | budget par worker → budget global × N (assumé, documenté) |
| compteurs de métriques | `worker_questions.moon:484-489` | un fichier `metrics-dns-q<N>.json` par file (agrégés par la page admin) |
| rate-limiting des logs | `log.moon` (table mmap partagée) | déjà partagé entre processus |

## Helpers partagés (`src/packet_utils.moon`)

Fonctions communes aux workers manipulant des paquets bruts :

- `skip_ipv6_ext_hdrs` — saut des en-têtes d'extension IPv6, renvoie proto L4 + offset.
- `mac2s(s, off=1)` — formate 6 octets d'une chaîne en `aa:bb:cc:dd:ee:ff`. Utilisé par `worker_tls`, `worker_arp_sniffer`, `mac_learner`, `mac_learner_ipc`, `mac_prober` et `nfq/ethernet` (ne pas re-implémenter localement).
- `dns_tcp_complete` / `new_dns_tcp_stream` — réassemblage DNS-over-TCP.

### Modules `src/lib/` partagés (paquets / DNS)

- `lib/checksums.moon` — accès byte-level big-endian (`r16/w16/w32/fold16`) et
  recalcul checksums sur buffers FFI : `fix_ip4_cksum(buf, ihl)` et
  `fix_l4_cksum(buf, pkt_len, l4_off, version, proto)` (UDP/TCP × IPv4/IPv6,
  pseudo-header dérivé de `version`). Distinct de `ipparse.l3.lib` (checksum sur
  strings, utilisé par `worker_reject`). Consommé par `worker_responses` /
  `lib.dns_response`.
- `lib/packet_parsing.moon` — agrège les `parse` ipparse L3/L4/L7
  (`parse_ip4/ip6/udp/tcp/dns`, `ip2s`, `dns_types`). Utilisé par
  `worker_questions` et `worker_responses` (évite le bloc de `require` dupliqué).
- `lib/dns_response.moon` — fonctions pures de (re)construction de réponse DNS :
  `replace_dns_payload` (reconstruit un paquet IP + recalcul checksums) et
  formatage des RR (`parse_answers`, `fmt_rdata`, `decode_simple_cname`).
- `lib/shquote.moon` — `shquote(s)` échappe un argument shell POSIX (quotes
  simples) ; à utiliser pour toute interpolation dans `io.popen`/`os.execute`.
