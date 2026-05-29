# Workers — I/O détaillé et formats IPC

Voir [architecture.md](architecture.md) pour la vue d'ensemble et le queue map.

---

## worker_questions (`src/worker_questions.moon`)

- **In :** NFQUEUE `QUEUE_QUESTIONS`, fd d'écriture `question_response`, `learn` et `events` injectés par `main.moon`.
- **Lecture config :** section `filter` de `/etc/custos/config.moon` via module `src/filter/`.
- **Out :** `NF_ACCEPT`/`NF_DROP` ; messages IPC via `ipc.write_msg` / `write_refused_msg` / `write_dnsonly_msg` dans `question_response` ; association IP→MAC dans `learn` ; événement DNS dans `events`.
- **Effets de bord :** logs `log_allow`/`log_block` ; métriques par règle (`metrics`).

## worker_responses (`src/worker_responses.moon`)

- **In :** NFQUEUE `QUEUE_RESPONSES` ; pipe `question_response` (lecture via `drain_pipe`) ; pipe ACK `nft` dédié ; `sessions.lua` (cache mtime).
- **Out :** `NF_ACCEPT` ou `nfq_set_verdict(NF_ACCEPT, patched_payload)` (TTL + EDE `Custos vigilat`) ou NXDOMAIN+EDE `Filtered` pour les transactions refusées.
- **Effets de bord :** demande l'ajout dans `ip4_allowed`, `ip6_allowed`, `mac4_allowed`, `mac6_allowed` **via le pipe `nft`** (timeout `nft.ip_timeout`), puis attend l'ACK de `worker_nft` avant de rendre le verdict ; rafraîchit la table de voisins (`ip neigh show`) au plus toutes les `NEIGH_REFRESH_COOLDOWN` secondes.

## worker_captive (`src/worker_captive.moon`)

- **In :** NFQUEUE `QUEUE_CAPTIVE` (TCP SYN/80 non authentifié) ; socket `AF_PACKET`/`SOCK_RAW` ouvert sur ifindex `br` (une seule fois au démarrage) ; `sessions.lua`.
- **Out :** `NF_DROP` sur le SYN ; 3 frames Ethernet injectées via `sendto()` sur le socket raw : SYN-ACK, HTTP 302, FIN-ACK.
  - MAC bridge lu depuis `/sys/class/net/br/address`.
  - AF_PACKET obligatoire : NFQUEUE ne peut pas inverser le sens ni injecter plusieurs paquets.
- **Config :** `auth_cfg.captive_ip4` / `captive_ip6` / `port` (défaut 33443) pour l'URL de redirection.

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
- **Traitement :**
  - extrait le SNI (TLS/QUIC) via `ipparse`,
  - applique `filter.decide` sur le SNI normalisé,
  - en mode `auth.sni_verdict.mode = strict-443` :
    - **allow** → ajoute la paire client→destination dans les sets nft (`ip*_allowed`, `mac*_allowed`) **via le pipe `nft`**,
    - **deny/no_sni** → `NF_DROP`.
- **Out :** `NF_ACCEPT` ou `NF_DROP` selon la policy `auth.sni_verdict` (`protocols`, `nft_failure_policy`).

## worker_sip (`src/worker_sip.moon`) — optionnel (`nfqueue.sip`)

- **In :** NFQUEUE `QUEUE_SIP` (signalisation SIP + STUN/ICE) ; pipe ACK `nft` dédié.
- **Traitement :** parse SIP/SDP (`src/sip/parser.moon`), extrait les IP de médias (RTP/RTCP) et l'IP du proxy.
- **Out :** `NF_ACCEPT` ; whiteliste les IP proxy + médias dans des sets nft par règle **via le pipe `nft`** (TTL `nft.sip_session_ttl`). Ports RTP exclus configurables (`rtp.excluded_ports`).

## worker_doh (`src/worker_doh.moon`) — optionnel (`doh.enabled`)

- **In :** serveur HTTPS **WolfSSL FFI** sur `doh.port` (défaut 8443) ; pipe ACK `nft` dédié. Pas de NFQUEUE.
- **Traitement :** reçoit les requêtes DoH (RFC 8484), résout en amont (`doh.upstream_ipv4`/`upstream_ipv6`, `doh.upstream_port`), applique `filter.decide`.
- **Out :** réponse DoH au client ; paires autorisées injectées dans les sets nft **via le pipe `nft`**.

## worker_nft (`src/worker_nft.moon`)

- **In :** pipe `nft` (commandes d'insertion sérialisées de tous les producteurs : responses, tls, sip, doh).
- **Out :** exécute les transactions nftables, puis écrit 1 octet d'ACK sur le `ack_<i>` du worker producteur concerné.
- **Rôle :** sérialise les écritures nft (évite les transactions concurrentes) et garantit la présence de l'élément dans le set avant que le producteur rende son verdict.

## worker_events (`src/worker_events.moon`)

- **In :** pipe `events` (événements DNS de `worker_questions`).
- **Out :** agrège et persiste les événements sous `events.dir` (rotation : `events.max_age_hours`, purge si espace libre < `events.min_free_pct`). Consommé par l'interface admin.

## worker_arp_sniffer (`src/worker_arp_sniffer.moon`)

- **In :** deux sockets `AF_PACKET/SOCK_RAW` sur `br` : EtherType `0x0806` (ARP) + `0x86DD` (IPv6, filtrage NDP ICMPv6 type 135/136 en Lua).
- **Out :** écrit les associations IP→MAC découvertes dans le pipe `learn` (22 octets).
- Aucun verdict NFQUEUE, aucune modification de paquet.

## mac_learner (`src/mac_learner.moon`)

- **In :** pipe `learn` (messages binaires 22 octets) ; socket Unix `SOCK_STREAM` (requêtes texte ligne `"ip_str\n"`).
- **Out :** répond `"aa:bb:cc:dd:ee:ff\n"` ou `"unknown\n"` sur le socket Unix.
- Sondage actif : si l'IP est inconnue, `mac_prober` envoie un ARP request ou Neighbor Solicitation sans bloquer. Les clients en attente sont notifiés dès la réponse ou à l'expiration de `PROBE_TIMEOUT_MS`.

## auth/worker (`src/auth/worker.moon`)

- **In :** sockets `AF_INET` + `AF_INET6` `SOCK_STREAM` sur `auth_cfg.port` (défaut 33443 ; HTTPS, **TLS via WolfSSL FFI** — `src/auth/ffi_wolfssl.moon`, certificats px5g dynamiques par SNI) ; `/etc/custos/secrets` ; `sessions.lua` ; résolution MAC via socket Unix → `mac_learner`.
- **Out :** écrit `sessions.lua` (rename atomique) ; gère les sets nft `authenticated_macs`, `authenticated_ips`, `authenticated_ips6`.
- **Interface admin :** `src/auth/server.moon` route les requêtes `/admin/*` vers `src/webui/router.moon` (édition de config, règles, listes, dictionnaires nommés ; reload SIGHUP). Accès réservé aux sessions admin (`auth.admin_users`).
- **Signaux :** `SIGHUP` → flag positionné dans le handler, rechargement des secrets au prochain cycle.
- **IPv6 dual-stack :** deux sockets distincts + `socket.select` ; ne jamais remplacer par `socket.bind "*"` (IPv4 uniquement).

---

## Format IPC question → response (`question_response` pipe, 43 octets)

Défini dans `src/ipc.moon`. Écriture atomique garantie (< `PIPE_BUF = 4096`).

| Offset | Taille | Champ |
|--------|--------|-------|
| 0 | 1 | Type : `'A'` (0x41) IPv4 accept · `'6'` (0x36) IPv6 accept · `'R'` (0x52) IPv4 refused · `'r'` (0x72) IPv6 refused · `'D'` (0x44) IPv4 dnsonly · `'d'` (0x64) IPv6 dnsonly |
| 1–2 | 2 | DNS `txid` (big-endian) |
| 3–18 | 16 | IP client — IPv4 paddée à gauche par `0x00`×12, ou IPv6 complète |
| 19–20 | 2 | Port source UDP/TCP client (big-endian) |
| 21–26 | 6 | MAC client (zéros si inconnu) |
| 27–42 | 16 | IP resolver — même convention de padding |

## Format IPC `learn` (22 octets)

Utilisé par `worker_questions`, `worker_arp_sniffer` et `worker_auth_queue` → `mac_learner`.

| Offset | Taille | Champ |
|--------|--------|-------|
| 0–15 | 16 | IP — IPv4 paddée à gauche par `0x00`×12, ou IPv6 complète |
| 16–21 | 6 | MAC (6 octets bruts) |

## Pipes `events`, `nft` et `ack_<i>`

- `events` : événements DNS sérialisés par `worker_questions`, consommés par `worker_events` (format interne au module, longueur variable).
- `nft` : commandes d'insertion nft sérialisées (set, famille, élément, timeout, index de worker pour l'ACK), de `worker_responses`/`worker_tls`/`worker_sip`/`worker_doh` vers `worker_nft`.
- `ack_<i>` : un pipe par worker producteur ; `worker_nft` y écrit 1 octet après chaque flush de batch pour débloquer le verdict du producteur.
