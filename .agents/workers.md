# Workers — I/O détaillé et formats IPC

Voir [architecture.md](architecture.md) pour la vue d'ensemble et le queue map.

---

## worker_questions (`src/worker_questions.moon`)

- **In :** NFQUEUE `QUEUE_QUESTIONS`, fd d'écriture `question_response` et `learn` injectés par `main.moon`.
- **Lecture config :** section `filter` de `/etc/config.moon` via module `src/filter/`.
- **Out :** `NF_ACCEPT`/`NF_DROP` ; messages IPC via `ipc.write_msg` / `write_refused_msg` / `write_dnsonly_msg` dans `question_response` ; association IP→MAC dans `learn`.
- **Effets de bord :** flow tracking nDPI (`ndpi.get_flow`) ; logs `log_allow`/`log_block`.

## worker_responses (`src/worker_responses.moon`)

- **In :** NFQUEUE `QUEUE_RESPONSES` ; pipe `question_response` (lecture via `drain_pipe`) ; `sessions.lua` (cache mtime).
- **Out :** `NF_ACCEPT` ou `nfq_set_verdict(NF_ACCEPT, patched_payload)` (TTL + EDE `Custos vigilat`) ou NXDOMAIN+EDE `Filtered` pour les transactions refusées.
- **Effets de bord :** alimente `ip4_allowed`, `ip6_allowed`, `mac4_allowed`, `mac6_allowed` (timeout 2 min) ; rafraîchit la table de voisins (`ip neigh show`) au plus toutes les `NEIGH_REFRESH_COOLDOWN` secondes.

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

## worker_tls (`src/worker_tls.moon`)

- **In :** NFQUEUE `QUEUE_SNI_LOG` (TCP/443 ACK path + UDP/443 QUIC Initial).
- **Traitement :**
  - extrait le SNI (TLS/QUIC) via `ipparse`,
  - applique `filter.decide` sur le SNI normalisé,
  - en mode `auth.sni_verdict.mode = strict-443` :
    - **allow** → ajoute la paire client→destination dans les sets nft (`ip*_allowed`, `mac*_allowed`) avec `NFT_IP_TIMEOUT`,
    - **deny/no_sni** → `NF_DROP`.
- **Out :** `NF_ACCEPT` ou `NF_DROP` selon la policy `auth.sni_verdict` (`protocols`, `nft_failure_policy`).

## worker_arp_sniffer (`src/worker_arp_sniffer.moon`)

- **In :** deux sockets `AF_PACKET/SOCK_RAW` sur `br` : EtherType `0x0806` (ARP) + `0x86DD` (IPv6, filtrage NDP ICMPv6 type 135/136 en Lua).
- **Out :** écrit les associations IP→MAC découvertes dans le pipe `learn` (22 octets).
- Aucun verdict NFQUEUE, aucune modification de paquet.

## mac_learner (`src/mac_learner.moon`)

- **In :** pipe `learn` (messages binaires 22 octets) ; socket Unix `SOCK_STREAM` (requêtes texte ligne `"ip_str\n"`).
- **Out :** répond `"aa:bb:cc:dd:ee:ff\n"` ou `"unknown\n"` sur le socket Unix.
- Sondage actif : si l'IP est inconnue, `mac_prober` envoie un ARP request ou Neighbor Solicitation sans bloquer. Les clients en attente sont notifiés dès la réponse ou à l'expiration de `PROBE_TIMEOUT_MS`.

## auth/worker (`src/auth/worker.moon`)

- **In :** sockets `AF_INET` + `AF_INET6` `SOCK_STREAM` sur `auth_cfg.port` (HTTPS, TLS via luasec) ; `/etc/custos/secrets` ; `sessions.lua` ; résolution MAC via socket Unix → `mac_learner`.
- **Out :** écrit `sessions.lua` (rename atomique) ; gère les sets nft `authenticated_macs`, `authenticated_ips`, `authenticated_ips6`.
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
