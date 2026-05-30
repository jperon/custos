# Architecture — CustosVirginum

CustosVirginum est un filtre DNS inline sur pont Linux (bridge), écrit en
MoonScript et exécuté par LuaJIT. Il fonctionne **exclusivement en mode bridge**
(`nftables table bridge`) ; il n'existe pas de mode routeur.

---

## Vue d'ensemble

```
LAN clients
    │  (bridge br)
    ▼
nftables (table bridge)
    │
    ├─ DNS questions  → QUEUE_QUESTIONS → worker_questions  ─┬→ question_response pipe (43 B) → worker_responses
    │                                                         ├→ learn pipe (22 B)  → mac_learner
    │                                                         └→ events pipe        → worker_events
    │
    ├─ DNS responses  → QUEUE_RESPONSES → worker_responses ──→ nft pipe → worker_nft (insertions nft sérialisées)
    │
    ├─ TCP/80 SYN     → QUEUE_CAPTIVE   → worker_captive   → AF_PACKET inject (3 frames)
    │
    ├─ Port 33443     → QUEUE_AUTH      → worker_auth_queue → learn pipe (22 B) → mac_learner
    │
    ├─ TCP/443 + UDP/443 → QUEUE_SNI → worker_tls       ──→ nft pipe → worker_nft
    │     (placement=integral : règle AVANT cv_action_vmap → tout le 443 inspecté ;
    │      placement=residual : règle APRÈS → seul le trafic résiduel ;
    │      flag `bypass` → passe si worker SNI absent)
    │
    ├─ SIP/STUN (opt.)   → QUEUE_SIP     → worker_sip       ──→ nft pipe → worker_nft
    │
    └─ Drop résiduel  → QUEUE_REJECT    → worker_reject

Worker AUTH (HTTPS/WolfSSL, port 33443) : portail captif + interface admin /admin/* (src/webui)
Worker DoH (opt., HTTPS/WolfSSL, port 8443) : résout via upstream DNS, applique filter.decide ──→ nft pipe
```

---

## Workers

| Module | Rôle |
|--------|------|
| `mac_learner` | Table IP→MAC en mémoire + TTL ; répond sur socket Unix |
| `worker_arp_sniffer` | Sniffer ARP/NDP passif ; alimente le pipe `learn` |
| `worker_auth_queue` | NFQUEUE sur `QUEUE_AUTH` ; extrait MAC/IP, écrit dans `learn` (mac_learner) |
| `worker_tls` | NFQUEUE sur `QUEUE_SNI` (optionnel) ; verdict SNI TLS/QUIC, insertions via pipe `nft` |
| `worker_sip` | NFQUEUE sur `QUEUE_SIP` (optionnel) ; whiteliste IP proxy + médias SDP dans des sets nft par règle |
| `worker_questions` | NFQUEUE sur `QUEUE_QUESTIONS` (1 worker par queue) |
| `worker_responses` | NFQUEUE sur `QUEUE_RESPONSES` (1 worker par queue) ; insertions via pipe `nft` |
| `worker_captive` | NFQUEUE sur `QUEUE_CAPTIVE` ; injection AF_PACKET |
| `worker_reject` | NFQUEUE sur `QUEUE_REJECT` ; forge RST/ICMP |
| `worker_nft` | Sérialise toutes les insertions nft (lit pipe `nft`, ACK par worker) — pas de NFQUEUE |
| `worker_events` | Agrège les événements DNS (pipe `events`) et les persiste sous `events.dir` |
| `worker_doh` | Serveur DoH HTTPS/WolfSSL (optionnel, `doh.enabled`) ; résout en amont + `filter.decide` |
| `auth/worker` | Portail HTTPS captif **WolfSSL FFI** (port 33443) + interface admin `/admin/*` (`src/webui`) ; résout la MAC via socket Unix → `mac_learner` |

Les numéros de queue sont **configurables** (section `nfqueue` de la config, ou
UCI : `QUEUE_QUESTIONS`, `QUEUE_RESPONSES`, `QUEUE_CAPTIVE`, `QUEUE_REJECT`,
`QUEUE_AUTH`, `QUEUE_SNI`, `QUEUE_SIP`). Ils supportent les plages, p. ex.
`"0,2,5-7"`. Valeurs par défaut : questions `0-1`, responses `4`, captive `20`,
reject `10-11`, auth `5`, sni `6`, sip `12`. Les workers `tls`, `sip` et
`doh` ne sont forkés que si leur clé respective est définie / activée.

### Mémoire : partage des listes de domaines (RAM faible)

Les listes `.bin` (`src/filter/conditions/to_domainlist.moon`) sont chargées par
`filter.load!` dans le superviseur **avant** le fork des workers porteurs de
filtre (`dns-q*`, `resp-q*`, `nft`, `tls`, `doh`). Le `.bin` est mappé via
`mmap(MAP_SHARED, PROT_READ)` : le tableau FFI `uint64_t*` pointe directement sur
les pages du fichier (en tmpfs, donc déjà en RAM). Conséquences :

- **Aucune recopie** : plus de string Lua transitoire (`read "*a"`) ni de
  `ffi.copy` — la donnée n'existe qu'une fois en mémoire.
- **Partage réel entre workers** : le mapping lecture seule hérité par `fork()`
  référence les **mêmes pages physiques** dans tous les workers (jamais
  dupliquées, car jamais écrites). Le COW est donc total et permanent.

Un `collectgarbage "collect"` est exécuté juste après `filter.load!` (avant le
fork) pour purger les strings de compilation des règles : le tas propre est
ensuite partagé en COW. Les réglages GC (`runtime.gc_pause`/`gc_stepmul`,
appliqués dans `main.moon` et hérités par les workers) rendent la collecte plus
agressive sur machines contraintes. Le format texte `.domains` (fallback) reste
coûteux (hachage + tri en RAM au démarrage) : préférer `.bin`.

---

## Pipes & sockets IPC

| Canal | Format | Producteur → Consommateur |
|-------|--------|---------------------------|
| `question_response` pipe | 43 octets (voir [workers.md](workers.md)) | `worker_questions` → `worker_responses` |
| `learn` pipe | 22 octets : ip16 + mac6 | `worker_questions` + `worker_arp_sniffer` + `worker_auth_queue` → `mac_learner` |
| `events` pipe | événements DNS sérialisés | `worker_questions` → `worker_events` |
| `nft` pipe | commandes d'insertion nft sérialisées | `worker_responses` + `worker_tls` + `worker_sip` + `worker_doh` → `worker_nft` |
| `ack_<i>` pipes | 1 octet d'ACK | `worker_nft` → chaque worker producteur (un pipe dédié par worker) |
| Socket Unix SOCK_STREAM | texte ligne : `"ip_str\n"` → `"mac\n"\|"unknown\n"` | requérants → `mac_learner` |
| `AF_PACKET SOCK_RAW` sur `br` | frames Ethernet brutes | `worker_captive` → bridge |

Tous les pipes unidirectionnels (`question_response`, `learn`, `events`, `nft`,
`ack_<i>`) sont créés dans `main.moon` via `pipe2(O_NONBLOCK)` avant tout
`fork()`. Atomicité garantie (< `PIPE_BUF`). Le pipe `nft` centralise les
insertions dans `worker_nft` (sérialisation des transactions nftables) ; chaque
worker producteur attend un ACK 1 octet sur son `ack_<i>` dédié avant de rendre
son verdict, afin que l'élément soit présent dans le set avant le retour du paquet.

---

## Fichiers & config

| Chemin | Rôle | Lecteurs |
|--------|------|---------|
| `/etc/config.moon` | Config runtime hiérarchique (filter/auth/dns/nft, etc.) | `src/config.moon` puis consommateurs |
| `/etc/config/custos` | UCI OpenWrt plateforme (enabled, cron update-lists) | init script OpenWrt |
| `/etc/custos/secrets` | Identifiants utilisateurs | `auth/worker` (rechargé sur SIGHUP) |
| `<sessions_file>` (défaut `tmp/sessions.lua`) | Sessions MAC (atomique rename) | écrit par AUTH, lu par workers question/response/captive |

---

## NFQUEUE — payload et métadonnées

- `nfq_get_payload()` retourne un buffer débutant à l'**en-tête IP** — pas
  d'en-tête Ethernet, même sur les hooks bridge.
- Parse à l'offset 0 (1 en indexation Lua).
- Le payload de remplacement passé à `nfq_set_verdict()` commence aussi à
  l'en-tête IP. NFQUEUE ne peut pas inverser le sens d'un paquet.

| Accesseur | Retour | Notes |
|-----------|--------|-------|
| `nfq_get_msg_packet_hdr` | `nfqnl_msg_packet_hdr*` | `packet_id` big-endian |
| `nfq_get_payload(nfad, &ptr)` | longueur + pointeur | IP header onwards |
| `nfq_get_packet_hw(nfad)` | `nfqnl_msg_packet_hw*` | MAC source (6 octets) ; MAC dest non exposé |
| `nfq_get_indev(nfad)` | `u32` | ifindex entrant |
| `nfq_get_outdev(nfad)` | `u32` | ifindex sortant (0 en pre-routing) |
| `nfq_get_nfmark(nfad)` | `u32` | VLAN ID (`meta mark set @ll,112,16 & 0xfff`) |

---

## Queue map

| Queue | Worker | Règle nft (table `bridge`) | Verdict | Injection |
|-------|--------|----------------------------|---------|-----------|
| `QUEUE_QUESTIONS` | `worker_questions` | `th dport 53 queue to N` | `NF_ACCEPT` (fail-closed sur erreur) | Aucune ; transaction dans question_response + learn |
| `QUEUE_RESPONSES` | `worker_responses` | `th sport 53 queue to N` | `NF_ACCEPT` ± payload patché | DNS TTL + EDE `Custos vigilat`, ou NXDOMAIN+EDE `Filtered` |
| `QUEUE_CAPTIVE` | `worker_captive` | `tcp dport 80 … syn queue to N` | `NF_DROP` | 3 frames Ethernet via AF_PACKET (SYN-ACK, HTTP 302, FIN-ACK) |
| `QUEUE_AUTH` | `worker_auth_queue` | trafic port 33443 | `NF_ACCEPT` | Aucune ; mac+ip dans `learn` → `mac_learner` |
| `QUEUE_SNI` | `worker_tls` | `tcp/udp dport 443 queue to N bypass` (opt. ; **avant** `cv_action_vmap` si `placement=integral`, **après** si `residual`) | `NF_ACCEPT`/`NF_DROP` selon `cfg.sni` | Paire client→dest dans `ip*_allowed`/`mac*_allowed` via pipe `nft` |
| `QUEUE_SIP` | `worker_sip` | trafic SIP/STUN (opt.) | `NF_ACCEPT` | IP proxy + médias SDP dans des sets nft par règle (TTL `nft.sip_session_ttl`) via pipe `nft` |
| `QUEUE_REJECT` | `worker_reject` | drop résiduel rate-limité | `NF_ACCEPT` + payload forgé | TCP RST/ACK ou ICMPv4 type 3/code 13 ou ICMPv6 type 1/code 1 |

Le worker DoH (`worker_doh`) n'a pas de NFQUEUE : c'est un serveur HTTPS (port
`doh.port`, défaut 8443) qui résout les requêtes DoH en amont, applique
`filter.decide`, et injecte les paires autorisées via le pipe `nft`.

---

## nft sets

Toutes les insertions dynamiques transitent par `worker_nft` (pipe `nft`) ; la
colonne « Source » indique le worker à l'origine de la commande.

| Set | Source | Règle nft |
|-----|--------|-----------|
| `ip4_allowed`, `ip6_allowed` | responses / tls / doh | `ip saddr . ip daddr @ip4_allowed accept` |
| `mac4_allowed`, `mac6_allowed` | responses / tls | `ether saddr . ip daddr @mac4_allowed accept` |
| sets par règle (SIP médias) | sip | proxy + IP médias SDP, TTL `nft.sip_session_ttl` |
| `authenticated_macs`, `authenticated_ips`, `authenticated_ips6` | AUTH (`nft_sessions`) | bypass Q_CAPTIVE |
| `ip4_dest_whitelist`, `ip6_dest_whitelist` | statique (`.nft`) | `ip daddr @ip4_dest_whitelist accept` |

---

## Superviseur (`main.moon`)

- Fork chaque worker et surveille via `waitpid(-1, …, WNOHANG)` ; redémarre
  après un backoff de 1 seconde en cas de crash.
- Boucle `signalfd` pour `SIGHUP` / `SIGTERM`.
- `SIGHUP` → `filter.load!` (relecture de `config` déjà chargé) + propagation AUTH (recharge secrets).
- `SIGTERM` → arrête tous les workers, supprime les règles nft ajoutées au démarrage.

---

## Sessions MAC-primary

Les sessions sont indexées par **adresse MAC** (pas IP), ce qui assure le
suivi cross-family IPv4/IPv6 et gère les privacy extensions.

- Utiliser `session_for_mac(mac, ip, path, sessions_table)` au lieu de lookups IP.
- Les workers extraient le MAC client via `get_l2(nfad)` → `nfq_get_packet_hw()`.
- Si `get_l2` échoue, `session_for_mac` effectue un fallback par recherche d'IP dans les sessions actives.
