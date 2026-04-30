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
    ├─ DNS questions  → QUEUE_QUESTIONS → worker_questions  ─┬→ q0q1 pipe (43 B) → worker_responses
    │                                                         └→ learn pipe (22 B) → mac_learner
    │
    ├─ DNS responses  → QUEUE_RESPONSES → worker_responses
    │
    ├─ TCP/80 SYN     → QUEUE_CAPTIVE   → worker_captive   → AF_PACKET inject (3 frames)
    │
    ├─ Port 33443     → QUEUE_AUTH      → worker_auth_queue → learn pipe (22 B) → mac_learner
    │
    └─ Drop résiduel  → QUEUE_REJECT    → worker_reject
```

---

## Workers

| Module | Rôle |
|--------|------|
| `mac_learner` | Table IP→MAC en mémoire + TTL ; répond sur socket Unix |
| `worker_arp_sniffer` | Sniffer ARP/NDP passif ; alimente le pipe `learn` |
| `worker_auth_queue` | NFQUEUE sur `QUEUE_AUTH` ; extrait MAC/IP, écrit dans `learn` (mac_learner) |
| `worker_questions` | NFQUEUE sur `QUEUE_QUESTIONS` (1 worker par queue) |
| `worker_responses` | NFQUEUE sur `QUEUE_RESPONSES` (1 worker par queue) |
| `worker_captive` | NFQUEUE sur `QUEUE_CAPTIVE` ; injection AF_PACKET |
| `worker_reject` | NFQUEUE sur `QUEUE_REJECT` ; forge RST/ICMP |
| `auth/worker` | Portail HTTPS captif (luasec) ; résout la MAC via socket Unix → `mac_learner` |

Les numéros de queue sont **configurables via UCI** (`QUEUE_QUESTIONS`,
`QUEUE_RESPONSES`, `QUEUE_CAPTIVE`, `QUEUE_REJECT`, `QUEUE_AUTH`). Ils
supportent les plages, p. ex. `"0,2,5-7"`. Valeurs par défaut : 0, 1, 2, 3, 5.

---

## Pipes & sockets IPC

| Canal | Format | Producteur → Consommateur |
|-------|--------|---------------------------|
| `q0q1` pipe | 43 octets (voir [workers.md](workers.md)) | `worker_questions` → `worker_responses` |
| `learn` pipe | 22 octets : ip16 + mac6 | `worker_questions` + `worker_arp_sniffer` + `worker_auth_queue` → `mac_learner` |
| Socket Unix SOCK_STREAM | texte ligne : `"ip_str\n"` → `"mac\n"\|"unknown\n"` | requérants → `mac_learner` |
| `AF_PACKET SOCK_RAW` sur `br` | frames Ethernet brutes | `worker_captive` → bridge |

Les deux pipes unidirectionnels `q0q1` et `learn` sont créés dans `main.moon`
via `pipe2(O_NONBLOCK)` avant tout `fork()`. Atomicité garantie (< `PIPE_BUF`).

---

## Fichiers & config

| Chemin | Rôle | Lecteurs |
|--------|------|---------|
| `/etc/custos/filter.yml` | Allowlist DNS, config auth, TTL, etc. | `src/filter/` (hot-reload sur SIGHUP) |
| `/var/run/custos/config.lua` | Config UCI runtime | tous workers au démarrage |
| `/etc/custos/secrets` | Identifiants utilisateurs | `auth/worker` (rechargé sur SIGHUP) |
| `<sessions_file>` (défaut `tmp/sessions.lua`) | Sessions MAC (atomique rename) | écrit par AUTH, lu par workers Q0/Q1/Q2 |

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
| `QUEUE_QUESTIONS` | `worker_questions` | `th dport 53 queue to N` | `NF_ACCEPT` (fail-closed sur erreur) | Aucune ; transaction dans q0q1 + learn |
| `QUEUE_RESPONSES` | `worker_responses` | `th sport 53 queue to N` | `NF_ACCEPT` ± payload patché | DNS TTL + EDE `Custos vigilat`, ou NXDOMAIN+EDE `Filtered` |
| `QUEUE_CAPTIVE` | `worker_captive` | `tcp dport 80 … syn queue to N` | `NF_DROP` | 3 frames Ethernet via AF_PACKET (SYN-ACK, HTTP 302, FIN-ACK) |
| `QUEUE_AUTH` | `worker_auth_queue` | trafic port 33443 | `NF_ACCEPT` | Aucune ; mac+ip dans `learn` → `mac_learner` |
| `QUEUE_REJECT` | `worker_reject` | drop résiduel rate-limité | `NF_ACCEPT` + payload forgé | TCP RST/ACK ou ICMPv4 type 3/code 13 ou ICMPv6 type 1/code 1 |

---

## nft sets

| Set | Écrivain | Règle nft |
|-----|----------|-----------|
| `ip4_allowed`, `ip6_allowed` | Q_RESPONSES | `ip saddr . ip daddr @ip4_allowed accept` |
| `mac4_allowed`, `mac6_allowed` | Q_RESPONSES | `ether saddr . ip daddr @mac4_allowed accept` |
| `authenticated_macs`, `authenticated_ips`, `authenticated_ips6` | AUTH (`nft_sessions`) | bypass Q_CAPTIVE |
| `ip4_dest_whitelist`, `ip6_dest_whitelist` | statique (`.nft`) | `ip daddr @ip4_dest_whitelist accept` |

---

## Superviseur (`main.moon`)

- Fork chaque worker et surveille via `waitpid(-1, …, WNOHANG)` ; redémarre
  après un backoff de 1 seconde en cas de crash.
- Boucle `signalfd` pour `SIGHUP` / `SIGTERM`.
- `SIGHUP` → propagé à `worker_questions` (recharge `filter.yml`) et `auth/worker` (recharge secrets).
- `SIGTERM` → arrête tous les workers, supprime les règles nft ajoutées au démarrage.

---

## Sessions MAC-primary

Les sessions sont indexées par **adresse MAC** (pas IP), ce qui assure le
suivi cross-family IPv4/IPv6 et gère les privacy extensions.

- Utiliser `session_for_mac(mac, ip, path, sessions_table)` au lieu de lookups IP.
- Les workers extraient le MAC client via `get_l2(nfad)` → `nfq_get_packet_hw()`.
- Si `get_l2` échoue, `session_for_mac` effectue un fallback par recherche d'IP dans les sessions actives.
