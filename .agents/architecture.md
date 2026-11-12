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
    ├─ Port DoH (input bridge, opt.) → QUEUE_DOH_VLAN → worker_doh_vlan → vlan_learn pipe (18 B) → mac_learner
    │     (NF_ACCEPT toujours ; renseigne req.vlan en DoH via get_vlan)
    │
    ├─ TCP/443 + UDP/443 → QUEUE_SNI → worker_tls       ──→ nft pipe → worker_nft
    │     (placement=integral : règle AVANT cv_action_vmap → tout le 443 inspecté ;
    │      placement=residual : règle APRÈS → seul le trafic résiduel ;
    │      refus strict : NF_ACCEPT + REJECT_MARK → QUEUE_REJECT → worker_reject ;
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
| `worker_tls` | NFQUEUE sur `QUEUE_SNI` (optionnel) ; verdict SNI TLS/QUIC **aligné sur `filter.decide_meta`** (redirect/SafeSearch → block, second avis `validate` synchrone), insertions via pipe `nft` |
| `worker_sip` | NFQUEUE sur `QUEUE_SIP` (optionnel) ; whiteliste IP proxy + médias SDP dans des sets nft par règle |
| `worker_questions` | NFQUEUE sur `QUEUE_QUESTIONS` (un worker par file de la plage) ; écrit chaque transaction dans **tous** les pipes `question_response<i>` |
| `worker_responses` | NFQUEUE sur `QUEUE_RESPONSES` (un worker par file de la plage) ; lit **son** pipe `question_response<i>`, insertions via pipe `nft`, verdicts du second avis diffusés entre workers |
| `worker_captive` | NFQUEUE sur `QUEUE_CAPTIVE` ; injection AF_PACKET |
| `worker_reject` | NFQUEUE sur `QUEUE_REJECT` ; forge RST/ICMP |
| `worker_nft` | Sérialise toutes les insertions nft (lit pipe `nft`, ACK par worker) — pas de NFQUEUE |
| `worker_events` | Agrège les événements DNS (pipe `events`) et les persiste sous `events.dir` |
| `worker_doh` | Serveur DoH HTTPS/WolfSSL (optionnel, `doh.enabled`) ; résout en amont + `filter.decide` |
| `worker_doh_vlan` | NFQUEUE `QUEUE_DOH_VLAN` (optionnel, `doh.enabled` + `nfqueue.doh_vlan`) ; détecte le VLAN des clients DoH, écrit dans `vlan_learn` (mac_learner), `NF_ACCEPT` toujours |
| `auth/worker` | Portail HTTPS captif **WolfSSL FFI** (port 33443) + interface admin `/admin/*` (`src/webui`) ; résout la MAC via socket Unix → `mac_learner` |

Les numéros de queue sont **configurables** (section `nfqueue` de la config, ou
UCI : `QUEUE_QUESTIONS`, `QUEUE_RESPONSES`, `QUEUE_CAPTIVE`, `QUEUE_REJECT`,
`QUEUE_AUTH`, `QUEUE_SNI`, `QUEUE_SIP`). Ils prennent un nombre ou une **plage
contiguë** (`"14-15"` → un worker par file) ; `queue num` n'accepte pas de liste
avec virgules (pour `responses`, une liste est ramenée à sa première file avec
un WARN ; pour `questions`, le générateur de règles émet un `queue num` par
segment contigu — cf. § « Workers DNS multiples »). Deux rôles ne peuvent pas
partager un numéro de file : au
chargement, un chevauchement (plages développées) émet une ERROR
`nfqueue_overlap` et **refuse le démarrage** (`src/config.moon`). Valeurs par
défaut : questions `0-1`, responses `3-4`, captive `20`, reject `10-11`, auth
`5`, sni `6`, sip `12`. Les workers `tls`, `sip` et `doh` ne sont forkés que si
leur clé respective est définie / activée.

### Mémoire : partage des listes de domaines (RAM faible)

Les listes `.bin` (`src/filter/conditions/to_domainlist.moon`) sont chargées par
`filter.load!` dans le superviseur **avant** le fork des workers porteurs de
filtre (`dns-q*`, `resp-q*`, `nft`, `tls`, `doh`). Le `.bin` est mappé via
`mmap(MAP_SHARED, PROT_READ)` : le pointeur FFI `const uint8_t*` pointe
directement sur les pages du fichier (en tmpfs, donc déjà en RAM). Le format est
N × 6 octets (xxh64 tronqué 48 bits, little-endian, trié — cf.
`src/filter/lib/bin48.moon`), soit −25 % de RAM/disque face à l'uint64, pour un
faux positif ≈ N/2⁴⁸ (négligeable). La lecture d'un enregistrement s'adapte à
l'architecture (`jit.arch`) : accès non aligné rapide sur x86/x64/ARM, repli
octet-par-octet sur MIPS. Conséquences :

- **Aucune recopie** : plus de string Lua transitoire (`read "*a"`) ni de
  `ffi.copy` — la donnée n'existe qu'une fois en mémoire.
- **Partage réel entre workers** : le mapping lecture seule hérité par `fork()`
  référence les **mêmes pages physiques** dans tous les workers (jamais
  dupliquées, car jamais écrites). Le COW est donc total et permanent.

Un `collectgarbage "collect"` est exécuté juste après `filter.load!` (avant le
fork) pour purger les strings de compilation des règles : le tas propre est
ensuite partagé en COW. Les réglages GC (section `gc`, `src/lib/gc_tune.moon`,
appliqués dans `main.moon` avant le fork puis rappelés au démarrage de chaque
worker) règlent pause/stepmul, un pas de GC sur temps mort et un plafond de tas
par worker. Le format texte `.domains` (fallback) reste coûteux (hachage + tri
en RAM au démarrage) : préférer `.bin`.

---

## Pipes & sockets IPC

| Canal | Format | Producteur → Consommateur |
|-------|--------|---------------------------|
| `question_response<i>` pipe | ligne texte `v1|…` (voir [workers.md](workers.md)) | `worker_questions` → **tous** les workers `worker_responses` (un pipe par worker) |
| `learn` pipe | 22 octets : ip16 + mac6 | `worker_questions` + `worker_arp_sniffer` + `worker_auth_queue` → `mac_learner` |
| `events` pipe | événements DNS sérialisés | `worker_questions` → `worker_events` |
| `nft` pipe | commandes d'insertion nft sérialisées | `worker_responses` + `worker_tls` + `worker_sip` + `worker_doh` → `worker_nft` |
| `ack_<i>` pipes | 1 ACK de 8 octets (uint64 : plus grand `seq` appliqué pour ce worker) | `worker_nft` → chaque worker producteur (un pipe dédié par worker) |
| `so_verdict_<i>` pipes | ligne texte `v1|…` (verdict validateur encodé) | chaque `worker_responses` → tous les **autres** (bus du second avis) |
| Socket Unix SOCK_STREAM | texte ligne : `"ip_str\n"` → `"mac\n"\|"unknown\n"` | requérants → `mac_learner` |
| `AF_PACKET SOCK_RAW` sur `br` | frames Ethernet brutes | `worker_captive` → bridge |

Tous les pipes unidirectionnels (`question_response<i>`, `learn`, `events`, `nft`,
`ack_<i>`, `so_verdict_<i>`) sont créés dans `main.moon` via `pipe2(O_NONBLOCK)`
avant tout `fork()`. Atomicité garantie (< `PIPE_BUF`). Le pipe `nft` centralise
les insertions dans `worker_nft` (sérialisation des transactions nftables) ;
chaque worker producteur attend un ACK de son `ack_<i>` dédié avant de rendre
son verdict, afin que l'élément soit présent dans le set avant le retour du paquet.
L'ACK porte le plus grand `seq` appliqué pour ce worker : un inject dont les
lignes sont réparties sur plusieurs flushes (`MAX_BATCH`) n'est acquitté qu'une
fois la dernière ligne traitée.

**Lecture de la file pendant l'attente d'ACK** (`src/nfq_loop.moon`
`read_packets`, `src/worker_responses.moon` `_flush_batch`) : le worker réponses
ne lit plus seulement le tube d'ACK pendant `wait_ack`. `nfq_loop.run_queue`
fournit au hook `on_batch_end` une fonction de lecture non bloquante, bornée à
`MAX_BATCH_PKTS` (64) et non réentrante (garde `reading` : un appel depuis un
callback de paquet rend 0). Le worker s'en sert via le `on_wait` de `wait_ack`
(après le drain du tube question), et les paquets ainsi lus et traités sont
placés dans le **lot suivant** : leurs verdicts ne sont posés qu'après **son
propre** ACK (plus grand `seq` enfilé pendant l'attente), jamais après l'ACK du
lot courant qui ne couvre pas leurs insertions. Aucune lecture pendant la
seconde attente : les paquets restants sont lus par la boucle principale, et le
budget total de 150 ms par `wait_ack` (comportement en timeout inclus) est
inchangé. Motivation : 9-23 % du temps du worker passait dans une attente
pendant laquelle le socket netlink n'était pas lu, d'où une file noyau qui
grossit (`response_entry_ms`, cf. [perf.md](../docs/agents/perf.md) §16).

### Workers DNS multiples (questions et réponses)

`nfqueue.questions` et `nfqueue.responses` acceptent une plage contiguë
(`"0-1"`, `"14-15"`) : un worker par file. La répartition est faite par le
noyau et, **depuis la branche `d-qhash` (2026-11-12)**, elle porte sur l'IP
**et** le port du client :

- **une seule file** : `queue num X`, inchangé ;
- **plusieurs files** : `nft_rules.dns_queue_rules`
  (`src/nft_rules.moon:163`) génère, via les ancres `DNS_QUESTIONS_RULES` /
  `DNS_RESPONSES_RULES` du template (`nft-rules/dns-filter-bridge.nft:215-216`),
  **une règle par famille** (IPv4/IPv6) :
  `queue to jhash <IP client> . <port client> mod N offset <première file>`
  — questions : `ip saddr . th sport`, réponses : `ip daddr . th dport`
  (resp. `ip6 …`). Le sélecteur de famille est `ip version 4` / `ip6 version 6`
  (`ether type` ne matche pas les trames VLAN encapsulées ; `meta nfproto` est
  refusé en famille bridge). Sans `bypass` : un paquet sans worker reste droppé,
  comme avant. Détail et validations : `docs/agents/perf.md` §11.5.

Sans cette clé, l'ancien hachage (`queue num N-M` → `nfqueue_hash`, adresses
triées + protocole, sans les ports) concentrait toutes les réponses du
résolveur validateur sur une seule file (`docs/agents/perf.md` §15.2, §16.3).
`fanout` n'est pas utilisé : ce flag répartit par CPU, ce qui casserait
l'affinité de flux.

L'état par processus des workers DNS est rendu compatible par deux fan-outs
(`main.moon`) :

1. **Transactions question→réponse** : un pipe par worker réponses
   (`question_response<i>`, `create_pipes` l. 139-143). Chaque worker questions
   écrit chaque message dans tous les pipes (`ipc.write_with_retry_all`), donc
   chaque worker réponses a la table `pending` complète : une réponse livrée à
   n'importe quelle file trouve sa transaction. À un seul worker, un seul pipe
   est créé : comportement identique à avant.
2. **Verdicts du second avis** : bus `so_verdict_<i>` (un pipe par worker,
   l. 335-344), chaque worker n'écrivant qu'aux autres. Il était nécessaire
   parce que la réponse d'origine (client ↔ résolveur) et celle du validateur
   (client ↔ validateur) ont des couples d'adresses différents, donc des files
   différentes sous l'ancien hachage. Depuis `d-qhash`, les deux réponses ont
   la même clé `(daddr = client, dport = port client)` — la question dupliquée
   conserve le port source du client (`src/dup_query.moon:47`) — et arrivent
   donc chez le même worker ; **le bus reste en place comme repli** (fragments,
   reconfiguration en cours de vie, retour à `queue num`). Le worker qui reçoit
   le verdict d'un autre le mémorise ou débloque immédiatement la réponse
   parquée (`drain_verdict_bus`) ; le pipe du bus est ajouté au `poll` de
   `nfq_loop` (`extra_rfds`) pour un réveil immédiat sans attendre le budget de
   80 ms.

Sans `so_verdict` (un seul worker réponses), les deux mécanismes sont inertes :
aucun fd, aucune écriture supplémentaire. Le superviseur fork, nomme
(`custos:resp-q3`, `custos:dns-q1`, …) et redémarre chaque worker indépendamment
(`worker_died` → refork après 1 s), et `SIGHUP` reforke tous les `dns-q*` /
`resp-q*` pour rafraîchir les listes en COW.

### Boucle `worker_nft` (faible latence)

`worker_nft` bloque sur `poll(rfd)` (plus de busy-poll `sleep`), draine en une
passe toutes les lignes disponibles (lectures non bloquantes jusqu'à `EAGAIN`,
plafonné à `MAX_BATCH` pour borner la taille de transaction nft), puis **flush
immédiatement** dès que le pipe est drainé. Il n'y a plus de fenêtre temporelle
`FLUSH_MS` : la latence d'insertion (et donc l'attente `wait_ack` côté producteur)
est minimale à faible charge, tandis que la coalescence reste naturelle sous
charge — pendant la durée d'un flush, le pipe accumule les insertions suivantes
qui forment le batch d'après. Le décompte de `pending` est tenu de façon
incrémentale (`try_add_pending`) plutôt que recalculé par `pairs` à chaque tour.

---

## Fichiers & config

| Chemin | Rôle | Lecteurs |
|--------|------|---------|
| `/etc/custos/config.moon` | Config runtime hiérarchique (filter/auth/dns/nft, etc.) — chemin par défaut `DEFAULT_CONFIG_PATH` de `src/config.moon`, surchargé par `CUSTOS_CONFIG_PATH` (init.d du paquet) | `src/config.moon` puis consommateurs |
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
| `QUEUE_QUESTIONS` | `worker_questions` | une file : `th dport 53 … queue to N` ; plage : `th dport 53 ip[6] version … counter queue to jhash ip[6] saddr . th sport mod N offset <1re file>` (une règle par famille, cf. § « Workers DNS multiples ») | `NF_ACCEPT` (fail-closed sur erreur) | Aucune ; transaction dans question_response + learn |
| `QUEUE_RESPONSES` | `worker_responses` | une file : `th sport 53 … queue to N` ; plage : `th sport 53 ip[6] version … counter queue to jhash ip[6] daddr . th dport mod N offset <1re file>` (une règle par famille) | `NF_ACCEPT` ± payload patché | DNS TTL + EDE `Custos vigilat`, ou NXDOMAIN+EDE `Filtered` |
| `QUEUE_CAPTIVE` | `worker_captive` | `tcp dport 80 … syn queue to N` | `NF_DROP` | 3 frames Ethernet via AF_PACKET (SYN-ACK, HTTP 302, FIN-ACK) |
| `QUEUE_AUTH` | `worker_auth_queue` | trafic port 33443 | `NF_ACCEPT` | Aucune ; mac+ip dans `learn` → `mac_learner` |
| `QUEUE_SNI` | `worker_tls` | `tcp/udp dport 443 queue to N bypass` (opt. ; **avant** `cv_action_vmap` si `placement=integral`, **après** si `residual`) | `NF_ACCEPT`; refus strict = `NF_ACCEPT` + `REJECT_MARK` puis `QUEUE_REJECT` | Paire client→dest dans `ip*_allowed`/`mac*_allowed` via pipe `nft` ; rejet réseau forgé par `worker_reject` |
| `QUEUE_SIP` | `worker_sip` | trafic SIP/STUN (opt.) | `NF_ACCEPT` | IP proxy + médias SDP dans des sets nft par règle (TTL `nft.sip_session_ttl`) via pipe `nft` |
| `QUEUE_REJECT` | `worker_reject` | drop résiduel rate-limité + paquets marqués `REJECT_MARK` par `worker_tls` | `NF_ACCEPT` + payload forgé | TCP RST/ACK ou ICMPv4 type 3/code 13 ou ICMPv6 type 1/code 1 |

Le worker DoH (`worker_doh`) n'a pas de NFQUEUE : c'est un serveur HTTPS (port
`doh.port`, défaut 8443) qui résout les requêtes DoH en amont, applique
`filter.decide`, et injecte les paires autorisées via le pipe `nft`.

---

## Namespace des marks nft/NFQUEUE

`src/nft_marks.moon` centralise les marks réservées par Custos :

| Mark | Usage |
|------|-------|
| `0x00000fff` | Zone basse utilisée pour transporter le VLAN ID dans `meta mark`. |
| `0x00004000+` | Marks de règles compilées (`filter.nft_compiler`) rejouées via `cv_action_vmap`/`ct mark`. |
| `0x00010000` | Auth mark interne au compilateur nft. |
| `0x02000000` (`REJECT_MARK`) | Demande explicite de rejet réseau forgé : `worker_tls` pose cette nfmark via `nfq_set_verdict2`, nft route ensuite vers `QUEUE_REJECT`. |

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

## Fast-path conntrack (cache de verdict en `ct mark`)

Sous fort débit (plusieurs downloads parallèles), chaque paquet d'un flux établi
retraversait toute la chaîne `forward` en contexte softirq (`ksoftirqd`) :
lookups de sets (NTP/mDNS/UniFi/whitelist/SIP), puis `jump cv_rules_dispatch`
(N sous-chaînes par règle × lookups de sets dynamiques) et les heuristiques.
Coût ≈ linéaire dans la taille de la chaîne × débit → latence ping qui grimpe.

`dns-filter-bridge.nft` mémorise donc le verdict d'un flux dans `ct mark` après
le premier paquet, puis le rejoue. La règle de rejeu (« fast-path ») n'est plus
inline dans le template : `nft_rules.moon` l'injecte à **une** de deux ancres
selon `sni.placement` (`{FAST_PATH_EARLY}` / `{FAST_PATH_LATE}`).

```
# ── ancre HAUTE {FAST_PATH_EARLY} (rendue si placement != "integral") ──
tcp dport 33443 … queue   # auth captif (toujours en premier)
ct state established,related ct mark != 0x0 meta mark set ct mark counter meta mark vmap @cv_action_vmap  # fast-path
… bloc infra (DHCP/ARP/ICMP/NTP/UniFi), DNS queue, ULA, whitelists, SIP …
{SNI_RULES_PRE}
# ── ancre BASE {FAST_PATH_LATE} (rendue si placement == "integral") ──
ct state established,related ct mark != 0x0 … meta mark vmap @cv_action_vmap  # fast-path
jump cv_rules_dispatch
meta mark != 0x0 ct mark set meta mark   # mémorise le verdict
meta mark vmap @cv_action_vmap
```

**Le filtrage reste prioritaire sur l'optimisation.** Garanties :

- On ne court-circuite QUE les flux **déjà positivement tranchés** par le ruleset
  (`ct mark != 0`), rejoués via le **même** `@cv_action_vmap` → aucun verdict que
  le ruleset n'aurait pas rendu lui-même.
- **Invariant de l'ancre HAUTE** : seuls les flux passés par `cv_rules_dispatch`
  portent `ct mark != 0`. Tout le bloc amont (broadcast/multicast, DHCP, ARP,
  ICMP/NDP, NTP/UniFi/syslog, DNS queue, ULA, whitelists, SIP) est `accept` ou
  `queue` terminal → `ct mark == 0` → jamais court-circuité. Remonter la
  fast-path au-dessus de ce bloc supprime ses lookups de sets pour les flux déjà
  tranchés (gain de softirq) sans rien changer pour les autres.
- **Ancre BASE en SNI `integral`** : le handshake TCP d'un flux 443 peut être
  marqué « allow » **avant** le ClientHello ; une fast-path remontée rejouerait
  ce verdict et sauterait l'inspection SNI du ClientHello. On la garde donc
  **après les règles SNI** pour que tout le 443 reste inspecté.
- DNS/auth captif (33443) restent **toujours queués** (ces flux ne sont pas
  marqués → `ct mark == 0`). La marque VLAN n'a pas besoin d'être reposée : la
  condition `from_vlan` est déjà encodée dans le verdict du 1ᵉ paquet.
- Un flux **non encore tranché** (`ct mark` 0 : ClientHello, 1re résolution)
  poursuit le chemin complet et atteint l'inspection habituelle (SNI residual…).
- Un `ct mark` **obsolète après SIGHUP** (marks recompilés) → miss du vmap → le
  flux retraverse `cv_rules_dispatch` et est redécidé. Aucun faux verdict.

Équivalent sémantique au `ct state established,related accept` situé en bas de
chaîne, mais borné aux flux décidés et placé avant le travail coûteux. Couvert
par `tests/unit/nft_filter_ips_spec.moon` (rendu residual/integral + ordre).

## Superviseur (`main.moon`)

- Fork chaque worker et surveille via `waitpid(-1, …, WNOHANG)` ; redémarre
  après un backoff de 1 seconde en cas de crash.
- **ENOBUFS NFQUEUE** : `nfq_loop` ne tue pas le worker sur `ENOBUFS` (errno 105,
  file noyau pleine sous charge) — le socket netlink reste utilisable, donc on
  logue (1re fois puis tous les 256) et on continue. Sans cela, une surcharge
  déclenchait une tempête de morts/redémarrages. Les autres erreurs de lecture
  (hors `EINTR`) restent fatales.
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

### Cache de lecture des sessions (hot-path question/response)

Les workers question/response lisent `sessions_file` via un cache à TTL court
(`CACHE_TTL = 5 s`). Sur un **miss** (MAC/IP non trouvée) ou une session expirée,
le cache peut être obsolète juste après une authentification : on rechargeait donc
le fichier (`loadfile` + exécution) à chaque miss, ce qui, pour un filtre DNS où la
majorité du trafic provient de MAC non authentifiées, déclenchait un rechargement
disque + compilation Lua **par paquet**.

Désormais, `reload_needed(path)` calcule une **signature `statx`** du fichier
(`mtime` ns + taille + inode) et ne déclenche le reload-on-miss que si cette
signature diffère de celle chargée en cache. On n'évite un reload **que** lorsqu'on
peut prouver que le fichier est byte-identique (statx réussi des deux côtés et
signatures égales) : recharger redonnerait alors la même table, c'est un no-op
strict — **aucun faux négatif possible**. Tout échec `statx` (fichier absent,
indisponible) → signature `nil` → reload, conservant le comportement antérieur.
`statx` est utilisé (et non `struct stat`) car son ABI est stable sur toutes les
architectures (x86/ARM/MIPS, glibc/musl). Toute écriture du fichier (donc toute
nouvelle session) change la signature et garantit la fraîcheur.
