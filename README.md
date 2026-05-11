# CustosVirginum

Inline DNS filter on Linux bridge, written in **MoonScript** and executed by
**LuaJIT**. Blocks all DNS traffic except explicitly allowed domains,
logs L2/L3/L4/L7 information, and dynamically builds nftables allowlists
as DNS resolutions occur.

Packet parsing uses **pure LuaJIT FFI pointer arithmetic** for L3/L4/L7
decoding — all without any C compilation step.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  Linux bridge machine                                          │
│                                                                │
│  nftables (kernel)                                             │
│  ├── policy DROP + REJECT LAN                                  │
│  ├── set ip4_allowed   { ipv4_src . ipv4_dst  timeout 2m }     │
│  ├── set ip6_allowed   { ipv6_src . ipv6_dst  timeout 2m }     │
│  ├── set authenticated_macs{ ether_addr timeout <idle_timeout> }│
│  ├── set authenticated_ips { ipv4_addr timeout <idle_timeout> } │
│  ├── set authenticated_ips6{ ipv6_addr timeout <idle_timeout> } │
│  ├── TCP :80 LAN SYN    → NFQUEUE_CAPTIVE    (portail captif)  │
│  ├── TCP :33443          → NFQUEUE_AUTH       (extrait MAC/IP)  │
│  ├── Reject résiduel     → NFQUEUE_REJECT     (reject, rate-limité) │
│  ├── UDP/TCP :53 src=LAN → NFQUEUE_QUESTIONS  (questions)       │
│  └── UDP/TCP :53 dst=LAN → NFQUEUE_RESPONSES  (réponses)        │
│                                                                │
│  LuaJIT (userspace)  BRIDGE_IFNAME=<br>                       │
│  ├── main.lua           supervisor + fork                      │
│  ├── mac_learner        table IP→MAC (socket Unix)             │
│  ├── worker_arp_sniffer ARP/NDP passif → pipe learn (22 B)     │
│  ├── worker_questions ── pipe question_response (43 B, rule_id + timeout) ──► worker_responses │
│  │   parse L2/L3/L4/L7      └─ pipe learn (22 B) → mac_learner│
│  │   rules (conditions+actions)              verify txid       │
│  │   log + ACCEPT/REFUSED/DNSONLY            patch TTL→60s     │
│  │                                           nft set add       │
│  ├── worker_auth_queue ─ pipe auth_ipc (22 B) ──► worker AUTH  │
│  ├── worker AUTH       — HTTPS login (port 33443)              │
│  ├── worker_captive    — TCP/80 SYN → AF_PACKET 302            │
│  ├── worker_reject     — forge RST/ICMP admin-prohibited       │
│  │                                                              │
│  └── logs → syslog (journald / logread)                        │
└────────────────────────────────────────────────────────────────┘
```

### Allowed packet flow

```
DNS Client (LAN)
   │  question UDP/53 → www.github.com ?
   ▼
nft FORWARD → NFQUEUE 0
   ▼
worker question : parse L2+L3+L4+DNS → qname="www.github.com"
   │  is_allowed("www.github.com") → true (suffix "github.com")
   │  log: ALLOW mac_src=aa:bb:.. src_ip=192.168.1.42 qname=www.github.com
   │  write(pipe, txid=0x1234, ip=192.168.1.42, port=54321, mac=aa:bb:cc:dd:ee:ff)
   └► NF_ACCEPT → question forwarded to resolver
   ▼
DNS Resolver (8.8.8.8) responds
   ▼
nft FORWARD → NFQUEUE 1
   ▼
worker response : drain pipe → pending[0x1234:192.168.1.42:54321] found (refused=false)
   │  parse response → A 140.82.121.4
   │  patch TTL → 60s + append EDE only when payload was modified + recalc checksums
   │  nft add element ip dns-filter ip4_allowed { 192.168.1.42 . 140.82.121.4 timeout TTL+grace (borné) }
   │  log: ALLOW action=response_patched answers=1 ttl_set=60
   └► NF_ACCEPT + modified payload
   ▼
Client receives response (TTL=60s)
   ▼
Client opens TCP connection → 140.82.121.4
   ▼
nft FORWARD : ip saddr . ip daddr @ip4_allowed accept → allowed through
```

### Blocked packet flow

```
DNS Client (LAN)
   │  question UDP/53 → www.facebook.com ?
   ▼
nft FORWARD → NFQUEUE 0
   ▼
worker question : qname="www.facebook.com"
   │  is_allowed("www.facebook.com") → false
   │  log: BLOCK reason=not_in_allowlist
   │  write_refused_msg(pipe, txid=0x1234|REFUSED, ip, port, mac)
   └► NF_ACCEPT → question forwarded to resolver
   ▼
DNS Resolver (8.8.8.8) responds
   ▼
nft FORWARD → NFQUEUE 1
   ▼
worker response : drain pipe → pending[0x1234:192.168.1.42:54321] found (refused=true)
   │  transform response → RCODE=5 REFUSED + EDE code 15 "Filtered" + "Custos vigilat."
   │  replace DNS payload, strip HTTPS/SVCB if present, recalc checksums
   │  log: BLOCK action=response_refused
   └► NF_ACCEPT + REFUSED payload (client receives REFUSED + EDE)
```

---

## Project Structure

```
custos/
├── cfg/
│   ├── filter.yml           Configuration des listes de domaines (updater)
│   └── secrets.sample       Exemple de fichier de mots de passe
├── src/
│   ├── config.moon          Configuration hiérarchique runtime (/etc/custos/config.moon)
│   ├── ffi_defs.moon        Déclarations FFI centralisées
│   ├── log.moon             Logging structuré key=value + rate-limiting
│   ├── ipc.moon             Protocole pipe question→response (msg 43 octets)
│   ├── nft.moon             Injection sets nftables via libnftables
│   ├── nft_add_helper.moon  Helper retry/backoff pour insertions nft
│   ├── nft_rules.moon       Règles nft statiques
│   ├── nft_extra_rules.moon Gestion règles nft supplémentaires (UCI)
│   ├── nfq_loop.moon        Boucle générique NFQUEUE
│   ├── bridge_raw.moon      AF_PACKET : injection de frames brutes
│   ├── captive_ips.moon     Détection IPs portail captif
│   ├── forge_dns.moon       Construction de réponses DNS forgées
│   ├── ip_whitelist.moon    Gestion whitelist IP statique
│   ├── mac_learner.moon     Table IP→MAC en mémoire + socket Unix
│   ├── mac_learner_ipc.moon Client IPC pour mac_learner
│   ├── mac_prober.moon      Sondage actif ARP/NDP
│   ├── ffi_xxhash.moon      FFI xxHash
│   ├── worker_questions.moon  Worker questions DNS
│   ├── worker_responses.moon  Worker réponses DNS
│   ├── worker_captive.moon    Worker portail captif TCP/80
│   ├── worker_auth_queue.moon Worker NFQUEUE port 33443 (extrait MAC/IP)
│   ├── worker_reject.moon     Worker forge RST/ICMP admin-prohibited
│   ├── worker_arp_sniffer.moon Worker sniffer ARP/NDP passif
│   ├── main.moon            Superviseur + fork
│   ├── auth/
│   │   ├── worker.moon          Worker AUTH principal
│   │   ├── server.moon          Serveur HTTPS (FFI WolfSSL)
│   │   ├── worker_conn.moon     Gestion des connexions HTTPS
│   │   ├── sessions.moon        Lecture/écriture sessions.lua
│   │   ├── nft_sessions.moon    Gestion sets nft pour sessions
│   │   ├── credentials.moon     Vérification PBKDF2
│   │   ├── cert.moon            Gestion certificats TLS (cache LRU/TTL)
│   │   ├── cert_generator.moon  Génération dynamique via px5g
│   │   ├── cert_cache.moon      Cache LRU/TTL pour certificats
│   │   ├── sni_extractor.moon   Parser SNI (TLS ClientHello)
│   │   ├── ffi_wolfssl.moon     FFI wrapper WolfSSL (remplace luasec)
│   │   └── html.moon            Templates HTML du portail
│   ├── filter/
│   │   ├── init.moon        Moteur de filtrage (load/decide/reload)
│   │   ├── rule.moon        Évaluateur de règles (conditions + actions)
│   │   ├── convert.moon     Convertisseurs YAML → types moteur
│   │   ├── updater.moon     CLI : téléchargement + compilation listes de domaines
│   │   ├── actions/
│   │   │   ├── allow.moon   Action allow — injecte IPs dans mac4/mac6_allowed
│   │   │   ├── deny.moon    Action deny — répond REFUSED + EDE
│   │   │   └── dnsonly.moon Action dnsonly — DNS autorisé sans injection nft
│   │   ├── conditions/
│   │   │   ├── from_net.moon / from_nets.moon / from_netlist.moon / from_netlists.moon
│   │   │   ├── from_mac.moon / from_macs.moon / from_maclist.moon / from_maclists.moon
│   │   │   ├── from_user.moon / from_users.moon / from_userlist.moon / from_userlists.moon
│   │   │   ├── to_domain.moon / to_domains.moon / to_domainlist.moon / to_domainlists.moon
│   │   │   ├── in_time.moon / in_times.moon
│   │   │   └── stolen_computer.moon
│   │   └── lib/
│   │       ├── bsearch.moon         Recherche binaire dans fichiers de listes
│   │       ├── ipcalc.moon          Test d'appartenance CIDR
│   │       ├── load_config.moon     Chargeur YAML (lyaml)
│   │       └── parse_domains.moon   Parser multi-format de listes de domaines
│   ├── nfq/
│   │   ├── ethernet.moon    L2 : MAC src via nfq_get_packet_hw
│   │   └── packet.moon      L3–L7 parseur unifié
│   └── ipparse/         Bibliothèque parsing L2/L3/L4/L7 (submodule)
├── lua/                     Lua généré par moonc (ne pas éditer)
├── nft-rules/
│   └── dns-filter-bridge.nft       Ruleset nftables (bridge mode)
├── packaging/
│   └── openwrt/custos/
│       └── files/usr/sbin/custos-update   Script de mise à jour des listes
├── tests/
│   ├── run_tests.moon       Tests unitaires source (sans root)
│   ├── run_tests.lua        Tests unitaires compilés
│   ├── test_e2e.moon        Tests E2E (VM/SSH)
│   ├── test_openwrt.moon    Tests E2E OpenWrt via SSH
│   ├── run_e2e.moon         Runner de la suite E2E
│   └── e2e_holos.moon       Suite E2E Holos
├── install-owrt.moon        Installeur OpenWrt (déploiement SSH)
├── install-owrt.lua         Installeur compilé
├── LICENSE                  Licence MIT
├── Makefile
└── README.md
```

---

## Prerequisites

### OpenWrt Packages

| Package                  | Role                                    |
|--------------------------|-----------------------------------------|
| `luajit`                 | Compiled Lua execution                  |
| `moonscript`             | `.moon` → `.lua` compilation            |
| `lyaml`                  | YAML config loader (`lyaml`, LuaJIT)    |
| `libnetfilter-queue`     | NFQUEUE C library                       |
| `libnftables`            | nftables library (set injection)        |
| `nftables`               | `nft` tool                              |
| `wolfssl`                | TLS/SSL library (via FFI)               |
| `px5g-wolfssl`           | Dynamic TLS certificate generation      |

```bash
opkg install luajit lyaml libnetfilter-queue nftables wolfssl px5g-wolfssl
# moonscript via luarocks or build from source
```

---

## Installation

### Déploiement sur OpenWrt

```bash
git clone <repo> custos
cd custos

# Compile MoonScript → Lua
make

# Run unit tests (no root required)
make test

# Deploy to OpenWrt router via SSH
luajit install-owrt.lua root@<routeur>
```

L'installeur (`install-owrt.moon`) :
1. Installe les paquets opkg requis
2. Déploie les fichiers dans `/usr/sbin/custos/`
3. Configure le service `/etc/init.d/custos`
4. Démarre le service

---

## Configuration

La configuration runtime principale est `/etc/custos/config.moon` (surcharge partielle des
défauts de `src/config.moon`). Elle couvre :
- runtime/NFQUEUE/nft/dns/auth/doh/events
- le moteur de filtrage (`filter.rules`, `filter.nets`, `filter.macs`, `filter.times`)
- les décisions de parcours de règles (`filter.decision.first_match_wins`,
  `filter.decision.continue_to_next_rule`)
- `dns.ttl_grace` (`grace`, `min`, `max`) — timeout nft = `TTL + grace`, borné

NFT extra rules (via UCI)
- Il est possible d’ajouter des règles nft supplémentaires depuis UCI (section `custos.main`) via l’option `nft_extra_rules`.
- Chaque entrée UCI est un fragment de règle nft (sans le préfixe `insert rule <table> <chain> ...`). Ces fragments sont insérés en tête de la chaîne `forward` de la table configurée au démarrage du service, et supprimés proprement à l’arrêt.
- Exemple d’entrée UCI (une ligne par fragment) :
  - `nft_extra_rules='ip saddr 10.0.0.0/8 counter log prefix "extra: " accept'`
- Remarques :
  - Les fragments doivent être des expressions nft valides pour la chaîne `forward`.
  - Les règles sont appliquées une seule fois au démarrage et retirées à l’arrêt ; elles ne sont pas ré-insertées lors d’un SIGHUP de rechargement du filtre.

```bash
make          # recompile après modification des sources
make reload   # envoie SIGHUP aux workers (rechargement à chaud)
```

---

## Domain List Updater

`src/filter/updater.moon` est un outil CLI qui télécharge, parse et compile
des listes de domaines au format binaire optimisé pour la recherche binaire.

```bash
# Télécharger et compiler toutes les listes définies dans filter.yml
LUA_PATH="lua/?.lua;lua/?/init.lua;;" luajit lua/filter/updater.lua cfg/filter.yml

# Sur OpenWrt (après installation) :
custos-update
```

### Sources

Chaque entrée `sources:` dans `filter.yml` peut être :

```yaml
sources:
  toulouse:
    url:    https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz
    format: toulouse          # archive tar.gz multi-catégories
    subdir: toulouse          # sous-dossier de domainlists_dir

  ma-liste:
    file:   /etc/custos/lists/custom/ma-liste.txt
    format: simple            # un domaine par ligne
    output: /etc/custos/lists/custom/ma-liste.bin
```

### Listes personnalisées

Positionner `custom_lists_dir` dans `filter.yml` pour activer le scan
automatique de fichiers `.txt` :

```yaml
domainlists_dir: /etc/custos/lists
custom_lists_dir: /etc/custos/lists/custom
```

Chaque fichier `custom/*.txt` (un domaine par ligne, `#` pour les commentaires)
est converti en `custom/*.bin`. Les originaux sont conservés.

Les listes sont référençables dans les règles :

```yaml
conditions:
  to_domainlist: custom/ma-liste
```

### `custos-update` (OpenWrt)

L'installeur (`install-owrt.moon`) déploie `/usr/sbin/custos-update` et
configure une tâche cron quotidienne (`0 4 * * *`) pour la mise à jour
automatique des listes.

---

## Running

### Sur OpenWrt

```bash
# Start the service
/etc/init.d/custos start

# Stop the service
/etc/init.d/custos stop

# Restart the service
/etc/init.d/custos restart

# View logs
logread -e custos
```

Example log:
```
[1718100000] [1234] INFO  action=dns-filter_start version=1.0.0
[1718100001] [1235] INFO  action=queue_listening queue=0
[1718100001] [1236] INFO  action=queue_listening queue=1
[1718100010] [1235] ALLOW mac_src=aa:bb:cc:dd:ee:ff in_if=3 src_ip=192.168.1.42
                          dst_ip=8.8.8.8 src_port=54321 dst_port=53
                          txid=0x1234 qname=www.github.com qtype=A
[1718100010] [1236] ALLOW action=response_patched src_ip=8.8.8.8
                          dst_ip=192.168.1.42 txid=0x1234
                          qnames=www.github.com answers=2 ttl_set=60
[1718100015] [1235] BLOCK mac_src=aa:bb:cc:dd:ee:ff src_ip=192.168.1.42
                          qname=www.facebook.com qtype=A reason=not_in_allowlist
```

---

## IPC Protocols

### Pipe question → response (`question_response`, 43 octets)

The Unix pipe (created before `fork()`) carries 43-byte messages.
Atomicity is guaranteed by POSIX for messages ≤ PIPE_BUF (4096 bytes).

```
Byte  0      : type  — 0x41 ('A') = IPv4 allowed,    0x36 ('6') = IPv6 allowed
                       0x52 ('R') = IPv4 refused,     0x72 ('r') = IPv6 refused
                       0x44 ('D') = IPv4 dns-only,    0x64 ('d') = IPv6 dns-only
Bytes 1-2    : DNS txid (big-endian uint16)
Bytes 3-18   : source IP — 16 bytes
                 IPv4 : 4 bytes address + 12 zero bytes (padding)
                 IPv6 : 16 bytes address (complete, no truncation)
Bytes 19-20  : source port (big-endian uint16)
Bytes 21-26  : source MAC (6 bytes, zeroed if unavailable)
Bytes 27-42  : resolver IP — 16 bytes
                 IPv4 : 4 bytes address + 12 zero bytes (padding)
                 IPv6 : 16 bytes address (complete, no truncation)
```

response maintains a table `pending[txid:ip:port:resolver_ip] = {expire, refused, dnsonly}` (TTL 5s).
`refused=true` means question determined the query must be blocked; response transforms
the upstream response into a REFUSED reply instead of patching TTL.
`dnsonly=true` means question allowed the query but without nft IP injection (e.g.
captive portal probes): response patches TTL + EDE but does not call `nft add element`.
Purge is **lazy**: an expired entry is removed at lookup time,
without a separate timer.

### Pipe `learn` et `auth_ipc` (22 octets)

Two additional pipes carry MAC/IP associations:

- **`learn` pipe** : written by `worker_questions` and `worker_arp_sniffer`, read by `mac_learner`.
- **`auth_ipc` pipe** : written by `worker_auth_queue`, read by `auth/worker`.

```
Bytes 0-15 : IP address — 16 bytes
               IPv4 : 4 bytes address + 12 zero bytes (left-padded)
               IPv6 : 16 bytes address (complete)
Bytes 16-21: source MAC (6 bytes)
```

---

## TTL Patch

Each allowed DNS response is modified before being returned to the client:

1. All Resource Record TTLs are rewritten to 60 seconds
2. An EDNS OPT option EDE code 0 "Other" with extra-text `"Custos vigilat."`
   is appended to the response's OPT RR, signalling that TTL was clamped
3. L4 checksum is recalculated (`UDP` or `TCP`, IPv4/IPv6 pseudo-header)
4. IPv4 header checksum is recalculated when applicable
5. `NF_ACCEPT` verdict is set with modified payload via
   `nfq_set_verdict(qh, pkt_id, NF_ACCEPT, len, patched_ptr)`

Each blocked DNS response (where question sent `refused=true`) is replaced by
a REFUSED reply with EDE code 15 "Filtered" and extra-text `"Custos vigilat."`,
reconstructed from the upstream server's TCP/UDP framing (so no raw-socket
spoofing is needed).

For multi-segment TCP DNS responses, response buffers segments, patches the fully
assembled DNS payload once complete, then reinjects a single coalesced
`PSH|ACK` segment (with corrected checksums and initial sequence number).

The goal is to force clients to re-validate resolution every 60 seconds,
ensuring IPs authorized in nft sets (2-minute timeout) remain valid
as long as the client actively resolves the name.

---

## Authentication

CustosVirginum includes an HTTPS authentication server that maps LAN client IPs to user
accounts. The `from_user` filter condition allows rules such as
"only user alice can reach github.com".

### Process model

A third worker (`AUTH`) is forked by the supervisor alongside the DNS workers,
the captive portal worker, and several auxiliary workers:

```
main (supervisor)
├── mac_learner          (table IP→MAC, socket Unix)
├── worker_arp_sniffer   (ARP/NDP passif → pipe learn)
├── worker_auth_queue    (NFQUEUE port 33443 → pipe auth_ipc)
├── worker_questions ×N (DNS questions)
├── worker_responses ×N (DNS réponses)
├── worker_captive   ×N (TCP/80 SYN → AF_PACKET 302)
├── worker_reject    ×N (forge RST/ICMP)
└── worker AUTH          (HTTPS login server)
```

Sessions are shared via a Lua-evaluable file (`/tmp/sessions.lua`). question/response workers
reload it every 5 seconds (TTL cache). No inter-process socket is needed.

### TLS certificate

The AUTH worker generates **self-signed certificates dynamically** via `px5g`
(WolfSSL-based) with an LRU/TTL cache (100 slots, 24h). Certificates are
generated on-demand based on the SNI (Server Name Indication) from the
TLS ClientHello.

To use your own static certificate, set `cert` and `key` in `cfg/filter.yml`:

```yaml
auth:
  port: 8443
  cert: /etc/custos/auth.crt
  key:  /etc/custos/auth.key
  secrets: cfg/secrets
  session_ttl: 0            # seconds (default: 0 = no absolute expiry)
```

### Secrets file

Each line holds one credential in the format:

```
user:pbkdf2-sha256:<iterations>:<salt_hex>:<hash_hex>
```

Generate an entry with:

```bash
make make-secret USER=alice PASS=hunter2
# → append the printed line to cfg/secrets
```

See `cfg/secrets.sample` for a full example.

### Logging in

Navigate to `https://<router>:8443/` in a browser (accept the self-signed cert
warning). After a successful login the client **MAC address** is recorded in the session
store as the primary identifier. This MAC-primary architecture allows seamless
cross-family tracking (IPv4/IPv6) and handles IP changes gracefully.
Sessions expire after `idle_timeout` seconds without heartbeat, or on explicit logout. `session_ttl` is optional; `0` disables absolute expiry.

### Using `from_user` in rules

```yaml
rules:
  - name: alice-only
    conditions:
      from_user: alice
    action: allow
    domains: [github.com, pypi.org]
```

Multiple users can be listed (logical OR):

```yaml
    conditions:
      from_user: [alice, bob]
```

### Captive portal

Un **worker captive** dédié intercepte les SYN TCP/80 des clients non authentifiés
via NFQUEUE 2 et répond directement avec une réponse HTTP 302 vers le portail
HTTPS (port 33443), sans passer par le proxy kernel. Une fois authentifié,
l'IP cliente est ajoutée à `authenticated_ips` et les SYN TCP/80 ne sont plus
interceptés.

La condition `dnsonly` permet de détecter les sondes de portail captif
(connectivitycheck, generate_204, etc.) et de les laisser passer au niveau
DNS **sans injecter les IPs dans les sets nft** — le client peut ainsi résoudre
les noms de domaine sans accéder aux serveurs cibles avant d'être authentifié :

```yaml
- description: Sondes portail captif
  actions: [dnsonly]
  conditions:
    to_domains:
      - connectivitycheck.gstatic.com
      - captive.apple.com
      - www.msftconnecttest.com
```

### Conditions utilisateur

`from_user`, `from_users`, `from_userlist`, `from_userlists` permettent
d'associer des règles à des comptes authentifiés :

```yaml
- name: alice-only
  conditions:
    from_user: alice
  actions: [allow]
  conditions:
    to_domainlist: toulouse/adult
```

Plusieurs utilisateurs (OR logique) :

```yaml
  conditions:
    from_users: [alice, bob]
```

---

## Known Limitations

- **DoH / DoT**: not covered (ports 443/853).
- **Scaling**: each worker processes its NFQUEUE socket single-threadedly by
  design (share-nothing architecture). libnfq does support out-of-order verdicts
  (each verdict references its packet by `packet_id`), but intra-queue parallelism
  would require shared-state synchronisation in workers that maintain flow context
  (`pending` table, TCP reassembly). Horizontal scaling via multiple queue
  numbers (`QUEUE_QUESTIONS="0,1,2"`) with nftables hash distribution
  (`queue num 0-2`) is the correct approach.
- **MAC spoofing**: `mac4_allowed`/`mac6_allowed` rely on the MAC address
  reported by `nfq_get_packet_hw`. On a bridge, this is the L2 source MAC
  and can be spoofed by a LAN client.

## nft Ruleset

The single file `nft-rules/dns-filter-bridge.nft` is a **ruleset for bridge mode**.

### How it works

- DNS (UDP/TCP port 53) from LAN → **NFQUEUE_QUESTIONS** (`worker_questions`)
- DNS responses (sport 53) to LAN → **NFQUEUE_RESPONSES** (`worker_responses`)
- TCP/80 SYN from LAN → **NFQUEUE_CAPTIVE** (`worker_captive`)
- TCP/33443 → **NFQUEUE_AUTH** (`worker_auth_queue`)
- Rate-limited reject traffic → **NFQUEUE_REJECT** (`worker_reject`)
- Queue numbers are **configurable via UCI** (`QUEUE_QUESTIONS`, `QUEUE_RESPONSES`,
  `QUEUE_CAPTIVE`, `QUEUE_AUTH`, `QUEUE_REJECT`); defaults: 0, 1, 2, 5, 3.
  Ranges like `"0,2,5-7"` spawn one worker per queue number.
- LuaJIT decides ACCEPT, REFUSED, or DNSONLY; populates `ip4_allowed`/`ip6_allowed` on success
- Clients in `authenticated_ips` bypass TCP/80 interception (QUEUE_CAPTIVE)
- All forwarded traffic matching a set entry → ACCEPT; rest → DROP/REJECT

### Sets nftables

| Set | Type | Rôle |
|-----|------|------|
| `ip4_allowed` | `ipv4_addr . ipv4_addr` | Paire (src IP client, IPv4 dest) autorisée après résolution DNS |
| `ip6_allowed` | `ipv6_addr . ipv6_addr` | Paire (src IPv6 client, IPv6 dest) autorisée après résolution DNS |
| `authenticated_macs` | `ether_addr` | MACs clientes authentifiées (bypass intercept TCP/80 captive) |
| `authenticated_ips` | `ipv4_addr` | IPs clientes IPv4 authentifiées (bypass intercept TCP/80 captive) |
| `authenticated_ips6` | `ipv6_addr` | IPs clientes IPv6 authentifiées (bypass intercept TCP/80 captive) |
| `ip4_dest_whitelist` | `ipv4_addr` | Destinations IPv4 toujours autorisées (bypass DNS, rechargement SIGHUP) |
| `ip6_dest_whitelist` | `ipv6_addr` | Destinations IPv6 toujours autorisées (bypass DNS, rechargement SIGHUP) |

### Prerequisites

Sur OpenWrt, les règles nft sont appliquées automatiquement par le service au démarrage. Pour appliquer manuellement :

```bash
nft -f nft-rules/dns-filter-bridge.nft
```

### DHCP / SLAAC

The ruleset explicitly passes bootstrap traffic that cannot be tracked by
conntrack and must therefore bypass the `policy drop`:

| Traffic | Direction | Rule |
|---------|-----------|------|
| DHCPv4 (UDP 67/68) | FORWARD | `udp dport { 67, 68 } accept` |
| DHCPv4 server on filter machine | INPUT | `udp dport 67 accept` |
| DHCPv6 (UDP 546/547) | FORWARD | `udp dport { 546, 547 } accept` |
| DHCPv6 server on filter machine | INPUT | `udp dport 547 accept` |
| SLAAC Router Advertisement from upstream router | FORWARD | `icmpv6 type nd-router-advert accept` |

Router Advertisements **emitted by the filter machine itself** (radvd,
WireGuard relay…) exit via the OUTPUT chain whose `policy accept` already
covers them.

### IPv6 / ICMPv6

The IPv6 FORWARD chain explicitly passes NDP messages (neighbor-solicit,
neighbor-advert, router-solicit, router-advert) and ICMPv6 echo — required
for IPv6 connectivity.

---

## Destination Whitelist (Bypass DNS Analysis)

For networks that should bypass DNS analysis entirely (e.g., servers accessible from outside), configure a destination whitelist via UCI:

```bash
# On OpenWrt router
uci add_list custos.main.dest_whitelist '10.0.0.0/24'
uci add_list custos.main.dest_whitelist '2001:db8::/32'
uci commit custos
/etc/init.d/custos reload
```

Traffic to these CIDRs is allowed without DNS resolution. The `ip4_dest_whitelist` and `ip6_dest_whitelist` nftables sets are checked before DNS NFQUEUE, enabling direct access.

The whitelist can also be configured in `cfg/filter.yml`:

```yaml
ip_whitelist:
  - 10.0.0.0/24
  - 2001:db8::/32
```

---
