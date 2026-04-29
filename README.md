# CustosVirginum

Inline DNS filter on Linux bridge, written in **MoonScript** and executed by
**LuaJIT**. Blocks all DNS traffic except explicitly allowed domains,
logs L2/L3/L4/L7 information, and dynamically builds nftables allowlists
as DNS resolutions occur.

Packet parsing uses **pure LuaJIT FFI pointer arithmetic** for L3/L4/L7
decoding, combined with **libndpi** for deep packet inspection and protocol
detection — all without any C compilation step.

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
│  ├── TCP :80 LAN SYN → NFQUEUE 2  (portail captif, non-auth)  │
│  ├── UDP/53 + TCP/53 src=LAN → NFQUEUE 0  (questions)          │
│  └── UDP/53 + TCP/53 dst=LAN → NFQUEUE 1  (réponses)           │
│                                                                │
│  LuaJIT (userspace)  BRIDGE_IFNAME=<br>         │
│  ├── main.lua        supervisor + fork                         │
│  ├── worker Q0  ─────────────────── pipe IPC ──► worker Q1    │
│  │   parse L2/L3/L4/L7 (FFI)                    drain pipe     │
│  │   rules (conditions + actions)               verify txid    │
│  │   log + ACCEPT/REFUSED/DNSONLY               patch TTL→60s  │
│  │   write(pipe, txid+ip+port+mac+type)         nft set add    │
│  │   or send REFUSED (socket UDP/53)            ACCEPT+payload │
│  ├── worker AUTH — HTTPS login (port 33443)                    │
│  ├── worker Q2   — TCP/80 SYN intercept → 302 → portail        │
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
worker Q0 : parse L2+L3+L4+DNS → qname="www.github.com"
   │  is_allowed("www.github.com") → true (suffix "github.com")
   │  log: ALLOW mac_src=aa:bb:.. src_ip=192.168.1.42 qname=www.github.com
   │  write(pipe, txid=0x1234, ip=192.168.1.42, port=54321, mac=aa:bb:cc:dd:ee:ff)
   └► NF_ACCEPT → question forwarded to resolver
   ▼
DNS Resolver (8.8.8.8) responds
   ▼
nft FORWARD → NFQUEUE 1
   ▼
worker Q1 : drain pipe → pending[0x1234:192.168.1.42:54321] found (refused=false)
   │  parse response → A 140.82.121.4
   │  patch TTL → 60s + append EDE code 0 "Custos vigilat." + recalc checksums
   │  nft add element ip dns-filter ip4_allowed { 192.168.1.42 . 140.82.121.4 timeout 2m }
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
worker Q0 : qname="www.facebook.com"
   │  is_allowed("www.facebook.com") → false
   │  log: BLOCK reason=not_in_allowlist
   │  write_refused_msg(pipe, txid=0x1234|REFUSED, ip, port, mac)
   └► NF_ACCEPT → question forwarded to resolver
   ▼
DNS Resolver (8.8.8.8) responds
   ▼
nft FORWARD → NFQUEUE 1
   ▼
worker Q1 : drain pipe → pending[0x1234:192.168.1.42:54321] found (refused=true)
   │  transform response → RCODE=5 REFUSED + EDE code 15 "Filtered" + "Custos vigilat."
   │  replace DNS payload, recalc checksums
   │  log: BLOCK action=response_refused
   └► NF_ACCEPT + REFUSED payload (client receives REFUSED + EDE)
```

---

## Project Structure

```
custos/
├── cfg/
│   ├── filter.yml           Config du filtre (YAML) — règles, listes, auth
│   └── secrets.sample       Exemple de fichier de mots de passe
├── src/
│   ├── config.moon          Configuration : constantes, chemins
│   ├── uci_config.moon      Chargeur config UCI (OpenWrt)
│   ├── ffi_defs.moon        Déclarations FFI centralisées
│   ├── log.moon             Logging structuré key=value + rate-limiting
│   ├── ipc.moon             Protocole pipe Q0→Q1 (msg 43 octets)
│   ├── neigh.moon           Lecture table voisins kernel (ip neigh show)
│   ├── nft.moon             Injection sets nftables via libnftables
│   ├── nft_add_helper.moon  Helper retry/backoff pour insertions nft
│   ├── nfq_loop.moon        Boucle générique NFQUEUE
│   ├── worker_q0.moon       Worker questions DNS
│   ├── worker_q1.moon       Worker réponses DNS
│   ├── worker_q2.moon       Worker portail captif TCP SYN
│   ├── main.moon            Superviseur + fork (Q0, Q1, AUTH, Q2)
│   ├── ffi_ndpi.moon        Façade détection version (charge v4 ou v5)
│   ├── ffi_ndpi_v4.moon     FFI cdef pour nDPI 4.2–4.8
│   ├── ffi_ndpi_v5.moon     FFI cdef pour nDPI 5.0+
│   ├── filter/
│   │   ├── init.moon        Moteur de filtrage (load/decide/reload)
│   │   ├── rule.moon        Évaluateur de règles (conditions + actions)
│   │   ├── convert.moon     Convertisseurs YAML → types moteur
│   │   ├── updater.moon     CLI : téléchargement + compilation listes de domaines
│   │   ├── actions/
│   │   │   ├── allow.moon   Action allow — injecte IPs dans mac4/mac6_allowed
│   │   │   ├── deny.moon    Action deny — répond REFUSED + EDE
│   │   │   ├── dnsonly.moon Action dnsonly — DNS autorisé sans injection nft
│   │   │   └── mail.moon    Action mail (future)
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
│   └── parse/
│       ├── ethernet.moon    L2 : MAC src via nfq_get_packet_hw
│       ├── ip.moon          L3 : IPv4 + IPv6 + checksums
│       ├── udp.moon         L4 : UDP + recalcul checksum
│       ├── dns.moon         L7 : RFC 1035 complet + patch TTL
│       ├── ndpi.moon        L3-L7 parseur unifié (façade)
│       ├── ndpi_v4.moon     Backend nDPI 4.2–4.8
│       └── ndpi_v5.moon     Backend nDPI 5.0+
├── lua/                     Lua généré par moonc (ne pas éditer)
├── nft-rules/
│   └── dns-filter-bridge.nft       Ruleset nftables (bridge mode)
├── packaging/
│   └── openwrt/custos/
│       └── files/usr/sbin/custos-update   Script de mise à jour des listes
├── tests/
│   ├── run_tests.moon       Tests unitaires source (sans root)
│   ├── run_tests.lua        Tests unitaires compilés
│   ├── test_ndpi.moon       Tests du wrapper nDPI
│   ├── test_ndpi.lua        Tests nDPI compilés
│   ├── test_openwrt.moon    Tests E2E OpenWrt via SSH source
│   └── test_openwrt.lua     Tests E2E OpenWrt compilés
├── install-owrt.moon        Installeur OpenWrt (déploiement SSH)
├── install-owrt.lua         Installeur compilé
├── LICENSE                  Licence MIT
├── Makefile
├── setup.sh
└── README.md
```

---

## Prerequisites

### System Packages

| Package                  | Role                                    |
|--------------------------|-----------------------------------------|
| `luajit`                 | Compiled Lua execution                  |
| `moonscript`             | `.moon` → `.lua` compilation            |
| `lua-yaml`               | YAML config loader (`lyaml`, LuaJIT)    |
| `libnetfilter-queue1`    | NFQUEUE C library                       |
| `libnftables1`           | nftables library (set injection)        |
| `libndpi-dev`            | nDPI deep packet inspection (FFI)       |
| `nftables`               | `nft` tool                              |

**Debian/Ubuntu:**
```bash
apt install luajit lua-yaml libnetfilter-queue1 libnftables1 libndpi-dev nftables
luarocks install moonscript
```

**OpenWrt:**
```bash
apk install luajit lyaml libndpi libnetfilter-queue nftables
# moonscript via luarocks or build from source
```

---

## Installation

```bash
git clone <repo> custos
cd custos

# Compile MoonScript → Lua
make

# Run unit tests (no root required)
make test

# Run nDPI wrapper tests (requires libndpi)
make test-ndpi

# Check deps, apply nft rules
sudo ./setup.sh up
```

---

## Configuration

La configuration principale est dans `cfg/filter.yml`. Elle couvre :
- les règles de filtrage (conditions + actions)
- les listes de domaines (`domainlists_dir`, `custom_lists_dir`)
- le serveur d'authentification (`auth:`)
- les dictionnaires de réseaux, MACs, utilisateurs, plages horaires

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

```bash
# Verify nft rules are in place
sudo ./setup.sh status

# Start the filter (stays in foreground)
sudo make run

# In another terminal, watch logs
make logs
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

## IPC Protocol Q0 → Q1

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

Q1 maintains a table `pending[txid:ip:port:resolver_ip] = {expire, refused, dnsonly}` (TTL 5s).
`refused=true` means Q0 determined the query must be blocked; Q1 transforms
the upstream response into a REFUSED reply instead of patching TTL.
`dnsonly=true` means Q0 allowed the query but without nft IP injection (e.g.
captive portal probes): Q1 patches TTL + EDE but does not call `nft add element`.
Purge is **lazy**: an expired entry is removed at lookup time,
without a separate timer.

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

Each blocked DNS response (where Q0 sent `refused=true`) is replaced by
a REFUSED reply with EDE code 15 "Filtered" and extra-text `"Custos vigilat."`,
reconstructed from the upstream server's TCP/UDP framing (so no raw-socket
spoofing is needed).

For multi-segment TCP DNS responses, Q1 buffers segments, patches the fully
assembled DNS payload once complete, then reinjects a single coalesced
`PSH|ACK` segment (with corrected checksums and initial sequence number).

The goal is to force clients to re-validate resolution every 60 seconds,
ensuring IPs authorized in nft sets (2-minute timeout) remain valid
as long as the client actively resolves the name.

---

## nDPI Integration

The `parse/ndpi` module replaces the separate `parse/ip` + `parse/udp` +
`parse/dns` pipeline with a single unified parser. It uses:

- **Pure FFI pointer arithmetic** (`uint8_t*` + `bit` library) for
  L3/L4/L7 header decoding — no `string.byte()`, no C bridge, no
  compilation step.
- **libndpi** (loaded at runtime via `ffi.load "ndpi"`) for protocol
  detection. nDPI provides two levels of classification:
  - `ndpi_master` — transport protocol (e.g. `5` = DNS)
  - `ndpi_app` — application behind the query (e.g. `203` = Github)
- **Pre-allocated buffers** (`flow_buf`, `ipv6_str`) reused across calls
  to avoid GC pressure in the hot path.
- **DNS name decompression** (RFC 1035 §4.1.4) implemented in MoonScript
  with FFI pointers — JIT-compilable by LuaJIT.

### Version Tolerance

The wrapper auto-detects the installed libndpi version via
`ndpi_revision()` at load time, then dispatches to the appropriate
backend:

| Versions | Backend | Key differences |
|----------|---------|----------------|
| 4.2–4.4  | `v4`    | 5-arg `ndpi_detection_process_packet` |
| 4.6–4.8  | `v4`    | 6-arg (added `input_info`), `bitmask2` returns `int` |
| 5.0+     | `v5`    | No `NDPI_PROTOCOL_BITMASK`, different `ndpi_init_detection_module` signature, opaque `ndpi_protocol` struct (read via accessors) |

```
ffi_ndpi.moon       → ndpi_revision() → major >= 5?
                       ├── yes → ffi_ndpi_v5 cdef + parse.ndpi_v5
                       └── no  → ffi_ndpi_v4 cdef + parse.ndpi_v4
                                  └── minor >= 6? → 5-arg or 6-arg
```

### API

```moonscript
ndpi = require "parse.ndpi"

-- Single-call L3+L4+L7 parse + nDPI detection
-- Returns (pkt, nil) on success, (nil, "buffering") while reassembling a
-- multi-segment TCP DNS stream, (nil, "tcp_control") for TCP control packets
-- without DNS payload (SYN/ACK/FIN), or (nil, nil) on unrecognised packets.
pkt, status = ndpi.parse_packet raw
-- pkt.ip    (version, ihl, src_ip, dst_ip, src_ip_raw, ...)
-- pkt.l4    (proto, src_port, dst_port, len, off, payload_len)
--   proto = "udp" or "tcp"
--   TCP extras: pkt.tcp_dns_raw        (assembled DNS payload, multi-segment)
--               pkt.tcp_single_segment  (bool — false when reassembled from N segments)
--               pkt.tcp_init_seq        (uint32 — TCP seq of first segment; used to
--                                        reinject a coalesced+TTL-patched reply)
-- pkt.dns   (txid, is_response, qdcount, ancount, rcode, ...)
-- pkt.questions  [{qname, qtype, qclass, qtype_name}, ...]
-- pkt.ndpi_master, pkt.ndpi_app

-- Parse DNS answer RRs
answers = ndpi.parse_answers raw, pkt
-- [{name, rtype, ttl, ttl_offset, rdata_str, rdata_raw}, ...]

-- Patch TTLs + fix checksums, return modified packet
patched = ndpi.patch_and_checksum raw, pkt, answers, 60

-- Cleanup
ndpi.cleanup!
```

The old per-layer modules (`parse/ip`, `parse/udp`, `parse/dns`) remain
available for reference or fallback.

---

## Authentication

CustosVirginum includes an HTTPS authentication server that maps LAN client IPs to user
accounts. The `from_user` filter condition allows rules such as
"only user alice can reach github.com".

### Process model

A third worker (`AUTH`) is forked by the supervisor alongside Q0 and Q1:

```
main (supervisor)
├── worker Q0 (DNS questions)
├── worker Q1 (DNS answers)
└── worker AUTH (HTTPS login server)
```

Sessions are shared via a Lua-evaluable file (`tmp/sessions.lua`). Q0/Q1 workers
reload it every 5 seconds (TTL cache). No inter-process socket is needed.

### TLS certificate

On first start the AUTH worker generates a **self-signed certificate** via
`openssl req` and stores it in `tmp/auth.crt` / `tmp/auth.key`.

To use your own certificate, set `cert` and `key` in `cfg/filter.yml`:

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

Un **worker Q2** dédié intercepte les SYN TCP/80 des clients non authentifiés
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
- **Single-threaded per worker**: one worker per queue. For very
  high throughput, use `--queue-balance N-M` with N workers per range.
- **MAC spoofing**: `mac4_allowed`/`mac6_allowed` rely on the MAC address
  reported by `nfq_get_packet_hw`. On a bridge, this is the L2 source MAC
  and can be spoofed by a LAN client.

## nft Ruleset

The single file `nft-rules/dns-filter-bridge.nft` is a **ruleset for bridge mode**.

### How it works

- DNS (UDP/TCP port 53) from LAN → **NFQUEUE 0** (questions, worker Q0)
- DNS responses (sport 53) to LAN → **NFQUEUE 1** (responses, worker Q1)
- TCP/80 SYN from LAN → **NFQUEUE 2** (captive portal, worker Q2)
- LuaJIT decides ACCEPT, REFUSED, or DNSONLY; populates `ip4_allowed`/`ip6_allowed` on success
- Clients in `authenticated_ips` bypass TCP/80 interception (Q2 sees their SYN and passes)
- All forwarded traffic matching a set entry → ACCEPT; rest → DROP/REJECT

### Sets nftables

| Set | Type | Rôle |
|-----|------|------|
| `ip4_allowed` | `ipv4_addr . ipv4_addr` | Paire (src IP client, IPv4 dest) autorisée après résolution DNS |
| `ip6_allowed` | `ipv6_addr . ipv6_addr` | Paire (src IPv6 client, IPv6 dest) autorisée après résolution DNS |
| `authenticated_macs` | `ether_addr` | MACs clientes authentifiées (bypass intercept TCP/80 Q2) |
| `authenticated_ips` | `ipv4_addr` | IPs clientes IPv4 authentifiées (bypass intercept TCP/80 Q2) |
| `authenticated_ips6` | `ipv6_addr` | IPs clientes IPv6 authentifiées (bypass intercept TCP/80 Q2) |
| `ip4_dest_whitelist` | `ipv4_addr` | Destinations IPv4 toujours autorisées (bypass DNS, rechargement SIGHUP) |
| `ip6_dest_whitelist` | `ipv6_addr` | Destinations IPv6 toujours autorisées (bypass DNS, rechargement SIGHUP) |

### Prerequisites

```bash
# Apply (no parameters needed)
sudo nft -f nft-rules/dns-filter-bridge.nft
# or
sudo ./setup.sh up
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

The whitelist can also be configured in `cfg/filter.yml` (fallback if UCI is empty):

```yaml
ip_whitelist:
  - 10.0.0.0/24
  - 2001:db8::/32
```

---

## OpenWrt

CustosVirginum peut être déployé directement sur un routeur OpenWrt
(LuaJIT + lyaml + libnetfilter-queue + nftables).

### Installation

```bash
# Déploiement complet sur un routeur via SSH (première installation)
luajit install-owrt.lua root@<routeur>

# Déploiement (mise à jour code uniquement, sans réinstallation des paquets)
make test-openwrt HOST=root@<routeur>
```

L'installeur (`install-owrt.moon`) :
1. Installe les paquets opkg requis
2. Copie les fichiers Lua + nft dans `/usr/share/custos/`
3. Copie la config dans `/etc/custos/`
4. Génère `/usr/sbin/custos-update` (mise à jour des listes)
5. Configure un procd initscript pour le démarrage automatique
6. Active une tâche cron quotidienne (`0 4 * * *`) pour `custos-update`

### Tests E2E OpenWrt (`make test-openwrt`)

```bash
make test-openwrt HOST=root@<routeur>
```

Le test (`tests/test_openwrt.moon`) se connecte via SSH, déploie les
fichiers Lua + nft, démarre les workers, puis exécute les requêtes DNS
depuis la machine locale et vérifie les résultats via `logread`.

Les logs sont acheminés vers le syslog du routeur via
`luajit main.lua 2>&1 | logger -t custos`. `logread` filtre les entrées
depuis un marqueur inséré avant le démarrage des workers.

| Catégorie | Vérifications |
|-----------|--------------|
| Infrastructure | Tables nft, sets, NFQUEUE, ports 33443/33080 |
| DNS ALLOW | `mac4_allowed` peuplé, TTL patché |
| DNS REFUSED | RCODE 5 attendu |
| IPv6 AAAA | `mac6_allowed` + cross-family |
| Authentification | Login/logout, heartbeat, sessions.lua |
| Portail captif | DNAT, redirect, `/generate_204` |
| Bypass MAC | `authenticated_macs` ip + ip6 |
| Whitelist statique | `ip4_dest_whitelist`, rechargement SIGHUP |
