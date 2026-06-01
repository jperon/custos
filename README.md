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
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│  Linux bridge machine                                                                        │
│                                                                                              │
│  nftables (kernel)                                                                           │
│  ├── policy DROP + REJECT LAN                                                                │
│  ├── set ip4_allowed   { ipv4_src . ipv4_dst  timeout 2m }                                   │
│  ├── set ip6_allowed   { ipv6_src . ipv6_dst  timeout 2m }                                   │
│  ├── set authenticated_macs{ ether_addr timeout <idle_timeout>}                              │
│  ├── set authenticated_ips { ipv4_addr timeout <idle_timeout>}                               │
│  ├── set authenticated_ips6{ ipv6_addr timeout <idle_timeout>}                               │
│  ├── TCP :80 LAN SYN    → NFQUEUE_CAPTIVE    (portail captif)                                │
│  ├── TCP :33443          → NFQUEUE_AUTH       (extrait MAC/IP)                               │
│  ├── TCP/UDP :443        → NFQUEUE_SNI    (verdict SNI TLS/QUIC, optionnel)              │
│  ├── SIP/STUN            → NFQUEUE_SIP        (signalisation VoIP, optionnel)                │
│  ├── Reject résiduel     → NFQUEUE_REJECT     (reject, rate-limité)                          │
│  ├── UDP/TCP :53 src=LAN → NFQUEUE_QUESTIONS  (questions)                                    │
│  └── UDP/TCP :53 dst=LAN → NFQUEUE_RESPONSES  (réponses)                                     │
│                                                                                              │
│  LuaJIT (userspace)  BRIDGE_IFNAME=<br>                                                      │
│  ├── main.lua           supervisor + fork                                                    │
│  ├── mac_learner        table IP→MAC (socket Unix)                                           │
│  ├── worker_arp_sniffer ARP/NDP passif → pipe learn (22 B)                                   │
│  ├── worker_questions ── pipe question_response (43 B, rule_id+timeout) ──► worker_responses │
│  │   parse L2/L3/L4/L7      ├─ pipe learn (22 B)   → mac_learner                             │
│  │   rules (conditions+actions)  └─ pipe events    → worker_events                           │
│  │   log + ACCEPT/REFUSED/DNSONLY            verify txid · patch TTL · ─ pipe nft ─► worker_nft │
│  ├── worker_nft         — sérialise les insertions nft + ACK par worker                      │
│  ├── worker_events      — agrège/persiste les événements DNS                                 │
│  ├── worker_auth_queue ─ pipe learn (22 B) ──► mac_learner                                   │
│  ├── worker AUTH       — HTTPS WolfSSL (port 33443) : portail captif + admin /admin/*        │
│  ├── worker_captive    — TCP/80 SYN → AF_PACKET 302                                          │
│  ├── worker_tls        — verdict SNI TLS/QUIC (443, optionnel) ─ pipe nft ─► worker_nft      │
│  ├── worker_sip        — IP médias SDP/proxy SIP (optionnel)   ─ pipe nft ─► worker_nft      │
│  ├── worker_doh        — serveur DoH HTTPS (8443, optionnel)   ─ pipe nft ─► worker_nft      │
│  ├── worker_reject     — forge RST/ICMP admin-prohibited                                     │
│  │                                                                                           │
│  └── logs → syslog (journald / logread)                                                      │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
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

Les sources sont écrites en MoonScript dans `src/` ; `make` les compile en Lua
dans `lua/` (ne jamais éditer `lua/` à la main).

```
custos/
├── cfg/
│   ├── config.moon          Exemple de configuration runtime annotée (MoonScript)
│   └── secrets.sample       Exemple de fichier de mots de passe
├── src/
│   ├── config.moon          Configuration hiérarchique runtime (/etc/custos/config.moon)
│   ├── main.moon            Superviseur : crée les pipes IPC, fork et supervise les workers
│   ├── ffi_defs.moon        Déclarations FFI centralisées
│   ├── ffi_xxhash.moon      FFI xxHash
│   ├── log.moon             Logging structuré key=value + rate-limiting
│   ├── metrics.moon         Métriques de performance par règle (verdicts, cache, TTL)
│   ├── ipc.moon             Protocole pipe question→response (msg 43 octets)
│   ├── dns_ede.moon         Helpers DNS EDE (RFC 8914) — partagés responses + DoH
│   ├── forge_dns.moon       Construction de réponses DNS forgées (vol de question)
│   ├── nft.moon             Injection sets nftables via libnftables
│   ├── nft_add_helper.moon  Helper retry/backoff pour insertions nft
│   ├── nft_rules.moon       Application du ruleset nft + compilation des règles
│   ├── nft_extra_rules.moon Règles nft supplémentaires (UCI)
│   ├── nft_queue.moon       Helpers de configuration des queues NFQUEUE
│   ├── nfq_loop.moon        Boucle générique NFQUEUE
│   ├── bridge_raw.moon      AF_PACKET : injection de frames brutes
│   ├── captive_ips.moon     Détection IPs portail captif
│   ├── ip_whitelist.moon    Gestion whitelist IP statique
│   ├── mac_learner.moon     Table IP→MAC en mémoire + socket Unix
│   ├── mac_learner_ipc.moon Client IPC pour mac_learner
│   ├── mac_prober.moon      Sondage actif ARP/NDP
│   ├── worker_questions.moon    Worker questions DNS
│   ├── worker_responses.moon    Worker réponses DNS (patch TTL/EDE, insertions nft)
│   ├── worker_nft.moon          Worker de sérialisation des insertions nft (pipe nft + ACK)
│   ├── worker_events.moon       Worker d'agrégation/persistance des événements DNS
│   ├── worker_captive.moon      Worker portail captif TCP/80
│   ├── worker_auth_queue.moon   Worker NFQUEUE port 33443 (extrait MAC/IP)
│   ├── worker_auth_pipeline.moon Pipeline d'authentification (parsing requêtes auth)
│   ├── worker_tls.moon          Worker SNI TLS/QUIC (port 443, optionnel)
│   ├── worker_sip.moon          Worker SIP/STUN (médias SDP, optionnel)
│   ├── worker_doh.moon          Worker serveur DoH HTTPS (port 8443, optionnel)
│   ├── worker_reject.moon       Worker forge RST/ICMP admin-prohibited
│   ├── worker_arp_sniffer.moon  Worker sniffer ARP/NDP passif
│   ├── lib/
│   │   ├── http.moon        Helpers HTTP (parsing requêtes/réponses)
│   │   ├── process.moon     Fork, set_process_name, signaux, shutdown
│   │   └── socket.moon      Helpers socket (FFI)
│   ├── nfq/
│   │   └── ethernet.moon    L2 : MAC src via nfq_get_packet_hw
│   ├── doh/
│   │   ├── query.moon       Résolution DoH (RFC 8484)
│   │   └── upstream.moon    Sélection upstream + sonde IPv6
│   ├── sip/
│   │   └── parser.moon      Parser léger SIP/SDP (méthode, CSeq, IP médias)
│   ├── auth/
│   │   ├── worker.moon          Worker AUTH principal
│   │   ├── server.moon          Serveur HTTPS (FFI WolfSSL) + routage /admin/*
│   │   ├── worker_conn.moon     Gestion des connexions HTTPS
│   │   ├── ffi_wolfssl.moon     FFI wrapper WolfSSL (remplace luasec)
│   │   ├── ffi_socket.moon      FFI sockets bas niveau
│   │   ├── cert.moon            Gestion certificats TLS (load_or_generate_sni)
│   │   ├── cert_generator.moon  Génération dynamique via px5g
│   │   ├── cert_cache.moon      Cache LRU/TTL pour certificats
│   │   ├── cert_parser.moon     Lecture des métadonnées de certificat
│   │   ├── sni_extractor.moon   Parser SNI (TLS ClientHello)
│   │   ├── sessions.moon        Lecture/écriture sessions.lua (MAC-primary)
│   │   ├── user_sessions.moon   Sessions par utilisateur authentifié
│   │   ├── nft_sessions.moon    Gestion sets nft pour sessions
│   │   ├── credentials.moon     Vérification PBKDF2-SHA256
│   │   ├── token.moon           Jetons de session signés (cookies)
│   │   ├── rule_user.moon       Résolution règle ↔ utilisateur
│   │   ├── html.moon            Templates HTML du portail
│   │   └── pages.moon           Pages du portail (login, succès…)
│   ├── filter/
│   │   ├── init.moon        Moteur de filtrage (load/decide/reload)
│   │   ├── rule.moon        Évaluateur de règles (conditions + actions)
│   │   ├── rule_id.moon     Identifiants stables de règles
│   │   ├── convert.moon     Convertisseurs config → types moteur
│   │   ├── updater.moon     CLI : téléchargement + compilation listes de domaines
│   │   ├── compiler_api.moon    Chargeur de conditions (auto-génération des variantes)
│   │   ├── nft_compiler.moon    Compilation des règles en expressions nft
│   │   ├── nft_dynamic_sets.moon Gestion des sets nft dynamiques
│   │   ├── localnets.moon   Détection des réseaux locaux (allow_localnets)
│   │   ├── actions/
│   │   │   ├── allow.moon     Autorise (injecte les IPs dans les sets nft)
│   │   │   ├── deny.moon      Répond REFUSED + EDE
│   │   │   ├── dnsonly.moon   DNS autorisé sans injection nft (sondes captives)
│   │   │   ├── nxdomain.moon  Répond NXDOMAIN (ex. désactivation DoH Firefox)
│   │   │   ├── cname.moon      Réécrit la réponse en CNAME vers une cible (SafeSearch)
│   │   │   ├── dns_strip.moon Retire des enregistrements de la réponse (ex. HTTPS/SVCB)
│   │   │   ├── log.moon       Journalise sans rendre de verdict
│   │   │   └── mail.moon      Notification par courriel
│   │   ├── conditions/
│   │   │   ├── from_net.moon    IP source (CIDR)
│   │   │   ├── from_subnet.moon IP source via sous-réseau config
│   │   │   ├── from_mac.moon    Adresse MAC source
│   │   │   ├── from_vlan.moon   VLAN source
│   │   │   ├── from_user.moon   Session authentifiée
│   │   │   ├── to_net.moon      IP destination (CIDR)
│   │   │   ├── to_domain.moon / to_domains.moon / to_domainlist.moon / to_domainlists.moon
│   │   │   ├── in_time.moon     Fenêtre horaire
│   │   │   ├── any_of.moon      Méta-condition OR
│   │   │   ├── not.moon         Méta-condition NOT
│   │   │   └── stolen_computer.moon  Détection d'appareil volé
│   │   │   (les variantes from_xxxs / from_xxx_list / from_xxx_lists sont
│   │   │    auto-générées à partir de from_xxx par compiler_api)
│   │   └── lib/
│   │       ├── bsearch.moon       Recherche binaire dans les listes binaires
│   │       ├── cidr_parser.moon   Parsing CIDR
│   │       ├── ipcalc.moon        Test d'appartenance CIDR
│   │       ├── load_config.moon   Chargeur de config
│   │       └── parse_domains.moon Parser multi-format de listes de domaines
│   ├── webui/
│   │   ├── router.moon      Dispatch des requêtes /admin/* vers les handlers
│   │   ├── serializer.moon  Lecture/écriture de config.moon (round-trip MoonScript)
│   │   ├── css.moon         Feuille de style de l'interface admin
│   │   ├── handlers/        dashboard, system, config, filter, rules, lists, admin_auth
│   │   └── schema/          config_schema, registry (validation des sections)
│   └── ipparse/             Bibliothèque parsing L2/L3/L4/L7 (sous-module)
├── sync/
│   ├── apply.moon           Fusion base + device → /etc/custos/config.moon
│   ├── custos-sync.sh       Synchronisation pull depuis un dépôt git central
│   └── custos-sync-push.sh  Publication push vers le dépôt central
├── .init.moon               UI redbean d'installation (empaquetée par make redbean-ui)
├── lua/                     Lua généré par moonc (ne pas éditer)
├── nft-rules/
│   └── dns-filter-bridge.nft       Ruleset nftables (bridge mode)
├── packaging/openwrt/custos/        Paquet OpenWrt (init script, custos-update, UCI)
├── libvirt/                 Homelab libvirt (3 VMs OpenWrt) pour tests E2E
├── tests/
│   ├── unit/**/*_spec.moon  Tests unitaires Busted (compilés par make test)
│   ├── helpers/             mini_busted, busted_setup
│   ├── e2e/                 Tests d'intégration nft + E2E
│   └── run_tests.moon       Runner local
├── doc/                     CONFIG.md (référence config), CHEATSHEET.md
├── .agents/                 Documentation détaillée pour agents/contributeurs
├── install-owrt.moon        Installeur OpenWrt (déploiement SSH)
├── LICENSE                  Licence MIT
├── Makefile
└── README.md
```

---

## Prerequisites

### OpenWrt Packages

| Package              | Role                                    |
|----------------------|-----------------------------------------|
| `luajit`             | Compiled Lua execution                  |
| `lpeg`               | Requis par MoonScript pour lire `config.moon` au runtime |
| `libnetfilter-queue` | NFQUEUE C library                       |
| `nftables`           | `nft` tool + libnftables (injection des sets) |
| `kmod-nft-queue`     | Module noyau NFQUEUE                     |
| `kmod-nft-bridge`    | Module noyau nftables en mode bridge    |
| `libxxhash`          | Hash xxHash (FFI, format `.bin`)        |
| `libwolfssl`         | TLS/SSL library (via FFI, `ffi_wolfssl`)|
| `px5g-wolfssl`       | Dynamic TLS certificate generation      |

```bash
opkg install luajit lpeg libnetfilter-queue nftables \
  kmod-nft-queue kmod-nft-bridge libxxhash libwolfssl px5g-wolfssl
```

> MoonScript est embarqué dans le dépôt (`src/lib/moonscript`) et déployé tel
> quel ; aucun paquet `moonscript` distant n'est requis. Pour compiler localement
> (`make`), il faut `moonc` + `luajit` (ou utiliser les `.lua` déjà générés).

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
2. Déploie les fichiers Lua + ruleset dans `/usr/share/custos/` (configurable via `--dest`)
3. Installe la config dans `/etc/custos/`, le service `/etc/init.d/custos` et `custos-update` (+ cron)
4. Démarre le service

---

## Configuration

### Configuration runtime (`config.moon`)

La configuration runtime principale est `/etc/custos/config.moon` (surcharge partielle des
défauts de `src/config.moon`). Elle est au format **MoonScript** et couvre :
- `runtime`, `nfqueue` (dont `sni`, `sip`), `nft`, `dns`, `ipc`, `clients`, `mac_learner`
- `auth` (port 33443, sessions, admin)
- `sni` (verdict SNI 443 : inspection TLS/QUIC, placement nft, policy d'échec)
- `doh` (serveur DoH HTTPS, port 8443, upstream)
- `events` (persistance des événements), `metrics` (mesures par règle), `rtp` (ports RTP exclus)
- le moteur de filtrage (`filter.rules`, `filter.nets`, `filter.macs`, `filter.times`,
  `filter.vlans`, `filter.users`)
- les décisions de parcours de règles (`filter.decision.first_match_wins`,
  `filter.decision.continue_to_next_rule`)
- `dns.ttl_grace` (`grace`, `min`, `max`) — timeout nft = `TTL + grace`, borné
- whitelist de destinations IP (`filter.dest_whitelist`)
- `lists_dir` — répertoire racine des listes de conditions (voir ci-dessous)

La **référence exhaustive** de toutes les clés est dans [`doc/CONFIG.md`](doc/CONFIG.md).

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

## Listes de conditions (`lists_dir`)

Il existe deux systèmes de listes distincts selon le type de condition :

| Système | Conditions | Format | Évaluation |
|---------|-----------|--------|------------|
| `domainlists_dir` + `custos-update` | `to_domainlist`, `to_domainlists` | binaire (xxhash64 triés) | O(log n) FFI userspace |
| `lists_dir` (plain text) | `from_xxx_list`, `from_xxx_lists` | texte (1 item/ligne) | kernel nft (interval tree / hash) |

Les listes de domaines peuvent contenir des millions d'entrées et passent obligatoirement
par `custos-update` pour être compilées en format binaire optimisé.

Les autres types de listes (réseaux, MACs, VLANs…) sont lus depuis des fichiers texte au
démarrage, puis compilés en expressions nft d'ensemble inline (`ip saddr { cidr1, cidr2 }`)
évaluées côté kernel. Nftables optimise ces ensembles via interval trees (CIDRs) ou hash
maps (MACs, VLANs). Les listes d'utilisateurs restent worker-only (les sessions sont
dynamiques et ne peuvent pas être exprimées en nft statique).

Les variantes `from_xxx_list` et `from_xxx_lists` lisent des fichiers texte organisés
par type dans un répertoire configurable :

```moonscript
filter:
  lists_dir: "/etc/custos/lists"   -- défaut : /etc/custos/lists
```

### Convention de nommage

| Condition | Argument | Fichier lu |
|-----------|----------|------------|
| `from_net_list "lan"` | nom de liste | `{lists_dir}/net/lan.txt` |
| `from_net_lists {"lan","dmz"}` | liste de noms | plusieurs fichiers |
| `from_mac_list "trusted"` | nom de liste | `{lists_dir}/mac/trusted.txt` |
| `from_user_list "admins"` | nom de liste | `{lists_dir}/user/admins.txt` |
| `from_vlan_list "corp"` | nom de liste | `{lists_dir}/vlan/corp.txt` |
| `from_in_time_list "biz"` | nom de liste | `{lists_dir}/in_time/biz.txt` |

Format des fichiers : 1 item valide par ligne, lignes vides et `#commentaires` ignorés.

### Auto-génération des variantes

Le chargeur `compiler_api` génère automatiquement les variantes à partir de la
condition atomique `from_xxx` :

- `from_xxxs {"a","b"}` — OR sur une table Lua (pas de fichier)
- `from_xxx_list "nom"` — lit `{lists_dir}/{xxx}/{nom}.txt`
- `from_xxx_lists {"n1","n2"}` — OR sur plusieurs fichiers

Il suffit de définir `from_xxx.moon` ; les trois variantes sont disponibles sans
fichier supplémentaire. Tout nouveau type de condition (ex. `from_mytype.moon`)
hérite automatiquement de `from_mytype_list` et `from_mytype_lists`.

### `requires_auth` dans les capabilities

Une condition peut déclarer `capabilities.requires_auth = true` pour indiquer
au compilateur nft qu'elle nécessite des sous-chaînes d'authentification.
`from_user.moon` le fait nativement ; tout nouveau type d'auth suit la même
convention sans modifier `nft_compiler`.

---

## Domain List Updater

`src/filter/updater.moon` est un outil CLI qui télécharge, parse et compile
des listes de domaines au format binaire optimisé pour la recherche binaire.

```bash
# Télécharger et compiler toutes les listes définies dans config.moon
LUA_PATH="lua/?.lua;lua/?/init.lua;;" luajit lua/filter/updater.lua

# Avec un fichier de configuration alternatif :
LUA_PATH="lua/?.lua;lua/?/init.lua;;" luajit lua/filter/updater.lua --config /path/to/config.moon

# Sur OpenWrt (après installation) :
custos-update
```

### Sources

Chaque entrée `filter.sources` dans `config.moon` peut être :

```moonscript
filter:
  sources:
    toulouse: {
      url: "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"
      format: "toulouse"          -- archive tar.gz multi-catégories
      subdir: "toulouse"          -- sous-dossier de domainlists_dir
    }

    ma_liste: {
      file: "/etc/custos/lists/custom/ma-liste.txt"
      format: "simple"            -- un domaine par ligne
      output: "/etc/custos/lists/custom/ma-liste.bin"
    }
```

### Listes personnalisées

Positionner `filter.custom_lists_dir` dans `config.moon` pour activer le scan
automatique de fichiers `.txt` :

```moonscript
filter:
  domainlists_dir: "/etc/custos/lists"
  custom_lists_dir: "/etc/custos/lists/custom"
```

Chaque fichier `custom/*.txt` (un domaine par ligne, `#` pour les commentaires)
est converti en `custom/*.bin`. Les originaux sont conservés.

Les listes sont référençables dans les règles :

```moonscript
conditions:
  { to_domainlist: "custom/ma-liste" }
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

### Pipe `learn` (22 octets)

The `learn` pipe carries MAC/IP associations, written by `worker_questions`,
`worker_arp_sniffer` and `worker_auth_queue`, and read by `mac_learner`.

```
Bytes 0-15 : IP address — 16 bytes
               IPv4 : 4 bytes address + 12 zero bytes (left-padded)
               IPv6 : 16 bytes address (complete)
Bytes 16-21: source MAC (6 bytes)
```

### Pipes `events`, `nft` et `ack_<i>`

Three further pipes, all created in `main.moon` before `fork()`:

- **`events`** : DNS events from `worker_questions` → `worker_events` (aggregation/persistence).
- **`nft`** : serialized nftables insertion commands from `worker_responses`,
  `worker_tls`, `worker_sip` and `worker_doh` → `worker_nft`.
- **`ack_<i>`** : one per producer worker; `worker_nft` writes a 1-byte ACK after
  each batch flush so the producer can return its verdict once the set element is live.

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

The `AUTH` worker is forked by the supervisor alongside the DNS workers,
the captive portal worker, and several auxiliary workers:

```
main (supervisor)
├── mac_learner          (table IP→MAC, socket Unix)
├── worker_arp_sniffer   (ARP/NDP passif → pipe learn)
├── worker_auth_queue    (NFQUEUE port 33443 → pipe learn)
├── worker_events        (agrégation des événements DNS)
├── worker_questions ×N (DNS questions → pipes question_response/learn/events)
├── worker_responses ×N (DNS réponses → pipe nft)
├── worker_nft           (sérialise les insertions nft + ACK par worker)
├── worker_captive   ×N (TCP/80 SYN → AF_PACKET 302)
├── worker_reject    ×N (forge RST/ICMP)
├── worker_tls           (SNI TLS/QUIC 443, optionnel → pipe nft)
├── worker_sip           (SIP/STUN, optionnel → pipe nft)
├── worker_doh           (serveur DoH HTTPS 8443, optionnel → pipe nft)
└── worker AUTH          (HTTPS WolfSSL, port 33443 : portail captif + admin /admin/*)
```

Sessions are shared via a Lua-evaluable file (`/tmp/sessions.lua`). question/response workers
reload it every 5 seconds (TTL cache). No inter-process socket is needed.

### TLS certificate

The AUTH worker generates **self-signed certificates dynamically** via `px5g`
(WolfSSL-based) with an LRU/TTL cache (100 slots, 24h). Certificates are
generated on-demand based on the SNI (Server Name Indication) from the
TLS ClientHello.

To use your own static certificate, configure `auth.cert` and `auth.key` in
`/etc/custos/config.moon`:

```moonscript
auth:
  cert: "/etc/custos/auth.crt"
  key:  "/etc/custos/auth.key"
  secrets: "/etc/custos/secrets"
  session_ttl: 0            -- seconds (default: 0 = no absolute expiry)
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

Navigate to `https://<router>:33443/` in a browser (accept the self-signed cert
warning). After a successful login the client **MAC address** is recorded in the session
store as the primary identifier. This MAC-primary architecture allows seamless
cross-family tracking (IPv4/IPv6) and handles IP changes gracefully.
Sessions expire after `idle_timeout` seconds without heartbeat, or on explicit logout. `session_ttl` is optional; `0` disables absolute expiry.

### Using `from_user` in rules

```moonscript
filter:
  rules:
    {
      description: "alice-only"
      conditions:
        { from_user: "alice" }
        { to_domains: {"github.com", "pypi.org"} }
      actions: {"allow"}
    }
```

Multiple users can be listed (logical OR):

```moonscript
      conditions:
        { from_users: {"alice", "bob"} }
```

Users from a text file (`lists_dir/user/admins.txt`, one username per line):

```moonscript
      conditions:
        { from_user_list: "admins" }
```

Multiple files (OR):

```moonscript
      conditions:
        { from_user_lists: {"admins", "vip"} }
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

```moonscript
{
  description: "Sondes portail captif"
  actions: {"dnsonly"}
  conditions:
    { to_domains: {
      "connectivitycheck.gstatic.com"
      "captive.apple.com"
      "msftconnecttest.com"
    } }
}
```

#### Sondes intégrées par défaut (NCSI/MSFT, Apple, Google…)

Les **règles par défaut** (`filter.default_rules`, cf. `src/config.moon`)
embarquent déjà l'ensemble canonique des sondes de connectivité **en ligne**
(via `to_domains`), donc fonctionnelles dès l'installation, sans dépendre d'une
liste externe :

- Google/Android : `connectivitycheck.gstatic.com`, `connectivitycheck.android.com`,
  `connectivitycheck.google.com`, `clients3.google.com`
- Apple : `captive.apple.com`
- **Microsoft NCSI** : `msftconnecttest.com`, `msftncsi.com`
- Firefox : `detectportal.firefox.com` — Ubuntu : `connectivity-check.ubuntu.com`
  — KDE : `networkcheck.kde.org`

Le **match par suffixe** couvre tous les sous-domaines : `msftncsi.com` couvre la
sonde DNS `dns.msftncsi.com` (NCSI vérifie qu'elle résout vers `131.107.255.255` ;
`dnsonly` laisse la réponse upstream intacte) et la sonde HTTP héritée
`www.msftncsi.com` ; `msftconnecttest.com` couvre `www.` et `ipv6.msftconnecttest.com`
(sonde HTTP active Windows 10/11).

Deux règles par défaut encadrent ces domaines : `allow` pour les utilisateurs
**authentifiés** (`from_user: "_any"`, ouverture pare-feu → la sonde réussit,
pas de portail) et `dnsonly` pour les autres (résolution DNS seule → la sonde
HTTP est interceptée par le worker captive et redirigée vers le portail).

Ces deux règles sont gouvernées par l'option `filter.captive_portal` (défaut
`true`). La passer à `false` les retire (le canari DoH Firefox reste actif) :

```moonscript
filter: { captive_portal: false }
```

### SafeSearch (réécriture CNAME)

L'option `filter.safe_search` (défaut `true`) ajoute des règles par défaut qui
**réécrivent la réponse DNS** des moteurs de recherche vers leur variante « safe »
via l'action générique `cname` : Google → `forcesafesearch.google.com`, YouTube →
`restrictmoderate.youtube.com` (ou `restrict.youtube.com`), Bing → `strict.bing.com`,
DuckDuckGo → `safe.duckduckgo.com`. Le filtre répond par un CNAME ; le client
re-résout la cible. Le mécanisme passe par le callback `on_response` (worker
responses **et** worker doh) : il couvre le DNS clair **UDP et TCP** ainsi que le
**DoH transitant par le worker doh**. Mode YouTube réglable
(`filter.youtube_restrict`: `"strict"`/`"moderate"`/`false`).

```moonscript
filter: { safe_search: false }          -- désactiver
filter: { youtube_restrict: "strict" }  -- YouTube en mode strict
```

L'action `cname` étant générique, elle s'utilise aussi dans `filter.rules` pour
réécrire un domaine arbitraire :
`{ actions: {"cname"}, conditions: { to_domain: "exemple.fr" }, cname: "cible.exemple.fr" }`.

### Conditions utilisateur

`from_user`, `from_users`, `from_user_list`, `from_user_lists` permettent
d'associer des règles à des comptes authentifiés :

```moonscript
{
  description: "alice-only"
  conditions:
    { from_user: "alice" }
    { to_domainlist: "toulouse/adult" }
  actions: {"allow"}
}
```

Plusieurs utilisateurs (OR logique) :

```moonscript
  conditions:
    { from_users: {"alice", "bob"} }
```

Depuis un fichier texte (`{lists_dir}/user/admins.txt`) :

```moonscript
  conditions:
    { from_user_list: "admins" }
```

---

## Known Limitations

- **DoH (DNS-over-HTTPS)**: partially covered. CustosVirginum can run its own DoH
  resolver (`worker_doh`, port 8443) and apply the same filtering policy; it also
  ships a default rule answering NXDOMAIN to Firefox's canary domain to disable its
  auto-DoH. Arbitrary third-party DoH endpoints over port 443 are constrained via
  the **SNI verdict** mechanism (`worker_tls`, `cfg.sni`) rather than DNS.
- **DoT (DNS-over-TLS, port 853)**: not covered.
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
- TCP/UDP/443 → **NFQUEUE_SNI** (`worker_tls`, optional)
- SIP/STUN → **NFQUEUE_SIP** (`worker_sip`, optional)
- Rate-limited reject traffic → **NFQUEUE_REJECT** (`worker_reject`)
- Queue numbers are **configurable** (config section `nfqueue`, or UCI:
  `QUEUE_QUESTIONS`, `QUEUE_RESPONSES`, `QUEUE_CAPTIVE`, `QUEUE_AUTH`,
  `QUEUE_SNI`, `QUEUE_SIP`, `QUEUE_REJECT`). Defaults: questions `0-1`,
  responses `4`, captive `20`, reject `10-11`, auth `5`, sni `6`, sip `12`.
  Ranges like `"0,2,5-7"` spawn one worker per queue number.
- LuaJIT decides ACCEPT, REFUSED, or DNSONLY; populates `ip4_allowed`/`ip6_allowed` on success
- Clients in `authenticated_ips` bypass TCP/80 interception (QUEUE_CAPTIVE)
- All forwarded traffic matching a set entry → ACCEPT; rest → DROP/REJECT

### Sets nftables

| Set                   | Type                    | Rôle                                                                    |    
|-----------------------|-------------------------|-------------------------------------------------------------------------|    
| `ip4_allowed`         | `ipv4_addr . ipv4_addr` | Paire (src IP client, IPv4 dest) autorisée après résolution DNS         |  
| `ip6_allowed`         | `ipv6_addr . ipv6_addr` | Paire (src IPv6 client, IPv6 dest) autorisée après résolution DNS       |
| `mac4_allowed`        | `ether_addr . ipv4_addr`| Paire (MAC client, IPv4 dest) autorisée (règles liées à une MAC)        |
| `mac6_allowed`        | `ether_addr . ipv6_addr`| Paire (MAC client, IPv6 dest) autorisée (règles liées à une MAC)        |
| `authenticated_macs`  | `ether_addr`            | MACs clientes authentifiées (bypass intercept TCP/80 captive)           |  
| `authenticated_ips`   | `ipv4_addr`             | IPs clientes IPv4 authentifiées (bypass intercept TCP/80 captive)       |
| `authenticated_ips6`  | `ipv6_addr`             | IPs clientes IPv6 authentifiées (bypass intercept TCP/80 captive)       |
| `ip4_dest_whitelist`  | `ipv4_addr`             | Destinations IPv4 toujours autorisées (bypass DNS, rechargement SIGHUP) |
| `ip6_dest_whitelist`  | `ipv6_addr`             | Destinations IPv6 toujours autorisées (bypass DNS, rechargement SIGHUP) |

### Prerequisites

Sur OpenWrt, les règles nft sont appliquées automatiquement par le service au démarrage. Pour appliquer manuellement :

```bash
nft -f nft-rules/dns-filter-bridge.nft
```

### DHCP / SLAAC

The ruleset explicitly passes bootstrap traffic that cannot be tracked by
conntrack and must therefore bypass the `policy drop`:

| Traffic                                           | Direction | Rule                                  | 
|---------------------------------------------------|-----------|---------------------------------------| 
| DHCPv4 (UDP 67/68)                                | FORWARD   | `udp dport { 67, 68 } accept`         |  
| DHCPv4 server on filter machine                   | INPUT     | `udp dport 67 accept`                 |  
| DHCPv6 (UDP 546/547)                              | FORWARD   | `udp dport { 546, 547 } accept`       |  
| DHCPv6 server on filter machine                   | INPUT     | `udp dport 547 accept`                |  
| SLAAC Router Advertisement from upstream router   | FORWARD   | `icmpv6 type nd-router-advert accept` |

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

The whitelist can also be configured in `/etc/custos/config.moon`:

```moonscript
filter:
  dest_whitelist: {
    "10.0.0.0/24"
    "2001:db8::/32"
  }
```

---

## Interface d'administration web

Le worker AUTH sert une interface d'administration sous `/admin/*` sur le même
port HTTPS que le portail captif (33443). L'accès est protégé par une session
authentifiée **et** restreint aux comptes listés dans `auth.admin_users`
(si la liste est vide, `auth.admin_allow_all_when_empty` autorise tout
utilisateur authentifié).

L'interface permet, sans CLI :
- d'éditer les sections de `config.moon` (relues/réécrites via `webui/serializer`) ;
- de gérer les règles de filtrage (ajout, édition, suppression, réordonnancement) ;
- de gérer les dictionnaires nommés (`nets`, `macs`, `users`, `times`) et les listes ;
- de consulter le tableau de bord (statut, événements) et de déclencher un reload (SIGHUP).

```
https://<router>:33443/admin/
```

---

## DoH (serveur DNS-over-HTTPS intégré)

`worker_doh` peut exposer un résolveur **DoH** (RFC 8484) en HTTPS sur le port
`doh.port` (défaut 8443). Les requêtes sont résolues auprès d'un upstream DNS
(`doh.upstream_ipv4` / `doh.upstream_ipv6`, choix selon `doh.prefer_ipv6`), puis
passent par le **même moteur de filtrage** que les requêtes DNS classiques :
les paires autorisées sont injectées dans les sets nft.

```moonscript
doh:
  enabled: true
  port: 8443
  upstream_ipv4: "1.1.1.3"
  upstream_ipv6: "2606:4700:4700::1113"
  prefer_ipv6: true
  -- cert/key optionnels (sinon certificat px5g dynamique)
```

Une règle par défaut répond `NXDOMAIN` au domaine canari de Firefox
(`use-application-dns.net`) pour désactiver son auto-DoH et forcer le passage par
le résolveur filtré.

---

## Filtrage SNI (TLS / QUIC)

`worker_tls` (optionnel, `nfqueue.sni`) intercepte les paquets TCP/443
(ClientHello TLS) et UDP/443 (QUIC Initial), extrait le **SNI** via `ipparse`,
puis applique `filter.decide` sur le nom extrait. En mode
`sni.mode = "strict-443"` :
- **allow** → la paire client→destination est ajoutée aux sets nft ;
- **deny / SNI absent** → le paquet est rejeté (`NF_DROP`).

```moonscript
sni: {
  enabled: true
  mode: "strict-443"     -- ou "permissive" pour journaliser sans bloquer
  protocols: "both"       -- "tls" | "quic" | "both"
  nft_failure_policy: "fail-closed"
}
```

Cela complète le filtrage DNS pour les clients qui contournent la résolution
(IP en dur, DoH tiers).

---

## SIP / VoIP

`worker_sip` (optionnel, `nfqueue.sip`) parse la signalisation SIP/SDP et
STUN/ICE (`src/sip/parser.moon`), extrait les IP de médias (RTP/RTCP) et l'IP
du proxy, puis les whiteliste dynamiquement dans des sets nft par règle
(TTL `nft.sip_session_ttl`). Les ports RTP à exclure sont configurables via
`rtp.excluded_ports`.

---

## Synchronisation de configuration multi-routeurs

Pour gérer plusieurs filtres depuis un dépôt git central :

```bash
# Sur la machine de dev : initialiser un device en mode pull (cron */15)
make sync-init HOST=root@<router> REPO=https://git.example.com/custos-configs

# Initialiser un filtre de référence autorisé à publier (push)
make sync-push-init HOST=root@<router> REPO=https://git.example.com/custos-configs
```

`sync/apply.moon` fusionne `base/config.moon` avec
`devices/<hostname>/config.moon` du dépôt et écrit `/etc/custos/config.moon`
(option `--reload` pour envoyer SIGHUP). `custos-sync.sh` (pull) et
`custos-sync-push.sh` (push) lisent `CUSTOS_CONFIG_REPO` depuis
`/etc/custos/sync.conf`.

Une **UI redbean** locale (`.init.moon`, `make redbean-ui`) permet aussi
d'installer, désinstaller et synchroniser un routeur sans CLI ; voir
[`doc/CHEATSHEET.md`](doc/CHEATSHEET.md) § « UI d'installation (redbean) ».

---


[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/jperon/custos)
