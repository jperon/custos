# CustosVirginum - CHEATSHEET

Quick reference for maintainers/contributors.
Detailed explanations and architecture remain in `README.md`.
Configuration reference: [`doc/CONFIG.md`](CONFIG.md).

## Quick entry

- Supervision: `src/main.moon`
- DNS workers: `src/worker_questions.moon` (questions), `src/worker_responses.moon` (responses)
- IPC question -> response: `src/ipc.moon`
- nftables ruleset: `nft-rules/dns-filter-bridge.nft`
- NFT extra rules (via UCI): `custos.main.nft_extra_rules` can hold one fragment per entry. Each fragment is a nft expression (without the `insert rule <table> <chain> ...` prefix) and will be inserted at the head of the `forward` chain at service startup and removed at shutdown. Example UCI fragment:
  - `nft_extra_rules='ip saddr 10.0.0.0/8 counter log prefix "extra: " accept'`
- Filtering rules: `cfg/config.moon`

## Where to modify what

- Business rules:
  - `cfg/config.moon`
  - `src/filter/init.moon`
  - `src/filter/rule.moon`
  - `src/filter/convert.moon`

- Add a condition:
  - Add `src/filter/conditions/<name>.moon`
  - Loaded via `require("filter.conditions.<name>")` in `src/filter/rule.moon`

- Add an action:
  - Add `src/filter/actions/<name>.moon`
  - Loaded via `require("filter.actions.<name>")` in `src/filter/rule.moon`

- SafeSearch / réécriture CNAME:
  - Options: `filter.safe_search` (défaut `true`), `filter.youtube_restrict` (`strict`/`moderate`/`false`)
  - Action générique `cname` (`src/filter/actions/cname.moon`) → `on_response` réécrit la réponse en CNAME
  - Mapping moteurs: `SAFE_SEARCH_GROUPS` dans `src/config.moon` (généré dans `normalize`)
  - Couvre DNS clair UDP+TCP (`replace_dns_payload`) et DoH (`doh/query.moon`)

- DNS logic (decision, correlation, reinjection):
  - question: `src/worker_questions.moon`
  - IPC: `src/ipc.moon`
  - response: `src/worker_responses.moon`
  - NFQUEUE loop: `src/nfq_loop.moon`
  - `rule_id` + `timeout` transitent de question → response → nft

- REFUSED, EDE, TTL:
  - EDE helpers (RFC 8914): `src/dns_ede.moon` (partagé worker_responses + doh)
  - Forge de réponses (vol de question / captif): `src/forge_dns.moon`
  - TTL + grace: `dns.ttl_grace` in `src/config.moon`
  - EDE code 4 n'est ajouté que si la réponse a réellement été modifiée

- nft injection (sets):
  - Commandes nft bas niveau: `src/nft.moon`, `src/filter/nft_dynamic_sets.moon`
  - Sérialisation des insertions: `src/worker_nft.moon` (pipe `nft` + ACK)
  - Conditions d'injection A/AAAA/dnsonly: `src/worker_responses.moon`
  - Noms de sets / timeouts: section `nft` de `src/config.moon`

- Authentication / captive portal / admin web:
  - Auth worker: `src/auth/worker.moon`
  - Auth server (HTTPS WolfSSL + routes `/admin/*`): `src/auth/server.moon`
  - Interface admin: `src/webui/router.moon` + `src/webui/handlers/`
  - Worker captive (TCP/80 intercept): `src/worker_captive.moon`
  - Sessions (MAC-primary): `src/auth/sessions.moon`
  - Auth nft integration: `src/auth/nft_sessions.moon`
  - Secrets/hash: `src/auth/credentials.moon`
  - TLS (FFI WolfSSL, certs px5g): `src/auth/ffi_wolfssl.moon`, `cert*.moon`

- Parsing:
  - L2 (MAC depuis métadonnées NFQUEUE): `src/nfq/ethernet.moon`
  - L3–L7 (IP/TCP/UDP/DNS/TLS/QUIC): bibliothèque `src/ipparse/`

## Useful contracts

- Compiled condition: `(req) -> ok, reason`
- Compiled action: `(req) -> verdict|nil, message`
- response pending key: `txid:ip:port:resolver_ip`
- Workers (cf. `src/main.moon`) :
  - `mac_learner`, `arp_sniffer`, `auth_queue` (apprentissage MAC)
  - `questions` / `responses` (DNS), `nft` (sérialise les insertions), `events` (agrégation)
  - `captive` (TCP/80), `reject` (RST/ICMP)
  - `auth` (HTTPS WolfSSL + admin)
  - optionnels : `tls` (SNI 443), `sip` (SIP/STUN), `doh` (DoH 8443)
- SIGHUP :
  - `main` relit `filter.load!` puis re-fork les workers questions/responses/captive/reject/doh (COW), et propage SIGHUP à AUTH (reload secrets)
- Active nft sets: `ip4_allowed`, `ip6_allowed`, `mac4_allowed`, `mac6_allowed`,
  `authenticated_macs`, `authenticated_ips`, `authenticated_ips6`,
  `ip4_dest_whitelist`, `ip6_dest_whitelist`
  - Le timeout des éléments injectés suit `TTL + grace` borné (`dns.ttl_grace`)

## Build, run, debug

- Build: `make`
- Run (root): `sudo make run`
- Reload config: `make reload`
- Update lists: `make update-lists`
- Logs: `make logs`

## Domainlists / Customlists

- Config source:
  - Main file: `cfg/config.moon` (or `/etc/custos/config.moon` on OpenWrt)
  - Useful fields: `filter.sources`, `filter.domainlists_dir`, `filter.custom_lists_dir`

- Update lists (Debian/dev machine):
  - `make update-lists`
  - Direct equivalent:
    - `LUA_PATH="lua/?.lua;lua/?/init.lua;;" luajit lua/filter/updater.lua --config cfg/config.moon`

- Update lists (OpenWrt):
  - `ssh root@<router> 'custos-update'`
  - The script uses `/etc/custos/config.moon` and reloads compiled lists.

- Custom lists (workflow):
  1. Drop `.txt` files in `custom_lists_dir` (1 domain per line, `#` for comments).
  2. Run update (`make update-lists` or `custos-update`).
  3. Reload service if needed:
     - Debian: `make reload`
     - OpenWrt: `ssh root@<router> '/etc/init.d/custos reload'`

## UI d'installation (redbean)

Interface web locale pour déployer Custos sur un routeur sans CLI.

- **Prérequis** : `redbean.com` présent à la racine (télécharger depuis https://redbean.dev/)
- **Empaqueter** : `make redbean-ui` (compile `.init.moon` → `.init.lua` + zip dans `redbean.com`)
- **Lancer** : `./redbean.com` puis ouvrir `http://localhost:8080/`
- **Source** : `.init.moon` à la racine (compilé en `.init.lua` par `make`)

Routes disponibles :

| Route | Action |
|-------|--------|
| `GET /` | Page d'accueil avec liens de navigation |
| `GET /install` | Formulaire d'installation (hôte, port, user, dest, flags) |
| `POST /install` | `luajit install-owrt.lua HOST --port P --user U --dest D [flags]` |
| `GET /uninstall` | Formulaire de désinstallation |
| `POST /uninstall` | `luajit install-owrt.lua HOST --port P --user U --uninstall` |
| `GET /sync` | Formulaire sync (radio pull / push) |
| `POST /sync` | `make sync-init HOST=… REPO=…` ou `make sync-push-init HOST=… REPO=…` |

Notes :
- Les entrées (hôte, user, dest, repo, port) sont sanitisées avant interpolation dans les commandes shell.
- La sortie des commandes est échappée HTML avant affichage.
- Un spinner JS masque l'écran pendant l'exécution (opérations synchrones).

## Tests (quick selection)

- Unit: `make test`
- OpenWrt E2E: `make test-openwrt HOST=root@<router>`

## Quick playbooks

- Add a condition:
  1. Create `src/filter/conditions/<name>.moon` (factory -> predicate `(req) -> ok, reason`).
  2. Reference the condition in `cfg/config.moon`.
  3. `make && make test`.

- Add an action:
  1. Create `src/filter/actions/<name>.moon` (`(req) -> verdict|nil, message`).
  2. Call it via `actions:` in `cfg/config.moon`.
  3. Verify action order (first non-nil verdict wins).
  4. `filter.decision.first_match_wins` contrôle si la première ou la dernière règle gagnante est conservée.

- Modify REFUSED/EDE behavior:
  1. Adjust `src/dns_ede.moon` (EDNS/EDE options) and/or `src/forge_dns.moon` (forge).
  2. Verify call in `src/worker_responses.moon` (`refused` branch).
  3. Test at minimum `make test` then an E2E (`test-openwrt`).

- Modify nft injection:
  1. Adjust `src/nft.moon` / `src/filter/nft_dynamic_sets.moon` (`add element`).
  2. Adjust A/AAAA/dnsonly logic in `src/worker_responses.moon` (insertions via pipe `nft` → `src/worker_nft.moon`).
  3. Verify sets via `nft list set ...`.

- Debug IPC question/response correlation:
  1. Verify format/key in `src/ipc.moon` (key `txid:ip:port`).
  2. Watch logs `response_no_matching_question` (response).
  3. Confirm question sends `write_msg`/`write_refused_msg`/`write_dnsonly_msg`.

## Ops Debian/OpenWrt

### Network interfaces (bridge/LAN/WAN)

- The ruleset `nft-rules/dns-filter-bridge.nft` is generic:
  - no interface names imposed (`eth0`, `br-lan`, etc. not hardcoded),
  - filtering based on families/protocols/sets, not interface names.
- The filter machine must be on the LAN <-> WAN path, as transparent bridge.

### Debian: installation, update, uninstall

- Installation:
  1. Install dependencies (see `README.md`), then `make`.
  2. Apply environment + rules: `sudo ./setup.sh up`.
  3. Run service in foreground: `sudo make run`.

- Update:
  1. `git pull`
  2. `make`
  3. `make reload` (SIGHUP) if process active, otherwise restart `sudo make run`.
  4. If ruleset changed: `sudo ./setup.sh up`.

- Uninstall:
  1. Stop process (`pkill -f "luajit.*main"` or local service manager).
  2. Delete nft tables: `sudo ./setup.sh down`.
  3. Optional: `make clean`.

### OpenWrt: installation, update, uninstall

- Initial installation (from dev machine):
  1. Compile locally: `make`.
  2. Deploy: `luajit install-owrt.lua root@<router>`.
  3. The installer:
     - installs packages,
     - copies Lua + ruleset to `/usr/share/custos`,
     - installs config `/etc/custos`,
     - installs service `/etc/init.d/custos`,
     - installs `custos-update` + cron.

- Update:
  - Simple option: `make test-openwrt HOST=root@<router>` (redeploys + validates).
  - Full option: rerun `luajit install-owrt.lua root@<router>` (without `--uninstall`).

- Uninstall:
  - `luajit install-owrt.lua root@<router> --uninstall`
  - This action stops/disables the service, deletes files and cleans nft/sysctl/UCI.
