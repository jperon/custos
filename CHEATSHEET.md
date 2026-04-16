# CustosVirginum - CHEATSHEET

Référence rapide pour mainteneurs/contributeurs.
Les explications détaillées et l'architecture restent dans `README.md`.

## Entrée rapide

- Supervision: `src/main.moon`
- Workers DNS: `src/worker_q0.moon` (questions), `src/worker_q1.moon` (réponses)
- IPC Q0 -> Q1: `src/ipc.moon`
- Ruleset nftables: `nft-rules/dns-filter.nft`
- Règles de filtrage: `cfg/filter.yml`

## Où modifier quoi

- Règles métier:
  - `cfg/filter.yml`
  - `src/filter/init.moon`
  - `src/filter/rule.moon`
  - `src/filter/convert.moon`

- Ajouter une condition:
  - Ajouter `src/filter/conditions/<nom>.moon`
  - Chargée via `require("filter.conditions.<nom>")` dans `src/filter/rule.moon`

- Ajouter une action:
  - Ajouter `src/filter/actions/<nom>.moon`
  - Chargée via `require("filter.actions.<nom>")` dans `src/filter/rule.moon`

- Logique DNS (décision, corrélation, réinjection):
  - Q0: `src/worker_q0.moon`
  - IPC: `src/ipc.moon`
  - Q1: `src/worker_q1.moon`
  - Boucle NFQUEUE: `src/nfq_loop.moon`

- REFUSED, EDE, TTL:
  - Helpers DNS: `src/parse/dns.moon`
  - Patch/rebuild paquet: `src/parse/ndpi.moon`
  - TTL forcé: `FORCED_TTL` dans `src/config.moon`

- Injection nft (sets):
  - Commandes nft: `src/nft.moon`
  - Conditions d'injection A/AAAA/dnsonly: `src/worker_q1.moon`
  - Noms de sets/timeouts: `src/config.moon`

- Authentification / portail captif:
  - Worker auth: `src/auth/worker.moon`
  - Serveur auth: `src/auth/server.moon`
  - Worker Q2 (TCP/80 intercept): `src/worker_q2.moon`
  - Sessions: `src/auth/sessions.moon`
  - Intégration nft auth: `src/auth/nft_sessions.moon`
  - Secrets/hash: `src/auth/credentials.moon`

- Parsing + nDPI:
  - Façade: `src/parse/ndpi.moon`
  - nDPI 4.x: `src/parse/ndpi_v4.moon`, `src/ffi_ndpi_v4.moon`
  - nDPI 5.x: `src/parse/ndpi_v5.moon`, `src/ffi_ndpi_v5.moon`
  - Dispatch de version: `src/ffi_ndpi.moon`

## Contrats utiles

- Condition compilée: `(req) -> ok, reason`
- Action compilée: `(req) -> verdict|nil, message`
- Clé pending Q1: `txid:ip:port`
- Workers: Q0 (questions), Q1 (réponses), AUTH (HTTPS), Q2 (TCP/80 captif, si `BRIDGE_MODE=1`)
- SIGHUP:
  - `main` le propage a Q0
  - Q0 fait `filter.reload()`
- Sets nft actifs: `ip4_allowed`, `ip6_allowed`, `authenticated_ips`

## Build, run, debug

- Build: `make`
- Run (root): `sudo make run`
- Reload config: `make reload`
- Update lists: `make update-lists`
- Logs: `make logs`

## Domainlists / Customlists

- Config source:
  - Fichier principal: `cfg/filter.yml` (ou `/etc/custos/filter.yml` sur OpenWrt)
  - Champs utiles: `sources`, `domainlists_dir`, `custom_lists_dir`

- Mettre à jour les listes (Debian/dev machine):
  - `make update-lists`
  - Equivalent direct:
    - `LUA_PATH="lua/?.lua;lua/?/init.lua;;" luajit lua/filter/updater.lua --config cfg/filter.yml`

- Mettre à jour les listes (OpenWrt):
  - `ssh root@<routeur> 'custos-update'`
  - Le script utilise `/etc/custos/filter.yml` et recharge les listes compilées.

- Custom lists (workflow):
  1. Déposer des fichiers `.txt` dans `custom_lists_dir` (1 domaine par ligne, `#` pour commentaires).
  2. Lancer la mise à jour (`make update-lists` ou `custos-update`).
  3. Recharger le service si nécessaire:
     - Debian: `make reload`
     - OpenWrt: `ssh root@<routeur> '/etc/init.d/custos reload'`

## Tests (selection rapide)

- Unitaires: `make test`
- nDPI: `make test-ndpi`
- Docker E2E: `make test-docker`
- KVM E2E (47 tests): `make test-kvm`
- OpenWrt E2E: `make test-openwrt HOST=root@<routeur>`

## Playbooks rapides

- Ajouter une condition:
  1. Créer `src/filter/conditions/<nom>.moon` (factory -> prédicat `(req) -> ok, reason`).
  2. Référencer la condition dans `cfg/filter.yml`.
  3. `make && make test`.

- Ajouter une action:
  1. Créer `src/filter/actions/<nom>.moon` (`(req) -> verdict|nil, message`).
  2. L'appeler via `actions:` dans `cfg/filter.yml`.
  3. Vérifier l'ordre des actions (premier verdict non-nil gagne).

- Modifier le comportement REFUSED/EDE:
  1. Ajuster `src/parse/dns.moon` (construction REFUSED, options EDNS/EDE).
  2. Vérifier l'appel dans `src/worker_q1.moon` (branche `refused`).
  3. Tester au minimum `make test` puis un E2E (`test-docker` ou `test-openwrt`).

- Modifier l'injection nft:
  1. Ajuster `src/nft.moon` (commande `add element`).
  2. Ajuster la logique A/AAAA/dnsonly dans `src/worker_q1.moon`.
  3. Vérifier les sets via `nft list set ...`.

- Debug correlation IPC Q0/Q1:
  1. Vérifier format/clé dans `src/ipc.moon` (clé `txid:ip:port`).
  2. Regarder logs `response_no_matching_question` (Q1).
  3. Confirmer que Q0 envoie bien `write_msg`/`write_refused_msg`/`write_dnsonly_msg`.

## Ops Debian/OpenWrt

### Interfaces réseau (bridge/LAN/WAN)

- Le ruleset `nft-rules/dns-filter.nft` est générique:
  - pas de noms d'interface imposés (`eth0`, `br-lan`, etc. non hardcodés),
  - filtrage basé sur familles/protocoles/sets, pas sur noms d'interfaces.
- La machine filtre doit être sur le chemin LAN <-> WAN (souvent en bridge transparent).
- `br_netfilter` doit être actif pour voir le trafic bridge dans netfilter/NFQUEUE.

### Debian: installation, mise à jour, désinstallation

- Installation:
  1. Installer les dépendances (cf. `README.md`), puis `make`.
  2. Appliquer environnement + règles: `sudo ./setup.sh up`.
  3. Lancer le service en foreground: `sudo make run`.

- Mise à jour:
  1. `git pull`
  2. `make`
  3. `make reload` (SIGHUP) si processus actif, sinon relancer `sudo make run`.
  4. Si le ruleset a changé: `sudo ./setup.sh up`.

- Désinstallation:
  1. Stopper le processus (`pkill -f "luajit.*main"` ou service manager local).
  2. Supprimer les tables nft: `sudo ./setup.sh down`.
  3. Optionnel: `make clean`.

### OpenWrt: installation, mise à jour, désinstallation

- Installation initiale (depuis la machine de dev):
  1. Compiler local: `make`.
  2. Déployer: `luajit install-owrt.lua root@<routeur>`.
  3. L'installeur:
     - installe les paquets,
     - copie Lua + ruleset vers `/usr/share/custos`,
     - installe la config `/etc/custos`,
     - installe service `/etc/init.d/custos`,
     - installe `custos-update` + cron.

- Mise à jour:
  - Option simple: `make test-openwrt HOST=root@<routeur>` (redéploie + valide).
  - Option complète: relancer `luajit install-owrt.lua root@<routeur>` (sans `--uninstall`).

- Désinstallation:
  - `luajit install-owrt.lua root@<routeur> --uninstall`
  - Cette action stoppe/désactive le service, supprime les fichiers et nettoie nft/sysctl/UCI.
