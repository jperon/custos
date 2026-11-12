# Tests

> **Definition of Done (rappel).** Avant de conclure toute tâche : (1) le code
> ajouté/modifié est **couvert** (`make coverage-split`), (2) la **documentation** est à
> jour, (3) **`make test` ET `make test-e2e` passent à 100 %** (`0 failed`),
> commandes réellement exécutées et total lu. Voir [AGENTS.md](../AGENTS.md)
> § « Definition of Done ». Si une suite ne peut être lancée, le dire — ne jamais
> annoncer un succès non constaté.

---

## Suites disponibles

| Commande | Prérequis | Description |
|----------|-----------|-------------|
| `make test` | aucun (pas de root) | Compile les specs `tests/unit/**/*_spec.moon` + helpers, puis exécute Busted. Couvre parsing, `filter.*`, `ipc`, `nft_queue`, `dns_ede`, `metrics`, `webui`, `sync`, `doh`, `sip` et les workers. |
| `make test-unit` | aucun | Sous-ensemble Busted sans dépendances FFI (CI rapide). |
| `make test-ffi` | wolfssl + libsocket | Tests FFI socket / WolfSSL / intégration TLS. |
| `make coverage-split` | aucun | Couverture **exacte** ligne-par-ligne (~30 min) : un Busted par spec, stats luacov fusionnées, rapport dans `tmp/coverage/`. `make coverage` (un seul processus, ~25 min) peut encore mourir d'un SIGSEGV LuaJIT intermittent sous le hook luacov ; `make coverage-quick` donne un ordre de grandeur par échantillonnage. |
| `make check` | aucun | Vérification syntaxique des `.lua` compilés **et** contrôle des lectures de globales non déclarées (`tools/check_globals.sh`). **Bloquante** : `exit 1` si au moins un fichier ne se charge pas (rapport complet affiché) ou si une globale inconnue est lue. |
| `make bench` | aucun | Micro-bench in-process (ns/op + KB) des hot-paths. Cf. [src/bench/README.md](../src/bench/README.md). |
| `make bench-load TARGET=host[:port]` | un résolveur DNS joignable | Charge DNS bout-en-bout (QPS, latences p50/p95/p99, pertes). Variables : `DURATION`, `RATE`, `DOMAINS`, `ITERS`, `SAVE_BASELINE`. |
| `make test-openwrt HOST=root@<host>` | SSH + OpenWrt avec LuaJIT + nftables | Déploie les fichiers Lua + règles nft via `scp`, démarre les workers via `logger -t custos`, puis lance les vérifications DNS/auth depuis la machine locale. |
| `make test-vm` | homelab libvirt démarré | Exécute les tests unitaires *à l'intérieur* de la VM `custos` (runner `mini_busted`). |
| `make test-e2e` | homelab libvirt | Suite E2E complète via les 3 VMs libvirt — groupes G0/G0b–G14 : DNS allow/block, EDE, auth/sessions, IPv6, DoH, interface admin webui `/admin/*`, inspection SNI **TLS et QUIC** (`worker_tls` ; le QUIC Initial UDP/443 est rejoué depuis la fixture `tests/e2e/fixtures/quic_initial.bin` via `socat`, installé à la volée sur servus — T125), IPv6 du data-plane (servus reçoit une ULA `fd42:42:0:1::/64` dans le test, son image n'ayant pas de client DHCPv6 — T74), **et approvisionnement des listes pré-compilées via `custos-update` (G0b, juste après l'infra de base)** (voir [libvirt/README.md](../libvirt/README.md)). G0b et T125 dépendent d'une ressource externe (accès internet + release `custos-lists` ; CDN d'assets GitHub) : faute de connectivité, de release ou d'outil installable, ils `skip` (« dépendance manquante ») au lieu d'échouer. `custos-update` retente les téléchargements (`curl --retry`) pour absorber les échecs transitoires du CDN. |
| `make test-e2e-rebuild` | libvirt | Reconstruit le homelab (`homelab-nuke` + ensure) puis lance la suite E2E. |
| `make test-e2e-ssh` | hôtes SSH accessibles | Suite E2E sur machines distantes (`FILTER_SSH=... CLIENT_SSH=... [CLIENT2_SSH=...]`). |

Cibles homelab associées : `make homelab-up` / `homelab-down` / `homelab-nuke` /
`homelab-redeploy` (cf. [libvirt/README.md](../libvirt/README.md)).

## Fiabilité du code retour des cibles de test (pipefail)

**Le code retour de `make test`, `test-unit`, `coverage`, `coverage-split` et `coverage-quick` est
fiable** : il reflète le statut réel de Busted, pas celui de `tee`.

Ces recettes envoient la sortie de Busted dans `tee tmp/test-logs/*.log` pour
conserver le rapport. Or `tee` réussit **toujours** : sans précaution, `$?`
vaut 0 même quand la suite échoue et `make test` retourne un faux positif —
intolérable pour la Definition of Done (qui exige `0 failed` constaté). Le
Makefile définit donc :

```make
SHELL := bash
PIPE_FAIL = set -o pipefail;
```

et **chaque** pipeline de test est préfixé par `$(PIPE_FAIL)`. `coverage`, `coverage-split` et
`coverage-quick` capturent en outre `rc=$$?` juste après le pipeline, génèrent
leur rapport, puis propagent l'échec : le diagnostic reste produit en cas d'échec,
mais le statut d'échec est bien propagé. `test-unit` se fie directement au
statut du pipeline (plus de `rc=$$?` post-`tee`).

`make test` dépend de `test-unit` **et** `test-js` : make s'arrête au premier
échec de sous-cible (aucun préfixe `-`, `.IGNORE` ni `|| true` sur ces cibles),
donc un échec Busted **ou** Node fait échouer `make test`.

**Ne pas réintroduire de masquage** : toute nouvelle recette qui pipe vers
`tee`/`grep`/`head` et doit signaler un échec doit utiliser `$(PIPE_FAIL)` (ou
`set -o pipefail`) et ne jamais se fier à un `$?` post-pipe nu. Note : `SHELL`
est volontairement `bash` (sans chemin absolu) et non `/bin/bash`, car dans
`nix develop` le `/bin/bash` de l'hôte peut être un lien mort ; `bash` est
résolu via `PATH`.

**`make check` est bloquante** : la boucle de vérification syntaxique agrège
les échecs (`rc=1` dès qu'un `.lua` ne se charge pas) puis `exit $$rc`, tout en
affichant chaque ligne `OK`/`FAIL` (pas d'arrêt au premier fichier cassé). Un
fichier cassé fait donc réellement échouer la cible — plus de « rouge à
l'écran, vert en code retour ».

La liste vérifiée (`CHECK_LUAS`) exclut le code du **sous-module** ipparse
(`src/lib/moontastik`, exposé via le lien symbolique `src/ipparse`) qui n'est
pas destiné à LuaJIT : `lua/ipparse/examples/`, `lua/ipparse/tests/` et
`lua/ipparse/lib/bit53.lua` (syntaxe Lua 5.3 `&`/`|`/`<<` que LuaJIT 5.1 ne
parse pas). Ces fichiers ne font pas partie du runtime déployé ; les inclure
laissait `check` rouge en permanence sur du code amont non modifiable.

### Contrôle des globales non déclarées (`tools/check_globals.sh`)

MoonScript rend **locale au bloc** toute variable assignée dans un bloc (boucle,
`if`, `pcall`…). Lue ensuite hors de ce bloc — ou hors de la fonction qui
l'assigne — elle compile en **lecture de globale**, donc en `nil`, sans aucune
erreur de compilation. C'est un piège silencieux : le code se charge, les tests
passent, et seule une valeur manquante à l'exécution le révèle (voir
`docs/agents/audits.md`, § « Globales nil »).

`make check` exécute donc, après la vérification syntaxique,
`tools/check_globals.sh` (code retour non nul si une globale inconnue est lue) :

- le script liste le bytecode de chaque `.lua` compilé (`luajit -bl`) et relève
  les instructions `GGET` (lecture de globale), y compris dans les fonctions
  imbriquées ;
- une **liste blanche explicite** couvre la base Lua 5.1, les bibliothèques
  standard, les globales LuaJIT (`bit`, `jit`) et `arg`. `ffi` n'y est
  volontairement pas : LuaJIT ne l'expose pas en globale, donc un fichier qui
  lit `ffi` sans le requérir est bien signalé ;
- périmètre : tout `lua/**.lua` sauf `lua/ipparse/` (sous-module moontastik,
  code amont) et `lua/moonscript/`, `lua/moon/` (runtime embarqué) ;
- usage ciblé : `tools/check_globals.sh lua/worker_tls.lua` pour un seul
  fichier ; durée ≈ 2 s sur l'ensemble.

Toute nouvelle globale légitime doit être ajoutée **explicitement** à
`STANDARD_GLOBALS` dans le script, avec sa justification.

### Connexion libvirt et clé SSH du homelab

`libvirt/homelab.sh` ne suppose plus que `virsh` nu voit les VMs. Il résout la
connexion dans cet ordre : `LIBVIRT_DEFAULT_URI` s'il est défini (priorité
absolue), sinon `qemu:///system` si des domaines `homelab-*` y sont visibles,
sinon `qemu:///session`, sinon connexion par défaut. La décision pure est dans
`libvirt/libvirt_uri.sh` et couverte par `tests/unit/libvirt_uri_spec.moon`.
Sans cela, un homelab en `qemu:///system` était invisible depuis
`qemu:///session` : `net-dhcp-leases` vide → `ERROR: timeout SSH sur via`.

De même, si `SSH_KEY` n'est pas défini, le harnais essaie toutes les clés
usuelles (`id_ed25519`, `id_rsa`, `id_ecdsa`) et retient celle qu'une VM
accepte. Un `Permission denied (publickey)` (VM provisionnée avec `id_rsa`,
script qui préfère `id_ed25519`) ne doit plus être confondu avec une VM non
démarrée ; `SSH_KEY=...` reste prioritaire.

---

## wolfSSL de l'environnement de test

Le devShell construit wolfSSL **5.8.4** (`flake.nix:17-38`), la version de
`libwolfssl` de la cible OpenWrt 25.12, avec `--enable-alpn --enable-sni
--enable-opensslextra --enable-opensslall` en plus des options px5g
(`--enable-keygen --enable-certgen --enable-certreq --enable-certext
--enable-ecc`). L'API TLS utilisée par `auth.ffi_wolfssl` est ainsi celle de la
cible, et non celle, plus pauvre, construite auparavant (5.6.6 sans ALPN).

Symboles exportés (vérifiés par `nm -D --defined-only` dans `nix develop`) :
`wolfSSL_UseALPN`, `wolfSSL_ALPN_GetProtocol`, `wolfSSL_get0_alpn_selected`,
`wolfSSL_CTX_set_alpn_protos`, `wolfSSL_set_alpn_protos`,
`wolfSSL_CTX_set_alpn_select_cb`, `wolfSSL_UseSNI`, `wolfSSL_SNI_GetRequest`,
`wolfSSL_CTX_set_servername_callback`, `wolfSSL_check_domain_name`,
`wolfSSL_CTX_load_verify_locations`. Les symboles optionnels (SNI, ALPN,
chargement du magasin de CA) doivent rester sondés par `pcall`
(`src/auth/ffi_wolfssl.moon:116`, `:148`) : la cible peut les omettre.

`wolfSSL_CTX_UseALPN` est exporté par **ni** l'environnement de test **ni** la
cible (supprimé de wolfSSL 5.x ; `src/auth/ffi_wolfssl.moon:190` le sonde donc en
vain). Aucun test ne doit en dépendre.

La VM e2e `custos` installe `libwolfssl` par `apk`/`opkg` sans épinglage
(`libvirt/homelab.sh:404`) : au 2026-11-11 c'est `libwolfssl5.9.1`, qui exporte
les mêmes symboles ALPN.

## Pièges OpenWrt

### Logging sur OpenWrt

Les workers sont lancés avec `2>&1 | logger -t custos` (pas de fichier log).
Les vérifications utilisent `logread` (buffer circulaire syslog). Pour filtrer
les entrées de la session de test courante, insérer un marqueur dans syslog
avant de démarrer le démon :

```custos/.agents/testing.md#L1-1
ssh "logger -t custos '#{LOG_MARKER}'"
ssh "(cd #{CUSTOS_DIR} && luajit2 main.lua </dev/null 2>&1 | logger -t custos) &"
-- puis interroger :
ssh "logread | sed -n '/#{LOG_MARKER}/,$p' | grep queue_listening"
```

Les logs utiles pour valider l'architecture courante sont `questions_*`
(champ `rule` + `timeout`) et `response_*` (champ `nft_rule_id` +
`payload_modified`).

### `grep -c` vs `wc -l`

`grep -c` retourne le code de sortie 1 quand le compte est 0, ce qui fait
échouer l'appel SSH (`ok=false`). Utiliser `grep PATTERN | wc -l` (toujours
code 0) pour les vérifications de comptage.

### AF_PACKET/`ETH_P_ALL` sur le bridge maître casse NFQUEUE

**Symptôme** : tous les workers NFQUEUE (DNS, captif, reject, SNI…) restent
bloqués en `read()` ; la règle nft `queue` incrémente bien son compteur mais le
paquet n'entre jamais dans la file (`/proc/net/netfilter/nfnetlink_queue` :
`id_sequence=0`, aucun drop comptabilisé). Tout le filtrage DNS tombe en timeout.

**Cause** : un socket `AF_PACKET/SOCK_RAW` ouvert avec `ETH_P_ALL` **et lié à
l'interface bridge maître** (ex. `br-lan`) se met à *capturer* tout le trafic
bridgé. Sur le noyau OpenWrt cible, cela casse la remise des paquets queués
depuis le hook bridge `forward` à l'espace utilisateur. Un socket identique lié
à un **port esclave** (`eth0`/`eth1`) ou ouvert en **protocole 0** (émission
seule) ne pose pas de problème.

**Pièges associés** :
- `detect_bridge_slaves` doit énumérer `/sys/class/net/<bridge>/brif/` :
  `ip link show type bridge_slave` n'existe pas en busybox, et le repli sur
  l'interface maître recrée exactement la condition fautive.
- `bridge_raw.open_socket` (injection de trames, émission seule) utilise le
  protocole `0`, jamais `ETH_P_ALL`.
- Ce bug est **latent** tant que `auth.bridge_ifname` n'est pas réglé sur le vrai
  bridge (un nom inexistant → `socket()`/`bind()` échoue → pas de capture).
