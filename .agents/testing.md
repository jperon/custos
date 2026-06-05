# Tests

> **Definition of Done (rappel).** Avant de conclure toute tâche : (1) le code
> ajouté/modifié est **couvert** (`make coverage`), (2) la **documentation** est à
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
| `make coverage` | aucun | `make test` + rapport luacov dans `tmp/coverage/`. |
| `make check` | aucun | Vérification syntaxique des `.lua` compilés. |
| `make test-openwrt HOST=root@<host>` | SSH + OpenWrt avec LuaJIT + nftables | Déploie les fichiers Lua + règles nft via `scp`, démarre les workers via `logger -t custos`, puis lance les vérifications DNS/auth depuis la machine locale. |
| `make test-vm` | homelab libvirt démarré | Exécute les tests unitaires *à l'intérieur* de la VM `custos` (runner `mini_busted`). |
| `make test-e2e` | homelab libvirt | Suite E2E complète via les 3 VMs libvirt — groupes G0/G0b–G14 : DNS allow/block, EDE, auth/sessions, IPv6, DoH, interface admin webui `/admin/*`, inspection SNI **TLS et QUIC** (`worker_tls` ; le QUIC Initial UDP/443 est rejoué depuis la fixture `tests/e2e/fixtures/quic_initial.bin` via `socat`, installé à la volée sur servus — T125), IPv6 du data-plane (servus reçoit une ULA `fd42:42:0:1::/64` dans le test, son image n'ayant pas de client DHCPv6 — T74), **et approvisionnement des listes pré-compilées via `custos-update` (G0b, juste après l'infra de base)** (voir [libvirt/README.md](../libvirt/README.md)). G0b et T125 dépendent d'une ressource externe (accès internet + release `custos-lists` ; CDN d'assets GitHub) : faute de connectivité, de release ou d'outil installable, ils `skip` (« dépendance manquante ») au lieu d'échouer. `custos-update` retente les téléchargements (`curl --retry`) pour absorber les échecs transitoires du CDN. |
| `make test-e2e-rebuild` | libvirt | Reconstruit le homelab (`homelab-nuke` + ensure) puis lance la suite E2E. |
| `make test-e2e-ssh` | hôtes SSH accessibles | Suite E2E sur machines distantes (`FILTER_SSH=... CLIENT_SSH=... [CLIENT2_SSH=...]`). |

Cibles homelab associées : `make homelab-up` / `homelab-down` / `homelab-nuke` /
`homelab-redeploy` (cf. [libvirt/README.md](../libvirt/README.md)).

---

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
