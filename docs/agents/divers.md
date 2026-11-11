# Divers (ipparse, sync, redbean, px5g)

## ipparse (sous-module moontastik)

La bibliothèque de parsing L2/L3/L4/L7 `ipparse` n'est plus une copie vendue :
c'est le sous-module git `src/lib/moontastik`
(https://github.com/luainkernel/moontastik), et `src/ipparse` est un **lien
symbolique relatif** vers `lib/moontastik/ipparse`. Le code custos continue de
faire `require "ipparse.…"` sans changement.

- **Commit épinglé** : `265876b` (90 commits après `a77fd2f`). L'amont avance :
  `checkout` toujours ce commit, jamais une branche.
- **Cloner/initialiser** : `git clone --recursive` ou
  `git submodule update --init` (idem pour `src/lib/moonscript`).
- **Mettre à jour** : `git -C src/lib/moontastik fetch`,
  `git -C src/lib/moontastik checkout <commit>`, puis `make all && make test`,
  et committer le nouveau pointeur de sous-module (`git add src/lib/moontastik`).
  Vérifier que `git -C src/lib/moontastik status --short` reste vide après
  compilation (aucun `.lua` généré dans le sous-module).
- **Piège `find`** : `find src/ipparse …` ne descend pas dans un lien
  symbolique donné comme point de départ. Le `Makefile` utilise donc
  `find -H $(SRC)/ipparse` pour `IPPARSE_MOONS`, et élague
  `$(MOONTASTIK_SUBMODULE)` du `find $(SRC)` global (sinon des
  `lua/lib/moontastik/…` parasites apparaissent).
- **Façade `fun`** : depuis `265876b`, `ipparse/fun.moon` réexporte
  `fun/{tables,memo,iter,protected}.moon` ; les modules protocole ne chargent
  que `ipparse.fun.tables`. `find -H` descend dans `src/ipparse/fun/` et
  compile `lua/ipparse/fun/*.lua` ; pas de collision avec
  `lua/ipparse/fun.lua` (`ipparse.fun` résout le fichier, `ipparse.fun.tables`
  le sous-dossier). Le sous-dossier est embarqué par le paquet OpenWrt
  (`packaging/openwrt/custos/Makefile:26,41`, `$(CP)` récursif), par
  `install-owrt.moon:218` (`tar -C lua .`) et par le homelab
  (`libvirt/homelab.sh:424`, `tar … lua tests`).
- **Sémantique `265876b` ayant exigé une adaptation** :
  - `ip6.pack` recalcule toujours `vtf` depuis `version`/`traffic_class`/
    `flow_label` ; recopier `vtf` seul perd TC et flow label. Adapté dans
    `src/dup_query.moon:56-57,88-89` et `src/forge_dns.moon:42-43` (les trois
    sites passent `traffic_class`/`flow_label`). Tests :
    `tests/unit/dup_query_spec.moon`, `tests/unit/forge_dns_spec.moon`.
- **Changements examinés sans impact** (usages custos) :
  - DNS : `opcode`/`z`/`rcode` renvoient un nombre (plus un booléen) ; aucun
    test de vérité custos sur ces accesseurs, le rcode numérique est déjà
    extrait de `ra_z_rcode` (`src/dns_classify.moon:35-36`,
    `src/worker_responses.moon:586`, `src/worker_doh.moon:134`). Seul effet
    visible, voulu : les logs `rcode` (`src/worker_responses.moon:541,762`)
    passent de `true`/`false` à 0-15. Classes NONE/ANY (254/255) et options
    EDNS parsées non utilisées.
  - IPv4/TCP : `parse` renvoie `nil` sous les longueurs minimales ; les
    appelants testent `nil` (`src/packet_utils.moon:86,100,109`,
    `src/worker_tls.moon:680-760`). Flags DF/MF/SYN… : custos ne lit que
    `.flags` (`tests/unit/forge_dns_spec.moon:93`).
  - TLS : `parse` renvoie `nil` sur enregistrement/handshake/ClientHello
    tronqué ; appels sous `pcall` + test nil (`src/worker_tls.moon:744-750`,
    `src/auth/sni_extractor.moon:37-48`). `message_types` corrigés : seul
    `client_hello` est utilisé (`src/worker_tls.moon:750`).
  - `pack_compat` lève sur `unpack` tronqué : custos n'utilise que `pack` ; les
    parseurs ipparse gardent leurs `need_bytes` avant `su`
    (`ipparse/l7/dns.moon:229,260,295`, `ipparse/l7/tls/init.moon:53`).
  - `hex2bin`/`bin2hex`, `fun.protected`, `fragmented_ip4`, `pcap`,
    `contains_ip`, `s2net6`, `hexdump` : aucun usage custos.
  - QUIC (`session`, `frames`, `protection`, `version_negotiation`) : couvert
    par `tests/unit/ipparse/l7/quic/session_spec.moon` (vert).
- **`lib/ffi_stub.lua` supprimé** : aucune règle du `Makefile` ne le
  référence ; seule une copie compilée d'exemple le cite
  (`lua/ipparse/examples/parse_real_quic.lua:20`), les exemples amont étant
  exclus de la compilation et de `make check`.

## Synchronisation de configuration (`sync/`)

Déploiement multi-routeurs depuis un dépôt git central.

- `sync/apply.moon` (→ `lua/sync/apply.lua`) : fusionne `base/config.moon` +
  `devices/<hostname>/config.moon` → `/etc/custos/config.moon` (`--reload` envoie SIGHUP).
- `sync/custos-sync.sh` : pull-only depuis `CUSTOS_CONFIG_REPO` (`/etc/custos/sync.conf`,
  surchargeable en test par `CUSTOS_SYNC_CONF`), cron */15. L'URL doit commencer
  par `https://` (refus explicite sinon) ; téléchargement par `curl --fail
  --silent --show-error --location --proto '=https' --proto-redir '=https'`
  (vérification des certificats par défaut, jamais `--insecure`), repli `wget`
  uniquement si `curl` est absent. L'archive fusionnée devient
  `/etc/custos/config.moon`, exécutée en root.
- `sync/custos-sync-push.sh` : publie la config d'un filtre de référence vers le dépôt.
- Init : `make sync-init HOST=… REPO=…` (pull) / `make sync-push-init HOST=… REPO=…` (push).

## UI d'installation redbean (`.init.moon`)

Mini serveur web local (redbean) pour installer/désinstaller/synchroniser Custos
sur un routeur sans CLI. `make redbean-ui` empaquète `.init.lua` dans `redbean.com`.
Voir [doc/CHEATSHEET.md](doc/CHEATSHEET.md) § « UI d'installation (redbean) ».

## px5g Migration — Dynamic TLS Certificate Generation

See [.agents/px5g_migration.md](.agents/px5g_migration.md) for full documentation on the migration from static (openssl-based) to dynamic (px5g-based) certificate generation with LRU/TTL caching.

**New modules**:
- `src/auth/cert_generator.moon` — px5g wrapper for dynamic cert generation
- `src/auth/cert_cache.moon` — LRU cache with TTL for generated certs
- `src/auth/sni_extractor.moon` — TLS ClientHello SNI parser (RFC 5246/6066)

**Modified modules**:
- `src/auth/cert.moon` — Added `load_or_generate_sni()` for SNI-aware certs, and
  `load_or_generate_static()` : si `auth.cert`/`auth.key` sont configurés mais
  absents (installation fraîche), génère un auto-signé à ces chemins (mkdir -p,
  clé 0600) au lieu d'échouer. Sans ce fix, `static_cert_paths` restait posé
  après l'échec du chargement parent et **chaque enfant AUTH-conn levait**
  « Cannot load static certificate in child » → portail inutilisable au premier
  lancement (observé sur 10.35.1.17, 2026-07-18).
- `src/auth/server.moon` — Cache initialization on AUTH server startup ;
  `static_cert_paths` n'est posé que si le contexte statique parent a été
  chargé (sinon repli SNI dynamique, jamais de hard-error par connexion)

