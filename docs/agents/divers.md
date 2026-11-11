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
- `src/auth/cert_cache.moon` — LRU cache with TTL for generated certs (quota de noms disque via `can_store`)
- `src/auth/sni_extractor.moon` — TLS ClientHello SNI parser (RFC 5246/6066)
- `src/auth/sni_peek.moon` — lecture du ClientHello sans consommation (`MSG_PEEK`) avant le handshake
- `src/auth/cert_name.moon` — validation des noms SNI (nom de fichier + CN) et repli IP locale
- `src/auth/cert_files.moon` — écriture atomique et verrouillée des paires clé/certificat

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
  chargé (sinon repli SNI dynamique, jamais de hard-error par connexion) ;
  lecture du SNI avant le handshake et repli sur l'IP locale (`cert_name_for`).


## Chemins d'écriture au runtime

Principe : `/etc/custos` ne contient que les **définitions manuelles** (config,
listes `.txt` saisies à la main, secrets, certificat fourni à la main). Tout
fichier **téléchargé** ou **généré au runtime** doit vivre en tmpfs, sous
`/tmp/custos` ou `/var/run`, et être régénéré au démarrage. Le service tourne
avec `cwd=/` : un chemin relatif `tmp/…` ne tombe en tmpfs que par accident.

Inventaire au 2026-11-11 (les chemins par défaut effectifs tiennent compte de
`src/config.moon` et de la config du paquet `packaging/openwrt/custos/files/`) :

| Site (fichier:ligne) | Chemin par défaut effectif | Nature | Emplacement |
|----------------------|----------------------------|--------|-------------|
| `src/metrics.moon:136` (chemin `:122`) | `<dirname(runtime.pid_file)>/metrics-<worker>.json`, soit `/var/run/metrics-*.json` (`src/main.moon:609`, `src/worker_questions.moon:483`, défaut `/var/run/custos.pid` en `src/lib/pidfile.moon:9`) | généré | tmpfs (`/var/run`) |
| `src/worker_events.moon:163` (chemin `:161`) | `/tmp/custos/events/recent-verdicts.tsv` (`events.dir`, `src/config.moon:342`) | généré | tmpfs |
| `src/worker_events.moon:226` | `/tmp/custos/events/events-<heure>.tsv` | généré | tmpfs |
| `src/auth/rate_limit.moon:91` | `<auth.sessions_file>.ratelimit`, soit `/tmp/sessions.lua.ratelimit` (`src/config.moon:300`, `src/auth/handlers.moon:329`) | généré | tmpfs |
| `src/auth/sessions.moon:79` | `auth.sessions_file`, soit `/tmp/sessions.lua` (`src/config.moon:300`) | généré (état) | tmpfs (voir cas douteux) |
| `src/auth/credentials.moon:262` | `auth.secrets`, soit `/etc/custos/secrets` (`src/config.moon:299`) | manuel / webui (comptes) | flash (`/etc`), légitime |
| `src/auth/cert.moon:55` (`write_pem_file`) | chemin fourni : `auth.cert`/`auth.key` (manuel) via `load_or_generate_static` ; SNI via `sni_paths` (`src/auth/cert.moon:130`) → `/tmp/custos/certs/auth_sni_<nom>_<année>.{key,crt}` | fourni manuel / généré | `/etc` si configuré ; tmpfs pour le SNI |
| `src/auth/cert_files.moon:56` | chemin fourni par `auth/cert.moon` ou `auth/cert_cache.moon` | généré | idem ligne précédente |
| `src/auth/cert_cache.moon:112-113` (index `:94`, écriture `:25`) | `/tmp/custos/certs/<nom>.{crt,key}` et `/tmp/custos/certs/cert_cache_index.lua` (`DEFAULT_CERT_DIR` en `src/auth/cert_cache.moon:21`, clé `auth.cert_dir` en `src/config.moon:304`) | généré | tmpfs |
| `src/nft_rules.moon:282-290` | `/tmp/custos/custos-rules-<epoch>.nft` et `.err` | généré (temporaire) | tmpfs |
| `src/lib/pidfile.moon:9` | `/var/run/custos.pid` (surcharges `runtime.pid_file`, env `CUSTOS_PID_FILE`) | généré | tmpfs |
| `src/webui/handlers/lists.moon:66` (chemin `:22-26`) | `{lists_dir}/{type}/{name}.txt` ; défaut `/etc/custos/lists` (`DEFAULTS.filter.lists_dir` `src/config.moon:368`, `compiler_api.DEFAULT_LISTS_DIR`) | manuel (webui) | flash (`/etc`), légitime |
| `src/webui/serializer.moon:75` | `{config_path}.webui.new` → `/etc/custos/config.moon` (`DEFAULT_CONFIG_PATH`, `src/config.moon:52`) | manuel (webui) | flash (`/etc`), légitime |
| `src/filter/updater.moon:223` | `filter.domainlists_dir` → `/tmp/custos/lists/*.bin` (`src/config.moon:363`) | téléchargé / généré | tmpfs |
| `src/filter/updater.moon:120` | `${TMPDIR:-/tmp}/custos-updater-<source>.tar.gz.tmp` | téléchargé (temporaire) | tmpfs |
| `src/filter/updater_io.moon:37,48,69` | `mkdir -p` des parents et `curl -o <dest>` ; chemins fournis par l'appelant (`/tmp/custos/lists`) | téléchargé / généré | tmpfs |
| `src/filter/convert.moon:45` | chemin de sortie passé en argument (outil CLI) | généré | non déterminé (hors service) |
| `src/auth/cert_generator.moon:54-55` | `/tmp/px5g_key_<suffixe>.pem`, `/tmp/px5g_cert_<suffixe>.pem` | généré (temporaire px5g) | tmpfs |
| `src/auth/token.moon:122` | `auth.session_key`, soit `/etc/custos/session.key` (`src/auth/server.moon:355`, schéma `src/webui/schema/config_schema.moon:95`) | généré si absent (secret) | flash (voir cas douteux) |
| `src/mac_learner.moon:387` | `/var/run/custos/mac_query.sock` (`mac_learner.query_sock`, `src/config.moon:281`) | généré (socket Unix) | tmpfs |
| `packaging/openwrt/custos/files/usr/sbin/custos-update:20,62` | `/tmp/custos/lists` (`custos.main.lists_dir`) et `mktemp -d /tmp/custos-lists.XXXXXX` | téléchargé | tmpfs |

Cas non trouvés : `recent-devices.tsv` n'existe pas dans le dépôt (le fichier
équivalent est `recent-verdicts.tsv`, `src/worker_events.moon:46`).

Défauts corrigés le 2026-11-11 : `auth/cert*.moon` (chemins relatifs
`tmp/certs`, `tmp/cert_cache_index.lua`, `tmp/auth_sni_*`), le temporaire de
`nft_rules.apply` (était `./tmp`) et `filter.lists_dir` (défaut
`/etc/custos/lists`, au lieu du repli `/tmp/custos/lists` de `compiler_api` et
de la webui).

Cas douteux laissés en l'état :
- `auth.sessions_file` (`/tmp/sessions.lua`) et son `.ratelimit` : tmpfs, donc
  perdus au redémarrage. Recommandation : conserver tel quel (état de session
  éphémère) ou, si la persistance est voulue, déplacer vers `/etc/custos`.
- `auth.session_key` (`/etc/custos/session.key`) : généré au runtime mais
  classé « secret », donc laissé dans `/etc`. Recommandation : le déplacer vers
  `/tmp/custos` seulement si l'on accepte d'invalider tous les jetons au
  redémarrage (les sessions sont déjà perdues).
- `load_or_generate_static` (`src/auth/cert.moon:241-257`) : si `auth.cert`
  est configuré mais absent, custos y génère un auto-signé — donc potentiellement
  dans `/etc`. Comportement documenté ; non modifié (chemin choisi par
  l'utilisateur), mais un déploiement qui ne veut rien écrire sur la flash doit
  laisser `auth.cert`/`auth.key` vides (repli SNI en tmpfs).
