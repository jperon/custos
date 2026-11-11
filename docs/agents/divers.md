# Divers (ipparse, sync, redbean, px5g)

## ipparse (sous-module moontastik)

La bibliothèque de parsing L2/L3/L4/L7 `ipparse` n'est plus une copie vendue :
c'est le sous-module git `src/lib/moontastik`
(https://github.com/luainkernel/moontastik), et `src/ipparse` est un **lien
symbolique relatif** vers `lib/moontastik/ipparse`. Le code custos continue de
faire `require "ipparse.…"` sans changement.

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

