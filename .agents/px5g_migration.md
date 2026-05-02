# Migration vers px5g — Génération dynamique de certificats TLS SNI

## Vue d'ensemble

Depuis v0.x, CustosVirginum utilisait un certificat auto-signé **statique** généré une seule fois au démarrage via `openssl req`. Tous les clients HTTPS voyaient le même certificat avec un CN fixe ("custos") et des SANs statiques (adresses IP locales).

**La migration px5g** remplace cela par un système de **génération dynamique** :
- Certificats générés à la volée via le binaire `px5g` (WolfSSL-based)
- Cache LRU/TTL : réutilisation intelligente des certificats (100 slots, 24h)
- Prépare le terrain pour la sélection de certificats par **SNI** (Server Name Indication)
- Certificats EC auto-signés (plus rapide que RSA)

## Architecture

### Modules nouveaux

#### 1. **cert_generator.moon** (`src/auth/cert_generator.moon`)
Wrapper simple pour le binaire `px5g` via `io.popen`.

```lua
local gen = require "auth.cert_generator"
local key_pem, cert_pem, ok, err = gen.generate_self_signed("example.com")
```

**Fonctions** :
- `generate_rsa_key(bits)` → (key_pem, ok, err)
  - Note: Obsolète pour px5g (génère EC par défaut)
- `generate_self_signed(cn, sans, days)` → (key_pem, cert_pem, ok, err)
  - Génère clé + certificat auto-signé en une commande
  - Retourne PEM strings (pas des fichiers)

**Dépendances** :
- `px5g` binaire (obligatoire)
  - OpenWrt : `opkg install px5g-wolfssl`
  - Debian/Ubuntu : disponible via `apt-get` sur certaines versions

#### 2. **cert_cache.moon** (`src/auth/cert_cache.moon`)
Cache LRU avec TTL pour certificats générés.

```lua
local cache_module = require "auth.cert_cache"
local cache = cache_module.create_cache(100, 86400)  -- 100 slots, 24h TTL

cache.set("example.com", cert_pem, key_pem, ctx)
local entry = cache.get("example.com")
cache.purge_expired()
```

**API** :
- `create_cache(max_size, ttl_seconds)` → cache object
- `cache:set(hostname, cert_pem, key_pem, ctx)` → bool
- `cache:get(hostname)` → entry or nil
- `cache:delete(hostname)` → bool
- `cache:purge_expired()` → count of deleted entries
- `cache:stats()` → {size, max_size, ttl_seconds}
- `cache:clear()` → bool

**Comportement** :
- Hostnames **case-insensitive** (normalisés en minuscules)
- **LRU eviction** : suppression de l'entrée la plus ancienne si cache plein
- **TTL expiration** : entrée invalide après TTL, suppression paresseuse
- Stockage en-mémoire seulement (pas de fichier)

#### 3. **sni_extractor.moon** (`src/auth/sni_extractor.moon`)
Parser du TLS ClientHello pour extraire le SNI **avant** le handshake complet.

```lua
local sni_module = require "auth.sni_extractor"
local hostname = sni_module.extract_sni(tls_hello_bytes)  -- nil si absent
```

**Fonction** :
- `extract_sni(data)` → hostname string or nil
  - Parse RFC 5246 (TLS 1.2) + RFC 6066 (SNI extension)
  - Retourne le premier hostname du server_name_list
  - Retourne nil si record non-Handshake, pas SNI, ou données invalides

**Format attendu** :
- Byte 0 : TLS record type (0x16 = Handshake)
- Bytes 1-2 : TLS version
- Bytes 3-4 : record length
- [Handshake data with extensions]

### Modules modifiés

#### `cert.moon`
Ajout de `load_or_generate_sni(hostname, cache)` :
```lua
local cert_module = require "auth.cert"
local ctx = cert_module.load_or_generate_sni("example.com", cache)
```

- Cherche dans le cache
- Si absent : génère via `cert_generator`
- Écrit cert/key dans `tmp/auth_sni_{hostname}_{timestamp}.{key,crt}`
- Crée contexte TLS via `ssl.newcontext()`
- Ajoute au cache
- Retourne le contexte

**Important** : WolfSSL exige des fichiers, pas des PEM strings. Les temporaires sont créés à la génération et cachés en mémoire.

#### `server.moon`
Au démarrage du serveur AUTH (`run()`) :
1. Initialise un cache LRU `cert_cache.create_cache(100, 86400)`
2. Génère le certificat initial (fallback générique "custos")
3. Passe le cache dans `state.cert_cache`

Le serveur conserve l'approche actuelle (certificat unique) mais est prêt pour l'intégration SNI :
- Extraction SNI du ClientHello brut
- Appel à `load_or_generate_sni(sni_hostname, state.cert_cache)`
- Utilisation du contexte SNI-spécifique

## Flux d'utilisation

### Démarrage
```
server.moon:run()
  → cert_cache = create_cache(100, 24h)
  → ctx_fallback = load_or_generate("custos")  # Fallback générique
  → state.cert_cache = cache
```

### Connexion client (approche future avec SNI)
```
handle_client()
  → raw_socket data (avant TLS wrap)
  → sni_hostname = extract_sni(data)
  → ctx = load_or_generate_sni(sni_hostname, cache)  # Avec cache
    ├─ cache.get(sni_hostname)   # Hit : contexte existant
    └─ cert_generator.generate_self_signed(sni_hostname)  # Miss : génère
  → ssl.wrap(socket, ctx)
  → TLS handshake
```

## Performance

| Opération | Latence | Notes |
|-----------|---------|-------|
| `px5g selfsigned` | ~50-100ms | EC auto-signé |
| `cache.get()` hit | <1ms | O(1) lookup |
| `cache.get()` miss + generate | ~100ms | Génère et ajoute au cache |
| LRU eviction | <1ms | O(1) per entry removed |

Avec cache :
- **Première connexion à un domaine** : ~100ms (génération)
- **Connexions suivantes** : <1ms (cache hit)
- **Après 24h** : TTL expiration, régénération

## Configuration

### Via `cfg/auth.yml` (futur)
```yaml
auth:
  cert_cache_size: 100        # Max certificats en cache
  cert_cache_ttl: 86400       # TTL en secondes (24h)
```

Actuellement, hardcoder dans `server.moon:run()`.

## Dépendances

### Obligatoires
- `px5g` binaire (must be on $PATH)
  - OpenWrt : `px5g-wolfssl` package
  - Debian : `px5g` ou `px5g-wolfssl`
  - Compilé depuis https://github.com/openwrt/packages

### À éviter
- ~~openssl~~ : plus utilisé pour la génération TLS
- ~~luasec~~ : remplacé par FFI WolfSSL

## Migration depuis l'ancienne approche

### Avant
```
src/auth/cert.moon
├─ generate_self_signed(key_path, cert_path, sans)
│  └─ Appelle openssl req
├─ load_or_generate(key_path, cert_path)
│  └─ Fichiers statiques : tmp/auth.key + tmp/auth.crt
└─ srv.run()
   └─ Un seul contexte TLS partagé par tous les clients
```

### Après
```
src/auth/cert_generator.moon
├─ generate_self_signed(cn, sans, days)
│  └─ Appelle px5g (PEM strings en sortie)
├─ Certificat + clé générés ensemble (EC)

src/auth/cert_cache.moon
└─ Cache LRU/TTL en-mémoire

src/auth/cert.moon (modifié)
├─ load_or_generate()  # Unchanged, backward-compatible
└─ load_or_generate_sni(hostname, cache)  # Nouveau

src/auth/server.moon (modifié)
└─ srv.run()
   ├─ Crée le cache
   └─ Prêt pour SNI (pas encore intégré)
```

### Fichiers supprimés/obsolètes
- `tmp/auth.key` et `tmp/auth.crt` : fichiers statiques
  - Peuvent être supprimés
  - Cleanup : `rm -f tmp/auth*.{key,crt}`
- Temporaires SNI : `tmp/auth_sni_*.{key,crt}`
  - Générés dynamiquement
  - Peuvent s'accumuler ; considérer un cron de cleanup

## Tests

### Unitaires
```bash
make test
```

Inclut tests pour :
- Cache LRU/TTL (insertion, éviction, expiration)
- SNI extraction (records valides/invalides)
- Validation des paramètres `cert_generator`

### E2E (futur)
Sur le filtre OpenWrt :
```bash
# Test 1 : Certificat généré avec px5g
curl -k https://filter.local:33443/

# Test 2 : Certificat en cache
curl -k https://filter.local:33443/ &
curl -k https://filter.local:33443/
# Deuxième requête doit être plus rapide

# Test 3 : Vérifier les fichiers temporaires
ls -lh /custos/tmp/auth_sni_*
```

## Notes de déploiement

### Installation sur OpenWrt
```bash
opkg update
opkg install px5g-wolfssl luajit

# Puis redémarrer CustosVirginum ou pusher `make run`
```

### Nettoyage des fichiers temporaires
```bash
# Cleanup manuel des temporaires vieux de >24h
find /custos/tmp -name "auth_sni_*.key" -mtime +1 -delete
find /custos/tmp -name "auth_sni_*.crt" -mtime +1 -delete

# Ou dans un cron (toutes les 6h)
0 */6 * * * find /custos/tmp -name "auth_sni_*.{key,crt}" -mtime +1 -delete
```

## Roadmap future

1. **SNI extraction au socket level** : extraire SNI AVANT ssl.wrap
2. **Certificats SNI-spécifiques** : CN = SNI hostname
3. **Wildcard SANs** : *.example.com basé sur SNI pattern
4. **Paramètres de cache configurables** : `cfg/auth.yml`
5. **Cleaning scheduler** : suppression auto des temporaires >24h

## Problèmes connus

### px5g génère EC par défaut
- `px5g selfsigned` génère une clé **EC** (Elliptic Curve), pas RSA
- Avantage : plus rapide (~50ms vs ~500ms pour RSA 2048)
- Si RSA est requis : faudrait post-traiter ou modifier px5g

### Fichiers temporaires s'accumulent
- Les contextes TLS WolfSSL exigent des fichiers (pas PEM strings)
- `tmp/auth_sni_*.{key,crt}` créés à la génération
- TTL du cache : 24h max (entries supprimées)
- Fichiers : restent sur disque, peut nécessiter cleanup cron

### WolfSSL ne supporte pas "any" protocol
- Quelquefois, `protocol: "any"` peut générer une erreur
- À tester sur cible réelle
- Fallback : spécifier `protocol: "tlsv1_2"`

## Contacts/Refs

- **px5g** : https://github.com/openwrt/packages/tree/master/utils/px5g-wolfssl
- **WolfSSL** : https://www.wolfssl.com/
- **MoonScript** : https://moonscript.org/
