# AGENTS.md — CustosVirginum

## Projet

**CustosVirginum** est un filtre DNS inline sur pont Linux (bridge), écrit en
MoonScript et exécuté par LuaJIT. Il bloque tout le trafic DNS sauf les domaines
explicitement autorisés, logue les informations L2/L3/L4/L7, et construit
dynamiquement des allowlists nftables au fil des résolutions DNS.

Voir [README.md](README.md) pour l'architecture complète.

---

## Règles agent

- **Ne jamais écrire en dehors du dossier du projet.** Toutes les sorties
  temporaires (fichiers de debug, redirections, captures) doivent être placées
  dans `./tmp/`. Ne jamais utiliser `/tmp/`, `~/.cache/` ou tout autre chemin
  extérieur au projet.

---

## Documentation détaillée

| Sujet | Fichier |
|-------|---------|
| Architecture, workers, queues, pipes, nft sets, superviseur | [.agents/architecture.md](.agents/architecture.md) |
| I/O par worker et formats de messages IPC | [.agents/workers.md](.agents/workers.md) |
| Syntaxe MoonScript, LDoc, pièges de refactoring | [.agents/skills/moonscript/SKILL.md](.agents/skills/moonscript/SKILL.md) |
| Suites de tests et pièges OpenWrt | [.agents/testing.md](.agents/testing.md) |
| Homelab libvirt (3 VMs OpenWrt : via/custos/servus) pour tests E2E | [libvirt/README.md](libvirt/README.md) |

---

## Aide-mémoire rapide

| Besoin | Approche |
|--------|----------|
| Fonctions pures | Module exportant des fonctions |
| Objet avec état | Fonction factory + `setmetatable` |
| Documentation | LDoc `@tparam`/`@treturn` |
| Lib C externe | `ffi.load` + `ffi.cdef` (pas de bridge C) |
| Struct C opaque | `ffi.new("uint8_t[?]", size)` + `ffi.cast` |
| Parsing de paquets | `ffi.cast("const uint8_t*", raw)` + `bit` |
| `$` dans une string | Écrire `$` directement — `\$` est invalide en Lua |
| Rate-limiting de logs | `log.moon` : une entrée par fenêtre de burst pour un même (action, key) |

---

## Système de conditions du filtre

### Interface standard d'une condition

```moonscript
-- src/filter/conditions/from_xxx.moon
(cfg) ->
  (args) ->
    {
      capabilities: { worker: true, nft: true|false, nft_dynamic: false }
      eval: (req) -> ok, msg
      compile_nft: (family) -> expr, err   -- si nft: true
    }
```

### Variantes auto-générées

Définir uniquement `from_xxx.moon` suffit. `compiler_api.load_condition` génère
automatiquement les variantes :

| Condition demandée | Dérivée de | Comportement |
|--------------------|-----------|--------------|
| `from_xxxs {…}` | `from_xxx` | OR sur table Lua |
| `from_xxx_list "nom"` | `from_xxx` | Lit `{lists_dir}/{xxx}/{nom}.txt` |
| `from_xxx_lists {…}` | `from_xxx` | OR sur plusieurs fichiers |

Format fichiers : 1 item/ligne, ignores vides et `#commentaires`.
`lists_dir` se configure via `cfg.lists_dir` ou `cfg.filter.lists_dir` (défaut : `/etc/custos/lists`).

### `requires_auth` dans les capabilities

Pour qu'une condition déclenche les sous-chaînes nft d'authentification
(sets `_auth_mac`, `_auth_ip4`, `_auth_ip6`), déclarer dans ses capabilities :

```moonscript
capabilities: { worker: true, nft: false, requires_auth: true }
```

`nft_compiler` lit ce flag dans `conditions_meta` — aucun nom hardcodé n'est
nécessaire. `from_user.moon` le déclare nativement ; tout nouveau type d'auth
suit la même convention sans toucher à `nft_compiler`.

### Ajouter un nouveau type de condition

1. Créer `src/filter/conditions/from_mytype.moon` (interface standard ci-dessus)
2. Compiler : `moonc -o lua/filter/conditions/from_mytype.lua src/filter/conditions/from_mytype.moon`
3. Les variantes `from_mytypes`, `from_mytype_list`, `from_mytype_lists` sont
   disponibles immédiatement via l'auto-génération — aucun autre fichier à créer.

---

## Interdictions absolues

- **`class`, `extends`** (syntaxe MoonScript orientée objet) → jamais : utiliser `setmetatable`
- **`end`, `local`, `then\n`...** (syntaxe Lua, fautive en Moonscript) → jamais
- **`require "moon"`** → le code compilé doit être indépendant de la lib MoonScript
- **`socket.bind "*"`** dans le worker AUTH → ne bind qu'IPv4 ; utiliser deux
  sockets distincts + `socket.select`
- **`\` au lieu de `.`** pour appeler des fonctions de module (ex. `nft_sessions`) →
  injecte la table comme premier argument

---

## px5g Migration — Dynamic TLS Certificate Generation

See [.agents/px5g_migration.md](.agents/px5g_migration.md) for full documentation on the migration from static (openssl-based) to dynamic (px5g-based) certificate generation with LRU/TTL caching.

**New modules**:
- `src/auth/cert_generator.moon` — px5g wrapper for dynamic cert generation
- `src/auth/cert_cache.moon` — LRU cache with TTL for generated certs
- `src/auth/sni_extractor.moon` — TLS ClientHello SNI parser (RFC 5246/6066)

**Modified modules**:
- `src/auth/cert.moon` — Added `load_or_generate_sni()` for SNI-aware certs
- `src/auth/server.moon` — Cache initialization on AUTH server startup
