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

### Definition of Done (obligatoire avant de conclure une tâche)

Une tâche n'est **jamais** terminée tant que les trois conditions suivantes ne
sont pas vérifiées et constatées (pas supposées) :

1. **Couverture de tests.** Tout code ajouté ou modifié doit être couvert par des
   tests. En toute fin d’un développement important, vérifier avec `make
   coverage-quick` (rapport dans `tmp/coverage_quick/`, ordre de grandeur par
   échantillonnage, ~20 min sur toute la suite). `make coverage` (luacov,
   ligne-par-ligne exhaustif) est réservé à un chiffre exact sur un module
   isolé (`tests/unit/<module>` ciblé) : sur la suite complète il est ~4x plus
   lent et a déjà échoué à écrire ses stats en fin de run (cf. § Corrections
   d'audit 2026-07-16). Une branche d'erreur non couvrable en unitaire doit
   l'être par un mock (cf. `tests/unit/auth/cert_generator_spec.moon`) ou par
   les tests e2e.
2. **Documentation à jour.** Mettre à jour la doc impactée par le changement
   (`AGENTS.md`, `.agents/*`, `README.md`, `doc/CONFIG.md`, `doc/CHEATSHEET.md`,
   etc.). Du code sans sa doc à jour n'est pas livrable.
3. **`make test` ET `make test-e2e` à 100 %.** Les deux suites doivent passer
   intégralement (`0 failed`). Lancer effectivement les commandes et lire le
   total ; ne jamais déclarer un succès non exécuté. `make test-e2e` exige le
   homelab libvirt provisionné (cf. [.agents/testing.md](.agents/testing.md) et
   [libvirt/README.md](libvirt/README.md)) ; quand le provisioning est déjà fait,
   il ne nécessite pas root. Toujours essayer `make test-e2e` à la fin des modifications,
   sans utiliser au préalable les outils de libvirt, mais signaler si cela échoue.

---

## Documentation détaillée

| Sujet | Fichier |
|-------|---------|
| Architecture, workers, queues, pipes, nft sets, superviseur | [.agents/architecture.md](.agents/architecture.md) |
| I/O par worker et formats de messages IPC | [.agents/workers.md](.agents/workers.md) |
| Syntaxe MoonScript, LDoc, pièges de refactoring | [.agents/skills/moonscript/SKILL.md](.agents/skills/moonscript/SKILL.md) |
| Suites de tests et pièges OpenWrt | [.agents/testing.md](.agents/testing.md) |
| Harnais de benchmark / stress test (`make bench`, `bench-load`) | [src/bench/README.md](src/bench/README.md) |
| Référence complète de toutes les clés de configuration | [doc/CONFIG.md](doc/CONFIG.md) |
| Aide-mémoire rapide pour les mainteneurs | [doc/CHEATSHEET.md](doc/CHEATSHEET.md) |
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
| Rate-limiting de logs | `log.moon` : empreinte (niveau, action, champs d'identité) dans une table mmap partagée entre processus ; `suppressed=N` à la réémission ; `rl_stats()` expose `shared`/`saturated` |
| Concaténer en boucle | Accumuler dans une table puis `table.concat` (jamais `..=` en boucle) |
| Log DEBUG dans un hot-path | Garder avec `log.level_enabled "DEBUG"` au call-site : sans ça la closure (thunk) est allouée par paquet même quand le niveau est filtré |
| `require` dans un hot-path | Mémoïser le module à la construction (factory/startup), jamais un `require` par paquet (≈150 ns/appel) |
| Piège `a\match "x" or b` | Parenthéser : `(a\match "x") or b` — sans ça l'`or` est avalé par l'argument et le repli ne s'applique jamais |
| Détecter l'interface bridge | `lib.bridge_detect` (sysfs `/sys/class/net/*/bridge`, busybox-compatible ; choix du bridge le plus peuplé). **Jamais** `ip … type bridge` (non supporté par busybox). `auth.bridge_ifname`/env `BRIDGE_IFNAME` priment (env validé par `valid_name`, valeur invalide ignorée avec warn → détection sysfs) ; `main.moon` warn `bridge_ifname_not_found` si la config force une interface absente |

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

## Compatibilité `os.execute` (Lua 5.1 / Lua 5.2+ `LUA52COMPAT`)

Le retour de `os.execute` dépend de la build de LuaJIT :

| Build | Succès | Échec |
|-------|--------|-------|
| Lua 5.1 / LuaJIT standard | `0` (number) | code ≠ 0 (number) |
| Lua 5.2+ / LuaJIT `LUA52COMPAT` (ex. Ubuntu 26.04) | `true, "exit", 0` | `nil, "exit", code` (ou `"signal"`) |

Conséquence : **ne jamais tester `ret == 0` seul** — sous `LUA52COMPAT` un
succès (`true`) est alors traité comme un échec. Utiliser `lib.os_exec.exec_ok`
(`src/lib/os_exec.moon`), qui teste `ret == 0 or ret == true`, ou le test
inline équivalent.

Sites concernés (statut de retour testé) : `filter/updater_io.moon`
(`download_file`, `ensure_dir`, `ensure_parent_dir` — le bug initial : tout
téléchargement réussi finissait en « curl échoué » et l'updater sortait en
code 1), `nft_rules.apply` (application du template via `nft -f`),
`nft_extra_rules.apply_from_config` (sonde de la chaîne `forward`, sinon
ré-application systématique), `sync/apply.moon` (`--reload`), `auth/cert_generator`,
`webui/handlers/lists` (`write_list_file`) et `tools/classifier/common` (commit
git). Les helpers I/O de l'updater sont isolés dans `filter/updater_io.moon`
(le script `filter/updater.moon` s'exécute au chargement, donc n'est pas
testable directement) et couverts par `tests/unit/filter/updater_io_spec.moon`
dans les deux sémantiques via un stub de `os.execute`.

## Documents détaillés (à lire à la demande)

Ce fichier est relu à chaque requête : il ne contient que le noyau. Avant de travailler sur un sujet, lis le document correspondant. Toute nouvelle note (journal, post-mortem, état des lieux, description de module) s'ajoute dans le document du sujet sous `docs/agents/`, pas ici ; ici, au plus une ligne d'index. Jamais d'import `@chemin`.

- `docs/agents/divers.md` — ipparse (sous-module moontastik), Synchronisation de configuration (`sync/`), UI d'installation redbean (`.init.moon`), px5g Migration — Dynamic TLS Certificate Generation ; à lire avant de toucher à ipparse/moontastik, à la synchronisation de configuration, à l'UI redbean ou à la génération de certificats TLS (px5g).
- `docs/agents/filtre.md` — Système de conditions du filtre, Anti-rafale des redirections captives (`src/worker_captive.moon`), Enforcement SNI (`src/worker_tls.moon`), Strip DNS contextuel à la chaîne CNAME (`dns_strip.follow_cname`) ; à lire avant de modifier les conditions du filtre, l'anti-rafale captive, l'enforcement SNI ou le strip DNS sur chaîne CNAME.
- `docs/agents/doh.md` — Modules DoH (`src/doh/`) ; à lire avant de modifier les modules DoH.
- `docs/agents/auth.md` — Structure du worker AUTH (`src/auth/`), Résilience du portail captif aux blips réseau (`src/auth/portal_client.js`) ; à lire avant de modifier le worker AUTH ou la résilience du portail captif.
- `docs/agents/webui.md` — Interface admin web (`src/webui/`) ; à lire avant de modifier l'interface admin web.
- `docs/agents/audits.md` — Corrections d'audit (2026-07-16), Corrections d'audit (2026-11-11) ; à lire avant de reprendre un point des corrections d'audit (2026-07-16 / 2026-11-11).
