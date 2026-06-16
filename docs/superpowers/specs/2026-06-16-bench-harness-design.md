# Harnais de stress test / benchmark du filtre — Design

Date : 2026-06-16
Statut : approuvé

## Objectif

Fournir un harnais permanent pour mesurer les performances du filtre DNS, en
deux volets complémentaires :

- **Micro-bench in-process** : pérennise les benchs jetables de `tmp/` (parsing
  paquet, lookups, décision filtre) en module structuré, ns/op + KB alloués,
  déterministe et sans réseau.
- **Charge DNS bout-en-bout** : générateur LuaJIT pur qui inonde le filtre de
  requêtes DNS réelles et mesure QPS soutenu, latences p50/p95/p99, taux de
  drop/timeout, à travers le pipeline complet NFQUEUE→workers→nft→upstream.

Sortie : rapport texte + JSON dans `tmp/bench/`, avec comparaison optionnelle à
une baseline sauvegardée (deltas %). **Pas de notion d'échec** : outil de mesure
pour comparer avant/après un changement.

## Structure des fichiers

```
tools/bench/
  run.moon      # orchestrateur + CLI (parse args, dispatch, rapport, baseline)
  micro.moon    # volet 1 : micro-bench in-process (ns/op + KB alloc)
  load.moon     # volet 2 : générateur de charge DNS LuaJIT (UDP/FFI)
  report.moon   # formatage rapport texte + (dé)sérialisation baseline JSON
  README.md
```

Compilés vers `lua/tools/bench/*.lua` comme le reste du projet (`moonc`).

Cibles Make :
- `make bench` — micro-bench par défaut (lançable partout, aucune infra).
- `make bench-micro` — volet micro seul.
- `make bench-load` — volet charge (exige le homelab ou un hôte cible).

## Volet 1 — micro-bench in-process (`micro.moon`)

Structure les benchs `tmp/bench*.lua` existants. Pour chaque cas :
`collectgarbage("collect")` avant, mesure `os.clock()` sur N itérations, capture
le delta `collectgarbage("count")`.

Cas couverts (jeu représentatif allow + block) :
- parsing paquet `nfq.packet.parse_packet`
- parsing L3/L4/L7 `ipparse` (ip4 / udp / dns)
- lookup `filter.lib.bin48` + xxhash
- décision filtre `filter.decide`

Sortie : liste de `{ name, ns_per_op, kb_alloc }`.

## Volet 2 — charge DNS bout-en-bout (`load.moon`)

Générateur LuaJIT pur, sockets UDP via le FFI socket déjà présent dans le
projet.

- Pool de domaines (allow + block) chargé d'un fichier `--domains FILE` ou jeu
  par défaut intégré.
- Envoi non bloquant à débit cible (`--rate`, ou « au plus vite ») pendant
  `--duration` secondes.
- Horodatage à l'émission et à la réception, corrélation par **txid DNS** →
  agrégation en latences p50/p95/p99, QPS soutenu, taux de drop/timeout.
- Cible paramétrable `--target host:port`.

**Point d'exécution** : sur le homelab, le générateur est déployé **sur la VM
`via`** (client) et tape à travers le pont `custos` — cohérent avec
`make test-e2e` et réaliste (traverse vraiment le bridge). En mode hôte distant,
il est poussé via SSH (comme `make test-openwrt HOST=...`). Le générateur est
identique quelle que soit la cible ; seul le point d'exécution change.

Sortie : `{ qps, sent, received, dropped, timeouts, p50, p95, p99 }`.

## Orchestrateur & sortie (`run.moon` + `report.moon`)

CLI :
- `--micro` / `--load` / (défaut : micro seul)
- `--target host:port`, `--duration N`, `--rate N`, `--domains FILE`
- `--save-baseline` : enregistre `tmp/bench/baseline.json`

Comportement :
- Écrit un rapport texte horodaté dans `tmp/bench/report-<ts>.txt` + un JSON
  structuré `tmp/bench/result-<ts>.json`.
- Sans `--save-baseline`, si `tmp/bench/baseline.json` existe, le rapport affiche
  les deltas % par métrique (ns/op, QPS, latences).
- `--save-baseline` écrit/écrase la baseline depuis le run courant.

`report.moon` :
- format texte aligné (réutilise le style de `tmp/bench_hotpath.lua`).
- (dé)sérialisation JSON de la baseline.
- calcul des deltas % entre deux résultats.

## Tests (Definition of Done)

Tests unitaires Busted (`tests/unit/bench/*_spec.moon`), sans réseau :
- parsing CLI (`run.moon`) : flags reconnus, valeurs par défaut.
- agrégation de latences : percentiles p50/p95/p99 sur échantillons connus.
- (dé)sérialisation baseline + calcul de deltas %.
- génération d'un paquet de requête DNS valide (`load.moon`) : entête, qname
  encodé, txid — vérifié en le reparsant via `ipparse`/`nfq.packet`. Socket
  mocké pour isoler l'I/O.

Volet charge réelle : couvert par un smoke e2e homelab (run court → métriques
cohérentes), `skip` si homelab absent (convention existante).

## Documentation (Definition of Done)

- `.agents/testing.md` : ligne(s) dans le tableau des suites + section bench.
- `doc/CHEATSHEET.md` : usage rapide `make bench` / `bench-load`.
- `tools/bench/README.md` : CLI, métriques, baseline, déploiement sur `via`.

## Hors périmètre (YAGNI)

- Pas de seuils d'échec / garde-fou CI (rapport seul, choix utilisateur).
- Pas d'outil DNS-bench externe (générateur maison, portable OpenWrt).
- Pas de graphes / export Prometheus.
