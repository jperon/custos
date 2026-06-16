# Harnais de benchmark / stress test

Mesure les performances du filtre DNS selon deux volets, écrit un rapport dans
`tmp/bench/`, et compare optionnellement à une baseline sauvegardée (deltas %).

## Volets

| Volet | Module | Mesure | Réseau ? |
|-------|--------|--------|----------|
| Micro-bench | `bench.micro` | ns/op + KB alloués sur les hot-paths (parsing ipparse, `bin48`, xxhash) | non |
| Charge DNS | `bench.load` | QPS soutenu, latences p50/p95/p99, pertes/timeouts | oui (UDP/53) |

## Usage rapide

```sh
make bench                       # micro-bench seul (aucune infra)
make bench-micro ITERS=2000000   # idem, plus d'itérations
make bench-load TARGET=10.0.0.2  # charge contre un résolveur (port 53 défaut)
make bench-load TARGET=10.0.0.2:5353 DURATION=30 RATE=500 DOMAINS=tmp/d.txt
make bench-micro SAVE_BASELINE=1 # enregistre tmp/bench/baseline.lua
```

Variables Make : `ITERS`, `TARGET=host[:port]`, `DURATION` (s), `RATE` (req/s,
vide = au plus vite), `DOMAINS` (fichier 1 domaine/ligne, `#` = commentaire),
`SAVE_BASELINE=1`.

## CLI directe

```sh
LUA_PATH="lua/?.lua;lua/?/init.lua;;" luajit lua/bench/cli.lua \
  --all --target 10.0.0.2:53 --duration 10 --rate 1000 --iters 1000000
```

Flags : `--micro` / `--load` / `--all`, `--target host[:port]`, `--duration N`,
`--rate N`, `--iters N`, `--max-queries N`, `--domains FILE`, `--save-baseline`.
`--load` seul ⇒ charge uniquement ; sans flag ⇒ micro seul.

## Sorties

- `tmp/bench/report-<ts>.txt` — rapport texte aligné (avec deltas si baseline).
- `tmp/bench/result-<ts>.lua` — résultat rechargeable (`return {…}`).
- `tmp/bench/baseline.lua` — baseline (écrite par `--save-baseline`).

Sans `--save-baseline`, si `baseline.lua` existe, le rapport affiche les
variations % par métrique. **Aucune notion d'échec** : c'est un outil de mesure.

## Cible homelab (charge réelle)

Conformément à `make test-e2e`, le générateur est destiné à tourner **sur la VM
`via`** (client) en tapant l'IP de `custos` à travers le pont — c'est le chemin
réaliste qui traverse le pipeline NFQUEUE→workers→nft→upstream. En local, on peut
viser n'importe quel résolveur (`TARGET=1.1.1.1`) pour valider le générateur.

## Conception

- `report.moon` — percentiles, (dé)sérialisation baseline (table Lua), deltas %,
  rendu texte. Fonctions pures.
- `micro.moon` — `bench(name, iters, fn)` + cas standards best-effort (un module
  absent ⇒ cas `skipped`, pas d'échec).
- `load.moon` — `encode_query` (encodeur DNS wire pur) + `run` avec client UDP
  non bloquant **injectable** (`client_factory`) pour les tests sans réseau.
- `run.moon` — `parse_args` + `main` (orchestration, fichiers, baseline).
- `cli.moon` — point d'entrée script (`luajit lua/bench/cli.lua …`).

Tests : `tests/unit/bench/*_spec.moon`.
