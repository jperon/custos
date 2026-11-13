# Harnais de benchmark / stress test

Mesure les performances du filtre DNS selon deux volets, écrit un rapport dans
`tmp/bench/`, et compare optionnellement à une baseline sauvegardée (deltas %).

## Volets

| Volet | Module | Mesure | Réseau ? |
|-------|--------|--------|----------|
| Micro-bench | `bench.micro` | ns/op + KB alloués sur les hot-paths (parsing ipparse, `bin48`, xxhash) | non |
| Charge DNS | `bench.load` | QPS soutenu, latences p50/p95/p99, pertes/timeouts | oui (UDP/53) |
| Profilage hot path | `bench.hotpath` | µs/paquet + profils `jit.profile`/`jit.v`/`jit.dump` des handlers réels des workers | non |
| CPU worker nft | `bench.nft_cpu` | CPU par ligne et par tour de boucle du worker `nft` réel (`nft` stubbé) | non |

## Usage rapide

```sh
make bench                       # micro-bench seul (aucune infra)
make bench-micro ITERS=2000000   # idem, plus d'itérations
make bench-load TARGET=10.0.0.2  # charge contre un résolveur (port 53 défaut)
make bench-load TARGET=10.0.0.2:5353 DURATION=30 RATE=500 DOMAINS=tmp/d.txt
make bench-micro SAVE_BASELINE=1 # enregistre tmp/bench/baseline.lua
make bench-hotpath               # profilage CPU du hot path (voir ci-dessous)
```

Variables Make : `ITERS`, `TARGET=host[:port]`, `DURATION` (s), `RATE` (req/s,
vide = au plus vite), `DOMAINS` (fichier 1 domaine/ligne, `#` = commentaire),
`SAVE_BASELINE=1`.

## Profilage du hot path (`make bench-hotpath`)

Rejoue en boucle, **sans NFQUEUE ni réseau**, les handlers réels des workers
(`handle_question`, `handle_response` — dont le cycle complet du second avis
réponse A + réponse validateur B) sur des paquets IPv4/UDP fabriqués, avec des
stubs minimaux pour `libnfq` (payload factice, verdicts comptés), `nft_queue`
(tube vidé après chaque lot, sans ACK) et `raw_send` (aucun socket). Le filtre
est réel (`filter.load`) et la transaction `pending` est produite par une
sonde `handle_question` réelle. Rapport : `tmp/prof/hotpath.md` ; détails et
interprétation : `docs/agents/perf.md` §18.

```sh
make bench-hotpath                          # mesures (100 000 iters × 3, min retenu)
make bench-hotpath HP_PROFILE=f HP_DURATION=12   # profil jit.profile par fonction
make bench-hotpath HP_PROFILE=l HP_DURATION=12   # profil jit.profile par ligne
make bench-hotpath HP_JIT_V=tmp/prof/jitv.txt HP_JIT_DUMP=tmp/prof/jitdump.txt
make bench-hotpath HP_ONLY=so_cycle HP_ITERS=200000
make bench-hotpath HP_TASKSET=5             # épingle le banc sur un cœur
make bench-hotpath HP_ONLY=response HP_EXTRA="--gc-pause 300 --gc-stepmul 400"  # A/B du GC
```

Variables : `HP_ITERS`, `HP_CHUNK` (64 = `MAX_BATCH_PKTS`), `HP_WARMUP`,
`HP_DURATION`, `HP_REPEAT` (passages chronométrés dont on garde le minimum),
`HP_PROFILE=f|l`, `HP_ONLY=<cas>`, `HP_JIT_V=<fichier>`,
`HP_JIT_DUMP=<fichier>`, `HP_TASKSET=<cpu>`, `HP_EXTRA` (flags bruts).
Flags GC (via `HP_EXTRA`) : `--gc-pause`, `--gc-stepmul`, `--gc-idle-step`,
`--gc-max-heap`. Le rapport porte le réglage appliqué et une colonne
`tas max (Kio)` (`collectgarbage "count"` relevé après chaque lot), ce qui
permet de comparer coût par paquet et empreinte entre deux réglages.
Cas disponibles : `question`, `ipc_drain`, `response`, `so_a`, `so_cycle`,
`setup_control` (`--list`). Le banc **échoue** (code 1) si le chemin mesuré n'est
pas celui attendu (mauvais code retour, verdict manquant) : une mesure ne doit
jamais porter sur un autre chemin que celui décrit.

Le cas `question` appelle le hook de fin de lot du worker questions
(`on_batch_end`, exposé comme `on_batch_end_q`) après chaque lot de `HP_CHUNK`
paquets : c'est là que la production vide les tampons d'écriture des pipes
events/learn (cf. `docs/agents/perf.md` §19), sinon la mesure exclurait ces
écritures. Sur une version sans tampon, le hook est absent et l'appel est un
no-op — la comparaison avant/après reste valable.

**Machine vivante** : le banc force `config.nft.table` à un nom inexistant —
`filter.load` appelle `ip_whitelist.init`, qui FLUSH les sets
`ip*_dest_whitelist` de la table, et avec la vraie table ce flush viderait le
ruleset d'un hôte où custos tourne. Aucune file NFQUEUE n'est ouverte
(`run_queue` neutralisé) et `raw_send` est stubé : aucun paquet n'est émis.
Seules écritures : `./tmp/prof/`.

## CPU du worker nft (`make bench-nftcpu`)

Isole le CPU du **worker `nft` seul** : `worker_nft.run` réel dans un enfant
`fork`, tube réel, `nft.run_cmd` remplacé par un stub (`true`). Les lignes sont
produites par `nft_queue.build_line` (16 par réponse : `ip4` + `mac4` pour
chacun des 8 A, comme `response_inject`), le débit est piloté en
réponses/s, et le CPU de l'enfant est lu dans `/proc/<pid>/stat` sur trois
fenêtres : charge, temps mort (`poll` bloqué) et total jusqu'à EOF.

Le paramètre `--turns` (réponses par écriture) règle le nombre de **tours de
boucle** à débit de lignes constant. La différence de CPU/s entre `--turns 1`
et `--turns 8` donne le coût d'un tour (`poll` + `read` + `gc.guard!` +
`gc.idle!`) sans modifier le code mesuré : c'est ce qui a isolé la régression
de GC par lot de `docs/agents/perf.md` §24.

```sh
make bench-nftcpu                                  # 500 réponses/s, tours 1 et 8
make bench-nftcpu NP_EXTRA="--gc-idle-step 0"      # A/B d'un réglage GC
make bench-nftcpu NP_TURNS=1 NP_DURATION=30 NP_REPEAT=5
```

Variables : `NP_QPS`, `NP_DURATION`, `NP_IDLE`, `NP_REPEAT`, `NP_TURNS`
(ex. `1,8`), `NP_TASKSET`, `NP_EXTRA`. Flags : `--qps`, `--lines`, `--turns`,
`--duration`, `--idle`, `--repeat`, `--alloc` (octets/ligne, GC arrêté),
`--alloc-responses`, `--legacy-gc` (version sans `lib.gc_tune` : applique
`runtime.gc_pause`/`gc_stepmul` comme l'ancien `main.moon`), `--gc-pause`,
`--gc-stepmul`, `--gc-idle-step`, `--gc-max-heap`, `--tag`. Pour comparer une
autre version, la placer en tête de `LUA_PATH` (ex. `git archive <commit> lua`),
le banc restant résolu depuis ce dépôt. Sorties : `tmp/bench/nftcpu/`.

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
- `hotpath.moon` — micro-banc de profilage du hot path (paquets, stubs libnfq /
  IPC / raw_send, cas de mesure, `jit.profile`, rapport) ; `hotpath_cli.moon` —
  son point d'entrée script.
- `nft_cpu.moon` — banc CPU du worker nft (worker réel forké, tube réel, `nft`
  stubbé, mesures `/proc`, coût par ligne et par tour, allocation) ;
  `nft_cpu_cli.moon` — son point d'entrée script.

Tests : `tests/unit/bench/*_spec.moon`.
