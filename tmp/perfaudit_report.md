# Audit de performance — chemin aller/retour d'une requête DNS (2026-11-12, branche `d-perfaudit`)

**Périmètre** : lecture et mesure uniquement. **Aucune modification de code**, aucun
redémarrage, aucune écriture sur `custos.lan`, aucun `/etc/custos` lu, aucune
capture AF_PACKET, aucun `perf` (absent de la cible, rien installé), aucun
`make test-e2e`.

**Question à trancher** : pourquoi un client **authentifié** charge-t-il davantage
Custos qu'un client non authentifié, alors qu'on devrait « voir moins de paquets
à réécrire » et que l'attente de l'amont devrait permettre de traiter en
pipeline les paquets arrivés entre-temps ?

Sources : code de la branche courante (citations `fichier:ligne`), harnais
`tmp/tune/` (réutilisé tel quel : `dnsload4.py`, `counters.sh`, `analyse.py`),
scripts complémentaires `tmp/perfaudit/` (ignorés par git, comme `tmp/tune/`),
données brutes `tmp/perfaudit/results/` (ignorées par git), et
`docs/agents/perf.md` (§13 = campagne non authentifiée, §15 = campagne
authentifiée).

---

## 1. Méthode de mesure

- **Cible** : `custos.lan` (10.35.1.254, OpenWrt, aarch64 ×4, noyau 6.12.74,
  workers `dns-q0/q1`, `resp-q14/q15`, `nft`, `doh` — plage `0-1`/`14-15`).
  **Générateur** : `servus.lan` (10.35.1.2), `python3 dnsload4.py`.
- **Sonde d'authentification avant CHAQUE phase** (obligatoire) :
  `dig +short @10.35.1.1 controlplane.tailscale.com A` rend **8 adresses**
  (192.200.0.10x) → `servus` authentifié (`runphase2.sh` échoue sinon, code 2).
  Vérifié aussi : sets `authenticated_ips`/`authenticated_macs` = 1 élément
  chacun (`results/*_sets_before.txt`).
- **Paliers** (30 s, 2 destinations `10.35.1.1,10.35.4.1` comme en §15,
  profil `mixed` = 30 % NX / 40 % Tailscale / 30 % vpn) :
  `repos` (20 s sans générateur), **200 q/s**, **350 q/s**. Rien au-delà.
  Repos vérifié avant chaque phase (profondeur 0 + compteurs figés 3 s),
  un seul générateur, sonde unique après.
- **Relevés** (lecture seule) : CPU par worker `utime`/`stime`
  (`/proc/<pid>/stat`, HZ≈97-99 dérivé de `/proc/stat`), changements de
  contexte (`/proc/<pid>/status`), **distribution de syscall courant à 20 Hz**
  (`/proc/<pid>/syscall`, `tmp/perfaudit/syscalls.pl`), `wchan`/`stack` toutes
  les 3 s, CPU `ksoftirqd/*`, profondeurs/compteurs NFQUEUE (1 Hz), compteurs
  nft, **compteurs d'éléments de sets uniquement** (`tmp/perfaudit/setcounts.sh`),
  journal `logread` (lignes `response_dns_benchmark`).
- **Limite d'instrumentation** : `perf` **absent** (`command -v perf` → rien),
  rien installé. `wchan` **vide** et `stack` non symbolisés (adresses brutes) :
  `/proc/kallsyms` n'existe pas sur la cible et `wchan` est sans effet sans
  kallsyms — les échantillons sont conservés dans
  `results/*_syscalls.log` (`WCHAN`/`STACK`) mais sont inexploitables en symboles.
  La « où ils attendent » repose donc sur `/proc/<pid>/syscall` (cf. §4.3).
- **Comparaison non authentifiée** : impossible **sans modification** (le client
  `servus` est rafraîchi en continu par son portail ; le dé-authentifier serait
  une modification d'état, et il n'existe aucune autre source non authentifiée
  commandable). Comparaison faite aux chiffres de `perf.md` §13/§15, comme
  autorisé.

### Reproductibilité

```
tmp/perfaudit/runphase2.sh <RATE> mixed <DUR> <TAG> 10.35.1.1,10.35.4.1
python3 tmp/perfaudit/extract.py   results/<base>    # CPU utime/stime, ctxt, ksoftirqd, idle
python3 tmp/perfaudit/sysanalyse.py results/<base>_syscalls.log
python3 tmp/perfaudit/decomp.py     <sampler> <bench> <SE> <EE>
python3 ../tune/analyse.py          results/<base>   # harnais d'origine
```

Résultats d'analyse : `results/{rest2,a200,a350}*_extract.txt`,
`*_sys.txt`, `*_decomp.txt`, `*_analyse.txt`.

---

## 2. Tracé complet du chemin, caractère synchrone/bloquant

### 2.1 Question (file `0-1`, `worker_questions`)

| # | Étape | Code | Synchrone/bloquant ? | Paquet suivant peut-il avancer pendant ce temps ? |
|---|-------|------|----------------------|--------------------------------------------------|
| 1 | Lecture netlink **bloquante** puis drain non bloquant du lot (≤64) | `src/nfq_loop.moon:201` (read), `:206-227` (drain + `on_batch_end`) | Oui, lecture bloquante **en attente de données** ; le drain est non bloquant | Oui : les paquets suivants restent dans la file noyau, lus au tour suivant |
| 2 | Parse L2/L3/L4/L7 | `src/worker_questions.moon:238-264` | Non (CPU pur) | Non (worker mono-thread) |
| 3 | `user_for_mac` (session) | `:378` → `src/auth/sessions.moon:158-164,286-307` | **Non** : cache 5 s à l'intérieur, `statx` uniquement si la signature a changé ou sur miss (`reload_needed`, `:182-185`) | — |
| 4 | `filter.decide_meta` (conditions) | `:393` → `src/filter/rule.moon:176-198,223-233` | Non (évaluation en mémoire ; `from_users` relit la session via le même cache) | — |
| 5 | Log ALLOW/BLOCK + métriques | `:408-415` | Non : `libc.write` stdout ~36-47 µs p50 (`log_write_us`, mesuré), pas de fsync (`src/log.moon:515`) | — |
| 6 | `write_event` (1 ligne/vers events) | `:421` → `:163-179` | 1 écriture pipe ≤ `PIPE_BUF` atomique, EAGAIN ignoré | — |
| 7 | `write_learn_msg` (22 o vers mac_learner) | `:294` → `:131-143` | 1 écriture pipe | — |
| 8 | Écriture IPC vers **tous** les workers réponses | `:453-457` → `src/ipc.moon:170-186,114-130` | **Potentiellement bloquant** : EAGAIN → jusqu'à **5 × 20 ms** de `nanosleep` (`IPC_WRITE_RETRY_COUNT=5`, `src/ipc.moon:27,125`) ; un destinataire déjà saturé n'est tenté qu'une fois non bloquant (`:147-186`) | Bloqué pendant les 5×20 ms ; **jamais observé en mesure** (0 `ipc_write_*`, 0 `nanosleep` échantillonné) |
| 9 | Second avis : duplication vers le validateur (socket RAW) | `:473-476` → `:108-121` | Non : `sendto` best-effort, ne bloque jamais | Oui |
| 10 | **Verdict `NF_ACCEPT`** | `src/worker_questions.moon:478`, posé par `src/nfq_loop.moon:104-105` | — | — |

**Réponse : le verdict d'une question n'attend ni l'amont, ni aucun ACK nft.**
Il n'attend que l'écriture IPC (au pire 5×20 ms si le tube est plein, cas non
observé). Le paquet est forwardé par le noyau **avant** que la réponse existe :
l'« attente amont » a donc bien lieu **hors** du chemin critique des questions —
l'intuition de l'utilisateur est exacte sur ce point.

### 2.2 Réponse (file `14-15`, `worker_responses`)

| # | Étape | Code | Synchrone/bloquant ? | Paquet suivant peut-il avancer ? |
|---|-------|------|----------------------|----------------------------------|
| 1 | `drain_pipe` du tube question (à chaque paquet **et** via `extra_rfds`) | `src/worker_responses.moon:1027`, `:1408-1423` | Non (non bloquant) | — |
| 2 | Parse + `user_for_mac` | `:1045`, `:1082` | Non | — |
| 3 | Appariement `pending` | `:1113` | Non (table mémoire) | — |
| 3b | Retry d'appariement si miss | `:1120` → `:526-551` | **Oui, `nanosleep` 20 ms/tentative** mais plafonné à **100 ms/s** par budget (`RETRY_BUDGET_MS`, `:232`) | Bloqué pendant le sommeil ; budget consommé : 0 en mesure (0 `response_matched_after_retry`, 0 `ipc_retry_attempts>0`) |
| 4 | Verdict **refusé** (REFUSED/NX + EDE) | `:1266-1292` | **Verdict immédiat** (patch payload + `nfq_set_verdict`), ni différé ni ACK | — |
| 5 | Second avis : si `validate`, **parquage de A** (verdict NFQUEUE non posé) | `:1314-1322` → `src/second_opinion.moon:161-181` | **A attend B ou le budget de 80 ms** (`budget_ms`, `:127` ; `idle_ms` armé `src/worker_responses.moon:1433,1437`) | Le worker continue de lire, **mais le paquet A garde sa place dans la file noyau en attendant son verdict** (`queue_total` compte les paquets sans verdict) |
| 6 | `finalize_a` : callbacks `run_on_response` (strip…) | `:714` | Non | — |
| 6b | `maybe_dynamic_strip` (miss cache) : socket AF_UNIX **par réponse** (socket+connect+send+recv+close) | `:723-729` → `src/mac_learner_ipc.moon:53-78,157` | Oui si actif (gating `chain_strip_enabled`, `:93,723`) ; **activité non déterminable** sans `/etc/custos` (comme `perf.md` §9) | Bloqué le temps de l'échange local (~µs-ms) |
| 7 | Injection nft : **1 `enqueue` par élément** (8 A × `ip4`+`mac4` = 16 lignes pour `r_utilisateurs`), **1 `write()` syscall par ligne** | `:767` → `src/response_inject.moon:106-131` → `src/nft_queue.moon:158-165,108-121` | Écriture pipe non bloquante (repli 3×10 ms si plein, `:22,119`) | Oui |
| 8 | `settle` : verdict **différé** en fin de lot | `:803` → `:473-482` | Non | — |
| 9 | **`flush_deferred` : UN `wait_ack` par lot NFQUEUE** (ACK de la plus grande séquence, budget **150 ms**, poll 5 ms) | `:446-461` → `src/nft_queue.moon:210-248` (`ACK_TIMEOUT_MS=150` l.11, `WAIT_POLL_MS=5` l.12) | **OUI, bloquant.** Pendant l'attente, `wait_ack` ne surveille **que le tube ACK** (`:218-225`) et `on_wait` ne draine **que le tube question** (`src/worker_responses.moon:455`) : **le socket netlink des réponses n'est PAS lu** → les réponses suivantes s'empilent dans la file noyau (`queue_total`), mesuré | **Non** : ni lecture netlink, ni traitement d'un paquet suivant |
| 10 | Verdicts du lot (1 netlink write par verdict) | `:456-457` | Non | — |
| 11 | (Après verdict) appel `worker_nft` : drain pipe ≤64 lignes, **1 transaction libnftables in-process par lot** (`nft_run_cmd_from_buffer`, **pas de sous-processus**) puis **1 ACK par worker producteur** | `src/worker_nft.moon:187-241`, `:135`, `src/nft.moon:31-32`, `src/worker_nft.moon:69-74,159-165` | Synchrone **dans le processus nft** (le worker réponses attend l'ACK via le tube dédié) | Les autres producteurs continuent d'écrire le pipe nft |

**Réponse : oui, le verdict d'une réponse attend l'ACK nft** — depuis le
correctif « ACK par lot » (`perf.md` §7), **une fois par lot NFQUEUE** (et non
plus une fois par réponse), avec repli fail-open à 150 ms. Les exceptions :
réponses **refusées** (verdict immédiat, étape 4) et réponses **`dnsonly` /
`skip_nft`** (`records_to_add = 0` → `need_ack` faux, `:803`, cf.
`perf.md` §4.2).

### 2.3 Ce que la boucle par lot signifie concrètement

`nfq_loop` : lecture bloquante → traitement **intégral** (étapes 2-8) de chaque
paquet du lot (≤64, `MAX_BATCH_PKTS`, `src/nfq_loop.moon:29`) → `on_batch_end`
→ `flush_deferred` (étape 9 : un seul `wait_ack`, **lecture netlink suspendue**)
→ verdicts → boucle. Il n'y a **aucun recouvrement intra-worker** entre
traitement, attente d'ACK et lecture : la seule concurrence est **inter-processus**
(question ∥ réponse ∥ nft), et chaque flux (hachage NFQUEUE par couple
d'adresses, `perf.md` §11.1) n'appartient qu'à **une** file.

---

## 3. Ce qui change pour un client authentifié

Le profil authentifié fait tomber les questions sur `r_utilisateurs`
(70,8 % du `mixed` : Tailscale + vpn, **8 RR A** par réponse) au lieu de
70 % `r_refus_a_priori` + 30 % `r_ouverture_complete` en non authentifié
(`perf.md` §13.1). Conséquences, toutes par paquet :

| Poste | Code | Coût par paquet (mesuré) | Par lot/cache possible ? |
|-------|------|--------------------------|--------------------------|
| **Second avis** : duplication RAW de la question (`r_utilisateurs` porte `validate`) | `src/worker_questions.moon:108-121,473-476` | 1 `sendto` par question **+ 1,70-1,71 paquet de réponse** à traiter dans `resp` (Δcompteurs `nft_r/nft_q` = **10207/6001 = 1,70** à 200, **17958/10507 = 1,71** à 350 ; conforme `perf.md` §4.1) | Non : politique de règle (config) ; c'est le principal multiplicateur |
| **Réponses B du validateur** : `dns_classify` + diffusion de verdict sur le bus | `:1100-1109`, `src/second_opinion.moon:65-82` | ~0,3 ms/paquet B (inférence), et **toutes** les B tombent sur **une seule file** (mesure §4.4) | Dispersion impossible par hachage (couple d'adresses fixe) sans changer d'IP validateur (config) |
| **Parquage de A** jusqu'à B (budget 80 ms) | `:1320-1322`, `src/second_opinion.moon:161-181` | Le paquet A occupe son emplacement dans la file noyau pendant l'aller-retour amont | — |
| **Injection nft** : 16 à 20 éléments par réponse Tailscale (`ip4`+`mac4`, × wildcard) **et 1 syscall `write()` par élément** | `src/response_inject.moon:106-131`, `src/nft_queue.moon:108-121` | 16-20 écritures pipe + 16-20 upserts nft ; **worker nft 50,9 % (200) / 64,5 % (350)** contre **5-12 %** en non authentifié (`perf.md` §13.3) → **1,87-2,58 ms nft/requête** | Oui : coalescer les lignes en une seule écriture (gain syscall côté resp) ; le **regroupement nft est déjà fait** (`worker_nft.build_batch`, `src/worker_nft.moon:98-120`) |
| **Upserts redondants** : les *mêmes* éléments (même client, mêmes IP en cache) sont réinsérés à chaque réponse (rafraîchissement de timeout) | `src/nft_queue.moon:158-165`, `src/worker_nft.moon:83-87` | **Mesuré : delta de taille de sets = 0** à 350 (avant/après identiques, `results/a350_*_sets_*.txt`), +2 ip6 seulement à 200 → le CPU nft produit des **rafraîchissements**, pas des insertions nouvelles | Oui : cache « déjà inséré récemment » côté `worker_nft` (TTL ≪ timeout) |
| **`write_event` par question** | `src/worker_questions.moon:421,163-179` | 1 pipe write/question ; worker `events` **7,1 % → 11,6 %** d'un vCPU (0,34-0,36 ms/événement) | Oui : piggyback dans la ligne IPC question→réponse |
| **`write_learn_msg` par question** (22 o) | `:294,131-143` | 1 pipe write/question | Oui : piggyback IPC |
| Logs ALLOW + benchmark ligne/réponse | `:408`, `src/worker_responses.moon:1213-1258` | `log_write_us` p50 **36-47 µs**, p99 1,2-2,2 ms, max 14-16 ms (mesuré ; conforme `perf.md` §3.4) | Borné par `log.moon` rate-limit |
| Conditions + `user_for_mac` (2× par transaction) | `src/worker_questions.moon:378,393`, `src/worker_responses.moon:1082` | Cache 5 s : **0 `statx` échantillonné** en profil authentifié (session trouvée dans le cache) | Déjà en cache ; c'est le profil **non** authentifié qui paie `statx` par miss |

**Réponse à l'intuition « moins de paquets à réécrire »** : elle est fausse
sur les faits. (a) le profil authentifié traite **1,70-1,71 fois plus de
paquets** dans le chemin réponses (second avis) ; (b) il **active** 16-20
insertions nft par réponse, que le refus a priori ne déclenche jamais ; (c) le
coût de « réécriture » lui-même est à peu près **le même** que hors auth
(1,78-1,89 ms/paquet réponses ici, contre 1,63-1,71 mesurés en non auth
`perf.md` §13.3) : ce n'est pas le parsing/patch qui coûte, c'est le **nombre
de paquets × le travail nft supplémentaire**. En total, le profil authentifié
consomme **≈ 7,5-8,3 ms de CPU par requête** (toutes charges confondues,
calcul §5.1) contre **≈ 3,4 ms** en non authentifié (`perf.md` §13.3 :
resp+dns+nft = 100,7 % × 30 s / 9000) — **≈ 2× par requête**.

---

## 4. Mesures

### 4.1 CPU par worker (utime/stime), changements de contexte, ksoftirqd

Fenêtre = `EPOCH_START±1 s` … `EPOCH_END+1 s` (`meta.txt`), HZ≈97-99.
Sources : `results/<base>_extract.txt`.

**Repos (20 s)** : tous les workers ≤ 0,4 % ; `/proc/stat` idle 85 % ;
ksoftirqd ≤ 0,14 %.

**200 q/s `mixed` (30 s — 6000/6000, 0 % de perte)** :

| worker | utime % | stime % | total | vcsw | nvcsw |
|---|---|---|---|---|---|
| custos:nft | 32,0 | 18,9 | 50,9 | 1 903 | 3 737 |
| custos:resp-q14 | 30,1 | 4,6 | 34,7 | 7 434 | 2 887 |
| custos:resp-q15 | 25,4 | 3,4 | 28,8 | 8 165 | 2 437 |
| custos:dns-q0 | 17,2 | 2,6 | 19,8 | 2 951 | 1 540 |
| custos:dns-q1 | 14,8 | 4,4 | 19,2 | 2 945 | 1 469 |
| custos:events | 3,0 | 4,1 | 7,1 | 7 219 | 264 |
| custos:mac-lrn | 1,9 | 1,0 | 2,9 | 6 703 | 108 |
| ksoftirqd/0-3 | 0,00 | 0,13 chacun | | | |

`/proc/stat` (fenêtre) : user 34,3 %, sys 23,1 %, idle 39,0 %, sirq 2,3 %,
irq 1,4 %. Profondeurs max : q14 **16**, q15 5, q0 2, q1 1 ; `qdrop`/`udrop` = 0.
Journal : `ack_wait_us` non nul sur 2 325/6 001 lignes (38,7 %), p90 **9 055 µs**,
p99 17 897 µs, max 31 962 µs ; **aucun WARN/ERROR** dans la fenêtre
(`results/a200_analyse.txt`).

**350 q/s `mixed` (30 s — 10500/10500, 0 % de perte)** :

| worker | utime % | stime % | total | vcsw | nvcsw |
|---|---|---|---|---|---|
| custos:resp-q14 | 53,2 | 5,9 | **59,1** | **845** | **9 478** |
| custos:nft | 47,3 | 17,2 | **64,5** | 411 | 9 767 |
| custos:resp-q15 | 42,4 | 3,8 | 46,2 | 1 850 | 8 451 |
| custos:dns-q0 | 30,1 | 7,0 | 37,1 | 3 842 | 5 312 |
| custos:dns-q1 | 30,3 | 5,9 | 36,2 | 3 870 | 4 977 |
| custos:events | 4,4 | 7,2 | 11,6 | 10 700 | 470 |
| custos:mac-lrn | 2,8 | 2,1 | 4,9 | 10 490 | 99 |
| ksoftirqd/0-3 | 0,00 | 0,17 chacun | | | |

`/proc/stat` : user 57,5 %, sys 26,6 %, **idle 11,3 %**, sirq 3,3 %, irq 1,3 %
(signature très proche de `perf.md` §15.4 à 400 q/s : 58,3/26,1/11,2 — la part
« hors workers » est systématique : logd, yggdrasil, harnais de mesure ;
`top` au repos affiche 97 % idle). Profondeurs max : **q14 210, q15 140**
(q0 4, q1 4) ; `qdrop`/`udrop` = **0 partout** ; **1 × `response_nft_ack_timeout`
(150 ms)** à 13:15:55 (`results/a350_analyse.txt`).

**Changement de nature des context switches** : à 200, les workers réponses
dorment **volontairement** une fois par paquet/lire (`vcsw` 7 434-8 165 ≈
250/s) ; à 350, `vcsw` s'effondre (845-1 850) et les commutations
**involontaires** explosent (`nvcsw` 8 451-9 478 ≈ 300/s resp, 9 767 nft) :
les workers tournent en continu et sont **préemptés** (contendance sur les
cœurs avec le harnais/logd/softirq), signe de travail CPU ininterrompu plutôt
que d'attente d'E/S.

### 4.2 Où ils attendent — distribution de syscall (20 Hz, 720 échantillons/worker/palier)

`syscall 73 = ppoll` (arm64), `nfds` = nombre de fds surveillés : pour les
workers réponses, **`ppoll(nfds=3)` = boucle principale** (netlink + tube
question + bus second avis, `src/nfq_loop.moon:139-144` + `src/worker_responses.moon:1408-1410`)
et **`ppoll(nfds=1)` = `wait_ack`** (`src/nft_queue.moon:218-225`) ;
`running` = espace utilisateur (état R). Source : `results/*_sys.txt`.

| worker | repos | 200 q/s | 350 q/s |
|---|---|---|---|
| resp-q14 | ppoll3 99,6 % | ppoll3 45,3 % / **ppoll1 20,3 %** / running 34,4 % | running **69,6 %** / ppoll3 21,1 % / **ppoll1 9,2 %** |
| resp-q15 | ppoll3 100 % | ppoll3 44,7 % / **ppoll1 22,9 %** / running 32,4 % | running 57,9 % / ppoll3 21,1 % / **ppoll1 21,0 %** |
| nft | ppoll1 100 % | running 49,2 % / ppoll1 50,8 % | running **76,1 %** / ppoll1 23,9 % |
| dns-q0/q1 | ppoll1 100 % | ppoll1 81 % / running 19 % | running 53 % / ppoll1 47 % |
| doh | ppoll2 ~100 % | ~100 % | ~100 % (`d-dohspin` bien actif) |

Lectures :

- **9-23 % du temps des workers réponses est passé dans `wait_ack`** (ppoll
  `nfds=1`) : pendant ces tranches, le socket netlink des réponses **n'est pas
  lu** (§2.2 étape 9) — c'est la fenêtre pendant laquelle la file noyau se
  remplit. Mesure cohérente avec `perf.md` §3.1/§7 (45-54 % avant correctifs,
  part résiduelle aujourd'hui).
- À 350, la part d'attente d'ACK **baisse** (9-21 %) au profit de l'exécution
  (53-70 %) : le goulot migré du ping-pong resp↔nft vers le **CPU par paquet**,
  pendant que `response_entry_ms` (file noyau) explose (§4.3).
- Aucun `nanosleep` (101) échantillonné → ni retry IPC, ni retry d'appariement
  n'ont consommé de sommeil pendant les paliers.
- `wchan`/`stack` : `WCHAN (vide)` systématique, `STACK` = adresses brutes
  non résolubles (kallsyms absent) — consigne `perf` : `perf` absent, rien
  installé.

### 4.3 Latence décomposée (`response_entry_ms` = avant d'entrée dans le worker réponses)

Source : `results/a200_decomp.txt`, `results/a350_decomp.txt`.

| palier | RTT client p50/p99 | `response_entry` p50/p90/p99 | `q_to_response` p50/p99 | prof. max q14/q15 |
|---|---|---|---|---|
| 200 | **24,7 / 73,0 ms** | **2 / 13 / 37 ms** | 5 / 40 ms | 16 / 5 |
| 350 | **474 / 873 ms** | **337 / 504 / 648 ms** | 340 / 651 ms | **210 / 140** |

- Les deux règles et les deux destinations ont **la même** `response_entry`
  (p50 333-346 ms à 350) : le délai est **commun aux deux files** (file noyau),
  pas propre à une règle ni au résolveur d'une destination.
- Série temporelle à 350 : montée 54 → 470 ms en 5 s, plateau ~400-470 ms
  (t+5 à t+20 s), **démontage** de la file à ~100 ms sur les 10 dernières
  secondes alors que le débit d'entrée reste constant (~350 A/s + ~270 B/s) —
  la capacité de service a donc augmenté d'≈10 % en fin de phase (échauffement
  interprétatif possible : compilation JIT/état du résolveur — **non tranché**,
  voir §6).
- `ack_wait_us` à 350 : non nul sur 296/10 504 lignes seulement (2,8 %),
  p99 21 638 µs, max **151 880 µs** (= le timeout de 150 ms). L'ACK « est déjà
  arrivé » quand le lot le réclame (le travail a pris plus de temps que la
  latence nft) : **l'attente d'ACK n'est plus le goulot de latence à 350 — la
  file noyau l'est** ; elle reste une cause de non-lecture (§4.2).

### 4.4 Répartition des paquets de réponse et sets

- Δcompteurs `nft_r / nft_q` : **1,70** (200), **1,71** (350) → 70 % de
  réponses validateurs (B) en plus des réponses client (A).
- Δ `id_sequence` par file à 350 : **q14 = 12 715**, **q15 = 5 283**
  (`results/a350_analyse.txt`). Le hachage (§15.2) place les A de `10.35.4.1`
  sur q14 et celles de `10.35.1.1` sur q15 (5 250 chacune, comptés) :
  **12 715 − 5 250 = 7 465 ≈ 7 434 lignes `r_utilisateurs` → TOUTES les
  réponses B tombent sur `resp-q14` = 70,6 % du trafic de réponse**, à l'identique
  de `perf.md` §15.2.
- Éléments de sets (comptes seuls) : **delta 0** à 350 sur l'ensemble des ~100
  sets ; +2 (`r_utilisateurs_ip6/mac6`) à 200 ; `authenticated_ips/mac` = 1
  pendant toute la campagne (`results/*_sets_{before,after}.txt`). Le CPU nft
  (50,9-64,5 %) est donc consacré à des **upserts de rafraîchissement** des
  mêmes éléments.

---

## 5. Synthèse : goulots classés, correctifs proposés

### 5.1 Bilan quantifié

CPU/requête (fenêtre de charge, calcul sur `*_extract.txt`) :

| poste | 200 q/s | 350 q/s | non auth. (perf §13.3, 300 q/s) |
|---|---|---|---|
| resp (2 workers) | 3,22 ms (1,89 ms/paquet, ×1,70) | 3,05 ms (1,78 ms/paquet, ×1,71) | ≈1,9 ms (1,63-1,71 ms/paquet, ×1,0) |
| questions (2 workers) | 1,98 ms | 2,12 ms | ≈1,3 ms |
| nft | 2,58 ms | 1,87 ms | ≈0,16 ms (5-12 % d'un vCPU) |
| events + mac-lrn | 0,51 ms | 0,48 ms | non détaillés |
| **total** | **≈8,3 ms/requête** | **≈7,5 ms/requête** | **≈3,4 ms/requête** |

Machine à 350 : idle 11,3 %, ksoftirqd ≤0,2 %, sirq 3,3 % — **les 4 cœurs sont
disponibles mais chaque worker est mono-thread par file hachée** ; les pertes
n'arrivent qu'au-delà (file noyau 1024, `perf.md` §15).

### 5.2 Réponse à la question : le pipeline pendant l'attente amont existe-t-il ?

**Oui au stade question → amont, non au stade réponse → verdict :**

1. **Réalisé** : la question est acceptée et forwardée **sans attendre** ni
   l'amont, ni nft (`src/worker_questions.moon:478` ; §2.1). L'attente du RTT
   amont a lieu **entre** deux passages dans Custos, dans deux processus/queues
   différents : c'est bien du pipeline, et il fonctionne (les questions sont
   lues avec `response_entry` qui ne concerne que le sens retour).
2. **Empêché — attente d'ACK nft synchrone par lot** : le verdict des réponses
   injectées ne peut pas être posé avant l'ACK (`flush_deferred`,
   `src/worker_responses.moon:446-461`, invariant `perf.md` §7 /
   `.agents/architecture.md:120-125`), et **pendant cette attente le worker ne
   lit pas son socket netlink** (`wait_ack` ne poll que l'ACK, `on_wait` ne
   draine que le tube question, `src/worker_responses.moon:455`) : mesuré
   9-23 % du temps (§4.2), file noyau qui enfle d'autant.
3. **Empêché — second avis** : la réponse A est **parquée sans verdict**
   pendant l'aller-retour du validateur (`src/worker_responses.moon:1314-1322`)
   : l'attente amont *est* pipelinée côté travail CPU (le worker continue), mais
   **le paquet garde son emplacement dans la file noyau** (`queue_total`), et
   les réponses du validateur sont **concentrées sur une seule file** (70,6 %
   mesuré §4.4) : la file chaude devient le point de saturation, pas la machine.
4. **Empêché — sérialisation par lot dans chaque worker** : traiter le lot
   (≤64) **puis** attendre l'ACK **puis** verdicter, sans recouvrement
   (`src/nfq_loop.moon:206-227`) : à ρ→1 sur une file, la file debout
   (≈2-3 lots : 210 paquets) vaut `profondeur/débit ≈ 337-440 ms` — c'est
   exactement `response_entry` mesuré à 350 (§4.3). À 200 (ρ petit), la file
   retombe à ≤16 et `entry` à 2 ms : **le genou est entre 200 et 350 q/s**.
5. **Fausses economies attendues** : « moins de paquets à réécrire » (×1,70 au
   contraire) et « le coût par paquet baisse avec l'authentification » (il est
   constant : 1,78-1,89 ms ici vs 1,63-1,71 non auth). Le vrai delta est
   **×1,7 paquets resp + 16-20 upserts nft + conditions/events/duplication**,
   soit ≈2× de CPU par requête (§5.1).

### 5.3 Goulots classés (coût mesuré) et correctifs proposés (sans les implémenter)

| # | Goulot | Coût mesuré | Correctif (fichier:ligne, principe) | Gain attendu | Risque |
|---|--------|-------------|--------------------------------------|--------------|--------|
| 1 | **Second avis ×1,70 paquets resp** (règle `validate`) | resp 2× charge ; 1,70-1,71 Δpaquets (§4.4) ; ≈+40-70 % de CPU resp (`perf.md` §10.2) | **Politique de config** (désactiver `validate` là où redondant) — `src/worker_questions.moon:473-476` ; aucun code | −40 à −70 % CPU resp, genou déplacé au-delà de 350 q/s | **Sécurité** : arbitrage explicite requis (déjà noté `perf.md` §10.2) |
| 2 | **`wait_ack` bloque la lecture netlink** (9-23 % du temps resp) + 1 timeout 150 ms | file noyau 16→210 ; `response_entry` p50 337 ms à 350 | Pendant `wait_ack`, **drainer aussi le socket netlink** dans `on_wait` en ajoutant des paquets au lot différé (aujourd'hui `src/worker_responses.moon:455` ne draine que le tube question ; extension possible via une boucle de lecture fournie par `src/nfq_loop.moon:145-154`) ; bornes : `MAX_BATCH_PKTS` (`src/nfq_loop.moon:29`) et budget 150 ms inchangés | Réduction directe de la fenêtre de non-lecture (≈9-23 %) et de la file debout ; latence p50 ↓ | **Invariant de sécurité** : aucun verdict avant ACK couvrant le lot — à préserver ; complexité moyenne (réentrance lecture/verdict) |
| 3 | **Userts nft redondants** (mêmes éléments réinsérés à chaque réponse) | nft 50,9-64,5 % d'un vCPU = 1,87-2,58 ms/requête ; delta de sets = **0** (§4.4) | Cache « élément fraîchement inséré » dans `worker_nft` (`try_add_pending`, `src/worker_nft.moon:83-87` + `build_batch` `:98-120`) : sauter un ré-inscription si la même clé l'a été depuis `k × timeout` (k≈0,5), TTL/expirations inchangés | 20-30 % du CPU de service (`perf.md` §10.4) | Expiration prématurée si le rafraîchissement est sauté trop longtemps (borne stricte nécessaire) |
| 4 | **1 `write()` syscall par élément nft** (16-20 par réponse) | stime resp 3,4-5,9 % ; stime nft 17,2-18,9 % | Coalescer les lignes d'une même réponse en **un seul `write`** (`nft_queue.enqueue`/`write_line`, `src/nft_queue.moon:108-121,158-165`), format ligne multiple déjà supporté par le parseur côté `worker_nft` (`src/worker_nft.moon:196-211` lit des lignes arbitraires) | Quelques % resp+nft, suppression de ~16 syscalls/réponse | Faible (atomicité < `PIPE_BUF` à vérifier : 16×~60 o ≈ 1 kio < 4 kio) |
| 5 | **File chaude du validateur : toutes les B sur `resp-q14`** (70,6 %) | q14 59,1 % vs q15 46,2 % ; profondeurs 210/140 (§4.4) | Config : **plusieurs IP validateurs** réparties (le hachage porte sur les adresses, `perf.md` §11.1) ou rotation de l'IP source du duplicate (`dup_query.pick_resolver`, `src/dup_query.moon`) ; dispersion **impossible** par `fanout` (casserait l'affinité de flux, `perf.md` §11.1.b) | Équilibrage des files, seuil de perte repoussé | Config/réseau (plus d'adresses validateurs) |
| 6 | **Longueur de file noyau 1024** (`NFQNL_QMAX_DEFAULT`) | §15 : perte à 42 % dès 500 q/s (`qdrop`, `udrop`=0) | Exposer `nfq_set_queue_maxlen()` à la création (`src/nfq_loop.moon:109-120`, après `nfq_create_queue`) + clé config | Repousse le point de **perte** (pas de débit CPU) ; n'empêche pas la latence | Files plus profondes = latence plus haute avant drop |
| 7 | **Écriture events + learn par question** (2 pipe writes) | events 7,1-11,6 % + mac-lrn 2,9-4,9 % d'un vCPU | Piggyback des champs events/learn dans la ligne IPC question (`src/worker_questions.moon:453-457`, format `src/ipc.moon:264-272`) ; `worker_events` deviendrait un simple consommateur du tube question | −7 à −12 % CPU total + 1 syscall/question | Format IPC (version `v1`) à faire évoluer ; compat deux versions |
| 8 | **Coût fixe par paquet resp/questions** (1,78-1,89 / ~2,0 ms) | non décomposé (`perf.md` §9/§10.3) | Build de mesure avec `jit.profile` (aucun déploiement prod) | Jusqu'à ×2 (théorique) sur resp+dns | Aucun (mesure) |

Ordre recommandé : **1** (arbitrage config, gain immédiat), **2** (latence/file),
**3** (CPU nft), **5** (équilibrage), puis **4/7** (gains marginaux) et **8**
(avant toute autre optimisation CPU).

---

## 6. Fait / non fait / douteux

### Fait

- Tracé complet du chemin avec citations `fichier:ligne`, caractère bloquant
  par étape (§2) : **verdict question = sans attente** (hormis IPC 5×20 ms non
  observé) ; **verdict réponse = attend l'ACK nft, une fois par lot**, sauf
  refus (`:1291`) et `dnsonly` (`:803`).
- Mesures **lecture seule** sur `custos.lan`, paliers 30 s à **200** et
  **350 q/s `mixed`** authentifiés (sonde `dig` 8 A avant chaque phase), +
  phase de repos. Aucun redémarrage, aucune écriture, aucun secret affiché
  (`/etc/custos` jamais lu), aucune capture paquets.
- CPU utime/stime, vcsw/nvcsw, `ksoftirqd`, idle `/proc/stat`, profondeurs
  NFQUEUE, `ack_wait_us`, `response_entry_ms`, distribution de syscall 20 Hz,
  comptes de sets, WARNs de fenêtre — tout est archivé dans
  `tmp/perfaudit/results/` et référencé ci-dessus.
- Constats centraux : 0 % de perte à 200 et 350 ; `response_entry` p50
  2 ms → 337 ms entre 200 et 350 ; profondeurs 16/5 → 210/140 ; ×1,70-1,71
  paquets resp ; toutes les réponses validateur sur **une** file (70,6 %) ;
  nft 50,9-64,5 % pour **delta de sets nul** ; 9-23 % de temps resp en
  `wait_ack` sans lecture netlink ; 1 timeout ACK de 150 ms à 350 ;
  signature machine (idle 11,3 %) identique à celle de `perf.md` §15.4.
- Correction d'hypothèse : `worker_nft` n'exécute **pas** `nft` en
  sous-processus — c'est libnftables **in-process** (`src/nft.moon:31-32`,
  « ni fork() ni popen() »).

### Non fait (et pourquoi)

- **Aucune modification de code**, aucun correctif implémenté (consigne).
- **Palier non authentifié** : non obtenu — impossible sans modification
  d'état (dé-authentification du client) ; comparaison à `perf.md` §13/§15.
- **`perf`/`jit.profile`** : `perf` absent de la cible, rien installé ; le coût
  fixe par paquet reste non décomposé (déjà noté `perf.md` §9/§10.3).
- **`wchan`/`stack`** : échantillonnés (preuve archivée) mais vides/non
  symbolisés (kallsyms absent) ; substitués par `/proc/<pid>/syscall`.
- Paliers > 350 q/s, capture AF_PACKET, `make test-e2e` : non faits (consignes).
- `chain_strip` / `maybe_dynamic_strip` : activité **non déterminable** sans
  lire la config (comme `perf.md` §9) ; aucun log `response_chain_strip` dans
  les fenêtres (DEBUG, non concluant).

### Douteux (non tranché par les mesures)

- Le **démontage** de la file au dernier tiers du palier 350 (§4.3) alors que
  l'entrée reste constante : hausse de capacité ≈10 % — échauffement JIT
  LuaJIT, cache du résolveur, ou effet de bord du second avis ; aucune
  instrumentation disponible pour trancher sans build instrumenté.
- L'attribution exacte des 20-27 points de CPU « hors workers » de
  `/proc/stat` (logd, yggdrasil, harnais de mesure) : le repos `top` affiche
  97 % idle, donc rien de structurel, mais la répartition par processus n'a
  pas été relevée pendant les paliers (seul `top -bn1` après coup).
- Le modèle de file exact (composante « rafale du résolveur » vs « cycle de
   lot ») : la corrélation profondeur ≈ 200-350 paquets ↔ `response_entry`
   300-440 ms est mesurée, mais la répartition rafale/sérialisation ne l'est
   pas (pas de capture L2 autorisée).
