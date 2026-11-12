# Profilage CPU du hot path DNS — rapport de branche `d-prof` (2026-11-12)

Objectif : trouver où part le temps CPU d'une requête (≈ 7,5-8,3 ms sur la
cible aarch64, soit 1,3-1,6 ms par paquet dans un worker réponses —
`docs/agents/perf.md` §8, §16.3) et descendre sous 2,5 ms par requête pour
1000 q/s. Tout a été fait **en local** : aucun accès réseau distant, aucun ssh,
aucun déploiement.

---

## 1. Ce qui a été construit : `make bench-hotpath`

Micro-banc dans `src/bench/hotpath.moon` (+ `src/bench/hotpath_cli.moon`,
cible Make `bench-hotpath` dans `Makefile:413-441`, doc
`src/bench/README.md` § « Profilage du hot path »).

Il **rejoue en boucle les handlers réels des workers**, sans NFQUEUE ni réseau :

| Élément | Réel ou stub | Détail |
|---|---|---|
| `handle_question`, `handle_response` | **réel** | callbacks installés par `worker_questions.run` / `worker_responses.run`, récupérés via le `nfq_loop.run_queue` neutralisé (`src/bench/hotpath.moon:272-275`) |
| Filtre (`decide_meta`, `run_on_response`) | **réel** | `filter.load` avec les règles par défaut de `config.moon` + les3 règles du banc (`src/bench/hotpath.moon:96-120`) |
| Transaction `pending` IPC | **réel** | produite par une sonde `handle_question` par domaine (`setup`, `src/bench/hotpath.moon:422-437`), réinjectée par `ipc.set_pending` |
| `libnfq` | stub | `nfq_get_payload` rend un paquet pré-construit, `nfq_set_verdict*` compte, `nfq_get_packet_hw` rend la MAC du client (`install_stubs`, `:230-277`) |
| `nft_queue` | **réel** | tube agrandi à 1 Mio, vidé après chaque lot ; `ack_rfd` absent → `wait_ack` rend immédiatement (l'attente d'ACK n'est pas du CPU) |
| tube question→réponse | **réel** | écriture dans le cas `ipc_drain`, lecture/décodage dans tous les cas |
| `raw_send` | stub | aucun socket, aucun paquet émis (zéro accès réseau) |
| `metrics`, `log`, `second_opinion`, `dns_classify`, `response_inject` | **réel** | y compris la journalisation ALLOW réelle (rate-limitée par `log.moon`) |

Cas mesurés (`build_cases`, `src/bench/hotpath.moon:472-580`) :

| cas | ce qu'il mesure |
|---|---|
| `question` | parse + décision filtre + ALLOW + écriture IPC + événement + apprentissage MAC + **duplication validateur** (`maybe_duplicate`) |
| `ipc_drain` | coût complet du tube question→réponse : écriture + lecture + décodage + insertion `pending` (1 message) |
| `response` | réponse **sans** second avis (`r_ouverture_complete`, 1 A, injection nft) |
| `so_a` | réponse A avec `validate` → parquage seul |
| `so_cycle` | cycle complet du second avis : A parquée + B validateur (8 A, 16 insertions nft) + flush de lot |
| `setup_control` | préparation seule (`set_pending` + `consume`) : incluse dans les mesures de réponse, à déduire pour comparer |

**Sécurité sur machine vivante** : le banc force `config.nft.table` à un nom
inexistant (`src/bench/hotpath.moon`, `apply_config`) parce que `filter.load`
exécute `ip_whitelist.init`, qui **FLUSH** les sets `ip*_dest_whitelist` de la
table courante — avec la vraie table, lancer le banc sur un hôte où custos
tourne viderait ces deux sets. Aucun autre effet de bord réseau : `run_queue`
neutralisé (aucune file NFQUEUE ouverte), `raw_send` stubé (aucun paquet émis),
sorties limitées à `./tmp/prof/`.

**Protocole** : échauffement 5 000 itérations non chronométré, puis
`HP_REPEAT=3` passages chronométrés dont on garde le **minimum** (la machine
partage ses cœurs avec d'autres processus : le total est bruyant ±30 %, cf.
§3.4), lots de 64 (= `MAX_BATCH_PKTS`), `os.clock` (résolution ~1 µs vérifiée,
coût d'appel ~0,2 µs), ≥ 100 000 itérations par cas. Allocation mesurée à part
avec `collectgarbage("stop")`.

**Vérifications de chemin** (`main`, `:841-849`) : codes retour attendus
(`NF_ACCEPT` pour la question, `-1` pour les réponses parquées/finale) et
nombre de verdicts posés = nombre de cycles/paquets. Si le chemin mesuré n'est
pas le décrit, le banc **sort en code 1** : aucune mesure de ce rapport ne porte
sur un autre chemin (toutes les lignes de mesure sont exemptes de
« ÉCHECS DE VÉRIFICATION »).

Sorties : `tmp/prof/hotpath.md` (dernier run), mesures archivées dans
`tmp/prof/*.txt`, profils dans `tmp/prof/profile_{f,l}_{before,final}.txt`,
traces dans `tmp/prof/jitv_final.txt` / `tmp/prof/jitdump_final.txt`.

---

## 2. Mesures — coût par paquet (µs, `os.clock`, 100 000 iters, min de 3)

### 2.1 Référence (aucun correctif) — `tmp/prof/ref_timing.txt`, `ref_timing2.txt`

| cas | µs/paquet (passage 1 / 2) | µs/paquet (lot min) | octets/paquet (GC arrêté) | µs/cycle second avis |
|---|---|---|---|---|
| question | 51,2 / 51,9 | 37,8 / 37,1 | 6 760 | — |
| ipc_drain | 14,1 / 13,9 | 10,3 / 10,9 | 2 634 | — |
| response | 55,6 / 52,5 | 49,9 / 38,8 | 13 387 | — |
| so_a | 29,0 / 32,1 | 23,9 / 19,0 | 8 994 | — |
| so_cycle | 110,3 / 116,3 | 94,4 / 92,2 | 40 465 | **220,6 / 232,5** |
| setup_control | 1,3 / 2,5 | 0,5 / 0,9 | 890 | — |

### 2.2 État final (4 correctifs appliqués) — `tmp/prof/after_cache.txt`, `after_cache2.txt`

| cas | µs/paquet (passage 1 / 2) | µs/paquet (lot min) | octets/paquet | gain vs référence (moyenne des 2 passages) |
|---|---|---|---|---|
| question | 26,2 / 26,7 | 24,5 / 23,8 | 6 640 | **−49 %** |
| ipc_drain | 5,9 / 8,7 | 3,7 / 3,8 | 1 906 | **−48 %** (lot min −64 %) |
| response | 30,1 / 29,3 | 25,5 / 24,7 | 11 223 | **−46 %** |
| so_a | 33,8 / 23,0 | 20,3 / 20,3 | 8 994 | −15 % (lot min) |
| so_cycle | 47,4 / 47,5 | 44,1 / 43,9 | 32 889 | **−56 %** (cycle 220,6 → **94,7 µs**) |
| setup_control | 1,4 / 1,4 | 0,5 / 0,5 | 890 | contrôlé inchangé |

Comparaison **même protocole,3 000 iters, un passage** avant/après profilage
(`tmp/prof/profile_f_before.txt` vs `profile_f_final.txt`) : question 49,3 →
25,9 (−47 %), ipc_drain 12,0 → 5,8 (−52 %), response 56,3 → 30,2 (−46 %),
so_a 27,3 → 23,1 (−15 %), so_cycle 94,7 → 43,9 (−54 %), setup_control 1,3 → 1,3.

### 2.3 Détail par correctif (uniquement ce qui a changé, mesures 100 000 iters)

| correctif | cas touchés | avant | après | gain constaté |
|---|---|---|---|---|
| 1. `to_hex` par table (`b3d44d0`) | question | 51,2 / 51,9 | 38,9 | −24 % |
| | response | 55,6 / 52,5 | 38,6 | −30 % |
| | so_cycle | 110,3 / 116,3 | 72,8 | −34 % |
| | ipc_drain | 14,1 / 13,9 | 11,8 | −16 % |
| | so_a (contrôle) | 29,0 / 32,1 | 29,5 | ~0 |
| 2. `from_hex` par nibbles (`552be16`) | ipc_drain | 11,8 | 9,3 | **−21 %** (lot min 9,5 → 7,3) |
| | question/response/so_cycle (contrôles) | 38,9 / 38,6 / 72,8 | 39,0 / 38,5 / 72,5 | ~0 |
| 3. suffixes sans allocation (`9013d37`) | question | 39,0 | 29,9 / 28,9 | **−25 %** (lot min 32,6 → 28,4/26,4) |
| | response/so_cycle (contrôles) | 38,5 / 72,5 | 39,4/43,9 / 71,9/73,2 | ~0 (bruit) |
| 4. pas de re-parse inutile (`e84ee03`) | response | 39,4 | 35,2 | **−11 %** (lot min 37,3 → 30,2) |
| | so_cycle | 71,9 | 64,5 | **−10 %** (lot min 68,6 → 60,1) |
| | question/so_a/ipc_drain (contrôles) | 28,9 / 22,8 / 9,8 | 27,8 / 22,6 / 9,5 | ~0 |
| 5. cache hex borné (`b2331c8`) | ipc_drain | 9,5 | 5,9 / 8,7 | **−38 %** (lot min 6,9 → 3,7) |
| | response | 35,2 | 30,1 / 29,3 | **−15 %** |
| | so_cycle | 64,5 | 47,4 / 47,5 | **−27 %** |
| | question | 27,8 | 26,2 / 26,7 | **−6 %** |
| | so_a (contrôle, lot min) | 19,4 | 20,3 | ~0 |

**Tous les correctifs appliqués dépassent le seuil de 5 % sur le cas visé**,
avec des témoins inchangés dans la même exécution.

### 2.4 Limite de mesure (bruit)

La machine héberge d'autres processus (firefox, qemu du homelab, autres
sessions d'agents) : sur un même état, le **total** d'un cas varie de ±30 %
entre deux exécutions (`question` 46,3 à 94,2 µs selon les runs), alors que le
**minimum de lot** reste à ±10 % et les cas témoins sont stables dans une même
exécution. Les gains revendiqués (≥ 6 %, la plupart ≥ 10 %) sont au-delà de ce
bruit et toujours accompagnés de témoins. Aucune mesure n'a de prétention
inférieure à ~5 %.

---

## 3. Profilage `jit.profile` — les 15 postes les plus coûteux

Durée ≥ 10 s par cas et par mode, ~1 000 échantillons par cas.
Fichiers : `tmp/prof/profile_f_before.txt` (avant correctifs),
`tmp/prof/profile_f_final.txt` (après), `tmp/prof/profile_l.txt` (lignes, avant),
`tmp/prof/profile_l_final.txt` (lignes, après).

### 3.1 Mode `f` — AVANT correctifs (`profile_f_before.txt`)

**question** (états VM : N 48,8 %, I 18,2 %, C 15,7 %, G 17,2 %) :

| % | fonction |
|---|---|
| 25,4 | `eval` (filtre : conditions/règles) |
| 14,1 | `ipc_hex.lua:19` (la boucle `gsub` de `to_hex`) |
| 5,8 | `sp` (pack → duplication validateur `build_udp`) |
| 5,3 | `su` (unpack, checksum/parse) |
| 4,8 | `cond` (évaluation d'une condition) |
| 3,6 | `encode_msg` |
| 3,2 | `step` (boucle du banc) |
| 2,6 | `write_event` |
| 2,5 | `checksum` |
| 2,5 | `parse_questions` |
| 2,3 | `parse_ip4` |
| 2,3 | `details_of` |
| 1,7 | `parse_rrs` |
| 1,5 | `build_udp` |
| 1,4 | `to_hex` (la partie hors `gsub`) |

**ipc_drain** (N 26,1 %, I 26,5 %, C 22,5 %, G 24,9 %) : `from_hex` **48,5 %**,
`decode_msg` 12,4, `now_fn` 9,5, `set_pending` 7,0, `split_fields` 6,0,
`drain_pipe` 3,7, `step` 3,2, `_append_pending_node` 1,6, `is_ipv4_str` 1,6,
`is_valid_mac` 1,3, `decode_modifiers` 1,3, `on_msg` 1,0, `drain_fd` 0,8,
`drain_lines` 0,7, `is_valid_timeout` 0,4.

**response** (C 22,3 %, I 32,1 %, G 37,0 %, N 8,6 %) :

| % | fonction |
|---|---|
| 21,7 | `ipc_hex.lua:19` (`to_hex`) |
| 10,2 | `finalize_a` |
| 7,7 | `step` |
| 7,4 | `labels` (parse des noms DNS) |
| 5,0 | `strip_https_rr` |
| 3,4 | `build_line` |
| 3,1 | `pre` (préparation du banc) |
| 2,7 | `to_hex` (hors `gsub`) |
| 2,5 | `inject` |
| 2,5 | `parse_dns_packet` |
| 2,3 | `parse_question` |
| 2,2 | `parse_udp` |
| 2,2 | `now_fn` |
| 2,0 | `parse_answers` |
| 2,0 | `parse_rrs` |

**so_a** (G 48,0 %, I 22,4 %, N 20,8 %) : `parse_rr` 29,3, `step` 18,1,
`parse_questions` 8,8, `labels` 6,1, `corr_key` 4,8, `drain_pipe` 3,7,
`label` 3,3, `su` 2,9, `need_bytes` 2,9, `pre` 2,1, `now_fn` 1,9,
`parse_rrs` 1,7, `parse_header` 1,4, `ip2s` 1,3, `parse_ip4` 1,3.

**so_cycle** (C 34,8 %, G 29,5 %, I 26,4 %, N 9,2 %) :

| % | fonction |
|---|---|
| 35,6 | `ipc_hex.lua:19` (`to_hex`) |
| 8,5 | `build_line` |
| 6,1 | `parse_rr` |
| 4,0 | `to_hex` (hors `gsub`) |
| 3,8 | `finalize_a` |
| 3,7 | `labels` |
| 3,7 | `parse_answers` |
| 2,9 | `step` |
| 2,4 | `flush` |
| 2,3 | `su` |
| 2,0 | `copy_section` |
| 1,6 | `parse_dns_packet` |
| 1,5 | `drain_pipe` |
| 1,5 | `parse_question` |
| 1,4 | `label` |

**setup_control** : `now_fn` 41,2, `pre` 26,2, `_append_pending_node` 15,3,
`consume` 8,9, `step` 2,2, `profile_case` 2,0, `_enforce_pending_max` 1,5,
`make_key` 1,3, `drain_fd` 0,8, `drain` 0,5, `_unlink_pending_node` 0,1.

### 3.2 Mode `f` — APRÈS correctifs (`profile_f_final.txt`)

**question** (N 41,4 %, G 32,5 %, I 16,9 %, C 9,2 %) : `eval` 10,1, `sp` 10,0,
`step` 6,7, `write_event` 6,4, `parse_questions` 6,1, `read_cached` 5,5,
`parse_ip4` 5,2, `cond` 4,2, `checksum` 3,9, `build_udp` 3,7, `encode_msg` 3,2,
`tostring` 2,6, `session_for_mac` 2,4, `su` 2,2, `details_of` 1,8.
→ `to_hex` n'est plus dans le top 15 (était 15,5 %).

**ipc_drain** (N 19,0 %, G 31,3 %, I 16,4 %, C 33,2 %) : `decode_msg` 19,9,
`set_pending` 13,9, `now_fn` 13,1, `split_fields` 12,6, `decode_modifiers` 10,0,
`drain_pipe` 9,4, `step` 6,2, `is_valid_mac` 2,3, `is_ipv4_str` 2,0,
`_append_pending_node` 1,7, `consume` 1,6, `drain_lines` 1,4, `on_msg` 1,2,
`is_valid_timeout` 0,9, `_enforce_pending_max` 0,8.
→ `from_hex` n'est plus dans le top 15 (était 48,5 %).

**response** (G 43,7 %, I 32,6 %, N 13,8 %, C 9,7 %) : `finalize_a` 15,4,
`step` 10,8, `strip_https_rr` 5,7, `run_on_response` 4,6, `pre` 4,3,
`labels` 4,3, `build_line` 4,0, `is_valid_timeout` 3,8, `parse_dns_packet` 3,6,
`now_fn` 3,1, `drain_pipe` 3,0, `parse_answers` 3,0, `parse_ip4` 2,6,
`inject` 2,3, `parse_question` 2,2.
→ `to_hex` n'est plus dans le top 15 (était 24,4 %).

**so_a** (G 45,2 %, I 27,5 %, N 19,0 %, C 8,3 %) : `parse_rr` 24,6, `step` 17,5,
`labels` 13,6, `corr_key` 5,1, `parse_questions` 4,5, `need_bytes` 3,3,
`label` 3,0, `drain_pipe` 2,9, `su` 2,9, `pre` 2,3, `parse_rrs` 2,1,
`parse_ip4` 1,5, `now_fn` 1,4, `parse_dns_packet` 1,1, `parse_header` 1,1.

**so_cycle** (G 46,7 %, I 25,1 %, N 20,5 %, C 7,6 %) : `to_hex` (cache, hors
hit) 22,8 — *à lire avec prudence : le run de profilage `--iters 3000` purge
le cache plus souvent qu'en mesure longue ; `build_line` 4,9, `parse_answers`
6,9, `finalize_a` 6,8, `step` 6,5, `parse_rr` 4,8, `is_valid_timeout` 4,2,
`su` 3,0, `labels` 2,9, `copy_section` 2,4, `flush` 2,1, `strip_https_rr` 2,1,
`parse_question` 1,8, `on_response_for_many` 1,8, `timeout_of` 1,7*.

**setup_control** : `log.lua:678` (`now`, horloge) 39,1, `ipc.lua:569`
(`set_pending`) 11,6, `ipc.lua:828` 9,7 — l'horloge `clock_gettime` domine ce
cas de contrôle (0,5 µs/paquet).

### 3.3 Mode `l` — les lignes dominantes

Avant (`tmp/prof/profile_l.txt`) :

| cas | ligne | % |
|---|---|---|
| question | `to_domain.lua:56` (la `sub` de suffixe) | 14,2 |
| question | `ipc_hex.lua:20` (closure/format de `to_hex`) | 12,2 |
| question | `to_domain.lua:60` (point suivant) | 7,6 |
| question | `to_domains.lua:30` (boucle des conditions) | 3,7 |
| ipc_drain | `ipc_hex.lua:36` (`string.char tonumber(sub)`) | 29,6 |
| ipc_drain | `ipc_hex.lua:31` (longueur impaire) | 8,6 |
| ipc_drain | `ipc.lua:363` (`gsub "\n+$"` de `decode_msg`) | 7,1 |
| ipc_drain | `log.lua:678` (`now`) | 6,9 |
| ipc_drain | `ipc_hex.lua:35` (motif de validation) | 5,0 |
| response | `ipc_hex.lua:20` | 23,3 |
| response | `dns.lua:198` (parse) | 6,6 |
| response | `worker_responses.lua:614` | 4,3 |
| response | `worker_responses.lua:1358` | 3,4 |
| response | `log.lua:678` (`now`) | 3,0 |
| so_a | `dns.lua:282` (parse_rr) | 21,0 |
| so_a | `worker_responses.lua:1358` | 6,7 |
| so_a | `dns.lua:244` | 6,2 |
| so_a | `worker_responses.lua:1099` | 5,8 |
| so_cycle | `ipc_hex.lua:20` | 36,7 |
| so_cycle | `nft_queue.lua:234` (`build_line`) | 7,7 |
| so_cycle | `dns.lua:282` | 5,1 |

Après (`tmp/prof/profile_l_final.txt`) : `ipc_hex.lua:125` reste à 12,9 % de
`so_cycle` (appelé par `nft_queue.lua:73`) et 4,6 % de `response` — c'est
`is_valid_timeout` (motif `^%d+[smhdw]?$`) appelé par `sanitize_timeout` à
chaque ligne nft, plus le `to_hex` non mis en cache ; `nft_queue.lua:224`
(`build_line`) 7,5 % ; `dns.lua:282` (`parse_rr`) 5,4 % ; `dns_response.lua:98`
(`parse_answers`) 5,1 % ; `log.lua:678` (`now`) 5,8 % ; `packet_utils.lua:103`
(recopie du payload DNS) 5,5 % ; `rule.lua:346` (`apply_on_response`) 5,2 % ;
`worker_responses.lua:1360` 4,7 %.

### 3.4 États VM (part des échantillons)

| cas | avant : G / C / I / N | après : G / C / I / N |
|---|---|---|
| question | 17,2 / 15,7 / 18,2 / 48,8 | 32,5 / 9,2 / 16,9 / 41,4 |
| ipc_drain | 24,9 / 22,5 / 26,5 / 26,1 | 31,3 / 33,2 / 16,4 / 19,0 |
| response | 37,0 / 22,3 / 32,1 / 8,6 | 43,7 / 9,7 / 32,6 / 13,8 |
| so_a | 48,0 / 8,8 / 22,4 / 20,8 | 45,2 / 8,3 / 27,5 / 19,0 |
| so_cycle | 29,5 / 34,8 / 26,4 / 9,2 | 46,7 / 7,6 / 25,1 / 20,5 |

`G` = GC, `C` = code C (appels FFI/syscalls), `I` = interprété, `N` = code
natif compilé, `J` = compilateur JIT. **Le GC reste le premier poste résiduel
(29-47 %)** : à allocation égale il ne diminue pas en part puisque les autres
postes reculent ; l'allocation par paquet a pourtant baissé de 16-28 % sur
`response`/`ipc_drain`/`so_cycle` (§2.2). `C` chute de 22-35 % à 8-33 %
(notamment `response` : 22,3 → 9,7 %) : c'est directement la suppression des
`string.format`/`gsub` par octet.

---

## 4. Traces avortées (`jit.v` / `jit.dump`)

Fichiers : `tmp/prof/jitv_final.txt` (1 097 lignes, 212 traces démarrées,
**885 aborts**), `tmp/prof/jitdump_final.txt` (3 219 lignes, mode `t`),
agrégat `tmp/prof/aborts_final.txt` et `tmp/prof/aborts_final_clean.txt`.
(Le run avant correctifs est dans `tmp/prof/jitdump.txt` : 839 aborts, dont
**25 × `ipc_hex.lua:21 -- NYI: bytecode FNEW`** et **`ipc_hex.lua:19 -- NYI:
return to lower frame`**, disparus après le correctif 1.)

Répartition des raisons (hors sites du banc `hotpath.lua`) :

| raisons | événements |
|---|---|
| `leaving loop in root trace` | 183 |
| `inner loop in root trace` | 178 |
| `NYI: bytecode UCLO` | 163 |
| `blacklisted` | 96 |
| `NYI: bytecode FNEW` | 63 |
| `loop unroll limit reached` | 18 |
| `NYI: return to lower frame` | 15 |

**Toutes les traces avortées du hot path** (site d'abort | raison | occurrences ;
liste complète dans `tmp/prof/aborts_final_clean.txt`) :

| site | raison | n |
|---|---|---|
| `worker_responses.lua:739` (boucle `pairs` des `no_v4`/`no_v6` de `finalize_a`) | NYI: bytecode UCLO | 17 |
| `worker_responses.lua:739` | leaving loop in root trace | 5 |
| `worker_responses.lua:964` (`sweep_parked`/`expired`) | NYI: bytecode UCLO | 11 |
| `worker_responses.lua:881` (`broadcast_verdict`) | NYI: bytecode UCLO | 11 |
| `worker_responses.lua:710` (`finalize_a`) | leaving loop in root trace | 11 |
| `worker_responses.lua:545` (en-tête de `finalize_a` : création des closures) | NYI: bytecode FNEW | 11 |
| `worker_responses.lua:403` (`_flush_batch`) | NYI: bytecode UCLO | 11 |
| `worker_responses.lua:1079` (entrée de `handle_response`) | blacklisted | 11 |
| `worker_responses.lua:350` / `:379` / `:372` / `:369` / `:264` / `:516-517` / `:188` | inner loop / UCLO / FNEW | 6+5+4+4+5+4+6 |
| `worker_questions.lua:405` (`write_event`) | leaving loop in root trace | 11 |
| `worker_questions.lua:198` / `:211` / `:242` (`append_unique`) | inner loop in root trace | 11+11+11 |
| `worker_questions.lua:236` (`list_from_condition_reason`) | blacklisted / inner loop | 6+4 |
| `worker_questions.lua:456-458` (`maybe_duplicate`/`write_msg`) | NYI return to lower frame / leaving loop | 11+11 (avant correctifs) |
| `rule.lua:307` / `:310` / `:329` / `:355` (`on_response_for_many`, `apply_on_response`) | inner loop in root trace | 11+48+11+9 |
| `rule.lua:215` / `:216` (`details_of`, boucle des règles) | inner loop / loop unroll limit | 11+17 |
| `rule.lua:199` / `:266` (`details_of`, `compile`) | loop unroll limit reached | 9+8 |
| `rule.lua:316` / `:347` / `:342` | leaving loop in root trace | 11+3+1 |
| `nft_queue.lua:169` / `:176` / `:181` (`flush` : découpage des tranches) | inner loop in root trace | 9+11+35 |
| `nft_queue.lua:121` / `:185` / `:309` (`write_data`, `wait_ack`) | NYI: bytecode UCLO | 10+8+4 |
| `nft_queue.lua:298` | inner loop in root trace | 4 |
| `ipc.lua:472` (`make_key`, `string.format`) | blacklisted | 34 |
| `ipc.lua:639` / `:711` / `:127` / `:200` / `:680` (`encode_msg`, `write_with_retry`) | NYI: bytecode UCLO | 22+11+11+11+10 |
| `ipc.lua:680` / `:704` / `:708` / `:748` / `:814` (`set_pending`, `overwrite_pending`) | blacklisted / inner loop | 19+8+11+8+11 |
| `ipc.lua:706` / `:745` / `:749` | inner loop / blacklisted | 22+10+18 |
| `ipc.lua:441` / `:445` / `:687` / `:90` / `:76` / `:68` | leaving loop in root trace | 11+11+11+1+1+1 |
| `dns_ede.lua:391` / `:380` / `:412` / `:431` / `:274` (closures de `strip_rrtypes`/`clear_ad_bit`) | NYI: bytecode FNEW | 32+11+10+11+11 |
| `dns_ede.lua:287` / `:291` / `:338` / `:342` (boucles de `strip_rrtypes`) | inner loop / blacklisted | 11+19+8+8 |
| `dns_ede.lua:326` / `:337` / `:394` / `:412` | leaving loop / blacklisted | 11+11+11+1 |
| `log.lua:676` (`now` : `clock_gettime`) | blacklisted | 26 |
| `log.lua:676` | leaving loop in root trace | 11 |
| `second_opinion.lua:166` (`corr_key`) | leaving loop in root trace | 11 |
| `second_opinion.lua:175` / `:199` / `:206` / `:209` / `:221` / `:223` / `:233` (`expired`, `take_parked`) | inner loop / UCLO / blacklisted | 11+11+11+4+11+11+4 |
| `response_inject.lua:78` (`inject`) | leaving loop in root trace | 11 |
| `response_inject.lua:109` | leaving loop in root trace | 11 |
| `dns.lua:245` / `:295` / `:197` / `:222` / `:303` (`label`, `labels`, `parse_rr`) | leaving loop / loop unroll | 11+11+2+1+11 |
| `dns_response.lua:89` / `:104` (`parse_answers`) | leaving loop in root trace | 11+2 |
| `dns_classify.lua:12` / `:40` / `:115` | leaving loop in root trace | 1+2+2 |
| `init.lua:160` / `:191` (moteur de conditions) | UCLO / blacklisted / inner loop | 10+7+4 |
| `ip4.lua:61` / `ip.lua:64` / `udp.lua:46` | NYI return to lower frame / leaving loop | 11+1+10 |
| `pack_compat_lib.lua:635` | leaving loop in root trace | 1 |
| `tcp_stream.lua:119` | leaving loop in root trace | 3 |
| `tsv.lua:3` | NYI: return to lower frame | 4 |
| `sessions.lua:289` | blacklisted | 4 |

Interprétation (sans sur-interprétation) :
- **`NYI: bytecode FNEW` / `UCLO`** = une closure est créée/fermée dans la
  trace : les sites restants sont les closures de `finalize_a`
  (`worker_responses.lua:545`), celles de `strip_rrtypes` (`dns_ede.lua:274` et
  suivants : `u16`/`skip_name` captent `dns_payload`/`len` et sont réalloués à
  chaque appel) et celles de `encode_msg`/`write_with_retry`. Ce sont des
  candidats à un refactoring « paramètres explicites », mais aucun ≥ 5 % mesuré
  isolément ;
- **`blacklisted`** = le site a échoué trop souvent et n'est plus tenté
  (`ipc.lua:472` = `make_key` avec `string.format`, `log.lua:676` =
  `clock_gettime` FFI) : ces deux-là ne sont pas supprimables (formatage de
  clé, horloge) ;
- **`inner/leaving loop in root trace`** = borne du traceur sur les boucles de
  filtrage (`rule.lua:215` = boucle des règles, `worker_questions.lua:198` =
  `append_unique`) : comportement normal de LuaJIT, pas un défaut ;
- **`loop unroll limit reached`** (`rule.lua:199`, `:266`) : débordement du
  nombre de règles/déroulés — sans conséquence de comportement.

---

## 5. Classification des causes et correctifs chiffrés

### 5.1 Appliqués (gain mesuré ≥ 5 %, sans changement de comportement)

| # | Cause | Correctif | Gain mesuré | Commit |
|---|---|---|---|---|
| 1 | **Encodage hex par closure + `string.format` par octet** : `to_hex` faisait un closure, un `string.format "%02x"` et un `c\byte!` pour CHAQUE octet — présent dans `encode_msg` (3 appels/message) et `build_line` (2 appels × 16 lignes nft par réponse) | table 256 entrées passée à `gsub` (`src/lib/ipc_hex.moon:25-27,49-62`) | question **−24 %**, response **−30 %**, so_cycle **−34 %**, ipc_drain −16 % | `b3d44d0` |
| 2 | **Décodage hex par `sub`+`tonumber`+`string.char` par paire**, plus un motif `^[0-9a-fA-F]+$` : 48,5 % du tube IPC | lecture par octet + table de nibbles, validation inline (`src/lib/ipc_hex.moon:68-73,81-104`) | ipc_drain **−21 %** (≈ −2,5 µs/paquet sur le chemin réponses complet en production) | `552be16` |
| 3 | **Boucle de suffixes de domaine** : `_domain\sub(pos+1)` allouait une sous-chaîne par point et par condition — ~150 conditions/ question avec les règles par défaut | rejet O(1) par le dernier octet (`src/filter/conditions/to_domain.moon:39,50-51`) + comparaison sans allocation (`:56-63`) | question **−25 %** | `9013d37` |
| 4 | **Re-parse de la réponse à chaque fois** alors que `dns_msg` vient d'être construit à partir du même octet | re-parse uniquement si `payload_modified` (callback `on_response` ou strip dynamique) — `src/worker_responses.moon:767-776` | response **−11 %**, so_cycle **−10 %**, allocation −15 % | `e84ee03` |
| 5 | **Re-conversion des mêmes chaînes** : `rule_id`/raison/`corr` réencodés 32 fois par réponse et identiques d'un paquet à l'autre | cache borné 8 entrées, purge en bloc (`src/lib/ipc_hex.moon:29-43,56-61,98-103`) | ipc_drain **−38 %**, so_cycle **−27 %**, response **−15 %**, question −6 % | `b2331c8` |

Effet cumulé : **question −49 %, response −46 %, so_cycle −56 % (cycle second
avis 220,6 → 94,7 µs), ipc_drain −48 %** ; allocation par paquet −16 %
(`response`), −19 % (`so_cycle`), −28 % (`ipc_drain`).

### 5.2 Proposés, NON appliqués (soit < 5 % mesuré, soit trop risqués)

| Cause | Site | Gain estimé | Pourquoi non appliqué |
|---|---|---|---|
| `is_valid_timeout` (motif Lua) appelé à chaque ligne nft | `src/lib/ipc_hex.moon:140-143`, appelé par `nft_queue.sanitize_timeout` (`src/nft_queue.moon:92-101`) | ≈ 3-4 % de `response`/`so_cycle` (3,8-4,2 % des échantillons) | **sous le seuil de 5 %** ; memo à1 entrée sûr mais gain insuffisant seul |
| `build_line` : table9 slots + `table.concat` + concat `"\n"` par ligne | `src/nft_queue.moon:200-211` | ≈ 2-3 % (concaténation directe de9 chaînes courtes : LuaJIT compile `..` en `CAT`) | sous le seuil ; à mesurer avec le banc avant/après si on veut le tenter |
| `parse_answers` construit9 champs par RR alors que `finalize_a` n'utilise que `rtype`/`rdata_str`/`ttl` | `src/lib/dns_response.moon:72-83`, consommé par `src/worker_responses.moon:787` | ≈ 2-3 % (`dns_response.lua:98` = 5,1 % de `so_cycle`) | sous le seuil ; changer la forme de sortie casserait `doh/query` |
| Closures `u16`/`skip_name`/`resolve` réallouées à chaque appel de `strip_rrtypes`/`strip_dns_rr` | `src/dns_ede.moon:286-311,367-379` | ≈ 2-4 % (`strip_https_rr` = 5,0-5,7 % de `response`, dont une part est le scan lui-même) | refactoring « paramètres explicites » partagé avec DoH, gain non prouvé ≥ 5 % |
| `user_for_mac` : `lookup_mac\lower!` alloue à chaque paquet, `read_cached` + `session_for_mac` = 7,9 % de `question` | `src/auth/sessions.moon:265-278,285-319` | ≈ 1-2 % réel (le profil surévalue les appels d'horloge : biais d'échantillonnage mur) | sous le seuil ; le `\lower!` est nécessaire à la correction des casse |
| Évaluation des règles (`eval`, `cond`, `details_of`) : 10-30 % de `question` | `src/filter/rule.moon:173-200,202-236` | inconnu (réécriture du moteur) | **trop risqué** : c'est la sémantique de filtrage elle-même ; à découper en sous-tâche avec sa propre campagne |
| `sp`/`su`/`checksum` (pack/unpack) dans la duplication validateur : 5,8 + 5,3 % de `question` | `src/lib/moontastik/ipparse/lib/pack_compat*` | ≈ 5-8 % de `question` | **sous-module moontastik non modifiable ici** (cf. `Makefile:61-68`) |
| `parse_rr`/`labels`/`label`/`need_bytes` : 40-50 % de `so_a`, ~15 % de `response` | `src/lib/moontastik/ipparse/lib/l7/dns.lua` | ≈ 15 % de `response` | **sous-module moontastik non modifiable** — le poste résiduel le plus gros avec le GC |
| GC (29-47 % des échantillons) | partout | ~20-30 % si on divise l'allocation par 2 | nécessite une campagne d'ensemble (voir ci-dessous), pas un correctif local |
| Réduire les appels d'horloge (`log.now`, `current_benchmark_ms`) | `src/log.moon:487-489`, `src/worker_responses.moon:282-293` | < 1 % | sous le seuil |

**Piste principale résiduelle** : diviser l'allocation par paquet (11,2 Ko sur
`response`, 32,9 Ko sur `so_cycle`) — les trois plus gros blocs sont le parsing
DNS (`parse_rr`/`labels`, sous-module), `parse_answers` et les16 lignes nft
(`build_line` + `to_hex` non caché). Une campagne dédiée (mesure
`collectgarbage("count")` par sous-chemin, puis restructuration ciblée) est la
suite logique ; elle dépasse le cadre « correctifs sûrs et locaux ≥ 5 % » de
cette tâche.

---

## 6. Ce qui n'a pas été fait / reste douteux

- **Aucune mesure sur la cible aarch64** (consigne : aucun accès distant) : tous
  les chiffres sont en x86-64 local. Les **ratios** (part de `to_hex`, du GC,
  des suffixes de domaine) sont ce qui se transpose ; les µs absolus non
  (1,3-1,6 ms/paquet sur A55 ↔ 50 µs ici : rapport ~25×).
- **Le banc ne reproduit pas** : l'attente d'ACK nft (`wait_ack` sans
  `ack_rfd`), le coût réel des syscalls `sendto`/`write` netlink du worker nft,
  `metrics.flush_if_due`/`sweep_parked` appelés par le `on_idle` du banc (le
  banc les appelle dans la préparation), ni la fragmentation des paquets TCP.
  Le `raw_send` stubé signifie que la duplication validateur ne paie pas son
  `sendto` (≈ 1 µs en production).
- **`so_a` est bruyant** (22,6 à 33,8 µs selon les passages) : son coût est
  faible et sa variance domine ; le minimum de lot (19-20 µs) est stable.
- **Le cache hex** rend `to_hex`/`from_hex` sensibles au nombre de clés
  distinctes : avec > 8 clés cycliques la purge est fréquente (perte bornée, pas
  d'erreur possible — les fonctions sont pures). En production, le worker
  réponses n'a que2 clés (`rule_id`, `corr` par réponse) et le worker questions
  ~3-6 : les taux de hit mesurés ici (≈ 100 %) restent représentatifs.
- **`make test-e2e` non lancé** dans cette branche : les4 correctifs ne
  changent que des calculs purs (sorties hex identiques, re-parse conditionnel,
  suffixes équivalents) et sont couverts en unitaire ; le homelab n'était pas
  sollicité ici. À lancer avant fusion (cf. `AGENTS.md` § Definition of Done).
- **Les parts d'échantillons `log.lua:678` (`now`) sont suspectes** (5,8 % de
  `response` pour2-3 `clock_gettime` ≈ 0,1 µs) : biais probable de
  l'échantillonnage mur autour des appels système — à ne pas prendre pour un
  gain réalisable.
