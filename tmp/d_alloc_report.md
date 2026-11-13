# Rapport de campagne — réduction des allocations par paquet (branche `d-alloc`, 2026-11-13)

Objectif : réduire les allocations par paquet dans custos (hors ipparse) pour
servir la montée à 1000 q/s (`docs/agents/perf.md` §16-§18, rapport
`tmp/prof_report.md` de la branche `d-prof`). Documentation détaillée :
**`docs/agents/perf.md` §19**. Artefacts bruts : `tmp/alloc/`.
Tout a été fait en local — aucun accès réseau, aucun déploiement, aucun push.

---

## 1. Méthode

1. **Répartition par sous-chemin avant toute modification** (consigne) :
   `tmp/alloc/split.lua` rejoue les six cas du banc `make bench-hotpath` avec
   des wrappers d'allocation (`collectgarbage "count"`, GC arrêté, delta
   inclusif/exclusif) autour des fonctions des modules appelés par les
   workers. Résultat : `tmp/alloc/split_run1.txt` (avant) et
   `tmp/alloc/split_run2.txt` (après correctifs).
   - Le script récupère `setup`/`build_cases` via `debug.getupvalue` sur
     `hotpath.main` (ces fonctions ne sont pas exportées par le module).
2. **A/B alterné dans la même fenêtre** par correctif : `make bench-hotpath
   HP_REPEAT=5` (minimum de lot = métrique retenue, cf. consigne et §18.1),
   état A (`git stash` des fichiers du correctif) puis B, deux couples A/B
   par correctif, témoins = cas non visés du même run.
3. **TDD** : test d'allocation GC arrêté dans le spec du fichier modifié,
   seuil calibré entre la mesure avant/après, constaté en échec avant le
   correctif puis en succès après (captures dans les sections 3).
4. `nix develop --command bash -c "make check && make test"` après chaque
   étape ; `make test-e2e` en fin de campagne.

### Pièges de mesure constatés (à réutiliser)

- **LuaJIT interne les strings identiques** : une boucle qui produit la même
  string mesure 0 o (constaté sur `strip_https_rr` avec inputs constants,
  et sur `tostring` de valeurs fixes).
- **Le JIT élimine les appels dont le résultat est ignoré** : il faut un
  sink (`sink = sink + #f()`) sinon la mesure tombe à 0 (constaté sur
  `build_line` et `strip_https_rr`).
- **`luassert.is_true` alloue à chaque appel** : +1 100 o/ligne dans une
  boucle mesurée (constaté : 1748 vs ~525 o/ligne) — pas d'assert dans les
  boucles de mesure.
- La mesure du spec `worker_responses_finalize_spec` varie avec les
  correctifs des *autres* modules qu'il charge (dns_ede n'est pas stubbé) :
  3897 → 3277 → 2710 o/appel au fil de la campagne.

---

## 2. Répartition initiale (o/itér, GC arrêté — `tmp/alloc/split_run1.txt`)

| cas | total | principaux postes |
|---|---|---|
| `question` | 6 664 | `parse_dns_packet` 2048 *(ipparse)*, `dup_query.build_udp` 1536 *(non nommé)*, `filter.decide_meta` 536 *(filtre)*, `ipc.write_msg` 328, reste 2216 (dont `write_event` — hors périmètre) |
| `ipc_drain` | 1 884 | `ipc.drain_pipe` 1624 |
| `response` | 10 883 | `parse_dns_packet` 2632 *(ipparse)*, `nft_queue.enqueue` 1091, `dns_ede.patch_modified_dns` 1040, `ipc.set_pending` 632, `dns_response.parse_answers` 536, `filter.run_on_response` 456 *(filtre)*, reste 3998 |
| `so_a` | 8 994 | `parse_dns_packet` 6600 *(ipparse)* |
| `so_cycle` | 30 544 | `parse_dns_packet` 9232 *(ipparse)*, `nft_queue.enqueue` 8714 (**16 lignes**), `dns_response.parse_answers` 3720, `patch_modified_dns` 1088 |
| `setup_control` | 890 | (témoin de préparation) |

`build_line` coûtait **~545 o par ligne** (mesure directe :
`tmp/alloc/measure_build_line.lua`, 410-545 o selon le contexte).

---

## 3. Fait — 6 correctifs, un commit chacun

Chaque ligne : fichier:ligne du changement, mesure A/B (deux couples),
test TDD constaté en échec avant / succès après.

### 3.1 `nft_queue.build_line` en concaténation directe — `21a7acf`

- **Fichier** : `src/nft_queue.moon:200-209` (compilé `lua/nft_queue.lua`).
  `table.concat` sur un tableau de 9 champs puis `.. "\n"` (2 strings +
  1 table par ligne) → concaténation directe des 9 champs, `"\n"` en
  dernier opérande (1 string par ligne). Le tableau de 9 éléments et la
  copie intermédiaire disparaissent.
- **Mesure** (`tmp/alloc/ab_A1.txt` … `ab_B2.txt`, HP_REPEAT=3) :
  - `so_cycle` : alloc 30 601 → 28 297 o/itér (**−7,5 %**), temps total
    9,06 → 8,48 s (**−6,5 %**) ;
  - `response` : 10 935 → 10 647 (−2,6 %) ;
  - témoins : `question` 6664, `so_a` 8994, `ipc_drain` 1906,
    `setup_control` 890 — inchangés.
- **Test** : `tests/unit/nft_queue_spec.moon:475` « enqueue alloue < 300 o
  par ligne » — **échec avant : 372 o/ligne ; succès après : 225**.
  Format 9 champs inchangé (spec « add_ip4 propage rule_id » + e2e).

### 3.2 `parse_answers` réduit aux 3 champs lus — `0674b10`

- **Fichier** : `src/lib/dns_response.moon:72-84`. 9 champs/RR → 3
  (`rtype`, `rdata_str`, `ttl`) : seuls champs lus par
  `src/worker_responses.moon:825-828` (boucle de `finalize_a`).
  Vérifié : `doh/query` a sa propre `normalize_answers`
  (`src/doh/query.moon:131`) et n'appelle jamais `parse_answers` ;
  `ndpi.parse_answers` (`tests/test_ndpi.lua:149`) est un autre module ;
  aucun lecteur des 6 champs supprimés (grep `src/ tests/`).
- **Mesure** (`tmp/alloc/ab_pa_*.txt`) : `so_cycle` alloc 28 297 → 25 993
  (**−8,1 %**), lot-min 37,9 → 35,0 µs (**−7,5 %**) ; `response` 10 647 →
  10 359 (−2,7 %) ; témoins `question`/`so_a` inchangés.
- **Test** : `tests/unit/lib/dns_response_spec.moon` (describe
  `parse_answers`) — contrat des 3 champs + allocation **échec avant :
  3723 o/appel (8 RR) ; succès après : 1419** (seuil 1800).

### 3.3 `dns_ede.strip_rrtypes` sans closures ni sets réalloués — `5ec6028`

- **Fichier** : `src/dns_ede.moon:311-430`. `u16`/`skip_name`/
  `copy_section` (closures réallouées à chaque appel, visibles en
  `NYI: bytecode FNEW` §18.4) → fonctions de module `u16_at`,
  `skip_name_at`, `copy_section` à paramètres explicites ; `strip_dns_rr`
  construisait `resolve` + `set` par appel → sets précalculés `A_SET`,
  `AAAA_SET`, `HTTPS_SVCB_SET` (`src/dns_ede.moon:23-25`).
- **Mesure** (`tmp/alloc/ab_ede_*.txt`) : `response` alloc 10 359 → 9 623
  (**−7,1 %**), lot-min 24,7 → 20,8 µs (**−16 %**) ; `so_cycle` −2 800 o ;
  témoins inchangés. Isolé : `strip_https_rr` 1040 → 304 o/appel.
- **Test** : `tests/unit/dns_ede_spec.moon` « strip_https_rr alloue < 800 o »
  — **échec avant : 1040 ; succès après : 304**. 29 specs dns_ede intacts.

### 3.4 `finalize_a` sans closures lourdes — `d44a9c6`

- **Fichier** : `src/worker_responses.moon:671-723`. Suppression des 3
  closures par paquet : `client_addr` (6 upvalues) → `client_addr_of(ctx,
  fam)` avec memoïsation dans le ctx (la closure restante
  `inject_opts.client_addr` ne capture plus que `ctx`) ;
  `inject_answers` → fonction de module `(ctx, inject_opts, answers)` ;
  `patch_and_accept` (≈15 upvalues) → fonction de module
  `(ctx, new_dns, action_label)` ; tables `ADD_IP`/`ADD_MAC` précalculées.
- **Mesure** (`tmp/alloc/ab_fin_*.txt`) : `response` alloc 9 623 → 8 503
  (**−11,6 %**), lot-min 21,6 → 20,7 µs ; `so_cycle` 25 257 → 24 137
  (−4,4 %) ; témoins inchangés.
- **Test** : `tests/unit/worker_responses_finalize_spec.moon` « finalize_a
  alloue < 3550 o » — **échec avant : 3897 ; succès après : 3277** (le
  strip scratch de §3.6 le porte ensuite à 2710).

### 3.5 `ipc.encode_msg` + timespec partagé — `549560f`

- **Fichier** : `src/ipc.moon:204-264` (concat directe des 14 champs,
  `response_ids_hex = ""` sans tableau quand la liste est vide —
  `to_hex("") = ""`, comportement identique) et `src/ipc.moon:41,119`
  (`sleep_req` module-level au lieu d'un cdata timespec FFI par écriture ;
  nanosleep synchrone, aucun rappel Lua → réutilisation sûre, même motif
  que `nft_queue.sleep_req`).
- **Mesure** (`tmp/alloc/ab_ipc2_*.txt`, HP_REPEAT=5) : `question`
  alloc 6664 → 6448 (−3,2 %), **lot-min 25,3 → 23,5 µs (−7,1 %)** ;
  poste isolé `encode_msg` 757 → 340 o/appel (−55 %) ; témoins `ipc_drain`
  1906 o, `response`, `so_a` inchangés.
- **Test** : `tests/unit/ipc/ipc_spec.moon` « encode_msg alloue < 550 o » —
  **échec avant : 757 ; succès après : 340**.
- *Écart au seuil honnête signalé* : l'allocation du cas `question` ne
  baisse que de 3,2 % (le reste du chemin est hors périmètre : ipparse
  2048, dup_query 1536, write_event ~800, decide_meta 536) ; c'est le
  **minimum de lot (−7,1 %)**, métrique retenue par la consigne, qui
  dépasse 5 %.

### 3.6 `strip_rrtypes` sans tables réallouées — `55bd240`

- **Fichier** : `src/dns_ede.moon:313-314` (scratch `_scratch_qp` /
  `_scratch_sec`, déclarés avant `copy_section` pour la portée Lua),
  `src/dns_ede.moon:379-395` et `:355-360` (reset des tables au lieu de
  `{}` par appel). Non réentrant vérifié : `clear_ad_bit`/`add_ede_modified`
  ne strip pas ; `doh/query` appelle `patch_modified_dns` de façon
  séquentielle ; les strings résultat sont recopiées par `table.concat`
  avant le retour, jamais retenues.
- **Mesure** (`tmp/alloc/ab_de2_*.txt`, HP_REPEAT=5) : `response`
  **lot-min 21,15 → 19,9 µs (−5,9 %)**, temps total 2,38 → 2,27 s (−4,7 %),
  alloc 8481 → 8177 (−3,6 %) ; `so_cycle` (mesuré avec le lot worker_responses
  reverté) inchangé à ±bruit.
- **Test** : `tests/unit/dns_ede_spec.moon` « strip_https_rr alloue < 230 o »
  — **échec avant : 305 ; succès après : 0** (0 = LuaJIT interne la string
  résultat pour inputs constants ; le seuil 230 reste significatif).

---

## 4. Bilan global (runs identiques HP_REPEAT=5, `tmp/alloc/bench_base.txt` → `tmp/alloc/bench_final.txt`)

| cas | alloc avant | alloc après | Δ alloc | lot-min avant | lot-min après |
|---|---|---|---|---|---|
| `response` | 10 935 | **8 201** | **−24,8 %** | 22,5 µs | 19,6 µs |
| `so_cycle` | 30 601 | **23 785** | **−22,3 %** | 37,9 µs | 31,3 µs |
| `question` | 6 624 | 6 448 | −2,7 % | 24,9 µs | 21,6 µs |
| `so_a` (témoin) | 8 994 | 8 994 | **0** | 25,0 µs | 20,6 µs |
| `ipc_drain` (témoin) | 1 906 | 1 906 | **0** | 3,7 µs | 3,9 µs |
| `setup_control` (témoin) | 890 | 890 | **0** | 0,5 µs | 0,5 µs |

Aucune ligne `ÉCHECS DE VÉRIFICATION` dans `tmp/alloc/bench_final.txt`.
Répartition post-campagne (`tmp/alloc/split_run2.txt`) : `response` 8473 o
(contre 10 883), `so_cycle` 24 059 (contre 30 544).

---

## 5. Tests — totaux exacts

- Référence avant campagne : **1920 successes / 0 failures** (base commune)
  — la suite complète évolue avec les autres branches ; dans cette branche :
- Après le dernier correctif :
  `nix develop --command bash -c "make check && make test"` →
  **`3185 successes / 0 failures / 0 errors / 0 pending`**
  (`tmp/alloc/test7.log`, lignes de total lues après chaque étape :
  3180 → 3182 → 3183 → 3184 → 3185 — les +1/+2 sont les tests TDD ajoutés).
- `nix develop --command bash -c "make test-e2e"` →
  **`Résultats : 94 passed, 0 failed`** au premier lancement
  (`tmp/alloc/e2e_1.log`), homelab provisionné, aucune relance nécessaire.

---

## 6. Non fait / reste douteux

1. **Reverté — sous le seuil de 5 %** (chiffres mesurés, version conservée
   dans le diff du rapport, non commitée) :
   - `answers` scratch + `qnames`/`txid_hex` paresseux dans `finalize_a`
     (`src/worker_responses.moon:824,865,684`) : **−3,3 % sur `response`,
     −1,4 % sur `so_cycle`** en allocation (−3 % en temps). Test TDD préparé
     et constaté (seuil 2550, mesure 2710 avant / 3014 après — la mesure du
     spec a même *augmenté* à cause des stubs du spec qui retiennent la table
     scratch, artefact non résolu) — reverté conformément à la consigne.
     Le test `finalize_a` garde le seuil de campagne 3550 o.
   - Fast-path `state == ""` dans `drain_pipe` (`src/ipc.moon:643`) :
     **gain nul** (1129 → 1135 o/message) — LuaJIT optimise déjà
     `"" .. s` ; reverté, son test retiré.
2. **Hors périmètre, non attaqué** (dominants résiduels) :
   - `parse_dns_packet`/`parse_rr`/`labels` (sous-module ipparse) :
     2048 o (`question`), 2632 (`response`), 9232 (`so_cycle`) ;
   - `filter.decide_meta`/`run_on_response` : 536/456 o — sémantique de
     filtrage, « trop risqué » selon `tmp/prof_report.md` §5.2 ;
   - `dup_query.build_udp` : 1536 o (`question`) — fichier non nommé ;
   - `write_event` et l'envoi d'événements — domaine de l'autre agent
     (consigne) ; `worker_questions.moon` est aussi modifié parallèlement
     par une autre branche (`d-batchev`), non touché.
3. **Mesuré mais non modifié** :
   - `make_key`/`string.format` : 4,1 % des échantillons de `response`
     (profil ligne `tmp/alloc/prof_resp.txt`) mais le remplacement par
     concatène ne gagne que 0,015 µs/appel (micro-mesure) — le poste est
     dominé par le log `ipc_pending_overwrite`, émis à chaque écrasement
     dans le banc (txid fixe = artefact du banc, rare en production).
   - `ctx` de `handle_response` (~23 clés hash ≈ 1 Ko) : non réductible —
     les champs `qname`/`vlan`/`af` sont lus par `format_block_event`
     (`src/worker_responses.moon:149-160`), qui écrit dans `events_wfd`
     (hors périmètre). `dnsonly`/`resolver_ip`/`nft_rule_id` sont
     redondants mais leur suppression seuls ne change pas la taille du
     hash part (23 → 20 clés = toujours 32 slots).
   - `decode_msg`/`split_fields` (14 sous-strings) : le format de message
     est un contrat (`worker_nft.parse_line` exige 9 champs,
     `tests/unit/nft_queue_spec.moon:103`) ; refactoring non mesuré ≥ 5 %.
   - `set_pending` 632 o : entry nécessaire (vit jusqu'à la réponse) +
     log overwrite (comportement de log inchangé).
4. **Non mesuré sur cible aarch64** (aucun déploiement, consigne) : tous
   les chiffres sont en x86-64 local ; les **ratios** (parts d'allocation)
   sont transposables, pas les µs absolus (rapport ~25×, §18.2).
5. **Non rejoué** : la campagne de charge `make bench-load`/paliers du §17
   (nécessite le homelab sous charge + client authentifié) — le gain
   réel sur `resp-q*`/`dns-q*` en q/s reste à mesurer sur la cible, idéalement
   en y déployant `make bench-hotpath` (§18.7).
6. `tmp/d_alloc_report.md` est en `tmp/*` (ignoré par git) : à ajouter avec
   `git add -f` si la branche doit le porter (précédent :
   `tmp/bench3_report.md`, `tmp/perfaudit_report.md` sont suivis).
