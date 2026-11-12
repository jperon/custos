# Rapport — workers multiples sur custos.lan et écart compteur nft / id_sequence

Date : 2026-11-12. Worktree `d-bench3`, branche courante. Aucune modification de
`src/`. Résultats bruts : `tmp/bench3/results/`. Scripts : `tmp/bench3/`
(`dnsload3.py`, `sampler3.sh`, `counters.sh`, `runphase3.sh`, `analyse3.py`).
Documentation mise à jour : `docs/agents/perf.md` §12.

## 1. Fait / non fait

**Fait**

- Relecture de `docs/agents/perf.md` (campagne §1-§11) et du code réel du
  multi-worker (`src/main.moon`, `src/ipc.moon`, `src/worker_questions.moon`,
  `src/worker_responses.moon`, `src/nfq_loop.moon`).
- Harnais de mesure réécrit pour la configuration déployée (files 0/1 et 14/15,
  compteurs nft et NFQUEUE lus **dans le même instantané**, CPU par worker).
- Mesure d'un palier de contrôle à 40 q/s `mixed` (8 s) avant incident :
  320/320 réponses, 0 % de perte, p50/p99 4,6/18,3 ms, **tout le trafic dans
  une seule file de chaque plage** (questions : file 1 ; réponses : file 15).
- Palier 300 q/s `mixed` (30 s) : **0 réponse sur 9 000**, `user_dropped`
  +8 553 sur la file 1, diagnostic du défaut bloquant (ci-dessous).
- Point 3 (écart nft / `id_sequence`) **résolu** : compteurs identiques au
  paquet près quand ils sont lus au même instant (Δ nft +9 010 = Δ
  `id_sequence` file 1 +9 010, file 0 Δ 0, résidu 0).
- Section datée ajoutée à `docs/agents/perf.md` (§12) ; rapport ci-dessous.

**Non fait (et pourquoi)**

- Paliers 300/400/500/700 `mixed` et 500/800 `up` : **impossible après le
  premier palier**. Le service est tombé en blocage définitif (§4) : 0 réponse
  DNS à 300, 200, 100 et même 40 q/s ensuite, et une sonde unique à 08:40 est
  restée sans réponse. Aucun redémarrage n'était autorisé (accès lecture seule),
  donc pas de reprise possible.
- Point 2 (varier l'IP source) : `servus` n'a **qu'une** adresse dans
  10.35.1.0/24 (`10.35.1.2/24` sur `wan`) ; les autres adresses sont sur
  d'autres sous-réseaux (`virbr*`, `docker*`, `tailscale0`, …). Changer l'IP
  source demanderait de modifier le réseau, ce qui était interdit → non fait.
- Comparaison chiffrée avec la référence §7.1 : **non valide**, pour deux
  raisons indépendantes : (a) le client `servus` n'était pas authentifié
  pendant la campagne (profil allégé, §3.1) ; (b) le service a bloqué.

## 2. Dispositif et méthode

- Cible : `custos.lan`, OpenWrt, noyau 6.12.74 aarch64, build `dev` courant
  (merge `d-multi`). Configuration déployée constatée par `nft list ruleset` :
  `queue to 0-1` (questions) et `queue to 14-15` (réponses) ; workers
  `custos:dns-q0` (pid 1421), `custos:dns-q1` (1422), `custos:resp-q14`
  (1418), `custos:resp-q15` (1419), `custos:nft` (1420).
- Générateur : `tmp/bench3/dnsload3.py` (variante de `tmp/bench2/dnsload2.py`,
  ajout des profils `up`/`tls`), exécuté sur `servus.lan` par `python3 -`
  (stdin, rien installé), vers `10.35.1.1:53`, un seul générateur à la fois
  (vérifié par `pgrep` avant chaque palier).
- Compteurs : `tmp/bench3/counters.sh` lit, dans un **seul** appel SSH, le
  compteur de la règle nft puis `/proc/net/netfilter/nfnetlink_queue`
  (`queue_total`, `queue_dropped`, `user_dropped`, `id_sequence` par file).
- CPU : `tmp/bench3/sampler3.sh`, 1 Hz, `utime+stime` de chaque `main.lua` ;
  HZ vérifié à 99,2 via `/proc/stat` (4 vCPU).
- Journal : `logread -l 60000` après chaque palier, filtré localement sur
  l'epoch de la fenêtre (`logread -e` de busybox n'est pas appliqué avant `-l`
  et n'accepte pas les alternatives POSIX — constaté).

## 3. Résultats mesurés

### 3.1 Profil réellement exercé (écart avec §7.1)

`servus` n'était **pas authentifié** : `auth_server_login_success
user=j@prn.ovh mac=d8:d3:85:63:6b:27` à 08:21:56, lignes `ALLOW
rule=r_utilisateurs user=j@prn.ovh` jusqu'à 08:24:07, puis `BLOCK
rule=r_refus_a_priori` **sans champ `user`** dès 08:27:06 — soit ~5 min après
le login, ce qui correspond à `auth.idle_timeout: 300`
(`src/config.moon:317`, utilisé comme expiration de session dans
`src/auth/handlers.moon:142-147,199-201`). Le profil `mixed` exercé est donc
70 % de refus a priori (controlplane/login/NX) + 30 %
`vpn.stemarie.dynv6.net` autorisé par `r_ouverture_complete` (1-2 RR), et non
40 % de Tailscale autorisé par `r_utilisateurs` (8 RR + second avis +
injection nft). Le coût nft mesuré le confirme : 0,7 % d'un vCPU à 40 q/s,
contre 50 % à 200 q/s dans §2 de `perf.md`.

### 3.2 Tableau

| palier | émis/reçus | perte | p50/p99 | `dns-q1` | `resp-q15` | `nft` | `doh` | `user_dropped` q1 | nft q 0-1 Δ | `id_sequence` q1 Δ | q0 Δ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 40 q/s `mixed`, 8 s | 320/320 | 0 % | 4,6/18,3 ms | 4,4 % | 4,6 % | 0,7 % | 100,1 % | 0 | +321 | +320 | 0 |
| 300 q/s `mixed`, 30 s | 9000/0 | **100 %** | n.m. | 1,4 % | 0,1 % | 0,1 % | 97,1 % | **+8 553** | +9 010 | +9 010 | 0 |

Détails 300 q/s : `queue_dropped` = 0 partout, `queue_total` = 164 en fin de
palier (max 216), nft « queue to 14-15 » Δ = 0, `id_sequence` q14/q15 Δ = 0,
**aucune ligne `response_dns_benchmark`** dans la fenêtre (aucune réponse
traitée). WARN de la fenêtre : `questions_queue_read_enobufs` ×1,
`questions_ipc_write_failed_exhausted` ×1, `questions_ipc_write_failed` ×1.

Détails 40 q/s : 321 lignes benchmark (220 `r_refus_a_priori`, 101
`r_ouverture_complete`), `ack_wait_us` non nul 25/321 (p99 6 909 µs, max
7 219 µs), `response_entry_ms` p50/p99 = 1/15 ms, `q_to_response_ms` 3/17 ms.
Répartition : questions **file 1 uniquement** (`id_sequence` q0 Δ = 0), réponses
**file 15 uniquement** (q14 Δ = 0).

### 3.3 Répartition entre files — réponse à la question posée

Le hachage noyau est `jhash_3words(min(saddr,daddr), max(saddr,daddr), proto)`
(symétrique, sans les ports ; cf. `perf.md` §11.1). Avec un seul client
(10.35.1.2) et un seul résolveur (10.35.1.1), **tous** les paquets des deux sens
tombent dans la même file : file 1 pour les questions, file 15 pour les
réponses. Les deuxièmes workers (`dns-q0`, `resp-q14`) ne reçoivent rien de
cette charge : `resp-q14` ne voit que des réponses de validateurs (29 paquets
sur toute la campagne). **Le multi-worker n'apporte donc aucun gain pour une
charge mono-client** — et c'est précisément ce cas qui a déclenché le défaut
§4.

## 4. Défaut bloquant (décrit, non corrigé)

**Symptôme.** Dès 08:31:19, `custos:dns-q1` boucle sur
`action=questions_ipc_write_failed_exhausted errno=11 attempts=5 fd=7`
(EAGAIN vers `resp-q14`), `suppressed` croissant (4 → 23 → 135 → 524), puis
`fd=9` (vers `resp-q15`) à partir de 08:36:22. Chaque échec coûte 5 × 20 ms de
`nanosleep` (`src/ipc.moon:110-127`) ; le worker passe en `nanosleep`
(syscall 101) et ne traite plus que ~10 q/s, d'où `user_dropped` +8 553. Le
service ne répond plus ensuite, même à 40 q/s (essais 40/100/200/300 après
l'incident : 0 réponse à chaque fois ; sonde unique à 08:40 : timeout).

**Mécanisme (code).**

1. Deux tubes question→réponse sont créés (`pipe_resize fd=7
   name=question_response`, `fd=9 name=question_response2`, 65 536 o ;
   `src/main.moon:84-85,108-125`) et le worker questions écrit dans **tous**
   (`write_with_retry_all`, `src/ipc.moon:137-143`).
2. Un worker réponses ne draine son tube que dans `handle_response`
   (`src/worker_responses.moon:1012-1018`), donc **seulement quand un paquet
   arrive sur sa file**. Le fd du tube n'est pas dans le `poll` :
   `extra_rfds` ne contient que le bus de verdicts
   (`src/worker_responses.moon:1390-1393`), `on_idle` = `sweep_parked` ne
   draine que ce bus (`src/worker_responses.moon:918-927`), et
   `nfq_loop.run_queue` ne surveille que le fd netlink et `extra_rfds`
   (`src/nfq_loop.moon:117-156`).
3. `resp-q14` (file 14) ne reçoit presque rien → son tube n'est presque jamais
   drainé → ses 64 Kio se remplissent (~200 o/message, ~320 messages ; le
   palier de 40 q/s y a écrit exactement 320 messages, et les premières erreurs
   apparaissent 4 min plus tard avec le trafic résiduel).
4. `write_with_retry_all` renvoie `false` dès qu'**un** destinataire échoue ;
   `worker_questions` traite cet échec comme définitif : `return NF_DROP`
   (`src/worker_questions.moon:449-464`). La question n'atteint pas le
   résolveur → pas de réponse → `resp-q15` ne reçoit plus de paquet → **son**
   tube cesse d'être drainé → blocage définitif jusqu'au redémarrage.

**Portée.** Défaut propre au multi-worker : il se déclenche dès qu'une file de
la plage reste inactive assez longtemps (cas systématique avec un seul client,
cas réel dès qu'un déséquilibre dure quelques centaines de requêtes). Pistes
sans les appliquer : ajouter le fd du tube aux `extra_rfds` du worker réponses
(et le drainer dans `on_extra_ready`), et/ou ne pas jeter la question quand un
seul des fan-out a échoué.

## 5. Écart compteur nft / `id_sequence` (PASSATION §7.4) — conclusion

Compteur nft et table NFQUEUE lus dans le **même** appel SSH (nft d'abord),
avant/après le palier de 300 q/s :

| instant | nft « queue to 0-1 » | `id_sequence` q0 | `id_sequence` q1 | q0+q1 |
|---|---|---|---|---|
| avant (08:32:48) | 678 | 0 | 678 | 678 |
| après (08:34:41) | 9 688 | 0 | 9 688 | 9 688 |
| **Δ** | **+9 010** | **0** | **+9 010** | **+9 010** |

`queue_dropped` = 0 et `user_dropped` = 0 sur les questions avant le blocage
(`user_dropped` monte pendant, sans effet sur `id_sequence`). **Résidu 0**, et
valeurs absolues égales : les deux compteurs comptent exactement les mêmes
paquets. **L'écart de PASSATION (+15 165 contre +11 693, soit −3 472) n'est pas
expliqué par la répartition 0/1** : pour cette charge, la file 0 ne reçoit
aucun paquet (Δ = 0). Il venait de la mesure (relevés non simultanés, ou
`id_sequence` remis à 0 par une recréation de file lors d'un redémarrage de
worker — le compteur est propre à l'instance NFQUEUE). À noter : la file 0
reçoit du trafic d'autres clients à d'autres moments (248 paquets observés
après la fenêtre), donc un partage 0/1 reste possible en général, mais pas ici.

## 6. Anomalie annexe : worker DoH à ~100 % d'un vCPU au repos

`custos:doh` (pid 1426) : 71 914 jiffies utime + 22 397 stime à 08:32:46 alors
qu'il a démarré à 08:18:05 ; mesure directe à 08:41 : **98,6 %** d'un vCPU sur
5 s, état `running` permanent, aucun log d'erreur récent (derniers
`doh_h2_failed err=h2_incomplete` à 06:11/06:13, instance précédente). Un cœur
sur quatre est donc indisponible en permanence. Ce n'est pas la cause du
blocage (le worker questions est en `nanosleep`, pas affamé), mais cela abaisse
le plafond de la machine et fausse toute comparaison CPU avec §7.1.

## 7. Vérifications

- `make all && make check && make test` : **2854 successes / 0 failures /
  0 errors / 0 pending** (82,7 s), plus 12/12 tests Node
  (`tests/unit/auth/portal_client.test.js`). Sortie complète :
  `tmp/test.log`.
- Aucun fichier de `src/` modifié ; seuls `docs/agents/perf.md` et ce rapport
  sont ajoutés (résultats bruts sous `tmp/bench3/`, ignorés par git).
- Aucune écriture sur `custos.lan` (lecture seule : `/proc`, `logread`,
  `nft list`) ; aucune installation sur `servus.lan` (générateur passé par
  stdin) ; aucun générateur laissé actif ; aucun `/etc/custos/*` lu.
