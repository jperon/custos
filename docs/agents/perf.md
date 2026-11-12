# Performances — goulot DNS sous charge (mesures 2026-11-12)

Diagnostic du plafond de débit du chemin DNS filtré, mesuré sur la pré-production
`custos.lan` (OpenWrt 25.12.2, aarch64 Cortex-A55 ×4, build `dev` = merge
`d-perf`), générateur `servus.lan` (10.35.1.2) → résolveur `10.35.1.1:53`.

Ce document remplace l'interprétation de `tmp/PASSATION.md` §4 et
`tmp/bench2/NOTES_20261112_staircase.md` sur la nature des pertes
(`user_dropped`) et sur la cause du plafond.

## 1. Protocole

- Un seul palier à la fois, 20–30 s, après retour au repos vérifié avant
  démarrage : profondeur de la file 4 = 0 **et** `user_dropped` figé sur 3 s
  (`tmp/bench2/runphase3.sh`), aucun générateur sur servus
  (`pgrep -af "[d]nsload|[p]ython3 -"`).
- Générateur `tmp/bench2/dnsload3.py` (variante de `dnsload2.py`) :
  `mixed` = 30 % `vpn.stemarie.dynv6.net` (A/AAAA), 40 %
  `controlplane/login.tailscale.com` (A/AAAA), 30 % de 10 noms
  `*.nxdomain.invalid` fixes ; `up` = 100 % `vpn.stemarie.dynv6.net` ;
  `nxu` = 100 % NXDOMAIN à noms uniques.
- Instrumentation : `tmp/bench2/sampler4.pl` (Perl, lecture seule de `/proc`,
  aucun fichier écrit sur la cible) : 1 Hz pour `/proc/net/netfilter/nfnetlink_queue`,
  `/proc/stat`, loadavg, `utime/stime/état/RSS/commutations de contexte` de
  chaque `main.lua` ; 20 Hz pour le numéro de syscall courant des workers
  `resp-q4`, `nft`, `dns-q1`.
- Journal : lignes `action=response_dns_benchmark` de la fenêtre, extraites par
  `tmp/bench2/fetch_window.sh` (champs `ack_wait_us`, `upstream_retries`,
  `response_entry_ms`, `log_write_us`, `q_to_response_ms`, `reason`).
- Compteurs nft (`queue to 0-1`, `queue to 4`) et NFQ avant/après chaque palier.
- Résultats bruts : `tmp/bench2/results3/<tag>_{client,meta,sampler,logread}.log`
  (ignorés par git). HZ = 100 (dérivé de `/proc/stat`, déjà établi).

## 2. Chiffres mesurés (état du service au moment des mesures)

CPU = % d'un vCPU, mesuré sur la fenêtre exacte de la charge (jiffies
`/proc/<pid>/stat`, HZ = 100). `ack` = somme des `ack_wait_us` du worker
réponses, rapportée à la durée du palier.

| palier | émis/reçus | perte | RTT client p50/p99 (ms) | `resp-q4` | `nft` | `dns-q1` | `ack` (part du temps) | file 4 max | `user_dropped` Δ |
|---|---|---|---|---|---|---|---|---|---|
| 200 q/s `mixed` | 6000/6000 | 0 % | 22,6 / 70 | 44 % | 50 % | 33 % | **9,18 s / 30 s = 31 %** | 21 | 0 |
| 200 q/s `up` | 6000/6000 | 0 % | 4,7 / 8,8 | 32 % | 10 % | 25 % | **0 s** | 1 | 0 |
| 250 q/s `mixed` | 5000/5000 | 0 % | 28,8 / 161 | 53 % | 48 % | 40 % | 6,11 s / 20 s = 31 % | 68 | 0 |
| 300 q/s `mixed` | 6000/5856 | **2,4 %** | 46,8 / 477 | 55 % | 42 % | 43 % | 5,48 s / 23 s = 24 % | 145 | +253 |
| 500 q/s `mixed` | 14999/6301 | **58,0 %** | 326 / 695 | 52 % | 51 % | 74 % | 10,3 s / 32 s = 32 % | 214 | **+14 674** |

La fenêtre de mesure inclut les ~2-3 s de fin de drainage après l'arrêt du
générateur (le service finit d'écouler son backlog) ; ramenée à la durée du
générateur, la part d'attente d'ACK est de 27-34 % selon le palier.

Détail des attentes d'ACK à 200 q/s `mixed` : n = 6000 lignes, `ack_wait_us`
moyenne 1 530 µs, p90 7 583 µs, p99 11 428 µs, max 19 602 µs ; 1 712 lignes
non nulles, 1 566 > 2 ms. Elles se concentrent sur les réponses de la règle
`r_utilisateurs` (8 enregistrements A par réponse : `ancounts=[(0,74),(1,49),(2,22),(8,95)]`
sur la sonde 20 q/s, et 37/38 et 37/38 des transitions `controlplane A` /
`login A` sont suivies d'une attente non nulle, contre 0/49 pour `vpn A`).

`response_entry_ms` (temps d'attente avant l'entrée dans le worker réponses,
c.-à-d. files NFQUEUE + socket netlink) : 6 ms p50 / 53 ms p99 à 200 q/s ;
33 / 464 ms à 300 q/s ; 300 / 641 ms à 500 q/s. `question_proc_ms` reste
≤ 5 ms dans tous les paliers.

## 3. Hypothèse par hypothèse

### 3.1 Attente synchrone de l'ACK nft — **CONFIRMÉE (goulot principal)**

Mécanisme (code, avant correctif) : pour chaque réponse dont les IP doivent
entrer dans nft, `finalize_a` enfilait ses insertions puis **attendait l'ACK du
worker `nft`** (ancien `finalize_a`, appel `measured_wait_ack` ; aujourd'hui
remplacé par `settle` l. 444 / `flush_deferred` l. 423, cf. §7), budget 150 ms
et poll de 5 ms (`src/nft_queue.moon:11-12`, `wait_ack` l. 165-198). Le worker
`nft` exécute **une transaction libnftables par flush**
(`src/worker_nft.moon:89-114`, `flush_batch` → `src/nft.moon:31-38`), et le
flush a lieu dès que son pipe est vidé (`src/worker_nft.moon:198-208`) : sous
attente synchrone, chaque réponse produisait donc **sa propre transaction**.

Mesures :
- 31 % du temps mural de `resp-q4` passé en `wait_ack` à 200 et 250 q/s,
  32 % à 500 q/s (tableau §2), avec `ack_wait_us` p99 8,7–13,5 ms et max
  21 ms ; `nft` à 42–51 % d'un vCPU, `nft_ack_timeout` = 0 (les ACK arrivent,
  lentement).
- Contre-épreuve : trafic `up` (où, dans la configuration déployée, les
  réponses `r_ouverture_complete` n'injectent rien — cf. §4.2) → **0 attente
  d'ACK**, `nft` à 10 %, RTT p50 4,7 ms au lieu de 22,6 ms au même débit.
- Échantillonnage 20 Hz : `resp-q4` est en `ppoll` 45–54 % des échantillons
  pendant les paliers chargés (contre 60–71 % au repos), et `nft` en exécution
  (« running ») 40–51 % du temps : les deux workers se renvoient la main en
  ping-pong au lieu de travailler en parallèle.
- Conséquence directe : pendant l'attente, `resp-q4` ne lit pas son socket
  netlink ; le noyau y empile les paquets jusqu'à saturer le tampon de
  réception (208 Ko, `net.core.rmem_default` = 212 992) et **jette** les
  suivants : c'est `user_dropped` (§5).

### 3.2 Retry upstream synchrone sur NXDOMAIN/SERVFAIL/REFUSED — **CONFIRMÉE mais marginale pour `mixed`, majeure pour des noms uniques**

- `mixed` (10 noms NX fixes) : `upstream_retries > 0` sur **12/6000** lignes à
  200 q/s, 19/5001 à 250, 19/5859 à 300, 19/6303 à 500 → négligeable. Le cache
  `nxdomain_bad` (`src/config.moon:226-235`, TTL 60 s) fait son travail.
- Noms uniques (`nxu`, 240 requêtes à 20 q/s) : `upstream_retries=2` sur
  **240/240** lignes, et le compteur nft « queue to 4 » progresse de
  **960 paquets = 4 par requête** (réponse initiale + 2 retries + 1 doublon
  « second avis »). Chaque requête NX unique coûte donc 3 transactions amont
  et 3 paquets dans la file des réponses.
- Ce n'est pas ce qui casse `mixed` (0,2 % des lignes), mais c'est un
  amplificateur ×3 sur toute charge à noms majoritairement uniques.

### 3.3 Tampon de réception netlink trop petit / absence de `NETLINK_NO_ENOBUFS` — **RÉFUTÉE comme cause racine**

- Aucun `setsockopt(SO_RCVBUF)` ni `NETLINK_NO_ENOBUFS` dans le binding
  (`src/nfq_loop.moon:92-127`) : le socket garde le défaut noyau
  (`rmem_default` = 212 992 o, soit ~140 paquets de 1,5 Ko).
- `queuedropped` (colonne 6) = **0** sur toutes les files à tous les paliers :
  la file nft (`maxlen` par défaut) ne déborde pas.
- Le tampon n'est pas « trop petit » en soi : il se remplit **parce que** le
  worker ne lit pas pendant l'attente d'ACK (§3.1). L'agrandir masquerait la
  perte en augmentant la latence ; ce n'est pas le correctif retenu.

### 3.4 Journalisation synchrone — **RÉFUTÉE**

`log_write_us` : moyenne 33–52 µs, p99 144–601 µs, max 1,0–8,4 ms ; part du
temps mural ≈ 0,7 % à 200 q/s (6000 × 33 µs = 0,2 s sur 30 s). Une seule
écriture > 1 ms à 200 q/s, 24 à 500 q/s (max 8,4 ms) : la queue de distribution
existe mais ne peut pas expliquer un plafond à 250 q/s.

### 3.5 Le résolveur amont (10.35.1.1) — **RÉFUTÉE**

Au débit où le filtre est au repos (20 q/s), le RTT client de bout en bout est
de 7,8 ms p50 (`vpn`, 1–2 enregistrements) ; le filtre n'y consomme que 6,4 %
d'un vCPU dans `resp-q4`. Au-delà, tout le délai mesuré est **dans le filtre** :
`question_proc_ms` ≤ 5 ms à tous les paliers et `response_entry_ms` (attente
avant traitement) porte 100 % de la croissance (300 ms p50 à 500 q/s). Le
résolveur ne peut pas être mesuré hors filtre (il est derrière le pont filtré) ;
cette réserve est notée au §7.

## 4. Découvertes annexes mesurées

### 4.1 Le « second avis » duplique 70 % des requêtes autorisées

Le compteur « queue to 4 » progresse de **+70 %** du nombre de requêtes dans
tous les paliers `mixed` (200 : +4185 paquets pour 6000 requêtes, et 4177 lignes
de benchmark `r_utilisateurs` = Tailscale 40 % + NXDOMAIN 30 % du mélange ;
500 : +10 481 pour 15 000 requêtes et ~10 500 réponses `r_utilisateurs`), et de
**+100 %** en NXDOMAIN unique (4 paquets par requête dont 2 retries, cf. §3.2). Le
surplus correspond exactement aux questions de la règle `r_utilisateurs`,
dupliquées vers un résolveur validateur
(`src/worker_questions.moon:100-121,465-471`). Conséquence : `resp-q4` traite
**1,7 paquet par requête**, et la réponse réelle est parquée le temps du verdict
du validateur (`src/second_opinion.moon`), ce qui explique aussi l'écart de RTT
entre `mixed` (22,6 ms p50) et `up` (4,7 ms p50) à débit identique.

Ce n'est pas un défaut : c'est le comportement configuré. C'est en revanche un
amplificateur de charge pour `resp-q4` (×1,7 paquets) qu'il faut garder en tête
pour dimensionner le correctif.

### 4.2 Dans la configuration déployée, `r_ouverture_complete` n'injecte rien

À 200 q/s en profil `up` (100 % `vpn.stemarie.dynv6.net`, autorisé par
`r_ouverture_complete`), `ack_wait_us` = 0 sur 6000/6000 lignes et `nft` reste à
10 % : aucune insertion n'est demandée (`inject` reçoit `inject_nft = false`,
donc `records_to_add = 0`, `src/response_inject.moon:110-116`). C'est cohérent
avec une action `dnsonly`/`skip_nft` sur cette règle (`src/filter/actions/dnsonly.moon:19-23`).
Conséquence méthodologique : le profil « 100 % autorisé » de
`tmp/loadtest_rapport_2.md` §5 **ne mesure pas** un trafic à injection nft
pleine ; il ne peut pas servir de référence de débit pour `mixed`.
Symétriquement, toute la charge nft mesurée §2 vient des réponses
`r_utilisateurs` (Tailscale, 8 enregistrements A → 8 `ip4` + 8 `mac4`).

## 5. Correction de l'interprétation de `user_dropped`

`/proc/net/netfilter/nfnetlink_queue` expose, dans l'ordre : `queue_num`,
`peer_portid`, `queue_total`, `copy_mode`, `copy_range`, `queue_dropped`,
**`queue_user_dropped`**, `id_sequence`, `id_sequence_global`. La 7<sup>e</sup>
colonne (`user_dropped`) est incrémentée par le noyau quand
`netlink_unicast()` vers le socket de l'userspace échoue (tampon de réception
plein) : **ce n'est pas un compteur de verdicts `drop` émis par Custos**.

Preuves sur nos paliers :

- à 500 q/s, `queue_dropped` (col. 6) = 0 partout, `queue_user_dropped` (col. 7)
  +14 674, et 8 698 réponses client manquent ;
- aucune voie de drop userspace n'a logué quoi que ce soit pendant la fenêtre :
  0 `response_orphan_dropped`, 0 `callback_exception`, 0
  `nft_add_failed_*`, 0 `nft_ack_timeout` ;
- 14 674 ≈ 8 698 réponses client perdues + ~6 000 réponses de validateurs
  (0,7 par requête, cf. §4.1) : ce sont bien les paquets que le noyau n'a pas pu
  remettre au socket qui manquent, client et validateurs confondus.

Correction également : la « profondeur max 210 » et le « maxlen 1676 » de
`tmp/PASSATION.md` §4 confondent deux colonnes. Le fichier n'expose **aucun**
`maxlen` ; `1676` est le `peer_portid` (PID du worker `dns-q0`), et la
profondeur observée est `queue_total` (col. 3), 214 au maximum à 500 q/s.

## 6. Chaîne de goulots (synthèse)

Pour une réponse de `r_utilisateurs` (8 enregistrements A, cas majoritaire du
profil) :

1. `resp-q4` parse, matche, journalise, puis enfile 8 insertions `ip4` + 8
   insertions `mac4` (16 lignes) dans le pipe nft ;
2. il **attend** l'ACK de `nft`, qui exécute alors une transaction libnftables
   pour ces 16 lignes (~3,7 ms de CPU `nft` par réponse à 200 q/s) ;
3. pendant ce temps, le socket netlink s'empile ; au-delà de ~140 paquets
   (208 Ko), le noyau jette les paquets suivants (`user_dropped`) ;
4. à 500 q/s offerts, `resp-q4` est ~84 % occupé (52 % CPU + 32 % d'attente
   d'ACK), traite ~350 paquets/s et n'absorbe que 42 % des requêtes.

Le plafond vient donc de la **sérialisation par réponse** entre `resp-q4` et
`nft`, pas d'une saturation CPU globale (2,2 cœurs sur 4 occupés au pire).

## 7. Correctif retenu et implémenté

**Regrouper les verdicts par lot NFQUEUE** (commit `fix(dns): acquitte les
insertions nft une fois par lot NFQUEUE`) :

- `src/nfq_loop.moon` : nouvelle option `on_batch_end`. **Un `read()` netlink ne
  rend qu'un paquet** (un skb par paquet côté noyau) : après la lecture
  bloquante, la boucle draine donc le socket sans bloquer (`poll` timeout 0 +
  `read` jusqu'à EAGAIN, borné à `MAX_BATCH_PKTS` = 64) et n'appelle
  `on_batch_end` qu'une fois par lot, plus une dernière fois à la sortie ;
- `src/worker_responses.moon` : `settle` mémorise le verdict au lieu de le poser
  (et supprime l'attente par réponse) ; `flush_deferred` pose tous les verdicts
  du lot après **un seul** `wait_ack` portant le plus grand `seq` enfilé depuis
  le dernier prélèvement (`nft_queue.get_last_seq`) ; `sweep_parked` pose le
  verdict immédiatement (hors lot) ; `run` arme `on_batch_end` dans tous les cas.

Taille de lot obtenue : elle est **auto-adaptative** — le socket accumule des
paquets pendant l'attente d'ACK du lot précédent et pendant son traitement, donc
plus la charge est forte, plus le lot est gros (plafond 64). À faible charge le
lot vaut 1 paquet : aucune latence ajoutée.

Invariant de sécurité inchangé : aucun verdict n'est posé avant que l'ACK du
plus grand `seq` du lot ne soit arrivé ; en cas de timeout, comportement
historique (verdicts posés, `nft_ack_timeout` logué) : le client peut au pire
résoudre une IP pas encore autorisée, jamais l'inverse.

Gain attendu, sur la base des chiffres §2 : l'attente d'ACK (31 % du temps
mural de `resp-q4` à 200-500 q/s) est **divisée par la taille de lot**, qui croît
avec la charge (§ ci-dessus) : le gain porte donc d'abord sur les paliers qui
perdent aujourd'hui (300-500 q/s), où le socket est plein en permanence. Le
worker `nft` passe aussi d'une transaction par réponse à une transaction par lot
(≤ 64 insertions, `src/worker_nft.moon:8`). Le plafond devient la limite CPU du
worker réponses, soit ~350–450 q/s pour `mixed` (≈1,7 paquet par requête,
1,3–1,6 ms de CPU par paquet mesuré, §8) — au-delà, `dns-q1` (74 % d'un vCPU à
500 q/s) prendrait le relais.

### 7.1 Résultats mesurés des deux correctifs (déploiements du 2026-11-12)

Trois campagnes au même protocole (`tmp/bench2/runphase3.sh`, 30 s par palier,
un seul générateur, repos vérifié avant chaque palier) : build initiale,
après `70e67fd` (correctif 1, ACK par lot) et après `c7e21ba` (correctif 2,
ACK consommé non ré-attendu). CPU = % d'un vCPU sur la fenêtre de mesure.
Colonne « perte / RTT p50/p99 / CPU resp-q4-nft-dns-q1 ».

| palier | avant (build initiale) | après correctif 1 (`70e67fd`) | après correctif 2 (`c7e21ba`) |
|---|---|---|---|
| 200 `mixed` | 0 % ; 22,6/70 ; 44/50/33 | 0 % ; **27/249** ; 44/47/34 | **0 % ; 22,9/68,4** ; 45/48/38 |
| 250 `mixed` | 0 % ; 28,8/161 ; 53/48/40 | 0 % ; **32/296** ; 55/48/41 | **0 % ; 22,0/68,7** ; 55/45/47 |
| 300 `mixed` | **2,4 %** ; 47/477 ; 55/42/43 | 0 % ; 84/287 ; 66/64/51 | **0 % ; 37,5/125,6** ; 68/66/59 |
| 400 `mixed` | non mesuré | **13,1 %** ; 250/467 ; 72/67/62 | **16,7 % ; 271/508** ; 74/65/72 |
| 500 `mixed` | **58,0 %** ; 326/695 ; 52/51/74 | 40,0 % ; 329/616 ; 68/60/75 | **36,8 % ; 498/881** ; 73/64/82 |
| 200 `up` | 0 % ; 4,7/8,8 ; 32/10/25 | 0 % ; **5,8/336** ; 33/10/26 | **0 % ; 4,8/18** ; 35/10/26 |
| 500 `up` | non mesuré | **24,0 %** ; 400/912 ; 51/13/45 | **0 % ; 6,1/42** ; 66/17/49 |

Critères annoncés au §7.2 :

| critère | résultat correctif 2 |
|---|---|
| `action=response_nft_ack_timeout` = 0 | **tenu** : 0 occurrence depuis le redéploiement (02:00:17) ; les 9 présentes dans le log datent de la build `70e67fd`. |
| `ack_wait_us` max < 20 ms | **tenu à 200/250/up** (18,2 / 18,9 / 15,5 / 19,7 ms) ; **non tenu à 300 (34,7 ms)** et marginalement à 400/500 (21,6 / 21,9 ms). Ce ne sont plus des timeouts mais des attentes réelles sous charge (p99 9,5-13 ms, ~1 % des lots). |
| p99 à 200-300 | **tenu** : 68,4 / 68,7 / 125,6 ms (c1 : 249 / 296 / 287 ; avant : 70 / 161 / 477). |

Verdict :

- **Le correctif 2 a supprimé la régression du correctif 1** : la queue de
  latence revient à son niveau d'origine à 200-250 q/s et s'améliore nettement à
  300 ; sur le contrôle `up` à 500 q/s (auparavant 24 % de perte et 44 % du temps
  de `resp-q4` en timeouts), on passe à **0 % de perte et p99 42 ms**.
- Le plafond `mixed` reste CPU : **0 % de perte jusqu'à 300 q/s**, 16,7 % à 400,
  36,8 % à 500. À 400-500 q/s, `resp-q4` (74 %), `dns-q1` (72-82 %) et `nft`
  (64 %) d'un vCPU sont tous proches de la saturation ; la part d'attente
  d'ACK n'est plus que de 6-7 %. Le prochain levier est donc le coût CPU par
  paquet (§8), en particulier le coût par instruction nft.

### 7.2 Régression trouvée par la re-mesure : ACK consommé puis ré-attendu 150 ms

Sur la build `70e67fd`, `logread` expose des `action=response_nft_ack_timeout`
(150 ms) et `ack_wait_us` atteint **151 954 µs** à 200 q/s, alors que la build
précédente plafonnait à **19,6 ms** au même débit. Chaque timeout immobilise
`resp-q4` 150 ms (pendant lesquels le socket netlink se remplit → `user_dropped`
→ pertes) : c'est la cause principale des pertes résiduelles et de la queue de
latence, et cela explique que la part d'attente d'ACK n'ait pas baissé à
200-300 q/s.

Cause (code) : `finalize_a` appelle `drain_ack!` **avant chaque injection**
(`src/worker_responses.moon:725` et `:636`), or avec les verdicts différés le
`wait_ack` du lot n'intervient qu'**après** toutes les réponses du lot. Si une
réponse traitée après la dernière insertion du lot draine le tube (cas d'une
réponse `inject_nft` vraie mais sans enregistrement A/AAAA à injecter), elle
jette l'ACK de cette dernière insertion ; `worker_nft` ne réémet un ACK qu'au
flush suivant, qui peut ne jamais venir → 150 ms d'attente pour un ACK déjà
appliqué. Le taux observé (~1 % des lots) suffit : 1 timeout = 150 ms de
blocage.

Correctif (commit `fix(nft): ne ré-attend pas un ACK déjà consommé`) :
`nft_queue` mémorise le plus grand seq acquitté observé (`last_acked_seq`),
mis à jour par `wait_ack` **et** par `drain_ack` ; `wait_ack` retourne
immédiatement si ce seq couvre la cible. `reset_ack_state!` purge le tube et
remet le compteur à zéro **au démarrage du worker** (un producteur redémarré
repart de seq 1 : un ACK résiduel d'un producteur précédent ne doit pas
satisfaire une attente). En complément, plus aucune purge d'ACK n'est faite en
cours de lot (`not ctx.defer`) : l'ACK du lot ne peut plus être consommé avant
d'être attendu.

Invariant inchangé : on ne rend un verdict qu'après un ACK couvrant les
insertions ; `last_acked_seq` ne fait que remplacer « attendre un nouvel
enregistrement » par « l'enregistrement a déjà été lu, il couvre la cible ».
En cas de timeout, le comportement reste celui d'avant (verdict posé,
`nft_ack_timeout` logué).

Protocole de re-mesure du correctif 2 (réalisé, résultats §7.1) : paliers de
30 s à 200, 250, 300, 400 et 500 q/s `mixed` plus `up` à 200 et 500, repos
vérifié avant chaque palier, puis contrôle de `action=response_nft_ack_timeout`
(0), de `ack_wait_us` (max), du p99 client et de `user_dropped`.

## 8. Goulot suivant après les deux correctifs (mesuré, non corrigé)

Mesures de décomposition faites sur la build `70e67fd` (profil `up` = 100 %
`vpn.stemarie.dynv6.net`, 1-2 enregistrements, sans doublon validateur ;
`tls` = 100 % Tailscale, 8 enregistrements, avec doublon validateur ; 200 q/s,
20 s, `tmp/bench2/runphase3.sh`) :

| profil | paquets traités par `resp-q4` | CPU `resp-q4` | CPU `nft` | attente d'ACK | CPU/paquet |
|---|---|---|---|---|---|
| `up` | 4000 (1 par requête) | 33 % | 10 % | 27 % (dont timeouts §7.2) | **1,34 ms** |
| `tls` | 8000 (1,7 par requête) | 60 % | 83 % | 30 % | **1,33 ms** |

Le coût CPU par paquet est **constant** (1,3-1,4 ms) que la réponse porte 1 ou 8
enregistrements, avec ou sans insertion nft : le poste n'est donc ni le parsing
des réponses, ni la construction des lignes nft (mesurés à quelques µs sur x86,
cf. §8). Les primitives isolables n'expliquent qu'une fraction du coût : il
faudrait un profileur dans le worker (`jit.profile`) pour l'attribuer, ce qui
n'est pas possible sans déployer un build instrumenté.

Autres postes mesurés au point de rupture (400 q/s `mixed`) :

- `nft` : 67 % d'un vCPU, pour ~20 instructions d'insertion par réponse qui
  injecte (8 `ip4` + 8 `mac4` + `mac6` pour une réponse Tailscale), soit
  **0,22-0,27 ms par instruction**.
  **Corrigé après cette mesure** (`perf(nft): regroupe les insertions d'un lot en
  une instruction par set`) : `worker_nft.build_batch` regroupe les éléments
  d'un même set en une instruction `add element <table> <set> { e1, e2, … }`
  (timeout par élément conservé), soit 2-3 instructions par réponse au lieu de
  ~20, avec repli élément par élément si le lot groupé est rejeté. Syntaxe
  validée avec nft 1.1.6 dans un espace de noms réseau isolé (sets concaténés
  `ip4`/`ip6`/`mac4`/`mac6`, sets simples `auth_*`/`sip`, timeouts par élément
  conservés). Gain non mesuré sur la cible (pas de déploiement depuis cette
  tâche) : protocole de re-mesure au §8.1.
- `dns-q1` : 62 % d'un vCPU à 400 q/s, soit ~1,7 ms par question, du même ordre
  que `resp-q4` et non décomposé non plus.
- second avis : ×1,7 paquet par requête dans `resp-q4` (§4.1), mesuré comme
  doublant sa charge CPU à débit client constant (`up` 33 % vs `tls` 60 %).
  Réduire ce coût suppose de changer la politique de validation (config), pas
  le code : hors périmètre.

### 8.1 Re-mesure du regroupement nft (à faire après déploiement)

1. repos vérifié (profondeur file 4 = 0, `user_dropped` figé), un seul
   générateur, comme `tmp/bench2/runphase3.sh` ;
2. paliers de 30 s à 300, 400 et 500 q/s `mixed` (+ `up` 500 en contrôle) ;
3. critères : `nft` doit passer de 64-65 % à ≲ 30 % d'un vCPU à 400-500 q/s
   (0,22-0,27 ms × ~20 instructions → ~3), `batch_failed` et `single_failed`
   rester à **0** dans `logread` (sinon la syntaxe groupée échoue), aucun
   `deferred_flush_error`, et la perte `mixed` doit reculer sous celle mesurée
   au §7.1 (16,7 % à 400, 36,8 % à 500) — le plafond restant `resp-q4`/`dns-q1`
   (~1,3-1,7 ms par paquet) ;
4. contrôler que les sets se remplissent normalement (`nft list set` juste
   après un palier) et que les timeouts par élément sont respectés (un élément
   doit expirer selon son TTL, pas celui du voisin).

## 9. Ce qui n'a pas pu être prouvé

- **Le coût CPU fixe par paquet de `resp-q4` (~1,3–1,6 ms sur la cible)** :
  mesuré (utime via `/proc/<pid>/stat`), mais non décomposé. Les primitives
  mesurables hors cible n'en expliquent qu'une fraction : `parse_dns_packet`
  = 11,5 µs/appel sur x86 (réponse à 8 A) et une ligne de journal benchmark
  27 champs = 9,6 µs/ligne sur x86, soit quelques dizaines de µs sur l'A55.
  Restent `run_on_response` (callbacks de filtre, dépendants des règles
  déployées), `patch_modified_dns`/`replace_dns_payload`, `drain_pipe` et
  `dns_classify.classify` sur les paquets de validateurs, non profilés (pas de
  `perf`/`strace` sur la cible, pas de déploiement possible ici).
- **`chain_strip` / `mac_learner_ipc.strip_target`** : pour un nom non caché,
  `maybe_dynamic_strip` ouvre un socket AF_UNIX, connecte et interroge
  `mac_learner` **par réponse** (`src/mac_learner_ipc.moon:52-71,157-163`), dans
  le chemin chaud, après `run_on_response` (donc hors des champs benchmark).
  Non mesuré : le profil `mixed` n'utilise que 6 noms (cache 2 s,
  `src/worker_responses.moon:91,112-126`), et je n'ai pas pu établir si une règle
  `dns_strip.follow_cname` est active sur la cible sans lire `/etc/custos`.
  À mesurer en priorité avec un profil à noms uniques.
- **Le résolveur 10.35.1.1 hors filtre** : inaccessible autrement qu'à travers
  le pont filtré (une seule machine cliente autorisée).
- **Le débit maximal réel** : non mesuré (pas de déploiement des correctifs
  depuis cette tâche) ; les deux protocoles de re-mesure sont au §7.1/§7.2 et
  les résultats déjà obtenus au §7.1.
- **La décomposition du coût CPU fixe par paquet** : le profil `up` (1-2
  enregistrements) et `tls` (8 enregistrements) donnent le même CPU/paquet
  (§8), ce qui exclut le parsing comme poste dominant sans l'identifier pour
  autant ; un `jit.profile` embarqué dans un build de mesure serait nécessaire.
