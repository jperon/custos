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

| palier | avant (build initiale) | après correctif 1 (`70e67fd`) | après correctif 2 (`c7e21ba`) | après correctif 3 (`6d11b2a`) |
|---|---|---|---|---|
| 200 `mixed` | 0 % ; 22,6/70 ; 44/50/33 | 0 % ; **27/249** ; 44/47/34 | **0 % ; 22,9/68,4** ; 45/48/38 | n.m. |
| 250 `mixed` | 0 % ; 28,8/161 ; 53/48/40 | 0 % ; **32/296** ; 55/48/41 | **0 % ; 22,0/68,7** ; 55/45/47 | n.m. |
| 300 `mixed` | **2,4 %** ; 47/477 ; 55/42/43 | 0 % ; 84/287 ; 66/64/51 | **0 % ; 37,5/125,6** ; 68/66/59 | **0 % ; 36,0/124,7** ; 64/63/59 |
| 400 `mixed` | non mesuré | **13,1 %** ; 250/467 ; 72/67/62 | 16,7 % ; 271/508 ; 74/65/72 | **9,9 % ; 209/481** ; 78/60/77 |
| 500 `mixed` | **58,0 %** ; 326/695 ; 52/51/74 | 40,0 % ; 329/616 ; 68/60/75 | 36,8 % ; 498/881 ; 73/64/82 | **35,9 % ; 529/962** ; 72/63/83 |
| 200 `up` | 0 % ; 4,7/8,8 ; 32/10/25 | 0 % ; **5,8/336** ; 33/10/26 | **0 % ; 4,8/18** ; 35/10/26 | n.m. |
| 500 `up` | non mesuré | **24,0 %** ; 400/912 ; 51/13/45 | **0 % ; 6,1/42** ; 66/17/49 | **0 % ; 6,2/48,9** ; 66/18/53 |

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

### 7.3 Résultat mesuré du regroupement nft (correctif 3, `6d11b2a`)

Re-mesure du 2026-11-12 après déploiement du regroupement (`build_batch` :
une instruction `add element { … }` par set), paliers 300/400/500 `mixed` +
`up` 500, 30 s, repos vérifié.

- **Correction : critères tenus.** `batch_failed` = **0**, `single_failed` = **0**,
  `deferred_flush_error` = 0, `response_nft_ack_timeout` = 0 (aucune occurrence
  depuis le redéploiement). La syntaxe groupée est donc acceptée par le nft de
  la cible en production. Les sets sont remplis et **les timeouts par élément
  sont bien distincts** (`r_utilisateurs_ip4` : `192.200.0.101 timeout 10m1s`,
  `.102 timeout 10m14s`, `.103 timeout 10m30s`, … pour une même réponse à 8 A).
- **Perte / latence** : 400 q/s passe de 16,7 % à **9,9 %** de perte
  (`user_dropped` +3398 → +2018), 500 q/s de 36,8 % à 35,9 % ; 300 q/s reste à
  0 % (p99 124,7 ms) et `up` 500 à 0 % (p99 48,9 ms).
- **CPU `nft` : critère NON tenu.** Attendu ≲ 30 % d'un vCPU à 400-500 q/s,
  mesuré **60 %** (400) et **63 %** (500), contre 65 % et 64 % au correctif 2 :
  le regroupement ne réduit pas le coût du worker nft (~5 points au mieux,
  dans le bruit). Interprétation : le coût est **par élément** (parsing de
  l'expression d'élément + insertion netlink dans le set + gestion du timeout),
  pas par instruction — regrouper 20 éléments en 3 instructions n'économise que
  l'en-tête des instructions. Le gain observé à 400 q/s vient de la latence par
  flush (3 allers-retours noyau au lieu de ~20), pas du CPU.
- Répartition CPU `nft` mesurée : ~62 % user / 38 % système à 400-500 q/s, ce qui
  confirme qu'une part significative du coût est côté noyau (insertion des
  éléments), hors de portée d'un simple regroupement textuel.

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

## 8. Goulot suivant après les deux premiers correctifs (mesuré)

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

- `nft` : 67 % d'un vCPU, pour ~20 éléments d'insertion par réponse qui
  injecte (8 `ip4` + 8 `mac4` + `mac6` pour une réponse Tailscale), soit
  **0,22-0,27 ms par élément** (le regroupement du §7.3 le confirme : le coût
  suit le nombre d'éléments, pas le nombre d'instructions).
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

### 8.1 Re-mesure du regroupement nft (réalisée — critère CPU non tenu)

1. repos vérifié (profondeur file 4 = 0, `user_dropped` figé), un seul
   générateur, comme `tmp/bench2/runphase3.sh` ;
2. paliers de 30 s à 300, 400 et 500 q/s `mixed` (+ `up` 500 en contrôle) ;
3. critères : `nft` ≲ 30 % d'un vCPU à 400-500 q/s, `batch_failed` et
   `single_failed` à **0**, pas de `deferred_flush_error`, perte `mixed` en
   recul. **Résultats (§7.3)** : syntaxe et pertes conformes (0 échec, 16,7 →
   9,9 % à 400), mais **CPU `nft` inchangé (60-63 %)** : le coût est par élément,
   pas par instruction ; l'hypothèse « 0,22-0,27 ms par instruction » du §8 est
   donc à corriger en « par élément » ;
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

## 10. Pistes restantes (chiffrées, classées par gain attendu)

État de référence après les trois correctifs : **0 % de perte jusqu'à 300 q/s**,
9,9 % à 400, 35,9 % à 500 (`mixed`), `up` 500 à 0 %. Au point de rupture le
service consomme 218 % (400 q/s) à 229 % (500 q/s) d'un vCPU sur **4 cœurs**,
donc la machine n'est pas saturée : le plafond vient de la **sérialisation par
processus** (`resp-q4` 78 %, `dns-q1` 77-83 %, `nft` 60-63 % d'UN cœur chacun),
pas de la capacité totale.

### 10.1 Répartir réponses et questions sur plusieurs workers — gain ×1,75 à ×2

**Implémenté** (branche `d-multi`, voir §11) : `nfqueue.responses` accepte une
plage (`"14-15"`), un worker par file, avec fan-out IPC et bus de verdicts.

- Mesure : `resp-q4` (un seul process, file `4`) à 78 % d'un vCPU à 400 q/s ;
  `dns-q1` à 77-83 % ; `nft` 60-63 %. Le superviseur crée un worker par file
  (`questions_queues`/`responses_queues`, `main.moon`) et alloue **un pipe ACK
  par worker réponses** : passer à `nfqueue.responses: "14-15"` (2 workers)
  double la capacité du chemin réponses. Avant cette branche, une plage
  `responses` était ramenée à sa première file par `config.moon` (avertissement
  `nfqueue_responses_single_queue_only`) parce que la table `pending` est privée
  à chaque processus ; ce garde-fou a été remplacé par le fan-out IPC.
- Plafond attendu : `nft` est partagé et à 62 % pour 500 q/s → ≈ 100 % vers
  **800 q/s** ; `resp-q4`×2 et `dns-q1`×2 tiendraient ~1000 q/s. Gain réaliste
  **~700-800 q/s**, soit ×1,75-2 par rapport aux 400 actuels.
- Coût/risque : configuration + vérification de l'allocation ACK par worker ;
  risque de collision softirq/worker (cf. `tmp/PASSATION.md` §5 : `taskset` des
  workers sur les cœurs les moins chargés en softirq). Aucun changement de
  sémantique de sécurité. Coût mémoire : `N` copies de la table `pending`
  (TTL 5 s) et `N` écritures IPC par question ; `runtime.lowmem` ramène les
  plages à une seule file.

### 10.2 Second avis ciblé — gain +40 à +70 % sur le chemin réponses

- Mesure : chaque requête autorisée produit **1,7 paquet** dans `resp-q4`
  (§4.1). À débit client constant, `up` (sans validateur) consomme 33 % d'un
  vCPU et `tls` (avec validateur) 60 % à 200 q/s : les doublons validateurs
  **doublent** la charge du worker réponses.
- Gain : retirer la duplication là où elle est redondante ferait passer
  `resp-q4` de ~2,4 ms de CPU par requête à ~1,4 ms, soit un plafond de
  ~420 à ~700 q/s sur ce seul poste (+40 à +70 %).
- Coût/risque : **décision de politique de filtrage** (config
  `validate`/`validate_resolvers`), pas du code ; ne pas toucher sans arbitrage
  sécurité.

### 10.3 Profiler le coût fixe par paquet de `resp-q4` et `dns-q1` — jusqu'à ×2 (théorique)

- Mesure : 1,3-1,4 ms de CPU **par paquet** dans `resp-q4`, indépendant du
  nombre d'enregistrements (profil `up` 1-2 RR = `tls` 8 RR, §8) ; ~1,7 ms par
  question dans `dns-q1`. Les primitives mesurables (parsing 4-12 µs, ligne de
  journal 10 µs, construction d'éléments nft 0,4 µs sur x86) n'expliquent
  qu'une fraction.
- Gain : si ce coût fixe était divisé par deux, les plafonds `resp-q4` et
  `dns-q1` doubleraient (×2, le plus fort potentiel) — mais **non attribué** à
  ce jour.
- Coût : build de mesure avec `jit.profile` (ou compteurs par section) sur la
  cible ; aucun déploiement de production nécessaire. À faire avant 10.1/10.2
  si l'on veut éviter d'optimiser le mauvais poste.

### 10.4 Coût nft par élément — ≤ 20-30 % du CPU de service

- Mesure : `nft` 60-63 % d'un vCPU à 400-500 q/s pour ~20 éléments par réponse
  qui injecte, dont ~62 % en temps utilisateur et 38 % en noyau (§7.3). Le
  regroupement en une instruction par set n'a **pas** réduit ce coût : il est
  par élément (expression + insertion netlink + timeout), pas par instruction.
- Pistes : API basse niveau `libnftnl` (contourne le parseur de texte, part
  inconnue des 62 % user) ; ou réduire le nombre d'éléments par réponse, ce qui
  touche la sémantique (les sets `mac*` portent le filtrage L2) — **hors
  périmètre sans arbitrage**.
- Gain attendu : au mieux 20-30 % du CPU de service, à comparer aux gains
  ×2 de 10.1/10.3.

### 10.5 Postes mineurs

- `events` 12 % et `mac-lrn` 4-5 % d'un vCPU à 400-500 q/s (écriture d'un
  événement par transaction DNS + apprentissage ARP/NDP). Optimisables mais
  sans effet sur le plafond actuel (< 5 %).

Ordre recommandé : **10.1** (gain ×1,75-2, sans risque sémantique), puis
**10.3** (mesure préalable au coup suivant), **10.2** (arbitrage sécurité),
**10.4**, **10.5**.

## 11. Multi-worker DNS — implémentation (branche `d-multi`)

Mise en œuvre de la piste §10.1 : répartir les questions DNS (file 1) et les
réponses DNS (file 4) sur **N workers**, par configuration, sans changer le
comportement à 1 worker.

### 11.1 Ce que le noyau garantit (vérifié dans les sources)

`queue num A-B` (plage) fait répartir par `nfqueue_hash` — et non « premier
listener disponible » : `nft_queue_eval` appelle `nfqueue_hash(skb, queue,
queues_total, pf, jhash_initval)` dès que `queues_total > 1` et que le flag
`fanout` est absent (`net/netfilter/nft_queue.c:36-46` ; sources Linux 6.6.86,
6.6.87 et 6.6.108 du dépôt OpenWrt local, identiques sur ces lignes). Le
hachage (`include/net/netfilter/nf_queue.h:49-125`) est :

- `hash_v4` : `jhash_3words(min(saddr,daddr), max(saddr,daddr), proto)` —
  **symétrique** (les deux sens d'un flux donnent le même indice) et **sans les
  ports** ;
- `hash_v6` : tri des mots d'adresse (même symétrie) ; `hash_bridge` route vers
  l'un ou l'autre selon l'EtherType (la table `bridge` est notre cas) ;
- indice final `reciprocal_scale(hash, queues_total)`.

Conséquences : (a) tous les paquets d'un flux — et de son sens retour — vont au
même worker, donc le réassemblage DNS/TCP est sûr ; (b) le `fanout` du langage
nft est **par CPU** (`nft_queue.c:37-40`) et casserait cette affinité : ne pas
l'ajouter ; (c) deux flux de couples d'adresses différents (client↔résolveur et
client↔validateur) peuvent tomber sur des files différentes — d'où le bus de
verdicts.

### 11.2 État par processus : ce qui devait être partagé

- `pending` (`ipc.moon`) : table privée au processus. Avec plusieurs workers
  réponses lisant *le même* pipe, une entrée n'était lue que par un seul : la
  réponse livrée à un autre worker était jetée (`response_orphan_dropped`).
  → **fan-out** : un pipe par worker réponses, chaque question écrite dans tous
  (`ipc.write_with_retry_all`).
- `mac_clients`/`ip_to_mac` (`worker_responses.moon`) : alimentés par `pending`,
  donc complets dans chaque worker après le fan-out.
- `so_state` (second avis) : la réponse A et la réponse B du validateur ont des
  couples d'adresses différents → files différentes. Le contexte parqué porte
  des handles NFQUEUE (`qh_ptr`, `pkt_id`) **propres au processus** : impossible
  de le débloquer depuis un autre worker. → **bus** `so_verdict_<i>` : le worker
  qui reçoit B diffuse le verdict encodé, celui qui détient A le débloque.
- `tcp_state`, `deferred`, `nft_queue` (`seq`/`last_acked_seq`), caches
  (`nxdomain_bad`, `strip_query_cache`) : sûrs (affinité de flux, état par lot,
  un tube ACK par worker via `worker_idx`).
- `_retry_budget` : budget de 100 ms/s **par worker** → ×N au global (assumé).

### 11.3 Configuration à déployer (2 workers par file)

```moonscript
nfqueue: {
  questions: "0-1"   -- 2 workers questions (défaut)
  responses: "14-15" -- 2 workers réponses
  captive:   "20"    -- inchangé
  reject:    "10-11" -- inchangé
}
```

Le ruleset rend `queue num 0-1` et `queue num 14-15` (`nft_rules.substitute`) ;
les workers sont nommés `custos:dns-q0`, `custos:dns-q1`, `custos:resp-q14`,
`custos:resp-q15` et redémarrés indépendamment. Contrôles après déploiement :
`logread | grep -E "queue_open|question_response_workers|nft_rules_applied"`,
`nft list ruleset | grep "queue to"`, `/proc/net/netfilter/nfnetlink_queue`
(deux lignes `peer_portid` distinctes pour les files 14 et 15), et absence de
`action=response_orphan_dropped`.

### 11.4 Non mesuré ici

Aucun déploiement depuis cette branche (consigne : pas de machine distante).
Le gain attendu reste celui du §10.1 ; le protocole de re-mesure est celui du
§7.1 (paliers 300/400/500 `mixed` + `up` 500, repos vérifié), en contrôlant en
plus `response_orphan_dropped`, `so_verdict_bus_invalid` et l'absence de
`nft_ack_timeout`.

## 12. Multi-worker mesuré sur custos.lan (2026-11-12) : blocage du fan-out et écart nft/id_sequence

Campagne demandée sur le déploiement `dev` courant (merge `d-multi`) :
`nfqueue.questions: "0-1"`, `nfqueue.responses: "14-15"`, workers
`custos:dns-q0/q1`, `custos:resp-q14/q15`, `custos:nft` (noyau 6.12.74,
aarch64). Générateur `servus.lan` (10.35.1.2) → `10.35.1.1:53`, un seul
générateur, paliers de 30 s, mêmes scripts que §1 (`tmp/bench3/`, résultats
bruts `tmp/bench3/results/`).

**La campagne complète n'a pas pu être réalisée** : le premier palier
(300 q/s `mixed`) a mis en évidence un **défaut bloquant du fan-out IPC**
(§12.3) qui a rendu le service définitivement muet (0 réponse DNS, y compris
après l'arrêt de la charge). Les chiffres ci-dessous sont ceux mesurés avant et
pendant ce blocage ; ils ne remplacent pas les paliers de §7.1.

### 12.1 Profil de charge réellement exercé

Deux écarts avec la campagne §7.1, tous deux constatés dans `logread` :

- **Le client n'était pas authentifié.** `action=auth_server_login_success
  user=j@prn.ovh mac=d8:d3:85:63:6b:27` à 08:21:56, lignes `ALLOW
  rule=r_utilisateurs user=j@prn.ovh` jusqu'à 08:24:07, puis `BLOCK
  rule=r_refus_a_priori` **sans champ `user`** dès 08:27:06 — soit 5 min après
  le login, ce qui correspond à `auth.idle_timeout: 300` (`src/config.moon:317`,
  `session_ttl: 0` l. 315) quand le client du portail ne ping plus. Conséquence :
  le profil `mixed` exercé est 70 % refusé a priori (controlplane/login/NX) +
  30 % `vpn.stemarie.dynv6.net` autorisé par `r_ouverture_complete` (1-2 RR),
  au lieu de 40 % Tailscale autorisé par `r_utilisateurs` (8 RR + second avis +
  injection nft). Le coût nft mesuré s'en ressent : 0,7 % d'un vCPU à 40 q/s
  (§12.2) contre 50 % à 200 q/s dans §2.
- **Le worker DoH tournait à ~100 % d'un vCPU au repos** (§12.5, corrigé depuis
  par `d-dohspin`), ce qui retirait un cœur sur quatre à la mesure.

Les chiffres de §12.2 ne sont donc **pas comparables** à la référence
« 1 worker, file 4 » (300 `mixed` 0 %, 400 9,9 %, 500 35,9 %).

### 12.2 Mesures obtenues

CPU = % d'un vCPU sur la fenêtre de charge (jiffies `/proc/<pid>/stat`, HZ
vérifié à 99,2 sur `/proc/stat`). Les compteurs nft et la table NFQUEUE sont lus
**dans le même appel SSH**, compteur nft d'abord (§12.4).

| palier | émis/reçus | perte | RTT p50/p99 | `dns-q1` | `resp-q15` | `nft` | `doh` | `user_dropped` q1 | nft « queue to 0-1 » Δ | `id_sequence` q1 Δ | q0 Δ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 40 q/s `mixed`, 8 s (avant blocage) | 320/320 | 0 % | 4,6 / 18,3 ms | 4,4 % | 4,6 % | 0,7 % | 100,1 % | 0 | +321 | +320 | 0 |
| 300 q/s `mixed`, 30 s (pendant le blocage) | 9000/0 | **100 %** | n.m. | 1,4 % | 0,1 % | 0,1 % | 97,1 % | **+8 553** | +9 010 | +9 010 | 0 |

Détails du palier à 300 q/s (`tmp/bench3/results/b3m300_r300_mixed_*`) :
`queue_dropped` = 0 sur toutes les files, `queue_total` = 164 en fin de palier
(profondeur max 216), `nft` « queue to 14-15 » Δ = **0** (aucune réponse n'a
atteint la file des réponses), `id_sequence` q14 et q15 Δ = 0. Aucune ligne
`action=response_dns_benchmark` dans la fenêtre : aucune réponse n'a été
traitée. WARN de la fenêtre : `questions_queue_read_enobufs` (1) et
`questions_ipc_write_failed[_exhausted]` (2).

### 12.3 Défaut bloquant : le tube IPC d'un worker réponses inactif n'est jamais drainé

**Symptôme.** À partir de 08:31:19, le worker questions boucle sur
`action=questions_ipc_write_failed_exhausted errno=11 attempts=5 fd=7`
(EAGAIN sur le tube vers `resp-q14`), avec `suppressed` croissant (4 → 23 → 135
→ 524), puis `fd=9` (tube vers `resp-q15`) à partir de 08:36:22. Chaque échec
coûte 5 × 20 ms de `nanosleep` (`src/ipc.moon:110-127`) avant d'abandonner la
question ; le worker passe son temps en `nanosleep(0)` (syscall 101) et ne
traite plus que ~10 q/s, d'où `user_dropped` +8 553 sur la file 1. Le service
ne répond plus à aucune requête, même à 40 q/s, et ne se rétablit pas après
l'arrêt de la charge (sonde unique à 08:40 : timeout).

**Chaîne causale (code).**

1. Avec `responses: "14-15"`, le superviseur crée **deux** tubes
   question→réponse (`pipe_resize fd=7 name=question_response`,
   `fd=9 name=question_response2`, taille 65 536 o ;
   `src/main.moon:84-85,108-125`) et le worker questions écrit **dans tous**
   (`write_with_retry_all`, `src/ipc.moon:137-143`).
2. Or le worker réponses ne draine son tube que dans `handle_response`
   (`src/worker_responses.moon:1012-1018`), c'est-à-dire **à chaque paquet
   reçu sur sa file**. Le tube n'est pas dans le `poll` : `run` ne met que le
   bus de verdicts dans `extra_rfds` (`src/worker_responses.moon:1390-1393`),
   et `on_idle` = `sweep_parked` ne draine que ce bus et les réponses parquées
   (`src/worker_responses.moon:918-927`) ; `nfq_loop.run_queue` ne surveille
   que le fd netlink et `extra_rfds` (`src/nfq_loop.moon:117-156`).
3. Le hachage noyau est sans les ports et symétrique (§11.1) : tout le trafic
   d'un client donné tombe dans **une** file. Ici `resp-q14` ne reçoit que des
   réponses de validateurs (rares, ~1 toutes les 10 s) : son tube n'est donc
   presque jamais drainé et ses 64 Kio se remplissent (≈200 o par message, soit
   ~320 messages ; le palier de 40 q/s a écrit exactement 320 messages dans ce
   tube, et les premières erreurs EAGAIN apparaissent 4 min plus tard, après le
   trafic résiduel du client).
4. `write_with_retry_all` renvoie `false` dès qu'**un** destinataire échoue,
   même si l'autre a reçu sa copie, et `worker_questions` traite alors l'échec
   comme définitif : `return NF_DROP` (`src/worker_questions.moon:449-464`).
   La question n'atteint jamais le résolveur, donc aucune réponse n'est
   produite, donc `resp-q15` ne reçoit plus de paquet et **son** tube cesse
   d'être drainé à son tour : blocage définitif, sans reprise possible sans
   redémarrage des workers.

**Portée.** Le défaut est propre au multi-worker (`d-multi`) et se déclenche dès
qu'une file de la plage reste inactive assez longtemps — cas systématique avec
un seul client, et cas réel dès qu'un déséquilibre de flux dure quelques
centaines de requêtes. Il n'est **pas corrigé ici** (hors périmètre : aucune
modification de `src/`). Correctifs possibles à arbitrer : mettre le fd du tube
dans `extra_rfds` du worker réponses (et le drainer dans `on_extra_ready`),
et/ou ne pas jeter la question quand un seul des fan-out a échoué.

### 12.4 Écart compteur nft / `id_sequence` (PASSATION §7.4) — résolu

Mesure propre, compteur nft et table NFQUEUE lus dans **le même appel SSH**
(nft d'abord, NFQUEUE ensuite), avant/après le palier de 300 q/s :

| instant | nft « queue to 0-1 » | `id_sequence` q0 | `id_sequence` q1 | q0+q1 |
|---|---|---|---|---|
| avant (08:32:48) | 678 | 0 | 678 | 678 |
| après (08:34:41) | 9 688 | 0 | 9 688 | 9 688 |
| **Δ** | **+9 010** | **0** | **+9 010** | **+9 010** |

`queue_dropped` = 0 et `user_dropped` = 0 pour les questions avant le blocage
(c'est `user_dropped` qui monte pendant, +8 553, sans effet sur `id_sequence`).
**Résidu = 0**, et égalité des valeurs absolues : le compteur nft et
`id_sequence` de la file 1 comptent exactement les mêmes paquets.

Conclusion : l'écart de PASSATION §7.4 (+15 165 nft contre +11 693
`id_sequence` de la file 1, soit −3 472) **n'est pas expliqué par la
répartition 0/1** : avec ce générateur, la file 0 ne reçoit **aucun** paquet
(Δ = 0) — tout tombe dans la file 1, et les deux compteurs y sont identiques.
L'écart venait donc de la mesure : les deux relevés n'étaient pas simultanés
(protocole §1 : « compteurs nft et NFQ avant/après » en appels séparés), et/ou
`id_sequence` a été remis à zéro par une recréation de file (le compteur est
propre à l'instance NFQUEUE, créée par `nfq_create_queue` ; un redémarrage de
worker le remet à 0 alors que le compteur nft survit). Pour toute re-mesure :
lire nft et NFQUEUE dans le même instantané, et noter les redémarrages de
workers. À noter : la file 0 reçoit bien du trafic d'**autres** clients à
d'autres moments (248 paquets observés sur la file 0 dans les minutes qui ont
suivi la fenêtre de mesure, alors qu'elle était à 0 pendant), donc un partage
0/1 reste possible en général — mais pas pour cette charge, et pas dans la
fenêtre mesurée.

### 12.5 Anomalie annexe : le worker DoH consomme ~100 % d'un vCPU au repos

`custos:doh` (pid 1426) : 71914 jiffies utime + 22397 stime à 08:32:46, alors
qu'il a démarré à 08:18:05 (≈880 s plus tôt) ; mesure directe à 08:41 :
**98,6 %** d'un vCPU en 5 s, état `running` en permanence, sans aucun log
d'erreur récent (les derniers `doh_h2_failed err=h2_incomplete` datent de
06:11/06:13, instance précédente). Le mécanisme n'est pas identifié (boucle
active sans syscall bloquant). Conséquence pour la mesure : un cœur sur quatre
est indisponible en permanence. Ce n'est **pas** la cause du blocage §12.3 (le
worker questions est en `nanosleep`, pas affamé), mais cela abaisse le plafond
réel de la machine.

**Cause et correctif (branche `d-dohspin`, 2026-11-12).** Le mécanisme est
maintenant identifié : `lib.socket.socket_select` remplissait `fd_set` avec la
bibliothèque `bit` de LuaJIT (32 bits) alors que le masque est fait de `long`
(64 bits sur x86-64), si bien que tout descripteur `>= 32` était surveillé
**sous l'identité de son alias `fd - 32`**. Le worker DoH hérite des tubes du
superviseur puis ouvre ses listeners IPv4 et IPv6 : l'un d'eux tombe au-delà
de 32, et son alias est `stdin`/`stdout` (`/dev/null`, toujours lisible) →
`select()` rendait aussitôt, `accept` répondait `EAGAIN`, boucle à vide à
100 % d'un vCPU, sans log, le service restant rendu par le listener sous 32.
Reproduction locale (descripteurs factices avant `run`) : 271 jiffies utime +
188 stime en 4 s, `state=R` avant ; 2 jiffies en 5 s, `state=S` après.
`socket_select` passe désormais par `poll(2)` (`src/lib/socket.moon:470-535`),
sans masque de bits ni plafond de 1024 ; tests
`tests/unit/lib/socket_spec.moon:429-464` (échec avant, succès après). Détail :
`docs/agents/audits.md` § « Worker DoH à ~100 % d'un vCPU au repos ».

### 12.6 Ce qui reste à mesurer

1. Corriger le fan-out (§12.3) puis rejouer le protocole §7.1 : 300/400/500/700
   `mixed` + 500/800 `up`, 30 s, repos vérifié, avec les compteurs lus dans le
   même instantané (§12.4) et le contrôle des WARN `questions_ipc_write_failed`,
   `response_orphan_dropped`, `so_verdict_bus_invalid`, `nft_ack_timeout`.
2. Réauthentifier le client `servus` sur le portail avant la campagne (sinon le
   profil `mixed` reste à 70 % de refus a priori et ne sollicite ni les 8 RR
   Tailscale ni le second avis).
3. Pour tester un partage réel 14/15, il faut plusieurs IP source : `servus`
   n'a que 10.35.1.2/24 sur le WAN (les autres adresses sont sur d'autres
   sous-réseaux) ; aucune variation d'IP source n'est possible sans modifier le
   réseau, donc ce point n'a pas été fait.

## 12. Blocage définitif du multi-worker réponses — défaut et correctif

Défaut observé en pré-prod sur `custos.lan` avec `nfqueue.responses: "14-15"`
(branche `d-bench3`, mesures et journal dans `tmp/bench3_report.md` §3-§4). Le
service est tombé **définitivement** en 4 minutes de trafic : 0 réponse DNS
ensuite, à n'importe quel débit, jusqu'au redémarrage.

### 12.1 Mécanisme (chaîne exacte)

1. `main.moon` crée **un** tube `question_response<i>` par worker réponses
   (`create_pipe`, 64 Kio demandés via `F_SETPIPE_SZ` ; `src/main.moon:128-148`)
   et le worker questions écrit chaque transaction dans **tous**
   (`ipc.write_with_retry_all`).
2. Côté worker réponses, le tube n'était lu que par `handle_response`
   (`drain_pipe`, `src/worker_responses.moon:1022-1027`), donc **seulement quand
   un paquet arrivait sur SA file**. Le fd du tube n'était pas surveillé par le
   `poll` de `nfq_loop` : `extra_rfds` ne contenait que le bus de verdicts du
   second avis (avant le correctif, `src/worker_responses.moon:1390-1393` ;
   désormais `:1408-1423`).
3. Le hachage NFQUEUE répartit par **couple d'adresses** (`§11.1`) : avec un seul
   client, tous les paquets tombent dans une seule file de la plage (mesuré :
   file 15 pour les réponses, file 14 inactive). Le tube du worker inactif
   n'était donc jamais drainé et ses 64 Kio se remplissaient (~200 o/message).
4. `write_with_retry_all` renvoyait `false` dès qu'**un** destinataire échouait
   (EAGAIN, 5 × 20 ms de `nanosleep` par question, `src/ipc.moon:110-147`) et
   `worker_questions` traitait cet échec comme définitif : `return NF_DROP`
   (`src/worker_questions.moon:459-468`).
5. Conséquence en boucle fermée : la question n'atteint plus le résolveur →
   aucune réponse → le worker qui traitait les réponses ne reçoit plus de paquet
   → **son** tube n'est plus drainé → l'échec devient permanent. Observé :
   `questions_ipc_write_failed_exhausted errno=11` en boucle, débit du worker
   questions effondré à ~10 q/s (`nanosleep`), `user_dropped` +8 553 sur la file 1.

Portée : le défaut est **propre au multi-worker**. Il se déclenche dès qu'une
file de la plage reste inactive assez longtemps pour remplir 64 Kio — cas
systématique avec un seul client, cas réel dès qu'un déséquilibre dure quelques
centaines de requêtes.

### 12.2 Correctif (deux volets)

**Volet 1 — le tube est drainé même sans paquet**
(`src/worker_responses.moon`, `run`) : le fd `pipe_rfd` est ajouté à
`extra_rfds` (avec `so_bus_rfd` s'il existe) et `on_extra_ready` appelle le même
`drain_pipe` que `handle_response`, avec le même callback `drain_on_msg`
(alimentation de `mac_clients`). `nfq_loop` réveille donc la boucle dès que le
tube est lisible, sans attendre un paquet sur la file (mécanisme déjà utilisé
par le bus de verdicts ; tests : `tests/unit/nfq_loop_enobufs_spec.moon`). Un
`POLLHUP` (worker questions arrêté) retire le fd de la surveillance : pas de
boucle à vide.

L'état `pending` reste cohérent : la purge par expiration de `handle_response`
(compteur mod 1000 paquets) ne tourne **jamais** sur un worker dont la file est
inactive, d'où une purge supplémentaire tous les `DRAIN_PURGE_EVERY` (64)
réveils du drain sans paquet — coût O(pending) borné, sinon les entrées
absorbées ne partiraient qu'à l'éviction `ipc.pending_max`.

Coût : `run_queue` passe désormais **toujours** par `poll()` (un appel par lot)
au lieu d'un `read()` bloquant. Négligeable devant l'attente d'ACK nft (§3.1),
mais c'est un changement de chemin pour la configuration à un seul worker.

**Volet 2 — un destinataire en échec ne jette plus la question**
(`src/ipc.moon`, `write_with_retry_all`) :

- le message est considéré distribué dès qu'**au moins un** destinataire l'a
  reçu (`true`) ; `false` seulement si **tous** ont échoué. Chaque worker
  réponses possède la table `pending` complète, donc la question reste
  appariable chez ceux qui l'ont reçue — c'est là que la réponse arrivera si sa
  file y est affectée ;
- un destinataire dont l'écriture a échoué est **marqué saturé** : les messages
  suivants ne lui coûtent plus qu'**une** écriture non bloquante (aucun
  `nanosleep`), jusqu'au premier succès qui efface la marque. Le retry complet
  (5 × 20 ms) n'est donc payé qu'une fois par épisode de saturation, pas par
  question — c'était le poste qui effondrait le débit du worker questions ;
- WARN rate-limité **par destinataire** (`action=ipc_write_saturated`,
  `ipc_fd`, `RL_CONFIG` fenêtre 60 s) à l'entrée en saturation, et
  `INFO ipc_write_resumed` à la reprise.

Choix de conserver le retry bloquant pour un destinataire non marqué : à un
seul worker (cas historique), le tube plein est une contre-pression légitime
(le worker réponses draine à chaque paquet) ; supprimer le retry y ferait perdre
des questions sur un simple retard. La saturation durable, elle, ne se produit
que si le destinataire ne draine plus du tout — cas où le retry ne peut rien
sauver. Le compromis garde donc la contre-pression utile et supprime le coût
pathologique.

Limite assumée : les messages écrits **pendant** la saturation d'un
destinataire sont perdus pour lui (une tentative non bloquante par message).
Avec le volet 1, un worker sain ne peut plus rester saturé (il draine dès qu'il
est réveillé) : la saturation ne persiste que si le worker est arrêté ou bloqué,
auquel cas sa file ne traite de toute façon plus rien.

Tests : `tests/unit/ipc/ipc_spec.moon` (tube plein → un seul `nanosleep` par
épisode, livraison si un destinataire reçoit, `false` si tous échouent, effacement
de l'état), `tests/unit/worker_questions_spec.moon` (un destinataire en échec
permanent → `NF_ACCEPT`), `tests/unit/worker_responses_spec.moon` (tube drainé
sans paquet nfq, purge bornée), `tests/unit/log_spec.moon` (rate-limiting par
`ipc_fd`).


## 13. Campagne multi-sources multi-worker (2026-11-12, branche `d-bench4`)

Campagne demandée après le correctif `d-mfix` (§12) : plafond de la configuration
déployée `nfqueue.questions: "0-1"`, `nfqueue.responses: "14-15"` en répartissant
la charge sur **plusieurs couples d'adresses** — le hachage NFQUEUE porte sur le
couple d'adresses et le protocole, sans les ports (§11.1). Harnais `tmp/bench4/`
(`dnsload4.py`, `runphase4.sh`, `counters.sh`, `sampler4.sh`, `analyse4.py`,
`mapqueues.sh`) ; résultats bruts `tmp/bench4/results/` (ignorés par git).
Aucune modification de `src/`, aucune écriture sur `custos.lan` (lecture seule :
`/proc`, `logread`, `nft list`, `top`), aucun redémarrage.

### 13.1 Deux écarts au protocole de §7.1, constatés avant la campagne

1. **Le client `servus` n'est pas authentifié.** Le dernier
   `auth_server_login_success` du journal date du 2026-11-12 08:21:56
   (`mac=d8:d3:85:63:6b:27`), et les trois sets `authenticated_*`
   (`nft list set bridge dns-filter-bridge authenticated_ips|ips6|macs`) sont
   **vides** au début de la campagne (`auth.idle_timeout` = 300 s). Le profil
   `mixed` réellement exercé est donc 70,7 % `r_refus_a_priori` + 29,3 %
   `r_ouverture_complete` (mesuré : 6359 / 2642 lignes à 300 q/s), et non
   40 % de Tailscale autorisé par `r_utilisateurs` : **ni second avis, ni
   injection nft** (CPU `nft` 5-12 %, contre 50 % à 200 q/s dans §2).
2. **Le worker DoH consommait ~1 cœur** (anomalie §12.5, corrigée depuis par la
   branche `d-dohspin` : cause `fd >= 32` aliasé, `poll(2)` en remplacement de
   `select(2)`) : 96,8 % d'un vCPU au repos (13 s) et 60-98 % pendant les
   paliers. Un quart de la machine était donc indisponible en permanence ; les
   chiffres de cette campagne restent marqués par cette consommation.

Les chiffres ci-dessous ne sont donc **pas comparables terme à terme** à ceux de
§7.1 (profil authentifié avec injection nft) : ils mesurent la montée en charge
du **chemin questions/réponses multi-worker** à coût nft quasi nul, et la
comparaison à §7.1 est faite explicitement §13.4.

### 13.2 Multi-source : IPv6 impossible, repli sur les adresses IPv4 du résolveur

**Le transport DNS IPv6 ne peut pas traverser le filtre.** La règle
`ip6 daddr fe80::/10 accept` (`nft-rules/dns-filter-bridge.nft:177`, déployée au
sein de `nft list ruleset` ligne 943) précède les règles
`queue num {QUEUE_QUESTIONS}` / `queue num {QUEUE_RESPONSES}`
(`:204-205`, déployées lignes 955-956). Une question DNS vers l'adresse
link-local du résolveur est donc acceptée **sans passer par la file**.

Vérifié avec une IPv6 `/128` temporaire (`2001:470:ca35:1::b001`, ajoutée par
`sudo -n ip -6 addr add … nodad`, retirée aussitôt) et une requête vers
`fe80::5ad6:1fff:fe57:4f94%wan` (l'adresse link-local de 10.35.1.1, MAC
`58:d6:1f:57:4f:94`) : aucune ligne de verdict pour la question, mais la réponse
a bien été prise en file puis jetée faute de `pending` —
`action=response_orphan_dropped src_ip=fe80::5ad6:1fff:fe57:4f94
dst_ip=2001:470:ca35:1::b001` (log du 2026-11-12 10:49:07). Les deux adresses
globales existantes de `wan` (`2001:470:ca35:1:dad3:85ff:fe63:6b27`,
`2001:470:ca35:1::bede`) ne peuvent donc servir que de sources vers une
destination globale.

Or **aucune adresse IPv6 globale du résolveur n'écoute sur :53** :
`reseau.stemarie.dynv6.net AAAA` = `2001:470:ca35:5:7823:17ff:fe74:fbe6`
(timeout), `2001:470:ca35:1::1` et `2001:470:ca35:1:5ad6:1fff:fe57:4f94` en
NDP `FAILED`, et l'adresse RDNSS annoncée (`resolvectl status wan` :
`2001:470:ca35:1::`) est l'adresse anycast subnet-router, qui **refuse** :53
(« connection refused »). L'adresse `/128` temporaire a été retirée et
`ip -6 addr show dev wan` ne contient plus que les deux globales d'origine et la
link-local (vérifié en fin de campagne).

**Repli retenu : faire varier la destination IPv4.** Les neuf adresses du
résolveur sur le routeur (`10.35.{1..8,99}.1`) répondent toutes le DNS
(30/30 réponses chacune) et le hachage porte sur le couple `(min,max,proto)`
(§11.1) : changer de destination change donc de file, exactement comme changer
de source. Cartographie mesurée par Δ`id_sequence` sur 30 requêtes par adresse
(`tmp/bench4/results/mapqueues.log`) :

| adresses du résolveur | index de file (questions / réponses) |
|---|---|
| `10.35.1.1`, `10.35.2.1`, `10.35.3.1`, `10.35.7.1` | 1 → `dns-q1` / `resp-q15` |
| `10.35.4.1`, `10.35.5.1`, `10.35.6.1`, `10.35.8.1`, `10.35.99.1` | 0 → `dns-q0` / `resp-q14` |

Les paliers « multi » ci-dessous utilisent `10.35.1.1,10.35.4.1` (50/50, une
adresse par file) ; les témoins « mono » n'utilisent que `10.35.1.1` (toute la
charge sur `dns-q1`/`resp-q15`). Répartition vérifiée à chaque palier : à
300 q/s, Δ`id_sequence` = 4500/4500 sur les deux files de chaque plage.

### 13.3 Résultats mesurés

Paliers de 30 s, un seul générateur, repos vérifié avant chacun (profondeur
nulle et `user_dropped` figé sur 3 s), sonde unique après arrêt. CPU = % d'un
vCPU sur la fenêtre (jiffies `/proc/<pid>/stat` ; HZ = 100 vérifié : 3993 ticks
`/proc/stat` en 10 s sur 4 CPU). `udrop` = `queue_user_dropped` (col. 7).

| palier | destinations | émis/reçus | perte | RTT p50/p99 (ms) | `dns-q0/q1` | `resp-q14/q15` | `nft` | `doh` | udrop q0/q1/q14/q15 | Δseq q0/q1 |
|---|---|---|---|---|---|---|---|---|---|---|
| 300 `mixed` | 2 (1 par file) | 9000/9000 | 0 % | **4,7 / 16,4** | 19,3/19,1 | 28,9/28,5 | 4,9 | 97,8 | 0/0/0/0 | 4500/4500 |
| 500 `mixed` | 2 | 15000/15000 | 0 % | **10,9 / 238** | 31,5/31,0 | 43,8/43,7 | 8,0 | 71,2 | 0/0/0/0 | 7500/7501 |
| 600 `mixed` | 2 | 17999/17999 | 0 % | **91,3 / 397** | 37,4/37,1 | 48,8/49,0 | 10,2 | 61,6 | 0/0/0/0 | 8999/9000 |
| 700 `mixed` | 2 | 21000/15934 | **24,1 %** | 507 / 1262 | 40,7/39,1 | 46,2/45,8 | 11,9 | 60,6 | 0/212/2383/2467 | 10500/10507 |
| 500 `up` | 2 | 15000/15000 | 0 % | **6,0 / 175** | 24,6/24,5 | 42,6/43,0 | 0,0 | 77,9 | 0/0/0/0 | 7500/7500 |
| 800 `up` | 2 | 24000/18205 | **24,1 %** | 503 / 1124 | 35,2/34,7 | 47,3/47,4 | 0,0 | 61,5 | 0/0/2889/2862 | 12000/12003 |
| 300 `mixed` | 1 (témoin) | 9000/9000 | 0 % | 4,7 / 64,4 | 0/35,4 | 10,6/41,1 | 4,9 | 92,6 | 0/0/0/0 | 0/9000 |
| 500 `mixed` | 1 (témoin) | 15000/15000 | 0 % | **207,6** / 1207 | 0/59,5 | 17,7/65,1 | 8,0 | 74,4 | 0/0/0/0 | 0/15000 |
| 600 `mixed` | 1 (témoin) | 17999/13900 | **22,8 %** | 388,6 / 1221 | 0/62,7 | 18,5/60,9 | 7,0 | 75,2 | 0/970/0/3092 | 0/18002 |

Sur les témoins mono, `resp-q14` consomme **10,6 à 18,5 % d'un vCPU alors que sa
file ne reçoit aucun paquet** : c'est le coût du drain du tube de fan-out (copie
de toutes les questions, `perf.md` §11.2 / §12.2 « volet 1 »).

Autres mesures de la fenêtre :

- **Perte = `user_dropped` uniquement, côté réponses.** À 700 `mixed` comme à
  800 `up`, `queue_dropped` = 0 sur toutes les files, les questions sont
  absorbées (udrop q0/q1 = 0/212 et 0/0) et la perte est exactement portée par
  `resp-q14`/`resp-q15` (4860 et 5751 paquets). `response_queue_read_enobufs`
  apparaît 2 fois à 700 (0 à 800) ; au palier 800 `up`, la profondeur max
  échantillonnée est de 279 (q14) et 258 (q15), contre 91 (q0) et 65 (q1).
- **Aucun défaut du fan-out `d-mfix`** : sur les neuf paliers, **0**
  `questions_ipc_write_failed`, 0 `ipc_write_saturated`, 0
  `response_orphan_dropped` (hors la sonde IPv6 du §13.2), 0
  `so_verdict_bus_invalid`, 0 `nft_ack_timeout`. Les seuls WARN de fenêtre sont
  les ENOBUFS ci-dessus et un `questions_l2_mac_missing` (1, `suppressed=3`) au
  témoin 600.
- **Coût par paquet** (CPU ÷ paquets traités, deux workers) : réponse
  **1,63-1,71 ms** (600 `mixed` / 500 `up`), question **1,24 ms** (600 `mixed`)
  et **0,98 ms** (500 `up`). Attente d'ACK nulle ou marginale (`ack_wait_us`
  non nul sur 2/15000 lignes en `up` ; p99 1,15 ms à 600 `mixed`), ce qui
  confirme que le correctif ACK par lot tient.

### 13.4 Comparaison à la référence §7.1

§7.1 (un seul worker, profil authentifié avec injection nft) : **0 % jusqu'à
300 q/s `mixed`**, 9,9 % à 400, 35,9 % à 500, et `up` 500 à 0 % ; au point de
rupture `resp-q4` 78 %, `dns-q1` 77-83 %, `nft` 60-63 % d'un vCPU chacun.

- **En débit offert**, la configuration multi-worker tient 0 % jusqu'à
  600 q/s `mixed` et 500 q/s `up`, et décroche à 700 / 800 (24,1 % dans les deux
  cas). Le témoin mono-file, mesuré avec **le même profil allégé**, décroche dès
  600 (22,8 %) : à profil identique, le passage à deux files gagne donc environ
  **+20 % de débit offert** (500 → 600) avant la perte, et non ×2.
- **En latence, le gain est net** : à 500 q/s `mixed`, p50 207,6 → 10,9 ms
  (÷19) et p99 1207 → 238 ms (÷5) ; à 300 q/s, p99 64,4 → 16,4 ms (÷4). Le
  décrochage de la file unique se voit d'abord en latence (p50 207 ms à 500,
  sans perte), pas en perte.
- **Coût du multi-worker** : à débit égal, le chemin réponses consomme ~35-40 %
  de CPU en plus (300 : 57,4 % contre 41,1 % ; 500 : 87,5 % contre 65,1 %),
  parce que chaque worker réponses draine et parse le tube de fan-out de
  **toutes** les questions (cf. `resp-q14` à 10-18 % sur les témoins mono).
- **§7.1 n'est pas battu en débit absolu** : sa référence à 300 q/s `mixed`
  exécute 8 RR Tailscale, le second avis et 16 insertions nft par réponse, alors
  que la présente campagne n'exécute ni second avis ni injection (`nft` 5-12 %
  au lieu de 50-63 %). Les deux plafonds ne mesurent pas le même travail par
  requête ; seule la comparaison mono/multi **à profil identique** est
  quantifiée ci-dessus.

### 13.5 Nouveau goulot

À 700 `mixed` et 800 `up` (24,1 % de perte dans les deux cas) :

1. **Le point de perte est le tampon de réception netlink des workers
   réponses**, pas leur CPU : `user_dropped` sur q14/q15 uniquement,
   `queue_dropped` = 0, profondeur 258-279, `response_queue_read_enobufs`, alors
   que les workers réponses sont à **46-49 % d'un vCPU chacun** et que la
   machine garde 5-10 % de temps CPU idle. Le socket garde le défaut noyau
   (~208 Ko, aucun `setsockopt(SO_RCVBUF)`, cf. §3.3) : les réponses du
   résolveur arrivent par rafales (profondeur qui bondit de ~150 paquets entre
   deux échantillons à 10 Hz) et le noyau jette l'excédent. Le chemin questions,
   alimenté au rythme régulier du client, ne perd rien.
2. **La machine est néanmoins à 90-95 % occupée** (moyenne fenêtre :
   user 60-63 %, sys 27-31 %, softirq 4 %, idle 5-8 %) : le plafond global est
   bien le CPU agrégé des 4 cœurs, mais **aucun worker n'est saturé** — c'est la
   différence avec §7.1/§10, où `resp-q4` à 78 % était le goulot.
3. **Le worker DoH était le premier consommateur** : 0,6 à 1,0 cœur en continu
   (§12.5, corrigé depuis par `d-dohspin`). Sans lui, ~25 % de capacité en plus.

En résumé : le multi-worker a supprimé la sérialisation par worker de §7.1, mais
le plafond est désormais (a) le tampon netlink des réponses, qui jette les
rafales du résolveur, (b) le coût par paquet (1,6-1,7 ms par réponse, 1,0-1,2 ms
par question) réparti sur 4 cœurs dont un est mangé par DoH.

### 13.6 Limites et reste à faire

- **Profil non authentifié** (§13.1) : la campagne ne dit rien du plafond avec
  `r_utilisateurs` (8 RR, second avis, injection nft). Réauthentifier `servus`
  sur le portail avant toute re-mesure de la référence §7.1.
- **Pas de source IPv6** (§13.2) : la variation de couple d'adresses a été
  obtenue par la **destination** IPv4 (neuf adresses du même résolveur). C'est
  équivalent pour le hachage, mais ce n'est pas un test multi-client : la
  répartition réelle entre clients reste à mesurer.
- Le mécanisme exact des rafales de réponses (batch du résolveur ou des
  workers questions, `MAX_BATCH_PKTS` = 64, `src/nfq_loop.moon:27,197-218`)
  n'est **pas observé** : aucune capture AF_PACKET n'était autorisée. L'hypothèse
  « rafales > tampon netlink » s'appuie sur les profondeurs et les `user_dropped`.
- Le diag à 600 `mixed` (14 s) et celui à 800 `up` (12 s, avec `top` et
  échantillonnage d'états) sont des diagnostics, pas des paliers de 30 s ; leurs
  chiffres ne figurent pas dans le tableau §13.3.
- Le worker DoH (~1 cœur, anomalie §12.5 depuis corrigée par `d-dohspin`) et
  plusieurs `logread -f` résiduels (six observés,
  sessions tierces, non tués : accès lecture seule) gonflent la consommation
  mesurée.
- Aucun redémarrage, aucune reprise n'a été nécessaire : la sonde unique après
  chaque palier a répondu (`rc=0`), y compris après les paliers à 24 % de perte,
  et les files sont revenues à une profondeur nulle.
