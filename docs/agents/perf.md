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
  (`src/nfq_loop.moon:92-127` avant la branche `d-rcvbuf`) : le socket garde le
  défaut noyau (`rmem_default` = 212 992 o, soit ~140 paquets de 1,5 Ko).
- `queuedropped` (colonne 6) = **0** sur toutes les files à tous les paliers :
  la file nft (`maxlen` par défaut) ne déborde pas.
- Le tampon n'est pas « trop petit » **à ces paliers** : il se remplit
  **parce que** le worker ne lit pas pendant l'attente d'ACK (§3.1). L'agrandir
  seul n'aurait pas corrigé le plafond de §3 ; ce n'est donc pas le correctif
  retenu à l'époque.
- **Depuis la branche `d-rcvbuf`** (2026-11-12), le tampon est réglé
  explicitement avant `nfq_create_queue` (`src/nfq_loop.moon:75-82`,
  `src/lib/nfq_rcvbuf.moon`) : `nfqueue.rcvbuf` (défaut 4 Mio, 512 Kio en RAM
  faible), relecture `getsockopt` et repli `SO_RCVBUFFORCE`. Cette correction
  vise le goulot **distinct** mesuré à 700-800 q/s en §13.5 (rafales du
  résolveur sur les files réponses), pas le plafond à 200-500 q/s analysé ici.
  `NETLINK_NO_ENOBUFS` reste volontairement inactif (il masquerait la perte).

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

> **Note datée (2026-11-12, branche `d-qhash`) — la répartition des plages DNS
> a changé.** Depuis cette branche, quand `nfqueue.questions` ou
> `nfqueue.responses` compte **plus d'une** file, les règles DNS ne sont plus
> `queue num A-B` mais `queue to jhash <IP client> . <port client> mod N offset
> <première file>`, une règle par famille (IPv4/IPv6) : le hachage porte sur
> l'IP **et** le port du client, ce qui écarte la concentration mesurée au §15.2
> et §16.3 (70,6 % des réponses sur une seule file). Le présent §11.1 reste
> exact pour la sémantique de `queue num A-B` — encore en vigueur pour une file
> unique et pour les autres rôles (captive, reject, sni, sip, auth). Détail,
> validations et justifications : **§11.5**.

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

### 11.5 Répartition par (IP, port) du client — branche `d-qhash` (2026-11-12)

**Constat.** Avec `queue num A-B`, le hachage noyau porte sur le couple
d'adresses symétrique **sans les ports** (§11.1) : les réponses du résolveur
validateur (second avis) ont le couple (validateur, client) et tombent donc
toutes sur **une seule** file de la plage — 70,6 % des paquets de réponse sur
`resp-q14` à 400 q/s (§15.2), reproduit à 350 q/s (§16.3). Deux flux de ports
différents d'un même client ne se répartissent pas non plus.

**Ce qui change** (les règles DNS sont désormais générées, plus écrites en dur dans le template) :

- `nft-rules/dns-filter-bridge.nft:215-216` : les deux règles littérales sont
  remplacées par les ancres `DNS_QUESTIONS_RULES` / `DNS_RESPONSES_RULES`.
  Piège constaté pendant le développement : le **commentaire** du template ne
  doit pas écrire ces accolades, sinon la substitution les remplace aussi et
  casse le rendu (corrigé) ;
- `src/nft_rules.moon:117-132` (table `DNS_RULES` : sélecteurs, clés, familles),
  `:135-146` (`contiguous_segments`), `:163-186` (`dns_queue_rules`) et
  `:203-204` (substitution) construisent le bloc.

Rendu pour `questions: "0-1"`, `responses: "14-15"` (quatre règles : deux
sens × deux familles) :

```text
meta l4proto {udp, tcp} th dport 53 ip version 4 log level debug prefix "custos question: " counter queue to jhash ip saddr . th sport mod 2 offset 0 comment "DNS questions → NFQUEUE"
meta l4proto {udp, tcp} th dport 53 ip6 version 6 log level debug prefix "custos question: " counter queue to jhash ip6 saddr . th sport mod 2 offset 0 comment "DNS questions → NFQUEUE"
meta l4proto {udp, tcp} th sport 53 ip version 4 log level debug prefix "custos response: " counter queue to jhash ip daddr . th dport mod 2 offset 14 comment "DNS responses → NFQUEUE"
meta l4proto {udp, tcp} th sport 53 ip6 version 6 log level debug prefix "custos response: " counter queue to jhash ip6 daddr . th dport mod 2 offset 14 comment "DNS responses → NFQUEUE"
```

- **une seule file** → `queue num X` **à l'identique** (branche `#segment == 1`
  de `dns_queue_rules`) : `nft list` l'affiche `queue to X`, comme avant ;
- **liste discontinue** (`"0,2"`) → une règle **par segment contigu**
  (`contiguous_segments`) : un `queue num` par file isolée, car
  `mod N offset premier` ne couvrirait que `[premier, premier+N-1]` et
  priverait les autres files de leurs paquets (aucun listener dessus) ;
- `bypass` **absent** : la règle historique n'en a pas ; avec `bypass`, un
  paquet sans worker continuerait dans la chaîne et contournerait le filtre
  DNS. Tous les autres éléments de la règle (sélecteur `meta l4proto {udp, tcp}`
  + `th dport 53`/`th sport 53`, `log level debug prefix`, `counter`,
  `comment`) sont conservés à l'identique.

**Validations réalisées** (local, nft **1.1.6** = version de la cible ;
netns utilisateur via `unshare -Urn`, protocole complet dans
`tmp/qhash_report.md`) :

1. `nft -c -f` sur le ruleset **rendu en entier** (`tmp/render_rules.lua` →
   `tmp/rendered_range.nft`, `_single.nft`, `_3.nft`) : **rc = 0** pour
   `0-1`/`14-15`, `0`/`4` et `0-2`/`14-16`, et `nft -f` réel (application en
   netns) accepte les trois. Sans `unshare`, `nft -c` échoue sur l'accès
   netlink (`Operation not permitted`) : c'est le cas « sans root » signalé à
   l'orchestrateur.
2. `th sport` / `th dport` **sont acceptés** dans l'expression jhash : pas
   besoin de séparer les règles `udp`/`tcp`.
3. Choix du sélecteur de famille — testé sur quatre trames (v4/v6 × taguée/non
   taguée, injection AF_PACKET dans un pont, compteurs nft) :
   - `ether type ip` / `ether type ip6` : **ne matchent PAS** les trames VLAN
     encapsulées (l'ethertype vu est 0x8100), alors que la résolution L4
     (`th dport 53`) y est correcte → un sélecteur choisi là laisserait tout
     le trafic VLAN sur une seule règle (ou aucune) ;
   - `ip version 4` / `ip6 version 6` : chacun couvre **ses deux** trames
     (taguée et non taguée) et rien de l'autre famille → **retenus** ;
   - `meta nfproto` : refusé par nft en famille bridge (« only useful in the
     inet family »).
4. Sémantique de la clé — règle témoin `meta mark set jhash … mod 2 offset 14`
   puis compteurs par marque : marques obtenues **14/15** uniquement, variant
   avec l'IP **et** le port du client (même IP, ports 12345/54321 → marques
   différentes ; même port, IP .1/.3 → marques différentes), et **stables**
   pour une même trame tant que le ruleset n'est pas réappliqué. La graine est
   recalculée à chaque installation de règle : deux applications successives
   peuvent inverser 14/15, sans incidence sur l'affinité intra-ruleset.
5. `nft list` normalise l'affichage : `queue num 4` s'affiche `queue to 4`, et
   `offset 0` est omis (`mod 3` seul pour `questions: "0-2"`) : les files
   couvertes restent exactement celles de la plage.

**Justifications (vérifiées sur le code, pas supposées)**

1. **A et B tombent sur la même file réponses.** La question dupliquée vers le
   validateur conserve le port source du client : `src/dup_query.moon:47`
   (`spt: l4.spt, dpt: l4.dpt`), le commentaire d'en-tête le dit explicitement
   (`src/dup_query.moon:4-9` : « SEULE l'IP destination est réécrite vers le
   validateur (src client, ports, txid et payload DNS préservés) »). La réponse
   A (résolveur→client) et la réponse B (validateur→client) ont donc toutes
   deux `(daddr = client, dport = port client)` → même clé `ip daddr . th
   dport` → même worker. **Le bus `so_verdict` reste** : il est le repli si
   deux paquets d'une même transaction ne coïncident pas (fragments,
   reconfiguration en cours de vie, retour à `queue num`) —
   `src/second_opinion.moon:17-23`.
2. **L'appariement reste garanti quel que soit le worker.** Chaque question est
   écrite dans **tous** les pipes question→réponse (`ipc.write_with_retry_all`,
   `src/ipc.moon:171-188`, appel `src/worker_questions.moon:455`) : chaque
   worker réponses possède la table `pending` (`src/ipc.moon:354`) et peut
   apparier une réponse (`src/worker_responses.moon:1094`).
3. **Affinité TCP DNS conservée.** Une connexion TCP DNS a une 5-tuple fixe :
   même (IP, port) → même clé → même worker pendant toute la connexion, donc
   l'état `tcp_state` (`src/worker_responses.moon:180`, consommé au `:1045`)
   reste dans un seul processus. La clé est en plus *plus fine* que l'ancienne :
   deux connexions TCP du même client se répartissent au lieu d'aller dans la
   même file.
4. **Fragments / en-tête L4 illisible** — tranché par un test réel (fragments
   fabriqués, compteurs nft + observation de la sortie du pont) :
   - **zone hors périmètre** (le lecteur de payload lit au-delà du paquet) :
     l'évaluation pose `NFT_BREAK`, la règle entière est sautée et le paquet
     **retombe dans la suite de la chaîne** — observé sur un fragment de
     2 octets dont les premiers valent 0x0035 : le sélecteur `th sport 53`
     matche, la clé `th dport` est hors périmètre, le compteur de la règle
     s'incrémente mais le paquet ressort (non avalé). C'est déjà le
     comportement d'aujourd'hui, où c'est le sélecteur lui-même qui échoue de
     la même façon ;
   - **zone lisible mais octets « garbage »** (fragment non-premier : les deux
     premiers octets du payload sont lus comme `th sport`) : aujourd'hui il
     partait dans la file du flux (hachage par adresses), il part désormais
     dans la file donnée par la clé (IP, port illisibles). Dans les deux cas
     le paquet n'est pas un message DNS complet : le worker ne peut ni
     l'interpréter ni l'apparier.
   **Aucun filet de repli ajouté** : une règle du type
   `ip frag-off & 0x1fff != 0 → queue num <première>` sans condition de port
   capturerait **tous** les fragments UDP/TCP non premiers (le port n'est pas
   lisible) et les ferait jeter par le worker DNS → elle casserait le trafic
   fragmenté non DNS qui traverse aujourd'hui la chaîne. Le cas limite
   (réponse fragmentée dont les octets lus valent 0x0035, non interpretable de
   toute façon) est donc accepté tel quel.

**Non fait / à revoir** :

- aucun déploiement (consigne : pas de ssh) — le
  comportement en charge reste à re-mesurer sur la cible avec le protocole
  §15.3 en contrôlant la répartition par Δ`id_sequence` sur les files de la
  plage, puis le rendu réel
  (`nft list chain bridge dns-filter-bridge forward` : quatre règles jhash en
  plage, deux `queue to N` en fichier unique) ;
- **commentaires devenus faux** (hors périmètre de cette branche) :
  `src/second_opinion.moon:17-23` et `src/worker_responses.moon:805-811`
  expliquent encore que A et B partent vers des files *différentes* sous
  l'ancien hachage — avec la clé (IP, port) du client elles arrivent chez le
  même worker ; le bus décrit reste le repli. À corriger lors d'une passe de
  doc sur ces deux fichiers (le commentaire n'a aucune incidence sur le
  comportement).

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
   alimenté au rythme régulier du client, ne perd rien. Correctif : §14.
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

## 14. Tampon de réception netlink des files NFQUEUE (2026-11-12, branche `d-rcvbuf`)

Correctif du point de perte identifié §13.5.1. **Aucune mesure de charge n'a été
refaite** dans cette branche (pas d'accès au homelab, pas d'e2e) : la section
décrit le mécanisme et le réglage, pas un gain mesuré.

### 14.1 Mécanisme

`libnetfilter_queue` crée son socket netlink dans `nfq_open()` et ne pose aucun
`setsockopt(SO_RCVBUF)` : la taille de réception reste `net.core.rmem_default`
(212 992 o sur `custos.lan`, mesuré §3.3). Quand le résolveur répond par
rafales, `netlink_unicast()` vers le socket du worker réponses échoue tant que
le tampon est plein ; le noyau jette le paquet et incrémente
`queue_user_dropped` (colonne 7), pas `queue_dropped` (colonne 6) — d'où la
perte côté réponses à 700-800 q/s alors que les workers ne sont qu'à 46-49 %
d'un vCPU. Aucun `SO_RCVBUF` n'est posé par nft ni par le noyau au nom du
processus : c'est bien le socket userspace qu'il faut dimensionner.

### 14.2 Réglage appliqué

- Nouveau module `src/lib/nfq_rcvbuf.moon`, appelé dans `run_queue` **avant**
  `nfq_create_queue` (`src/nfq_loop.moon:75-82`) : dès que le handler de file
  existe, des paquets peuvent être mis en file, donc le tampon est réglé avant.
- Clé `nfqueue.rcvbuf` (octets, `doc/CONFIG.md` §3). Absente, nulle ou
  illisible : **4 Mio** (`DEFAULT_RCVBUF`), ou **512 Kio** (`LOWMEM_RCVBUF`)
  quand `runtime.lowmem` est actif — le mode RAM faible réduit aussi le nombre
  de workers, mais 4 Mio de tampon noyau par socket y seraient disproportionnés.
- Séquence : `setsockopt(SO_RCVBUF)` → `getsockopt` (le noyau borne la demande
  par `net.core.rmem_max` puis renvoie le **double** de la valeur accordée,
  man 7 socket ; le module divise par deux pour obtenir la taille effective)
  → si cette taille effective est inférieure à la demande,
  `setsockopt(SO_RCVBUFFORCE)` (contourne `rmem_max`, exige `CAP_NET_ADMIN`)
  → nouvelle relecture. Si FORCE échoue (EPERM), la valeur bornée est conservée.
- Journalisation : INFO `queue_rcvbuf` avec `requested`, `obtained` (taille
  **effective**, c'est-à-dire la moitié du brut renvoyé par `getsockopt`) et
  `forced` ; WARN `queue_rcvbuf_below_requested`
  si `obtained < requested` malgré le repli ; WARN `queue_rcvbuf_failed`
  (`errno`) si `setsockopt(SO_RCVBUF)` échoue — la file démarre quand même.
- `NETLINK_NO_ENOBUFS` reste **inactif** : l'option supprime la remontée
  d'ENOBUFS au lieu de traiter le débordement, ce qui masquerait la perte
  (`queue_read_enobufs` / `user_dropped` sont les seuls signaux de ce goulot).
  Le dimensionnement du tampon est la réponse ; l'option ne serait justifiée
  que si l'on voulait ignorer délibérément la perte, ce qui n'est pas le cas.

### 14.3 Portée et vérification

- Le réglage s'applique à **toutes** les files (`run_queue` est commun aux
  workers questions/réponses/captive/reject/auth/SNI/SIP/DoH-VLAN). Il est
  surtout utile aux réponses, mais un tampon plus grand ne coûte que de la
  mémoire noyau non touchée tant qu'elle n'est pas remplie.
- Tests unitaires : `tests/unit/lib/nfq_rcvbuf_spec.moon` (valeur demandée
  config/profil, valeur obtenue, repli FORCE, refus EPERM, échec setsockopt,
  absence d'API socket, logs INFO/WARN). `make test` couvre aussi le chemin
  d'appel dans `run_queue` (stub `ffi_defs` du harnais Busted : le module
  désactive alors silencieusement le réglage, faute de `getsockopt` cdef).
- **Reste à faire** : rejouer les paliers 700 `mixed` / 800 `up` de §13.3 sur
  le homelab et vérifier que `queue_user_dropped` retombe à 0 sur q14/q15 et
  que la perte client disparaît, avec `forced=true` et `obtained` cohérent dans
  les lignes `queue_rcvbuf` du journal.

## 15. Campagne de réglage des paramètres de charge (2026-11-12, branche `d-tune`)

Campagne demandée après §14 (`nfqueue.rcvbuf`) et `d-dohspin` : mesurer l'effet
des clés de réglage documentées sur le débit, une variable à la fois, puis
proposer des défauts pour deux profils. **Aucune modification de `src/` ni de
défaut dans le code.** Harnais `tmp/tune/` (`dnsload4.py`, `runphase.sh`,
`counters.sh`, `sampler.sh`, `analyse.py`, `apply_cfg.sh`, `mapqueues.sh`) ;
résultats bruts `tmp/tune/results/` (ignorés par git) ; rapport de campagne et
recommandation `tmp/tune_report.md`.

Cible : `custos.lan` (10.35.1.254, OpenWrt, aarch64 Cortex-A55 ×4, noyau 6.12.74,
`MemTotal` 4 029 208 Ko, build `dev`). Configuration déployée au départ :
`nfqueue: { responses: "14-15" }` (donc `questions` = défaut `"0-1"`),
`rcvbuf` absent = défaut 4 Mio (`forced=true` relevé dans `queue_rcvbuf`),
`pending_max` absent = défaut 20 000. `nproc` n'existe pas sur la cible :
`grep -c ^processor /proc/cpuinfo` = **4**.

### 15.1 Profil réellement exercé : authentifié (contrairement à §13)

`servus` (10.35.1.2) était **authentifié sur le portail** pendant toute la
campagne. Contrôle avant **chaque** palier : `dig +short @10.35.1.1
controlplane.tailscale.com A` doit rendre des réponses (une requête d'un client
non authentifié est refusée par `r_refus_a_priori`). Les sets
`authenticated_ips`/`authenticated_macs` contenaient bien 10.35.1.2 et
`d8:d3:85:63:6b:27` (TTL glissant ~1 min 30 s, rafraîchi par le client).

Conséquence mesurée à 300 q/s `mixed` : le journal de la fenêtre contient
**6 245** lignes `r_utilisateurs` et **2 759** `r_ouverture_complete` (8 004
lignes), et `nft` consomme **56,5 %** d'un vCPU — contre 5-12 % dans la
campagne §13 (profil non authentifié). La charge exerce donc bien les 8 RR
Tailscale, le second avis et l'injection nft ; le worker DoH est à
**0,0-0,1 %** d'un vCPU (`d-dohspin` effectif). Les chiffres ci-dessous ne sont
donc **pas comparables** à ceux de §13.3 (profil allégé) : ils mesurent le
profil complet, et c'est ce profil qui fixe les défauts.

### 15.2 Multi-source et répartition

Le hachage NFQUEUE porte sur le couple d'adresses (§11.1) : la charge est
répartie en tourniquet sur plusieurs **destinations** du résolveur
(`10.35.{1..8,99}.1`, cf. §13.2). Cartographie refaite par Δ`id_sequence` pour
la plage `0-2`/`14-16` (`tmp/tune/mapqueues.sh`) :

| plage | destinations utilisées | files |
|---|---|---|
| 1/1 (`0`/`14`) | `10.35.1.1` | tout sur q0/q14 |
| 2/2 (`0-1`/`14-15`) | `10.35.1.1`, `10.35.4.1` | 1.1 → q1/q15 ; 4.1 → q0/q14 |
| 3/3 (`0-2`/`14-16`) | `10.35.1.1`, `10.35.3.1`, `10.35.4.1` | 1.1 → q2/q16 ; 3.1 → q1/q15 ; 4.1 → q0/q14 |

Répartition vérifiée à chaque palier par Δ`id_sequence` (p. ex. 4 500/4 500 à
300 q/s sur 2/2, 4 000/4 000/4 013 à 400 q/s sur 3/3). **Découverte :** en
profil authentifié, la file des réponses est **dissymétrique** — avec 2/2,
q14 reçoit **70,6 %** des paquets de réponse à 400 q/s `mixed` (14 495 contre
6 033) et q15 le reste ; avec 3/3, q15 en reçoit 73 % (10 893 contre ~4 000).
En `up` (sans second avis), la répartition est parfaitement égale (12 000 /
12 003). La cause est le **second avis** : les réponses du résolveur validateur
ont un couple d'adresses (validateur, client) distinct de celui du résolveur,
donc **toutes** tombent dans une seule file, quelle que soit la taille de la
plage. C'est cette file « chaude » qui déborde la première.

### 15.3 Résultats mesurés

Paliers de 30 s, un seul générateur, repos vérifié avant chacun (profondeur
nulle sur les files de la plage et compteurs figés), compteurs nft et NFQUEUE
lus dans le même instantané, sonde unique après arrêt. CPU = % d'un vCPU sur
la fenêtre (jiffies `/proc/<pid>/stat`, HZ = 100,8 mesuré) ; `resp`/`dns` =
somme des workers de la plage ; `nft` = worker nft ; RSS = `VmRSS` de fin de
fenêtre, somme des workers réponses. `qdrop` = `queue_dropped` (col. 6 de
`/proc/net/netfilter/nfnetlink_queue`, dépassement de la longueur de file
noyau) ; `udrop` = `queue_user_dropped` (col. 7, tampon netlink userspace).

**Configuration de référence — 2 workers / 2, rcvbuf 4 Mio, pending 20 000 :**

| palier | émis/reçus | perte | p50/p99 (ms) | resp / dns / nft (% vCPU) | RSS resp | qdrop / udrop | prof. max |
|---|---|---|---|---|---|---|---|
| 300 `mixed` | 9000/9000 | 0 % | 41,9 / 185,6 | 80,0 / 59,0 / 56,5 | 21,9 Mio | 0 / 0 | 14 |
| 400 `mixed` | 12000/11993 | **0,1 %** | 1206 / 2345 | 98,5 / 77,7 / 57,3 | 30,5 Mio | 18 / 0 | 915 |
| 500 `mixed` | 15000/8662 | **42,3 %** | 3452 / 5960 | 92,3 / 98,6 / 62,7 | 30,4 Mio | **8 782** / 0 | 1024 |
| 800 `up` | 24000/24000 | 0 % | 246,6 / 711,2 | 111,7 / 81,8 / 1,5 | 30,5 Mio | 0 / 0 | 246 |
| 1000 `up` | 30002/21738 | **27,5 %** | 2975 / 3616 | 113,3 / 99,5 / 0,1 | 36,1 Mio | **8 191** / 0 | 1024 |

Conformément au protocole (arrêt de la montée à > 5 % de perte), les paliers
700 et 900 `mixed` **n'ont pas été lancés** pour cette configuration : 500
`mixed` perd déjà 42,3 %.

**Variantes (une variable à la fois) — paliers discriminants :**

| configuration | 400 `mixed` | 500 `mixed` | 800 `up` | 1000 `up` | RSS resp |
|---|---|---|---|---|---|
| 2/2, rcvbuf 1 Mio | — | 38,2 % (p50 3342) | 0 % (p50 347) | — | 30,3 Mio |
| 2/2, rcvbuf 2 Mio | — | 35,6 % (p50 3277) | 0 % (p50 932) | — | 30,0 Mio |
| 2/2, rcvbuf 8 Mio | — | 41,2 % (p50 3438) | 0 % (p50 215) | — | 30,4 Mio |
| 2/2, pending_max 5 000 | — | 38,3 % (p50 3376) | 0 % (p50 785) | — | 30,6 Mio |
| 1/1, rcvbuf 4 Mio | **12,6 %** (p50 1646) | 43,8 % (p50 2482) | **15,7 %** (p50 1556) | 36,6 % (p50 2676) | 10,6-13,8 Mio |
| 3/3, rcvbuf 4 Mio | **5,2 %** (p50 2988) | 40,0 % (p50 4107) | 0 % (p50 907) | 40,2 % (p50 3868) | 46,2-67,3 Mio |
| 1/1, rcvbuf 512 Kio, pending 5 000 | **22,9 %** (p50 2119) | — | **17,9 %** (p50 1592) | — | 11,2-11,9 Mio |

Détails et enseignements :

1. **`nfqueue.rcvbuf` n'a aucun effet sur la perte à ces paliers.** Les quatre
   valeurs (1/2/4/8 Mio) donnent 35,6-42,3 % à 500 `mixed`, écart dans le bruit
   de reproductibilité de la cible, et **`user_dropped` = 0 partout**, y compris
   avec 512 Kio (configuration `lowmem`). La perte est **entièrement
   `queue_dropped`** : la file noyau est pleine (`profondeur 1024`, valeur
   `NFQNL_QMAX_DEFAULT`), pas le socket userspace. Le correctif §14 tient donc
   (plus aucun `queue_read_enobufs` ni `user_dropped`) ; il ne pouvait pas
   relever le plafond mesuré ici. À 800 `up` (0 % de perte), la latence varie
   de 215 à 932 ms entre 8 Mio et 2 Mio **sans tendance** : aucune valeur ne se
   distingue. Le défaut 4 Mio reste le bon compromis ; 8 Mio ne gagne rien.
2. **1/1 est nettement pire** : 12,6 % de perte dès 400 `mixed` (contre 0,1 %
   en 2/2), 15,7 % à 800 `up` (contre 0 %), 36,6 % à 1000 `up` (contre 27,5 %).
   Le CPU `resp` d'un seul worker plafonne à 64-81 % d'un vCPU : la
   sérialisation par processus (§10.1) est bien le facteur limitant. Gain
   mémoire : ~20 Mio de RSS en moins (un worker réponses et un worker
   questions en moins).
3. **3/3 n'apporte rien et dégrade** : 5,2 % dès 400 `mixed` (contre 0,1 %),
   40,2 % à 1000 `up` (contre 27,5 %), p50 907 ms à 800 `up` (contre 247 ms),
   RSS réponses 46-67 Mio (contre 30-36 Mio). Surtout, **3/3 fait apparaître
   des `response_nft_ack_timeout`** (3 à 400 `mixed`, 1 à 500 `mixed`,
   `worker_idx` 1/2/3), absents de tous les paliers 2/2 et 1/1 : hypothèse la
   plus probable, la contention sur le worker nft partagé et ses trois
   producteurs d'ACK. Le coût du fan-out
   (chaque worker réponses draine **toutes** les questions, §13.4) croît avec N
   et n'est pas compensé, la file chaude du second avis restant unique.
4. **`pending_max` 5 000 n'a aucun effet mesurable** à ces charges : RSS
   réponses 30,6 Mio contre 30,4 Mio à 20 000 (500 `mixed`), aucun
   `pending_evicted`. La table reste sous 5 000 entrées (~5 s × 500 q/s). Le
   chiffrage de `doc/CONFIG.md:559-560` (≈ 0,84 Ko/entrée, ≈ 16 Mio pour
   20 000 entrées **par worker**) ne s'applique qu'à un afflux de questions sans
   réponse : 20 000 ≈ 16 Mio/worker contre 5 000 ≈ 4 Mio/worker dans ce cas
   seulement.
5. **Autres clés documentées, non variées** : `ipc.pending_ttl` (5 s,
   `doc/CONFIG.md:529`) et `ipc.match_retry.budget_ms` (100 ms,
   `doc/CONFIG.md:534`) changent la sémantique d'appariement, pas le débit
   nominal ; `nft.ack_timeout_ms` (150 ms, `doc/CONFIG.md:507`) est un budget de
   latence, pas un levier de débit ; `runtime.gc_pause` (`doc/CONFIG.md:74`) et
   `runtime.lowmem`/`lowmem_threshold_kb` (`doc/CONFIG.md:287-288`) sont des
   réglages mémoire (le second a été testé via 1/1 + 512 Kio). La **longueur du
   tube** question→réponse n'est pas une clé : elle est fixée à 64 Kio dans le
   code (`F_SETPIPE_SZ`, `src/main.moon:85,118`). Aucune clé ne règle la
   **longueur de la file noyau** (1024, `NFQNL_QMAX_DEFAULT`) : c'est elle qui
   porte la perte mesurée.

### 15.4 Nouveau plafond, et ce qu'il faudrait étudier

À 400 `mixed` (0,1 % de perte, mais p50 déjà à 1,2 s), le service consomme
`resp` 98,5 %, `dns` 77,7 %, `nft` 57,3 %, `events` 10,8 %, `mac-lrn` 4,7 %
d'un vCPU ; `/proc/stat` donne user 58,3 %, sys 26,1 %, softirq 3,2 %,
**idle 11,2 %**. À 500 `mixed`, `resp` 92,3 %, `dns` 98,6 %, `nft` 62,7 %,
idle 8,0 %, et la perte est **exclusivement** `queue_dropped` sur q14/q15
(profondeur 1024), `user_dropped` = 0. À 1000 `up`, même tableau : `resp`
113,3 %, `dns` 99,5 %, qdrop 8 191, udrop 0.

Le plafond est donc double : (a) le **CPU agrégé** des 4 cœurs, où `resp` et
`dns` saturent ensemble, et (b) la **longueur de file noyau** (1024) de la file
réponses chaude, qui jette les rafales avant même que le worker ne lise. Le
levier suivant n'est **pas** `MAX_BATCH_PKTS` (`src/nfq_loop.moon:29`, lot déjà
borné à 64 et jamais identifié comme limitant ici) mais un
`nfq_set_queue_maxlen()` (non exposé par Custos, non documenté) et/ou une
répartition qui éviterait de concentrer les réponses du validateur sur une
seule file. Ces deux pistes sont des changements de code, hors de cette
campagne.

### 15.5 Recommandation de défauts (détail dans `tmp/tune_report.md`)

- **Profil complet** (machine ≥ 512 Mo, ≥ 4 cœurs) : **2 workers questions /
  2 réponses** (`questions: "0-1"`, `responses: "14-15"`), **`rcvbuf` 4 Mio**,
  **`pending_max` 20 000** — c'est-à-dire les défauts actuels pour `rcvbuf` et
  `pending_max`, et la plage déjà déployée pour les workers. Aucune des
  variantes mesurées ne fait mieux : 1/1 et 3/3 sont pires, 8 Mio n'apporte
  rien, 5 000 n'économise rien à charge nominale.
- **Profil `lowmem`** (RAM faible, priorité mémoire) : **1 worker par file**
  (réduction déjà appliquée par `runtime.lowmem`, `src/lib/lowmem.moon:1-7`),
  **`rcvbuf` 512 Kio** et **`pending_max` 5 000**. Mesuré : `user_dropped` = 0
  à 512 Kio (le tampon suffit), RSS réponses 11 Mio contre 30 Mio, total des
  workers 106-109 Mio contre 135-141 Mio. Coût : le débit avant perte tombe de
  ~400 à ~300 q/s `mixed` et de ~800 à ~700 `up` (400 `mixed` : 12,6-22,9 % de
  perte contre 0,1 % en 2/2 ; 800 `up` : 15,7-17,9 % contre 0 %). Si la machine
  lowmem doit tenir la charge, garder 2/2 et ne réduire que `rcvbuf` et
  `pending_max` : c'est la réduction du nombre de workers, pas le tampon, qui
  coûte le débit.

### 15.6 Suite : `nfqueue.maxlen` (branche `d-maxlen`)

Le levier identifié en §15.4 — la longueur de la file **noyau** (1024,
`NFQNL_QMAX_DEFAULT`) — est désormais exposé par la clé `nfqueue.maxlen`
(`doc/CONFIG.md` §3). Chaque file appelle `nfq_set_queue_maxlen()` juste après
sa création (`src/nfq_loop.moon`, module `src/lib/nfq_maxlen.moon`) : défaut
**4096** paquets, **1024** en mode RAM faible, INFO `queue_maxlen` et WARN
`queue_maxlen_failed` (sans empêcher le démarrage). Mémoire : chaque paquet en
attente occupe de la mémoire noyau (skb + payload), ~6 Mio par file à 4096
emplacements dans le pire cas. **Aucune mesure de charge n'a été rejouée** :
les paliers 500 `mixed` / 1000 `up` de §15.3 restent à refaire avec une valeur
supérieure à 1024 pour vérifier que `queue_dropped` disparaît avant le plafond
CPU.

## 16. Audit aller/retour d'une requête : pourquoi l'authentification charge (2026-11-12, branche `d-perfaudit`)

Audit **lecture seule** (aucune modification de code) répondant à la question :
« un client authentifié devrait coûter **moins** cher (moins de réécritures,
attente amont pipelinable) — pourquoi coûte-t-il **plus** ? ». Tracé du chemin
complet, mesures à 200 et 350 q/s `mixed` authentifiés (30 s, 2 destinations,
sonde `dig` avant chaque palier), phase de repos en comparaison.
Rapport complet, protocole et sources : `tmp/perfaudit_report.md` (données
brutes `tmp/perfaudit/results/`). Comparaison non authentifiée par référence à
§13 (aucune source non authentifiée commandable sans modification d'état).

### 16.1 Le verdict d'une question n'attend rien ; celui d'une réponse attend l'ACK nft (par lot)

- **Question** : verdict `NF_ACCEPT` posé juste après l'écriture IPC
  (`src/worker_questions.moon:453-478`) — ni l'amont, ni nft ; seule l'écriture
  IPC peut dormir (5 × 20 ms sur tube plein, `src/ipc.moon:27,114-130`),
  **jamais observé** en mesure (0 warn, 0 `nanosleep` échantillonné à 20 Hz).
- **Réponse** : le verdict attend l'ACK nft **une fois par lot NFQUEUE**
  (`flush_deferred`, `src/worker_responses.moon:446-461` →
  `nft_queue.wait_ack`, `src/nft_queue.moon:210-248`, budget 150 ms). Exception
  : verdict **immédiat** pour les réponses refusées
  (`src/worker_responses.moon:1291`) et `need_ack` faux pour `dnsonly`/`skip_nft`
  (`:803`).
- **Point clé** : pendant `wait_ack`, le worker ne surveille **que** le tube ACK
  et `on_wait` ne draine **que** le tube question (`:455`) : **le socket netlink
  des réponses n'est pas lu** — mesuré **9-23 %** du temps des workers réponses
  (`ppoll(nfds=1)` vs `ppoll(nfds=3)` de la boucle principale, échantillonnage
  20 Hz, `tmp/perfaudit/results/*_sys.txt`). **Corrigé depuis** par la branche
  `d-ackread` (§16.6).

### 16.2 Mesures (authentifié, 30 s chacun)

| palier | perte | RTT p50/p99 | `response_entry` p50/p99 | prof. max q14/q15 | resp¹ / dns¹ / nft (utime+stime) |
|---|---|---|---|---|---|
| repos | — | — | — | 0 | ≤0,4 % chacun |
| 200 `mixed` | 0 % | 24,7 / 73 ms | **2 / 37 ms** | 16 / 5 | 63,5 / 39,0 / 50,9 % |
| 350 `mixed` | 0 % | **474 / 873 ms** | **337 / 648 ms** | **210 / 140** | 105,3 / 73,3 / 64,5 % |

¹ somme des deux workers. Sources : `tmp/perfaudit/results/*_extract.txt`,
`*_decomp.txt`, `*_analyse.txt`. `ack_wait_us` : non nul sur 38,7 % des lignes
à 200 (p90 9 ms), sur 2,8 % à 350 (max 151 9 ms = le timeout de 150 ms, 1
occurrence) : **à 350 l'attente d'ACK n'est plus le goulot de latence, la file
noyau l'est** (`response_entry` = file + RTT résolveur, identique pour les deux
règles et les deux destinations → file noyau). `/proc/stat` à 350 :
user 57,5 / sys 26,6 / **idle 11,3** / sirq 3,3 % (même signature que §15.4) ;
`ksoftirqd` ≤ 0,17 % ; `qdrop` = `udrop` = **0** partout ; context switches :
volontaires ≈250/s à 200 → involontaires ≈300/s à 350 (préemption, CPU
ininterrompu).

### 16.3 Ce qui change avec l'authentification (les chiffres qui tranchent)

- **×1,70-1,71 paquets dans le chemin réponses** (Δcompteurs nft
  `nft_r/nft_q` = 10207/6001 et 17958/10507) : le second avis duplique chaque
  question `r_utilisateurs` (`src/worker_questions.moon:108-121,473-476`).
- **Toutes les réponses du validateur (B) tombent sur UNE file** : à 350,
  Δ`id_sequence` q14 = 12 715 = 5 250 A (`10.35.4.1`) + 7 465 B ≈ 7 434 lignes
  `r_utilisateurs` → **70,6 % sur `resp-q14`** (reproduit §15.2). La réponse A
  est en outre **parquée sans verdict** jusqu'à B ou 80 ms
  (`src/worker_responses.moon:1314-1322`) : elle occupe alors son emplacement
  dans la file noyau pendant l'aller-retour amont.
- **16-20 insertions nft par réponse Tailscale** (8 A × `ip4`+`mac4`,
  `src/response_inject.moon:106-131`), **1 syscall `write()` par élément**
  (`src/nft_queue.moon:108-121`) : worker `nft` **50,9-64,5 %** contre 5-12 % en
  §13 — et **delta de taille de sets = 0** (mêmes éléments réinsérés à chaque
  réponse pour rafraîchir leur timeout, comptes avant/après identiques) : le
  CPU nft est du rafraîchissement, pas de l'insertion neuve.
- **CPU par requête ≈ 7,5-8,3 ms** (resp+dns+nft+events+mac-lrn) contre
  **≈3,4 ms** en non authentifié (§13.3) : **×2 par requête**. Le coût **par
  paquet** resp est en revanche le même (1,78-1,89 ms ici vs 1,63-1,71 en §13.3)
  : « moins de paquets à réécrire » est donc une fausse piste — il y en a
  **davantage**, et c'est le nft additionnel qui double la facture.

### 16.4 Réponse à la question du pipeline

Le pipeline question→amont **existe** (verdict immédiat, processus/queues
distincts) : l'attente du résolveur n'est pas dans le chemin critique. Il ne
« libère » pas le chemin réponses parce que (a) le verdict réponse est
synchrone sur l'ACK nft et **suspend la lecture netlink** pendant l'attente,
(b) le second avis immobilise A (sans verdict) pendant un second aller-retour
dont les réponses tombent sur une file unique, (c) chaque worker est mono-thread
par file hachée et la boucle lot (≤64) est sérialisée : traitement intégral →
`wait_ack` → verdicts, sans recouvrement (`src/nfq_loop.moon:206-227`). Entre
200 et 350 q/s, ρ sur la file chaude atteint 1 : file debout ≈200-350 paquets
↔ `response_entry` 337 ms (mesuré), machine pourtant à 11 % d'idle.

### 16.5 Pistes de correctif (proposées, non implémentées)

Classement et détails (fichier:ligne, gain, risque) : `tmp/perfaudit_report.md`
§5.3. Ordre recommandé : (1) arbitrage config du second avis (−40 à −70 % CPU
resp), (2) drainer le netlink **pendant** `wait_ack` (borne `MAX_BATCH_PKTS`
inchangée ; préserver l'invariant « pas de verdict avant ACK »), (3) cache
d'upsert côté `worker_nft` (20-30 % du CPU nft), (5) dispersion des IP
validateurs (file chaude), (4/7) écritures events/learn/nft coalescées,
(8) `jit.profile` avant toute optimisation CPU résiduelle.

**Non fait / douteux** : `perf` absent de la cible (rien installé) ; `wchan`
vide et `stack` non symbolisés (kallsyms absent) — remplacés par
`/proc/<pid>/syscall` ; paliers > 350 non lancés ; aucune capture L2 ;
`chain_strip` non déterminable sans config ; le démontage de la file pendant
les 10 dernières secondes du palier 350 (capacité +10 % à entrée constante)
reste inexpliqué (échauffement JIT ou résolveur) faute d'instrumentation.

### 16.6 Correctif du drain netlink pendant `wait_ack` (branche `d-ackread`)

Implémentation de la piste (2) de §16.5, **sans mesure de charge** (pas de
déploiement depuis cette branche).

- **Ce qui change** : `nfq_loop.run_queue` fournit au hook `on_batch_end` une
  lecture non bloquante bornée (`read_packets`, `src/nfq_loop.moon:183-206`),
  non réentrante (garde `reading` : un appel depuis un callback de paquet rend 0
  et ne lit rien). `worker_responses._flush_batch`
  (`src/worker_responses.moon:448-462`) s'en sert dans le `on_wait` de
  `wait_ack`, après le drain du tube question.
- **Invariant préservé** : les paquets lus pendant l'attente sont traités
  normalement (parse, appariement, enqueue nft, `settle`) mais leur verdict est
  mémorisé dans un **lot suivant** (`flush_deferred`,
  `src/worker_responses.moon:477-497`) ; ce lot est posé après **son propre**
  ACK, c'est-à-dire le plus grand `seq` enfilé pendant l'attente, jamais après
  l'ACK du lot courant. Les verdicts immédiats (refus, `dnsonly` sans insertion)
  sont inchangés. En cas de timeout, comportement historique : verdicts posés,
  `nft_ack_timeout` logué.
- **Bornes** : au plus `MAX_BATCH_PKTS` (64, `src/nfq_loop.moon:30`) paquets lus
  par attente, le budget de `wait_ack` reste de 150 ms
  (`src/nft_queue.moon:11,217`) et aucune lecture n'a lieu pendant la seconde
  attente (pas de récursion) : les paquets restants sont lus par la boucle
  principale. Le coût de la lecture est proportionnel au seul retard de la file
  (un `poll(0)` puis `EAGAIN` quand elle est vide) : à faible charge, la boucle
  d'attente n'ajoute qu'un appel système négligeable par tour. L'ACK est
  revérifié avant chaque rafale de lecture, donc une rafale retarde sa détection
  d'un lot de travail au plus. Cas le plus défavorable théorique : deux timeouts
  consécutifs (lot courant puis lot suivant), soit 300 ms, uniquement si
  `worker_nft` ne répond plus du tout.
- **Tests** : `tests/unit/nfq_loop_enobufs_spec.moon` (lecture pendant le hook,
  borne du lot, ENOBUFS, non-réentrance) et
  `tests/unit/worker_responses_spec.moon` (ordre ACK-puis-verdict pour les deux
  lots, paquet lu pendant l'attente non verdicté avant l'ACK de son lot,
  timeout, borne du budget).
- **Reste à faire** : rejouer les paliers 200/350 q/s authentifiés de §16.2 et
  surveiller `response_entry_ms` (attendu : recul de la profondeur de file et de
  la latence d'entrée), `ack_wait_us` (inchangé), et l'absence de
  `deferred_flush_error` / `nft_ack_timeout`.

### 16.7 Répartition des validateurs sur toutes les IP (branche `d-valspread`)

Correctif du goulot n° 5 de `tmp/perfaudit_report.md` §5.3 (« toutes les
réponses B sur une seule file ») : `pick_resolver` renvoyait toujours la
**première** IP de la famille, alors que la config par défaut en liste 3 en
IPv4 et 3 en IPv6. `dup_query.get_picker` (`src/dup_query.moon`) précalcule
désormais les listes UDP par famille et choisit par question l'index
`(id DNS + port source client) % n` ; `worker_questions.maybe_duplicate`
l'applique au moment de dupliquer. Aucune allocation ni `find` par paquet
(sélecteur mémoïsé par liste, cache à clés faibles).

La corrélation ne suppose pas « la première » IP : `second_opinion.is_validator`
reconnaît **toute** IP de `resolvers` (`src/second_opinion.moon:132-143`),
ensemble alimenté par `collect_all_resolvers` (`src/worker_responses.moon:1370-1380`)
et consulté tel quel (`:1093`). `worker_tls` et les modules DoH n'appellent pas
`dup_query.pick_resolver` (seul `cname.pick_resolver_ip` choisit l'amont DoH,
sans rapport) : comportement inchangé.

Effet attendu : les réponses B se répartissent entre les files des workers
réponses au lieu de saturer une seule file chaude (70,6 % sur `resp-q14`,
§16.3). **Non mesuré** sur la cible (pas de déploiement depuis cette branche).


### 16.8 Correctif implémenté : cache d'upsert dans `worker_nft` (branche `d-nftcache`, 2026-11-12)

La piste (3) de §16.5 est **implémentée** : `worker_nft` saute désormais les
ré-insertions d'un même élément (clé `(famille/table, set, élément)`) inséré
avec succès depuis moins de `min(timeout/10, 5 s)`, sans jamais raccourcir la
durée de vie résiduelle, et acquitte quand même les lignes sautées.
Règle, inventaire des invalidations externes, borne mémoire mesurée
(4096 entrées = 932 Kio) et tests : `docs/agents/audits.md`
§ « Cache d'upsert dans `worker_nft` (branche `d-nftcache`) », détail
`tmp/nftcache_report.md`, code `src/worker_nft.moon`, doc worker
`.agents/workers.md`. Gain attendu : les 20-30 % du CPU nft estimés au
§5.3 du rapport d'audit — **non remesurés** (aucune campagne de charge sur
cette branche ; `perf` absent de la cible).

**Suite (2026-11-12)** : le cache ne s'applique — ni saut ni enregistrement —
qu'aux sets alimentés exclusivement par `worker_nft` ; les kinds `auth_*` et
les sets vidés/supprimés hors du worker (`authenticated_*`,
`ip*_dest_whitelist`, `{rule_id}_auth_*`) sont exclus en un point unique
(`cache_key_of`, `UNCACHEABLE_KINDS`/`UNCACHEABLE_SETS`). Motivation,
inventaire fichier:ligne et écart de scénario : `docs/agents/audits.md`
§ « Exclusions du cache » (même section `d-nftcache`).

### 16.9 Coalescence des écritures du pipe nft côté producteurs (branche `d-nftwrite`)

Implémentation de la piste (4) de §16.5 (« écritures events/learn/nft
coalescées »), volet **pipe nft** uniquement. Constat de §16.3 : chaque
`add_ip4/add_ip6/add_mac4/add_mac6` faisait un `write()` par élément
(`src/nft_queue.moon`, ancienne version) — une réponse DNS à N enregistrements
coûtait N appels système avant l'unique `wait_ack` du lot.

- **Producteur** (`src/nft_queue.moon`) : `enqueue` (`:221`) n'écrit plus ; il
  accumule la ligne dans `pending_lines` (table + `table.concat`, jamais `..=`
  en boucle) avec son `seq` (`pending_seqs`, `:66-68`). `flush` (`:154`) écrit
  le lot en **un `write()` par tranche ≤ `PIPE_BUF_ATOMIC` = 4096 o**
  (`:26`) : plusieurs workers écrivent dans le même pipe, une tranche ≤
  `PIPE_BUF` reste atomique. Une tranche pleine est vidée dès qu'une ligne
  supplémentaire la ferait dépasser (`:229`).
- **Flush avant toute attente** : `get_last_seq` (`:258`), `wait_ack` (`:283`)
  et `send_barrier` (`:242`) vident le tampon avant de rendre le seq /
  d'attendre / d'écrire la barrière. `worker_sip`, dont les insertions
  `allow_sip_peer` ne sont suivies d'aucun ACK, vide en fin de paquet
  (`flush_nft`, `:311`), sinon la dernière insertion d'une session resterait
  tamponnée jusqu'au paquet suivant.
- **Seq exact** : `last_enqueued_seq` n'est posé qu'après une écriture réussie,
  au seq de la **dernière ligne effectivement écrite** de la tranche. Si une
  tranche échoue (EAGAIN épuisé, EIO), les lignes restantes sont abandonnées
  (`nft_queue_flush_failed`) et `get_last_seq` rend le seq de la tranche
  précédente (ou `nil` si rien n'a été écrit) : `wait_ack` n'attend jamais
  l'ACK d'une ligne absente du pipe. Retry EAGAIN/partial inchangé
  (`write_data`, `:125`).
- **Appelants vérifiés** (flush effectif) : `worker_responses._flush_batch`
  (`src/worker_responses.moon:448-459`, `get_last_seq` → `wait_ack`) et
  `settle` (`:509-525`, hors lot) ; `doh/query.inject_nft_and_wait`
  (`src/doh/query.moon:77-78`, sous verrou ACK) ; `worker_sip.allow_mac_ip`
  (`src/worker_sip.moon:132-137`) et flush de fin de paquet (`:319-321`).
  `worker_questions` n'utilise pas `nft_queue` (aucun flush à y placer).
- **Mort supprimé au passage** : `add_auth_mac/add_auth_ip4/add_auth_ip6`
  n'avaient aucun appelant et `worker_nft.validate_item` refuse les kinds
  `auth_*` (ligne rejetée `tuple` avant le cache) — fonctions et exports
  retirés.
- **Tests** : `tests/unit/nft_queue_spec.moon` (+6 specs, 42 au fichier) : lot
  de N lignes = 1 `write`, découpage ≤ 4096 o, flush avant `wait_ack` (l'ACK
  n'arrive que si le lot est écrit), seq exact sur échec partiel/total, flush
  avant barrière.
- **Non mesuré** : aucune campagne de charge sur cette branche (pas de
  déploiement) ; gain attendu = N−1 appels système par réponse, à confronter
  au CPU `nft`/`resp` de §16.3 lors d'une re-mesure à 200/350 q/s authentifiés.

## 17. Campagne de charge après les correctifs de l'audit (2026-11-12, branche `d-bench5`)

Campagne demandée après le déploiement sur `custos.lan` d'un build `dev`
contenant **tous** les correctifs de §16.6-§16.9 et des campagnes précédentes
(`d-ackread`, `d-valspread`, `d-nftcache`, `d-nftwrite`, `d-maxlen`,
`d-rcvbuf`, `d-qhash`, `d-dohspin`). **Aucune modification de code** : seules
la configuration `nfqueue` de la cible et la documentation changent. Harnais
`tmp/tune/` (copié de `d-tune`, plus `dnsload5.py` et `runphase5.sh`), résultats
bruts `tmp/tune/results/` (ignorés par git), rapport de campagne
`tmp/bench5_report.md`.

### 17.1 Dispositif et protocole

- **Cible** : `custos.lan` (10.35.1.254, OpenWrt, aarch64 Cortex-A55 ×4, noyau
  6.12.74, `MemTotal` 4 029 208 Ko). Le build déployé est **identique** au
  `lua/` de cette branche : `md5sum` égaux pour `nfq_loop.lua`,
  `worker_nft.lua`, `nft_queue.lua`, `dup_query.lua`,
  `worker_responses.lua`, `nft_rules.lua` et `worker_questions.lua`.
- **Générateur** : `servus.lan` (10.35.1.2), `tmp/tune/dnsload5.py` passé par
  stdin (rien installé). Une **seule IP source** (10.35.1.2) et **N ports
  source** (un socket par port), charge en tourniquet sur deux destinations du
  résolveur (`10.35.1.1`, `10.35.4.1`). `mixed` = 30 % NXDOMAIN + 70 % noms
  cacheables (dont Tailscale) ; `up` = 100 % `vpn.stemarie.dynv6.net` (A).
- **Authentification** : `servus` est authentifié sur le portail pendant toute
  la campagne. Contrôle **avant chaque palier** (`dig controlplane.tailscale.com
  @10.35.1.1` doit rendre 8 adresses) : jamais en échec.
- **Paliers** : 30 s de charge, repos vérifié avant (profondeur nulle sur les
  files de la plage et compteurs figés 3 s), un seul générateur (`pgrep`),
  compteurs nft et NFQUEUE lus dans le même instantané, sonde DNS après chaque
  palier. **Drain après la fenêtre** : 45 s pour les paliers principaux (la perte
  « à chaud » d'un drain de 2 s, comme §15, ne distingue pas une file en retard
  d'une perte réelle), 2 s pour les contrôles explicitement comparés à §15.
- **CPU** : jiffies `/proc/<pid>/stat` échantillonnés (HZ mesuré 96-102 selon
  la fenêtre), ramenés à la **fenêtre de 30 s** (pas au drain) ; `idle`/`user`/
  `sys`/`softirq` par Δ`/proc/stat`. RSS = `VmRSS` de fin de fenêtre.
- **Configurations** (une variable à la fois, `/etc/init.d/custos restart`
  entre les deux, sauvegarde `.dbench5` avant toute modification) :
  - **A — config de la cible** : `nfqueue: { responses: "14-15" }` (donc
    `questions` = défaut `"0-1"`, `rcvbuf` absent = 4 Mio, `maxlen` absent =
    4096, `pending_max` absent = 20 000) ;
  - **B — défauts du code** : la seule clé `nfqueue` supprimée par `sed` →
    `questions` `"0-1"`, `responses` `"3-4"`, mêmes défauts `rcvbuf`/`maxlen`/
    `pending_max`. **A et B ne diffèrent donc que par les numéros de files**
    (14-15 contre 3-4) : toutes les autres clés étaient déjà aux défauts en A.

### 17.2 Répartition jhash mesurée (effet de `d-qhash`)

Règles présentes dans `nft list ruleset` (lignes 973-976 sur la cible) :
`ip saddr . th sport mod 2` (questions) et `ip daddr . th dport mod 2 offset 14`
ou `offset 3` (réponses), conformes à `src/nft_rules.moon:163-183` et
`doc/CONFIG.md:388-425`. La clé des réponses porte sur l'**IP et le port du
client**, pas sur le couple client/résolveur.

Distribution mesurée par Δ`id_sequence`, **une seule destination**
(`10.35.1.1`), donc une seule « source » au sens de §13.2/§15.2 :

| source | questions q0/q1 | réponses q14/q15 |
|---|---|---|
| 1 socket (1 port) | 1200 / 1 | **0 / 2058** |
| 8 sockets (8 ports) | 1800 / 600 | **2045 / 2057** |
| 128 sockets (128 ports) | 998 / 1002 | **1742 / 1706** |

Avec un port unique, **tout** tombe sur une file de chaque sens (le hachage
`(IP, port)` est constant) ; avec plusieurs ports, les réponses se répartissent
sur les deux files — c'est l'effet attendu de `d-qhash`. `d-valspread` n'est
pas séparable de `d-qhash` dans cette mesure : les deux sont dans le même
build, et le choix du validateur n'est pas journalisé. Sur les paliers
principaux (2 destinations, 128 ports), la répartition est équilibrée
(p. ex. A 500 `mixed` : q14 13 562 / q15 12 008 ; B 500 : q3 12 597 / q4
12 928).

### 17.3 Résultats — configuration A de la cible (`0-1` / `14-15`)

Paliers de 30 s, 128 ports source, 2 destinations, drain 45 s. `resp`/`dns` =
somme des workers de la plage, `nft` = worker nft, `idle` = Δ`/proc/stat` sur
la fenêtre. Perte = côté client après drainage ; `qdrop`/`udrop` = colonnes 6
et 7 de `/proc/net/netfilter/nfnetlink_queue` ; `prof.` = profondeur max des
files réponses.

| palier | perte | p50/p99 (ms) | resp / dns / nft (% vCPU) | idle | RSS resp | qdrop / udrop | prof. |
|---|---|---|---|---|---|---|---|
| 200 `mixed` | 0 % | 22,7 / 42,5 | 62,6 / 41,3 / 18,0 | 42,1 % | 36,1 Mio | 0 / 0 | 7 |
| 350 `mixed` | 0 % | 37,6 / 333,7 | 104,6 / 76,5 / 34,5 | 15,9 % | 36,1 Mio | 0 / 0 | 30 |
| 500 `mixed` | **14,9 %** | 3866 / 6170 | 115,9 / 110,2 / 38,5 | 4,4 % | 36,1 Mio | 0 / 0 | 2 589 |
| 700 `mixed` | **31,7 %** | 9394 / 14 677 | 115,8 / 115,9 / 36,0 | 3,6 % | 35,8 Mio | 0 / 0 | 3 083 |
| 800 `up` | 0 % | 832 / 4605 | 124,5 / 91,2 / 0,0 | 3,8 % | 35,8 Mio | 0 / 0 | 2 044 |
| 1000 `up` | **34,1 %** | 4526 / 6800 | 124,1 / 113,3 / 0,0 | 5,2 % | 38,0 Mio | 0 / 0 | 3 052 |
| 1300 `up` | **63,0 %** | 5806 / 9817 | 125,9 / 133,8 / 0,0 | 4,2 % | 41,0 Mio | **687** / 0 | 4 049 |

### 17.4 Résultats — défauts du code (B, `0-1` / `3-4`)

Mêmes paliers, même générateur (128 ports), drain 45 s.

| palier | perte | p50/p99 (ms) | resp / dns / nft (% vCPU) | idle | RSS resp | qdrop / udrop | prof. |
|---|---|---|---|---|---|---|---|
| 200 `mixed` | 0 % | 22,5 / 44,9 | 69,6 / 43,8 / 19,6 | 45,7 % | 20,5 Mio | 0 / 0 | 4 |
| 350 `mixed` | 0 % | 36,5 / 348,4 | 104,5 / 72,6 / 34,1 | 17,1 % | 23,0 Mio | 0 / 0 | 15 |
| 500 `mixed` | **12,9 %** | 4401 / 5887 | 117,4 / 102,8 / 39,4 | 5,5 % | 29,5 Mio | 0 / 0 | 2 399 |
| 700 `mixed` | **33,0 %** | 7485 / 14 692 | 115,3 / 115,1 / 35,5 | 4,2 % | 32,8 Mio | 0 / 0 | 3 454 |
| 800 `up` | 0 % | 390 / 2173 | 126,8 / 83,3 / 0,0 | 3,9 % | 32,7 Mio | 0 / 0 | 858 |
| 1000 `up` | **28,8 %** | 4264 / 5962 | 125,9 / 103,3 / 0,0 | 5,2 % | 35,8 Mio | 0 / 0 | 3 217 |
| 1300 `up` | **67,3 %** | 4854 / 6802 | 128,8 / 129,2 / 0,0 | 5,1 % | 45,7 Mio | **1 907** / 0 | 4 096 |

**A et B sont équivalents** : les écarts (p. ex. 800 `up` p50 390 contre
832 ms, 1000 `up` 28,8 % contre 34,1 %) sont dans la variabilité du tirage de
ports et de la charge, pas dans la configuration. C'est attendu — les deux
configurations sont le même profil 2/2 avec `rcvbuf` 4 Mio, `maxlen` 4096 et
`pending_max` 20 000 ; seuls les numéros de files changent.

### 17.5 Comparaison à §15 et §16.2, et gain par correctif

**Contrôle au protocole exact de §15** (1 socket, 2 destinations, 30 s,
drain 2 s) : à **500 `mixed`**, 15 000 émis / 9 787 reçus = **34,8 %** de perte
(§15 : 42,3 %), `qdrop` **664** (q15) contre **8 782**, `udrop` 0, profondeur
max 4 082. Le même palier avec un drain de 20 s rend **3,7 %** (14 447 reçus,
`qdrop` 0) : l'essentiel de la perte « à chaud » est une **file en retard**, pas
des paquets jetés. Détail des gains :

1. **`nfqueue.maxlen` 4096 (`d-maxlen`)** — le plafond de 1024 ne jette plus :
   à 500 `mixed` `qdrop` passe de 8 782 (§15) à 664 (contrôle 2 s) et 0 (drain
   20 s) ; à 800 `up` et 1000 `up` (128 ports) `qdrop` = 0 (contre 8 191 à
   1000 `up` §15). Il ne réapparaît qu'à **1300 `up`** (687 en A, 1 907 en B),
   avec une profondeur de 4 049-4 096 : la longueur de file redevient le
   limiteur à ce débit seulement.
2. **Drain netlink pendant `wait_ack` (`d-ackread`)** — à **350 `mixed`**, avec
   le même générateur 1 socket, p50 **81,2 ms** (p99 282) contre **474 / 873**
   en §16.2, `response_entry_ms` p99 **98 ms** contre **337** ; à 200 `mixed`,
   p99 **46,6** contre 73. La distribution est pourtant *moins* bonne dans ce
   contrôle (un seul port ⇒ une seule file réponses, 100 % sur q4), donc le
   gain vient bien du chemin de lecture, pas du hachage.
3. **Cache d'upsert (`d-nftcache`) + coalescence des écritures (`d-nftwrite`)**
   — CPU `nft` à 200 `mixed` : **20,3 %** (1 socket) contre **50,9 %** en §16.2
   et **18,0-19,6 %** (128 ports) ; à 350 : **35,1 %** contre **64,5 %**. Le
   nombre d'upserts par requête est inchangé (`nft_r`/`nft_q` = 1,70-1,71), donc
   le coût **par paquet** a été divisé par ~2. Les deux branches ne sont pas
   séparables dans ce build (aucun build sans l'une des deux) ; le cache
   explique le saut d'insertions, la coalescence les `write()`.
4. **`d-qhash` (+ `d-valspread`)** — la répartition est effective avec
   plusieurs ports (§17.2), mais **un client à port source unique concentre
   désormais tout son trafic sur une file de chaque sens** : à 800 `up`, le
   contrôle 1 socket perd **22,2 %** (`qdrop` 1 202, un seul worker réponses à
   80,5 % d'un vCPU) alors que §15 avait mesuré **0 %** avec l'ancien hachage
   sur le couple d'adresses (les réponses A se répartissaient par destination).
   Ce n'est pas une régression pour un client réel (les résolveurs tirent un
   port éphémère par requête), mais c'est une limite à connaître : le hachage
   par `(IP, port)` n'équilibre que si les ports varient.
5. **`d-rcvbuf` / `d-dohspin`** : `udrop` = 0 et `doh` ≤ 0,1 % sur **tous** les
   paliers, y compris avec un seul port ; les deux correctifs tiennent.

### 17.6 Nouveau goulot

À partir de 500 `mixed` et 800 `up` avec 128 ports, `idle` tombe à **3,6-5,5 %**
et la perte n'est plus un débordement de file noyau : `qdrop` = `udrop` = 0
jusqu'à 1000 `up` inclus. Deux mécanismes la portent :

- **CPU agrégé** : `resp` 116-129 %, `dns` 91-134 %, `nft` 36-39 % (mixed),
  `events` 13-22 %, `mac-lrn` 6-12 % — les quatre cœurs sont saturés
  (`user` 62-68 %, `sys` 22-28 %, `softirq` 1,4-1,6 %). Aucun worker isolé ne
  plafonne (les deux workers réponses restent à 56-65 % chacun) : c'est la
  **somme** qui sature, comme en §15.4, mais sans les jets de file.
- **`response_orphan_dropped`** : la perte visible est faite de réponses qui
  arrivent sans entrée `pending` correspondante. Les lignes de la fenêtre
  portent `ipc_retry_attempts=5`, `ipc_retry_wait_ms=100` et un compteur
  `suppressed=` de **1 630** (500 `mixed` B), **5 069** (700 `mixed` A),
  **8 258** (1000 `up` A), **27 161** (1300 `up` B) — du même ordre que les
  réponses manquantes. L'hypothèse la plus cohérente avec les mesures : le
  délai de lecture des réponses (`response_entry_ms` p99 5,5-5,9 s) dépasse
  **`ipc.pending_ttl` = 5 s** (`doc/CONFIG.md:529`), l'entrée `pending` est
  purgée avant que la réponse ne soit appariée. Non prouvé directement (aucun
  journal d'expiration `pending`), mais cohérent avec le fait que la perte
  n'apparaît qu'au-delà de p99 ≈ 5 s.

Le plafond de débit mesuré du profil complet (2/2, 4 Mio, 4096, 20 000) est
donc **≈ 350 q/s `mixed` et ≈ 800 q/s `up`** sans perte, avec une marge de
latence déjà consommée à 350 (p99 334 ms) ; au-delà, la machine sature et la
perte est d'abord un **retard d'appariement**, puis, à 1300 `up`, un
débordement de file réponses.

### 17.7 Recommandation de configuration

- **Garder `responses: "14-15"` sur la cible** : c'est la configuration
  mesurée, elle est équivalente aux défauts du code (`"3-4"`), et la changer
  n'apporte rien. Les deux profils sont 2/2 avec les mêmes défauts de
  `rcvbuf`/`maxlen`/`pending_max` ; le numéro de file est local et sans effet
  mesurable.
- **Pour une installation neuve**, les défauts du code (`questions` `"0-1"`,
  `responses` `"3-4"`) conviennent : mêmes chiffres que 14-15 à la variabilité
  près. Rien à changer dans les défauts.
- **Capacité** : la cible 4 cœurs tient ~350 `mixed` / ~800 `up` sans perte.
  Au-delà, la limite est le CPU agrégé, pas un réglage `nfqueue`. Les leviers
  restants sont hors de cette campagne : (a) arbitrer `ipc.pending_ttl` (5 s)
  contre le délai de file, (b) éventuellement borner `maxlen` pour échanger
  moins de retard contre plus de jets, (c) réduire le coût CPU par requête
  (le poste `dns`+`resp` reste le plus lourd).

### 17.8 Non fait / douteux

- **`d-valspread`** : effet non isolé (non séparable de `d-qhash` dans ce
  build ; le validateur choisi n'est pas journalisé).
- **Compteurs du cache d'upsert** : invisibles — la cible est au niveau INFO
  (`batch_ok`/`skipped` sont émis en DEBUG) et le niveau de log n'a **pas** été
  changé, comme demandé. L'effet est mesuré indirectement par le CPU `nft`.
- **Perte vs retard** : la perte client dépend du drain. Les paliers saturés
  sont donnés avec 45 s (contrôles §15 explicitement en 2 s) ; le partage exact
  entre réponses jamais délivrées (orphelines) et réponses arrivées après la
  fenêtre n'est pas instrumenté côté cible.
- **Un seul client** (`servus`), deux destinations IPv4 ; pas de source IPv6
  (aucune IPv6 temporaire n'a été nécessaire : la variation de couple se fait
  par le port et la destination). Aucune capture AF_PACKET (interdit).
- **`perf` absent** de la cible (rien installé) ; pas de `make test-e2e`
  (consigne : le homelab ne doit pas tourner en même temps).
- **Reproductibilité** : à charge égale, le tirage des ports modifie la
  répartition (8 ports ont donné 25/75 et 50/50 selon le tirage ; 128 ports
  donnent 48-52 %). Les chiffres A/B à 800-1300 `up` en portent la trace ; les
  conclusions de capacité reposent sur les deux séries et le contrôle 1 socket,
  pas sur un seul run.

### 17.9 Délestage précoce des questions périmées (branche `d-shed`)

§17.6 a montré que la perte au-delà de ~350 q/s `mixed` n'est plus un
débordement de file : les réponses arrivent après expiration de leur entrée
`pending` (`ipc.pending_ttl` = 5 s) et sont jetées en
`response_orphan_dropped` après un traitement complet. Le correctif jette
**plus tôt** les questions déjà périmées, pour rendre du CPU aux requêtes
encore servables.

- **Mesure de l'âge** : `src/nfq_loop.moon` expose `packet_age_ms(nfad)`, qui
  lit l'horodatage **noyau** du paquet (`NFQA_TIMESTAMP`, via
  `nfq_get_timestamp`, déclaré dans `src/ffi_defs.moon`) et le compare à
  `CLOCK_REALTIME` (`ktime_get_real` côté noyau, même base). L'attribut est le
  seul témoin du temps passé **dans la file noyau** : un horodatage pris à la
  lecture userspace serait toujours ~0, puisque la lecture *est* le début du
  traitement.
- **Disponibilité noyau** (vérifiée dans les sources Linux v6.12, celui de la
  cible) : `nfqnl_build_packet_message` n'ajoute `NFQA_TIMESTAMP` que si
  `skb_tstamp_cond(entskb, false)` est non nul, pour les hooks
  `<= NF_INET_FORWARD` ; `skb_tstamp_cond` ne renseigne l'horodatage que si
  `netstamp_needed_key` est active (socket `SO_TIMESTAMP`). Il n'existe **pas**
  de flag `NFQA_CFG_F_TIMESTAMP` dans les en-têtes 6.12/7.2 (seuls FAIL_OPEN,
  CONNTRACK, GSO, UID_GID, SECCTX). Sans horodatage, `nfq_get_timestamp` rend
  -1 et `packet_age_ms` rend `nil` : aucun délestage (chemin sûr). Sonde
  locale (noyau 6.18.60, netns non privilégié, script jetable `tmp/tsprobe.lua`) :
  `ts_rc=0`, âge mesuré **1 200 ms** après un retard de lecture imposé de
  1 200 ms — le mécanisme et l'horloge sont donc justes.
- **Activation automatique** (`src/lib/netstamp.moon`) : au démarrage du
  worker questions, quand `max_age_ms > 0`, un socket UDP `SO_TIMESTAMP` est
  ouvert sans `bind` ni trafic et conservé jusqu'à la fin du processus ; il
  active `netstamp_needed_key` pour tout le système. Constantes dans
  `src/ffi_defs.moon` : `SO_TIMESTAMP` = 29 (`asm-generic`, x86_64/arm),
  `SO_TIMESTAMP_NEW` = 63 (32 bits avec `time_t` 64 bits, musl d'OpenWrt) ;
  sur MIPS `SOL_SOCKET` = `0xffff` (au lieu de 1), essayé en repli. Un échec
  (`socket` ou `setsockopt`) produit le WARN `netstamp_enable_failed` et n'est
  **pas fatal**. Au premier paquet traité, un INFO unique
  `question_shed_timestamp` (`available: true|false`) indique si
  l'horodatage est réellement joint ; aucun log par paquet ensuite.
- **Décision** : dans `src/worker_questions.moon`, avant la copie du payload,
  `age_ms > nfqueue.max_age_ms` (**1 500 ms** par défaut, `0` = désactivé) →
  `NF_DROP` immédiat, compteur `shed_total`, log INFO rate-limité
  `question_shed` (une ligne / 10 s, `suppressed=N`). Aucun parse, aucune
  décision de filtre, aucune écriture IPC, aucune duplication second avis.
  La file `questions` ne sélectionne que `th dport 53`
  (`src/nft_rules.moon:118-121`) : le paquet jeté est bien une question ; le
  verdict est **DROP** (jamais ACCEPT), fail-closed conservé.
- **Réponses** : jamais jetées sur l'âge. Le coût d'une orpheline était borné
  par `ipc.match_retry` (5 × 20 ms, budget 100 ms/s par worker,
  `src/worker_responses.moon:211-232`) ; ce sommeil ne peut plus apparier une
  réponse plus vieille que `pending_ttl` (le token IPC de la question est écrit
  avant que celle-ci ne parte en amont). `retry_worthwhile` saute donc le retry
  au-delà de `pending_ttl` : coût d'une orpheline très vieille réduit au parse,
  au lookup `pending` et au log rate-limité.
- **Non mesuré** : aucun palier de charge n'a été rejoué sur la cible dans cette
  branche (pas d'accès au homelab, consigne §17.8) ; le gain CPU attendu
  (part des questions > 1,5 s × coût complet par question) reste à chiffrer.
  L'horodatage noyau est désormais activé automatiquement par un socket
  `SO_TIMESTAMP`, et le log `question_shed_timestamp` (au premier paquet) dit
  s'il est réellement disponible ; la mesure de charge sur `custos.lan`, elle,
  reste à faire.


## 18. Profilage du hot path (2026-11-12, branche `d-prof`)

Réponse à la piste §10.3 / §16.5 (8) : « il faudrait un profileur dans le
worker (`jit.profile`) ». Fait **entièrement en local** (aucun accès distant,
aucun déploiement) : un micro-banc rejoue en boucle les handlers **réels** des
workers sans NFQUEUE ni réseau, ce qui rend possible à la fois la mesure
`os.clock` et les profils `jit.profile`/`jit.v`/`jit.dump`. Rapport complet
(chiffres, profils, traces, propositions) : **`tmp/prof_report.md`** ; artefacts
bruts : `tmp/prof/`.

### 18.1 Le banc : `make bench-hotpath`

`src/bench/hotpath.moon` (+ `hotpath_cli.moon`, cible `Makefile`,
doc `src/bench/README.md`). Il appelle `handle_question` et `handle_response`
tels que les installent `worker_questions.run` / `worker_responses.run`
(`nfq_loop.run_queue` neutralisé pour les capturer), avec le filtre réel
(`filter.load`), la transaction IPC réelle (produite par une sonde
`handle_question`), `nft_queue` réel (tube vidé après chaque lot, sans
`ack_rfd` donc sans attente d'ACK — l'attente n'est pas du CPU) et des stubs
minimaux : `libnfq` (payload factice, verdicts comptés), `raw_send` (aucun
socket, aucun paquet émis).

**Sécurité sur machine vivante** : le banc force `config.nft.table` à un nom
inexistant (`src/bench/hotpath.moon`, `apply_config`) parce que `filter.load`
exécute `ip_whitelist.init`, qui **FLUSH** les sets `ip*_dest_whitelist` de la
table courante — avec la vraie table, lancer le banc sur un hôte où custos
tourne viderait ces deux sets. Aucun autre effet de bord réseau : `run_queue`
neutralisé (aucune file NFQUEUE ouverte), `raw_send` stubé (aucun paquet émis),
sorties limitées à `./tmp/prof/`.

Six cas : `question` (dont la duplication validateur), `ipc_drain` (coût
complet du tube question→réponse : écriture + lecture + décodage + insertion
`pending`), `response` (sans second avis, 1 A), `so_a` (parquage seul),
`so_cycle` (A + réponse validateur B, 8 A, 16 insertions nft), `setup_control`
(préparation seule, à déduire des cas réponse).

Protocole : échauffement 5 000, **100 000 itérations** par cas, `HP_REPEAT=3`
passages dont le minimum retenu (la machine est partagée : le total varie de
±30 %, le minimum de lot de ±10 %), lots de64 (= `MAX_BATCH_PKTS`),
allocation mesurée avec `collectgarbage("stop")`. Le banc **sort en code 1** si
le chemin mesuré n'est pas le décrit (codes retour ou nombre de verdicts) :
aucune mesure ne porte sur un autre chemin.

### 18.2 Coût par paquet (x86-64 local, µs, min de 3 passages)

| cas | avant correctifs | après | gain |
|---|---|---|---|
| question | 51,2 / 51,9 | **26,2 / 26,7** | −49 % |
| ipc_drain | 14,1 / 13,9 | **5,9 / 8,7** | −48 % (minimum de lot −64 %) |
| response | 55,6 / 52,5 | **30,1 / 29,3** | −46 % |
| so_a | 29,0 / 32,1 | 33,8 / 23,0 | −15 % au minimum de lot |
| so_cycle | 110,3 / 116,3 | **47,4 / 47,5** | −56 % (cycle second avis 220,6 → **94,7 µs**) |
| setup_control | 1,3 / 2,5 | 1,4 / 1,4 | témoin inchangé |

Allocation (GC arrêté) : `response` 13 387 → 11 223 o/paquet, `so_cycle`
40 465 → 32 889 o/itération, `ipc_drain` 2 634 → 1 906 o/paquet.

Ces chiffres sont en **x86-64** : ils ne se transposent pas en absolu sur
l'A55 (rapport ~25×), seules les **parts** (profils ci-dessous) sont
transposables. Ils servent à arbitrer « où optimiser », pas à prédire le
plafond de §7/§15.

### 18.3 Profil (`jit.profile`, 10 s par cas) — avant correctifs

Postes dominants (extraits de `tmp/prof/profile_f_before.txt` et
`profile_l.txt`, détail complet dans `tmp/prof_report.md` §3) :

| cas | postes ≥ 5 % des échantillons |
|---|---|
| question | `eval` 25,4 % (moteur de règles), `ipc_hex.lua:19` 14,1 % (`to_hex`), `sp` 5,8 % (pack → duplication), `su` 5,3 %, `cond` 4,8 % |
| ipc_drain | **`from_hex` 48,5 %**, `decode_msg` 12,4 %, `now_fn` 9,5 %, `set_pending` 7,0 %, `split_fields` 6,0 % |
| response | **`ipc_hex.lua:19` 21,7 %**, `finalize_a` 10,2 %, `step` 7,7 %, `labels` 7,4 %, `strip_https_rr` 5,0 % |
| so_a | `parse_rr` 29,3 %, `step` 18,1 %, `parse_questions` 8,8 %, `labels` 6,1 % |
| so_cycle | **`ipc_hex.lua:19` 35,6 %**, `build_line` 8,5 %, `parse_rr` 6,1 %, `to_hex` 4,0 % |
| états VM | `G` (GC) 17-48 %, `C` (code C/FFI) 9-35 %, `I` (interprété) 18-32 %, `N` (compilé) 9-49 % |

En mode ligne : `to_domain.lua:56` (la `sub` de suffixe) 14,2 % de `question`,
`ipc_hex.lua:20` 12,2/23,3/36,7 % (question/response/so_cycle),
`ipc_hex.lua:36` (`string.char tonumber(sub)`) 29,6 % de `ipc_drain`.

### 18.4 Traces avortées (`jit.v` + `jit.dump`, 20 000 iters)

`tmp/prof/jitv_final.txt` (212 traces démarrées, **885 aborts**),
`tmp/prof/jitdump_final.txt`, agrégats `tmp/prof/aborts_final*.txt`. Raisons
(hors sites du banc) : `leaving loop in root trace` 183, `inner loop in root
trace` 178, `NYI: bytecode UCLO` 163, `blacklisted` 96, `NYI: bytecode FNEW`
63, `loop unroll limit reached` 18, `NYI: return to lower frame` 15. Sites
dominants : `rule.lua:307/310` (boucle des règles), `worker_responses.lua:739`
(boucle `pairs` de `finalize_a`), `ipc.lua:472` (`make_key`, `string.format`),
`nft_queue.lua:169/176/181` (`flush`), `dns_ede.lua:274-431` (closures de
`strip_rrtypes`), `log.lua:676` (`clock_gettime`). **Avant** les correctifs,
`ipc_hex.lua:21 -- NYI: bytecode FNEW` (25×) et `ipc_hex.lua:19 -- NYI: return
to lower frame` figuraient en tête : la closure de `to_hex` empêchait toute
compilation de ce segment — disparus après le correctif. Liste complète des
sites + raisons : `tmp/prof_report.md` §4.

### 18.5 Correctifs appliqués (gain mesuré ≥ 5 %, un commit par correctif)

| Correctif | Fichier:ligne | Gain mesuré | Commit |
|---|---|---|---|
| `to_hex` par table 256 entrées au lieu d'une closure + `string.format`/octet | `src/lib/ipc_hex.moon:25-27,48-66` | question −24 %, response −30 %, so_cycle −34 % | `b3d44d0` |
| `from_hex` par table de nibbles au lieu de `sub`+`tonumber`+motif | `src/lib/ipc_hex.moon:72-77,85-108` | ipc_drain −21 % | `552be16` |
| suffixes de domaine sans allocation (rejet O(1) par le dernier octet + `find` littéral) | `src/filter/conditions/to_domain.moon:39,50-51,56-63` | question −25 % | `9013d37` |
| pas de re-parse de la réponse si aucun callback ne l'a réécrite | `src/worker_responses.moon:767-776` | response −11 %, so_cycle −10 % | `e84ee03` |
| cache borné (8 entrées, purge en bloc) des deux conversions hex | `src/lib/ipc_hex.moon:29-43,50,59-65,102-107` | ipc_drain −38 %, so_cycle −27 %, response −15 %, question −6 % | `b2331c8` |

Chaque commit porte son avant/après ; tests d'équivalence ajoutés
(`tests/unit/lib/ipc_hex_spec.moon` : +8 — sortie identique sur les 256 octets,
**arité (une seule valeur, y compris sur un hit de cache)**, débordement du
cache, erreurs jamais mises en cache ;
`tests/unit/filter/conditions_spec.moon` : +7 cas d'équivalence des suffixes).
L'arité de `to_hex` est un **contrat** : la 2e valeur ajoutée par le cache de
`b2331c8` corrompait les lignes nft (cf. `audits.md`, « Régression e2e du
contrat d'arité de `to_hex` »).

### 18.6 Correctifs proposés, non appliqués

Aucun des postes restants n'atteint 5 % de façon sûre et isolée, ou est hors
portée (détail chiffré : `tmp/prof_report.md` §5.2) : `is_valid_timeout` à
chaque ligne nft (3,8-4,2 %), `build_line` en concaténation directe (2-3 %),
`parse_answers` qui construit9 champs par RR (2-3 %), les closures de
`strip_rrtypes` (2-4 %), `user_for_mac`/`read_cached` (sous-estimé par le
profil : biais d'échantillonnage mur), le moteur d'évaluation des règles
(`eval` 10-25 % : sémantique de filtrage, trop risqué), `sp`/`su`/`checksum`
(5-8 % de `question`) et **`parse_rr`/`labels` (40-50 % de `so_a`, ~15 % de
`response`) — sous-module moontastik non modifiable ici** (`Makefile:63-68`).
Le GC reste à 29-47 % des échantillons : la piste principale résiduelle est de
diviser l'allocation par paquet (11,2 Ko sur `response`), ce qui demande une
campagne dédiée et non un correctif local.

### 18.7 Reste à faire

- `make test-e2e` avant fusion : **fait** — la première campagne a révélé la
  régression du contrat d'arité de `to_hex` (cf. `audits.md`, « Régression e2e
  du contrat d'arité de `to_hex` »), corrigée ; 94 passed / 0 failed depuis ;
- re-mesurer sur la cible aarch64, où les parts ci-dessus (et non les µs) sont
  transposables — idéalement en déployant le banc lui-même (`make bench-hotpath`
  tourne sans NFQUEUE ni réseau ; le flush `ip_whitelist` est neutralisé par la
  table forcée en inexistant, cf. §18.1) ;
- campagne « allocation par paquet » (§18.6) si le coût CPU par paquet reste le
  plafond après le multi-worker §11 et le second avis ciblé §10.2.


## 19. Réglage du GC LuaJIT par worker (2026-11-12, branche `d-gctune`)

Le profilage §18 impute 29-47 % des échantillons du hot path au GC. Cette
section mesure le compromis coût/empreinte des paramètres `pause`/`stepmul` sur
le micro-banc local, fixe des défauts chiffrés et décrit le protocole de
validation sur la cible (aucune connexion à `custos.lan` n'a été faite ici).

### 19.1 Ce qui a été implémenté

| Élément | Fichier | Détail |
|---|---|---|
| Module de réglage | `src/lib/gc_tune.moon` | `normalize` (validation entière + bornes), `new` (état injectable : `collectgarbage`, horloge, log), `apply!` (`setpause`/`setstepmul`), `idle!` (pas `collectgarbage "step", idle_step`), `guard!` (`count` ≤ 1×/s, jusqu'à 8 pas forcés au-delà de `max_heap_mb`, log `gc_heap_guard` ≤ 1/10 s), `shared!` (état du processus). |
| Section de config | `src/config.moon` (normalize) | `gc = { pause, stepmul, idle_step, max_heap_mb }` ; valeurs absentes/invalides → défauts + warn `gc_invalid` ; repli sur `runtime.gc_pause`/`runtime.gc_stepmul` (compatibilité). |
| Application au démarrage | `src/main.moon:57-71` | Réglage appliqué dans le superviseur avant tout fork (hérité COW), puis rappelé dans chaque worker par `gc.apply!` : `nfq_loop.run_queue` (`src/nfq_loop.moon:122-125`), `worker_events.run`, `mac_learner.run`, `worker_nft.run`. |
| Pas sur temps mort | `src/nfq_loop.moon:279-283`, `src/worker_events.moon` (après poll), `src/mac_learner.moon` (poll 1 s sans fd prêt), `src/worker_nft.moon` (timeout de `poll` depuis §24) | `gc.idle!` uniquement quand la file/tube est vide. |
| Garde-fou | boucles ci-dessus | `gc.guard!` à chaque tour (coût : une comparaison d'horloge, `count` au plus 1×/s). |
| WebUI | `src/webui/schema/config_schema.moon`, `handlers/config.moon`, `router.moon` | Section `gc` éditable (4 champs), valeurs par défaut affichées. |
| Doc | `doc/CONFIG.md` § 2bis, `.agents/architecture.md`, `src/bench/README.md` | Clés, bornes, sémantique, anciennes clés marquées obsolètes. |

Les anciennes clés `runtime.gc_pause`/`runtime.gc_stepmul` ne sont plus
documentées comme réglage courant mais restent lues si la section `gc` ne les
fournit pas : une configuration existante garde son comportement.

### 19.2 Mesure locale (`make bench-hotpath`)

Ajout au banc : `--gc-pause`, `--gc-stepmul`, `--gc-idle-step`,
`--gc-max-heap` (appliqués dans `setup`, donc avant les mesures) et une colonne
`tas max (Kio)` (`collectgarbage "count"` relevé après chaque lot, maximum sur
les passages). Protocole : 3 tours, chaque couple exécuté une fois par tour dans
un ordre alterné (A/B), `--iters 100000 --repeat 5`, CPU épinglé
(`taskset -c 5`), métrique de coût = **minimum de lot** (le minimum par lot est
stable, le total ne l'est pas sur une machine partagée). Matrice complète :
`tmp/gctune/matrix2.log` / `matrix2_rows.tsv` (ignorés par git).

| pause | stepmul | question µs/paq (lot min) | response µs/paq (lot min) | tas max médian (Kio) |
|---|---|---|---|---|
| **110** (ancien défaut) | 400 | 43,0 | 38,0 | 1 968 |
| 200 | 200 | 32,7 | 24,0 | 3 593 |
| **200** | **400** | **32,5** | **23,5** | **3 356** |
| 300 | 200 | 33,7 | 23,3 | 5 124 |
| 300 | 400 | 31,7 | 23,7 | 4 885 |
| 400 | 200 | 32,0 | 23,4 | 6 689 |
| 400 | 400 | 32,6 | 22,8 | 6 455 |

Lecture :

1. **Le couple historique 110/400 est le plus coûteux** : réponse 38,0 µs/paquet
   contre 22,8-24,0 pour tous les `pause ≥ 200` (−37 à −40 %), question 43,0
   contre 31,7-33,7 (−22 à −26 %). C'est cohérent avec la part GC de §18 : une
   pause de 110 % collecte en permanence.
2. **Au-delà de 200, le coût ne baisse plus** : les écarts 200/300/400 (22,8 à
   24,0 µs réponse) sont dans la dispersion run-à-run (±5 %). Le tas, lui,
   croît linéairement avec `pause` : ~3,4 Mio à 200, ~4,9-5,1 à 300,
   ~6,5-6,8 à 400 (tas maximum observé sur le cas réponse).
3. **`stepmul` 400 plutôt que 200** : à `pause` égal, coût identique mais tas
   légèrement plus bas (3 356 vs 3 593 Kio à pause 200 ; 4 885 vs 5 124 à 300),
   ce qui est l'effet attendu d'un GC incrémental plus rapide.

**Défauts retenus** : `pause: 200`, `stepmul: 400` — coût minimal mesuré, tas
+1,4 Mio par worker par rapport à l'ancien défaut (3,36 vs 1,97 Mio), soit
~14 Mio pour 10 workers. `idle_step: 100` (taille de pas par défaut de LuaJIT,
uniquement sur temps mort) et `max_heap_mb: 32` (plafond de sécurité > le pire
tas légitime observé, y compris `ipc.pending_max = 20 000` ≈ 16 Mio/worker de
§15.5) ; `0` désactive chacun. Le garde-fou et le pas sur temps mort sont
couverts par `tests/unit/lib/gc_tune_spec.moon` (13 cas) et le câblage
`apply!`/`guard!`/`idle!` par `tests/unit/nfq_loop_enobufs_spec.moon`.

Limites de cette mesure : micro-banc **x86_64** (pas la cible aarch64), débit
d'allocation très supérieur à la production (100 000 réponses en ~0,4-0,8 s),
pas de NFQUEUE ni de réseau. Les rapports entre couples sont transposables ; les
µs absolues ne le sont pas.

### 19.3 Protocole de validation sur la cible (à faire, hors de cette branche)

Aucune connexion à `custos.lan` n'a été faite. Pour valider les défauts sur la
cible (aarch64 A55 ×4, OpenWrt) :

1. **Déployer** la branche puis deux variantes de `/etc/custos/config.moon` :
   `gc: { pause: 110, stepmul: 400 }` (référence) et
   `gc: { pause: 200, stepmul: 400 }` (candidat). Vérifier au démarrage la ligne
   `gc_tuning` (pause/stepmul/idle_step/max_heap_mb effectifs) dans `logread`.
2. **Charge** : générateur `tmp/bench2/dnsload3.py` en `mixed` à 200 puis 300
   q/s, 30 s par palier, après retour au repos (profondeur file 4 = 0 et
   `user_dropped` figé sur 3 s, cf. §1). Rejouer chaque variante 3 fois en
   alternance (A/B/A/B/A/B) pour décorréler la dérive thermique.
3. **Mesures par palier** : débit émis/reçus et perte (`queue_dropped`,
   `user_dropped`), latence client p50/p99, `q_to_response_ms` p50/p99 des
   lignes `response_dns_benchmark`, CPU (`utime+stime`) des workers `dns-q*`,
   `resp-q*`, `nft`, `events`, et **RSS par worker** (`/proc/<pid>/statm`,
   `sampler4.pl` le collecte déjà à 1 Hz). Relever aussi le nombre de lignes
   `gc_heap_guard` (doit rester nul hors incident).
4. **Critères d'acceptation** : p99 et perte non dégradées de plus de 5-10 %
   par rapport à 110/400 ; RSS total augmenté de ≤ 2 Mio × nombre de workers ;
   part GC des échantillons (`make bench-hotpath` sur la cible ou profil
   `jit.profile`) en baisse. Si la RAM est le facteur limitant (mode
   `runtime.lowmem`), garder `pause: 110` ou fixer `max_heap_mb` plus bas
   (12-16 Mio) : le compromis mesuré ci-dessus est un arbitrage CPU↔mémoire,
   pas un gain gratuit.
5. **Temps mort** : sur une cible au repos, vérifier que le CPU de `events` et
   `mac-lrn` ne remonte pas (le pas `idle_step` ne tourne qu'après un timeout de
   poll sans donnée ; `mac_learner` l'exclut quand des probes sont en vol).

## 20. Écritures groupées vers les workers events et mac-learner (2026-11-12, branche `d-batchev`)

Implémentation de la piste (7) de `tmp/perfaudit_report.md` §5.3 (« écriture
events + learn par question : 2 pipe writes par paquet ») et du volet
« écritures events/learn coalescées » de §16.5. Constat de départ : chaque
question DNS validée coûtait **deux `write()`** sur des pipes distincts — une
ligne TSV de 11 champs vers `worker_events` (`worker_questions.write_event`) et
un message binaire de 22 octets vers `mac_learner`
(`worker_questions.write_learn_msg`) — soit deux appels système par paquet sur
le chemin chaud du worker questions, et **deux réveils par paquet** des
lecteurs (mesurés à 11,6 % et 4,9 % d'un vCPU à 350 q/s, §16.2).

### 20.1 Ce qui change

- **Nouveau module `src/lib/pipe_batch.moon`** : tampon d'écriture groupée,
  deux formes selon le protocole du pipe. `new_records(fd, rec_size)` accumule
  des messages de taille fixe (learn : 22 o) dans un tampon FFI ;
  `new_lines(fd)` accumule des lignes (events : TSV terminé par `\n`) dans une
  table. Les deux vident par un `write()` **par tranche ≤ `PIPE_BUF_ATOMIC` =
  4096 o** : l'écriture reste atomique vis-à-vis des autres producteurs du même
  pipe (`worker_tls` et `worker_responses` écrivent aussi dans `events`,
  `worker_arp_sniffer` et `worker_auth_queue` dans `learn`). L'ordre
  d'insertion est préservé et un message n'est jamais coupé entre deux
  `write()`. Un échec (EAGAIN épuisé, EIO) est journalisé
  (`pipe_batch_write_failed`, avec `bytes`/`written`/`errno`) et les messages de
  la tranche sont abandonnés — comportement historique d'EAGAIN, désormais
  observable.
- **`worker_questions`** : `write_event` et `write_learn_msg` ne font plus
  qu'ajouter au tampon ; `flush_pipes()` vide les deux tampons. Le vidage a lieu
  en **fin de lot NFQUEUE** (`on_batch_end`, installé même quand les métriques
  sont coupées) et une dernière fois à la sortie du worker. Le hook
  `run_queue` existait déjà pour `worker_responses` (`src/nfq_loop.moon:185,301`)
  : `worker_questions` gagne au passage le drain borné du lot
  (`MAX_BATCH_PKTS`), comme le worker réponses. Conséquence directe pour un lot
  de 64 questions : **3 écritures** dans le pipe events (ligne TSV ≈ 156 o,
  tranche 4096 o → 26 lignes par écriture) et **1** dans learn (186 messages de
  22 o par tranche), au lieu de 64 + 64 ; une question isolée (trafic
  sporadique) est vidée à la fin de son propre lot, donc sans délai ajouté.
- **`mac_learner`** : le pipe learn est drainé par blocs de 128 messages
  (`LEARN_READ_MSGS`, 2816 o) au lieu d'un `read()` de 22 o par message. Un
  message coupé par une lecture courte est conservé en tête de tampon et
  complété par la lecture suivante (jamais consommé ni perdu) — l'ancienne
  boucle jetait un fragment court.
- **`worker_events`** : le découpage d'un bloc de lignes avance par position
  dans `line_buf` au lieu de recréer le reliquat après chaque ligne (O(N²)
  octets copiés par bloc → O(N)) ; le reliquat sans `\n` est recopié une fois.
  Sémantique inchangée (une ligne coupée entre deux lectures est conservée,
  testé).
- **Banc** : le cas `question` de `make bench-hotpath` appelle désormais le hook
  de fin de lot (`on_batch_end_q`), comme la production ; sur une version sans
  tampon le hook est absent et l'appel est un no-op, ce qui rend l'A/B
  comparable (`src/bench/README.md`).

Formats, destinataires et sémantique de perte : **inchangés**. Un arrêt brutal
du processus peut perdre jusqu'à un lot de messages (avant : jusqu'au message
en cours sur EAGAIN) ; la fenêtre est bornée par le vidage en fin de lot.

### 20.2 Mesures (locale x86-64, machine partagée, minimum de passages)

Protocole A/B alterné dans la même fenêtre ; les `.lua` compilés des deux états
sont échangés (même banc, mêmes sources de banc). Détail : `tmp/batchev_report.md`.

| mesure | avant | après | gain |
|---|---|---|---|
| écritures events+learn par question (`tmp/bench/writers.lua`, 200 000 paires, min de 5) | 1,27-1,31 µs | 0,52 µs | **−60 %** |
| `write()` par question (`strace -c -e trace=write`, 13 000 questions) | 3,00 | 1,06 | **−65 %** |
| dont écritures visées (events+learn) | 2,00 | 0,06 | 2 → 4 par lot de 64 (3 events + 1 learn) |
| découpage + agrégation d'une ligne events (`tmp/bench/readers.lua`, 40 lignes/bloc) | 9,4 µs | 6,7 µs | **−29 %** |
| drainage du pipe learn (`read` + `process_learn`) | 0,15 µs/msg | 0,05 µs/msg | −67 % (absolu faible) |
| cas `question` du banc hot path (lot min, 3 paires A/B, 300 000 iters) | 21,7 µs | 21,4 µs | ~−1,5 % (sous le bruit) |
| cas `question`, total (moyenne des 3 passages) | 34,1 µs | 33,4 µs | ~−2 % |

La réduction du nombre d'appels système est **déterministe** (2 par question →
4 par lot de 64, mesurée par `strace` : 0,062 écriture visée par question,
soit exactement 3 + 1 par lot). Sur le cas complet `question` du banc, le gain
attendu (≈0,8 µs sur ≈22-26 µs/paquet, soit 3-4 %) est du même ordre que le
bruit de la machine (±10 % sur le lot min) : il n'est pas résolu. Le **coût
côté lecteurs baisse aussi par construction du nombre de réveils** : à 350 q/s
`worker_events` était réveillé ~350 fois/s, il l'est désormais ~13 fois/s
(3 écritures par lot de 64, une par tranche de 26 lignes) ; `mac_learner` passe
de ~350 `read()`/s à ~5,5 écritures et ~3 `read()` par seconde (blocs de 128) — ce dernier effet n'est pas mesuré sur la cible (pas de
déploiement depuis cette branche).

**Témoins** (`make bench-hotpath`, même fenêtre, après vs référence) :
`ipc_drain` 4,5/4,5 µs (lot min), `response` 25,1/24,9, `so_cycle` 36,2/40,0
(bruit connu de ce cas) — stables.

### 20.3 Couverture et vérifications

- `tests/unit/lib/pipe_batch_spec.moon` : accumulation sans écriture, vidage en
  un `write`, tranche ≤ capacité (jamais d'écriture coupée), messages hors
  format refusés, tampon inerte sans fd, échec d'écriture journalisé + tampon
  vidé, arrondi de capacité, ordre préservé.
- `tests/unit/worker_questions_spec.moon` : `write_event`/`write_learn_msg`
  n'écrivent rien avant le vidage puis **une seule écriture** pour N messages
  (comptage des `write()` par fd), contenu et ordre des lignes/messages de
  22 o, `on_batch_end` dans les options de `run_queue` même sans métriques,
  `handle_question` tamponne jusqu'au hook.
- `tests/unit/mac_learner_core_spec.moon` : lecture par blocs (`read` de
  capacité > un message), deux messages appris dont un coupé par une lecture
  courte (reliquat conservé) ; `tests/unit/worker_events_core_spec.moon` : bloc
  de 40 lignes réparti sur deux lectures, 20e ligne coupée, toutes agrégées.
- `make check` + `make test` : **3198 successes / 0 failures / 0 errors**
  (`tmp/test.log`) ; `make test-e2e` : **94 passed / 0 failed**, après une
  première tentative invalidée par un déploiement concurrent d'un autre agent
  sur le homelab partagé (le build testé n'était pas celui de la branche :
  `worker_questions.lua` d'avant + `lib/pipe_batch.lua` absent ; deux
  `homelab.sh test-e2e` simultanés, `PANIC` du superviseur et `worker_died
  name=auth` dans la fenêtre). Relance en fenêtre exclusive : build de la
  branche déployé (`worker_questions.lua` 20 412 o, `lib/pipe_batch.lua`
  présent), 94/0 (`tmp/e2e-rerun.log`, `tmp/e2e-rerun-context.txt`).

**Non fait / douteux** : gain CPU global non mesuré sur la cible (aucune
campagne de charge ni déploiement depuis cette branche) ; l'effet des réveils
évités sur `events`/`mac-lrn` est déduit du nombre d'écritures, pas mesuré ;
les producteurs secondaires de ces pipes (`worker_tls`,
`worker_responses.write_block_event`, `worker_arp_sniffer`,
`worker_auth_queue`) écrivent toujours message par message — ils peuvent
réutiliser `lib.pipe_batch` sans changement de format.


## 21. Campagne de charge après les optimisations du hot path (2026-11-13, branche `d-bench6`)

Campagne demandée après le déploiement sur `custos.lan` d'un build `dev`
contenant les optimisations de §18 (`d-prof`), §19 (`d-gctune`), du sous-module
ipparse (`d-ipp`, commit `265876b` — `docs/agents/divers.md`) et §20
(`d-batchev`). **Aucune modification de code** ; la configuration de la cible
n'a **pas** été changée (elle était déjà celle du §17.3 : `nfqueue:
{ responses: "14-15" }`, donc `questions` = défaut `"0-1"`, `rcvbuf` 4 Mio,
`maxlen` 4096, `pending_max` 20 000, `max_age_ms` 1 500,
`gc` = défauts `pause 200` / `stepmul 400` / `max_heap_mb 32`, cf.
`src/config.moon:217-235,634-660` et `doc/CONFIG.md:378-380`). Une sauvegarde
`/etc/custos/config.moon.dbench6` a néanmoins été prise avant la première
mesure et restaurée à la fin (identité `md5` vérifiée, §21.8). Le scénario
« défauts du code » (B de §17.4) n'a **pas** été rejoué, comme demandé.

### 21.1 Dispositif et protocole

- **Build déployé identique à la branche** : `md5sum` égaux pour
  `nfq_loop.lua`, `worker_nft.lua`, `nft_queue.lua`, `dup_query.lua`,
  `worker_responses.lua`, `nft_rules.lua`, `worker_questions.lua`,
  `lib/ipc_hex.lua`, `lib/gc_tune.lua`, `lib/pipe_batch.lua`,
  `worker_events.lua`, `mac_learner.lua`, `filter/conditions/to_domain.lua`,
  `config.lua`, et les **95** fichiers `lua/ipparse/**/*.lua`
  (`LC_ALL=C sort` + `diff` : identiques). Réglage GC effectif constaté au
  démarrage : `action=gc_tuning pause=200 stepmul=400 idle_step=100
  max_heap_mb=32` (`src/main.moon:57-71`, `src/lib/gc_tune.moon`).
- **Générateur** : `tmp/tune6/dnsload5.py` (copie de `d-bench5`, aucune
  modification), une seule IP source (10.35.1.2), 128 sockets = 128 ports
  source, 2 destinations (`10.35.1.1`, `10.35.4.1`), `mixed` = 30 % NXDOMAIN
  + 70 % noms cacheables, `up` = 100 % `vpn.stemarie.dynv6.net` (A).
- **Authentification** : contrôle `dig controlplane.tailscale.com
  @10.35.1.1` avant **chaque** palier (8 adresses à chaque fois, jamais en
  échec — le harnais `runphase6.sh` s'arrête sinon). Aucune IPv6 temporaire
  n'a été créée sur `servus` (aucune n'était nécessaire : la variation de
  couple se fait par le port source et la destination).
- **Paliers** : 30 s de charge ; repos vérifié avant (profondeur nulle sur
  q0/q1/q14/q15) ; un seul générateur ; compteurs nft **avant** NFQUEUE dans
  le même instantané ; sonde DNS après chaque palier ; **drain 45 s** pour
  distinguer une file en retard d'une perte réelle. Séries arrêtées au premier
  palier > 5 % de perte, comme demandé.
- **CPU** : jiffies `/proc/<pid>/stat`, ramenés à la fenêtre de **32 s**
  (30 s de charge + 2 s) et non au drain ; `idle/user/sys/softirq` par
  Δ`/proc/stat` sur la même fenêtre. **RSS** : `VmRSS` par worker relevé à
  1 Hz, agrégé en trois phases — *avant* (dernier échantillon ≤ début),
  *pendant* (maximum sur la fenêtre), *après* (dernier échantillon, ~4 s
  après la fin du drain). Ces deux derniers points diffèrent de §17 (RSS de
  fin de fenêtre seulement) : les chiffres de RSS ne sont donc pas
  strictement superposables à ceux de §17.3.
- **Journal** : `response_dns_benchmark` (p50/p99 de `q_to_response_ms`,
  `response_entry_ms`, `ack_wait_us`), `question_shed`,
  `response_orphan_dropped` (avec `suppressed=`), `gc_heap_guard`,
  `pipe_batch_write_failed`, WARN/ERROR de la fenêtre. Niveau de log **non
  changé** (INFO).

### 21.2 Résultats — `mixed` (128 ports, 2 destinations, 30 s, drain 45 s)

`resp`/`dns` = somme des workers de la plage, `nft` = worker nft ; % d'un
vCPU sur 32 s. Comparaison à §17.3 (configuration A de `d-bench5`).

| palier | d-bench5 perte | d-bench6 perte | d-bench5 p50/p99 (ms) | d-bench6 p50/p99 (ms) | b5 resp/dns/nft | b6 resp/dns/nft |
|---|---|---|---|---|---|---|
| 200 | 0 % | 0 % | 22,7 / 42,5 | **20,6 / 35,5** | 62,6 / 41,3 / 18,0 | 44,5 / 36,6 / **29,3** |
| 350 | 0 % | 0 % | 37,6 / 333,7 | **22,1 / 87,5** | 104,6 / 76,5 / 34,5 | 64,6 / 59,1 / **43,0** |
| 500 | **14,9 %** | **0 %** | 3 866 / 6 170 | **42,5 / 217,1** | 115,9 / 110,2 / 38,5 | 78,0 / 81,3 / **46,1** |
| 700 | **31,7 %** | **7,8 %** | 9 394 / 14 677 | **600,3 / 1 794,8** | 115,8 / 115,9 / 36,0 | 94,9 / 105,2 / **46,4** |
| 850 | non mesuré en §17 | série arrêtée | — | — | — | — |
| 1000 | non mesuré en §17 | série arrêtée | — | — | — | — |

À vide (**20 q/s `mixed`**, 600 requêtes, 128 ports) : **0 % de perte, p50
23,3 ms / p99 56,4 ms** (pas de référence §17 pour ce palier). C'est le RTT
DNS de bout en bout (~20 ms de résolveur amont), pas un coût du filtre.

### 21.3 Résultats — `up` (100 % `vpn.stemarie.dynv6.net` A)

| palier | d-bench5 perte | d-bench6 perte | d-bench5 p50/p99 (ms) | d-bench6 p50/p99 (ms) | b5 resp/dns/nft | b6 resp/dns/nft |
|---|---|---|---|---|---|---|
| 800 | 0 % | 0 % | 832 / 4 605 | **17,3 / 107,0** | 124,5 / 91,2 / 0,0 | 75,2 / 64,3 / 0,2 |
| 1000 | **34,1 %** | **0 %** | 4 526 / 6 800 | **22,4 / 175,7** | 124,1 / 113,3 / 0,0 | 86,7 / 77,9 / 0,1 |
| 1300 | **63,0 %** | **0 %** | 5 806 / 9 817 | **297,0 / 965,9** | 125,9 / 133,8 / 0,0 | 101,0 / 94,5 / 0,2 |
| 1600 | non mesuré | **16,1 %** | — | 1 712,6 / 6 965,3 | — | 108,5 / 109,5 / 0,1 |

`nft` reste ~0 sur ce profil : le nom est servi par le cache du résolveur et
la réponse ne contient **aucun enregistrement** (voir §21.8), donc pas
d'upsert d'adresse.

### 21.4 Comparaison chiffrée et plafonds

- **Mixed** : le plafond sans perte passe de **≈ 350 à 500 q/s** (0 % à 500
  contre 14,9 % en §17) ; le premier palier en perte est **700** (7,8 %
  contre 31,7 %, soit ÷4). La latence à 500 s'effondre : p50 3,9 s → **42 ms**
  (÷92), p99 6,2 s → **217 ms** (÷28). À 350, p99 334 → **87,5 ms** (÷3,8).
- **Up** : le plafond sans perte passe de **≈ 800** (avec une marge de
  latence déjà consommée) à **≈ 1 300 q/s** ; 1000 et 1300, qui perdaient
  34 % et 63 %, sont à **0 %** ; p50 4,5 s → 22 ms à 1000 et 5,8 s → 297 ms
  à 1300. Le palier **1600** (nouveau, absent de §17) perd 16,1 %.
- **CPU par requête** : à charge égale, `resp` baisse de 32-40 % (62,6 → 44,5
  à 200 ; 124,5 → 75,2 à 800 `up`) et `dns` de 8-25 % (41,3 → 36,6 ; 91,2 →
  64,3). Ces gains sont cohérents avec §18 (−46 à −49 % de coût par paquet
  sur le micro-banc x86, partiellement amortis par les postes hors hot path).
- **`nft` augmente** au contraire de **+8 à +11 points** à 200-350 `mixed`
  (18,0 → 29,3 puis 34,5 → 43,0) et reste ~46 % à 500-700 (contre 36-38,5).
  Le profil `mixed` n'a pourtant pas changé et le nombre d'upserts par question
  (1,70-1,71, §17.5) n'est pas mesuré ici. C'est le seul poste qui régresse ;
  il n'est pas expliqué par les mesures de cette campagne (voir §21.8).

### 21.5 Nouveau goulot

À 500 `mixed`, `idle` = **13,1 %** (`user` 54,9 %, `sys` 26,3 %, `softirq`
4,2 %) ; à 700, `idle` = **5,3 %** (user 62,8, sys 25,6, sirq 4,9) : les
quatre cœurs sont saturés et la répartition est **plate** — `dns-q0` 51,3 % +
`dns-q1` 53,9 % (105,2 % au total), `resp-q14` 48,9 % + `resp-q15` 46,0 %
(94,9 %), `nft` 46,4 %, `events` 5,5 %, `mac-lrn` 1,0 %. Aucun worker isolé
ne plafonne à 100 % : c'est la **somme** qui sature, comme en §17.6, mais avec
un plafond repoussé de 350 à 500.

En `up`, même chose à 1300 : `resp` 101,0 %, `dns` 94,5 %, `events` 3,4 %,
`mac-lrn` 2,1 %, `idle` 7,2 %. À **1600**, la limite change de nature :
`idle` 2,3 %, `resp` 108,5 %, `dns` 109,5 %, et la file réponses déborde —
**`qdrop` 1 846 sur q14**, profondeur max **4 036** (≈ `maxlen` 4096), alors
que q15 reste à 302 et `qdrop` 0 : le déséquilibre de `jhash` (25 218 contre
18 641 paquets traités) fait déborder **une seule** file avant l'autre. La
profondeur des files questions monte aussi (q1 1 312 à 1600 ; 576 à 700
`mixed`) : c'est elle qui explique le p50 client (600 ms à 700) alors que
`q_to_response_ms` p50 n'est que de 26 ms.

`question_shed` = **0** sur **tous** les paliers : le plus vieux paquet en
file questions est resté sous `max_age_ms` = 1 500 ms (profondeur 1 312 à
1 600 q/s ≈ 1 s d'attente au plus). `response_orphan_dropped` n'apparaît qu'à
**1600 `up`** (2 lignes rate-limitées, `suppressed=2 383`), en cohérence avec
`response_entry_ms` p99 = **5 477 ms** > `ipc.pending_ttl` 5 s ; `qdrop` et
`udrop` sont **0** partout ailleurs, et il n'y a **aucune** orpheline à
500-1300.

### 21.6 RSS et effet du GC

`gc_heap_guard` = **0** sur toute la campagne : le plafond `max_heap_mb` = 32
n'a jamais été atteint. RSS par worker (Kio, somme des 2 `resp-q*` puis des 2
`dns-q*`, avant / max pendant / après) :

| palier | resp avant | resp max | resp après | dns avant | dns max | dns après | tous max |
|---|---|---|---|---|---|---|---|
| 20 `mixed` | 20 064 | 24 264 | 24 264 | 23 376 | 23 952 | 23 952 | 147 912 |
| 200 `mixed` | 24 264 | 28 524 | 28 516 | 23 952 | 24 284 | 24 284 | 152 672 |
| 350 `mixed` | 28 524 | 31 540 | 31 544 | 24 288 | 24 324 | 24 324 | 155 804 |
| 500 `mixed` | 31 544 | 35 416 | 35 288 | 24 324 | 24 448 | 24 448 | 160 000 |
| 700 `mixed` | 35 288 | 39 584 | 39 456 | 24 448 | 24 492 | 24 492 | 164 400 |
| 800 `up` | 39 456 | 39 456 | 39 456 | 24 492 | 24 492 | 24 492 | 164 284 |
| 1000 `up` | 39 448 | 39 456 | 39 456 | 24 492 | 24 492 | 24 492 | 164 288 |
| 1300 `up` | 39 456 | 46 984 | 44 416 | 24 492 | 24 492 | 24 492 | 172 068 |
| 1600 `up` | 44 416 | 58 840 | 50 008 | 24 500 | 24 504 | 24 504 | 184 328 |

Lecture :

1. **Pas de gonflement anormal** : le RSS des `dns-q*` est plat (23,4 →
   24,5 Mio pour deux workers) et celui des `resp-q*` croît avec la charge
   (20 → 58,8 Mio pour deux workers au pic de 1600), puis redescend
   partiellement (50,0). `MemAvailable` reste ≥ 3 566 828 Kio (3,4 Gio) ; la machine n'est
   jamais sous pression mémoire.
2. **Comparaison à §17.3** (RSS de fin de fenêtre, `pause` 110 à l'époque) :
   à 200 `mixed` 36,1 Mio → **28,5** ici, à 350 36,1 → **31,5**, à 500 36,1
   → **35,3**, à 700 35,8 → **39,6**, à 800 `up` 35,8 → **39,5**, à 1000
   38,0 → **39,5**, à 1300 41,0 → **46,9 (max)**. Le RSS est donc **plus bas
   à faible charge et un peu plus haut au-delà de 700**, ce qui est le
   compromis attendu de `pause: 200` (tas +1,4 Mio/worker sur le micro-banc,
   §19.2) : le plancher monte, mais la croissance sous charge reste bornée.
   Ces chiffres mêlent le tas GC, la table `pending` (`pending_max` 20 000 ≈
   16 Mio/worker potentiels, §15.5) et l'historique des paliers — le RSS
   n'isole pas le GC (aucune variante `pause 110` n'a été déployée, la
   configuration n'était pas modifiable au-delà de `nfqueue`/`pending_max`).
3. **Marge du garde-fou** : au pic de 1600, `resp-q14` atteint **32 840 Kio
   de RSS** alors que le seuil du garde-fou est un **tas** de 32 Mio
   (`gc_heap_guard` n'a pas tiré). La marge est mince : c'est un point à
   surveiller avant de viser > 1 300 q/s (§21.7).

### 21.7 Recommandations chiffrées vers 1000 q/s

1. **Le plafond `mixed` est désormais le CPU agrégé, pas un réglage
   `nfqueue`** : à 500, `idle` 13,1 % ; à 700, 5,3 % avec `qdrop`=`udrop`=0.
   Pour tenir 1000 `mixed` avec la même marge, il faudrait gagner ~50 % de CPU
   par requête (700 → 1000 à idle constant). Les postes à viser, dans
   l'ordre mesuré : `dns` + `resp` (200 % cumulés à 700) puis **`nft` 46 %**
   — ce dernier est le seul poste qui a *augmenté* depuis §17 et mérite une
   mesure dédiée avant tout autre correctif.
2. **`up` tient 1000 q/s sans perte avec 15,4 % d'idle**, et 1300 avec 7,2 % :
   la cible 1000 q/s est déjà atteinte sur ce profil. La limite suivante est
   **1600**, où une file réponses déborde (`qdrop` 1 846, profondeur 4 036).
   Deux leviers chiffrés : (a) borner/équilibrer `jhash` (q14 25 218 contre
   q15 18 641 paquets, soit 57/43) ; (b) `maxlen` > 4096 échangerait du
   retard contre moins de jets, mais le CPU est déjà à 2,3 % d'idle — sans
   gain de débit.
3. **GC** : garder `pause 200`/`stepmul 400`/`max_heap_mb 32`. Aucun
   `gc_heap_guard`, RSS total ≤ 184 328 Kio (180 Mio) sur 4 Gio, `dns` plat. Si la cible
   doit dépasser 1300 `up`, remonter `max_heap_mb` (p. ex. 48) **ou** borner
   `ipc.pending_max` : `resp-q14` est à 32,8 Mio de RSS pour un seuil de tas
   de 32 Mio.
4. **`mixed` 700** : la perte (7,8 %) n'est **pas** expliquée par les
   compteurs custos (`qdrop`=`udrop`=0, aucune orpheline, `q_to_response_ms`
   p50 26 ms) ; le client a reçu 19 365 réponses sur 20 999 questions alors
   que 20 249 lignes `response_dns_benchmark` ont été émises dans la fenêtre.
   Une partie est le retard de la file questions (profondeur 576), le reste
   est à localiser (émission `raw_send`, pont, ou client). Avant d'annoncer
   500-700 comme plafond ferme, rejouer 600-700 (2-3 runs, comme §17.8).
5. **Ne rien changer aux défauts** : la configuration mesurée est celle du
   code (hors `responses: "14-15"`, sans effet) ; les gains viennent des
   branches, pas d'un réglage.

### 21.8 Vérifications finales, non fait, douteux

**Vérifications finales**

- **Configuration restaurée** : `cp /etc/custos/config.moon.dbench6
  /etc/custos/config.moon`, `rm` de la sauvegarde, `/etc/init.d/custos
  restart`, puis `grep -n -E "^[[:space:]]*(nfqueue|ipc|gc):"` :
  **ligne 2 = `nfqueue: { responses: "14-15" }`, aucune autre clé** ;
  `md5sum` de `config.moon` = `bddc79b591badfc94c17e9380759d8e0`, identique à
  la sauvegarde ; `.dbench6` absent ; `status` = `running`. Aucune clé n'a
  été modifiée pendant la campagne (la configuration était déjà la cible),
  la sauvegarde/restauration n'a donc servi qu'à garantir l'état initial.
- **Sonde DNS finale** (servus → 10.35.1.1) : `controlplane.tailscale.com A`
  → **8 adresses** (rc=0) ⇒ toujours authentifié ; sonde de transfert sur
  `vpn.stemarie.dynv6.net` : requête servie (rc=0, réponse NODATA — voir
  ci-dessous). Aucun générateur résiduel (`pgrep`), aucune IPv6 temporaire
  créée sur `servus` (`ip -6 addr show dev wan` : 2 adresses globales
  existantes + 1 lien-local, inchangées).
- `make all && make check && make test` : **3219 succès / 0 échec / 0 erreur /
  0 pending** (47,9 s, `tmp/test.log`) ; aucun `.lua` régénéré.

**Non fait / douteux**

- **Scénario « défauts » (B)** non rejoué (consigne) ; `d-valspread`,
  compteurs du cache d'upsert : mêmes limites qu'en §17.8.
- **Le nom du profil `up` n'a plus d'enregistrement A** : au moment de la
  campagne, `vpn.stemarie.dynv6.net` et `reseau.stemarie.dynv6.net` rendent
  `NOERROR` sans réponse en A (vérifié via `dns.google`, NS `ns3.dynv6.org`) ;
  `reseau` n'a qu'un AAAA. En §17.3 la réponse était un CNAME sans A
  (`reseau.stemarie.dynv6.net.`) : le profil `up` mesure donc toujours un
  **NODATA cacheable**, avec un enregistrement de moins qu'en §17 — la
  comparaison reste valable pour le chemin cache/NODATA, pas pour une réponse
  A complète.
- **Perte à 700 `mixed`** : non attribuée (voir §21.7 point 4) ; une seule
  mesure par palier, pas de répétition A/B.
- **`nft` CPU en hausse** (+8 à +11 points à faible charge) : non expliqué par
  cette campagne (aucune variante GC testée sur la cible, compteurs du cache
  invisibles au niveau INFO). À vérifier par une mesure dédiée avant de
  conclure à une régression.
- **Orphelines / retard** : seules les lignes rate-limitées sont visibles ;
  le partage exact entre réponse jamais délivrée et réponse tardive reste non
  instrumenté.
- **`events`/`mac-lrn` sous-estimés aux paliers saturés** : leurs tampons
  groupés (§20) ne sont vidés qu'en fin de lot, et une partie du traitement
  peut se produire pendant le drain, hors de la fenêtre CPU de 32 s (p. ex.
  `events` 8,5 % à 350 mais 3,4 % à 1300 `up`).
- Une seule source (servus), deux destinations IPv4, pas d'IPv6 temporaire ;
  `perf` absent de la cible ; aucune capture AF_PACKET.
- **Flottement de la suite de tests** : un run intermédiaire de `make test` a
  donné 3218 succès / **1 échec** sur `tests/unit/ipc/ipc_spec.moon:1024-1038`
  (mesure mémoire d'une entrée `pending` par `collectgarbage` : `per_entry`
  négatif). Le spec passe seul (63/0) et le run final
  `make all && make check && make test` redonne **3219 / 0** ; flottement
  préexistant, sans rapport avec la campagne (aucun code modifié).

## 22. Campagne « allocation par paquet » (2026-11-13, branche `d-alloc`)

Suite logique du §18.6 : le GC reste le premier poste résiduel (29-47 % des
échantillons, §18.3) parce que le hot path alloue ~6,6 Ko/question,
~11,2 Ko/réponse et ~32,9 Ko/cycle second avis (§18.2). Objectif : réduire
l'allocation par paquet, hors sous-module ipparse. Tout a été fait **en
local** : aucun accès réseau, aucun déploiement. Rapport complet (mesures
brutes, scripts, échecs) : **`tmp/d_alloc_report.md`** ; artefacts dans
`tmp/alloc/`.

### 22.1 Méthode

- **Répartition par sous-chemin** avant de toucher au code : script
  `tmp/alloc/split.lua` qui rejoue les six cas du banc (`setup`/
  `build_cases` récupérés par `debug.getupvalue` sur `hotpath.main`) avec
  des wrappers d'allocation autour des fonctions des modules appelés par
  les workers — chaque wrapper mesure `collectgarbage "count"` avant/après
  (GC arrêté), en distinguant inclusif/ exclusif (sous-wrappers déduits).
  Postes instrumentés : `parse_dns_packet`, `encode_msg`/`write_msg`,
  `drain_pipe`, `set_pending`, `enqueue` (build_line), `parse_answers`,
  `patch_modified_dns`/`strip_*`, `inject`, `decide_meta`/
  `run_on_response`, `classify`, `user_for_mac`, `log_*`.
- **A/B alterné dans la même fenêtre** par correctif : `make bench-hotpath
  HP_REPEAT=5` (minimum de lot retenu, métrique stable — §18.1), état A
  (`git stash`) puis B, deux couples par correctif ; témoins = les cas non
  visés du même run.
- **TDD** : pour chaque correctif, un test d'allocation GC arrêté dans le
  spec du fichier modifié, seuil calibré entre la mesure avant/après
  (constaté en échec avant correctif, en succès après).
- Pièges de mesure constatés : **LuaJIT interne les strings identiques**
  (mesure à 0 pour des inputs constants) ; le JIT **élimine les appels dont
  le résultat est ignoré** (il faut un sink) ; `luassert.is_true` alloue
  (+1 100 o/ligne mesuré dans une boucle).

### 22.2 Répartition initiale (o/itér, GC arrêté)

| cas | total | postes principaux (hors périmètre entre parenthèses) |
|---|---|---|
| `question` | 6 664 | (parse_dns_packet 2048), (dup_query.build_udp 1536), (decide_meta 536), write_msg 328, reste 2216 (write_event) |
| `ipc_drain` | 1 884 | drain_pipe 1624 (read+decode+set_pending) |
| `response` | 10 883 | (parse_dns_packet 2632), **enqueue 1091**, **patch_modified_dns 1040**, set_pending 632, **parse_answers 536**, (run_on_response 456), reste 3998 |
| `so_a` | 8 994 | (parse_dns_packet 6600) |
| `so_cycle` | 30 544 | (parse_dns_packet 9232), **enqueue 8714 (16 lignes)**, **parse_answers 3720**, patch_modified_dns 1088 |

Hors périmètre : sous-module ipparse (`parse_dns_packet`/`parse_rr`/`labels`),
filtre (`decide_meta`/`run_on_response`, sémantique de filtrage), `write_event`
et l'envoi d'événements (autre agent), `dup_query.build_udp` (fichier non
nommé), `set_pending` (table d'entrée nécessaire + log `ipc_pending_overwrite`
dominant dans le banc — artefact du txid fixe).

### 22.3 Correctifs retenus (un commit par optimisation)

| # | Correctif | Cas visé | Gain (A/B alterné) | Commit |
|---|---|---|---|---|
| 1 | `nft_queue.build_line` en concaténation directe (supprime la table de 9 champs + la double copie `.. "\n"` par ligne) | `so_cycle` (16 lignes) | alloc 30601 → 28297 (**−7,5 %**), temps total 9,06 → 8,48 s (−6,5 %) ; `response` −2,6 % ; test 372 → 225 o/ligne | `21a7acf` |
| 2 | `parse_answers` réduit aux 3 champs lus (`rtype`, `rdata_str`, `ttl`) par `finalize_a` | `so_cycle` | alloc 28297 → 25993 (**−8,1 %**), lot-min 37,9 → 35,0 µs (**−7,5 %**) ; test 3723 → 1419 o/appel (8 RR) | `0674b10` |
| 3 | `dns_ede.strip_rrtypes` : `u16_at`/`skip_name_at`/`copy_section` en fonctions de module (params explicites) + sets précalculés `A_SET`/`AAAA_SET`/`HTTPS_SVCB_SET` | `response` | alloc 10359 → 9623 (**−7,1 %**), lot-min 24,7 → 20,8 µs (**−16 %**) ; test `strip_https_rr` 1040 → 304 o/appel | `5ec6028` |
| 4 | `finalize_a` sans closures lourdes : `client_addr_of`/`inject_answers`/`patch_and_accept` en fonctions de module + `ADD_IP`/`ADD_MAC` précalculés | `response` | alloc 9623 → 8503 (**−11,6 %**), lot-min 21,6 → 20,7 µs ; test 3897 → 3277 o/appel | `d44a9c6` |
| 5 | `ipc.encode_msg` en concaténation directe (14 champs) + `response_ids` sans tableau vide + `write_with_retry` avec timespec module-level | `question` | alloc 6664 → 6448 (−3,2 %), **lot-min 25,3 → 23,5 µs (−7,1 %)** ; poste isolé 757 → 340 o/appel ; test seuil 550 | `549560f` |
| 6 | `strip_rrtypes` : tables `question_parts`/`sec` en scratch module-level | `response` | **lot-min 21,15 → 19,9 µs (−5,9 %)**, total −4,7 %, alloc −3,6 % (8481 → 8177) ; test 305 → 0 o/appel | `55bd240` |

Chaque commit porte son avant/après ; `make check && make test` vert à chaque
étape (référence de campagne : 3180 → **3185 succès / 0 échec**),
`make test-e2e` : **94 passed / 0 failed**.

### 22.4 Bilan global (mêmes runs, HP_REPEAT=5)

| cas | alloc avant | alloc après | Δ | lot-min avant | lot-min après |
|---|---|---|---|---|---|
| `response` | 10 935 | **8 201** | **−24,8 %** | 22,5 µs | 19,6 µs |
| `so_cycle` | 30 601 | **23 785** | **−22,3 %** | 37,9 µs | 31,3 µs |
| `question` | 6 624 | 6 448 | −2,7 % | 24,9 µs | 21,6 µs |
| `so_a` (témoin) | 8 994 | 8 994 | 0 | 25,0 µs | 20,6 µs |
| `ipc_drain` (témoin) | 1 906 | 1 906 | 0 | 3,7 µs | 3,9 µs |
| `setup_control` (témoin) | 890 | 890 | 0 | 0,5 µs | 0,5 µs |

Les témoins d'allocation sont strictement stables ; les écarts de temps des
témoins (`so_a` 25,0 → 20,6 µs) reflètent la charge de la machine partagée
entre les deux runs, pas un effet des correctifs.

### 22.5 Non fait / constaté sous le seuil

- **Tables `answers`/`qnames`/`txid_hex` paresseux dans `finalize_a`**
  (reverté) : −3,3 % sur `response` et −1,4 % sur `so_cycle` en allocation
  (−3 % en temps), **sous le seuil de 5 %** — la version revertée reste dans
  `tmp/alloc/`. Le test `finalize_a` garde son seuil de campagne (3550 o,
  mesure initiale 3897).
- **`drain_pipe` fast-path `state == ""`** (reverté) : gain nul mesuré —
  LuaJIT optimise déjà `"" .. s`.
- **`make_key`/`string.format`** : 4,1 % d'échantillons dans le profil mais
  le remplacement par concatène ne gagne que 0,015 µs/appel (le poste est
  dominé par le log `ipc_pending_overwrite`, artefact du banc).
- **`ctx` de `handle_response`** (~23 clés hash ≈ 1 Ko) : non réductible
  sans toucher à `format_block_event` (envoi d'événements, hors périmètre) —
  les champs `qname`/`vlan`/`af` y sont lus.
- **`decode_msg`/`split_fields`** (14 sous-strings) : non refondu — le
  format de message est un contrat (`worker_nft.parse_line`, §18.5) et le
  refactoring ne montre pas ≥ 5 %.
- **`set_pending`** (632 o dans le banc) : dominé par le log INFO
  `ipc_pending_overwrite` émis à chaque écrasement — comportement de log
  inchangé, et dans la production l'écrasement est rare (le banc réutilise
  le même txid à chaque itération).
- Résiduel hors périmètre toujours dominant : `parse_dns_packet`/`parse_rr`
  (ipparse, 2048-9232 o selon le cas), `decide_meta`/`run_on_response`
  (filtre), `build_udp` (dup_query), `write_event`.

## 24. Régression CPU du worker nft après d-gctune : pas de GC par lot (2026-11-13, branche `d-nftcpu`)

La campagne §21 a mesuré une **hausse du CPU du worker `nft`** en profil
`mixed` : 18,0 % → 29,3 % à 200 q/s, 34,5 % → 43,0 % à 350, 38,5 % → 46,1 % à
500 (§21.2), alors que `dns` et `resp` baissaient de 8 à 40 %. Le nombre
d'upserts par question n'avait pas changé. Aucune mesure n'isolait le worker
nft : cette section construit ce banc, isole la cause et la corrige.

### 24.1 Cause mesurée : `gc.idle!` à chaque tour de boucle

`src/lib/gc_tune.moon` (`d-gctune`) a ajouté trois appels par worker :
`apply!` au démarrage, `guard!` à chaque tour et `idle!` sur temps mort.
`worker_nft` était le seul worker à appeler `gc.idle!` **après chaque lot** :

- avant correctif (`src/worker_nft.moon:491` de `dev` avant ce commit) :
  `gc.idle! unless batch_full`, en fin de boucle ;
- or cette boucle faisait `libc.poll poll_fd, 1, -1` (blocage infini) : il
  n'existe **aucun tour à vide**. Chaque tour suit l'arrivée de données, draine
  le tube et flushe — `gc.idle!` s'exécutait donc après **chaque batch**, soit
  une fois par réponse porteuse d'insertions, et non « sur temps mort ».
- `gc.idle!` fait `collectgarbage "step", 100` (`src/lib/gc_tune.moon:95-98`).
  Avec le tas du worker (`pause 200`, plusieurs Mio de cache/pending), ce pas
  coûte **~366 à 569 µs de CPU** par tour au lieu de zéro.

Les autres boucles ne font pas cette erreur : `nfq_loop` (`src/nfq_loop.moon:264-268`)
et `worker_events` (`src/worker_events.moon:378-422`) ne font un pas de GC que
lorsque `poll` a **expiré** (`pr == 0`) ; `mac_learner` idem avec son timeout
long (`src/mac_learner.moon:455-467`).

### 24.2 Banc dédié (`make bench-nftcpu`, `src/bench/nft_cpu.moon`)

Boucle `worker_nft.run` **réelle** dans un enfant `fork`, tube réel non
bloquant, `nft.run_cmd` remplacé par un stub (`true`, aucune transaction
libnftables : ce coût est identique entre les versions comparées). Les lignes
sont produites par `nft_queue.build_line` — profil de §21 : client authentifié
unique, 8 enregistrements A, donc 16 lignes par réponse (`ip4` + `mac4` par
adresse, `response_inject.inject`), `rule_id` `r_utilisateurs`, timeout
`rr_timeout(60)` = `660s`, corrélateur de 16 octets distinct par réponse. CPU
lu dans `/proc/<pid>/stat` (utime+stime, HZ 100) sur trois fenêtres : charge,
temps mort (`poll` bloqué), total.

Le nombre de **tours** est piloté par `--turns` (réponses par écriture) à débit
de lignes constant : `turns=1` = un tour par réponse (production), `turns=8` =
un tour pour huit. La différence de CPU/s entre les deux donne le coût d'un
tour, sans modifier le code mesuré :

`CPU/s = a·lignes/s + b·tours/s` ⇒ `b = ΔCPU/s / Δtours/s`.

Protocole : 500 réponses/s × 16 lignes = 8 000 lignes/s, 8 s de charge + 1 s de
temps mort, 5 passages, **médiane** (la dispersion vient de la phase du GC, pas
d'interférence externe : le minimum d'un petit nombre de passages est biaisé).
Comparaisons : `ecdf4ab` (référence `d-bench5`, `pause 110`, aucun appel GC dans
la boucle), `dev` avant correctif, `dev` après, et `dev --gc-idle-step 0`
(neutralisation du seul pas de GC sur temps mort, sans toucher au code).

### 24.3 Résultats

| variante | tours | µs CPU/ligne (médiane) | CPU charge % | µs CPU/tour (dérivé) | octets/ligne (GC arrêté) |
|---|---|---|---|---|---|
| `ecdf4ab` (réf. d-bench5, pause 110, sans `gc.idle`) | 1 | 32,2 | 25,7 | −43 (bruit) | 448,9 |
| `ecdf4ab` | 8 | 34,5 | 27,6 | — | 448,9 |
| `dev` **avant** correctif (pause 200 + `gc.idle` par lot) | 1 | **50,3** | **40,2** | **569** | 248,9 |
| `dev` **avant** correctif | 8 | 19,2 | 15,4 | — | 248,9 |
| `dev` **après** correctif (pause 200, pas sur timeout seul) | 1 | **19,5** | **15,6** | 43 (bruit) | 248,9 |
| `dev` **après** correctif | 8 | 17,2 | 13,7 | — | 248,9 |
| `dev` après, `--gc-idle-step 0` | 1 | 19,1 | 15,2 | 43 (bruit) | 248,9 |
| `dev` après, `--gc-idle-step 0` | 8 | 16,7 | 13,4 | — | 248,9 |

Lecture :

1. **La cause est le pas de GC par tour**, pas `pause`/`stepmul` : avant
   correctif, `turns=1` coûte 569 µs/tour de plus que `turns=8` (50,3 vs
   19,2 µs/ligne) ; après correctif, l'écart tombe à 43 µs/tour, dans le bruit.
   Neutraliser `idle_step` (`--gc-idle-step 0`) sur le code corrigé ne change
   rien (19,1 vs 19,5 µs/ligne) : il ne reste plus de pas par lot.
2. **`pause 200` n'est pas en cause** : à charge égale et sans pas par tour
   (`--gc-pause 110 --gc-idle-step 0`), le coût est de 20,4-28,7 µs/ligne
   contre 19,5 à `pause 200` (mesure de mise au point, 3 s × 2 passages) ; et
   la référence `ecdf4ab` en `pause 110` est plus chère (32,2) que `dev`
   corrigé en `pause 200` (19,5).
3. **Le garde-fou est gratuit** : `guard!` à chaque tour (une comparaison
   d'horloge) est dans le bruit ; le désactiver (`--gc-max-heap 0`) ne change
   pas les chiffres (16,2-19,0 vs 19,2-20,0 µs/ligne, mesure de mise au point).
4. **Le parse s'est amélioré entre-temps** : `dev` corrigé est à 19,5 µs/ligne
   contre 32,2 pour `ecdf4ab` (−39 %) et à 248,9 octets/ligne contre 448,9
   (−45 %), grâce à `from_hex` par table de nibbles (`d-prof`/`d-alloc`).
   `nft_queue.build_line` (concaténation directe, `d-alloc`) n'apparaît pas ici :
   il est côté producteur, hors du processus mesuré.
5. **Temps mort** : 0,0 % de CPU dans toutes les variantes — `poll` bloque
   réellement quand le tube est vide (aucun tour à vide avant comme après).

### 24.4 Correctif

`src/worker_nft.moon` : `poll` reçoit un timeout borné
`POLL_IDLE_MS = 1000` (retour immédiat dès qu'une ligne arrive : la latence
n'est pas affectée, seule une expiration signifie « temps mort »), et le pas de
GC n'est fait que si `poll` a expiré sans donnée
(`idle_after_poll pr`, `pr == 0`), comme `nfq_loop`/`worker_events`. Le
garde-fou `guard!` reste à chaque tour, et `pause 200`/`stepmul 400` sont
inchangés : l'objet de `d-gctune` (pas de GC borné sur temps mort, garde-fou
mémoire) est conservé, sans le pas par lot.

Tests : `tests/unit/worker_nft_spec.moon` couvre la décision
(`idle_after_poll` 0/1/−1), l'absence de pas après un lot traité (le test
échoue sur le code d'avant correctif : `1` au lieu de `0`) et le pas effectif
quand `poll` expire (`gc` injecté, `poll_idle_ms` de test) ;
`tests/unit/bench/nft_cpu_spec.moon` couvre le banc (format de ligne identique à
`nft_queue.build_line`, 16 lignes/réponse, alternance `ip4`/`mac4`, CLI).

### 24.5 Gain attendu sur la cible et limites

Sur le banc (x86_64, `nft` stubbé), le correctif ramène le coût worker nft de
50,3 à 19,5 µs/ligne au tour par réponse, soit **−61 %** ; le pas supprimé vaut
**~0,37 à 0,57 ms par batch**. Sur `custos.lan`, la régression mesurée est de
+8 à +11 points de CPU (§21.4) : elle est entièrement imputable à ce pas, qui
s'exécutait une fois par réponse porteuse d'insertions (~200-350 tours/s à
200-500 q/s `mixed`). Le gain attendu est donc la **récupération des ~8-11
points** (retour au niveau `d-bench5`, voire en dessous grâce au parse plus
rapide), et ~10-15 points de marge à 700 q/s où le CPU total sature (§21.5).

**Non fait / limites** :

- Aucune campagne de charge sur `custos.lan` : elle était en cours (consigne),
  et `make test-e2e` n'a pas été lancé (homelab occupé). Le chiffre cible
  ci-dessus est une **extrapolation** à partir du coût par tour mesuré
  localement, pas une mesure sur la cible.
- Banc x86_64 : les µs absolues ne sont pas transposables à l'aarch64 A55 ; le
  rapport entre « avec » et « sans » pas de GC l'est.
- `nft.run_cmd` est stubbé : le coût libnftables (dominant quand les insertions
  ne sont pas sautées par le cache) est exclu du banc. Il est identique entre
  les versions comparées, donc neutre pour la régression, mais le CPU absolu du
  worker en production reste supérieur aux chiffres du tableau.
- Charge synthétique : toutes les réponses portent 16 lignes (profil
  authentifié 8 A). En `mixed` réel, une partie des réponses n'insère rien (NXDOMAIN,
  NODATA) et le cache d'upsert saute des réinsertions : le nombre de tours
  utiles est plus faible, ce qui explique que la régression observée
  (+8-11 points) soit inférieure aux 25 points du cas synthétique.
