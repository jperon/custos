# Configuration de CustosVirginum

Ce document décrit en détail toutes les clés de configuration disponibles dans
`/etc/custos/config.moon` (ou `cfg/config.moon` en développement).

Voir `cfg/config.moon` pour un exemple complet annoté.

---

## Sommaire

1. [Chargement de la configuration](#1-chargement-de-la-configuration)
2. [Section `runtime`](#2-section-runtime)
3. [Section `nfqueue`](#3-section-nfqueue)
4. [Section `dns`](#4-section-dns)
5. [Section `nft`](#5-section-nft)
6. [Section `ipc`](#6-section-ipc)
7. [Section `clients`](#7-section-clients)
8. [Section `mac_learner`](#8-section-mac_learner)
9. [Section `auth`](#9-section-auth)
10. [Section `doh`](#10-section-doh)
11. [Section `events`](#11-section-events)
12. [Section `metrics`](#12-section-metrics)
13. [Section `rtp`](#13-section-rtp)
14. [Section `filter`](#14-section-filter) ← section principale
    - [Répertoires de listes](#141-répertoires-de-listes)
    - [Dictionnaires nommés](#142-dictionnaires-nommés-nets-macs-times-vlans-users)
    - [Sources de listes de domaines](#143-sources-de-listes-de-domaines-filtersources)
    - [Règles de filtrage](#144-règles-de-filtrage-filterrules)
    - [Logique de décision](#145-logique-de-décision-filterdecision)
15. [Référence des conditions](#15-référence-des-conditions)
16. [Référence des actions](#16-référence-des-actions)

---

## 1. Chargement de la configuration

Le fichier de configuration est un script MoonScript qui retourne une table Lua.
Il est fusionné avec les valeurs par défaut de `src/config.moon` : seules les
clés présentes dans le fichier utilisateur surchargent les défauts ; les clés
absentes conservent leur valeur par défaut.

**Emplacement par défaut :** `/etc/custos/config.moon`

**Variables d'environnement :**

| Variable | Effet |
|----------|-------|
| `CUSTOS_CONFIG_PATH` | Chemin alternatif vers le fichier de config |
| `CUSTOS_REQUIRE_EXTERNAL_CONFIG` | `1`/`true` → erreur fatale si le fichier ne se charge pas |

**Format minimal :**

```moonscript
{
  filter: {
    rules: {
      { actions: {"allow"} }
    }
  }
}
```

---

## 2. Section `runtime`

Contrôle le comportement global du service.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `log_level` | string | `"INFO"` | Niveau de log : `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `benchmark` | bool | `false` | Active les mesures de performance dans les logs |
| `gc_pause` | number | `110` | Réglage GC LuaJIT (`collectgarbage "setpause"`). Le GC se déclenche dès que le tas dépasse de `gc_pause`-100 % la taille post-collecte. Défaut LuaJIT : 200 (le tas peut doubler). 110 ⇒ collecte dès +10 %, plus économe en RAM. |
| `gc_stepmul` | number | `400` | Réglage GC LuaJIT (`collectgarbage "setstepmul"`). Multiplicateur de la vitesse du GC incrémental ; une valeur plus haute compense le `gc_pause` bas. |
| `pid_file` | string | `"/var/run/custos.pid"` | Pidfile du superviseur (PID qui traite SIGHUP pour le hot-reload). Écrit au démarrage, supprimé à l'arrêt. Lu par la webui (« Recharger maintenant ») et `custos-update`. Surchargeable aussi via l'env `CUSTOS_PID_FILE`. |

Quand `benchmark` est activé, le verdict `ALLOW`/`BLOCK` est journalisé **dans la
même ligne** que les temps de mesure, émise par le worker responses au retour de
la réponse DNS (avec `action=response_dns_benchmark`). Le worker DNS (questions)
**supprime** alors sa propre ligne `ALLOW`/`BLOCK` pour éviter la duplication ;
les métriques (`metrics.record_verdict`) restent inchangées. La ligne porte les
champs de décision habituels (`qname`, `qtype`, `mac_src`, `vlan`, `src_ip`,
`dst_ip`, `rule`, `reason`, `user`, `af`) plus les temps. `action=response_dns_benchmark`
est **jamais limitée** (règle `dns_benchmark` de `RL_NEVER_LIMIT`, comme
`worker_died`) : une option d'instrumentation ne doit pas être rendue muette
par le limiteur. Sur un banc à qname fixe, la règle `ALLOW`/`BLOCK` aurait
fusionné tous les échantillons d'un même triplet `mac_src`/`qname`/`qtype`
pendant 30 s et perdu les mesures (`q_to_response_ms`, `drain_ms`, `parse_ms`,
`match_ms`…) des échantillons supprimés — c'est-à-dire l'objet même de
l'option. Aucune autre action de banc/instrumentation n'est émise (seul
`dns_benchmark` est concerné).

`q_to_response_ms` mesure la latence **totale**, de l'entrée de la question dans
le worker DNS jusqu'au log de la réponse correspondante côté worker responses,
traitement Custos inclus. Elle se décompose en trois étages :

- `question_proc_ms` : traitement interne du worker DNS (parse L2/L3/L4/L7,
  décision, écriture IPC), de l'entrée de la question à sa sortie.
- `response_entry_ms` : de la sortie de la question (worker DNS) à l'arrivée de
  la réponse dans le worker responses. Inclut le résolveur amont, le réseau,
  les retransmissions et les files NFQUEUE — c'est généralement le poste
  dominant et il est **hors** Custos.
- jalons locaux côté worker responses : `drain_ms`, `payload_ms`, `parse_ms`,
  `match_ms`, `log_ms`.

Deux mesures supplémentaires sont exprimées en **microsecondes entières**
(`tv_sec*1e6 + tv_nsec/1000`) : le plancher de 1 ms des jalons ci-dessus
masquerait une attente habituellement sous la milliseconde, et c'est la queue de
distribution qui importe. Ce sont des mesures **parallèles, NON additives** :

- `ack_wait_us` — durée du dernier appel à `nft_queue.wait_ack` terminé sur ce
  worker, c'est-à-dire l'attente de l'ACK nftables du batch d'injection (budget
  `nft.ack_timeout_ms`, défaut 150 ms, découpé en polls de 5 ms pendant lesquels
  le pipe IPC question→réponse est drainé). **L'ACK intervient APRÈS l'émission
  de cette ligne et APRÈS `set_verdict`** : il est donc **hors** de la chaîne
  additive ci-dessus. Sur une ligne donnée la valeur provient du `wait_ack` de
  la transaction **précédente** (elle est consommée une seule fois) ; elle vaut
  `0` si aucun `wait_ack` n'a eu lieu depuis la ligne précédente. **Ne jamais
  l'ajouter à `q_to_response_ms`** : cela casserait l'invariant à résidu nul.
- `log_write_us` — durée du `libc.write` du journal (stdout → logd), mesurée
  par `log.moon` quand `runtime.benchmark` est actif (`log.set_timing true`,
  posé une fois par `main.moon` avant les forks). La ligne courante ne peut pas
  porter sa propre durée : le champ contient le dernier `write` **terminé**
  avant la construction de la ligne (en régime benchmark sans autres logs,
  c'est la ligne benchmark précédente). Vaut `0` si l'instrumentation est
  désactivée ou avant la première écriture.

Coût en mode nominal (`benchmark: false`) : **exactement nul**. `log.moon`
n'ajoute aucun `clock_gettime` autour des `write` (seule l'horloge de l'epoch,
préexistante, reste appelée) et `worker_responses` n'appelle pas l'horloge
autour de `wait_ack`. En mode benchmark, ces deux mesures ajoutent au plus
quelques appels `clock_gettime` par transaction ; l'écriture de log reste, elle,
sur le même `libc.write` bloquant qu'auparavant.

Deux compteurs de retry **distincts** figurent dans la ligne, et ne mesurent pas
la même chose :

- `ipc_retry_attempts` / `ipc_retry_wait_ms` : retry d'**appariement IPC**
  (réponse arrivée avant que la question correspondante ne soit lue du pipe
  `question_response` ; cf. `ipc.match_retry`). `ipc_retry_wait_ms` est le temps
  cumulé réellement dormi. Vaut `0` / `0` quand l'appariement a réussi du premier
  coup — c'est le cas très majoritaire.
- `upstream_retries` : nombre de renvois de la requête vers le **résolveur amont**
  effectués pour cette transaction (`dns.upstream_retry`, `entry.upstream_retries`),
  c'est-à-dire le nombre de réponses transitoirement en échec (SERVFAIL/REFUSED/
  NXDOMAIN selon `rcodes`) qui ont été remplacées par un nouvel essai vers le
  même résolveur au lieu d'être transmises au client. Vaut `0` quand aucun retry
  upstream n'a eu lieu (cas majoritaire). **Seul un compteur existe** : aucune
  durée d'attente upstream n'est stockée, donc aucune n'est journalisée.

> Ces deux champs portaient auparavant les noms nus `retry_attempts` et
> `retry_wait_ms`, qui laissaient croire à une mesure du retry upstream alors
> qu'ils ne décrivaient que le retry d'appariement IPC (et valaient donc `0` dans
> la quasi-totalité des lignes). Les lignes `action=response_matched_after_retry`
> et `action=response_no_matching_question[_after_retry]` utilisent les mêmes
> noms `ipc_retry_attempts` / `ipc_retry_wait_ms`.

On a donc `q_to_response_ms ≈ question_proc_ms + response_entry_ms + (drain_ms +
payload_ms + parse_ms + match_ms + log_ms)`. `ipc_retry_wait_ms` détaille une
composante de `match_ms` (le jalon de fin `match_ms` est pris après la boucle de
retry IPC), il ne s'y ajoute pas. `ack_wait_us` et `log_write_us` sont des
mesures **parallèles** : elles ne figurent dans aucune de ces sommes.

Quand `benchmark` est désactivé (défaut), le verdict `ALLOW`/`BLOCK` est journalisé
côté worker DNS comme auparavant, sans temps.

### Rate-limiting des logs

`src/log.moon` limite les messages répétitifs. Une empreinte est calculée à
partir du **niveau**, de l'**action complète** (préfixe worker compris) et des
**champs d'identité présents** du message. Les messages de même empreinte sont
supprimés pendant la fenêtre ; le premier message émis après la fenêtre porte
`suppressed=N` (N = nombre de messages supprimés depuis). Un message qui diffère
par un champ d'identité n'est jamais fusionné avec un autre.

Résolution de la règle : action complète dans `RL_CONFIG`, puis action sans le
préfixe du worker (`response_no_ipv6_for_client` → `no_ipv6_for_client`), puis
règle par défaut **du niveau**, qui s'applique même quand `action` est présent.

| Niveau | Fenêtre | Champs discriminants |
|--------|---------|----------------------|
| `ERROR`, `CRIT`, `ALERT`, `EMERG` | 10 s | champs d'identité |
| `WARN`, `INFO`, `NOTICE` | 60 s | champs d'identité |
| `DEBUG`, `TRACE` | 30 s | champs d'identité |
| `ALLOW`, `BLOCK` | 30 s | `mac_src`, `qname`, `qtype` |
| `dns_benchmark` (préfixé ou non) | jamais | — (instrumentation) |
| `log_rl_mmap_failed`, `log_rl_saturated` | jamais | — (diagnostic du limiteur) |
| `captive_redirect` | 60 s | `ip` |
| `no_ipv6_for_client`, `no_ipv4_for_client` (préfixés ou non) | 120 s | `client` |
| `response_dnsonly` | 30 s | `dst_ip`, `qnames` |

Champs d'identité par défaut : `peer`, `peer_ip`, `peer_mac`, `ip`, `ip_src`,
`ip_dst`, `client`, `client_ip`, `client_mac`, `mac`, `mac_src`, `src_ip`,
`dst_ip`, `qname`, `qnames`, `domain`, `qtype`, `hostname`, `host`, `sni`,
`cert`, `key`, `path`, `method`, `url`, `file`, `ifname`, `name`, `queue`,
`worker`, `user`, `username`, `vlan`, `resolver`, `resolver_ip`, `upstream_ip`,
`addr`, `protocol`, `l4_proto`, `rcode`, `errno`, `source`, `direction`,
`version`, `verdict`, `backend`, `type`, `cn`, `local_ip`, `rule`, `list`,
`err`, `reason`, `cmd`.
Les champs volatils (`pid`, `txid`, ports, durées, compteurs, tailles) en sont
exclus : deux lignes qui n'en diffèrent que par eux fusionnent.

Exclusions réfléchies (volontairement hors empreinte) : `status` (sémantique
mixte — code de sortie de commande ou couche de parsing — donc volatil),
`mode` (constante de configuration : ne varie pas entre deux lignes d'un même
processus), `detail` (texte libre explicatif ; l'`action` et `reason` portent
la discrimination), `af`/`family` (redondants avec `src_ip`/`dst_ip`).

**Saturation et repli.** Chaque slot stocke `{hash, ts, expires, count}` (4
`uint32`, en-tête de 2 mots pour la main d'horloge et le compteur de
saturation ; 64 Kio au total). Un slot n'est recyclé pour une autre empreinte
que si **sa propre** échéance (`expires = ts + fenêtre de sa règle`) est
passée : une entrée encore dans sa fenêtre n'est jamais supprimée, même sous
saturation. Quand le sondage (8 pas) est épuisé, une main d'horloge balaie
32 slots supplémentaires à la recherche d'une entrée expirée ; si elle n'en
trouve pas, la ligne est journalisée **sans rate-limiting** et le compteur
`rl_stats().saturated` est incrémenté (avertissement `log_rl_saturated` une
fois par processus, émis hors du chemin limité). Une horloge en marche
arrière (pas de RTC, step NTP : `epoch < ts`) est traitée comme une entrée
expirée, sinon rien ne serait plus jamais recyclé.

Si `mmap` échoue, le limiteur retombe sur une table Lua par processus (plafonnée
à `RL_SLOTS`, purge des entrées expirées puis vidage en dernier recours) et
émet une fois par processus `action=log_rl_mmap_failed reason=… arch=…`. Le
mode est observable via `log.rl_shared()` et `log.rl_stats()`.

La valeur de `MAP_ANONYMOUS` est choisie à l'exécution depuis `jit.arch` :
`0x800` sur MIPS (où `0x20` est `MAP_RENAME`), `0x20` ailleurs ; `MAP_SHARED`
(`0x01`) est commun à toutes les architectures Linux.

Actions de cycle de vie **jamais** limitées : `worker_died`, `child_crashed`,
`worker_started`, `worker_stopping`, `worker_start`, `supervisor_running`,
`supervisor_sigterm`, `supervisor_sighup_*`, `dns-filter_start`, `config_source`,
`config_external_missing` (un crash ou un rechargement répété doit rester
visible). La comparaison se fait aussi après retrait du préfixe worker.

L'état est une table de hachage à taille fixe (4096 slots × 3 `uint32`, 48 Kio)
dans une zone `mmap(MAP_SHARED|MAP_ANONYMOUS)` créée au chargement du module,
donc dans le superviseur **avant tout fork** : workers et enfants forkés par
connexion partagent le même état. Sans verrou, une course bénigne peut produire
une ligne en double ou un compteur légèrement faux. Une empreinte différente
tombant dans le même slot sonde le suivant (jusqu'à 8) ; table saturée ou
collision non résolue → le message est journalisé (jamais supprimé à tort). Si
`mmap` échoue, repli sur une table Lua par processus, plafonnée à 4096 entrées.
Le filtrage `runtime.log_level` reste appliqué **avant** tout calcul d'empreinte.

```moonscript
runtime: {
  log_level: "DEBUG"
  benchmark: false
  gc_pause: 110      -- machines à faible RAM (128 Mo) ; 200 = défaut LuaJIT
  gc_stepmul: 400
  lowmem: "auto"            -- "auto" (défaut) | true/"on" | false/"off"
  lowmem_threshold_kb: 131072  -- seuil d'autodétection (128 Mo)
}
```

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `lowmem` | bool/string | `"auto"` | Mode RAM faible. `"auto"` : autodétection selon `MemTotal`. `true`/`"on"` : forcé. `false`/`"off"` : désactivé. |
| `lowmem_threshold_kb` | integer | `131072` | Seuil (kB) sous lequel l'autodétection active le mode RAM faible. |

> **Mode RAM faible (`runtime.lowmem`).** Quand il est actif, custos ramène
> automatiquement chaque plage `nfqueue` (`questions`, `responses`, `captive`,
> `reject`) à une **seule** file — donc un seul worker forké par règle — afin de
> minimiser l'empreinte mémoire (cf. [section `nfqueue`](#3-section-nfqueue)).
> Par défaut (`"auto"`), il s'active si `MemTotal < 128 Mo` (`lowmem_threshold_kb`).
> Ce seuil de 128 Mo est aligné sur l'autodétection de profil de listes par
> `custos-update` (`full`/`lowmem`).

> **RAM faible (≈128 Mo).** Les listes de domaines au format `.bin` sont mappées
> en lecture seule partagée (`mmap` `MAP_SHARED`) : leurs pages ne sont jamais
> recopiées, ni au chargement ni entre les workers forkés. Privilégier le format
> `.bin` (produit par l'updater) plutôt que `.domains` (texte), qui doit être
> haché/trié en mémoire à chaque démarrage. Stocker les listes en tmpfs (`/tmp`)
> reste sans surcoût : la donnée mappée *est* la page tmpfs (une seule copie).
>
> L'essentiel de la RAM consommée par custos vient du **nombre de processus
> workers**, pas des listes. Pour alléger une installation contrainte :
> - **Se passer de DoH** : laisser `doh.enabled = false` (cf. [section `doh`](#10-section-doh))
>   supprime le worker `doh`.
> - **Se passer du verdict SNI/TLS** : ne pas définir `nfqueue.sni` (ou
>   laisser la queue inutilisée) évite le worker `tls`. Le filtrage DNS reste
>   pleinement fonctionnel sans lui — on perd seulement le contrôle/journal SNI
>   sur le port 443.
> - **Réduire le parallélisme** : ramener chaque plage `nfqueue` à une seule
>   queue (cf. [section `nfqueue`](#3-section-nfqueue)). Le mode
>   [`runtime.lowmem`](#2-section-runtime) le fait automatiquement sous 128 Mo.
>
> Hormis la réduction des files par le mode `runtime.lowmem`, ces réglages
> relèvent du déploiement (config) : custos n'adapte rien d'autre automatiquement
> selon la RAM disponible.

---

## 3. Section `nfqueue`

Définit les numéros (ou plages) des files NFQUEUE utilisées par les workers.
Chaque entrée correspond à un worker distinct qui lit depuis le noyau Linux.

| Clé | Type | Défaut | Worker |
|-----|------|--------|--------|
| `questions` | string | `"0-1"` | Questions DNS entrantes |
| `responses` | string | `"4"` | Réponses DNS à réinjecter (**une seule file**, voir note) |
| `captive` | string | `"20"` | Détection portail captif (TCP/80) |
| `reject` | string | `"10-11"` | Paquets à rejeter (RST/ICMP) |
| `auth` | string | `"5"` | Authentification HTTPS |
| `sni` | string | `"6"` | Verdict SNI TLS/QUIC (443) |
| `sip` | string | `"12"` | Trafic SIP/VoIP |
| `doh_vlan` | string | `"13"` | Détection VLAN des clients DoH (worker `worker_doh_vlan`, optionnel : seulement si `doh.enabled`). Renseigne `req.vlan` en DoH pour `from_vlan`. |

Une plage (ex. `"0-1"`) permet à plusieurs threads de traiter la même queue en
parallèle. **Exception : `responses` doit désigner une seule file.** L'état
d'appariement question/réponse (`pending`) est privé à chaque processus worker,
alors que tous lisent le même pipe question→réponse : avec plusieurs files de
réponse, une réponse livrée à un autre worker que celui qui a lu la question est
jetée (`NF_DROP`). Une plage du type `"4-5"` est donc ramenée à sa première file
(`"4"`) au chargement, avec un avertissement `nfqueue_responses_single_queue_only`.

```moonscript
nfqueue: {
  questions: "0-1"
  responses: "4"
  captive:   "20"
  reject:    "10-11"
  auth:      "5"
  sni:       "6"
  sip:       "12"
  doh_vlan:  "13"
}
```

> **Réduire l'empreinte mémoire.** Chaque numéro de queue = **un worker forké**
> (un processus LuaJIT). Le coût RAM de custos est essentiellement linéaire au
> nombre de workers (tas GC, code JIT, buffers FFI propres à chaque processus) —
> pas aux listes, qui sont partagées via `mmap`. Sur une machine contrainte, on
> peut **ramener chaque plage à une seule queue** (p. ex. `questions: "0"`,
> `reject: "10"`) : on perd le traitement parallèle (débit moindre sous forte
> charge) mais on économise un processus par queue supprimée (~3 à 8 Mo chacun).
> Le mode [`runtime.lowmem`](#2-section-runtime) applique cette réduction
> automatiquement sous 128 Mo. Voir aussi la note « RAM faible » de la section
> [`runtime`](#2-section-runtime).

---

## 4. Section `dns`

Paramètres du traitement DNS.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `port` | int | `53` | Port DNS écouté (bridge intercept) |
| `ttl_grace.grace` | int | `600` | Secondes ajoutées au TTL DNS dans les sets nft |
| `ttl_grace.min` | int | `60` | TTL minimum accepté (en secondes) |
| `ttl_grace.max` | int | `2592000` | TTL maximum accepté (30 jours, en secondes) |
| `upstream_retry.enabled` | bool | `true` | Réinterroge le résolveur sur réponse transitoirement en échec |
| `upstream_retry.max_attempts` | int | `2` | Nombre maximal de réémissions par transaction |
| `upstream_retry.rcodes` | liste | `{2, 3, 5}` | rcodes retentés (SERVFAIL, NXDOMAIN, REFUSED) |
| `upstream_retry.nxdomain_bad_ttl` | int | `60` | Durée (s) de suppression du retry pour un nom durablement NXDOMAIN |
| `upstream_retry.nxdomain_bad_max` | int | `4096` | Taille max du cache de noms « durablement NXDOMAIN » |

Le TTL effectif injecté dans nftables est `clamp(dns_ttl + grace, min, max)`.

### Retry upstream (`upstream_retry`)

Custos est un filtre **inline** : il laisse passer la requête du client vers le
résolveur et intercepte la réponse au retour. Quand le résolveur renvoie une
réponse transitoirement en échec (rcode ∈ `rcodes`, p. ex. SERVFAIL après un
upstream instable comme dynv6), `worker_responses` ne la transmet **pas** au
client. Il réémet la même question vers **le même résolveur** (requête dupliquée
émise via socket RAW, IP source du client spoofée) et `DROP` la réponse en échec.
La transaction en attente reste vivante : la réponse du retry repasse par le pont,
est recapturée et appariée à la même transaction. Au-delà de `max_attempts`, la
réponse en échec est finalement transmise au client (comportement historique).

Cela évite le symptôme « connexion refusée plusieurs fois puis page OK au
rafraîchissement » : sans enregistrement A/AAAA, aucune IP n'est ajoutée à
l'allowlist nft, donc l'hôte reste injoignable jusqu'à une résolution réussie.

**NXDOMAIN intermittent et cache « noms mauvais ».** Certains autoritatifs
instables (ex. dynv6) renvoient NXDOMAIN par intermittence pour un nom qui existe
pourtant — symptôme observé sur **tous** les résolveurs publics testés (Cloudflare,
Quad9). NXDOMAIN (rcode 3) est donc retenté par défaut. Pour ne pas pénaliser les
NXDOMAIN légitimes (fautes de frappe, `.lan`, sondes, PTR…), un nom n'est plus
retenté que s'il n'est pas déjà connu « durablement absent » : un nom dont **même
le retry** reste NXDOMAIN (budget épuisé) entre dans un cache (`nxdomain_bad_ttl`
secondes) ; il en sort dès qu'il résout de nouveau (NOERROR). Conséquence : un nom
réellement inexistant n'est retenté qu'une fois par fenêtre de TTL, tandis qu'un
nom flaky (rarement NXDOMAIN `max_attempts+1` fois d'affilée) reste toujours
retenté. Mettre `rcodes: { 2, 5 }` pour désactiver entièrement le retry NXDOMAIN.

```moonscript
dns: {
  port: 53
  ttl_grace: {
    grace: 600
    min:   60
    max:   2592000
  }
  upstream_retry: {
    enabled:          true
    max_attempts:     2
    rcodes:           { 2, 3, 5 }   -- SERVFAIL, NXDOMAIN, REFUSED
    nxdomain_bad_ttl: 60
    nxdomain_bad_max: 4096
  }
}
```

---

## 5. Section `nft`

Paramètres d'intégration nftables. Ces valeurs doivent correspondre au ruleset
`nft-rules/dns-filter-bridge.nft`.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `family` | string | `"bridge"` | Famille nft pour les sets IPv4 |
| `family6` | string | `"bridge"` | Famille nft pour les sets IPv6 |
| `table` | string | `"dns-filter-bridge"` | Nom de la table nft |
| `ip_timeout` | string | `"2m"` | Durée de vie des éléments dans les sets IP |
| `sip_session_ttl` | string | `"5m"` | Durée de vie des sessions SIP |
| `add_backoff_ms` | array | `{20,50,200,400,800,2000}` | Délais (ms) entre chaque tentative — la longueur du tableau détermine le nombre de tentatives |
| `add_failure_policy` | string | `"fail-closed"` | Comportement si tous les retry échouent : `"fail-closed"` bloque, `"fail-open"` laisse passer |
| `ack_timeout_ms` | int | `150` | Timeout total (ms) d'attente d'acquittement nft ; pendant l'attente, le pipe IPC est drainé par tranches de 5 ms pour éviter la saturation sous burst |
| `extra_rules` | array | `{}` | Fragments nft supplémentaires insérés en tête de chaîne `forward` au démarrage |

**`extra_rules`** : chaque entrée est une expression nft sans le préfixe
`insert rule <table> <chain>`. Exemple :

```moonscript
nft: {
  extra_rules: {
    'ip saddr 10.0.0.0/8 counter log prefix "extra: " accept'
  }
}
```

---

## 6. Section `ipc`

Communication interne entre le worker questions et le worker réponses.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `pending_ttl` | int | `5` | Durée (s) de conservation d'une question en attente de réponse |
| `match_retry.enabled` | bool | `true` | Active les tentatives de correspondance question/réponse |
| `match_retry.count` | int | `5` | Nombre de tentatives |
| `match_retry.sleep_ms` | int | `20` | Délai (ms) entre chaque tentative |
| `match_retry.budget_ms` | int | `100` | Budget de **sommeil** (ms) consommable par fenêtre d'une seconde et par worker ; au-delà, le retry est sauté (aucun `nanosleep`) et la réponse est traitée comme orpheline |

La clé de corrélation est `txid:ip:port:résolveur` (ID de transaction DNS + IP
source du client + port source du client + IP du résolveur).

### Budget du retry d'appariement (`match_retry.budget_ms`)

Le retry existe pour absorber un **réordonnancement IPC légitime** : la réponse
du résolveur peut être recapturée avant que le worker questions n'ait écrit (ou
que `worker_responses` n'ait drainé) la question correspondante sur le pipe
`question_response`. Ce réordonnancement se compte en microsecondes à quelques
millisecondes (la question est écrite avant le forward upstream ; le RTT
upstream, lui, se compte en ms) : la première tentative (`sleep_ms`) suffit dans
le cas nominal.

Sans borne, une rafale de réponses **orphelines** sérialisait le worker dans le
hot-path NFQ : `count` × `sleep_ms` = 5 × 20 ms = **100 ms de blocage par
réponse**, soit ~10 réponses/s de débit et jusqu'à 100 % du temps en `nanosleep`
— un vecteur de déni de service local.

Le budget `budget_ms` borne le sommeil cumulé **par seconde d'epoch et par
worker**, toutes réponses confondues. Défaut `100` : le cas nominal (un
réordonnancement isolé) consomme 20 ms et reste donc entièrement servi,
plusieurs fois par seconde ; le pire cas plafonne le temps passé en retry à
10 % et, une fois le budget épuisé, les orphelins suivants sont **jetés
immédiatement** (aucun `nanosleep`). Un `budget_ms: 0` désactive le retry (tout
orphelin est jeté sans tentative). Le retry est compté en sommeil *consommé*,
non en tentatives : une tentative qui apparie au premier drain ne coûte que
`sleep_ms`.

### Non-appariement et écrasement de clé

Une réponse qui ne trouve aucune question après le retry est **jetée**
(`NF_DROP`) : Custos ne relaie jamais une réponse non sollicitée. C'est un
choix défensif, et l'événement est visible en production : il est émis au
niveau `INFO` sous l'action `response_orphan_dropped` (champs `txid`,
`dst_ip`/`dst_port` du client, `src_ip` du résolveur, `qname`, `rcode`,
`ipc_retry_attempts`, `ipc_retry_wait_ms`, `retry_budget_skipped`). Le détail
reste disponible en `DEBUG` (`response_no_matching_question`,
`response_no_matching_question_after_retry`).

Le volume est borné par le rate-limiting de `log.moon` : les actions
`response_orphan_dropped`, `ipc_pending_overwrite` et
`ipc_pending_overwrite_divergent` ont une entrée `RL_CONFIG` dédiée, **clé =
action seule**, fenêtre 10 s. L'état du limiteur est une table mmap **partagée
entre tous les workers** : au plus une ligne par 10 s, tous workers confondus,
le nombre d'occurrences supprimées étant reporté dans le champ `suppressed=N`
(une rafale de 400 réponses orphelines/s produit donc ~1 ligne / 10 s, pas
400 lignes/s). Une action **sans** entrée dédiée retombe sur la règle par
défaut de son niveau (`INFO` : 60 s, empreinte sur `RL_IDENTITY_KEYS`) : c'est
pourquoi ces trois actions, très répétitives en rafale, ont une entrée à 10 s
et sans champ discriminant.

**Réutilisation de clé (`ipc_pending_overwrite`).** Une nouvelle question qui
réutilise une clé `pending` existante est comparée champ à champ avec l'entrée
(`refused`, `rule_id`, `reason`, `timeout`, `modifiers`, `response_rule_ids`).

- **Cas identique** (retransmission UDP : même question, même verdict) :
  politique **first-wins** — seul `expire` est rafraîchi, toutes les métadonnées
  et les jalons `benchmark_ms`/`question_proc_ms` restent ceux de la première
  question. C'est le cas dominant et il préserve le jalon d'entrée, base de
  `q_to_response_ms`. Tracé en `INFO` (`ipc_pending_overwrite`).
- **Divergence** : verdict le plus restrictif (**fail-closed**). Si l'une des
  deux questions est refusée, l'entrée conservée est celle de la question
  refusée (`refused`, `rule_id`, `reason`, `timeout`, `modifiers`,
  `response_rule_ids` ; jalons de la première question conservés). Si les deux
  sont autorisées mais par des règles différentes, aucun choix ne peut être
  prouvé non élargissant : `response_hooks` et l'injection nft de
  `worker_responses` appliquent les métadonnées de la règle retenue à la
  réponse de l'autre (ex. règle `dnsonly` ou strip d'un côté, allow normale de
  l'autre), donc l'entrée est marquée refusée avec
  `reason: ipc_pending_conflict`. Tracé en `WARN`
  (`ipc_pending_overwrite_divergent` : `refused_kept`/`refused_new`,
  `rule_kept`/`rule_new`, `resolution`).

Limite connue : `qname`/`qtype` ne sont pas transmis par le protocole IPC
(format A4) ; une divergence de **contenu** de question à métadonnées
identiques reste indétectable (elle se comporte comme une retransmission).

Quand `runtime.benchmark` est actif, ces tentatives alimentent les champs
`ipc_retry_attempts` / `ipc_retry_wait_ms` de la ligne `action=response_dns_benchmark`
(cf. [section `runtime`](#2-section-runtime)) ; ils sont sans rapport avec le retry
upstream `dns.upstream_retry` (champ `upstream_retries`).

---

## 7. Section `clients`

Gestion du cache client-side.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `expiry` | int | `300` | Durée (s) avant expiration d'une entrée client |

---

## 7bis. Section `second_opinion`

Couche **« second avis »** : pour chaque question DNS autorisée par une règle
portant l'action [`validate`](#validate), `worker_questions` **duplique** le
paquet en réécrivant uniquement l'IP destination vers un résolveur de filtrage
(ex. **DNSforFamily**), en conservant src client, txid et qname.
`worker_responses` reçoit alors **deux** réponses :

- celle du **vrai résolveur** (transmise au client, intacte ou spoofée) ;
- celle du **validateur** (src ∈ `resolvers`) : jamais transmise (NF_DROP), elle
  ne sert qu'à décider du verdict.

`worker_responses` corrèle les deux par `(client, txid, qname)` et applique :

| Réponse du validateur | Action sur la réponse d'origine |
|-----------------------|---------------------------------|
| **NXDOMAIN** | Blocage : réponse synthétique NXDOMAIN + EDE 17 (Filtered) |
| **Sinkhole** (`A 0.0.0.0` / `AAAA ::`) | Blocage : la réponse d'origine est réécrite en **reproduisant le sinkhole** (mêmes adresses nulles, `NOERROR`) + EDE 17. DNSforFamily bloque ainsi, pas par NXDOMAIN — on conserve sa sémantique côté client plutôt que de la convertir en NXDOMAIN |
| **CNAME** | Réorientation (ex. SafeSearch) : spoof avec le CNAME + A/AAAA du validateur, AD effacé + EDE (Forged_Answer), IP injectées dans l'allowlist nft. **Sauf** si la réponse d'origine porte déjà le même CNAME cible → transmise telle quelle |
| Réponse normale | Transmise intacte (DNSSEC préservé) |

La réponse d'origine est **parquée** (verdict NFQUEUE différé) jusqu'à l'arrivée
de la réponse validateur ou l'expiration de `budget_ms` (→ fail-open).

> **Parité DoH.** Le résolveur DoH applique désormais le **même** verdict
> classifié : le second avis y est **synchrone** (`doh.validator.query_classified`
> → `dns_classify.classify`) et reproduit `block` (NXDOMAIN), `sinkhole`
> (`A 0.0.0.0`/`AAAA ::`) et `redirect` (CNAME + injection nft des cibles), au lieu
> de l'ancien blocage booléen. REFUSED reste traité comme un blocage. Fail-open si
> tous les validateurs sont muets.

> **Opt-in par règle.** La duplication n'a lieu que pour les requêtes autorisées
> par une règle portant l'action `validate`. Sans cette action, la réponse est
> transmise telle quelle, sans aucune interaction avec le résolveur validateur.

> **Texte EDE.** Pour un blocage/réorientation décidé par le validateur, l'EDE
> porte « Filtered by upstream validator » — et **non** la raison
> d'*autorisation* locale (ex. « Allowed by rule: … »), qui serait trompeuse.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `resolvers` | liste | — | IPs v4/v6 (UDP/53) et/ou URLs DoH `https://…` (via libcurl) ; la famille UDP est choisie selon le paquet client |
| `budget_ms` | int | `80` | Attente max de la réponse validateur **UDP** avant fail-open |
| `doh_budget_ms` | int | `3000` | Attente max pour les endpoints **DoH** `https://…` (TLS + HTTP/2 plus longs à établir) |
| `fail_open` | bool | `true` | Validateur silencieux → laisser passer la réponse d'origine |
| `verdict_ttl_s` | int | `60` | TTL du cache de verdict **côté SNI** (`worker_tls`) : durée de mémorisation d'un verdict validateur par domaine pour éviter un aller-retour upstream à chaque nouveau flux TLS/QUIC |

> **Application au SNI (`worker_tls`).** Le second avis ne se limite pas au DNS :
> `worker_tls` applique la **même** logique au niveau du SNI (cf. § [`sni`](#10-section-sni)).
> Pour une règle `validate`, il interroge le validateur de façon **synchrone**
> sur le SNI (requête A wire) au premier flux d'un domaine, puis met le verdict
> en cache (`verdict_ttl_s`). Fail-open en cas de validateur muet/injoignable.
> Il privilégie des résolveurs **UDP/53** (budget court) ; un endpoint DoH
> `https://` synchrone sur ce hot-path est déconseillé.

> **Émission de la requête dupliquée.** Elle se fait via un **socket RAW routé
> par le noyau** (`SOCK_RAW`/`IP_HDRINCL` en IPv4, `IPV6_HDRINCL` en IPv6) avec
> src = IP du client : le noyau résout lui-même le next-hop et l'interface de
> sortie. Aucune MAC de passerelle à configurer, et un **IPv6 routé par un
> tunnel** (ex. WireGuard) distinct de la route IPv4 est géré nativement. Une
> famille n'est **activée que si un validateur de cette famille est routable**
> (sinon ni duplication ni parking pour cette famille → latence inchangée).
>
> **Cas « le validateur est le DNS principal du client ».** Si un client a déjà
> configuré une IP `resolvers` comme résolveur, sa requête part directement vers
> le validateur : la réponse est filtrée à la source. Custos le détecte
> (réponse d'un validateur **corrélée à une transaction en attente**), ne
> duplique pas et **laisse passer la réponse intacte** — pas de double requête,
> pas de blocage erroné, pas de latence ajoutée.
>
> **Contraintes.** Ne s'applique qu'au **Do53 en clair** transitant le pont
> (DoH/DoT/DoQ sortants restent bloqués au L3). Les **questions UDP** seules sont
> dupliquées. Le trafic Do53 vers les IP `resolvers` doit être autorisé en sortie
> du boîtier. Sous mode RAM faible, le coût reste minime (pas de worker ni cache
> supplémentaire).

---

## 8. Section `mac_learner`

Apprentissage des adresses MAC via un socket Unix.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `query_sock` | string | `"/var/run/custos/mac_query.sock"` | Chemin du socket IPC |
| `entry_ttl` | int | `900` | Durée (s) de conservation d'une entrée MAC apprise |
| `strip_ttl` | int | `120` | Durée de vie (s) d'une cible CNAME apprise pour le strip contextuel (`dns_strip.follow_cname`, cf. § 11). TTL court : limite la fenêtre où un nom terminal est strippé hors de son contexte de chaîne. |

---

## 9. Section `auth`

Portail captif et authentification des utilisateurs.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `host` | string | `"::"` | Adresse d'écoute du serveur auth (`::`= toutes interfaces IPv4+IPv6) |
| `port` | int | `33443` | Port HTTPS du serveur d'authentification |
| `captive_port` | int | `33080` | Port HTTP du portail captif |
| `cert` | string | — | Chemin vers le certificat TLS. Si le fichier n'existe pas au démarrage (installation fraîche), un certificat auto-signé est **généré automatiquement** à cet emplacement (px5g, dossiers parents créés). En cas d'échec de génération, repli sur le cache de certificats dynamiques keyé par le nom SNI demandé (lu par `MSG_PEEK` avant le handshake, `src/auth/sni_peek.moon`), puis sur l'IP locale du socket si le SNI est absent, invalide, hors quota (`SNI_CERT_MAX_NAMES`) ou si sa génération échoue. |
| `key` | string | — | Chemin vers la clé privée TLS (générée avec `cert` si absente, permissions `0600`) |
| `cert_dir` | string | `"/tmp/custos/certs"` | Répertoire des certificats **générés au runtime** (SNI/IP, cache px5g) et de leur index `cert_cache_index.lua`. Défaut tmpfs : ils ne sont pas persistés sur la flash et sont régénérés après un redémarrage. Un certificat fourni à la main reste désigné par `cert`/`key`. |
| `secrets` | string | `"/etc/custos/secrets"` | Répertoire contenant les secrets (hash mots de passe) |
| `session_ttl` | int | `0` | Durée (s) des sessions auth (0 = illimitée) |
| `sessions_file` | string | `"/tmp/sessions.lua"` | Fichier de persistance des sessions |
| `heartbeat_interval` | int | `30` | Intervalle (s) entre heartbeats client |
| `refusals_poll_interval` | int | `5` | Intervalle (s) entre interrogations de `/refusals` par la page de succès (liste défilante des domaines bloqués récemment, filtrée sur la MAC du client). Lecture seule, indépendant de `/ping`. |
| `idle_timeout` | int | `300` | Inactivité maximale (s) avant déconnexion. Le cookie de session `custos_session` expire **exactement** en même temps (pas de marge séparée) : aucune fenêtre où la page indiquerait « connecté » alors que l'accès DNS a déjà expiré. Élargir cette valeur pour tolérer des pings/heartbeats retardés (throttling des onglets en arrière-plan). |
| `close_grace` | int | `45` | Grâce (s) appliquée quand la page de session disparaît (`pagehide` → beacon `/bye`) : l'expiration de la session est **raccourcie** à `now + close_grace` au lieu d'être détruite. Si la page revit (reload, navigation, onglet restauré), le `/ping` suivant re-prolonge la session ; si la fenêtre est vraiment fermée, l'accès tombe après la grâce. Garder ≥ 2× l'intervalle de ping (20 s). |
| `max_body` | int | `1048576` | Taille maximale du corps d'une requête HTTP acceptée (octets). Le plus gros POST légitime est l'éditeur de listes (`<textarea>` de domaines). Un `Content-Length` supérieur — ou non entier/négatif — est rejeté sans lecture du corps (réponse 413), ce qui évite l'allocation d'un tampon arbitrairement grand avant authentification. |
| `client_timeout` | int | `15` | Timeout I/O (s) par connexion au portail (SO_RCVTIMEO/SO_SNDTIMEO + échéance de handshake TLS). Une connexion qui n'envoie rien (préconnexion spéculative du navigateur, client disparu sans FIN) est fermée et son processus `AUTH-conn` libéré au lieu de rester suspendu indéfiniment — ces sockets zombies saturaient la limite de connexions par hôte du navigateur et retardaient les pings (~70 s). |
| `challenge_ttl` | int | `120` | Durée de validité (s) d'un nonce de challenge-réponse (`/challenge`). Le mot de passe est haché côté client (PBKDF2+HMAC sur le nonce) et n'est jamais transmis en clair ; une réponse capturée n'est rejouable que pendant cette fenêtre, et seulement pour la même MAC. Le nonce est signé (HMAC `session.key`), sans état serveur. |
| `allow_plaintext_login` | bool | `true` | Autorise le repli d'envoi du mot de passe en clair quand le JavaScript est totalement désactivé (le serveur recourt alors à `verify_password`). Défaut `true` pour compatibilité ascendante ; **recommandé `false`** une fois le déploiement validé, pour garantir que le mot de passe ne quitte jamais le navigateur. N'affecte pas les clients avec JS (WebCrypto ou repli JS pur), qui hachent toujours. |
| `register_rate_limit` | int | `3` | Nombre maximal de **tentatives d'inscription** (`POST /register`) autorisées par client et par fenêtre de `register_rate_window` secondes. Client identifié par sa MAC si elle est connue, sinon par son IP. La tentative au-delà de la limite reçoit `429` avec `Retry-After` (secondes restantes), **sans créer de compte ni écrire le fichier de secrets**. Fenêtre **fixe** ; `0` (ou une valeur négative) désactive la limitation. L'état est partagé entre les enfants AUTH forké dans le fichier `<sessions_file>.ratelimit` (écrit sous verrou `flock`, purgé à chaque écriture, plafonné à 4096 entrées). Toute erreur interne du limiteur échoue **ouvert** (tentative acceptée). |
| `register_rate_window` | int | `300` | Durée de la fenêtre (s) du limiteur d'inscription. Une valeur absente, nulle ou négative retombe sur `300`. |
| `bridge_ifname` | string | auto | Nom de l'interface bridge (sniffer ARP/NDP, mac_learner, worker captif, AF_PACKET). **Détecté automatiquement** si absent (`src/lib/bridge_detect.moon`) : via sysfs `/sys/class/net/*/bridge` (busybox-compatible), en choisissant le bridge ayant **le plus de ports esclaves** (départage `br-lan` > `br0` > ordre alphabétique) ; repli `ip -brief link show type bridge` puis `"br0"`. Surchargeable par la config ou l'env `BRIDGE_IFNAME` (qui prime sur l'autodétection). Si la valeur configurée ne correspond à aucune interface existante, le superviseur émet un warning `bridge_ifname_not_found` au démarrage. |
| `redirect_url` | string | — | URL de redirection après authentification (optionnel). Son hostname définit le **domaine du portail captif** : toute requête A/AAAA sur ce nom est forgée vers l'IP locale du boîtier (`captive_ip4`/`captive_ip6`), **aussi bien par l'intercepteur UDP que par le résolveur DoH** (parité, cf. AGENTS.md § « Parité UDP/DoH »). |
| `admin_users` | array | `{}` | Liste des utilisateurs avec droits administrateur (interface `/admin/*`) |
| `admin_allow_all_when_empty` | bool | `true` | Si `true` et `admin_users` vide, tous les utilisateurs authentifiés sont admin |

```moonscript
auth: {
  host: "::"
  port: 33443
  captive_port: 33080
  cert: "/etc/custos/certs/auth.crt"
  key:  "/etc/custos/keys/auth.key"
  cert_dir: "/tmp/custos/certs"
  secrets: "/etc/custos/secrets"
  session_ttl: 0
  sessions_file: "/var/run/custos/sessions.lua"
  bridge_ifname: "br0"
}
```

---

## 10. Section `sni`

Inspection et filtrage du trafic TLS/QUIC sur port 443 (worker `worker_tls`,
queue `nfqueue.sni`).

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `enabled` | bool | `true` | Active la vérification SNI |
| `mode` | string | `"strict-443"` | Mode de vérification : `"strict-443"` n'inspecte que le port 443 |
| `placement` | string | `"residual"` | Placement de la mise en file SNI dans le ruleset nft (cf. ci-dessous) : `"integral"` ou `"residual"` |
| `protocols` | string | `"both"` | Protocoles à inspecter : `"both"`, `"tls"`, `"quic"` |
| `nft_failure_policy` | string | `"fail-closed"` | Comportement si l'extraction SNI échoue : `"fail-closed"` bloque, `"fail-open"` laisse passer |

**`placement`** — détermine *où* la règle de mise en file SNI est insérée par
rapport aux règles de filtrage DNS compilées (`cv_rules_dispatch` /
`@cv_action_vmap`) :

- `"integral"` : la règle est placée **avant** le dispatch des règles. *Tout* le
  trafic 443 (TCP + QUIC) est inspecté par SNI, y compris les destinations déjà
  autorisées par résolution DNS. Garantit qu'aucun flux ne contourne
  l'inspection SNI, mais c'est le mode le plus intrusif (peut perturber des
  connexions légitimes vers des hôtes déjà autorisés).
- `"residual"` (défaut) : la règle est placée **après** l'application du verdict.
  Seul le trafic *non déjà autorisé* par DNS atteint la file SNI ; l'inspection
  agit comme un filet de sécurité sur le trafic résiduel. Moins intrusif.

Une valeur inconnue retombe sur le défaut `"residual"`.

**Filtrage SNI = filtrage DNS.** `worker_tls` applique au SNI **exactement** la
même décision que les workers DNS, à partir de `filter.decide_meta` :

| Décision DNS pour le domaine (= SNI) | Action sur le flux TLS/QUIC |
|--------------------------------------|------------------------------|
| Autorisé (allow pur) | Laissé passer (IP/MAC insérées dans les sets nft) |
| Refusé (deny / `dnsonly`) | Bloqué (`NF_DROP` en `strict-443`) |
| **Réécriture de destination** (SafeSearch/`cname`) | **Bloqué** : on ne peut pas rediriger un flux déjà établi vers une IP. Le client est forcé de repasser par le DNS Custos, qui renvoie l'IP correcte. **Exception** : si l'IP de destination est **déjà** une cible légitime du CNAME (cache DNS périmé mais correct), le flux passe |
| Soumis au **second avis** (`validate`) | Validateur interrogé synchroniquement sur le SNI ; bloqué si l'amont bloque, sinon laissé passer (fail-open si validateur muet). Cf. § [`second_opinion`](#7bis-section-second_opinion) (`verdict_ttl_s`) |

Cela ferme le contournement où un client résout un domaine via un **DoH externe**
(hors pipeline Custos) puis se connecte en HTTP/3 vers l'IP non filtrée : le SNI
porte toujours le domaine, et `worker_tls` rejoue la décision DNS.

> `dns_strip` (suppression de RR HTTPS/SVCB, anti-ECH) **n'est pas** traité comme
> une redirection : il ne change pas la destination, le flux est laissé passer.
> Une règle `cname` injoignable au moment de la vérification est **fail-closed**
> côté redirect (bloquée), faute de pouvoir confirmer que le client vise la bonne IP.

**Fragmentation TLS** — les ClientHello étalés sur plusieurs segments TCP
(petit MTU, PMTUd cassé, ClientHello volumineux avec ECH / post-quantique) sont
réassemblés avant extraction du SNI, via le défragmenteur générique
`ipparse.l4.tcp_stream` (le même que pour le DNS sur TCP/53). Le verdict tombe
sur le segment qui complète l'enregistrement TLS Handshake ; en `strict-443`,
un DROP à ce moment empêche la finalisation du handshake. Parité avec QUIC, où
les CRYPTO frames multi-datagrammes étaient déjà réassemblés. *Limite connue* :
un ClientHello réparti sur plusieurs **records** TLS distincts (>16 Ko, très
rare) n'est pas recollé au niveau record ; le parser tolérant prend alors le
relais sur le premier record.

```moonscript
sni: {
  enabled: true
  mode: "strict-443"
  placement: "residual"
  protocols: "both"
  nft_failure_policy: "fail-closed"
}
```

---

## 11. Section `doh`

Proxy DNS-over-HTTPS vers un résolveur amont.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `enabled` | bool | `true` | Active le serveur DoH |
| `port` | int | `8443` | Port HTTPS d'écoute |
| `upstream_ipv4` | string | `"1.1.1.3"` | IP amont IPv4 (Cloudflare for Families par défaut) |
| `upstream_ipv6` | string | `"2606:4700:4700::1113"` | IP amont IPv6 |
| `upstream_port` | int | `53` | Port du résolveur amont |
| `upstream_timeout_ms` | int | `2000` | Timeout (ms) vers le résolveur amont |
| `client_timeout` | int | `15` | Timeout I/O (s) par connexion DoH : SO_RCVTIMEO/SO_SNDTIMEO + échéance de handshake TLS et lecture de requête/frames HTTP/2. Une connexion muette est fermée et son enfant `DOH-conn` libéré au lieu de rester suspendu indéfiniment. |
| `upstream_dead_ttl_s` | int | `30` | TTL (s) du cache négatif d'un résolveur amont injoignable (action `cname`). Un résolveur qui timeout n'est pas re-sollicité pendant ce délai, afin de ne pas bloquer le worker responses (jusqu'à `upstream_timeout_ms`) à chaque paquet. Re-sondé après expiration. |
| `cert` | string | `nil` | Chemin du certificat TLS statique du serveur DoH (optionnel) |
| `key` | string | `nil` | Chemin de la clé privée TLS statique du serveur DoH (optionnel) |
| `prefer_ipv6` | bool | `true` | Préférer IPv6 pour les requêtes amont |
| `upstream_doh_url` | string | `nil` | URL DoH amont, ex. `"https://dns.quad9.net/dns-query"`. Si défini, le worker DoH proxifie vers ce résolveur via **libcurl** (HTTP/2 + ALPN natif, fallback HTTP/1.1 automatique) au lieu d'UDP/53. Requis pour les providers qui imposent HTTP/2 (RFC 8484 §5.2, ex. DNSforFamily). Opt-in. Si libcurl ne peut être chargé ou initialisé, le worker bascule une fois sur le repli HTTP/1.1 wolfSSL (`doh.upstream_doh`, vérifié par défaut) ; une erreur de requête (timeout, 5xx) ne déclenche pas ce repli. |
| `upstream_doh_tls_verify` | bool | `true` | Vérifier le certificat TLS du résolveur `upstream_doh_url` (sécurisé par défaut). Ne mettre à `false` que pour un résolveur de confiance hors chaîne PKI ; le worker DoH loggue alors `upstream_doh_tls_verify_disabled`. |
| `upstream_fallback_insecure` | bool | `false` | Repli wolfSSL (HTTP/1.1) quand libcurl est inutilisable. `false` (défaut) : le repli **refuse de fonctionner** s'il ne peut pas vérifier certificat + nom d'hôte (symbole absent ou aucun magasin de CA) ; l'erreur est journalisée. `true` : repli non vérifié accepté avec un `log_warn` explicite. Jamais appliqué au validateur (`doh.validate_resolvers`), qui n'accepte aucun transport non vérifié. |
| `upstream_fallback_ca_file` | string | `nil` | Magasin de CA du repli wolfSSL. `nil` : `SSL_CERT_FILE`, puis `/etc/ssl/certs/ca-certificates.crt`, `/etc/ssl/cert.pem`, `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/ca-bundle.pem`. |

> **Note `from_vlan` en DoH.** La condition `from_vlan` ne fonctionne pas pour
> les connexions DoH quand les switches amont suppriment les tags 802.1Q avant
> le pont : la couche L2 n'est pas visible sur la connexion TCP/TLS. Utiliser
> `from_nets` (sous-réseaux IP) à la place pour les règles DoH.

### Clé `doh.validate_resolvers`

Liste d'endpoints pour le second avis DNS (action `validate` dans les règles de filtre). Supporte les IPs UDP/53 et les URLs DoH (`https://…`). Les endpoints DoH utilisent **libcurl** avec le timeout `second_opinion.doh_budget_ms` (défaut 3000 ms) ; si libcurl est inutilisable, ils basculent vers le repli wolfSSL **toujours vérifié** (jamais `upstream_fallback_insecure`, même à `true` : un verdict forgé serait pire qu'une absence de verdict).

```moonscript
doh: {
  validate_resolvers: { "9.9.9.9", "https://dns.quad9.net/dns-query" }
}
```

---

## 12. Section `events`

Stockage des événements système (journaux d'activité).

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `dir` | string | `"/tmp/custos/events"` | Répertoire de stockage des événements |
| `max_age_hours` | int | `168` | Conservation maximale (heures) — 168h = 7 jours |
| `min_free_pct` | int | `30` | Pourcentage d'espace disque libre minimum avant purge |

En plus des fichiers TSV horaires agrégés (`events-YYYY-MM-DD-HH.tsv`),
`worker_events` maintient un ring buffer unique `recent-verdicts.tsv` dans
`dir` : jusqu'à 8192 derniers verdicts DNS (allow **et** block), dédupliqués par
`mac+qname+decision` avec compteur, réécrit atomiquement avec un throttle de 5 s.
Format : `mac\tip\tuser\tqname\tdecision\treason\tcount\tfirst_ts\tlast_ts`.
Ce fichier alimente trois UX :
- l'endpoint `/refusals` du portail (blocages récents du client : lignes
  `decision == "block"` filtrées par MAC) ;
- la page admin `/admin/config/devices` (agrégation par MAC) ;
- la page admin `/admin/config/verdicts` (liste brute de tous les verdicts).

---

## 13. Section `metrics`

Collecte de métriques internes. Chaque worker `worker_questions` accumule les
verdicts par règle en mémoire, puis écrit périodiquement un instantané JSON
`metrics-<worker>.json` dans le répertoire d'exécution (celui du pidfile
`runtime.pid_file`, `/var/run` par défaut ; surchargeable par
`CUSTOS_PID_FILE`). Le superviseur **purge** les `metrics-*.json` et
`metrics-*.json.tmp.*` d'une exécution précédente au démarrage, avant de forker
les workers ; chaque worker écrit immédiatement un instantané à zéro après son
`init` (y compris après un redémarrage), puis toutes les `flush_interval`
secondes. L'écriture est atomique (fichier temporaire + `os.rename`) et n'a
lieu que dans le worker concerné, jamais dans le chemin par paquet : l'horloge
n'est lue qu'au point de passage `on_idle` de `run_queue` (poll
`opts.idle_ms = 1000`), une fois par tour de boucle, indépendamment du trafic
(et à chaque expiration du poll). Aucun compteur de paquets n'intervient : un
`read` netlink peut livrer plusieurs messages NFQUEUE sans nouveau passage.
La page admin en
lecture seule `/admin/metrics` agrège **tous** les instantanés valides de
l'exécution courante ; l'âge de chacun est affiché à titre d'information, sans
exclusion des totaux (voir [docs/agents/webui.md](../docs/agents/webui.md)).

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `enabled` | bool | `true` | Active la collecte et l'écriture des instantanés. `false` : aucun compteur ni fichier, coût nul dans le chemin par paquet, la page indique que les métriques sont désactivées. |
| `flush_interval` | int | `60` | Intervalle (s) entre deux instantanés JSON par worker |
| `max_rules` | int | `1000` | Nombre maximum de règles tracées dans les métriques |

---

## 14. Section `rtp`

Paramètres pour le trafic RTP/VoIP.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `excluded_ports` | array | `{5060}` | Ports exclus du filtrage RTP (SIP par défaut) |

---

## 15. Section `filter`

Section principale : définit les règles de filtrage DNS, les listes et la logique de décision.

### 14.1 Répertoires de listes

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `domainlists_dir` | string | `"/tmp/custos/lists"` | Répertoire racine des listes de domaines **compilées** (`.bin`, repli `.domains`) lues par `to_domainlist`/`to_domainlists` |
| `lists_dir` | string | `"/etc/custos/lists"` | Répertoire des listes-texte lues par les conditions `*_list`/`*_lists` : `{lists_dir}/{type}/{nom}.txt` (définitions manuelles, persistantes) |
| `custom_lists_dir` | string | `nil` | Dossier **source** des `.txt` scannés par l'updater (non lu par le filtre ; les `.bin` produits vont sous `{domainlists_dir}/custom/`) |
| `allow_localnets` | bool | `false` | Si `true`, injecte automatiquement les réseaux locaux en whitelist nft |
| `captive_portal` | bool | `true` | Active les règles par défaut de détection de portail captif (sondes NCSI/MSFT, Apple, Google…). `false` → ces règles ne sont pas injectées (cf. § Règles par défaut) |
| `safe_search` | bool | `true` | Active SafeSearch : réécriture CNAME des moteurs de recherche vers leur variante « safe » (Google→`forcesafesearch.google.com`, YouTube, Bing→`strict.bing.com`, DuckDuckGo→`safe.duckduckgo.com`). `false` → aucune réécriture (cf. § SafeSearch) |
| `youtube_restrict` | string | `"moderate"` | Mode YouTube Restricted : `"strict"` (`restrict.youtube.com`), `"moderate"` (`restrictmoderate.youtube.com`) ou `false` (YouTube non réécrit). Sans effet si `safe_search` est `false` |
| `dest_whitelist` | array | `{}` | IPs/CIDRs de destination toujours autorisées (bypass filtrage) |
| `allowed_domains` | array | `{"local","lan","home.arpa"}` | Domaines autorisés par défaut si `rules` est vide |

**Ce qui est lu où.** Le filtre lit (1) les domainlists **compilées** sous
`domainlists_dir` (`{domainlists_dir}/{nom}.bin`, repli `.domains`) pour
`to_domainlist`/`to_domainlists`, et (2) les fichiers nommés sous `lists_dir`
(`{lists_dir}/{type}/{nom}.txt`, une valeur par ligne) pour les conditions
`*_list`/`*_lists`. `custom_lists_dir` n'est **pas** lu par le filtre : c'est
le dossier **source** des `.txt` que l'updater scanne
(`src/filter/updater.moon:425-434`) pour produire les `.bin` sous
`{domainlists_dir}/custom/` (ou dans `custom_lists_dir` lui-même si
`domainlists_dir` est absent). Une liste référencée mais introuvable ou vide
est signalée au chargement par `filter_list_missing` / `filter_list_empty`
(champs `condition`, `list`, `path`), sans changer le filtrage : elle ne
correspond jamais.

`domainlists_dir` est le répertoire de **sortie** lu par le filtre
(`to_domainlist`). Sur OpenWrt il est sur tmpfs (`/tmp/custos/lists`, vidé à
chaque redémarrage) : `custos-update` le repeuple au démarrage, en déployant la
release `custos-lists` puis en compilant les listes locales.

`custom_lists_dir` est au contraire le dossier **source** des `.txt` locaux
(jamais lu directement par le filtre) : chaque `*.txt` est compilé en
`{domainlists_dir}/custom/<nom>.bin` par `custos-update` (updater avec
`--custom-only`). La compilation locale ayant lieu après l'extraction de la
release, une liste locale de même nom qu'une liste de la release l'emporte.


### 14.2 Dictionnaires nommés et listes de valeurs

Les variantes `_list` / `_lists` des conditions ne prennent **pas** le nom d'un
groupe de ces dictionnaires : elles lisent des fichiers texte sous
`filter.lists_dir` (`{lists_dir}/{type}/{nom}.txt`, un élément par ligne, lignes
vides et `#commentaires` ignorées). Les lignes lues sont ensuite évaluées par la
condition de base, qui peut y résoudre un alias (`filter.macs`) ou un nom de
fenêtre (`filter.times`). L'usage réel de chaque dictionnaire est indiqué
ci-dessous.

#### `filter.nets` — Réseaux nommés (résolus par `from_net`/`to_net`)

```moonscript
filter: {
  nets: {
    lan: {
      "192.168.0.0/16"
      "10.0.0.0/8"
      "172.16.0.0/12"
    }
    private_ipv6: { "fd00::/8" }
  }
}
```

`from_net` et `to_net` consultent ce dictionnaire : quand leur argument n'est
ni `_any`/`_none`, ni un CIDR/une IP littérale, mais une clé de `nets`, la
condition porte sur le ou les CIDRs du groupe (OU logique). Les variantes
`from_nets`, `from_net_list` et `from_net_lists` en héritent : une entrée de
`from_nets` ou une ligne de fichier peut donc être un alias. Un alias vers un
seul CIDR reste compilable en nft ; un groupe de plusieurs CIDRs (y compris
IPv4 et IPv6 mélangés) est évalué uniquement par le worker (`nft: false`,
l'expression nft d'un set déjà groupé n'étant pas recombineé de façon fiable).
Un nom inconnu ne correspond jamais et journalise `filter_net_unknown` une
seule fois au chargement (jamais dans `eval`). Pour un groupe non nommé,
`from_net_list: "lan"` reste disponible : fichier `{lists_dir}/net/lan.txt`,
un CIDR par ligne.

#### `filter.macs` — Alias de MAC

Chaque valeur est **une** adresse MAC (chaîne unique), pas une liste.

```moonscript
filter: {
  macs: {
    trusted:      "aa:bb:cc:dd:ee:ff"
    iot_devices:  "00:1a:2b:3c:4d:5e"
  }
}
```

Résolus par `from_mac: "trusted"` et par chaque entrée de `from_macs`
(alias ou MAC brute). Pour un groupe de plusieurs MACs, utiliser
`from_mac_list: "trusted"` : fichier `{lists_dir}/mac/trusted.txt`, une valeur
par ligne (les alias de `filter.macs` y sont résolus).

#### `filter.times` — Fenêtres horaires

Chaque entrée est une table `{heure_début, heure_fin}` au format `"HH:MM"`.
Une fenêtre nocturne (fin < début) est interprétée correctement.

```moonscript
filter: {
  times: {
    business_hours: {"08:00", "18:00"}
    after_hours:    {"18:00", "08:00"}
  }
}
```

Référencées via `in_time: "business_hours"`, ou par un fichier nommé listant
des noms de fenêtres (`in_time_list: "fichier"`, un nom par ligne dans
`{lists_dir}/time/fichier.txt`).

#### VLAN (`from_vlan`, `from_vlan_list`)

Il n'existe pas de dictionnaire `filter.vlans` : `from_vlan` prend un ID
numérique (`from_vlan: 100`). Pour un groupe, utiliser
`from_vlan_list: "guests"` : fichier `{lists_dir}/vlan/guests.txt`, un ID par
ligne.

> **Limite connue** : les lignes lues par `from_vlan_list` sont des chaînes,
> comparées telles quelles à `req.vlan` (numérique) par
> `src/filter/conditions/from_vlan.moon:21-27` ; la variante fichier ne
> correspond donc pas aux VLAN réels tant que cette comparaison n'est pas
> convertie.

#### `filter.users` / `filter.userlists` — Utilisateurs

Associent un identifiant court à un email. `userlists` est un alias de
`users` (les deux sont synchronisés au chargement).

```moonscript
filter: {
  users: {
    alice: "alice@example.com"
    bob:   "bob@example.com"
  }
}
```

`from_user` ne résout pas ces alias : il attend directement l'identifiant
d'authentification, comparé au champ `user` de la session. Pour un groupe
d'identifiants, utiliser `from_user_list: "admins"` : fichier
`{lists_dir}/user/admins.txt`, un identifiant par ligne.

### 14.3 Sources de listes de domaines (`filter.sources`)

Définit d'où proviennent les listes de domaines et comment elles sont téléchargées/compilées.
Utilisé par `make update-lists` (compilation locale via `updater.lua`).

> **Note OpenWrt :** sur routeur, `custos-update` ne compile plus localement —
> il télécharge les `.bin` pré-compilés depuis les releases `custos-lists`
> (cf. `doc/CHEATSHEET.md`). `filter.sources` ne sert alors qu'à la CI de
> `custos-lists` ; le profil (`full`/`lowmem`) et le tag se règlent via UCI
> (`custos.main.lists_profile`, `custos.main.lists_tag`, `custos.main.lists_dir`)
> ou les variables d'environnement `CUSTOS_LISTS_*`.

Chaque source a un format et au moins un champ d'entrée :

**Format `toulouse`** — archive des blacklists de l'Université Paul Sabatier :

```moonscript
sources: {
  toulouse_threats: {
    url: "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"
    format: "toulouse"
    categories: {"ads", "malware", "phishing", "gambling", "adult", "publicite"}
    subdir: "toulouse"
  }
}
```

**Format `simple`** — liste de domaines bruts (un par ligne, `#` pour les commentaires) :

```moonscript
sources: {
  ads_tracking: {
    urls: {
      "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    }
    format: "simple"
    output: "/etc/custos/lists/ads_tracking.bin"
  }
  my_custom: {
    file: "/etc/custos/lists/custom/my_list.txt"
    format: "simple"
    output: "/etc/custos/lists/custom/my_list.bin"
  }
}
```

| Champ | Description |
|-------|-------------|
| `url` / `urls` | URL(s) source à télécharger |
| `file` | Fichier local source |
| `format` | `"toulouse"` ou `"simple"` |
| `categories` | (toulouse uniquement) sous-catégories à extraire |
| `subdir` | Sous-répertoire de destination dans `domainlists_dir` |
| `output` | Chemin du fichier `.bin` compilé (si absent : dérivé du nom de la source) |

Les fichiers `.bin` sont des tableaux triés de hachages XXH64 tronqués à 48 bits
(N × 6 octets little-endian, sans en-tête ; cf. `src/filter/lib/bin48.moon`).
L'outil de conversion est `lua/filter/convert.lua`.

### 14.4 Règles de filtrage (`filter.rules`)

Tableau ordonné de règles. Chaque règle est une table avec :

```moonscript
{
  description: "Texte libre (affiché dans les logs)"
  conditions:  { ... }   -- toutes doivent être vraies (AND implicite)
  actions:     { ... }   -- évaluées en séquence, première avec verdict gagne
  enabled:     true      -- optionnel ; false désactive la règle (défaut : true)
}
```

Une règle sans `conditions` s'applique à toute requête (catch-all).

**Désactiver une règle.** `enabled = false` rend la règle totalement inerte :
elle ne matche jamais côté worker et ne produit aucune sortie nftables, mais
reste présente dans la config (et conserve son rang/`rule_id`). Pratique pour
neutraliser temporairement une règle sans la supprimer. La clé absente ou `true`
laisse la règle active. Dans l'interface admin (`/admin/config/filter/rules`),
le bouton « Désactiver »/« Activer » bascule cet état.

#### Exemple complet

```moonscript
filter: {
  rules: {
    -- Blocage des menaces connues pour le LAN
    {
      description: "Blocage malware/phishing LAN"
      conditions: {
        from_net_list: "lan"
        to_domainlists: {"toulouse/malware", "toulouse/phishing"}
      }
      actions: {"deny"}
    }

    -- Autorisation DNS-only des sondes captives (pas d'ouverture pare-feu)
    {
      description: "Sondes captives"
      conditions: {
        to_domainlist: "custom/captive_detect"
      }
      actions: {"dnsonly"}
    }

    -- Alice peut accéder à auth-required.test
    {
      description: "Auth alice"
      conditions: {
        from_user: "alice"
        to_domain: "auth-required.test"
      }
      actions: {"allow"}
    }

    -- Fallback : tout autoriser
    {
      description: "Autorisation par défaut"
      actions: {"allow"}
    }
  }
}
```

#### Règles par défaut (`filter.default_rules`)

`src/config.moon` fournit des **règles par défaut** préfixées aux `filter.rules`
de l'utilisateur (les `default_rules` d'abord, puis les `rules`). Elles sont
**autonomes** (domaines en ligne via `to_domains`, sans dépendre d'une liste
externe) et donc fonctionnelles dès l'installation :

1. `nxdomain` sur `use-application-dns.net` — désactive l'auto-DoH de Firefox.
2. `allow` (utilisateurs **authentifiés**, `from_user: "_any"`) sur l'ensemble
   canonique des sondes de connectivité — ouvre le pare-feu pour que la sonde
   réussisse (pas de portail).
3. `dnsonly` sur le même ensemble — résolution DNS seule pour les clients non
   authentifiés (la sonde HTTP est interceptée et redirigée vers le portail).

L'ensemble des sondes couvre **NCSI/MSFT** (`msftconnecttest.com`, `msftncsi.com`
— le match par suffixe couvre `dns.msftncsi.com`, `www.msftncsi.com`,
`www./ipv6.msftconnecttest.com`), ainsi qu'Apple, Google/Android, Firefox,
Ubuntu et KDE.

Pour **désactiver toutes** les règles par défaut : `filter: { default_rules: {} }`.
Pour **désactiver uniquement** la détection de portail captif (sondes NCSI/MSFT,
Apple, Google… — règles 2 et 3) tout en conservant le canari DoH :
`filter: { captive_portal: false }`. Pour **étendre**, ajouter ses propres règles
dans `filter.rules` (appliquées ensuite).

#### SafeSearch (`filter.safe_search`, `filter.youtube_restrict`)

Quand `safe_search` est actif (défaut), des règles par défaut supplémentaires
utilisant l'action générique `cname` **réécrivent la réponse DNS** des moteurs de
recherche vers leur variante « safe » :

| Moteur | Domaines (suffixe, sous-domaines inclus) | Cible CNAME |
|--------|------------------------------------------|-------------|
| Google | `google.com` + ccTLDs nationaux | `forcesafesearch.google.com` |
| YouTube | `youtube.com`, `youtube-nocookie.com`, `youtube(i).googleapis.com` | `restrictmoderate.youtube.com` (`moderate`) / `restrict.youtube.com` (`strict`) |
| Bing | `bing.com` | `strict.bing.com` |
| DuckDuckGo | `duckduckgo.com` | `safe.duckduckgo.com` |

La condition `to_domains` matche par **suffixe** (donc aussi `mail.google.com`,
`accounts.google.com`…), mais la réécriture CNAME ne s'applique **qu'aux hôtes
réellement concernés** par SafeSearch : le domaine lui-même et ses préfixes de
recherche `www.` / `m.` (champ `cname_names` des règles générées). Un
sous-domaine étranger (ex. `mail.google.com`) traverse donc le filtre sans être
réécrit. Pour une règle `cname` manuelle sans `cname_names`, le comportement
historique s'applique (tout nom matché est réécrit).

Le filtre répond par un enregistrement **CNAME** enrichi de RR `A`/`AAAA`
(TTL borné). Pour obtenir ces adresses, l'action réutilise en priorité les
`A`/`AAAA` de la cible **déjà présents dans la réponse upstream** (cas fréquent :
un résolveur amont — y compris DoH — qui applique lui-même SafeSearch renvoie
directement `forcesafesearch.google.com A …`). Si la cible n'y figure pas, elle
retombe sur une résolution directe en UDP/53 vers `doh.upstream_ipv4/ipv6`. Cette
priorité évite une requête redondante et fonctionne même quand l'upstream est
DoH-only ou que l'IPv6 amont est injoignable.
Le mécanisme passe par le callback `on_response` des actions : il couvre le DNS
clair **UDP et TCP** ainsi que le **DoH transitant par le worker doh** de Custos.
Mode YouTube réglable via `youtube_restrict`
(`"strict"`/`"moderate"`/`false`). Pour désactiver entièrement :
`filter: { safe_search: false }`.

Important : l'action `cname` est un effet de bord (réécriture) et ne modifie pas
le verdict ALLOW/DENY ; celui-ci dépend des autres actions de règles.

L'action `cname` est générique : on peut l'utiliser dans `filter.rules` pour
réécrire n'importe quel domaine, ex. :
`{ actions: {"cname"}, conditions: { to_domain: "exemple.fr" }, cname: "cible.exemple.fr" }`.
Pour restreindre la réécriture à des hôtes précis (et laisser les autres
sous-domaines intacts), ajouter `cname_names` (set `{ ["www.exemple.fr"]: true }`) :
seuls les noms présents dans ce set sont réécrits.

> Limite : n'agit que sur le DNS clair intercepté et le DoH passant par le worker
> doh ; un client utilisant un DoH/DoT tiers contourne la réécriture.

### 14.5 Logique de décision (`filter.decision`)

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `first_match_wins` | bool | `true` | Si `true` : la première règle avec un verdict gagne et arrête l'évaluation |
| `continue_to_next_rule` | bool | `false` | Si `true` : continue même après un match (le dernier verdict non-nil gagne) |

Avec les valeurs par défaut (`first_match_wins: true`, `continue_to_next_rule: false`),
l'évaluation s'arrête à la première règle dont toutes les conditions sont vraies.
Si aucune règle ne correspond, le verdict est `deny` (fail-closed).

---

## 16. Référence des conditions

Les conditions se placent dans le champ `conditions` d'une règle.
Elles sont combinées en **AND implicite** : toutes doivent être vraies pour que la règle s'applique.

Pour un **OU** entre conditions hétérogènes, utiliser `any_of`. Pour la négation, utiliser `not`.

**Variantes `_list` / `_lists`.** `from_xxx_list "nom"` lit
`{lists_dir}/{type}/nom.txt` (un élément par ligne) et `from_xxx_lists {…}` fait
un OU sur plusieurs fichiers. Le `{type}` est le nom de base après le premier
`_` : `from_net`→`net`, `from_mac`→`mac`, `from_vlan`→`vlan`,
`from_user`→`user`, `in_time`→`time`. Ces variantes ne sont **pas** une
référence à un groupe des dictionnaires `filter.nets` / `filter.macs` /
`filter.users` : ce sont des fichiers, dont chaque ligne est évaluée par la
condition de base (un alias de `filter.nets` pour `from_net`/`to_net`, de
`filter.macs` ou un nom de `filter.times` y est résolu). L'orthographe sans
tiret bas (`from_netlist`, `from_maclists`…)
n'existe pas : `compiler_api.load_condition` renvoie
`Condition '…' not found` et `src/filter/rule.moon:57` refuse la règle.

### Domaines DNS

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `to_domain` | `"example.com"` | Correspond au domaine exact et à tous ses sous-domaines |
| `to_domains` | `{"example.com","foo.com"}` | OU entre plusieurs domaines |
| `to_domainlist` | `"toulouse/malware"` | Correspond si le domaine est dans la liste compilée |
| `to_domainlists` | `{"toulouse/malware","ads"}` | OU entre plusieurs listes (inline) |
| `to_domainlist_list` | `"mon_groupe"` | **Groupe de domainlists** : fichier nommé listant des domainlists, une par ligne |
| `to_domainlist_lists` | `{"groupe_a","groupe_b"}` | OU entre plusieurs fichiers-groupes |

Le chemin d'une liste est relatif à `filter.domainlists_dir`.
`"toulouse/malware"` correspond au fichier `{domainlists_dir}/toulouse/malware.bin`
(ou `.domains` pour le format texte).

**Groupe de domainlists (`to_domainlist_list`)** — variante auto-générée pour
éviter de répéter le même `to_domainlists {a, b, c}` sur plusieurs règles. La
valeur est le nom d'un fichier `{lists_dir}/domainlist/{nom}.txt` (relatif à
`filter.lists_dir`, **distinct** de `domainlists_dir`) dont **chaque ligne est un
nom de domainlist** ; le domaine matche s'il appartient à l'une d'elles. Éditable
dans l'UI admin : règle → condition « Liste de domaines » → forme « Groupe de
listes (fichier nommé) », le fichier-groupe se gère sous
`/admin/config/filter/lists/domainlist/{nom}`.

### IP source

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `from_net` | `"10.0.0.0/8"` ou alias de `filter.nets` | CIDR IPv4 ou IPv6 (support nft natif), ou réseau nommé |
| `from_nets` | `{"10.0.0.0/8","fc00::/7"}` | OU entre plusieurs CIDRs |
| `from_subnet` | `"10.0.0.0/8"` ou `{net:"...",family:"inet"}` | CIDR avec famille explicite optionnelle |
| `from_subnets` | `{"10.0.0.0/8","172.16.0.0/12"}` | OU entre plusieurs subnets |
| `from_net_list` | `"lan"` | Lit `{lists_dir}/net/lan.txt` (un CIDR par ligne) |
| `from_net_lists` | `{"lan","private_ipv6"}` | OU entre plusieurs fichiers |

**Formats CIDR acceptés :**
- IPv4 : `"192.168.0.0/24"`, `"10.0.0.0/8"`, `"192.168.1.1"` (= /32)
- IPv6 : `"fc00::/7"`, `"2001:db8::/32"`, `"::1"` (= /128)

### IP destination

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `to_net` | `"192.168.0.0/24"` | CIDR de destination (support nft natif) |

### Adresse MAC

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `from_mac` | `"aa:bb:cc:dd:ee:ff"` ou un alias de `filter.macs` | Adresse MAC exacte (support nft natif) |
| `from_macs` | `{"aa:bb:...","11:22:..."}` | OU entre plusieurs MACs (alias acceptés) |
| `from_mac_list` | `"trusted"` | Lit `{lists_dir}/mac/trusted.txt` (une MAC ou un alias par ligne) |
| `from_mac_lists` | `{"trusted","iot"}` | OU entre plusieurs fichiers |

### VLAN

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `from_vlan` | `100` | VLAN ID exact (support nft natif) |
| `from_vlans` | `{100,101,102}` | OU entre plusieurs VLAN IDs |
| `from_vlan_list` | `"guests"` | Lit `{lists_dir}/vlan/guests.txt` (un ID par ligne) |
| `from_vlan_lists` | `{"guests","mgmt"}` | OU entre plusieurs fichiers |

### Fenêtres horaires

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `in_time` | `"business_hours"` | Référence un intervalle dans `filter.times` |
| `in_time` | `{start:"08:00",end:"18:00",days:{"Mon","Fri"}}` | Intervalle inline avec jours optionnels |
| `in_times` | `{"business_hours","weekend"}` | OU entre plusieurs fenêtres |
| `in_time_list` | `"fichier"` | Lit `{lists_dir}/time/fichier.txt` (un nom de fenêtre par ligne) |
| `in_time_lists` | `{"f1","f2"}` | OU entre plusieurs fichiers |

**Jours acceptés :** `"Sun"`, `"Mon"`, `"Tue"`, `"Wed"`, `"Thu"`, `"Fri"`, `"Sat"`.
Si `days` est absent, la fenêtre s'applique tous les jours.

### Utilisateur authentifié

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `from_user` | `"alice@example.com"` | Identifiant d'authentification (champ `user` de la session) |
| `from_user` | `{user:"alice",source:"tls"}` | Avec source d'authentification explicite |
| `from_users` | `{"alice","bob"}` | OU entre plusieurs utilisateurs |
| `from_user_list` | `"admins"` | Lit `{lists_dir}/user/admins.txt` (un identifiant par ligne) |
| `from_user_lists` | `{"admins","vip"}` | OU entre plusieurs fichiers |

**Sources d'authentification :**
- `"sessions_file"` (défaut) : sessions du portail captif
- `"tls"` : certificat client TLS

### Sécurité

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `stolen_computer` | `{"aa:bb:...","11:22:..."}` | Blacklist d'adresses MAC (machines volées/révoquées) |

### Méta-conditions

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `any_of` | `[{cond1}, {cond2}]` | OU logique entre conditions hétérogènes |
| `not` | `{from_vlan: 1}` | Négation d'une condition |

**Exemple `any_of` :**
```moonscript
conditions: {
  any_of: {
    {from_net_list: "lan"}
    {from_mac_list: "trusted"}
  }
}
```

**Exemple `not` :**
```moonscript
conditions: {
  not: {from_vlan: 100}
  to_domain: "example.com"
}
```

---

## 17. Référence des actions

Les actions se placent dans le champ `actions` d'une règle, sous forme de tableau ordonné.
La première action qui retourne un verdict non-nil (`true` ou `false`) gagne ;
les actions avec verdict `nil` sont des effets de bord purs (log, etc.) et l'évaluation continue.

### `allow`

Autorise la requête DNS. La réponse DNS est transmise et les IPs résolues sont
injectées dans les sets nftables `ip4_allowed` / `ip6_allowed` avec un timeout
calculé depuis le TTL DNS.

```moonscript
actions: {"allow"}
```

### `deny`

Bloque la requête DNS. Une réponse REFUSED est forgée (avec EDE code 4 si
applicable). Les IPs ne sont pas injectées dans nft.

```moonscript
actions: {"deny"}
```

### `dnsonly`

Autorise la résolution DNS mais **n'injecte pas** les IPs résolues dans nftables.
Utile pour les domaines de détection de portail captif ou de métriques qui ne
doivent pas ouvrir le pare-feu.

```moonscript
actions: {"dnsonly"}
```

### `validate`

Autorise la requête DNS **et la soumet au résolveur validateur** (second avis
DNS). Si le validateur répond NXDOMAIN, sinkhole ou CNAME (SafeSearch), la
réponse d'origine est spoofée en conséquence. Les IPs résolues sont injectées
dans nftables comme avec `allow`.

Sans cette action, la requête est transmise telle quelle sans interaction avec
le résolveur validateur.

Par défaut, utilise les résolveurs globaux de `second_opinion.resolvers`. Le
champ optionnel **`validate_resolvers`** permet de spécifier des IPs (v4/v6,
UDP/53) ou des URLs DoH (`https://…`) propres à la règle :

```moonscript
-- Résolveurs globaux (second_opinion.resolvers)
actions: {"validate"}

-- Résolveurs spécifiques à cette règle (IP UDP ou DoH https://)
actions: {"validate"}
validate_resolvers: {"94.140.14.15", "https://dns.quad9.net/dns-query"}
```

> **Comportement selon le worker :**
> - **worker_questions (UDP)** : duplique la requête via socket RAW ; corrélation
>   asynchrone dans `worker_responses`. Timeout `budget_ms`.
> - **worker_doh** : interrogation synchrone via `doh.validator` (pas de
>   duplication RAW). Endpoints DoH via libcurl ; timeout `doh_budget_ms`.
>   Fail-open si tous les validateurs sont injoignables.

Les résolveurs IP per-règle sont pré-armés au démarrage (sockets RAW ouverts,
familles vérifiées) et enregistrés dans `so_state` pour que `worker_responses`
puisse corréler leurs réponses.

### `dns_strip`

Autorise la résolution DNS mais supprime certains enregistrements de la réponse.
Par défaut, supprime les enregistrements `A` (IPv4). Configurable via `rr_type`.

```moonscript
-- Supprime les enregistrements AAAA (force IPv4)
actions: {
  {dns_strip: {rr_type: "AAAA"}}
}
```

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `rr_type` | string | `"A"` | Type d'enregistrement à supprimer : `"A"`, `"AAAA"`, `"CNAME"`, etc. |
| `follow_cname` | bool | `true` | Strippe aussi les requêtes **terminales** de la chaîne CNAME (cf. ci-dessous). Actif par défaut dès qu'une règle `dns_strip` existe ; passer à `false` rétablit l'ancien comportement coût-nul. |

#### `follow_cname` — strip contextuel à la chaîne CNAME

`dns_strip` matche sur le **nom de la question**. Or certains résolveurs
(systemd-resolved, et tout résolveur qui chase les CNAME lui-même) n'envoient
pas une seule requête sur le domaine racine : ils suivent la chaîne CNAME en
émettant des requêtes **séparées** dont la question est le **nom terminal** de
la chaîne (ex. `atm.outlook.mira.tm.svc.cloud.microsoft` pour
`smtp.office365.com`). Ce nom terminal n'étant pas couvert par `to_domains`, le
strip est contourné et les RR (ex. AAAA) repassent.

Avec `follow_cname: true`, quand `worker_responses` strippe la réponse d'un
domaine matché, il **enregistre les noms cibles CNAME** de la chaîne dans une
table à TTL court hébergée par le worker `mac_learner` (`mac_learner.strip_ttl`,
défaut 120 s ; cf. § 8). À chaque réponse ultérieure, `worker_responses`
interroge cette table par le nom de question ; si ce nom est une cible **vue
récemment via une chaîne buggée**, le strip s'applique aussi. Un nom interrogé
**sans** ce contexte (table vide / TTL expiré) n'est **jamais** strippé — les
usages directs légitimes de ces noms (hors chaîne) sont préservés.

```moonscript
-- Force IPv4 sur office365, y compris pour les résolveurs qui chasent les CNAME
{
  conditions: { to_domains: { "office365.com", "outlook.com", "office.com" } }
  actions: { "dns_strip" }
  dns_strip: { rr_type: "AAAA" }   -- follow_cname: true implicite
}
```

**Actif par défaut, opt-out via `follow_cname: false`** : recevoir un RR (ex.
AAAA) qu'on a justement demandé à supprimer est contre-intuitif ; le suivi de
chaîne est donc activé dès qu'une règle `dns_strip` existe. Le pipe dédié et la
table à TTL court ne sont alors créés que dans ce cas (toujours aucun coût sans
règle `dns_strip`). Pour retrouver l'ancien comportement strictement coût-nul
(aucune requête IPC sur le plan de données, mais strip contourné par les
résolveurs qui chasent les CNAME), poser explicitement `follow_cname: false`.
La consultation est mémoïsée localement (cache 2 s) pour borner les allers-retours
IPC sur le plan de données. Inutile (et déconseillé) d'ajouter les noms terminaux
à `to_domains` : `follow_cname` rend cet ajout superflu et, contrairement à lui,
préserve les usages directs hors chaîne.

### `log`

Enregistre un message dans les logs sans prendre de décision (verdict `nil`).
L'évaluation des actions suivantes continue.

```moonscript
actions: {
  {log: {log_msg: "Accès suspect détecté"}}
  "deny"
}
```

### Ordre d'évaluation des actions

```
[log]        verdict=nil  → continue
[log]        verdict=nil  → continue
[allow/deny] verdict=bool → STOP, retourne verdict
```

Actions multiples avec conditions partielles :

```moonscript
-- Log puis deny
actions: {
  {log: {log_msg: "Bloqué"}}
  "deny"
}

-- Log seulement si allow (log avant, allow après)
actions: {
  {log: {log_msg: "Autorisé"}}
  "allow"
}
```
