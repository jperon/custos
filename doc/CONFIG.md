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

```moonscript
runtime: {
  log_level: "DEBUG"
  benchmark: false
  gc_pause: 110      -- machines à faible RAM (128 Mo) ; 200 = défaut LuaJIT
  gc_stepmul: 400
}
```

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
>   queue (cf. [section `nfqueue`](#3-section-nfqueue)).
>
> Ces réglages relèvent du déploiement (config), pas d'un « mode » dédié : custos
> n'adapte rien automatiquement selon la RAM disponible.

---

## 3. Section `nfqueue`

Définit les numéros (ou plages) des files NFQUEUE utilisées par les workers.
Chaque entrée correspond à un worker distinct qui lit depuis le noyau Linux.

| Clé | Type | Défaut | Worker |
|-----|------|--------|--------|
| `questions` | string | `"0-1"` | Questions DNS entrantes |
| `responses` | string | `"4"` | Réponses DNS à réinjecter |
| `captive` | string | `"20"` | Détection portail captif (TCP/80) |
| `reject` | string | `"10-11"` | Paquets à rejeter (RST/ICMP) |
| `auth` | string | `"5"` | Authentification HTTPS |
| `sni` | string | `"6"` | Verdict SNI TLS/QUIC (443) |
| `sip` | string | `"12"` | Trafic SIP/VoIP |

Une plage (ex. `"0-1"`) permet à plusieurs threads de traiter la même queue en
parallèle.

```moonscript
nfqueue: {
  questions: "0-1"
  responses: "4"
  captive:   "20"
  reject:    "10-11"
  auth:      "5"
  sni:       "6"
  sip:       "12"
}
```

> **Réduire l'empreinte mémoire.** Chaque numéro de queue = **un worker forké**
> (un processus LuaJIT). Le coût RAM de custos est essentiellement linéaire au
> nombre de workers (tas GC, code JIT, buffers FFI propres à chaque processus) —
> pas aux listes, qui sont partagées via `mmap`. Sur une machine contrainte, on
> peut **ramener chaque plage à une seule queue** (p. ex. `questions: "0"`,
> `reject: "10"`) : on perd le traitement parallèle (débit moindre sous forte
> charge) mais on économise un processus par queue supprimée (~3 à 8 Mo chacun).
> Voir aussi la note « RAM faible » de la section [`runtime`](#2-section-runtime).

---

## 4. Section `dns`

Paramètres du traitement DNS.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `port` | int | `53` | Port DNS écouté (bridge intercept) |
| `ttl_grace.grace` | int | `600` | Secondes ajoutées au TTL DNS dans les sets nft |
| `ttl_grace.min` | int | `60` | TTL minimum accepté (en secondes) |
| `ttl_grace.max` | int | `2592000` | TTL maximum accepté (30 jours, en secondes) |

Le TTL effectif injecté dans nftables est `clamp(dns_ttl + grace, min, max)`.

```moonscript
dns: {
  port: 53
  ttl_grace: {
    grace: 600
    min:   60
    max:   2592000
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
| `set_ip4` | string | `"ip4_allowed"` | Nom du set nft IPv4 |
| `set_ip6` | string | `"ip6_allowed"` | Nom du set nft IPv6 |
| `set_mac4` | string | `"mac4_allowed"` | Nom du set nft MAC→IPv4 |
| `set_mac6` | string | `"mac6_allowed"` | Nom du set nft MAC→IPv6 |
| `ip_timeout` | string | `"2m"` | Durée de vie des éléments dans les sets IP |
| `sip_session_ttl` | string | `"5m"` | Durée de vie des sessions SIP |
| `add_backoff_ms` | array | `{20,50,200,400,800,2000}` | Délais (ms) entre chaque tentative — la longueur du tableau détermine le nombre de tentatives |
| `add_failure_policy` | string | `"fail-closed"` | Comportement si tous les retry échouent : `"fail-closed"` bloque, `"fail-open"` laisse passer |
| `ack_timeout_ms` | int | `150` | Timeout (ms) d'attente d'acquittement nft |
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

La clé de corrélation est `txid:ip:port` (ID de transaction DNS + IP source + port source).

---

## 7. Section `clients`

Gestion du cache client-side.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `expiry` | int | `300` | Durée (s) avant expiration d'une entrée client |

---

## 8. Section `mac_learner`

Apprentissage des adresses MAC via un socket Unix.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `query_sock` | string | `"/var/run/custos/mac_query.sock"` | Chemin du socket IPC |
| `entry_ttl` | int | `900` | Durée (s) de conservation d'une entrée MAC apprise |

---

## 9. Section `auth`

Portail captif et authentification des utilisateurs.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `host` | string | `"::"` | Adresse d'écoute du serveur auth (`::`= toutes interfaces IPv4+IPv6) |
| `port` | int | `33443` | Port HTTPS du serveur d'authentification |
| `captive_port` | int | `33080` | Port HTTP du portail captif |
| `cert` | string | — | Chemin vers le certificat TLS (optionnel si px5g activé) |
| `key` | string | — | Chemin vers la clé privée TLS (optionnel si px5g activé) |
| `secrets` | string | `"/etc/custos/secrets"` | Répertoire contenant les secrets (hash mots de passe) |
| `session_ttl` | int | `0` | Durée (s) des sessions auth (0 = illimitée) |
| `sessions_file` | string | `"/tmp/sessions.lua"` | Fichier de persistance des sessions |
| `heartbeat_interval` | int | `30` | Intervalle (s) entre heartbeats client |
| `idle_timeout` | int | `120` | Inactivité maximale (s) avant déconnexion |
| `register_rate_limit` | int | `3` | Enregistrements maximum par fenêtre |
| `register_rate_window` | int | `300` | Fenêtre de rate-limiting (s) |
| `bridge_ifname` | string | `"br0"` | Nom de l'interface bridge (utilisé pour la détection MAC) |
| `redirect_url` | string | — | URL de redirection après authentification (optionnel) |
| `admin_users` | array | `{}` | Liste des utilisateurs avec droits administrateur (interface `/admin/*`) |
| `admin_allow_all_when_empty` | bool | `true` | Si `true` et `admin_users` vide, tous les utilisateurs authentifiés sont admin |

```moonscript
auth: {
  host: "::"
  port: 33443
  captive_port: 33080
  cert: "/etc/custos/certs/auth.crt"
  key:  "/etc/custos/keys/auth.key"
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
| `cert_path` | string | `nil` | Chemin certificat TLS (optionnel) |
| `key_path` | string | `nil` | Chemin clé privée TLS (optionnel) |
| `prefer_ipv6` | bool | `true` | Préférer IPv6 pour les requêtes amont |

---

## 12. Section `events`

Stockage des événements système (journaux d'activité).

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `dir` | string | `"/tmp/custos/events"` | Répertoire de stockage des événements |
| `max_age_hours` | int | `168` | Conservation maximale (heures) — 168h = 7 jours |
| `min_free_pct` | int | `30` | Pourcentage d'espace disque libre minimum avant purge |

---

## 13. Section `metrics`

Collecte de métriques internes.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `enabled` | bool | `true` | Active la collecte de métriques |
| `flush_interval` | int | `60` | Intervalle (s) de vidange des métriques |
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
| `domainlists_dir` | string | `"/etc/custos/lists"` | Répertoire racine des listes de domaines compilées |
| `custom_lists_dir` | string | `nil` | Répertoire des listes personnalisées (optionnel) |
| `allow_localnets` | bool | `false` | Si `true`, injecte automatiquement les réseaux locaux en whitelist nft |
| `dest_whitelist` | array | `{}` | IPs/CIDRs de destination toujours autorisées (bypass filtrage) |
| `allowed_domains` | array | `{"local","lan","home.arpa"}` | Domaines autorisés par défaut si `rules` est vide |

### 14.2 Dictionnaires nommés : `nets`, `macs`, `times`, `vlans`, `users`

Ces dictionnaires permettent de nommer des groupes réutilisables dans les conditions.

#### `filter.nets` — Groupes de réseaux IP

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

Référencés via `from_netlist: "lan"` ou `from_netlists: {"lan", "private_ipv6"}`.

#### `filter.macs` — Groupes d'adresses MAC

```moonscript
filter: {
  macs: {
    trusted: {
      "aa:bb:cc:dd:ee:ff"
      "11:22:33:44:55:66"
    }
    iot_devices: { "00:1a:2b:3c:4d:5e" }
  }
}
```

Référencés via `from_maclist: "trusted"`.

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

Référencées via `in_time: "business_hours"`.

#### `filter.vlans` — Groupes de VLAN

```moonscript
filter: {
  vlans: {
    management: {10, 20}
    guests:     {100, 101}
  }
}
```

Référencés via `from_vlanlist: "guests"`.

#### `filter.users` / `filter.userlists` — Utilisateurs authentifiés

Associe un identifiant court à un email ou un identifiant d'authentification.
`userlists` est un alias de `users` (les deux sont synchronisés au chargement).

```moonscript
filter: {
  users: {
    alice: "alice@example.com"
    bob:   "bob@example.com"
  }
}
```

Référencés via `from_user: "alice"`.

### 14.3 Sources de listes de domaines (`filter.sources`)

Définit d'où proviennent les listes de domaines et comment elles sont téléchargées/compilées.
Utilisé par `make update-lists` / `custos-update`.

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

Les fichiers `.bin` sont des tables de hachage XXH64 (format binaire compact).
L'outil de conversion est `lua/filter/convert.lua`.

### 14.4 Règles de filtrage (`filter.rules`)

Tableau ordonné de règles. Chaque règle est une table avec :

```moonscript
{
  description: "Texte libre (affiché dans les logs)"
  conditions:  { ... }   -- toutes doivent être vraies (AND implicite)
  actions:     { ... }   -- évaluées en séquence, première avec verdict gagne
}
```

Une règle sans `conditions` s'applique à toute requête (catch-all).

#### Exemple complet

```moonscript
filter: {
  rules: {
    -- Blocage des menaces connues pour le LAN
    {
      description: "Blocage malware/phishing LAN"
      conditions: {
        from_netlist: "lan"
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

### Domaines DNS

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `to_domain` | `"example.com"` | Correspond au domaine exact et à tous ses sous-domaines |
| `to_domains` | `{"example.com","foo.com"}` | OU entre plusieurs domaines |
| `to_domainlist` | `"toulouse/malware"` | Correspond si le domaine est dans la liste compilée |
| `to_domainlists` | `{"toulouse/malware","ads"}` | OU entre plusieurs listes |

Le chemin d'une liste est relatif à `filter.domainlists_dir`.
`"toulouse/malware"` correspond au fichier `{domainlists_dir}/toulouse/malware.bin`
(ou `.domains` pour le format texte).

### IP source

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `from_net` | `"10.0.0.0/8"` | CIDR IPv4 ou IPv6 (support nft natif) |
| `from_nets` | `{"10.0.0.0/8","fc00::/7"}` | OU entre plusieurs CIDRs |
| `from_subnet` | `"10.0.0.0/8"` ou `{net:"...",family:"inet"}` | CIDR avec famille explicite optionnelle |
| `from_subnets` | `{"10.0.0.0/8","172.16.0.0/12"}` | OU entre plusieurs subnets |
| `from_netlist` | `"lan"` | Référence un groupe dans `filter.nets` |
| `from_netlists` | `{"lan","private_ipv6"}` | OU entre plusieurs groupes |

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
| `from_mac` | `"aa:bb:cc:dd:ee:ff"` | Adresse MAC exacte (support nft natif) |
| `from_macs` | `{"aa:bb:...","11:22:..."}` | OU entre plusieurs MACs |
| `from_maclist` | `"trusted"` | Référence un groupe dans `filter.macs` |
| `from_maclists` | `{"trusted","iot"}` | OU entre plusieurs groupes |

### VLAN

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `from_vlan` | `100` | VLAN ID exact (support nft natif) |
| `from_vlans` | `{100,101,102}` | OU entre plusieurs VLAN IDs |
| `from_vlanlist` | `"guests"` | Référence un groupe dans `filter.vlans` |
| `from_vlanlists` | `{"guests","mgmt"}` | OU entre plusieurs groupes |

### Fenêtres horaires

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `in_time` | `"business_hours"` | Référence un intervalle dans `filter.times` |
| `in_time` | `{start:"08:00",end:"18:00",days:{"Mon","Fri"}}` | Intervalle inline avec jours optionnels |
| `in_times` | `{"business_hours","weekend"}` | OU entre plusieurs fenêtres |

**Jours acceptés :** `"Sun"`, `"Mon"`, `"Tue"`, `"Wed"`, `"Thu"`, `"Fri"`, `"Sat"`.
Si `days` est absent, la fenêtre s'applique tous les jours.

### Utilisateur authentifié

| Condition | Valeur | Description |
|-----------|--------|-------------|
| `from_user` | `"alice"` | Utilisateur identifié dans `filter.users` |
| `from_user` | `{user:"alice",source:"tls"}` | Avec source d'authentification explicite |
| `from_users` | `{"alice","bob"}` | OU entre plusieurs utilisateurs |
| `from_userlist` | `"admins"` | Référence un groupe dans `filter.users` |

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
    {from_netlist: "lan"}
    {from_maclist: "trusted"}
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
