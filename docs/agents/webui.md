# Interface admin web

## Interface admin web (`src/webui/`)

Servie par le worker AUTH (`src/auth/server.moon` `require "webui.router"`) sous
`/admin/*`, derrière le portail captif **et** une vérification de session admin
(`auth.admin_users`, `admin_auth.moon`). Permet d'éditer la config (`config.moon`
relu/réécrit via `webui/serializer.moon`), les règles, les dictionnaires nommés
(`nets`/`macs`/`users`/`times`), les listes, et de déclencher un reload SIGHUP.

**Reload SIGHUP — cible obligatoire : le superviseur.** Seul le superviseur
(`main.moon`) traite SIGHUP pour le hot-reload de la config (relecture +
recompilation des règles + kill/refork des workers DNS/resp/captive/reject/DoH/SNI ;
il ne fait que **transmettre** SIGHUP au worker AUTH pour relire les secrets). La
webui s'exécute dans un enfant `AUTH-conn` (petit-enfant du superviseur), donc
`getppid()` viserait le **worker AUTH** → seuls les secrets seraient relus, jamais
les règles (bug du bouton « Recharger maintenant »). Le PID cible provient donc du
**pidfile** `/var/run/custos.pid`, écrit par le superviseur au démarrage et supprimé
à l'arrêt (`src/lib/pidfile.moon`, chemin surchargeable via `runtime.pid_file` ou
env `CUSTOS_PID_FILE`). `handle_reload` (`system.moon`) et `default_reload`
(`devices.moon`) lisent ce pidfile ; `custos-update` l'utilise déjà. `handle_reload`
accepte `state.kill_fn` injectable (tests).

**POST de section = fusion sur les clés du schéma.** `handle_config_section_post`
(`handlers/config.moon`) ne remplace que les clés non `_` déclarées dans
`config_schema[section]` ; les clés hors schéma de la section existante sont
préservées telles quelles (`auth.admin_users`/`admin_allow_all_when_empty`,
`dns.upstream_retry`, `nft.extra_rules`…). Une clé du schéma rendue `nil` par
`build_section` reste supprimée. Ne jamais revenir à un remplacement de section
entier : effacer `admin_users` le fait retomber sur `{}` + `admin_allow_all_when_empty
= true` au rechargement, rendant tout utilisateur authentifié admin.

**Échappement HTML : `webui.util` est la source unique.** Le DSL `auth.html`
n'échappe ni le texte ni les attributs ; `webui.util.esc` (`&`, `<`, `>`, `"`,
`'`, nil → `""`) doit être appliqué à **toute** valeur de config ou de requête
injectée dans du HTML (règles, champs de section, titres `page`), et
`webui.util.parse_form` est le décodeur urlencodé commun des handlers.

Les champs scalaires de `filter` (SafeSearch, YouTube Restricted, `allow_localnets`,
`captive_portal`, `domainlists_dir`, `dest_whitelist`, `allowed_domains`…) sont
édités par `handle_filter_general_get/post` : ils parcourent `config_schema.filter`
en ignorant les types `named_map`/`rules_list` et la sous-table `decision`, et ne
réécrivent que ces clés sans toucher au reste de `filter`. Dans l'index config
(`/admin/config/`) ils s'affichent comme un `<details>` replié inline
(`#section-filter-general`), cohérent avec les autres sections scalaires ; la
page autonome `/admin/config/filter/general` reste accessible. Les éditeurs
spécialisés (règles, listes, décision, nets, macs, users, times) gardent des
pages dédiées car ils ont leurs propres formulaires multi-lignes — l'index les
liste sous « Filtre DNS — éditeurs dédiés ».

- Routeur + dispatch : `src/webui/router.moon`
- Handlers : `src/webui/handlers/{dashboard,system,config,filter,rules,lists,devices,admin_auth}.moon`
- Sérialisation MoonScript : `src/webui/serializer.moon` (+ `schema/`). `serializer`
  écrit du **MoonScript** (`{ clé: valeur }`), pas du Lua, pour rester cohérent
  avec les `config.moon` écrits à la main.

### Éditeur de règles — réordonnancement drag-and-drop (`handlers/rules.moon`)

`handle_rules_list` rend chaque ligne `draggable` avec `data-idx` (index 1-based
d'origine) et une poignée `⠿`. Un `H.script RULES_REORDER_JS` (JS vanilla inline,
sans dépendance, motif `MODAL_JS`) réordonne les `<tr>` du `<tbody id="rules-tbody">`
au glisser-déposer puis soumet `#reorder-form` (POST
`/admin/config/filter/rules/reorder`, champ `order` = permutation des `data-idx`
séparés par virgule). `handle_rules_reorder` **valide une permutation exacte de
`1..#rules`** (longueur, bornes, pas de doublon → sinon `400` sans écriture),
reconstruit `cfg.filter.rules` dans le nouvel ordre et `write_config`. Les boutons
↑/↓ (`handle_rules_move`) restent le repli sans JavaScript.

**Désactivation de règle (`enabled = false`).** Une règle peut porter `enabled =
false` (défaut `true`/absent = active) pour la neutraliser sans la supprimer :
`filter.rule.compile_rule` la compile en **entité inerte** (eval ne matche
jamais, métadonnées vides marquées `metadata.enabled = false`) plutôt que de la
sauter — l'alignement des index `rules_metadata[idx]`, des `rule_id` et du
réordonnancement est ainsi préservé. `nft_compiler.compile` la **saute** via le
même drapeau (`rules_cfg[idx].enabled == false`) : aucune sortie `action_map`,
sets dynamiques ni `plan_rules`. Côté webui, `handle_rules_toggle` (POST
`/admin/config/filter/rules/:n/toggle`) bascule la clé (false ↔ retirée) ;
`handle_rules_edit_post` **préserve** `enabled = false` (rebuild_rule ne connaît
pas cette clé hors formulaire) ; la liste marque la ligne `(désactivée)`.

### Page « Appareils » (`src/webui/handlers/devices.moon`)

`GET/POST /admin/config/devices` facilite l'enregistrement des clients réseau.
Elle lit `recent-verdicts.tsv` (ring-buffer unique écrit par `worker_events`, cf.
[.agents/workers.md](.agents/workers.md)) via `read_devices`, qui **agrège les
verdicts par MAC** (1ʳᵉ occurrence = dernier verdict, `count` sommé, `first_ts`
min / `last_ts` max), et affiche un tableau
triable/filtrable (JS inline, sans dépendance) des appareils vus : Nom, MAC, IP,
user, dernier domaine, décision, vus, dernière activité. La colonne **Nom** est
remplie par recoupement avec `filter.macs` (`mac_name_index`, map inverse
MAC→nom) ; une mini-form POST `{mac, name}` (champ texte pré-rempli si déjà
nommé, bouton « + ») permet de l'ajouter **ou de renommer** un appareil existant.
`handle_devices_post` valide la MAC, retire d'abord tout nom string pointant déjà
vers cette MAC (renommage idempotent), écrit
`cfg.filter.macs[name] = mac` (**string unique**, pas une liste) puis recharge via
`state.reload` (SIGHUP ; injectable pour les tests). Le DSL `auth.html`
n'échappant rien, `devices.moon` échappe lui-même les valeurs (`esc`).

**Contrat `filter.macs` = nom→MAC unique** (pas une liste) : `from_mac.moon` fait
`(mac_map[alias] or alias)\lower!`, qui plante sur une table. L'éditeur
`MACs nommées` (`handle_macs_post`, `is_list_value=false`) et le schéma
(`config_schema.macs.value_type = "string"`) sont alignés sur ce contrat. Un alias
ainsi défini est résoluble dans `from_macs {…}` / `from_mac_list` (chaque entrée
passe par `from_mac` via `make_plural`), mélangeable avec des MAC brutes.

### Page « Verdicts » (`src/webui/handlers/verdicts.moon`)

`GET /admin/config/verdicts` (lecture seule, pas de POST) liste **tous** les
derniers verdicts DNS (allow ET block) lus depuis `recent-verdicts.tsv` via
`read_verdicts` (une ligne par verdict, **sans** agrégation, contrairement à la
page Appareils). Même UX que « Appareils » : recherche plein-texte + tri par clic
d'en-tête (JS inline, ids `verdtbl`/`verdfilter`), valeurs échappées via `esc`.
Colonnes : **MAC / IP** (fusionnées dans une cellule à deux lignes via `mac_cell`,
+ le nom de l'appareil sur une 3ᵉ ligne s'il est défini), User, Domaine, Décision,
Raison, Vus, Première, Dernière. Le nom est résolu par `name_by_mac_for` qui
applique `bidirectional` (ipparse.fun) à `filter.macs` (nom→MAC) pour obtenir
l'accès inverse MAC→nom sans construire d'index explicite. Classe CSS `.muted`
(`webui/css.moon`) pour l'IP secondaire. La cellule MAC/IP porte aussi un
**mini-formulaire d'édition du nom** (`name_form`, pré-rempli si la MAC est déjà
nommée) qui **réutilise `handle_devices_post`** : il poste vers
`/admin/config/devices` avec un champ caché `redirect=/admin/config/verdicts`.
`handle_devices_post` ne redirige que vers une cible de sa `REDIRECT_WHITELIST`
(`/admin/config/devices` ou `/admin/config/verdicts`, anti open-redirect), défaut
`devices`. Aucune route POST propre à Verdicts n'est donc nécessaire.

**Détail par appareil (modale / popup).** Dans les deux tableaux (Appareils ET
Verdicts), chaque ligne porte `data-mac` et une cellule « Détails » (lien
`a.vdetail` → `GET /admin/config/verdicts?mac=<MAC>`, `target="_blank"`). Avec ce
paramètre `mac`, `handle_verdicts_get` rend une **vue détail** (`detail_section`,
conteneur `#verd-detail`) listant uniquement les verdicts de cette MAC. `MODAL_JS`
(JS partagé, défini dans `devices.moon` avec `detail_cell`/`modal_dialog` —
`verdicts.moon` en dépend déjà, pas de cycle) intercepte le clic sur la ligne (hors
formulaire de nom) ou sur le lien, `fetch` cette URL et injecte `#verd-detail`
dans un `<dialog id="vmodal">` (modale). **Sans JS**, le lien ouvre simplement la
page filtrée (popup `_blank`). Le routeur (`webui/router.moon`) sépare désormais la
query string du chemin (`webui.util.parse_form`) et expose `req.query` aux handlers ; le
matching de route reste sur le **chemin nu**.

**Déconnexion admin.** Le lien « Déconnexion » de `dashboard.moon` pointe vers
`/logout` (route GET du portail, `auth/handlers.moon`) : `/admin/logout` n'existe
pas et retombait sur la redirection du routeur webui.

**Listes — pas d'écrasement silencieux.** `handle_list_new_post` et le
renommage de `handle_list_post` (`handlers/lists.moon`) répondent **409** si le
fichier cible existe déjà (hors renommage vers le même nom) : la cible n'est
jamais écrasée.

