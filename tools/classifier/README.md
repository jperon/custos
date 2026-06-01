# classifier — classification automatique de noms de domaines

Outil autonome (conçu pour tourner en Docker, typiquement sur un serveur) qui classe
des noms de domaines dans les catégories de listes de CustosVirginum, en s'appuyant sur
une IA (OpenRouter) et un navigateur headless (Playwright) pour découvrir les domaines
tiers réellement contactés par un site.

## Pipeline

1. **Découverte des catégories** : `ls <lists-dir>/*.txt` → liste des catégories
   existantes (ex. `ads`, `cdn`, `news`, `religious`…).
2. **Lecture des domaines** : un fichier texte fourni par l'utilisateur, 1 domaine par
   ligne (`#` = commentaire).
3. **Classification IA** : la liste est découpée en **lots** de `--batch-size`
   domaines (défaut 50), chaque lot faisant une requête OpenRouter demandant, au
   format JSON, à quelles catégories **existantes** appartient chaque domaine
   (plusieurs possibles). Si le moteur renvoie **une catégorie inexistante**, c'est le
   signe d'un moteur sous-optimal : la réponse du lot est **rejetée** et la requête
   **relancée en excluant ce provider** (jusqu'à `--max-retries` fois).
4. **Écriture** : chaque domaine (validé via `is_valid` du projet → rejette IP,
   labels malformés…) est ajouté à `<lists-dir>/<catégorie>.txt`. Le fichier est
   **dédupliqué (insensible à la casse) et trié alphabétiquement** ; les commentaires
   (`#`) sont conservés en tête.
5. **Navigation** : pour chaque domaine d'entrée, Chromium charge le site et enregistre
   un HAR ; les domaines tiers contactés sont extraits puis classés à leur tour, avec le
   contexte « contactés en chargeant `<site>` » — un CDN ira dans `cdn`, une régie pub
   dans `ads`, etc., pas forcément la catégorie du site père.
6. **Compilation `.bin`** : chaque `<lists-dir>/<cat>.txt` est compilé en
   `<bin-dir>/<cat>.bin` (tableau trié de hashs xxh64, **octet-pour-octet identique** à
   ce que produit `src/filter/updater.moon`). Les filtres peuvent récupérer ces `.bin`
   prêts à l'emploi.
7. **Commit git** automatique (`.txt` + `.bin`), **sans push**.

### Robustesse

- **Reprise après interruption** : le fichier d'entrée est réécrit après chaque lot
  traité (domaines classés retirés). Relancer la même commande reprend où ça s'était
  arrêté.
- **Arrêt de sécurité** : après **10 appels IA en échec consécutifs** (réseau, HTTP,
  JSON…), le traitement s'interrompt et le programme sort en code **1** (le travail déjà
  fait est committé, l'entrée ne garde que le reste). Un appel réussi remet le compteur
  à zéro.
- **Erreurs explicites** : en cas d'échec d'un appel, le **code HTTP** et le **corps
  d'erreur** de l'API (ou le message réseau de curl) sont remontés tels quels.
- **Round-robin de modèles** : si `CLASSIFIER_MODEL`/`--model` liste plusieurs modèles
  (séparés par des virgules), les lots tournent sur les modèles et une **erreur 429**
  (rate limit) bascule immédiatement sur le suivant au lieu de réitérer.

## Build

Le contexte de build doit être la **racine du dépôt** custos :

```sh
docker build -f tools/classifier/Dockerfile -t custos-classifier .
```

## Utilisation

```sh
docker run --rm \
  --env-file .env \
  -v "$PWD/lists:/work/lists" \
  -v "$PWD/domains.txt:/work/domains.txt" \
  custos-classifier /work/domains.txt
```

- `lists/` est le dépôt git de listes monté en volume (le commit est créé dedans).
- `domains.txt` contient les domaines à classer. **Il doit être inscriptible** (pas de
  `:ro`) : après chaque lot traité, les domaines déjà classés en sont retirés, si bien
  qu'une **reprise après interruption** ne retraite que ce qui reste.
- La configuration (clé/URL/modèle) vient d'un fichier `.env` (`--env-file .env`) ou de
  `-e VAR=…`. On peut aussi monter le `.env` dans `/work` (`-v "$PWD/.env:/work/.env:ro"`).
- Pour un autre fournisseur, renseigner `CLASSIFIER_API_URL`, `CLASSIFIER_API_KEY` et
  `CLASSIFIER_MODEL` (cf. [`.env.example`](.env.example)).

> Note : l'exclusion de provider lors d'un retry (`provider.ignore`) est propre à
> OpenRouter ; les autres endpoints OpenAI-compatibles ignorent ce champ sans erreur.

### Options de `classifier.moon`

| Option | Défaut | Rôle |
|--------|--------|------|
| `<domains-file>` | — | Fichier de domaines (positionnel, requis) |
| `--lists-dir DIR` | `lists` | Répertoire des listes `.txt` |
| `--bin-dir DIR` | = `--lists-dir` | Répertoire de sortie des `.bin` |
| `--model NAMES` | `openrouter/free` | Modèle(s), séparés par des virgules → round-robin (cf. ci-dessous) |
| `--batch-size N` | `50` | Domaines par requête IA (découpage en lots) ; `0` = tout d'un coup |
| `--max-retries N` | `3` | Tentatives max si le moteur renvoie une catégorie inconnue |
| `--no-browse` | — | Désactive l'étape 5 (navigation) |
| `--no-bin` | — | Désactive l'étape 6 (compilation `.bin`) |
| `--no-commit` | — | Désactive l'étape 7 (commit git) |
| `--normalize-all` | — | Déduplique + trie **toutes** les listes (assainissement ponctuel) |
| `--no-simplify` | — | Désactive la simplification auto (étape 5bis) des catégories enrichies |
| `--simplify-min-children N` | `3` | Seuil de sous-domaines pour proposer un repli lors de la simplification |

### Variables d'environnement

- `CLASSIFIER_API_KEY` — clé API (repli accepté : `OPENROUTER_API_KEY`).
- `CLASSIFIER_API_URL` — endpoint *chat/completions* (API OpenAI-compatible). Défaut :
  OpenRouter. Permet d'utiliser OpenAI, Groq, un serveur local (Ollama), etc.
- `CLASSIFIER_MODEL` — modèle(s) par défaut (repli : `openrouter/free`) ; `--model` prime.
  **Plusieurs modèles séparés par des virgules** activent un **round-robin** : chaque lot
  démarre sur le modèle suivant, et en cas d'**erreur 429** (rate limit) classifier
  bascule sur un autre modèle plutôt que de réessayer le même. Ex. :
  `CLASSIFIER_MODEL=modele-a:free, modele-b:free`.
- `CLASSIFIER_ENV` — chemin du fichier `.env` à charger (défaut : `./.env`).
- `CUSTOS_LUA` — chemin du `lua/` compilé du projet (défini par l'image Docker ;
  utile aussi pour un usage hors Docker).

Ces variables peuvent être posées dans un fichier **`.env`** (format `KEY=VALUE`, voir
[`.env.example`](.env.example)) chargé automatiquement depuis le répertoire de travail
(`/work/.env` en Docker), ou passées directement. Les variables réelles de
l'environnement (`docker -e`, `export`) restent prioritaires sur le `.env`. Le `.env`
est gitignoré et exclu de l'image (`.dockerignore`).
- `GIT_AUTHOR_NAME` / `GIT_AUTHOR_EMAIL` — identité des commits automatiques
  (défaut : `custos-classifier` / `classifier@custos.local`).

> **Commit & volume monté.** Le dépôt de listes est le volume monté lui-même
> (`/work/lists`). Comme il appartient à l'uid de l'hôte, les commandes git sont
> lancées avec `-c safe.directory='*'` pour éviter le refus « dubious ownership ».

## Usage hors Docker

Nécessite : `moon` (MoonScript), `luajit`, `python3` + `playwright` (`playwright
install chromium`), `libxxhash`, `curl`, `git`, et le `lua/` du projet compilé
(`make all`). Exemple :

```sh
export OPENROUTER_API_KEY=sk-or-...
export CUSTOS_LUA="$PWD/lua"
moon tools/classifier/classifier.moon domains.txt --lists-dir lists
```

> **Intégration dans classifier.** Avant de compiler les `.bin` (étape 6),
> classifier **simplifie automatiquement** les catégories qu'il vient d'enrichir
> (cf. ci-dessous) : suppression des sous-domaines redondants + repli IA. Désactivable
> avec `--no-simplify` ; seuil ajustable via `--simplify-min-children N` (défaut 3).

## simplifier — repli des sous-domaines vers leur parent

`simplifier.moon` est un second outil, **partageant l'infrastructure de classifier**
(`common.moon` : chargement `.env`, appel IA, écriture des listes, compilation `.bin`,
commit git ; `simplify.moon` : cœur d'orchestration réutilisé par les deux outils).
Son objet : **raccourcir** les listes en remplaçant des grappes de sous-domaines
par leur domaine parent. Exemple :

```
sun1-13.userapi.com   sun1-16.userapi.com   sun1-19.userapi.com   …
        →   userapi.com
```

C'est valide car custos autorise un domaine **et tous ses sous-domaines**
(cf. `to_domainlist`) : replier vers le parent est équivalent côté correspondance.

**Mais tout n'est pas repliable.** `userapi.com` est anodin ; en revanche sur
`google.com` on peut vouloir autoriser `mail.google.com` tout en bloquant
`www.google.com` et `google.com` lui-même. La décision « replier ou non ce parent »
est donc confiée à une **IA** (même back-end qu'classifier).

### Pipeline

1. **Catégories** : `ls <lists-dir>/*.txt` (restreint à `<list-name>` si fourni en
   argument positionnel).
2. **Redondance « gratuite »** (sans IA) : tout sous-domaine dont un **ancêtre est
   déjà présent dans la même liste** est supprimé d'office (ex. si `userapi.com`
   figure dans la liste, `sun1-13.userapi.com` y est inutile — déjà couvert). C'est
   une équivalence stricte côté correspondance : aucune décision n'est requise.
3. **Parents candidats** : sur les domaines restants, on calcule les suffixes
   (≥ 2 labels) couvrant au moins `--min-children` domaines, en ne gardant que les
   **maximaux** (le plus large l'emporte : si `c.net` et `b.c.net` sont candidats,
   seul `c.net` est proposé). Logique pure dans `simplify_lib.moon`.
4. **Jugement IA** : par lots de `--batch-size`, l'IA répond `true`/`false` par
   parent (sûr de tout replier, ou non). Round-robin de modèles + bascule sur 429,
   comme classifier ; une réponse incomplète/non booléenne est rejetée et relancée
   sur un autre provider.
5. **Réécriture** : redondants (étape 2) et sous-domaines repliés (étape 4) sont
   retirés, les parents approuvés (ré)ajoutés ; la liste est dédupliquée et triée.
6. **Compilation `.bin`** des seules catégories modifiées (mêmes hashs que classifier).
7. **Commit git** automatique (pas de push).

### Utilisation

```sh
# Toutes les catégories (image classifier, entrypoint surchargé) :
docker run --rm --env-file .env \
  --entrypoint luajit \
  -v "$PWD/lists:/work/lists" \
  custos-classifier /opt/custos/tools/classifier/simplifier.lua --lists-dir /work/lists

# Une seule catégorie, en simulation (n'écrit rien) :
moon tools/classifier/simplifier.moon cdn --lists-dir lists --dry-run
```

### Options de `simplifier.moon`

| Option | Défaut | Rôle |
|--------|--------|------|
| `<list-name>` | — | Catégorie unique à traiter (positionnel, optionnel : sinon toutes) |
| `--lists-dir DIR` | `lists` | Répertoire des listes `.txt` |
| `--bin-dir DIR` | = `--lists-dir` | Répertoire de sortie des `.bin` |
| `--model NAMES` | `openrouter/free` | Modèle(s) IA, séparés par des virgules → round-robin |
| `--min-children N` | `3` | Nb minimal de sous-domaines pour proposer un parent |
| `--batch-size N` | `30` | Parents candidats par requête IA (`0` = tout d'un coup) |
| `--max-retries N` | `3` | Tentatives max par lot |
| `--samples N` | `5` | Sous-domaines d'exemple par parent dans le prompt |
| `--dry-run` | — | N'écrit rien : affiche seulement le plan de repli |
| `--no-bin` | — | Ne pas recompiler les `.bin` |
| `--no-commit` | — | Ne pas committer |

Les variables d'environnement (clé/URL/modèle, `.env`, `CUSTOS_LUA`) sont **identiques**
à classifier (cf. section précédente).

## Fichiers

| Fichier | Rôle |
|---------|------|
| `classifier.moon` | Orchestrateur de classification (simplifie avant les `.bin`) |
| `simplifier.moon` | Enveloppe CLI de simplification (arguments, `.bin`, commit) |
| `simplify.moon` | Cœur d'orchestration de la simplification (partagé classifier/simplifier) |
| `simplify_lib.moon` | Logique pure de simplification (redondance, candidats, plan de repli) |
| `common.moon` | Helpers partagés (`.env`, appel IA, écriture listes, `.bin`, commit git) |
| `browse.py` | Helper Playwright : URL → JSON des domaines contactés |
| `json.lua` | Décodeur/encodeur JSON minimal vendoré (rxi/json.lua, MIT) |
| `Dockerfile` | Image autonome |

> Tests unitaires de la logique pure : `tests/unit/tools/simplify_lib_spec.moon`
> (lancé par `make test`).
