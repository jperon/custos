---
name: moonscript
description: Moonscript syntax and usage
---

# MoonScript — Syntaxe, LDoc et pièges

Ce projet **évite le mot-clé `class`** de MoonScript. Le code compilé doit être
indépendant de la bibliothèque MoonScript (pas de `require "moon"`).

---

## Syntaxe de base

### Indentation significative

MoonScript utilise l'**espace blanc significatif** — l'indentation définit les
blocs. Utiliser des espaces (pas de tabulations) de façon cohérente.

### Mots-clés absents

- **Pas de `local`** — toutes les déclarations sont locales par défaut.
- **Pas de `end`** — les blocs sont fermés par retour au niveau d'indentation précédent.
- **Pas de `then`** — suit `if` directement sur la même ligne ou en indentation.
- **Pas de `do`** après `while`/`for` — mais `do` seul crée un bloc autonome.

```custos/.agents/moonscript.md#L1-1
if condition
  -- corps
else
  -- sinon

for i = 1, 10
  -- boucle

while true
  -- boucle

switch value
  when 1
    -- cas 1
  else
    -- défaut

a = 1
do
  b = 2
  a = 2
assert a == 2  -- OK
assert b == 2  -- Erreur : b n'est pas visible hors du bloc `do`
```

### Tables : syntaxe implicite vs explicite

MoonScript offre deux façons d'écrire une table dict — choisir la plus lisible
selon le contexte.

**Table implicite par indentation** : quand la valeur d'une clé est elle-même
un dict multi-clés, on peut omettre les `{}` et indenter les sous-clés. Les
deux formes compilent en Lua identique :

```moonscript
-- Forme explicite (accolades)
auth: {
  port: 33443
  idle_timeout: 90
}

-- Forme implicite (indentation) — équivalent exact
auth:
  port: 33443
  idle_timeout: 90
```

**Table inline à clé unique** : quand une table ne contient qu'une seule clé,
on peut l'écrire sur la même ligne sans accolades :

```moonscript
-- Forme explicite
conditions: { to_domainlist: "captive" }

-- Forme inline chaînée — équivalent exact
conditions: to_domainlist: "captive"
```

**Accolades obligatoires** pour les tableaux (séquences à clés entières) — la
syntaxe implicite ne fonctionne qu'avec des dicts clé/valeur :

```moonscript
-- Tableau : {} toujours requis
actions: {"allow"}
from_vlans: {2, 3, 4, 5}

-- Module retournant une table : {} requis (valeur de retour nue)
{
  runtime:
    log_level: "DEBUG"
  filter:
    domainlists_dir: "/etc/custos/lists"
}
```

**Clés qui sont des mots réservés Lua** (`local`, `end`, `if`, …) : les écrire
entre guillemets dans un constructeur de table :

```moonscript
nets:
  "local": {"10.0.0.0/8", "192.168.0.0/16"}
-- compile en : nets = { ["local"] = {"10.0.0.0/8", "192.168.0.0/16"} }
```

### Style fonctionnel (recommandé)

Préférer les modules exportant des fonctions :

```custos/.agents/moonscript.md#L1-1
parse_ip = (raw) ->
  -- ...

{ :parse_ip }
```

### Fat arrow et `@`

`=>` crée une fonction où `self` est lié automatiquement :

- `@` ≡ `self`
- `@prop` ≡ `self.prop`
- `(...) =>` ≡ `(self, ...) ->`

```custos/.agents/moonscript.md#L1-1
increment = (amount) =>
  @value += amount

obj = {
  value: 10
  increment: (amount) => @value += amount
}
```

### Objets avec `setmetatable`

Pour un objet avec état, utiliser une fonction factory :

```custos/.agents/moonscript.md#L1-1
MaTable = (prop1) ->
  obj = {
    value: prop1
    increment: (amount) => @value += amount
  }
  setmetatable obj, { __index: MaTable }
  obj

obj = MaTable 10
obj\increment 5
```

### Concaténation en boucle : table + `table.concat`

Ne jamais accumuler une chaîne avec `..=` dans une boucle. Les chaînes Lua sont
immuables : chaque `..=` réalloue toute la chaîne → coût quadratique. Construire
une table puis concaténer d'un coup après la boucle.

```moonscript
-- FAUX : réallocation à chaque itération
opts = ""
for o in *options
  opts ..= render o

-- CORRECT : une seule allocation finale
parts = {}
for o in *options
  parts[#parts + 1] = render o
table.concat parts          -- ou : table.concat parts, ","
```

S'applique à toute génération itérative (HTML, JS, JSON, lignes de tableau).
Exemples dans `src/webui/handlers/rules.moon` (`cond_a_select`,
`cond_b_select`, `cond_families_js`).

---

## LDoc

Toutes les fonctions doivent être documentées avec des commentaires LDoc :

```custos/.agents/moonscript.md#L1-1
--- Parse un en-tête IPv4 brut.
-- @tparam string raw   Données brutes du paquet
-- @tparam number offset Offset de départ de l'en-tête IP
-- @treturn table|nil   En-tête parsé ou nil en cas d'erreur
parse_ip = (raw, offset) ->
  -- ...
```

| Tag | Usage |
|-----|-------|
| `@tparam type name desc` | Paramètre typé |
| `@treturn type desc` | Valeur de retour typée |
| `@raise` | Exception pouvant être levée |

Types de base : `string`, `number`, `boolean`, `nil`, `table`, `function`,
`cdata`, `thread`. Paramètre optionnel : `@tparam table|nil [fields] desc`.

---

## Pièges de refactoring

### Destructuration avec alias

`{ :name }` est un raccourci pour `{ name: name }`. Dès que le nom local
diffère de la clé, le `:` préfixe est invalide :

```custos/.agents/moonscript.md#L1-1
-- FAUX : syntaxe invalide
{ :new: new_eth } = require "ipparse.l2.ethernet"

-- CORRECT : forme explicite
{ new: new_eth } = require "ipparse.l2.ethernet"

-- CORRECT : raccourci uniquement quand clé = nom local
{ :new } = require "ipparse.l2.ethernet"
```

### Fonctions de module vs méthodes : `.` pas `\`

Les modules exportant des fonctions simples (ex. `auth.nft_sessions`) doivent
être appelés avec `.`, pas `\`. L'opérateur `\` compile en syntaxe colon Lua
et injecte la table comme premier argument :

```custos/.agents/moonscript.md#L1-1
-- FAUX : nft_sessions exporte des fonctions, pas des méthodes
nft_sess\add_authenticated ip, ttl
-- Compile en : nft_sess.add_authenticated(nft_sess, ip, ttl)
-- → ip est la table du module → ip:find(":") plante

-- CORRECT :
nft_sess.add_authenticated ip, ttl
```

Signe de ce bug : `"attempt to call a nil value (field 'find')"` ou erreur
similaire sur une méthode string appelée sur ce qui devrait être une string.

### Appel de méthode `\` : l'argument sans parenthèses avale le `and`

Un appel `obj\method "arg"` sans parenthèses consomme tout ce qui suit comme
argument, y compris un opérateur `and` :

```moonscript
-- FAUX : ":" and ip6 ~= "::" est évalué en Lua comme argument unique
-- Résultat compilé : ip6:find(":" and ip6 ~= "::") → ip6:find(boolean)
if ip6 and ip6\find ":" and ip6 != "::"

-- CORRECT (parenthèses) : délimite explicitement l'argument
if ip6 and (ip6\find ":") and ip6 != "::"

-- CORRECT (sans espace) : guillemets accolés au nom → argument limité à la string
if ip6 and ip6\find":" and ip6 != "::"
```

La règle : un espace entre le nom de méthode et la string ouvre une liste
d'arguments qui consomme tout ce qui suit (y compris `and`, `or`, `==`, …).
Sans espace (`\find"..."`), l'argument s'arrête à la fin de la string littérale
et les opérateurs suivants sont des opérateurs booléens normaux.

### Appels multi-lignes : précalculer les arguments complexes

```custos/.agents/moonscript.md#L1-1
-- RISQUÉ : body peut être parsé comme argument de H.head
"<!DOCTYPE html>\n" .. H.html({ lang: "fr" },
  H.head { H.meta { charset: "UTF-8" } },
  body
)

-- SÛR : précalculer, utiliser la forme implicit-table
head = H.head { H.meta { charset: "UTF-8" } }
body = H.body { H.p "Content" }
"<!DOCTYPE html>\n" .. H.html lang: "fr", head, body
```

### `$` dans les strings MoonScript

Dans une string double-quotée MoonScript, `\$` compile en `\$` Lua, qui est
une séquence d'échappement invalide. Écrire `$` directement :

```custos/.agents/moonscript.md#L1-1
-- FAUX : \$p est un échappement invalide en Lua
"sed -n '/#{MARKER}/,\$p'"

-- CORRECT :
"sed -n '/#{MARKER}/,$p'"
```

### IPv6 dual-stack : conserver le pattern `socket.select`

```custos/.agents/moonscript.md#L1-1
-- FAUX : ne bind qu'IPv4, les clients IPv6 obtiennent "connection refused"
srv = socket.bind "*", port

-- CORRECT :
listen4 = make_server4 port  -- bind 0.0.0.0
listen6 = make_server6 port  -- bind ::
all_servers = { listen4 }
all_servers[#all_servers + 1] = listen6 if listen6
-- socket.select(all_servers, nil, timeout) pour accepter des deux
```

Un status 0 dans les DevTools du navigateur indique que la connexion a été
fermée avant tout réponse HTTP — généralement un crash dans le handler
capturé par `pcall`.

## Pièges de scope en MoonScript

### Variables dans les blocs de contrôle (`if`, `pcall`, etc.)

**Piège critique** : Les variables définies pour la première fois *dans* un bloc
`if`, `pcall`, `for`, ou autres structures de contrôle ne sont accessibles que
*dans* ce bloc. Elles sont indéfinies (nil) après le bloc.

```moonscript
-- ❌ INCORRECT : x est undefined après le if
if condition
  x = 10
print x  -- nil (erreur!)

-- ✓ CORRECT : déclarer avant le bloc
x = nil
if condition
  x = 10
print x  -- OK

-- ❌ INCORRECT : ctx est undefined après pcall
ok, err = pcall ->
  ctx = load_or_generate_sni "custos", cache
print ctx  -- nil (erreur!)

-- ✓ CORRECT : déclarer avant pcall
ctx = nil
ok, err = pcall ->
  ctx = load_or_generate_sni "custos", cache
-- ctx est maintenant accessible et non-nil
```

**Règle générale** : Si une variable doit être utilisée *après* un bloc de
contrôle, **la déclarer avant le bloc** (même si la déclaration est `var = nil`).

### Bug `if`/`else` dual-branch (piège subtil)

Le cas le plus trompeur : la variable est assignée dans **les deux branches**
d'un `if`/`else`. On pense que la variable sera définie dans tous les cas —
mais elle reste nil après le bloc car chaque branche crée sa propre locale.

```moonscript
-- ❌ INCORRECT : allowed/reason sont locaux à chaque branche
if decision
  allowed = decision.verdict   -- local au bloc if
  reason  = decision.reason    -- local au bloc if
else
  allowed, reason = filter.decide req  -- local au bloc else
log(reason)  -- nil! (et allowed == nil → verdict "denied" par défaut)

-- ✓ CORRECT : pré-déclarer avant le if
allowed, reason = nil, nil
if decision
  allowed = decision.verdict
  reason  = decision.reason
else
  allowed, reason = filter.decide req
log(reason)  -- OK
```

Ce bug a causé `reason=denied rule=` dans tous les logs DNS de `worker_questions`
même quand une règle catch-all (`actions: {"allow"}`, sans conditions) était
présente — **la règle s'appliquait bien mais son résultat était perdu**.
Commit de correction : `39562b9`.

**Indicateur** : si le Lua compilé contient `local x = …` à l'intérieur
d'un bloc `if`/`else`, c'est un signal de ce bug.

### Portée des boucles

Les variables de boucle (`for i`, `for k, v`) sont toujours locales à la boucle.
Les variables *modifiées* dans une boucle restent accessibles après.

```moonscript
x = 0
for i = 1, 10
  x = x + i  -- x accessible, modifiable
print x  -- 55 (OK)

for i = 1, 10
  y = i  -- y créée dans la boucle
print y  -- 10 (OK, persist après boucle)
```

### Problème avec les closures et `pcall`

MoonScript autorise les closures, mais `pcall` crée une portée supplémentaire.
Les variables créées dans le callback `pcall` ne survivent pas à la fin du callback.

```moonscript
-- ❌ PROBLÈME : ctx échappé du callback pcall
ok = pcall ->
  ctx = create_context()
ssl.wrap socket, ctx  -- ctx est nil!

-- ✓ SOLUTION : déclarer ctx avant
ctx = nil
ok = pcall ->
  ctx = create_context()
ssl.wrap socket, ctx  -- OK
```

### Matrice de test pour les modifications du worker AUTH

Toujours tester toutes les combinaisons après une modification du worker AUTH :

| Test | Commande | Attendu |
|------|----------|---------|
| GET / IPv4 | `curl -v http://<ip4>:33443/` | 200 OK + formulaire HTML |
| GET / IPv6 | `curl -v http://[<ip6>]:33443/` | 200 OK + formulaire HTML |
| POST /login IPv4 | `curl -X POST -d "user=..." -d "password=..."` | 200 OK ou 401 |
| POST /login IPv6 | idem sur IPv6 | 200 OK ou 401 |
| TLS handshake | navigateur ou `openssl s_client` | complète sans erreur |
