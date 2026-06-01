-- tools/classifier/simplify_lib.moon
-- Logique PURE de simplification de listes de domaines (sans IA, sans I/O).
-- Isolée de simplifier.moon pour être testable unitairement.
--
-- Rappel sémantique custos : un domaine autorisé couvre lui-même ET tous ses
-- sous-domaines (cf. to_domain / to_domainlist). Replier
-- {sun1-13.userapi.com, sun1-16.userapi.com, …} vers `userapi.com` est donc
-- équivalent côté correspondance, et raccourcit la liste — à condition que
-- replier l'ensemble du domaine parent soit souhaitable (décision déléguée à l'IA).

--- Nombre de labels d'un domaine ("a.b.com" → 3).
nlabels = (d) ->
  n = 1
  n += 1 for _ in d\gmatch "%."
  n

--- Vrai si `anc` est un ancêtre strict de `d` (d est un sous-domaine de anc).
is_ancestor = (anc, d) -> d\sub(-(#anc + 1)) == ".#{anc}"

--- Suffixes d'un domaine ayant au moins 2 labels, le domaine lui-même inclus.
-- "a.b.c.com" → { "a.b.c.com", "b.c.com", "c.com" }.
-- @tparam string d
-- @treturn table liste de suffixes (du plus spécifique au plus large)
suffixes = (d) ->
  out = {}
  out[#out + 1] = d if nlabels(d) >= 2
  pos = d\find ".", 1, true
  while pos
    s = d\sub pos + 1
    out[#out + 1] = s if nlabels(s) >= 2
    pos = d\find ".", pos + 1, true
  out

--- Sous-domaines rendus redondants par la présence d'un de leurs ancêtres dans
-- la MÊME liste. Ex. si `userapi.com` figure dans la liste, `sun1-13.userapi.com`
-- y est inutile (déjà couvert par le parent). Suppression « gratuite » : aucune
-- décision IA, c'est une stricte équivalence côté correspondance.
-- @tparam table domains liste de domaines
-- @treturn table drop set { [domaine]: true } des sous-domaines redondants
redundant = (domains) ->
  present = {}
  present[d] = true for d in *domains
  drop = {}
  for d in *domains
    pos = d\find ".", 1, true
    while pos
      anc = d\sub pos + 1
      if present[anc]
        drop[d] = true
        break
      pos = d\find ".", pos + 1, true
  drop

--- Calcule les parents candidats au repli pour une liste de domaines.
--
-- Un parent candidat est un suffixe (≥ 2 labels) qui couvre au moins
-- `min_children` domaines DISTINCTS de la liste (lui-même inclus s'il y figure).
-- On ne conserve ensuite que les candidats MAXIMAUX : si `c.net` et `b.c.net`
-- sont tous deux candidats, seul `c.net` (le plus large) est proposé — l'approuver
-- subsume l'autre. C'est volontairement à l'IA de refuser un parent trop large
-- (p. ex. `google.com`) ; côté outil on propose le repli le plus agressif.
--
-- @tparam table  domains     liste de domaines (minuscules, validés)
-- @tparam number min_children seuil minimal de domaines couverts (défaut 3)
-- @treturn table liste de { parent: string, children: {domaines…}, count: n },
--   triée par nombre de domaines couverts décroissant puis par nom.
candidates = (domains, min_children) ->
  min_children or= 3
  seen = {}
  uniq = {}
  for d in *domains
    continue if seen[d]
    seen[d] = true
    uniq[#uniq + 1] = d

  -- children[suffixe] = set des domaines de la liste couverts par ce suffixe.
  children = {}
  for d in *uniq
    for s in *suffixes d
      children[s] or= {}
      children[s][d] = true

  -- Candidats bruts : suffixes couvrant ≥ min_children domaines, et qui ne sont
  -- pas réduits à un unique domaine = lui-même (il faut un réel regroupement).
  raw = {}
  for s, set in pairs children
    kids = [d for d in pairs set]
    -- Couvre-t-il au moins un domaine AUTRE que lui-même ? (sinon rien à replier)
    has_other = false
    for d in *kids
      if d != s
        has_other = true
        break
    continue unless has_other
    continue if #kids < min_children
    raw[#raw + 1] = { parent: s, children: kids, count: #kids }

  -- Filtre maximal : retire tout candidat dont un AUTRE candidat est un ancêtre.
  parents_set = {}
  parents_set[c.parent] = true for c in *raw
  maximal = {}
  for c in *raw
    subsumed = false
    for p in pairs parents_set
      if p != c.parent and is_ancestor p, c.parent
        subsumed = true
        break
    maximal[#maximal + 1] = c unless subsumed

  for c in *maximal
    table.sort c.children
  table.sort maximal, (a, b) ->
    return a.count > b.count if a.count != b.count
    a.parent < b.parent
  maximal

--- Construit le set des domaines à supprimer pour un ensemble de parents approuvés.
-- Pour chaque parent P approuvé, on supprime P et tous ses sous-domaines présents
-- dans la liste ; P sera (ré)ajouté par ailleurs.
-- @tparam table domains  liste complète des domaines de la catégorie
-- @tparam table approved set { [parent]: true }
-- @treturn table drop set { [domaine]: true }, table parents (liste à ajouter)
fold_plan = (domains, approved) ->
  drop = {}
  for d in *domains
    for p in pairs approved
      if d == p or is_ancestor p, d
        drop[d] = true
        break
  add = [p for p in pairs approved]
  table.sort add
  drop, add

{ :nlabels, :is_ancestor, :suffixes, :redundant, :candidates, :fold_plan }
