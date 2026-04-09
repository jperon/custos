-- src/filter/lib/bsearch.moon
-- Recherche binaire dans un tableau FFI uint64_t[N] trié croissant.
-- Toutes les comparaisons se font sur cdata uint64_t (pas de tonumber),
-- évitant ainsi toute perte de précision pour les hashes > 2⁵³.

--- Recherche binaire dans un tableau FFI uint64_t trié.
-- @tparam cdata   arr    Tableau FFI uint64_t[N] (0-indexé)
-- @tparam number  n      Nombre d'éléments dans le tableau
-- @tparam cdata   target Valeur cdata uint64_t à rechercher
-- @treturn boolean true si la valeur est présente, false sinon
bsearch = (arr, n, target) ->
  lo, hi = 0, n - 1
  while lo <= hi
    mid = math.floor (lo + hi) * 0.5
    v = arr[mid]
    if v == target
      return true
    elseif v < target
      lo = mid + 1
    else
      hi = mid - 1
  false

{ :bsearch }
