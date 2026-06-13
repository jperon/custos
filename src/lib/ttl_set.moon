-- src/lib/ttl_set.moon
-- Petit ensemble de clés à expiration (TTL) borné en taille, sans dépendance.
-- Conçu pour des suppressions légères (ex. noms DNS durablement NXDOMAIN dont on
-- ne veut plus retenter la résolution). Expiration paresseuse à la lecture +
-- élagage à l'insertion ; borne dure simple (vidage) si la taille maximale est
-- atteinte après élagage — acceptable pour un cache de suppression (au pire un
-- retry supplémentaire). Sans état module : chaque `new` crée une instance isolée.

--- Crée un ensemble TTL borné.
-- @tparam[opt=4096] number max_size Nombre maximal d'entrées.
-- @tparam[opt=60]   number ttl      Durée de vie d'une entrée, en secondes.
-- @tparam[opt]      function now_fn  Horloge (→ secondes) ; défaut os.time.
-- @treturn table { has, add, remove, size }
new = (max_size = 4096, ttl = 60, now_fn = os.time) ->
  max_size = math.max 1, tonumber(max_size) or 4096
  ttl      = math.max 1, tonumber(ttl) or 60
  store = {}   -- clé → timestamp d'expiration
  size  = 0

  prune = ->
    t = now_fn!
    for k, exp in pairs store
      if exp <= t
        store[k] = nil
        size -= 1

  --- La clé est-elle présente et non expirée ? (expire paresseusement.)
  has = (k) ->
    return false unless k
    exp = store[k]
    return false unless exp
    if exp <= now_fn!
      store[k] = nil
      size -= 1
      return false
    true

  --- Ajoute/rafraîchit une clé (expire à now + ttl).
  add = (k) ->
    return unless k
    unless store[k]
      if size >= max_size
        prune!
        if size >= max_size   -- toujours plein : borne dure, on repart à vide
          store = {}
          size = 0
      size += 1
    store[k] = now_fn! + ttl

  --- Retire une clé (si présente).
  remove = (k) ->
    return unless k
    if store[k]
      store[k] = nil
      size -= 1

  { :has, :add, :remove, size: -> size }

{ :new }
