-- src/auth/cert_cache.moon
-- Cache LRU avec TTL pour certificats TLS générés dynamiquement.
-- Clé : SNI hostname (ex: "example.com")
-- Valeur : {cert_pem, key_pem, ctx, expires_at}
-- Limite : ~100 certificats max, éviction LRU si plein
-- TTL : configurable, défaut 24h (86400 sec)

{ :log_debug, :log_warn } = require "log"

--- Factory pour créer une instance de cache LRU avec TTL.
-- @tparam number max_size Nombre max de certificats en cache (défaut: 100)
-- @tparam number ttl Temps de vie des entrées en secondes (défaut: 86400 = 24h)
-- @treturn table Instance du cache avec méthodes get/set/evict
create_cache = (max_size = 100, ttl = 86400) ->
  max_size = math.max(1, tonumber(max_size) or 100)
  ttl = math.max(60, tonumber(ttl) or 86400)
  
  -- Stockage : {hostname → {cert_pem, key_pem, ctx, expires_at, lru_order}}
  data = {}
  -- Order de LRU : liste ordonnée des hostnames par accès (le plus ancien d'abord)
  lru_order = {}
  
  --- Ajoute ou met à jour une entrée de cache.
  -- @tparam string hostname SNI hostname (ex: "example.com")
  -- @tparam string cert_pem Certificat en PEM
  -- @tparam string key_pem Clé privée en PEM
  -- @tparam table ctx Contexte TLS WolfSSL (optionnel)
  -- @treturn boolean true
  set = (hostname, cert_pem, key_pem, ctx) ->
    unless hostname and #hostname > 0
      return false
    
    hostname_lower = hostname\lower!
    now = os.time!
    expires_at = now + ttl
    
    -- Si entrée existe déjà, la supprimer de LRU order avant réinsertion
    if data[hostname_lower]
      for i = 1, #lru_order
        if lru_order[i] == hostname_lower
          table.remove lru_order, i
          break
    
    -- Ajouter à LRU order (fin = plus récent)
    table.insert lru_order, hostname_lower
    
    -- Vérifier si cache est plein et éviction nécessaire
    while #lru_order > max_size
      victim = table.remove lru_order, 1  -- Enlever le plus ancien
      data[victim] = nil
      log_debug { action: "cert_cache_evict", hostname: victim, reason: "lru_full" }
    
    -- Insérer/mettre à jour l'entrée
    data[hostname_lower] = {
      cert_pem: cert_pem
      key_pem: key_pem
      ctx: ctx
      expires_at: expires_at
      accessed_at: now
    }
    
    log_debug { action: "cert_cache_set", hostname: hostname_lower, size: #lru_order }
    true
  
  --- Récupère une entrée du cache si elle existe et n'a pas expiré.
  -- @tparam string hostname SNI hostname
  -- @treturn table|nil Entrée {cert_pem, key_pem, ctx}, ou nil si absent/expiré
  get = (hostname) ->
    unless hostname and #hostname > 0
      return nil
    
    hostname_lower = hostname\lower!
    entry = data[hostname_lower]
    
    unless entry
      log_debug { action: "cert_cache_miss", hostname: hostname_lower, reason: "not_found" }
      return nil
    
    now = os.time!
    if now >= entry.expires_at
      data[hostname_lower] = nil
      -- Retirer du LRU order
      for i = 1, #lru_order
        if lru_order[i] == hostname_lower
          table.remove lru_order, i
          break
      log_debug { action: "cert_cache_expired", hostname: hostname_lower }
      return nil
    
    -- Mise à jour de la position dans LRU order (déplacer à la fin = plus récent)
    for i = 1, #lru_order
      if lru_order[i] == hostname_lower
        table.remove lru_order, i
        break
    table.insert lru_order, hostname_lower
    
    entry.accessed_at = now
    log_debug { action: "cert_cache_hit", hostname: hostname_lower }
    entry
  
  --- Supprime une entrée du cache.
  -- @tparam string hostname SNI hostname
  delete = (hostname) ->
    unless hostname and #hostname > 0
      return false
    
    hostname_lower = hostname\lower!
    if data[hostname_lower]
      data[hostname_lower] = nil
      for i = 1, #lru_order
        if lru_order[i] == hostname_lower
          table.remove lru_order, i
          break
      log_debug { action: "cert_cache_delete", hostname: hostname_lower }
      return true
    false
  
  --- Purge toutes les entrées expirées.
  -- @treturn number Nombre d'entrées supprimées
  purge_expired = () ->
    now = os.time!
    removed_count = 0
    
    expired_hosts = {}
    for hostname, entry in pairs data
      if now >= entry.expires_at
        table.insert expired_hosts, hostname
    
    for hostname in *expired_hosts
      data[hostname] = nil
      for i = 1, #lru_order
        if lru_order[i] == hostname
          table.remove lru_order, i
          break
      removed_count += 1
    
    if removed_count > 0
      log_debug { action: "cert_cache_purge_expired", count: removed_count }
    
    removed_count
  
  --- Retourne les stats du cache.
  -- @treturn table {size, max_size, ttl_seconds, hits, misses}
  stats = () ->
    {
      size: #lru_order
      max_size: max_size
      ttl_seconds: ttl
    }
  
  --- Vide complètement le cache.
  clear = () ->
    data = {}
    lru_order = {}
    log_debug { action: "cert_cache_clear" }
    true
  
  -- Return public interface
  {
    :set
    :get
    :delete
    :purge_expired
    :stats
    :clear
  }

{ :create_cache }
