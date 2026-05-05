-- src/auth/cert_cache.moon
-- Cache persistent avec TTL pour certificats TLS générés dynamiquement.
-- Clé : SNI hostname (ex: "example.com")
-- Valeur : {cert_pem, key_pem, ctx, expires_at}
--
-- Persistance disk :
--   - Certificats sauvegardés dans tmp/certs/ comme hostname.crt et hostname.key
--   - Index persistant dans tmp/cert_cache_index.lua (table sérialisée)
--   - Charge au démarrage, sauvegarde à chaque SET
--   - TTL long (90+ jours) : on régénère seulement si expiré

{ :log_debug, :log_warn } = require "log"

--- Sauvegarde l'index persistant sur disque (timestamp + expiration)
persist_index = (index_path, index_data) ->
  fh = io.open index_path, "w"
  return false unless fh

  -- Sérialiser sous forme de Lua : {hostname = {expires_at, accessed_at}, ...}
  lines = { "return {" }
  for hostname, entry in pairs index_data
    escaped_hostname = hostname\gsub('"', '\\"')
    table.insert lines, string.format('  ["%s"] = {expires_at=%d, accessed_at=%d},', escaped_hostname, entry.expires_at, entry.accessed_at)
  table.insert lines, "}"

  fh\write table.concat(lines, "\n")
  fh\close!

  log_debug { action: "cert_cache_persist_index", path: index_path }
  true

--- Charge l'index persistant depuis disque
load_persistent_index = (index_path) ->
  fh = io.open index_path, "r"
  return {} unless fh

  content = fh\read "*a"
  fh\close!

  unless content and #content > 0
    return {}

  -- Charger la table Lua
  status, result = pcall(loadstring, content)
  unless status
    log_warn { action: "cert_cache_load_index_failed", path: index_path, err: result }
    return {}

  loaded_fn = result!
  log_debug { action: "cert_cache_loaded_index", path: index_path, entries: #loaded_fn }
  loaded_fn or {}

--- Factory pour créer une instance de cache persistant avec TTL.
-- @tparam number max_size Nombre max de certificats en cache RAM (défaut: 500)
-- @tparam number ttl Temps de vie des certificats en secondes (défaut: 7776000 = 90 jours)
-- @tparam string cert_dir Répertoire pour stocker les certificats (défaut: "tmp/certs")
-- @treturn table Instance du cache avec méthodes get/set/evict
create_cache = (max_size = 500, ttl = 7776000, cert_dir = "tmp/certs") ->
  max_size = math.max(1, tonumber(max_size) or 500)
  ttl = math.max(60, tonumber(ttl) or 7776000)  -- Min 60 sec, default 90 days

  cert_dir = cert_dir or "tmp/certs"
  index_path = "tmp/cert_cache_index.lua"

  -- Créer répertoire de certificats s'il n'existe pas
  os.execute "mkdir -p #{cert_dir} 2>/dev/null"

  -- Stockage RAM : {hostname → {cert_pem, key_pem, ctx, expires_at, accessed_at}}
  data = {}
  -- Order de LRU : liste ordonnée des hostnames par accès (le plus ancien d'abord)
  lru_order = {}
  -- Index persistant : {hostname → {expires_at, accessed_at}}
  persistent_index = load_persistent_index index_path

  --- Sauvegarde une paire cert/key sur disque et met à jour l'index
  save_cert_to_disk = (hostname, cert_pem, key_pem) ->
    hostname_lower = hostname\lower!
    cert_file = "#{cert_dir}/#{hostname_lower}.crt"
    key_file = "#{cert_dir}/#{hostname_lower}.key"

    -- Écrire le certificat
    cert_fh, cert_err = io.open cert_file, "w"
    unless cert_fh
      log_warn { action: "cert_cache_disk_write_failed", file: cert_file, reason: cert_err or "io.open failed" }
      return false
    cert_fh\write cert_pem
    cert_fh\close!

    -- Écrire la clé
    key_fh, key_err = io.open key_file, "w"
    unless key_fh
      log_warn { action: "cert_cache_disk_write_failed", file: key_file, reason: key_err or "io.open failed" }
      os.remove cert_file
      return false
    key_fh\write key_pem
    key_fh\close!

    log_debug { action: "cert_cache_disk_saved", hostname: hostname_lower }
    true

  --- Charge une paire cert/key depuis disque
  load_cert_from_disk = (hostname) ->
    hostname_lower = hostname\lower!
    cert_file = "#{cert_dir}/#{hostname_lower}.crt"
    key_file = "#{cert_dir}/#{hostname_lower}.key"

    cert_fh = io.open cert_file, "r"
    key_fh = io.open key_file, "r"

    unless cert_fh and key_fh
      return nil, nil

    cert_pem = cert_fh\read "*a"
    key_pem = key_fh\read "*a"
    cert_fh\close!
    key_fh\close!

    unless cert_pem and key_pem and #cert_pem > 0 and #key_pem > 0
      return nil, nil

    log_debug { action: "cert_cache_disk_loaded", hostname: hostname_lower }
    cert_pem, key_pem

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

    -- Sauvegarder sur disque
    unless save_cert_to_disk hostname_lower, cert_pem, key_pem
      log_warn { action: "cert_cache_set_disk_failed", hostname: hostname_lower, reason: "save_cert_to_disk returned false" }
      return false

    -- Mettre à jour l'index persistant
    persistent_index[hostname_lower] = {
      expires_at: expires_at
      accessed_at: now
    }
    persist_index index_path, persistent_index

    -- Si entrée existe déjà en RAM, la supprimer de LRU order avant réinsertion
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

    -- Insérer/mettre à jour l'entrée en RAM
    data[hostname_lower] = {
      cert_pem: cert_pem
      key_pem: key_pem
      ctx: ctx
      expires_at: expires_at
      accessed_at: now
    }

    log_debug { action: "cert_cache_set", hostname: hostname_lower, size: #lru_order }
    true

  --- Récupère une entrée du cache (RAM en priorité, puis disque si absent en RAM).
  -- @tparam string hostname SNI hostname
  -- @treturn table|nil Entrée {cert_pem, key_pem, ctx}, ou nil si absent/expiré
  get = (hostname) ->
    unless hostname and #hostname > 0
      return nil

    hostname_lower = hostname\lower!

    -- Vérifier l'index persistant : a-t-il expiré ?
    persistent_entry = persistent_index[hostname_lower]
    if persistent_entry
      now = os.time!
      if now >= persistent_entry.expires_at
        log_debug { action: "cert_cache_disk_expired", hostname: hostname_lower }
        persistent_index[hostname_lower] = nil
        persist_index index_path, persistent_index
        return nil

    -- Chercher en RAM d'abord
    entry = data[hostname_lower]
    if entry
      now = os.time!
      if now >= entry.expires_at
        data[hostname_lower] = nil
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
      log_debug { action: "cert_cache_hit", hostname: hostname_lower, source: "ram" }
      return entry

    -- Si absent en RAM, charger depuis disque
    cert_pem, key_pem = load_cert_from_disk hostname_lower
    if cert_pem and key_pem
      -- Recréer l'entrée en RAM pour performance
      now = os.time!
      expires_at = if persistent_entry then persistent_entry.expires_at else (now + ttl)
      entry = {
        cert_pem: cert_pem
        key_pem: key_pem
        ctx: nil  -- Sera créé par le code appelant
        expires_at: expires_at
        accessed_at: now
      }

      -- Ajouter en RAM (peut déclencher une éviction LRU)
      table.insert lru_order, hostname_lower
      while #lru_order > max_size
        victim = table.remove lru_order, 1
        data[victim] = nil
      data[hostname_lower] = entry

      log_debug { action: "cert_cache_hit", hostname: hostname_lower, source: "disk" }
      return entry

    log_debug { action: "cert_cache_miss", hostname: hostname_lower, reason: "not_found" }
    nil

  --- Supprime une entrée du cache (RAM et disque).
  -- @tparam string hostname SNI hostname
  delete = (hostname) ->
    unless hostname and #hostname > 0
      return false

    hostname_lower = hostname\lower!

    -- Supprimer de RAM
    if data[hostname_lower]
      data[hostname_lower] = nil
      for i = 1, #lru_order
        if lru_order[i] == hostname_lower
          table.remove lru_order, i
          break

    -- Supprimer du disque
    os.remove "#{cert_dir}/#{hostname_lower}.crt"
    os.remove "#{cert_dir}/#{hostname_lower}.key"

    -- Supprimer de l'index persistant
    persistent_index[hostname_lower] = nil
    persist_index index_path, persistent_index

    log_debug { action: "cert_cache_delete", hostname: hostname_lower }
    true

  --- Purge toutes les entrées expirées (RAM et disque).
  -- @treturn number Nombre d'entrées supprimées
  purge_expired = () ->
    now = os.time!
    removed_count = 0

    -- Purger le disque (via l'index persistant)
    expired_hosts = {}
    for hostname, entry in pairs persistent_index
      if now >= entry.expires_at
        table.insert expired_hosts, hostname

    for hostname in *expired_hosts
      os.remove "#{cert_dir}/#{hostname}.crt"
      os.remove "#{cert_dir}/#{hostname}.key"
      persistent_index[hostname] = nil
      removed_count += 1

    if #expired_hosts > 0
      persist_index index_path, persistent_index

    -- Purger la RAM
    expired_ram = {}
    for hostname, entry in pairs data
      if now >= entry.expires_at
        table.insert expired_ram, hostname

    for hostname in *expired_ram
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
  -- @treturn table {size_ram, size_disk, max_size, ttl_seconds}
  stats = () ->
    {
      size_ram: #lru_order
      size_disk: #persistent_index
      max_size: max_size
      ttl_seconds: ttl
    }

  --- Vide complètement le cache (RAM et disque).
  clear = () ->
    data = {}
    lru_order = {}

    -- Effacer tous les fichiers du répertoire
    os.execute "rm -f #{cert_dir}/*.crt #{cert_dir}/*.key 2>/dev/null"

    persistent_index = {}
    persist_index index_path, persistent_index

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
