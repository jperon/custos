-- src/auth/cert.moon
-- Génération d'un certificat TLS auto-signé et chargement du contexte wolfssl FFI.
--
-- Si les fichiers cert/key existent déjà, ils sont réutilisés directement.
-- Sinon, un certificat RSA-2048 auto-signé est généré via `openssl req`.
--
-- Utilise ffi_wolfssl (FFI wrapper pour WolfSSL, remplace luasec).

ssl = require "auth.ffi_wolfssl"
{ :log_debug, :log_warn, :log_error } = require "log"

CERT_DAYS     = 3650    -- validité : ~10 ans
CERT_KEY_BITS = 2048

--- Génère un hash court pour une chaîne de caractères.
-- @tparam string s La chaîne à hacher
-- @treturn string Hash hexadécimal
hash_string = (s) ->
  h = 0
  for i = 1, #s
    h = (h * 31 + s\byte i) % 0x7FFFFFFF
  string.format "%x", h

--- Détecte les adresses IP non-loopback (v4 et v6) du système.
-- Inclut adresses privées et publiques (exclut loopback et adresses link-local IPv6).
-- @treturn table Liste des SANs au format "IP:adresse"
get_local_ips = () ->
  ips = {}
  -- IPv4 : toutes les adresses sauf loopback
  ok, out = pcall ->
    f = io.popen "ip -4 addr show | awk '/inet/{print $2}' | cut -d'/' -f1 | grep -v '^127\\.' | sort -u"
    res = f\read "*a"
    f\close!
    res
  if ok and out
    for ip in out\gmatch "%S+"
      table.insert ips, "IP:#{ip}"

  -- IPv6 : toutes les adresses sauf loopback et link-local (fe80::)
  ok, out = pcall ->
    f = io.popen "ip -6 addr show | awk '/inet6/{print $2}' | cut -d'/' -f1 | grep -v '^::1$' | grep -v '^fe80:' | sort -u"
    res = f\read "*a"
    f\close!
    res
  if ok and out
    for ip in out\gmatch "%S+"
      table.insert ips, "IP:#{ip}"
  ips

--- Génère un certificat RSA auto-signé via l'outil `openssl`.
-- @tparam string key_path  Chemin de destination pour la clé privée
-- @tparam string cert_path Chemin de destination pour le certificat
-- @tparam table sans Liste des Subject Alternative Names (ex: {"DNS:custos", "IP:1.2.3.4"})
-- @treturn boolean true si la génération a réussi
-- @treturn string  Sortie de la commande (stderr inclus), ou message d'erreur
generate_self_signed = (key_path, cert_path, sans) ->
  cnf_path = "tmp/auth.cnf"
  san_str = table.concat sans, ","
  config = " [ req ]\n" ..
           " distinguished_name = req_distinguished_name\n" ..
           " x509_extensions = v3_req\n" ..
           " prompt = no\n\n" ..
           " [ req_distinguished_name ]\n" ..
           " CN = custos\n\n" ..
           " [ v3_req ]\n" ..
           " basicConstraints = CA:FALSE\n" ..
           " keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n" ..
           " extendedKeyUsage = serverAuth\n" ..
           " subjectKeyIdentifier = hash\n" ..
           " authorityKeyIdentifier = keyid:always,issuer:always\n" ..
           " subjectAltName = #{san_str}\n"
  ok_w, err_w = pcall ->
    fh = io.open cnf_path, "w"
    fh\write config
    fh\close!
  unless ok_w
    return false, "Échec écriture config SAN : #{err_w}"

  cmd = string.format(
    "openssl req -x509 -newkey rsa:%d -keyout '%s' -out '%s' " ..
    "-days %d -nodes -config '%s' 2>&1",
    CERT_KEY_BITS, key_path, cert_path, CERT_DAYS, cnf_path
  )
  fh = io.popen cmd
  out = fh\read "*a"
  -- En Lua 5.1 / LuaJIT, popen:close() retourne true (booléen) si exit 0,
  -- et nil en cas d'échec — jamais le nombre 0. Tester la truthiness.
  ok_close = fh\close!
  pcall os.remove, cnf_path
  (ok_close ~= nil and ok_close ~= false), out

--- Crée un contexte TLS luasec en mode serveur.
-- @tparam string key_path  Chemin de la clé privée PEM
-- @tparam string cert_path Chemin du certificat PEM
-- @treturn table  Contexte luasec prêt à l'emploi
-- @raise   string Message d'erreur si la création échoue
make_context = (key_path, cert_path) ->
  ctx, err = ssl.newcontext {
    mode:        "server"
    protocol:    "any"
    key:         key_path
    certificate: cert_path
    options:     {"no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1"}
  }
  error "Échec création contexte TLS : #{err}" unless ctx
  ctx

--- Vérifie si un fichier est lisible.
-- @tparam string path Chemin du fichier
-- @treturn boolean
file_exists = (path) ->
  fh = io.open path, "r"
  if fh
    fh\close!
    true
  else
    false

--- Charge ou génère le contexte TLS.
-- Si key_path et cert_path existent tous les deux, ils sont utilisés directement.
-- Sinon un certificat auto-signé est généré à ces emplacements.
-- @tparam string key_path  Chemin de la clé privée
-- @tparam string cert_path Chemin du certificat
-- @treturn table  Contexte luasec (ssl.newcontext)
-- @raise   string Message d'erreur si échec
load_or_generate = (key_path, cert_path) ->
  -- Si on utilise les chemins par défaut, on bascule sur le nommage par hash
  if (key_path == "tmp/auth.key" or key_path == nil) and (cert_path == "tmp/auth.crt" or cert_path == nil)
    ips = get_local_ips()
    sans = { "DNS:custos" }
    for ip_san in *ips
      table.insert sans, ip_san
    san_str = table.concat sans, ","
    h = hash_string san_str
    key_path = "tmp/auth_#{h}.key"
    cert_path = "tmp/auth_#{h}.crt"

  unless file_exists(key_path) and file_exists(cert_path)
    ips = get_local_ips()
    sans = { "DNS:custos" }
    for ip_san in *ips
      table.insert sans, ip_san
    ok, out = generate_self_signed key_path, cert_path, sans
    error "Impossible de générer le certificat TLS :\n#{out}" unless ok
  make_context key_path, cert_path

--- Charge ou génère un contexte TLS pour un hostname SNI spécifique.
-- Utilise un cache LRU avec TTL pour éviter la régénération répétée.
-- @tparam string hostname Hostname SNI (ex: "example.com"), ou nil pour fallback générique
-- @tparam table cache Instance du cache (créée par cert_cache.create_cache)
-- @treturn table  Contexte TLS WolfSSL (ssl.newcontext)
-- @raise   string Message d'erreur si échec
load_or_generate_sni = (hostname, cache) ->
  hostname = hostname or "custos"
  hostname_lower = hostname\lower!
  
  log_debug { action: "cert_sni_request", hostname: hostname_lower }
  
  -- Vérifier le cache
  entry = cache.get hostname_lower
  if entry and entry.ctx
    log_debug { action: "cert_sni_cache_hit_ram", hostname: hostname_lower }
    return entry.ctx
  
  if entry and entry.cert_pem and entry.key_pem
    -- Entry depuis disque, recréer contexte
    log_debug { action: "cert_sni_cache_hit_disk", hostname: hostname_lower }
    
    key_file = "tmp/auth_sni_#{hostname_lower}_#{os.time!}.key"
    cert_file = "tmp/auth_sni_#{hostname_lower}_#{os.time!}.crt"
    
    key_ok = pcall ->
      key_fh = io.open key_file, "w"
      error "Cannot open key file" unless key_fh
      key_fh\write entry.key_pem
      key_fh\close!
    
    cert_ok = pcall ->
      cert_fh = io.open cert_file, "w"
      error "Cannot open cert file" unless cert_fh
      cert_fh\write entry.cert_pem
      cert_fh\close!
    
    if key_ok and cert_ok
      ctx = ssl.newcontext { certificate: cert_file, key: key_file }
      cache.set hostname_lower, entry.cert_pem, entry.key_pem, ctx
      log_debug { action: "cert_sni_context_recreated", hostname: hostname_lower }
      return ctx
  
  -- Pas en cache ou erreur : générer
  log_debug { action: "cert_sni_cache_miss", hostname: hostname_lower }
  
  gen = require "auth.cert_generator"
  log_debug { action: "cert_sni_generating", hostname: hostname_lower }
  key_pem, cert_pem, ok, err = gen.generate_self_signed hostname_lower
  unless ok
    log_error { action: "cert_sni_generation_failed", hostname: hostname_lower, err: err }
    error "Impossible de générer le certificat SNI pour #{hostname_lower} : #{err}"
  
  log_debug { action: "cert_sni_generated", hostname: hostname_lower, key_size: #key_pem, cert_size: #cert_pem }
  
  -- WolfSSL utilise des fichiers, pas des PEM strings.
  -- Écrire les PEM dans des fichiers temporaires.
  key_file = "tmp/auth_sni_#{hostname_lower}_#{os.time!}.key"
  cert_file = "tmp/auth_sni_#{hostname_lower}_#{os.time!}.crt"
  
  log_debug { action: "cert_sni_writing_files", key_file: key_file, cert_file: cert_file }
  
  -- Écrire la clé
  key_fh = io.open key_file, "w"
  unless key_fh
    log_error { action: "cert_sni_key_write_failed", key_file: key_file }
    error "Impossible d'écrire la clé SNI : #{key_file}"
  bytes_written = key_fh\write key_pem
  key_fh\close!
  
  log_debug { action: "cert_sni_key_written", key_file: key_file, bytes: bytes_written }
  
  -- Vérifier que le fichier existe et peut être lu
  key_stat = io.open key_file, "r"
  unless key_stat
    log_error { action: "cert_sni_key_verify_failed", key_file: key_file }
    error "Clé SNI écrite mais non relisible : #{key_file}"
  key_stat\close!
  
  -- Écrire le certificat
  cert_fh = io.open cert_file, "w"
  unless cert_fh
    os.remove key_file
    log_error { action: "cert_sni_cert_write_failed", cert_file: cert_file }
    error "Impossible d'écrire le certificat SNI : #{cert_file}"
  bytes_written = cert_fh\write cert_pem
  cert_fh\close!
  
  log_debug { action: "cert_sni_cert_written", cert_file: cert_file, bytes: bytes_written }
  
  -- Vérifier que le fichier existe et peut être lu
  cert_stat = io.open cert_file, "r"
  unless cert_stat
    log_error { action: "cert_sni_cert_verify_failed", cert_file: cert_file }
    error "Certificat SNI écrit mais non relisible : #{cert_file}"
  cert_stat\close!
  
  -- Créer le contexte TLS via les fichiers
  log_debug { action: "cert_sni_newcontext", hostname: hostname_lower, protocol: "tlsv1_2" }
  ctx = ssl.newcontext {
    mode: "server"
    protocol: "tlsv1_2"
    certificate: cert_file
    key: key_file
    options: {"no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1"}
  }
  
  log_debug { action: "cert_sni_context_created", hostname: hostname_lower }
  
  -- Mettre en cache (avec les fichiers temporaires)
  cache.set hostname_lower, cert_pem, key_pem, ctx
  
  log_debug { action: "cert_sni_cached", hostname: hostname_lower }
  
  ctx

--- Charge un certificat et clé statiques (depuis filter.yml).
-- @tparam string key_path  Chemin de la clé privée PEM
-- @tparam string cert_path Chemin du certificat PEM
-- @treturn table  Contexte TLS WolfSSL (ssl.newcontext), ou nil si succès
-- @treturn string Message d'erreur, ou nil si succès
load_static = (key_path, cert_path) ->
  unless key_path and cert_path
    return nil, "cert_path and key_path must be provided"
  
  unless file_exists(key_path) and file_exists(cert_path)
    return nil, "cert or key file not found"
  
  ok, ctx = pcall ->
    make_context key_path, cert_path
  unless ok
    return nil, "Failed to create TLS context from static files"
  
  ctx, nil

{ :load_or_generate, :generate_self_signed, :make_context, :load_or_generate_sni, :load_static }
