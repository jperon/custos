-- src/auth/cert.moon
-- Chargement de certificats TLS et génération dynamique via px5g (auth.cert_generator).
--
-- Utilise ffi_wolfssl (FFI wrapper pour WolfSSL, remplace luasec).

ssl = require "auth.ffi_wolfssl"
{ :log_debug, :log_warn, :log_error } = require "log"
{ :safe_cert_name } = require "auth.cert_name"
{ :materialize_pair } = require "auth.cert_files"

CERT_DAYS = 730     -- validité : 2 ans

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

--- Écrit un PEM dans un fichier.
-- @tparam string path Chemin de destination
-- @tparam string content Contenu PEM
-- @treturn boolean true si succès
-- @treturn string|nil Message d'erreur si échec
write_pem_file = (path, content) ->
  fh, err = io.open path, "w"
  unless fh
    return false, "Impossible d'ouvrir #{path} : #{err}"
  ok_w, write_err = pcall -> fh\write content
  fh\close!
  unless ok_w
    return false, "Impossible d'écrire #{path} : #{write_err}"
  true, nil

--- Génère un certificat auto-signé via px5g et l'écrit dans les chemins demandés.
-- @tparam string key_path  Chemin de destination pour la clé privée
-- @tparam string cert_path Chemin de destination pour le certificat
-- @tparam table sans Liste des Subject Alternative Names (ex: {"DNS:custos", "IP:1.2.3.4"})
-- @treturn boolean true si la génération a réussi
-- @treturn string  Message d'erreur éventuel
generate_self_signed = (key_path, cert_path, sans) ->
  gen = require "auth.cert_generator"
  dns_sans = {}
  cn = "custos"

  if sans
    for san in *sans
      dns_name = san\match "^DNS:(.+)$"
      if dns_name and #dns_name > 0
        cn = dns_name if cn == "custos"
        table.insert dns_sans, dns_name

  key_pem, cert_pem, ok, err = gen.generate_self_signed cn, dns_sans, CERT_DAYS
  unless ok
    return false, err or "Échec génération px5g"

  ok_key, key_err = write_pem_file key_path, key_pem
  return false, key_err unless ok_key

  ok_cert, cert_err = write_pem_file cert_path, cert_pem
  unless ok_cert
    pcall os.remove, key_path
    return false, cert_err

  true, nil

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

--- Chemins des fichiers PEM du certificat dynamique d'un nom.
-- @tparam string hostname_lower Nom normalisé (validé par safe_cert_name)
-- @treturn string Chemin de la clé privée
-- @treturn string Chemin du certificat
sni_paths = (hostname_lower) ->
  year = os.date "%Y"
  "tmp/auth_sni_#{hostname_lower}_#{year}.key", "tmp/auth_sni_#{hostname_lower}_#{year}.crt"

--- Charge ou génère un contexte TLS pour un hostname SNI spécifique.
-- Utilise un cache LRU avec TTL pour éviter la régénération répétée.
-- @tparam string hostname Hostname SNI (ex: "example.com"), IP locale du repli, ou nil ("custos")
-- @tparam table cache Instance du cache (créée par cert_cache.create_cache)
-- @treturn table  Contexte TLS WolfSSL (ssl.newcontext)
-- @raise   string Message d'erreur si échec
load_or_generate_sni = (hostname, cache) ->
  -- Le nom peut venir du client : safe_cert_name interdit tout ce qui
  -- composerait un chemin hors de tmp/ (ou un CN douteux). L'IP locale du
  -- repli reste acceptée pour conserver le comportement historique.
  hostname_lower = safe_cert_name(hostname) or "custos"

  log_debug -> { action: "cert_sni_request", hostname: hostname_lower }

  -- Vérifier le cache
  entry = cache.get hostname_lower
  if entry and entry.ctx
    log_debug -> { action: "cert_sni_cache_hit_ram", hostname: hostname_lower }
    return entry.ctx

  key_file, cert_file = sni_paths hostname_lower

  if entry and entry.cert_pem and entry.key_pem
    -- Entry depuis disque, recréer contexte. materialize_pair réutilise la
    -- paire déjà présente (écrite par un autre enfant) au lieu de l'écraser.
    log_debug -> { action: "cert_sni_cache_hit_disk", hostname: hostname_lower }

    ok_pair, reused_ctx = pcall ->
      disk_key, disk_cert = materialize_pair key_file, cert_file, entry.key_pem, entry.cert_pem
      ctx = ssl.newcontext { certificate: cert_file, key: key_file }
      cache.set hostname_lower, disk_cert, disk_key, ctx
      ctx

    if ok_pair
      log_debug -> { action: "cert_sni_context_recreated", hostname: hostname_lower }
      return reused_ctx
    log_warn -> { action: "cert_sni_disk_reuse_failed", hostname: hostname_lower, err: tostring reused_ctx }

  -- Pas en cache ou erreur : générer
  log_debug -> { action: "cert_sni_cache_miss", hostname: hostname_lower }

  gen = require "auth.cert_generator"
  log_debug -> { action: "cert_sni_generating", hostname: hostname_lower }
  key_pem, cert_pem, ok, err = gen.generate_self_signed hostname_lower
  unless ok
    log_error -> { action: "cert_sni_generation_failed", hostname: hostname_lower, err: err }
    error "Impossible de générer le certificat SNI pour #{hostname_lower} : #{err}"

  log_debug -> { action: "cert_sni_generated", hostname: hostname_lower, key_size: #key_pem, cert_size: #cert_pem }

  -- WolfSSL utilise des fichiers, pas des PEM strings. materialize_pair écrit
  -- chaque fichier via temporaire + rename sous verrou et renvoie la paire
  -- réellement sur disque (celle d'un éventuel gagnant de la course).
  log_debug -> { action: "cert_sni_writing_files", key_file: key_file, cert_file: cert_file }
  key_pem, cert_pem = materialize_pair key_file, cert_file, key_pem, cert_pem

  -- Créer le contexte TLS via les fichiers
  log_debug -> { action: "cert_sni_newcontext", hostname: hostname_lower, protocol: "tlsv1_2" }
  ctx = ssl.newcontext {
    mode: "server"
    protocol: "tlsv1_2"
    certificate: cert_file
    key: key_file
    options: {"no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1"}
  }

  log_debug -> { action: "cert_sni_context_created", hostname: hostname_lower }

  -- Mettre en cache (avec les fichiers temporaires)
  cache.set hostname_lower, cert_pem, key_pem, ctx

  log_debug -> { action: "cert_sni_cached", hostname: hostname_lower }

  ctx

--- Charge un certificat et clé statiques (depuis config.moon).
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

--- Charge le certificat statique, en le générant (auto-signé) s'il est absent.
-- Ne lève jamais : sur une installation
-- fraîche, les chemins configurés (ex. /etc/custos/certs/auth.crt) n'existent
-- pas encore — on génère alors un auto-signé à ces emplacements (dossiers
-- parents créés, clé en 0600) pour que le portail fonctionne dès le premier
-- lancement. Retourne (ctx, nil) ou (nil, err) : l'appelant peut se replier
-- sur le cache SNI dynamique en cas d'échec.
-- @tparam string key_path  Chemin de la clé privée PEM
-- @tparam string cert_path Chemin du certificat PEM
-- @treturn table|nil Contexte TLS WolfSSL, ou nil si échec
-- @treturn string|nil Message d'erreur si échec
load_or_generate_static = (key_path, cert_path) ->
  unless key_path and cert_path
    return nil, "cert_path and key_path must be provided"

  unless file_exists(key_path) and file_exists(cert_path)
    for path in *{ key_path, cert_path }
      dir = path\match "^(.*)/[^/]+$"
      os.execute "mkdir -p '#{dir}'" if dir
    sans = { "DNS:custos" }
    for ip_san in *get_local_ips!
      table.insert sans, ip_san
    ok, gen_err = generate_self_signed key_path, cert_path, sans
    unless ok
      return nil, gen_err or "self-signed generation failed"
    os.execute "chmod 600 '#{key_path}'"

  load_static key_path, cert_path

{ :load_or_generate_sni, :load_static, :load_or_generate_static, :generate_self_signed, :make_context, :hash_string }
