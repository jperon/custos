-- src/auth/cert.moon
-- Génération d'un certificat TLS auto-signé et chargement du contexte wolfssl FFI.
--
-- Si les fichiers cert/key existent déjà, ils sont réutilisés directement.
-- Sinon, un certificat RSA-2048 auto-signé est généré via `openssl req`.
--
-- Utilise ffi_wolfssl (FFI wrapper pour WolfSSL, remplace luasec).

ssl = require "auth.ffi_wolfssl"

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

{ :load_or_generate, :generate_self_signed, :make_context }
