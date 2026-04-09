-- src/auth/cert.moon
-- Génération d'un certificat TLS auto-signé et chargement du contexte luasec.
--
-- Si les fichiers cert/key existent déjà, ils sont réutilisés directement.
-- Sinon, un certificat RSA-2048 auto-signé est généré via `openssl req`.
--
-- Dépendance : luasec (paquet Debian : lua-luasec).

ssl = require "ssl"

CERT_DAYS     = 3650    -- validité : ~10 ans
CERT_KEY_BITS = 2048

--- Génère un certificat RSA auto-signé via l'outil `openssl`.
-- @tparam string key_path  Chemin de destination pour la clé privée
-- @tparam string cert_path Chemin de destination pour le certificat
-- @treturn boolean true si la génération a réussi
-- @treturn string  Sortie de la commande (stderr inclus), ou message d'erreur
generate_self_signed = (key_path, cert_path) ->
  cmd = string.format(
    "openssl req -x509 -newkey rsa:%d -keyout '%s' -out '%s'" ..
    " -days %d -nodes -subj '/CN=custos' 2>&1",
    CERT_KEY_BITS, key_path, cert_path, CERT_DAYS
  )
  fh = io.popen cmd
  out = fh\read "*a"
  ok = fh\close!
  ok, out

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
    options:     {"all", "no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1"}
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
  unless file_exists(key_path) and file_exists(cert_path)
    ok, out = generate_self_signed key_path, cert_path
    error "Impossible de générer le certificat TLS :\n#{out}" unless ok
  make_context key_path, cert_path

{ :load_or_generate, :generate_self_signed, :make_context }
