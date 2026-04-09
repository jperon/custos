-- src/auth/credentials.moon
-- Vérification des mots de passe au format PBKDF2-SHA256.
--
-- Format du fichier secrets (une ligne par utilisateur) :
--   user:pbkdf2-sha256:<iter>:<salt_hex>:<hash_hex>
-- Lignes vides et commentaires (#) ignorés.
--
-- Le hash est calculé via PKCS5_PBKDF2_HMAC (OpenSSL libcrypto),
-- déjà disponible comme dépendance transitive de luasec.
--
-- Pour générer un hash (helper CLI) :
--   luajit lua/auth/credentials.lua <user> <password>

ffi = require "ffi"
bit = require "bit"

local crypto
do
  ok, lib = pcall ffi.load, "crypto"
  error "libcrypto introuvable (paquet openssl requis)" unless ok
  crypto = lib

ffi.cdef [[
  int PKCS5_PBKDF2_HMAC(
    const char *pass, int passlen,
    const unsigned char *salt, int saltlen,
    int iter,
    const void *digest,
    int keylen, unsigned char *out
  );
  const void* EVP_sha256(void);
  int RAND_bytes(unsigned char *buf, int num);
]]

HASH_LEN         = 32     -- SHA-256 → 32 octets
DEFAULT_ITER     = 100000
DEFAULT_SALT_LEN = 16     -- 128 bits

-- ── Utilitaires hex ─────────────────────────────────────────────

--- Convertit une chaîne hexadécimale en buffer FFI.
-- @tparam  string hex Chaîne hexadécimale (longueur paire)
-- @treturn cdata, number Buffer uint8_t[] et sa longueur en octets
hex_to_buf = (hex) ->
  n = math.floor(#hex / 2)
  buf = ffi.new "uint8_t[?]", n
  for i = 0, n - 1
    buf[i] = tonumber hex\sub(i * 2 + 1, i * 2 + 2), 16
  buf, n

--- Convertit un buffer FFI en chaîne hexadécimale minuscule.
-- @tparam cdata  buf Buffer uint8_t[]
-- @tparam number len Nombre d'octets à convertir
-- @treturn string Chaîne hexadécimale
buf_to_hex = (buf, len) ->
  t = {}
  for i = 0, len - 1
    t[i + 1] = string.format "%02x", buf[i]
  table.concat t

-- ── PBKDF2-SHA256 ───────────────────────────────────────────────

--- Calcule le hash PBKDF2-SHA256 d'un mot de passe.
-- @tparam string password   Mot de passe en clair
-- @tparam string salt_hex   Sel (hexadécimal)
-- @tparam number iterations Nombre d'itérations PBKDF2
-- @treturn string Hash en hexadécimal (64 caractères)
pbkdf2 = (password, salt_hex, iterations) ->
  salt_buf, salt_len = hex_to_buf salt_hex
  out = ffi.new "uint8_t[32]"
  rc = crypto.PKCS5_PBKDF2_HMAC(
    password, #password,
    salt_buf, salt_len,
    iterations,
    crypto.EVP_sha256!,
    HASH_LEN, out
  )
  error "PKCS5_PBKDF2_HMAC a échoué" unless rc == 1
  buf_to_hex out, HASH_LEN

--- Génère un enregistrement de hash pour un mot de passe.
-- Retourne la chaîne à écrire dans le fichier secrets.
-- @tparam string password   Mot de passe en clair
-- @tparam number iterations Nombre d'itérations (défaut : 100000)
-- @treturn string Chaîne au format pbkdf2-sha256:<iter>:<salt_hex>:<hash_hex>
hash_password = (password, iterations) ->
  iterations = iterations or DEFAULT_ITER
  salt_buf = ffi.new "uint8_t[?]", DEFAULT_SALT_LEN
  rc = crypto.RAND_bytes salt_buf, DEFAULT_SALT_LEN
  error "RAND_bytes a échoué" unless rc == 1
  salt_hex = buf_to_hex salt_buf, DEFAULT_SALT_LEN
  hash     = pbkdf2 password, salt_hex, iterations
  "pbkdf2-sha256:#{iterations}:#{salt_hex}:#{hash}"

--- Vérifie un mot de passe contre un enregistrement stocké.
-- Comparaison en temps constant pour éviter les attaques timing.
-- @tparam string password Mot de passe en clair
-- @tparam string stored   Enregistrement au format pbkdf2-sha256:<iter>:<salt>:<hash>
-- @treturn boolean true si le mot de passe correspond
verify_password = (password, stored) ->
  algo, iter_s, salt_hex, hash_hex = stored\match "^([^:]+):(%d+):([0-9a-f]+):([0-9a-f]+)$"
  return false unless algo == "pbkdf2-sha256" and iter_s and salt_hex and hash_hex
  computed = pbkdf2 password, salt_hex, tonumber iter_s
  -- Comparaison en temps constant (évite les timing attacks)
  return false if #computed ~= #hash_hex
  diff = 0
  for i = 1, #computed
    diff = bit.bor diff, bit.bxor computed\byte(i), hash_hex\byte(i)
  diff == 0

-- ── Chargement du fichier secrets ───────────────────────────────

--- Charge un fichier secrets et retourne une table user → hash stocké.
-- Format : une ligne par utilisateur "user:pbkdf2-sha256:<iter>:<salt>:<hash>".
-- Lignes vides et commentaires (#) ignorés.
-- @tparam  string     path Chemin du fichier secrets
-- @treturn table|nil       Table {user → stored}, ou nil + erreur
-- @treturn nil|string      Message d'erreur
load_secrets = (path) ->
  fh, err = io.open path, "r"
  return nil, "impossible d'ouvrir #{path} : #{err}" unless fh
  secrets = {}
  for line in fh\lines!
    line = line\match "^%s*(.-)%s*$"
    if line ~= "" and not line\match "^#"
      user, stored = line\match "^([^:]+):(.+)$"
      secrets[user] = stored if user and stored
  fh\close!
  secrets

{ :pbkdf2, :hash_password, :verify_password, :load_secrets }
