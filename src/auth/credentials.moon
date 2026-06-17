-- src/auth/credentials.moon
-- Vérification des mots de passe au format PBKDF2-SHA256.
--
-- Format du fichier secrets (une ligne par utilisateur) :
--   user:pbkdf2-sha256:<iter>:<salt_hex>:<hash_hex>
-- Lignes vides et commentaires (#) ignorés.
--
-- Implémentation crypto pure Lua, avec backend wolfSSL opportuniste si disponible.
--
-- Pour générer un hash (helper CLI) :
--   luajit lua/auth/credentials.lua <user> <password>

bit = require "bit"
ffi = require "ffi"

ffi.cdef [[
  int chmod(const char *path, unsigned int mode);
]]

HASH_LEN         = 32     -- SHA-256 → 32 octets
DEFAULT_ITER     = 10000
DEFAULT_SALT_LEN = 16     -- 128 bits

-- ── Backend SHA/HMAC ───────────────────────────────────────────────

is_hex_digest = (s) ->
  type(s) == "string" and #s == 64 and s\match("^[0-9a-fA-F]+$") != nil

load_sha = ->
  ok, mod = pcall require, "ipparse.lib.sha"
  return mod if ok and mod and mod.hmac and mod.sha256
  ok, mod = pcall require, "ipparse.lib.sha2"
  return mod if ok and mod and mod.hmac and mod.sha256 and mod.hex_to_bin
  ok, mod = pcall require, "sha2"
  return mod if ok and mod and mod.hmac and mod.sha256 and mod.hex_to_bin
  error "Aucun backend SHA/HMAC disponible"

sha = load_sha!
:hmac, :sha256 = sha
hex_to_bin = sha.hex_to_bin or (hex) ->
  out = {}
  for i = 1, #hex, 2
    out[#out + 1] = string.char tonumber(hex\sub(i, i + 1), 16)
  table.concat out

hmac_bin = (key, msg) ->
  d = hmac sha256, key, msg
  if is_hex_digest d
    hex_to_bin d
  else
    d

wolfssl_pbkdf2 = nil
do
  -- Prefer auth.ffi_wolfssl (already loaded in server context, reliable handle).
  -- Fall back to ffi_defs for standalone CLI usage.
  lib = nil
  ok, mod = pcall require, "auth.ffi_wolfssl"
  lib = mod.libwolfssl if ok and mod and mod.libwolfssl
  unless lib
    ok, ffi_defs = pcall require, "ffi_defs"
    lib = ffi_defs.libwolfssl if ok and ffi_defs and ffi_defs.libwolfssl

  if lib
    ok_cdef = pcall ffi.cdef, [[
      enum wc_HashType {
        WC_HASH_TYPE_SHA256 = 2
      };

      int wc_PBKDF2(unsigned char* output, const unsigned char* passwd, int pLen,
                    const unsigned char* salt, int sLen, int iterations, int kLen,
                    int hashType);
    ]]
    ok_sym = ok_cdef and pcall(-> lib.wc_PBKDF2)
    if ok_sym
      wolfssl = lib
      wolfssl_pbkdf2 = (password, salt_bin, iterations, dk_len = HASH_LEN) ->
        pass_len = #password
        salt_len = #salt_bin
        pass_buf = ffi.new "unsigned char[?]", math.max(pass_len, 1)
        salt_buf = ffi.new "unsigned char[?]", math.max(salt_len, 1)
        out = ffi.new "unsigned char[?]", dk_len

        if pass_len > 0
          ffi.copy pass_buf, password, pass_len
        if salt_len > 0
          ffi.copy salt_buf, salt_bin, salt_len

        rc = wolfssl.wc_PBKDF2 out, pass_buf, pass_len, salt_buf, salt_len, iterations, dk_len, 2
        return nil, "wc_PBKDF2 rc=#{rc}" if rc != 0
        ffi.string out, dk_len

-- Log which PBKDF2 backend is active (best-effort: log module may not be present in CLI mode).
do
  ok_log, log = pcall require, "log"
  if ok_log and log and log.log_info
    if wolfssl_pbkdf2
      log.log_info -> { action: "pbkdf2_backend", backend: "wolfssl" }
    else
      log.log_info -> { action: "pbkdf2_backend", backend: "lua_pure" }



bin_to_hex = (s) ->
  (s\gsub ".", (c) -> string.format "%02x", string.byte c)

u32be = (n) ->
  string.char(
    bit.band(bit.rshift(n, 24), 0xFF),
    bit.band(bit.rshift(n, 16), 0xFF),
    bit.band(bit.rshift(n, 8), 0xFF),
    bit.band(n, 0xFF)
  )

xor_bytes = (a, b) ->
  out = {}
  for i = 1, #a
    out[i] = string.char bit.bxor(a\byte(i), b\byte(i))
  table.concat out

-- ── PBKDF2-SHA256 ──────────────────────────────────────────────────

pbkdf2_raw = (password, salt_bin, iterations, dk_len = HASH_LEN) ->
  hlen = HASH_LEN
  blocks = math.ceil dk_len / hlen
  t = {}

  for i = 1, blocks
    u = hmac_bin password, salt_bin .. u32be(i)
    acc = u
    for _ = 2, iterations
      u = hmac_bin password, u
      acc = xor_bytes acc, u
    t[#t + 1] = acc

  derived = table.concat t
  derived\sub 1, dk_len

--- Calcule le hash PBKDF2-SHA256 d'un mot de passe.
-- @tparam string password   Mot de passe en clair
-- @tparam string salt_hex   Sel (hexadécimal)
-- @tparam number iterations Nombre d'itérations PBKDF2
-- @treturn string Hash en hexadécimal (64 caractères)
pbkdf2 = (password, salt_hex, iterations) ->
  salt_bin = hex_to_bin salt_hex
  if wolfssl_pbkdf2
    ok, out = pcall wolfssl_pbkdf2, password, salt_bin, iterations, HASH_LEN
    return bin_to_hex(out) if ok and out
  out = pbkdf2_raw password, salt_bin, iterations, HASH_LEN
  bin_to_hex out

read_urandom = (n) ->
  fh, err = io.open "/dev/urandom", "rb"
  error "Impossible d'ouvrir /dev/urandom : #{err}" unless fh
  data = fh\read n
  fh\close!
  error "Lecture incomplète de /dev/urandom" unless data and #data == n
  data

--- Génère un enregistrement de hash pour un mot de passe.
-- Retourne la chaîne à écrire dans le fichier secrets.
-- @tparam string password   Mot de passe en clair
-- @tparam number iterations Nombre d'itérations (défaut : 100000)
-- @treturn string Chaîne au format pbkdf2-sha256:<iter>:<salt_hex>:<hash_hex>
hash_password = (password, iterations) ->
  iterations = iterations or DEFAULT_ITER
  salt_hex = bin_to_hex read_urandom DEFAULT_SALT_LEN
  hash = pbkdf2 password, salt_hex, iterations
  "pbkdf2-sha256:#{iterations}:#{salt_hex}:#{hash}"

--- Décompose un enregistrement stocké en ses champs.
-- @tparam string stored Enregistrement pbkdf2-sha256:<iter>:<salt>:<hash>
-- @treturn table|nil { algo, iter, salt_hex, hash_hex } ou nil si malformé
parse_record = (stored) ->
  return nil unless type(stored) == "string"
  algo, iter_s, salt_hex, hash_hex = stored\match "^([^:]+):(%d+):([0-9a-f]+):([0-9a-f]+)$"
  return nil unless algo == "pbkdf2-sha256" and iter_s and salt_hex and hash_hex
  { :algo, iter: tonumber(iter_s), :salt_hex, :hash_hex }

-- Comparaison hex en temps constant (évite les timing attacks).
hex_equal_ct = (a, b) ->
  return false unless type(a) == "string" and type(b) == "string"
  return false if #a ~= #b
  diff = 0
  for i = 1, #a
    diff = bit.bor diff, bit.bxor a\byte(i), b\byte(i)
  diff == 0

--- Vérifie un mot de passe contre un enregistrement stocké.
-- Comparaison en temps constant pour éviter les attaques timing.
-- @tparam string password Mot de passe en clair
-- @tparam string stored   Enregistrement au format pbkdf2-sha256:<iter>:<salt>:<hash>
-- @treturn boolean        true si le mot de passe correspond
-- @treturn boolean        true si le hash doit être mis à jour (iter > DEFAULT_ITER)
verify_password = (password, stored) ->
  rec = parse_record stored
  return false unless rec
  computed = pbkdf2 password, rec.salt_hex, rec.iter
  return false unless hex_equal_ct computed, rec.hash_hex
  true, rec.iter > DEFAULT_ITER

--- Vérifie une réponse de challenge-réponse (hachage côté client).
-- Le client a calculé dk = PBKDF2(password, salt, iter) puis
-- response = HMAC(dk, nonce). Le serveur connaît dk (= hash stocké) et
-- recompute HMAC(hex_to_bin(hash_hex), nonce) pour comparer en temps constant.
-- @tparam string stored      Enregistrement stocké, ou nil/factice (user inconnu)
-- @tparam string nonce       Nonce du challenge (message HMAC)
-- @tparam string response_hex Réponse fournie par le client (hex)
-- @treturn boolean true si la réponse correspond
verify_response = (stored, nonce, response_hex) ->
  rec = parse_record stored
  return false unless rec and type(nonce) == "string" and type(response_hex) == "string"
  expected = bin_to_hex hmac_bin hex_to_bin(rec.hash_hex), nonce
  hex_equal_ct expected, response_hex

-- ── Chargement du fichier secrets ──────────────────────────────────

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

-- ── Inscription ────────────────────────────────────────────────────

--- Valide un identifiant (courriel) pour l'inscription.
-- Doit être une adresse de type local@domaine, 3 à 64 caractères.
-- Caractères autorisés : alphanumériques, _ . - +, exactement un @.
-- @tparam string username Identifiant proposé
-- @treturn boolean true si valide
valid_username = (username) ->
  return false unless #username >= 3 and #username <= 64
  return false unless username\match "^[a-zA-Z0-9_.%-+]+@[a-zA-Z0-9_.%-]+%.[a-zA-Z]+$"
  true

--- Inscrit un nouvel utilisateur dans le fichier secrets.
-- Vérifie l'absence de doublon, hash le mot de passe, et append
-- la ligne de manière atomique (write temp + rename).
-- Retourne la nouvelle table secrets en cas de succès.
-- @tparam string username    Nom d'utilisateur (3-32 chars, [a-zA-Z0-9_.-])
-- @tparam string password    Mot de passe en clair (≥ 8 caractères)
-- @tparam string secrets_path Chemin du fichier secrets
-- @tparam table  current_secrets Table actuelle {user → hash} (pour vérif doublon)
-- @treturn table|nil  Nouvelle table secrets, ou nil en cas d'erreur
-- @treturn string     Message d'erreur (si nil)
register_user = (username, password, secrets_path, current_secrets) ->
  unless valid_username username
    return nil, "Adresse de courriel invalide."
  if #password < 8
    return nil, "Le mot de passe doit contenir au moins 8 caractères."
  if current_secrets and current_secrets[username]
    return nil, "Ce nom d'utilisateur est déjà pris."

  hash_entry = hash_password password

  tmp_path = secrets_path .. ".new"
  fh, err = io.open tmp_path, "w"
  unless fh
    return nil, "Impossible de créer le fichier temporaire : #{err}"

  existing = io.open secrets_path, "r"
  if existing
    for line in existing\lines!
      fh\write line .. "\n"
    existing\close!

  fh\write "#{username}:#{hash_entry}\n"
  fh\close!

  -- Set restrictive permissions (600) before rename
  ffi.C.chmod tmp_path, 0x180  -- 0o600

  ok, rename_err = os.rename tmp_path, secrets_path
  unless ok
    os.remove tmp_path
    return nil, "Impossible de renommer le fichier secrets : #{rename_err}"

  new_secrets, load_err = load_secrets secrets_path
  unless new_secrets
    return nil, "Impossible de recharger le fichier secrets : #{load_err}"

  new_secrets

--- Met à jour le hash d'un utilisateur existant dans le fichier secrets.
-- Réécrit le fichier de façon atomique (temp + rename).
-- Typiquement appelé après verify_password pour migrer un hash obsolète.
-- @tparam string username     Nom d'utilisateur
-- @tparam string password     Mot de passe en clair (pour recalculer le hash)
-- @tparam string secrets_path Chemin du fichier secrets
-- @treturn true|nil   true en cas de succès, nil + message d'erreur sinon
-- @treturn nil|string Message d'erreur
update_user_hash = (username, password, secrets_path) ->
  new_entry = hash_password password
  tmp_path = secrets_path .. ".new"
  fh, err = io.open tmp_path, "w"
  return nil, "Impossible de créer le fichier temporaire : #{err}" unless fh

  existing = io.open secrets_path, "r"
  if existing
    for line in existing\lines!
      u = line\match "^([^:]+):"
      if u == username
        fh\write "#{username}:#{new_entry}\n"
      else
        fh\write line .. "\n"
    existing\close!

  fh\close!
  ffi.C.chmod tmp_path, 0x180  -- 0o600

  ok, rename_err = os.rename tmp_path, secrets_path
  unless ok
    os.remove tmp_path
    return nil, "Impossible de renommer le fichier secrets : #{rename_err}"

  true

--- Écrit un enregistrement déjà calculé (hash côté client) pour un utilisateur.
-- Le serveur ne voit jamais le mot de passe : le client fournit directement
-- l'enregistrement pbkdf2-sha256:<iter>:<salt>:<hash>. Remplace la ligne de
-- l'utilisateur si elle existe, l'ajoute sinon. Écriture atomique (temp+rename).
-- @tparam string username     Nom d'utilisateur
-- @tparam string record       Enregistrement pbkdf2-sha256:<iter>:<salt>:<hash>
-- @tparam string secrets_path Chemin du fichier secrets
-- @treturn true|nil   true en cas de succès, nil + message d'erreur sinon
-- @treturn nil|string Message d'erreur
set_record = (username, record, secrets_path) ->
  return nil, "Enregistrement invalide." unless parse_record record
  tmp_path = secrets_path .. ".new"
  fh, err = io.open tmp_path, "w"
  return nil, "Impossible de créer le fichier temporaire : #{err}" unless fh

  found = false
  existing = io.open secrets_path, "r"
  if existing
    for line in existing\lines!
      u = line\match "^([^:]+):"
      if u == username
        fh\write "#{username}:#{record}\n"
        found = true
      else
        fh\write line .. "\n"
    existing\close!
  fh\write "#{username}:#{record}\n" unless found

  fh\close!
  ffi.C.chmod tmp_path, 0x180  -- 0o600

  ok, rename_err = os.rename tmp_path, secrets_path
  unless ok
    os.remove tmp_path
    return nil, "Impossible de renommer le fichier secrets : #{rename_err}"

  true

{ :pbkdf2, :hash_password, :verify_password, :verify_response, :parse_record,
  :update_user_hash, :set_record, :load_secrets, :valid_username, :register_user,
  :DEFAULT_ITER, :DEFAULT_SALT_LEN, :hmac_bin, :bin_to_hex, :hex_to_bin }
