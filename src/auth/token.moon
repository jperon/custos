-- src/auth/token.moon
-- Sessions HTTP stateless via HMAC-SHA256.
--
-- Format du token (valeur du cookie) :
--   "user=<u>&mac=<m>&expires=<n>&type=<t>&nonce=<16hex>.<64hex HMAC>"
--
-- Propriétés :
--   • Aucun état serveur : chaque enfant fork vérifie le token indépendamment.
--   • Rolling refresh : chaque ping émet un nouveau token avec expires mis à jour.
--   • Persistance restart : le token est dans le cookie du client, survit au
--     redémarrage du worker auth si la session.key ne change pas.

bit = require "bit"
ffi = require "ffi"

KEY_LEN = 32  -- 256 bits

-- ── Backend HMAC-SHA256 (même stratégie que credentials.moon) ─────────────────

load_sha = ->
  for name in *{"ipparse.lib.sha", "ipparse.lib.sha2", "sha2"}
    ok, mod = pcall require, name
    if ok and mod and mod.hmac and mod.sha256
      return mod
  error "Aucun backend SHA/HMAC disponible"

sha_mod = load_sha!
{ :hmac, :sha256 } = sha_mod

hex_to_bin = sha_mod.hex_to_bin or (hex) ->
  out = {}
  for i = 1, #hex, 2
    out[#out + 1] = string.char tonumber(hex\sub(i, i + 1), 16)
  table.concat out

bin_to_hex = (s) -> s\gsub(".", (c) -> string.format "%02x", string.byte(c))

hmac_bin = (key, msg) ->
  d = hmac sha256, key, msg
  if #d == 64 then hex_to_bin(d) else d

-- ── Aléatoire ────────────────────────────────────────────────────────────────

read_urandom = (n) ->
  fh = assert io.open("/dev/urandom", "rb"), "Impossible d'ouvrir /dev/urandom"
  data = fh\read n
  fh\close!
  assert data and #data == n, "Lecture incomplète /dev/urandom"
  data

-- ── Encodage du payload ──────────────────────────────────────────────────────
--
-- Les valeurs ne doivent pas contenir '&', '=' ni '.'.
-- user et mac sont déjà en format safe. expires et nonce sont hex/numériques.

encode_payload = (type_, user, mac, expires, nonce) ->
  "user=" .. tostring(user or "") ..
  "&mac=" .. tostring(mac or "") ..
  "&expires=" .. tostring(expires or 0) ..
  "&type=" .. tostring(type_ or "user") ..
  "&nonce=" .. tostring(nonce or "")

decode_payload = (s) ->
  t = {}
  for k, v in s\gmatch "([^&=]+)=([^&]*)"
    t[k] = v
  t.expires = tonumber t.expires
  t

-- ── API publique ─────────────────────────────────────────────────────────────

--- Génère un token HMAC signé.
-- @tparam string type_   "user" ou "admin"
-- @tparam string user    Identifiant utilisateur
-- @tparam string mac     Adresse MAC (peut être "" pour les admins)
-- @tparam number expires Timestamp d'expiration (os.time() + ttl)
-- @tparam string key     Clé HMAC (32 octets binaires)
-- @treturn string        Token opaque pour le cookie
generate = (type_, user, mac, expires, key) ->
  nonce   = bin_to_hex read_urandom 8
  encoded = encode_payload type_, user, mac, expires, nonce
  sig     = bin_to_hex hmac_bin key, encoded
  encoded .. "." .. sig

--- Vérifie un token et retourne son payload décodé.
-- @tparam string token  Valeur du cookie
-- @tparam string key    Clé HMAC (32 octets binaires)
-- @treturn table|nil    Payload { type, user, mac, expires, nonce } ou nil
-- @treturn nil|string   Message d'erreur
verify = (token, key) ->
  return nil, "token absent" unless token and #token > 0
  dot = token\find("%.", 1, true)
  return nil, "token malformé" unless dot
  encoded = token\sub 1, dot - 1
  sig_hex = token\sub dot + 1
  return nil, "signature trop courte" if #sig_hex ~= 64
  expected = bin_to_hex hmac_bin key, encoded
  -- Comparaison en temps constant
  diff = 0
  for i = 1, 64
    diff = bit.bor diff, bit.bxor sig_hex\byte(i), expected\byte(i)
  return nil, "signature invalide" if diff ~= 0
  p = decode_payload encoded
  return nil, "token expiré" if os.time! > (p.expires or 0)
  p, nil

--- Charge ou génère la clé HMAC depuis un fichier.
-- Si le fichier n'existe pas, génère 32 octets aléatoires et les y écrit.
-- @tparam  string path  Chemin du fichier (ex: /etc/custos/session.key)
-- @treturn string       Clé binaire de 32 octets
load_key = (path) ->
  fh = io.open path, "rb"
  if fh
    key = fh\read KEY_LEN
    fh\close!
    return key if key and #key == KEY_LEN
  key = read_urandom KEY_LEN
  fh, err = io.open path, "wb"
  error "Impossible d'écrire #{path} : #{err}" unless fh
  fh\write key
  fh\close!
  key

--- Extrait la valeur d'un cookie nommé depuis l'en-tête Cookie.
-- @tparam string header_val  Valeur de l'en-tête "Cookie: ..."
-- @tparam string name        Nom du cookie recherché
-- @treturn string|nil        Valeur du cookie ou nil
get_cookie = (header_val, name) ->
  return nil unless header_val
  pattern = name .. "=([^;]+)"
  header_val\match pattern

{ :generate, :verify, :load_key, :get_cookie }
