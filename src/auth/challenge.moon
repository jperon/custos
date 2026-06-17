-- src/auth/challenge.moon
-- Challenge-réponse à nonce pour le portail captif (login / changement de mot
-- de passe). Le nonce est signé et borné dans le temps, sans état serveur
-- (cohérent avec auth.token), car le worker AUTH est multi-process.
--
-- Format du nonce :
--   <rand16hex>.<expires>.<mac>.<sig>
-- où sig = HMAC(token_key, "<rand16hex>.<expires>.<mac>").
--
-- La MAC du client est intégrée à la signature : un nonce ne vaut que pour la
-- MAC à laquelle il a été émis, ce qui réduit encore la fenêtre de rejeu.

bit = require "bit"
credentials = require "auth.credentials"
{ :hmac_bin, :bin_to_hex, :DEFAULT_ITER, :DEFAULT_SALT_LEN, :parse_record } = credentials

read_urandom = (n) ->
  fh = assert io.open("/dev/urandom", "rb"), "Impossible d'ouvrir /dev/urandom"
  data = fh\read n
  fh\close!
  assert data and #data == n, "Lecture incomplète /dev/urandom"
  data

norm_mac = (mac) ->
  if mac and mac ~= "" then tostring(mac)\lower! else "unknown"

sign = (token_key, payload) -> bin_to_hex hmac_bin token_key, payload

hex_equal_ct = (a, b) ->
  return false unless type(a) == "string" and type(b) == "string"
  return false if #a ~= #b
  diff = 0
  for i = 1, #a
    diff = bit.bor diff, bit.bxor a\byte(i), b\byte(i)
  diff == 0

--- Génère un nonce signé pour un client.
-- @tparam string token_key Clé HMAC (32 octets binaires)
-- @tparam string mac       MAC du client (liée à la signature)
-- @tparam number ttl       Durée de validité en secondes (défaut 120)
-- @treturn string Nonce opaque
make_nonce = (token_key, mac, ttl=120) ->
  rand = bin_to_hex read_urandom 8
  expires = os.time! + (tonumber(ttl) or 120)
  payload = "#{rand}.#{expires}.#{norm_mac mac}"
  "#{payload}.#{sign token_key, payload}"

--- Vérifie un nonce : signature, expiration, liaison à la MAC.
-- @tparam string token_key Clé HMAC
-- @tparam string mac       MAC du client courant
-- @tparam string nonce     Nonce à vérifier
-- @treturn boolean ok
-- @treturn string|nil message d'erreur
verify_nonce = (token_key, mac, nonce) ->
  return false, "nonce absent" unless type(nonce) == "string" and #nonce > 0
  rand, expires_s, n_mac, sig = nonce\match "^(%x+)%.(%d+)%.([^.]+)%.(%x+)$"
  return false, "nonce malformé" unless rand and expires_s and n_mac and sig
  payload = "#{rand}.#{expires_s}.#{n_mac}"
  return false, "signature invalide" unless hex_equal_ct sig, sign token_key, payload
  return false, "mac inattendue" unless n_mac == norm_mac mac
  return false, "nonce expiré" if os.time! > tonumber expires_s
  true

--- Retourne { salt, iter } pour un utilisateur, sans révéler son existence.
-- User connu → salt/iter réels du fichier secrets. User inconnu → salt
-- déterministe dérivé de la clé (anti-énumération), iter par défaut.
-- @tparam table  secrets   Table { user → record }
-- @tparam string token_key Clé HMAC (pour le salt factice)
-- @tparam string user      Identifiant demandé
-- @treturn table { salt = <hex>, iter = <number> }
salt_iter_for = (secrets, token_key, user) ->
  rec = parse_record (secrets and secrets[user])
  if rec
    { salt: rec.salt_hex, iter: rec.iter }
  else
    user_lc = tostring(user or "")\lower!
    fake = bin_to_hex hmac_bin token_key, "salt:#{user_lc}"
    { salt: fake\sub(1, DEFAULT_SALT_LEN * 2), iter: DEFAULT_ITER }

{ :make_nonce, :verify_nonce, :salt_iter_for }
