-- src/auth/cert_expiry.moon
-- Avertissements d'expiration des certificats statiques.
--
-- AUTH et DoH chargent un certificat statique depuis `auth.cert`/`doh.cert`
-- (souvent un `fullchain.pem`). Un certificat expiré était servi sans aucune
-- trace : ce module lit `notAfter` via WolfSSL et émet `cert_expired` /
-- `cert_expires_soon` (seuil 14 jours) au démarrage du worker.
--
-- Le parsing ASN.1 est fait en Lua pur sur les octets de `WOLFSSL_ASN1_TIME`
-- (UTCTime `YYMMDDHHMMSSZ` / GeneralizedTime `YYYYMMDDHHMMSSZ`) : il est
-- testable sans certificat et sans dépendre de `struct tm` côté FFI.

ffi = require "ffi"
ssl = require "auth.ffi_wolfssl"
{ :log_warn, :log_debug } = require "log"

SSL_FILETYPE_PEM = 1
SECONDS_PER_DAY  = 86400
EXPIRY_WARN_DAYS = 14

--- Jours civils depuis 1970-01-01 (algorithme days_from_civil, UTC).
-- @tparam number year Année complète (ex. 2026).
-- @tparam number month Mois 1-12.
-- @tparam number day Jour 1-31.
-- @treturn number Nombre de jours (négatif avant 1970).
days_from_civil = (year, month, day) ->
  y = if month <= 2 then year - 1 else year
  era = if y >= 0
    math.floor y / 400
  else
    math.floor (y - 399) / 400
  yoe = y - era * 400
  mp = (month + 9) % 12
  doy = math.floor((153 * mp + 2) / 5) + day - 1
  doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
  era * 146097 + doe - 719468

--- Convertit une date UTC en timestamp epoch.
-- @tparam number year Année complète.
-- @tparam number month Mois 1-12.
-- @tparam number day Jour 1-31.
-- @tparam number hour Heure 0-23.
-- @tparam number min Minute 0-59.
-- @tparam number sec Seconde 0-59.
-- @treturn number Timestamp epoch UTC.
utc_epoch = (year, month, day, hour, min, sec) ->
  days_from_civil(year, month, day) * SECONDS_PER_DAY +
    hour * 3600 + min * 60 + sec

--- Parse une date ASN.1 `notAfter` (UTCTime ou GeneralizedTime, suffixe Z).
-- @tparam string|nil s Chaîne ASCII de la date.
-- @treturn number|nil Timestamp epoch, ou nil si le format est inattendu.
parse_asn1_time = (s) ->
  return nil unless type(s) == "string"
  len = #s
  return nil unless s\sub(len, len) == "Z"

  year = nil
  off = nil
  if len == 13
    yy = tonumber s\sub(1, 2)
    return nil unless yy
    year = if yy >= 50 then 1900 + yy else 2000 + yy
    off = 3
  elseif len == 15
    year = tonumber s\sub(1, 4)
    return nil unless year
    off = 5
  else
    return nil

  month = tonumber s\sub(off, off + 1)
  day   = tonumber s\sub(off + 2, off + 3)
  hour  = tonumber s\sub(off + 4, off + 5)
  min   = tonumber s\sub(off + 6, off + 7)
  sec   = tonumber s\sub(off + 8, off + 9)
  return nil unless month and day and hour and min and sec
  return nil unless month >= 1 and month <= 12
  return nil unless day >= 1 and day <= 31
  return nil unless hour <= 23 and min <= 59 and sec <= 59
  utc_epoch year, month, day, hour, min, sec

--- Lit la date `notAfter` d'un certificat PEM via WolfSSL.
-- @tparam string path Chemin du certificat PEM.
-- @tparam table|nil lib Bibliothèque FFI (défaut : libwolfssl).
-- @treturn number|nil Timestamp epoch de `notAfter`.
-- @treturn string|nil Raison si la date n'est pas lisible.
certificate_not_after = (path, lib) ->
  lib or= ssl.libwolfssl
  return nil, "library_unavailable" unless lib
  for name in *{"wolfSSL_X509_load_certificate_file", "wolfSSL_X509_get_notAfter", "wolfSSL_X509_free"}
    return nil, "symbol_missing:#{name}" unless ssl.symbol_available name, lib

  ok_load, x509 = pcall -> lib.wolfSSL_X509_load_certificate_file path, SSL_FILETYPE_PEM
  return nil, "load_failed" unless ok_load and x509 != nil

  ok_asn, asn = pcall -> lib.wolfSSL_X509_get_notAfter x509
  unless ok_asn and asn != nil and asn.length and asn.length > 0
    pcall -> lib.wolfSSL_X509_free x509
    return nil, "not_after_unavailable"

  text = ffi.string asn.data, asn.length
  pcall -> lib.wolfSSL_X509_free x509
  epoch = parse_asn1_time text
  return nil, "unparsable:#{text}" unless epoch
  epoch

--- Classe une échéance vis-à-vis de maintenant.
-- @tparam number|nil not_after Timestamp epoch de `notAfter`.
-- @tparam number now Timestamp courant.
-- @tparam number|nil warn_days Seuil d'avertissement (défaut 14 jours).
-- @treturn string|nil "expired", "expires_soon", "valid", ou nil si date absente.
classify_expiry = (not_after, now, warn_days=EXPIRY_WARN_DAYS) ->
  return nil unless type(not_after) == "number"
  if not_after <= now
    "expired"
  elseif not_after - now <= warn_days * SECONDS_PER_DAY
    "expires_soon"
  else
    "valid"

--- Émet un avertissement si un certificat statique est expiré ou proche de
-- l'expiration. Silencieux (hors DEBUG) si la date n'est pas lisible.
-- @tparam string|nil path Chemin du certificat PEM.
-- @tparam table|nil opts {now, warn_days, worker, lib, log_warn_fn, log_debug_fn}.
-- @treturn string|nil Statut ("expired"/"expires_soon"/"valid") ou nil.
check_cert = (path, opts={}) ->
  return nil unless path
  now = opts.now or os.time!
  warn_fn = opts.log_warn_fn or log_warn
  debug_fn = opts.log_debug_fn or log_debug
  not_after, err = certificate_not_after path, opts.lib
  unless not_after
    debug_fn -> { action: "cert_expiry_unknown", cert: path, err: err or "unknown" }
    return nil

  status = classify_expiry not_after, now, opts.warn_days
  return status unless status == "expired" or status == "expires_soon"

  fields = {
    cert: path
    not_after: os.date "!%Y-%m-%dT%H:%M:%SZ", not_after
    days_left: math.floor((not_after - now) / SECONDS_PER_DAY)
    worker: opts.worker
    action: if status == "expired" then "cert_expired" else "cert_expires_soon"
  }
  warn_fn -> fields
  status

{ :days_from_civil, :utc_epoch, :parse_asn1_time, :certificate_not_after, :classify_expiry, :check_cert, :EXPIRY_WARN_DAYS, :SECONDS_PER_DAY }
