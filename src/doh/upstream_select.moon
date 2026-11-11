-- src/doh/upstream_select.moon
-- Sélection du transport DoH amont, décidée une seule fois par processus.
--
-- curl (`doh.upstream_doh_curl`, HTTP/2, vérification native) est le transport
-- normal. wolfSSL (`doh.upstream_doh`, HTTP/1.1) n'est utilisé que si libcurl
-- ne peut être chargé (ffi.load) ou initialisé (curl_easy_init). Une erreur de
-- requête (timeout, 5xx, refus TLS…) n'est jamais une raison de basculer : la
-- décision est figée au démarrage (worker) ou à la première ouverture
-- (validateur).
--
-- Le repli vérifie certificat + nom d'hôte quand la libwolfssl chargée le
-- permet. Sinon il refuse de fonctionner, sauf `doh.upstream_fallback_insecure`
-- pour l'upstream de production (jamais pour le validateur, dont un verdict
-- forgé serait pire qu'une absence de verdict).

{ :log_info, :log_warn } = require "log"

CURL_MOD = "doh.upstream_doh_curl"
WOLF_MOD = "doh.upstream_doh"

--- Charge curl et vérifie qu'il peut réellement créer une session.
-- @tparam function req Fonction require (injectable en test).
-- @treturn table|nil Module curl, string|nil raison d'indisponibilité.
load_curl = (req) ->
  ok, mod = pcall req, CURL_MOD
  unless ok
    return nil, "load_failed: #{tostring mod}"
  if type(mod.probe) == "function"
    ok_p, avail, why = pcall mod.probe
    unless ok_p
      return nil, "init_probe_failed: #{tostring avail}"
    unless avail
      return nil, "init_failed: #{tostring why}"
  mod

--- Descripteur de repli qui refuse toute connexion (vérification impossible).
-- @tparam string reason Raison lisible.
-- @treturn table Descripteur {transport, verify_tls, make_client, close}.
refused_desc = (reason) ->
  {
    transport: "wolfssl_refused"
    verify_tls: false
    make_client: (url, timeout_ms, verify_tls) ->
      nil, "upstream_doh: tls_verify_unavailable: #{reason}"
    close: ->
  }

--- Descripteur du transport curl.
make_curl_desc = (mod, opts) ->
  verify = opts.verify_tls != false
  log_info -> {
    action: "upstream_doh_curl_enabled"
    url: opts.url
    verify_tls: verify
  }
  unless verify
    log_warn -> {
      action: "upstream_doh_tls_verify_disabled"
      url: opts.url
      detail: "certificat TLS du résolveur amont NON vérifié (MITM possible)"
    }
  {
    transport: "curl"
    verify_tls: verify
    make_client: (url, timeout_ms, verify_tls) ->
      mod.new_client url, timeout_ms, verify_tls
    close: (client) -> mod.close client
  }

--- Descripteur du repli wolfSSL (vérifié, non vérifié, ou refusé).
-- Un unique `log_warn` `doh_upstream_fallback_wolfssl` porte la raison du
-- repli et le niveau de vérification TLS effectif.
make_wolf_desc = (mod, opts, curl_reason) ->
  role    = opts.role or "upstream"
  wanted  = opts.verify_tls != false
  verify_ok, verify_why, ca_file = true, nil, nil

  if wanted
    if type(mod.verification_available) == "function"
      ok_v, a, why, ca = pcall mod.verification_available, { ca_file: opts.ca_file }
      unless ok_v
        verify_ok, verify_why = false, "sonde de vérification en échec: #{tostring a}"
      else
        verify_ok  = a == true
        verify_why = why
        ca_file    = ca
    else
      -- Module sans sonde : impossible de garantir la vérification.
      verify_ok, verify_why = false, "module sans verification_available"

  insecure_allowed = role != "validator" and opts.fallback_insecure == true
  effective = false

  if wanted and verify_ok
    effective = true
  elseif wanted and not verify_ok and not insecure_allowed
    reason = "curl #{curl_reason}; wolfSSL: #{verify_why or 'vérification indisponible'}"
    log_warn -> {
      action: "doh_upstream_fallback_wolfssl"
      url: opts.url
      reason: reason
      verify_tls: false
      refused: true
      detail: "repli refusé : vérification TLS impossible et doh.upstream_fallback_insecure=false (ou validateur)"
    }
    return refused_desc verify_why or "vérification indisponible"

  detail = nil
  unless effective
    detail = if wanted
      "repli wolfSSL NON vérifié (certificat et nom d'hôte) — MITM possible (doh.upstream_fallback_insecure=true)"
    else
      "repli wolfSSL NON vérifié (doh.upstream_doh_tls_verify=false)"
  log_warn -> {
    action: "doh_upstream_fallback_wolfssl"
    url: opts.url
    reason: "curl #{curl_reason}"
    verify_tls: effective
    detail: detail
  }
  {
    transport: "wolfssl"
    verify_tls: effective
    make_client: (url, timeout_ms) ->
      mod.new_client url, timeout_ms, effective, { ca_file: ca_file }
    close: (client) -> mod.close client
  }

--- Choisit le transport DoH amont. Décision unique, jamais remise en cause par
-- une erreur de requête.
-- @tparam table opts {url, timeout_ms, verify_tls, fallback_insecure, ca_file, role}
-- @tparam table|nil deps {require_fn} injectable en test.
-- @treturn table|nil Descripteur {transport, verify_tls, make_client, close}.
-- @treturn string|nil Erreur si aucun transport n'est disponible.
select = (opts, deps={}) ->
  unless opts and opts.url
    return nil, "upstream_select: url manquante"

  wanted = if opts.verify_tls == nil then true else opts.verify_tls
  o = {
    url: opts.url
    timeout_ms: opts.timeout_ms
    verify_tls: wanted
    fallback_insecure: opts.fallback_insecure == true
    ca_file: opts.ca_file
    role: opts.role or "upstream"
  }
  req = deps.require_fn or require

  curl_mod, curl_reason = load_curl req
  return make_curl_desc curl_mod, o if curl_mod

  ok_w, wolf_mod = pcall req, WOLF_MOD
  unless ok_w
    reason = "curl #{curl_reason}; wolfSSL load_failed: #{tostring wolf_mod}"
    log_warn -> {
      action: "doh_upstream_fallback_wolfssl"
      url: o.url
      reason: reason
      verify_tls: "none"
      detail: "aucun transport DoH amont disponible"
    }
    return nil, reason

  make_wolf_desc wolf_mod, o, curl_reason

{ :select, :load_curl }
