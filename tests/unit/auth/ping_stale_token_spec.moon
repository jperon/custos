-- tests/unit/auth/ping_stale_token_spec.moon
-- Régression : un ping retardé par le navigateur (file d'attente ~70 s) part
-- avec un token périmé alors qu'un ping plus récent a déjà prolongé la session.
-- Le 401 strict déclenchait une fausse alerte de déconnexion côté client.
-- Fix : token authentique mais expiré + session encore vivante → 204 no-op
-- (ni refresh nft, ni write_sessions, ni nouveau cookie).

token = require "auth.token"
{ :handle_ping } = require "auth.handlers"
{ :add_session, :load_sessions, :write_sessions, :reset_cache } = require "auth.sessions"

SESS = "tmp/ping_stale_spec_sessions.lua"
KEY  = token.load_key "tmp/ping_stale_spec.key"
MAC  = "aa:bb:cc:44:55:66"
IP   = "10.42.0.60"
USER = "alice@test.lan"
IDLE = 300

make_state = (nft_sess) ->
  {
    token_key: KEY
    sessions_file: SESS
    auth_cfg: { idle_timeout: IDLE }
    nft_sess: nft_sess
  }

ping_req = (tok) ->
  { headers: { cookie: "custos_session=#{tok}" }, path: "/ping", method: "GET" }

write_session_expiring = (expires) ->
  sessions = {}
  add_session sessions, MAC, IP, USER, expires
  write_sessions sessions, SESS
  reset_cache!

describe "handle_ping (token périmé hors séquence)", ->
  original_os_time = os.time
  -- NOW proche de l'heure réelle : auth.sessions capture os.time au chargement
  -- (cf. bye_spec), un NOW figé dans le passé ferait purger les sessions.
  NOW = original_os_time!

  before_each ->
    os.time = -> NOW
    reset_cache!

  after_each ->
    os.time = original_os_time
    os.remove SESS

  it "token.verify retourne le payload en 3e valeur quand le token est expiré", ->
    tok = token.generate "user", USER, MAC, NOW - 10, KEY
    p, err, expired_p = token.verify tok, KEY
    assert.is_nil p
    assert.equals "token expiré", err
    assert.is_not_nil expired_p
    assert.equals MAC, expired_p.mac
    assert.equals USER, expired_p.user

  it "token.verify ne retourne PAS de payload sur signature invalide", ->
    tok = token.generate "user", USER, MAC, NOW - 10, KEY
    bad = tok\sub(1, #tok - 4) .. "0000"
    p, err, expired_p = token.verify bad, KEY
    assert.is_nil p
    assert.equals "signature invalide", err
    assert.is_nil expired_p

  it "token expiré + session vivante → 204 no-op (pas de refresh ni cookie)", ->
    write_session_expiring NOW + IDLE
    calls = {}
    nft_sess = {
      add_authenticated: (ip, ttl) -> calls[#calls + 1] = { "ip", ip, ttl }
      add_authenticated_mac: (mac, ttl) -> calls[#calls + 1] = { "mac", mac, ttl }
    }
    tok = token.generate "user", USER, MAC, NOW - 10, KEY
    status, headers = handle_ping (ping_req tok), IP, MAC, make_state nft_sess
    assert.equals 204, status
    assert.is_nil headers["Set-Cookie"], "pas de nouveau cookie pour un token périmé"
    assert.equals 0, #calls, "pas de refresh nft pour un token périmé"
    -- la session n'a pas été rallongée par le ping retardé
    assert.equals NOW + IDLE, ((load_sessions SESS)[MAC]).expires

  it "token expiré + session absente → 401 (comportement strict conservé)", ->
    tok = token.generate "user", USER, MAC, NOW - 10, KEY
    status = handle_ping (ping_req tok), IP, MAC, make_state!
    assert.equals 401, status

  it "token expiré + session expirée (purge) → 401", ->
    write_session_expiring NOW - 5
    tok = token.generate "user", USER, MAC, NOW - 10, KEY
    status = handle_ping (ping_req tok), IP, MAC, make_state!
    assert.equals 401, status

  it "token expiré après logout → 401 (ne ressuscite pas la session)", ->
    write_session_expiring NOW + IDLE
    sessions = load_sessions SESS
    sessions[MAC\lower!] = nil
    write_sessions sessions, SESS
    reset_cache!
    tok = token.generate "user", USER, MAC, NOW - 10, KEY
    status = handle_ping (ping_req tok), IP, MAC, make_state!
    assert.equals 401, status

  it "signature invalide → 401 même si la session est vivante", ->
    write_session_expiring NOW + IDLE
    tok = token.generate "user", USER, MAC, NOW - 10, KEY
    bad = tok\sub(1, #tok - 4) .. "0000"
    status = handle_ping (ping_req bad), IP, MAC, make_state!
    assert.equals 401, status

  it "token valide reste le chemin nominal : 204 avec nouveau cookie", ->
    write_session_expiring NOW + 10
    tok = token.generate "user", USER, MAC, NOW + IDLE, KEY
    status, headers = handle_ping (ping_req tok), IP, MAC, make_state!
    assert.equals 204, status
    assert.is_not_nil headers["Set-Cookie"]
    assert.equals NOW + IDLE, ((load_sessions SESS)[MAC]).expires
