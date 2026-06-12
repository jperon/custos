-- tests/unit/auth/bye_spec.moon
-- Régression : le beacon pagehide envoyait /logout, détruisant la session sur
-- un simple reload/navigation (pagehide ≠ fermeture de fenêtre). /bye doit
-- seulement RACCOURCIR l'expiration à now + close_grace, jamais supprimer ni
-- rallonger : un /ping ultérieur re-prolonge, /logout reste destructif.

token = require "auth.token"
{ :handle_bye, :handle_ping, :handle_logout, :handle_request } = require "auth.handlers"
{ :add_session, :load_sessions, :write_sessions, :reset_cache } = require "auth.sessions"

SESS = "tmp/bye_spec_sessions.lua"
KEY  = token.load_key "tmp/bye_spec.key"
MAC  = "aa:bb:cc:11:22:33"
IP   = "10.42.0.50"
USER = "alice@test.lan"
GRACE = 45
IDLE  = 300

make_state = (nft_sess) ->
  {
    token_key: KEY
    sessions_file: SESS
    auth_cfg: { idle_timeout: IDLE, close_grace: GRACE }
    nft_sess: nft_sess
  }

req_with_token = (expires) ->
  tok = token.generate "user", USER, MAC, expires, KEY
  { headers: { cookie: "custos_session=#{tok}" }, path: "/bye", method: "POST" }

write_session_expiring = (expires) ->
  sessions = {}
  add_session sessions, MAC, IP, USER, expires
  write_sessions sessions, SESS
  reset_cache!

describe "handle_bye (grâce courte sur pagehide)", ->
  original_os_time = os.time
  -- NOW proche de l'heure réelle : auth.sessions capture os.time au chargement
  -- (os_time), donc purge_expired voit l'horloge réelle même quand os.time est
  -- stubbé ici. Un NOW figé dans le passé ferait purger les sessions du test.
  NOW = original_os_time!

  before_each ->
    os.time = -> NOW
    reset_cache!

  after_each ->
    os.time = original_os_time
    os.remove SESS

  it "raccourcit l'expiration à now + close_grace sans supprimer la session", ->
    write_session_expiring NOW + IDLE
    status = handle_bye (req_with_token NOW + IDLE), IP, MAC, make_state!
    assert.equals 204, status
    s = (load_sessions SESS)[MAC]
    assert.is_not_nil s, "la session ne doit pas être détruite"
    assert.equals NOW + GRACE, s.expires

  it "ne rallonge jamais une session qui expire avant la grâce", ->
    write_session_expiring NOW + 10
    handle_bye (req_with_token NOW + 10), IP, MAC, make_state!
    s = (load_sessions SESS)[MAC]
    assert.equals NOW + 10, s.expires

  it "répond 204 sans effet quand aucune session n'existe", ->
    status = handle_bye (req_with_token NOW + IDLE), IP, MAC, make_state!
    assert.equals 204, status
    assert.is_nil (load_sessions SESS)[MAC]

  it "retombe sur peer_mac quand le cookie est absent ou invalide", ->
    write_session_expiring NOW + IDLE
    req = { headers: {}, path: "/bye", method: "POST" }
    status = handle_bye req, IP, MAC, make_state!
    assert.equals 204, status
    assert.equals NOW + GRACE, ((load_sessions SESS)[MAC]).expires

  it "réaligne les sets nft globaux sur la grâce", ->
    write_session_expiring NOW + IDLE
    calls = {}
    nft_sess = {
      add_authenticated: (ip, ttl) -> calls[#calls + 1] = { "ip", ip, ttl }
      add_authenticated_mac: (mac, ttl) -> calls[#calls + 1] = { "mac", mac, ttl }
    }
    handle_bye (req_with_token NOW + IDLE), IP, MAC, make_state nft_sess
    assert.equals 2, #calls
    for c in *calls
      assert.equals GRACE, c[3]

  it "un /ping après /bye re-prolonge la session (pas de 401)", ->
    write_session_expiring NOW + IDLE
    state = make_state!
    handle_bye (req_with_token NOW + IDLE), IP, MAC, state
    -- la page revit (reload) : ping avec un cookie encore valide
    req = req_with_token NOW + IDLE
    req.path, req.method = "/ping", "GET"
    status = handle_ping req, IP, MAC, state
    assert.equals 204, status
    assert.equals NOW + IDLE, ((load_sessions SESS)[MAC]).expires

  it "handle_request route POST /bye vers handle_bye", ->
    write_session_expiring NOW + IDLE
    status = handle_request (req_with_token NOW + IDLE), IP, MAC, make_state!
    assert.equals 204, status
    assert.equals NOW + GRACE, ((load_sessions SESS)[MAC]).expires

  it "/logout reste destructif (la session disparaît)", ->
    write_session_expiring NOW + IDLE
    status = handle_logout (req_with_token NOW + IDLE), IP, MAC, make_state!
    assert.equals 302, status
    assert.is_nil (load_sessions SESS)[MAC]
