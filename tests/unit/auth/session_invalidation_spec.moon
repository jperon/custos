-- tests/unit/auth/session_invalidation_spec.moon
-- Régression pour le bug 2 : handle_ping ressuscitait une session après logout.
--
-- Le fix dans server.moon vérifie `sessions[mac\lower!] == nil` AVANT d'appeler
-- add_session. Ce spec valide l'invariant sessions au niveau de la couche sessions :
-- supprimer sessions[mac] puis write+load → session_for_mac retourne nil.

{ :add_session, :purge_expired, :load_sessions,
  :write_sessions, :session_for_mac, :reset_cache } = require "auth.sessions"

SESS = "tmp/invalidation_spec.lua"
MAC  = "aa:bb:cc:11:22:33"
IP   = "10.42.0.50"
FAR_FUTURE = 9999999999

describe "session invalidation (logout invariant)", ->

  before_each ->
    reset_cache!

  after_each ->
    os.remove SESS

  it "session supprimée → session_for_mac retourne nil (invariant handle_ping)", ->
    sessions = {}
    add_session sessions, MAC, IP, "alice@test.lan", FAR_FUTURE
    write_sessions sessions, SESS
    reset_cache!
    -- simuler le logout
    sessions = load_sessions SESS
    sessions[MAC\lower!] = nil
    write_sessions sessions, SESS
    reset_cache!
    -- reload : session doit être absente
    sessions2 = load_sessions SESS
    assert.is_nil sessions2[MAC\lower!]

  it "session expirée après purge_expired → session_for_mac retourne nil", ->
    sessions = {}
    add_session sessions, MAC, IP, "alice@test.lan", 1  -- expires dans le passé
    write_sessions sessions, SESS
    reset_cache!
    sessions2 = load_sessions SESS
    purge_expired sessions2
    assert.is_nil sessions2[MAC\lower!]

  it "session non expirée reste présente après purge_expired", ->
    sessions = {}
    add_session sessions, MAC, IP, "alice@test.lan", FAR_FUTURE
    write_sessions sessions, SESS
    reset_cache!
    sessions2 = load_sessions SESS
    purge_expired sessions2
    assert.is_not_nil sessions2[MAC\lower!]
