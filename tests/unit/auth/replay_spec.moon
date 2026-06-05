-- tests/unit/auth/replay_spec.moon
-- Tests de replay_sessions_to_nft : repeupler les sets nft au démarrage du
-- worker auth depuis le fichier sessions persisté.
-- Pas de FFI, pas de root requis.

{ :replay_sessions_to_nft } = require "auth.server"
{ :write_sessions, :reset_cache } = require "auth.sessions"

SESS_FILE = "tmp/replay_spec.lua"
FUTURE    = 9999999999
PAST      = 1

describe "auth/server replay_sessions_to_nft", ->

  before_each ->
    reset_cache!

  -- ── Sans nft_sess ────────────────────────────────────────────────────────────

  it "ne fait rien si nft_sess absent", ->
    state = { nft_sess: nil, sessions_file: SESS_FILE, auth_cfg: { idle_timeout: 120 } }
    assert.has_no_error -> replay_sessions_to_nft state

  it "ne fait rien si sessions_file absent", ->
    calls = 0
    nft_mock = { add_authenticated_mac: -> calls += 1 }
    state = { nft_sess: nft_mock, sessions_file: nil, auth_cfg: {} }
    replay_sessions_to_nft state
    assert.equal 0, calls

  -- ── Sessions expirées ignorées ───────────────────────────────────────────────

  it "n'appelle pas add_authenticated pour une session expirée", ->
    sessions = {
      ["aa:bb:cc:dd:ee:ff"]: {
        user: "alice", expires: PAST, mac: "aa:bb:cc:dd:ee:ff"
        ips: { ipv4: "10.0.0.1" }
      }
    }
    write_sessions sessions, SESS_FILE
    reset_cache!

    calls = 0
    nft_mock = {
      add_authenticated: (ip, ttl) -> calls += 1
      add_authenticated_mac: (mac, ttl) -> calls += 1
      add_authenticated6: -> calls += 1
      run_nft: -> true
    }
    state = { nft_sess: nft_mock, sessions_file: SESS_FILE, auth_cfg: { idle_timeout: 120 } }
    replay_sessions_to_nft state
    assert.equal 0, calls

  -- ── Session valide avec IP ───────────────────────────────────────────────────

  it "appelle add_authenticated pour l'IPv4 d'une session valide", ->
    sessions = {
      ["bb:cc:dd:ee:ff:00"]: {
        user: "bob", expires: FUTURE, mac: "bb:cc:dd:ee:ff:00"
        ips: { ipv4: "10.0.0.2" }
      }
    }
    write_sessions sessions, SESS_FILE
    reset_cache!

    auth_calls = {}
    mac_calls  = {}
    nft_mock = {
      add_authenticated: (ip, ttl) -> auth_calls[#auth_calls + 1] = { ip: ip, ttl: ttl }
      add_authenticated_mac: (mac, ttl) -> mac_calls[#mac_calls + 1] = { mac: mac, ttl: ttl }
      run_nft: -> true
    }
    state = { nft_sess: nft_mock, sessions_file: SESS_FILE, auth_cfg: { idle_timeout: 120 } }
    replay_sessions_to_nft state

    assert.equal 1, #auth_calls
    assert.equal "10.0.0.2", auth_calls[1].ip
    assert.equal 1, #mac_calls
    assert.equal "bb:cc:dd:ee:ff:00", mac_calls[1].mac

  -- ── Session valide avec IPv4 + IPv6 ─────────────────────────────────────────

  it "appelle add_authenticated pour IPv4 et IPv6 d'une même session", ->
    sessions = {
      ["cc:dd:ee:ff:00:11"]: {
        user: "carol", expires: FUTURE, mac: "cc:dd:ee:ff:00:11"
        ips: { ipv4: "10.0.0.3", ipv6: "2a11::1" }
      }
    }
    write_sessions sessions, SESS_FILE
    reset_cache!

    auth_calls = {}
    nft_mock = {
      add_authenticated: (ip, ttl) -> auth_calls[#auth_calls + 1] = ip
      add_authenticated_mac: -> true
      run_nft: -> true
    }
    state = { nft_sess: nft_mock, sessions_file: SESS_FILE, auth_cfg: { idle_timeout: 120 } }
    replay_sessions_to_nft state

    assert.equal 2, #auth_calls
    table.sort auth_calls
    assert.equal "10.0.0.3", auth_calls[1]
    assert.equal "2a11::1", auth_calls[2]

  -- ── Session sans IP → au moins la MAC ───────────────────────────────────────

  it "ajoute la MAC même si ips absent", ->
    sessions = {
      ["dd:ee:ff:00:11:22"]: {
        user: "dave", expires: FUTURE, mac: "dd:ee:ff:00:11:22"
      }
    }
    write_sessions sessions, SESS_FILE
    reset_cache!

    mac_calls = {}
    nft_mock = {
      add_authenticated: -> true
      add_authenticated_mac: (mac, ttl) -> mac_calls[#mac_calls + 1] = mac
      run_nft: -> true
    }
    state = { nft_sess: nft_mock, sessions_file: SESS_FILE, auth_cfg: { idle_timeout: 120 } }
    replay_sessions_to_nft state

    assert.equal 1, #mac_calls
    assert.equal "dd:ee:ff:00:11:22", mac_calls[1]

  -- ── Mix expirée + valide ─────────────────────────────────────────────────────

  it "ignore la session expirée et rejoue la session valide", ->
    sessions = {
      ["aa:bb:cc:dd:ee:ff"]: {
        user: "expired", expires: PAST, mac: "aa:bb:cc:dd:ee:ff"
        ips: { ipv4: "10.0.0.99" }
      }
      ["bb:cc:dd:ee:ff:00"]: {
        user: "valid", expires: FUTURE, mac: "bb:cc:dd:ee:ff:00"
        ips: { ipv4: "10.0.0.2" }
      }
    }
    write_sessions sessions, SESS_FILE
    reset_cache!

    auth_calls = {}
    nft_mock = {
      add_authenticated: (ip, ttl) -> auth_calls[#auth_calls + 1] = ip
      add_authenticated_mac: -> true
      run_nft: -> true
    }
    state = { nft_sess: nft_mock, sessions_file: SESS_FILE, auth_cfg: { idle_timeout: 120 } }
    replay_sessions_to_nft state

    assert.equal 1, #auth_calls
    assert.equal "10.0.0.2", auth_calls[1]

  -- ── TTL basé sur expires restant ─────────────────────────────────────────────

  it "passe un TTL >= 1 même si expires est dans le futur proche", ->
    future_close = os.time! + 5
    sessions = {
      ["ee:ff:00:11:22:33"]: {
        user: "eve", expires: future_close, mac: "ee:ff:00:11:22:33"
        ips: { ipv4: "10.0.0.5" }
      }
    }
    write_sessions sessions, SESS_FILE
    reset_cache!

    ttl_received = nil
    nft_mock = {
      add_authenticated: (ip, ttl) -> ttl_received = ttl
      add_authenticated_mac: -> true
      run_nft: -> true
    }
    state = { nft_sess: nft_mock, sessions_file: SESS_FILE, auth_cfg: { idle_timeout: 120 } }
    replay_sessions_to_nft state

    assert.is_not_nil ttl_received
    assert.is_true ttl_received >= 1
