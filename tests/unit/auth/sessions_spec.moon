-- tests/unit/auth/sessions_spec.moon
-- Tests des fonctions pures de auth/sessions :
--   serialize, write_sessions, load_sessions, add_session, purge_expired,
--   session_for_ip, user_for_ip.
-- Pas de FFI, pas de root requis.
-- Stubs injectés par tests/helpers/busted_setup.lua.

{ :serialize, :write_sessions, :load_sessions,
  :add_session, :purge_expired,
  :session_for_ip, :user_for_ip,
  :reset_cache } = require "auth.sessions"

-- Tous les fichiers temporaires restent dans ./tmp/ (règle AGENTS.md).
SESS_FILE = "tmp/sessions_spec_main.lua"
SF_FILE   = "tmp/sessions_spec_sf.lua"

-- Constante « loin dans le futur » pour les sessions non expirées.
FUTURE = 9999999999

-- Écrire + invalider le cache en une seule opération (pattern identique à
-- run_tests.moon pour session_for_ip).
write_and_reset = (sessions, path) ->
  write_sessions sessions, path
  reset_cache!


-- ════════════════════════════════════════════════════════════════════════════
describe "auth/sessions", ->

  -- ── serialize ─────────────────────────────────────────────────────────────
  describe "serialize", ->

    it "table vide → contient 'return {'", ->
      result = serialize {}
      assert.is_true result\find("return {", 1, true) ~= nil

    it "une session : MAC, user et expires présents", ->
      sessions = {
        ["aa:bb:cc:dd:ee:ff"]: { user: "alice", expires: 9999, mac: "aa:bb:cc:dd:ee:ff" }
      }
      result = serialize sessions
      assert.is_true result\find('"aa:bb:cc:dd:ee:ff"', 1, true) ~= nil
      assert.is_true result\find('"alice"',              1, true) ~= nil
      assert.is_true result\find("expires = 9999",       1, true) ~= nil

    it "heartbeat sérialisé quand présent", ->
      sessions = {
        ["11:22:33:44:55:66"]: { user: "bob", expires: 8888, heartbeat: 7777, mac: "11:22:33:44:55:66" }
      }
      result = serialize sessions
      assert.is_true result\find("heartbeat = 7777", 1, true) ~= nil

    it "expires absent si nil", ->
      sessions = {
        ["11:22:33:44:55:66"]: { user: "bob", heartbeat: 7777, mac: "11:22:33:44:55:66" }
      }
      result = serialize sessions
      assert.is_nil result\find("expires =", 1, true)
      assert.is_true result\find("heartbeat = 7777", 1, true) ~= nil

    it "ips multi-famille (ipv4 + ipv6) sérialisées", ->
      sessions = {
        ["aa:bb:cc:dd:ee:ff"]: {
          user: "carol", expires: 5555, mac: "aa:bb:cc:dd:ee:ff",
          ips: { ipv4: "1.2.3.4", ipv6: "::1" }
        }
      }
      result = serialize sessions
      assert.is_true result\find('ipv4 = "1.2.3.4"', 1, true) ~= nil
      assert.is_true result\find('ipv6 = "::1"',     1, true) ~= nil

    it "pas de champ ips si nil", ->
      sessions = {
        ["00:11:22:33:44:55"]: { user: "dave", expires: 4444, mac: "00:11:22:33:44:55" }
      }
      result = serialize sessions
      assert.is_nil result\find("ips =", 1, true)

    it "IP stockée dans ips.ipv4", ->
      sessions = {
        ["aa:bb:cc:dd:ee:ff"]: {
          user: "alice", expires: 9999, mac: "aa:bb:cc:dd:ee:ff",
          ips: { ipv4: "10.0.0.1" }
        }
      }
      result = serialize sessions
      assert.is_true result\find('ipv4 = "10.0.0.1"', 1, true) ~= nil


  -- ── write_sessions + load_sessions ────────────────────────────────────────
  describe "write_sessions + load_sessions", ->

    after_each ->
      os.remove SESS_FILE

    it "round-trip : trois sessions distinctes", ->
      sessions = {
        ["aa:bb:cc:dd:ee:ff"]: { user: "alice", expires: 9999999, mac: "aa:bb:cc:dd:ee:ff" }
        ["11:22:33:44:55:66"]: { user: "bob",   expires: 8888888, heartbeat: 111, mac: "11:22:33:44:55:66" }
        ["22:33:44:55:66:77"]: { user: "carol", expires: 7777777, mac: "22:33:44:55:66:77",
                                  ips: { ipv4: "192.168.1.30" } }
      }
      ok, err = write_sessions sessions, SESS_FILE
      assert.is_true ok, tostring(err)
      loaded = load_sessions SESS_FILE
      assert.is_not_nil loaded["aa:bb:cc:dd:ee:ff"]
      assert.equals "alice", loaded["aa:bb:cc:dd:ee:ff"].user
      assert.equals 9999999, loaded["aa:bb:cc:dd:ee:ff"].expires
      assert.is_not_nil loaded["11:22:33:44:55:66"]
      assert.equals 111, loaded["11:22:33:44:55:66"].heartbeat
      assert.is_not_nil loaded["22:33:44:55:66:77"]
      assert.equals "192.168.1.30", loaded["22:33:44:55:66:77"].ips.ipv4

    it "load_sessions : fichier absent → table vide", ->
      result = load_sessions "tmp/absent_sessions_spec.lua"
      assert.equals "table", type(result)
      count = 0
      for _ in pairs result do count += 1
      assert.equals 0, count

    it "load_sessions : fichier corrompu → table vide", ->
      corrupt = "tmp/corrupt_sessions_spec.lua"
      fh = io.open corrupt, "w"
      fh\write "THIS IS NOT VALID LUA {\n"
      fh\close!
      result = load_sessions corrupt
      assert.equals "table", type(result)
      count = 0
      for _ in pairs result do count += 1
      assert.equals 0, count
      os.remove corrupt


  -- ── add_session ───────────────────────────────────────────────────────────
  describe "add_session", ->

    it "crée une session avec user et expires dans le futur", ->
      sessions = {}
      add_session sessions, "aa:bb:cc:dd:ee:ff", "10.1.0.1", "charlie", 3600, 0
      s = sessions["aa:bb:cc:dd:ee:ff"]
      assert.is_not_nil s
      assert.equals "charlie", s.user
      assert.is_true s.expires > os.time!
      assert.is_nil s.heartbeat  -- idle_timeout=0 → pas de heartbeat

    it "stocke l'IP dans ips.ipv4", ->
      sessions = {}
      add_session sessions, "aa:bb:cc:dd:ee:ff", "10.1.0.1", "charlie", 3600, 0
      assert.equals "10.1.0.1", sessions["aa:bb:cc:dd:ee:ff"].ips.ipv4

    it "normalise la MAC en minuscules", ->
      sessions = {}
      add_session sessions, "AA:BB:CC:DD:EE:FF", "10.1.0.5", "eve", 3600, 0
      assert.is_not_nil sessions["aa:bb:cc:dd:ee:ff"]
      assert.equals "eve", sessions["aa:bb:cc:dd:ee:ff"].user

    it "heartbeat non nil si idle_timeout > 0", ->
      sessions = {}
      add_session sessions, "aa:bb:cc:dd:ee:ff", "10.1.0.2", "diana", 3600, 120
      s = sessions["aa:bb:cc:dd:ee:ff"]
      assert.is_not_nil s.heartbeat
      assert.is_true s.heartbeat > os.time!

    it "session_ttl=0 → expires nil", ->
      sessions = {}
      add_session sessions, "aa:bb:cc:dd:ee:ff", "10.1.0.3", "frank", 0, 120
      s = sessions["aa:bb:cc:dd:ee:ff"]
      assert.is_not_nil s
      assert.is_nil s.expires
      assert.is_true s.heartbeat > os.time!

    it "deux sessions différentes → session_count == 2", ->
      sessions = {}
      add_session sessions, "aa:bb:cc:dd:ee:01", "10.0.0.1", "user1", 3600, 0
      add_session sessions, "aa:bb:cc:dd:ee:02", "10.0.0.2", "user2", 3600, 0
      count = 0
      for _ in pairs sessions do count += 1
      assert.equals 2, count

    it "MAC 'unknown' est ignorée", ->
      sessions = {}
      add_session sessions, "unknown", "10.0.0.1", "ghost", 3600, 0
      count = 0
      for _ in pairs sessions do count += 1
      assert.equals 0, count

    it "MAC nil est ignorée", ->
      sessions = {}
      add_session sessions, nil, "10.0.0.1", "ghost", 3600, 0
      count = 0
      for _ in pairs sessions do count += 1
      assert.equals 0, count


  -- ── purge_expired ─────────────────────────────────────────────────────────
  describe "purge_expired", ->

    it "supprime une session dont expires est dans le passé", ->
      sessions = {
        ["aa:bb:cc:dd:ee:01"]: { user: "old",   expires: 1 }
        ["aa:bb:cc:dd:ee:02"]: { user: "valid", expires: FUTURE }
      }
      purge_expired sessions
      assert.is_nil    sessions["aa:bb:cc:dd:ee:01"]
      assert.is_not_nil sessions["aa:bb:cc:dd:ee:02"]

    it "supprime une session dont heartbeat est expiré (même si expires futur)", ->
      sessions = {
        ["aa:bb:cc:dd:ee:03"]: { user: "hb", expires: FUTURE, heartbeat: 1 }
      }
      purge_expired sessions
      assert.is_nil sessions["aa:bb:cc:dd:ee:03"]

    it "conserve une session sans expires absolu (heartbeat futur)", ->
      sessions = {
        ["aa:bb:cc:dd:ee:04"]: { user: "noabs", heartbeat: FUTURE }
      }
      purge_expired sessions
      assert.is_not_nil sessions["aa:bb:cc:dd:ee:04"]

    it "sessions valides restent toutes présentes après purge", ->
      sessions = {
        ["aa:bb:cc:dd:ee:05"]: { user: "u1", expires: FUTURE }
        ["aa:bb:cc:dd:ee:06"]: { user: "u2", expires: FUTURE }
        ["aa:bb:cc:dd:ee:07"]: { user: "u3", expires: 1 }
      }
      purge_expired sessions
      assert.is_not_nil sessions["aa:bb:cc:dd:ee:05"]
      assert.is_not_nil sessions["aa:bb:cc:dd:ee:06"]
      assert.is_nil     sessions["aa:bb:cc:dd:ee:07"]


  -- ── session_for_ip / user_for_ip ──────────────────────────────────────────
  describe "session_for_ip", ->

    MAC = "aa:bb:cc:dd:ee:ff"

    before_each ->
      reset_cache!

    after_each ->
      os.remove SF_FILE

    it "retourne la session par lookup MAC direct", ->
      write_and_reset { [MAC]: { user: "alice", expires: FUTURE } }, SF_FILE
      s = session_for_ip nil, SF_FILE, MAC
      assert.is_not_nil s
      assert.equals "alice", s.user

    it "retourne la session par scan IPv4 (sans MAC)", ->
      write_and_reset {
        [MAC]: { user: "alice", expires: FUTURE, ips: { ipv4: "10.0.0.1" } }
      }, SF_FILE
      s = session_for_ip "10.0.0.1", SF_FILE
      assert.is_not_nil s
      assert.equals "alice", s.user

    it "retourne la session par scan IPv6 (sans MAC)", ->
      write_and_reset {
        [MAC]: { user: "j@prn.ovh", expires: FUTURE, ips: { ipv6: "fd00::1" } }
      }, SF_FILE
      s = session_for_ip "fd00::1", SF_FILE
      assert.is_not_nil s
      assert.equals "j@prn.ovh", s.user

    it "MAC 'unknown' bascule sur scan IP", ->
      write_and_reset {
        [MAC]: { user: "alice", expires: FUTURE, ips: { ipv4: "10.0.0.99" } }
      }, SF_FILE
      s = session_for_ip "10.0.0.99", SF_FILE, "unknown"
      assert.is_not_nil s
      assert.equals "alice", s.user

    it "IP inconnue → nil", ->
      write_and_reset {
        [MAC]: { user: "alice", expires: FUTURE }
      }, SF_FILE
      s = session_for_ip "9.9.9.9", SF_FILE
      assert.is_nil s

    it "session expirée → nil", ->
      write_and_reset {
        [MAC]: { user: "alice", expires: 1 }
      }, SF_FILE
      s = session_for_ip "10.0.0.9", SF_FILE, MAC
      assert.is_nil s

    it "MAC fournie explicitement prime sur scan IP", ->
      write_and_reset {
        [MAC]: { user: "j@prn.ovh", expires: FUTURE }
      }, SF_FILE
      s = session_for_ip "10.35.1.53", SF_FILE, MAC
      assert.is_not_nil s
      assert.equals "j@prn.ovh", s.user


  -- ── user_for_ip ───────────────────────────────────────────────────────────
  describe "user_for_ip", ->

    MAC = "aa:bb:cc:dd:ee:ff"

    before_each ->
      reset_cache!

    after_each ->
      os.remove SF_FILE

    it "retourne le username pour une IP connue", ->
      write_and_reset {
        [MAC]: { user: "j@prn.ovh", expires: FUTURE, ips: { ipv4: "10.35.1.53" } }
      }, SF_FILE
      user = user_for_ip "10.35.1.53", SF_FILE
      assert.equals "j@prn.ovh", user

    it "IP nil → nil", ->
      user = user_for_ip nil, SF_FILE
      assert.is_nil user

    it "IP sans session correspondante → nil", ->
      write_and_reset {
        [MAC]: { user: "alice", expires: FUTURE, ips: { ipv4: "10.0.0.1" } }
      }, SF_FILE
      user = user_for_ip "192.168.99.1", SF_FILE
      assert.is_nil user

    it "session expirée → nil", ->
      write_and_reset {
        [MAC]: { user: "alice", expires: 1, ips: { ipv4: "10.0.0.1" } }
      }, SF_FILE
      user = user_for_ip "10.0.0.1", SF_FILE, MAC
      assert.is_nil user
