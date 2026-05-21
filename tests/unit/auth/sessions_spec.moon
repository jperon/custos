-- tests/unit/auth/sessions_spec.moon
-- Tests des fonctions pures de auth/sessions.
-- Pas de FFI, pas de root requis.

{ :serialize, :write_sessions, :load_sessions,
  :add_session, :purge_expired,
  :session_for_mac, :user_for_mac,
  :reset_cache } = require "auth.sessions"

SESS_FILE = "tmp/sessions_spec_main.lua"
SF_FILE   = "tmp/sessions_spec_sf.lua"
FUTURE    = 9999999999

write_and_reset = (sessions, path) ->
  write_sessions sessions, path
  reset_cache!


describe "auth/sessions", ->

  -- ── serialize ───────────────────────────────────────────────────────────────
  describe "serialize", ->

    it "table vide → contient 'return {'", ->
      result = serialize {}
      assert.is_true result\find("return {", 1, true) ~= nil

    it "MAC, user et expires présents", ->
      sessions = {
        ["aa:bb:cc:dd:ee:ff"]: { user: "alice", expires: 9999, mac: "aa:bb:cc:dd:ee:ff" }
      }
      result = serialize sessions
      assert.is_true result\find('"aa:bb:cc:dd:ee:ff"', 1, true) ~= nil
      assert.is_true result\find('"alice"',              1, true) ~= nil
      assert.is_true result\find("expires = 9999",       1, true) ~= nil

    it "expires absent si nil", ->
      sessions = { ["aa:bb:cc:dd:ee:ff"]: { user: "bob", mac: "aa:bb:cc:dd:ee:ff" } }
      result = serialize sessions
      assert.is_nil result\find("expires =", 1, true)

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
      sessions = { ["00:11:22:33:44:55"]: { user: "dave", expires: 4444, mac: "00:11:22:33:44:55" } }
      result = serialize sessions
      assert.is_nil result\find("ips =", 1, true)


  -- ── write_sessions + load_sessions ──────────────────────────────────────────
  describe "write_sessions + load_sessions", ->

    after_each ->
      os.remove SESS_FILE

    it "round-trip : deux sessions distinctes", ->
      sessions = {
        ["aa:bb:cc:dd:ee:ff"]: { user: "alice", expires: 9999999, mac: "aa:bb:cc:dd:ee:ff" }
        ["22:33:44:55:66:77"]: { user: "carol", expires: 7777777, mac: "22:33:44:55:66:77",
                                  ips: { ipv4: "192.168.1.30" } }
      }
      ok, err = write_sessions sessions, SESS_FILE
      assert.is_true ok, tostring(err)
      loaded = load_sessions SESS_FILE
      assert.equals "alice",       loaded["aa:bb:cc:dd:ee:ff"].user
      assert.equals 9999999,       loaded["aa:bb:cc:dd:ee:ff"].expires
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


  -- ── add_session ─────────────────────────────────────────────────────────────
  describe "add_session", ->

    it "crée une session avec user et expires dans le futur", ->
      sessions = {}
      add_session sessions, "aa:bb:cc:dd:ee:ff", "10.1.0.1", "charlie", os.time! + 3600
      s = sessions["aa:bb:cc:dd:ee:ff"]
      assert.is_not_nil s
      assert.equals "charlie", s.user
      assert.is_true s.expires > os.time!

    it "stocke l'IP dans ips.ipv4", ->
      sessions = {}
      add_session sessions, "aa:bb:cc:dd:ee:ff", "10.1.0.1", "charlie", os.time! + 3600
      assert.equals "10.1.0.1", sessions["aa:bb:cc:dd:ee:ff"].ips.ipv4

    it "normalise la MAC en minuscules", ->
      sessions = {}
      add_session sessions, "AA:BB:CC:DD:EE:FF", "10.1.0.5", "eve", os.time! + 3600
      assert.is_not_nil sessions["aa:bb:cc:dd:ee:ff"]
      assert.equals "eve", sessions["aa:bb:cc:dd:ee:ff"].user

    it "mise à jour d'une session existante (même MAC)", ->
      sessions = {}
      add_session sessions, "aa:bb:cc:dd:ee:ff", "10.0.0.1", "alice", os.time! + 3600
      add_session sessions, "aa:bb:cc:dd:ee:ff", "10.0.0.2", "alice", os.time! + 7200
      s = sessions["aa:bb:cc:dd:ee:ff"]
      -- IP v4 mise à jour, expires mis à jour
      assert.equals "10.0.0.2", s.ips.ipv4
      assert.is_true s.expires > os.time! + 3600

    it "deux sessions différentes → session_count == 2", ->
      sessions = {}
      add_session sessions, "aa:bb:cc:dd:ee:01", "10.0.0.1", "user1", os.time! + 3600
      add_session sessions, "aa:bb:cc:dd:ee:02", "10.0.0.2", "user2", os.time! + 3600
      count = 0
      for _ in pairs sessions do count += 1
      assert.equals 2, count

    it "MAC 'unknown' est ignorée", ->
      sessions = {}
      add_session sessions, "unknown", "10.0.0.1", "ghost", os.time! + 3600
      count = 0
      for _ in pairs sessions do count += 1
      assert.equals 0, count

    it "MAC nil est ignorée", ->
      sessions = {}
      add_session sessions, nil, "10.0.0.1", "ghost", os.time! + 3600
      count = 0
      for _ in pairs sessions do count += 1
      assert.equals 0, count


  -- ── purge_expired ───────────────────────────────────────────────────────────
  describe "purge_expired", ->

    it "supprime une session dont expires est dans le passé", ->
      sessions = {
        ["aa:bb:cc:dd:ee:01"]: { user: "old",   expires: 1 }
        ["aa:bb:cc:dd:ee:02"]: { user: "valid", expires: FUTURE }
      }
      purge_expired sessions
      assert.is_nil    sessions["aa:bb:cc:dd:ee:01"]
      assert.is_not_nil sessions["aa:bb:cc:dd:ee:02"]

    it "session sans expires n'est pas purgée", ->
      sessions = { ["aa:bb:cc:dd:ee:03"]: { user: "noexp" } }
      purge_expired sessions
      assert.is_not_nil sessions["aa:bb:cc:dd:ee:03"]

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


  -- ── session_for_mac / user_for_mac ──────────────────────────────────────────
  describe "session_for_mac", ->

    MAC = "aa:bb:cc:dd:ee:ff"

    before_each ->
      reset_cache!

    after_each ->
      os.remove SF_FILE

    it "retourne la session par lookup MAC direct", ->
      write_and_reset { [MAC]: { user: "alice", expires: FUTURE } }, SF_FILE
      s = session_for_mac MAC, nil, SF_FILE
      assert.is_not_nil s
      assert.equals "alice", s.user

    it "retourne la session par scan IPv4 (sans MAC)", ->
      write_and_reset {
        [MAC]: { user: "alice", expires: FUTURE, ips: { ipv4: "10.0.0.1" } }
      }, SF_FILE
      s = session_for_mac nil, "10.0.0.1", SF_FILE
      assert.is_not_nil s
      assert.equals "alice", s.user

    it "retourne la session par scan IPv6 (sans MAC)", ->
      write_and_reset {
        [MAC]: { user: "j@prn.ovh", expires: FUTURE, ips: { ipv6: "fd00::1" } }
      }, SF_FILE
      s = session_for_mac nil, "fd00::1", SF_FILE
      assert.is_not_nil s
      assert.equals "j@prn.ovh", s.user

    it "MAC 'unknown' bascule sur scan IP", ->
      write_and_reset {
        [MAC]: { user: "alice", expires: FUTURE, ips: { ipv4: "10.0.0.99" } }
      }, SF_FILE
      s = session_for_mac "unknown", "10.0.0.99", SF_FILE
      assert.is_not_nil s
      assert.equals "alice", s.user

    it "IP inconnue → nil", ->
      write_and_reset { [MAC]: { user: "alice", expires: FUTURE } }, SF_FILE
      s = session_for_mac nil, "9.9.9.9", SF_FILE
      assert.is_nil s

    it "session expirée → nil", ->
      write_and_reset { [MAC]: { user: "alice", expires: 1 } }, SF_FILE
      s = session_for_mac MAC, "10.0.0.9", SF_FILE
      assert.is_nil s

    it "MAC fournie explicitement prime sur scan IP", ->
      write_and_reset { [MAC]: { user: "j@prn.ovh", expires: FUTURE } }, SF_FILE
      s = session_for_mac MAC, "10.35.1.53", SF_FILE
      assert.is_not_nil s
      assert.equals "j@prn.ovh", s.user


  -- ── user_for_mac ────────────────────────────────────────────────────────────
  describe "user_for_mac", ->

    MAC = "aa:bb:cc:dd:ee:ff"

    before_each ->
      reset_cache!

    after_each ->
      os.remove SF_FILE

    it "retourne le username pour une IP connue", ->
      write_and_reset {
        [MAC]: { user: "j@prn.ovh", expires: FUTURE, ips: { ipv4: "10.35.1.53" } }
      }, SF_FILE
      user = user_for_mac nil, "10.35.1.53", SF_FILE
      assert.equals "j@prn.ovh", user

    it "IP nil → nil", ->
      assert.is_nil user_for_mac nil, nil, SF_FILE

    it "IP sans session correspondante → nil", ->
      write_and_reset {
        [MAC]: { user: "alice", expires: FUTURE, ips: { ipv4: "10.0.0.1" } }
      }, SF_FILE
      assert.is_nil user_for_mac nil, "192.168.99.1", SF_FILE

    it "session expirée → nil", ->
      write_and_reset {
        [MAC]: { user: "alice", expires: 1, ips: { ipv4: "10.0.0.1" } }
      }, SF_FILE
      assert.is_nil user_for_mac MAC, "10.0.0.1", SF_FILE


  -- ── load_sessions cas limites ────────────────────────────────────────────────
  describe "load_sessions cas limites", ->

    it "load_sessions nil → table vide", ->
      { :load_sessions } = require "auth.sessions"
      result = load_sessions nil
      assert.is_not_nil result
      assert.equals 0, #(result or {})

    it "load_sessions fichier Lua valide mais sans return → table vide", ->
      path = "tmp/sessions_noreturn.lua"
      fh = io.open path, "w"
      fh\write "-- no return\nlocal x = 1\n"
      fh\close!
      { :load_sessions } = require "auth.sessions"
      result = load_sessions path
      assert.is_not_nil result
      os.remove path


  -- ── enrich_session_ip + bind_session_mac ─────────────────────────────────────
  describe "enrich_session_ip + bind_session_mac", ->
    { :enrich_session_ip, :bind_session_mac, :session_for_mac } = require "auth.sessions"
    ENRICH_FILE = "tmp/sessions_enrich.lua"
    EMAC  = "11:22:33:44:55:66"
    EMAC2 = "aa:bb:cc:dd:ee:ff"

    before_each ->
      reset_cache!

    it "enrich_session_ip : args invalides → false", ->
      assert.is_false (enrich_session_ip nil,  "10.0.0.1",  ENRICH_FILE)
      assert.is_false (enrich_session_ip EMAC, nil,         ENRICH_FILE)
      assert.is_false (enrich_session_ip EMAC, "10.0.0.1",  nil)

    it "enrich_session_ip : IPv6 address → family=ipv6", ->
      fh = io.open ENRICH_FILE, "w"
      fh\write string.format('return { ["%s"] = { user="bob", expires=%d } }\n', EMAC, FUTURE)
      fh\close!
      reset_cache!
      enrich_session_ip EMAC, "2001:db8::1", ENRICH_FILE
      s = session_for_mac EMAC, "2001:db8::1", ENRICH_FILE
      assert.is_not_nil s
      os.remove ENRICH_FILE

    it "bind_session_mac : args invalides → false", ->
      assert.is_false (bind_session_mac EMAC,  nil,   "10.0.0.1", ENRICH_FILE)
      assert.is_false (bind_session_mac EMAC,  EMAC2, "10.0.0.1", nil)

    it "bind_session_mac : même MAC → appelle enrich", ->
      fh = io.open ENRICH_FILE, "w"
      fh\write string.format('return { ["%s"] = { user="carol", expires=%d } }\n', EMAC, FUTURE)
      fh\close!
      reset_cache!
      bind_session_mac EMAC, EMAC, "10.0.0.1", ENRICH_FILE
      os.remove ENRICH_FILE
