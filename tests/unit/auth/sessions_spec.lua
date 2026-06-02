local serialize, write_sessions, load_sessions, add_session, purge_expired, session_for_mac, user_for_mac, reset_cache
do
  local _obj_0 = require("auth.sessions")
  serialize, write_sessions, load_sessions, add_session, purge_expired, session_for_mac, user_for_mac, reset_cache = _obj_0.serialize, _obj_0.write_sessions, _obj_0.load_sessions, _obj_0.add_session, _obj_0.purge_expired, _obj_0.session_for_mac, _obj_0.user_for_mac, _obj_0.reset_cache
end
local SESS_FILE = "tmp/sessions_spec_main.lua"
local SF_FILE = "tmp/sessions_spec_sf.lua"
local FUTURE = 9999999999
local write_and_reset
write_and_reset = function(sessions, path)
  write_sessions(sessions, path)
  return reset_cache()
end
return describe("auth/sessions", function()
  describe("serialize", function()
    it("table vide → contient 'return {'", function()
      local result = serialize({ })
      return assert.is_true(result:find("return {", 1, true) ~= nil)
    end)
    it("MAC, user et expires présents", function()
      local sessions = {
        ["aa:bb:cc:dd:ee:ff"] = {
          user = "alice",
          expires = 9999,
          mac = "aa:bb:cc:dd:ee:ff"
        }
      }
      local result = serialize(sessions)
      assert.is_true(result:find('"aa:bb:cc:dd:ee:ff"', 1, true) ~= nil)
      assert.is_true(result:find('"alice"', 1, true) ~= nil)
      return assert.is_true(result:find("expires = 9999", 1, true) ~= nil)
    end)
    it("expires absent si nil", function()
      local sessions = {
        ["aa:bb:cc:dd:ee:ff"] = {
          user = "bob",
          mac = "aa:bb:cc:dd:ee:ff"
        }
      }
      local result = serialize(sessions)
      return assert.is_nil(result:find("expires =", 1, true))
    end)
    it("ips multi-famille (ipv4 + ipv6) sérialisées", function()
      local sessions = {
        ["aa:bb:cc:dd:ee:ff"] = {
          user = "carol",
          expires = 5555,
          mac = "aa:bb:cc:dd:ee:ff",
          ips = {
            ipv4 = "1.2.3.4",
            ipv6 = "::1"
          }
        }
      }
      local result = serialize(sessions)
      assert.is_true(result:find('ipv4 = "1.2.3.4"', 1, true) ~= nil)
      return assert.is_true(result:find('ipv6 = "::1"', 1, true) ~= nil)
    end)
    return it("pas de champ ips si nil", function()
      local sessions = {
        ["00:11:22:33:44:55"] = {
          user = "dave",
          expires = 4444,
          mac = "00:11:22:33:44:55"
        }
      }
      local result = serialize(sessions)
      return assert.is_nil(result:find("ips =", 1, true))
    end)
  end)
  describe("write_sessions + load_sessions", function()
    after_each(function()
      return os.remove(SESS_FILE)
    end)
    it("round-trip : deux sessions distinctes", function()
      local sessions = {
        ["aa:bb:cc:dd:ee:ff"] = {
          user = "alice",
          expires = 9999999,
          mac = "aa:bb:cc:dd:ee:ff"
        },
        ["22:33:44:55:66:77"] = {
          user = "carol",
          expires = 7777777,
          mac = "22:33:44:55:66:77",
          ips = {
            ipv4 = "192.168.1.30"
          }
        }
      }
      local ok, err = write_sessions(sessions, SESS_FILE)
      assert.is_true(ok, tostring(err))
      local loaded = load_sessions(SESS_FILE)
      assert.equals("alice", loaded["aa:bb:cc:dd:ee:ff"].user)
      assert.equals(9999999, loaded["aa:bb:cc:dd:ee:ff"].expires)
      return assert.equals("192.168.1.30", loaded["22:33:44:55:66:77"].ips.ipv4)
    end)
    it("load_sessions : fichier absent → table vide", function()
      local result = load_sessions("tmp/absent_sessions_spec.lua")
      assert.equals("table", type(result))
      local count = 0
      for _ in pairs(result) do
        count = count + 1
      end
      return assert.equals(0, count)
    end)
    return it("load_sessions : fichier corrompu → table vide", function()
      local corrupt = "tmp/corrupt_sessions_spec.lua"
      local fh = io.open(corrupt, "w")
      fh:write("THIS IS NOT VALID LUA {\n")
      fh:close()
      local result = load_sessions(corrupt)
      assert.equals("table", type(result))
      local count = 0
      for _ in pairs(result) do
        count = count + 1
      end
      assert.equals(0, count)
      return os.remove(corrupt)
    end)
  end)
  describe("add_session", function()
    it("crée une session avec user et expires dans le futur", function()
      local sessions = { }
      add_session(sessions, "aa:bb:cc:dd:ee:ff", "10.1.0.1", "charlie", os.time() + 3600)
      local s = sessions["aa:bb:cc:dd:ee:ff"]
      assert.is_not_nil(s)
      assert.equals("charlie", s.user)
      return assert.is_true(s.expires > os.time())
    end)
    it("stocke l'IP dans ips.ipv4", function()
      local sessions = { }
      add_session(sessions, "aa:bb:cc:dd:ee:ff", "10.1.0.1", "charlie", os.time() + 3600)
      return assert.equals("10.1.0.1", sessions["aa:bb:cc:dd:ee:ff"].ips.ipv4)
    end)
    it("normalise la MAC en minuscules", function()
      local sessions = { }
      add_session(sessions, "AA:BB:CC:DD:EE:FF", "10.1.0.5", "eve", os.time() + 3600)
      assert.is_not_nil(sessions["aa:bb:cc:dd:ee:ff"])
      return assert.equals("eve", sessions["aa:bb:cc:dd:ee:ff"].user)
    end)
    it("mise à jour d'une session existante (même MAC)", function()
      local sessions = { }
      add_session(sessions, "aa:bb:cc:dd:ee:ff", "10.0.0.1", "alice", os.time() + 3600)
      add_session(sessions, "aa:bb:cc:dd:ee:ff", "10.0.0.2", "alice", os.time() + 7200)
      local s = sessions["aa:bb:cc:dd:ee:ff"]
      assert.equals("10.0.0.2", s.ips.ipv4)
      return assert.is_true(s.expires > os.time() + 3600)
    end)
    it("deux sessions différentes → session_count == 2", function()
      local sessions = { }
      add_session(sessions, "aa:bb:cc:dd:ee:01", "10.0.0.1", "user1", os.time() + 3600)
      add_session(sessions, "aa:bb:cc:dd:ee:02", "10.0.0.2", "user2", os.time() + 3600)
      local count = 0
      for _ in pairs(sessions) do
        count = count + 1
      end
      return assert.equals(2, count)
    end)
    it("MAC 'unknown' est ignorée", function()
      local sessions = { }
      add_session(sessions, "unknown", "10.0.0.1", "ghost", os.time() + 3600)
      local count = 0
      for _ in pairs(sessions) do
        count = count + 1
      end
      return assert.equals(0, count)
    end)
    return it("MAC nil est ignorée", function()
      local sessions = { }
      add_session(sessions, nil, "10.0.0.1", "ghost", os.time() + 3600)
      local count = 0
      for _ in pairs(sessions) do
        count = count + 1
      end
      return assert.equals(0, count)
    end)
  end)
  describe("purge_expired", function()
    it("supprime une session dont expires est dans le passé", function()
      local sessions = {
        ["aa:bb:cc:dd:ee:01"] = {
          user = "old",
          expires = 1
        },
        ["aa:bb:cc:dd:ee:02"] = {
          user = "valid",
          expires = FUTURE
        }
      }
      purge_expired(sessions)
      assert.is_nil(sessions["aa:bb:cc:dd:ee:01"])
      return assert.is_not_nil(sessions["aa:bb:cc:dd:ee:02"])
    end)
    it("session sans expires n'est pas purgée", function()
      local sessions = {
        ["aa:bb:cc:dd:ee:03"] = {
          user = "noexp"
        }
      }
      purge_expired(sessions)
      return assert.is_not_nil(sessions["aa:bb:cc:dd:ee:03"])
    end)
    return it("sessions valides restent toutes présentes après purge", function()
      local sessions = {
        ["aa:bb:cc:dd:ee:05"] = {
          user = "u1",
          expires = FUTURE
        },
        ["aa:bb:cc:dd:ee:06"] = {
          user = "u2",
          expires = FUTURE
        },
        ["aa:bb:cc:dd:ee:07"] = {
          user = "u3",
          expires = 1
        }
      }
      purge_expired(sessions)
      assert.is_not_nil(sessions["aa:bb:cc:dd:ee:05"])
      assert.is_not_nil(sessions["aa:bb:cc:dd:ee:06"])
      return assert.is_nil(sessions["aa:bb:cc:dd:ee:07"])
    end)
  end)
  describe("session_for_mac", function()
    local MAC = "aa:bb:cc:dd:ee:ff"
    before_each(function()
      return reset_cache()
    end)
    after_each(function()
      return os.remove(SF_FILE)
    end)
    it("retourne la session par lookup MAC direct", function()
      write_and_reset({
        [MAC] = {
          user = "alice",
          expires = FUTURE
        }
      }, SF_FILE)
      local s = session_for_mac(MAC, nil, SF_FILE)
      assert.is_not_nil(s)
      return assert.equals("alice", s.user)
    end)
    it("retourne la session par scan IPv4 (sans MAC)", function()
      write_and_reset({
        [MAC] = {
          user = "alice",
          expires = FUTURE,
          ips = {
            ipv4 = "10.0.0.1"
          }
        }
      }, SF_FILE)
      local s = session_for_mac(nil, "10.0.0.1", SF_FILE)
      assert.is_not_nil(s)
      return assert.equals("alice", s.user)
    end)
    it("retourne la session par scan IPv6 (sans MAC)", function()
      write_and_reset({
        [MAC] = {
          user = "j@prn.ovh",
          expires = FUTURE,
          ips = {
            ipv6 = "fd00::1"
          }
        }
      }, SF_FILE)
      local s = session_for_mac(nil, "fd00::1", SF_FILE)
      assert.is_not_nil(s)
      return assert.equals("j@prn.ovh", s.user)
    end)
    it("MAC 'unknown' bascule sur scan IP", function()
      write_and_reset({
        [MAC] = {
          user = "alice",
          expires = FUTURE,
          ips = {
            ipv4 = "10.0.0.99"
          }
        }
      }, SF_FILE)
      local s = session_for_mac("unknown", "10.0.0.99", SF_FILE)
      assert.is_not_nil(s)
      return assert.equals("alice", s.user)
    end)
    it("IP inconnue → nil", function()
      write_and_reset({
        [MAC] = {
          user = "alice",
          expires = FUTURE
        }
      }, SF_FILE)
      local s = session_for_mac(nil, "9.9.9.9", SF_FILE)
      return assert.is_nil(s)
    end)
    it("session expirée → nil", function()
      write_and_reset({
        [MAC] = {
          user = "alice",
          expires = 1
        }
      }, SF_FILE)
      local s = session_for_mac(MAC, "10.0.0.9", SF_FILE)
      return assert.is_nil(s)
    end)
    return it("MAC fournie explicitement prime sur scan IP", function()
      write_and_reset({
        [MAC] = {
          user = "j@prn.ovh",
          expires = FUTURE
        }
      }, SF_FILE)
      local s = session_for_mac(MAC, "10.35.1.53", SF_FILE)
      assert.is_not_nil(s)
      return assert.equals("j@prn.ovh", s.user)
    end)
  end)
  describe("session_for_mac reload-on-miss (statx)", function()
    local MAC1 = "aa:bb:cc:dd:ee:ff"
    local MAC2 = "99:88:77:66:55:44"
    before_each(function()
      return reset_cache()
    end)
    after_each(function()
      return os.remove(SF_FILE)
    end)
    it("session fraîchement écrite résolue sur miss (cache chaud, fichier modifié)", function()
      write_sessions({
        [MAC1] = {
          user = "alice",
          expires = FUTURE
        }
      }, SF_FILE)
      reset_cache()
      assert.equals("alice", (session_for_mac(MAC1, nil, SF_FILE)).user)
      local t = load_sessions(SF_FILE)
      add_session(t, MAC2, "10.0.0.50", "bob", FUTURE)
      write_sessions(t, SF_FILE)
      local s = session_for_mac(MAC2, "10.0.0.50", SF_FILE)
      assert.is_not_nil(s)
      return assert.equals("bob", s.user)
    end)
    return it("miss sur fichier inchangé → nil", function()
      write_and_reset({
        [MAC1] = {
          user = "alice",
          expires = FUTURE
        }
      }, SF_FILE)
      assert.equals("alice", (session_for_mac(MAC1, nil, SF_FILE)).user)
      return assert.is_nil(session_for_mac(MAC2, "10.0.0.77", SF_FILE))
    end)
  end)
  describe("user_for_mac", function()
    local MAC = "aa:bb:cc:dd:ee:ff"
    before_each(function()
      return reset_cache()
    end)
    after_each(function()
      return os.remove(SF_FILE)
    end)
    it("retourne le username pour une IP connue", function()
      write_and_reset({
        [MAC] = {
          user = "j@prn.ovh",
          expires = FUTURE,
          ips = {
            ipv4 = "10.35.1.53"
          }
        }
      }, SF_FILE)
      local user = user_for_mac(nil, "10.35.1.53", SF_FILE)
      return assert.equals("j@prn.ovh", user)
    end)
    it("IP nil → nil", function()
      return assert.is_nil(user_for_mac(nil, nil, SF_FILE))
    end)
    it("IP sans session correspondante → nil", function()
      write_and_reset({
        [MAC] = {
          user = "alice",
          expires = FUTURE,
          ips = {
            ipv4 = "10.0.0.1"
          }
        }
      }, SF_FILE)
      return assert.is_nil(user_for_mac(nil, "192.168.99.1", SF_FILE))
    end)
    return it("session expirée → nil", function()
      write_and_reset({
        [MAC] = {
          user = "alice",
          expires = 1,
          ips = {
            ipv4 = "10.0.0.1"
          }
        }
      }, SF_FILE)
      return assert.is_nil(user_for_mac(MAC, "10.0.0.1", SF_FILE))
    end)
  end)
  describe("load_sessions cas limites", function()
    it("load_sessions nil → table vide", function()
      load_sessions = require("auth.sessions").load_sessions
      local result = load_sessions(nil)
      assert.is_not_nil(result)
      return assert.equals(0, #(result or { }))
    end)
    return it("load_sessions fichier Lua valide mais sans return → table vide", function()
      local path = "tmp/sessions_noreturn.lua"
      local fh = io.open(path, "w")
      fh:write("-- no return\nlocal x = 1\n")
      fh:close()
      load_sessions = require("auth.sessions").load_sessions
      local result = load_sessions(path)
      assert.is_not_nil(result)
      return os.remove(path)
    end)
  end)
  return describe("enrich_session_ip + bind_session_mac", function()
    local enrich_session_ip, bind_session_mac
    do
      local _obj_0 = require("auth.sessions")
      enrich_session_ip, bind_session_mac, session_for_mac = _obj_0.enrich_session_ip, _obj_0.bind_session_mac, _obj_0.session_for_mac
    end
    local ENRICH_FILE = "tmp/sessions_enrich.lua"
    local EMAC = "11:22:33:44:55:66"
    local EMAC2 = "aa:bb:cc:dd:ee:ff"
    before_each(function()
      return reset_cache()
    end)
    it("enrich_session_ip : args invalides → false", function()
      assert.is_false((enrich_session_ip(nil, "10.0.0.1", ENRICH_FILE)))
      assert.is_false((enrich_session_ip(EMAC, nil, ENRICH_FILE)))
      return assert.is_false((enrich_session_ip(EMAC, "10.0.0.1", nil)))
    end)
    it("enrich_session_ip : IPv6 address → family=ipv6", function()
      local fh = io.open(ENRICH_FILE, "w")
      fh:write(string.format('return { ["%s"] = { user="bob", expires=%d } }\n', EMAC, FUTURE))
      fh:close()
      reset_cache()
      enrich_session_ip(EMAC, "2001:db8::1", ENRICH_FILE)
      local s = session_for_mac(EMAC, "2001:db8::1", ENRICH_FILE)
      assert.is_not_nil(s)
      return os.remove(ENRICH_FILE)
    end)
    it("bind_session_mac : args invalides → false", function()
      assert.is_false((bind_session_mac(EMAC, nil, "10.0.0.1", ENRICH_FILE)))
      return assert.is_false((bind_session_mac(EMAC, EMAC2, "10.0.0.1", nil)))
    end)
    return it("bind_session_mac : même MAC → appelle enrich", function()
      local fh = io.open(ENRICH_FILE, "w")
      fh:write(string.format('return { ["%s"] = { user="carol", expires=%d } }\n', EMAC, FUTURE))
      fh:close()
      reset_cache()
      bind_session_mac(EMAC, EMAC, "10.0.0.1", ENRICH_FILE)
      return os.remove(ENRICH_FILE)
    end)
  end)
end)
