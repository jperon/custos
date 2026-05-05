local serialize, write_sessions, load_sessions, add_session, purge_expired, session_for_ip, user_for_ip, reset_cache
do
  local _obj_0 = require("auth.sessions")
  serialize, write_sessions, load_sessions, add_session, purge_expired, session_for_ip, user_for_ip, reset_cache = _obj_0.serialize, _obj_0.write_sessions, _obj_0.load_sessions, _obj_0.add_session, _obj_0.purge_expired, _obj_0.session_for_ip, _obj_0.user_for_ip, _obj_0.reset_cache
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
    it("une session : MAC, user et expires présents", function()
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
    it("heartbeat sérialisé quand présent", function()
      local sessions = {
        ["11:22:33:44:55:66"] = {
          user = "bob",
          expires = 8888,
          heartbeat = 7777,
          mac = "11:22:33:44:55:66"
        }
      }
      local result = serialize(sessions)
      return assert.is_true(result:find("heartbeat = 7777", 1, true) ~= nil)
    end)
    it("expires absent si nil", function()
      local sessions = {
        ["11:22:33:44:55:66"] = {
          user = "bob",
          heartbeat = 7777,
          mac = "11:22:33:44:55:66"
        }
      }
      local result = serialize(sessions)
      assert.is_nil(result:find("expires =", 1, true))
      return assert.is_true(result:find("heartbeat = 7777", 1, true) ~= nil)
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
    it("pas de champ ips si nil", function()
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
    return it("IP stockée dans ips.ipv4", function()
      local sessions = {
        ["aa:bb:cc:dd:ee:ff"] = {
          user = "alice",
          expires = 9999,
          mac = "aa:bb:cc:dd:ee:ff",
          ips = {
            ipv4 = "10.0.0.1"
          }
        }
      }
      local result = serialize(sessions)
      return assert.is_true(result:find('ipv4 = "10.0.0.1"', 1, true) ~= nil)
    end)
  end)
  describe("write_sessions + load_sessions", function()
    after_each(function()
      return os.remove(SESS_FILE)
    end)
    it("round-trip : trois sessions distinctes", function()
      local sessions = {
        ["aa:bb:cc:dd:ee:ff"] = {
          user = "alice",
          expires = 9999999,
          mac = "aa:bb:cc:dd:ee:ff"
        },
        ["11:22:33:44:55:66"] = {
          user = "bob",
          expires = 8888888,
          heartbeat = 111,
          mac = "11:22:33:44:55:66"
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
      assert.is_not_nil(loaded["aa:bb:cc:dd:ee:ff"])
      assert.equals("alice", loaded["aa:bb:cc:dd:ee:ff"].user)
      assert.equals(9999999, loaded["aa:bb:cc:dd:ee:ff"].expires)
      assert.is_not_nil(loaded["11:22:33:44:55:66"])
      assert.equals(111, loaded["11:22:33:44:55:66"].heartbeat)
      assert.is_not_nil(loaded["22:33:44:55:66:77"])
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
      add_session(sessions, "aa:bb:cc:dd:ee:ff", "10.1.0.1", "charlie", 3600, 0)
      local s = sessions["aa:bb:cc:dd:ee:ff"]
      assert.is_not_nil(s)
      assert.equals("charlie", s.user)
      assert.is_true(s.expires > os.time())
      return assert.is_nil(s.heartbeat)
    end)
    it("stocke l'IP dans ips.ipv4", function()
      local sessions = { }
      add_session(sessions, "aa:bb:cc:dd:ee:ff", "10.1.0.1", "charlie", 3600, 0)
      return assert.equals("10.1.0.1", sessions["aa:bb:cc:dd:ee:ff"].ips.ipv4)
    end)
    it("normalise la MAC en minuscules", function()
      local sessions = { }
      add_session(sessions, "AA:BB:CC:DD:EE:FF", "10.1.0.5", "eve", 3600, 0)
      assert.is_not_nil(sessions["aa:bb:cc:dd:ee:ff"])
      return assert.equals("eve", sessions["aa:bb:cc:dd:ee:ff"].user)
    end)
    it("heartbeat non nil si idle_timeout > 0", function()
      local sessions = { }
      add_session(sessions, "aa:bb:cc:dd:ee:ff", "10.1.0.2", "diana", 3600, 120)
      local s = sessions["aa:bb:cc:dd:ee:ff"]
      assert.is_not_nil(s.heartbeat)
      return assert.is_true(s.heartbeat > os.time())
    end)
    it("session_ttl=0 → expires nil", function()
      local sessions = { }
      add_session(sessions, "aa:bb:cc:dd:ee:ff", "10.1.0.3", "frank", 0, 120)
      local s = sessions["aa:bb:cc:dd:ee:ff"]
      assert.is_not_nil(s)
      assert.is_nil(s.expires)
      return assert.is_true(s.heartbeat > os.time())
    end)
    it("deux sessions différentes → session_count == 2", function()
      local sessions = { }
      add_session(sessions, "aa:bb:cc:dd:ee:01", "10.0.0.1", "user1", 3600, 0)
      add_session(sessions, "aa:bb:cc:dd:ee:02", "10.0.0.2", "user2", 3600, 0)
      local count = 0
      for _ in pairs(sessions) do
        count = count + 1
      end
      return assert.equals(2, count)
    end)
    it("MAC 'unknown' est ignorée", function()
      local sessions = { }
      add_session(sessions, "unknown", "10.0.0.1", "ghost", 3600, 0)
      local count = 0
      for _ in pairs(sessions) do
        count = count + 1
      end
      return assert.equals(0, count)
    end)
    return it("MAC nil est ignorée", function()
      local sessions = { }
      add_session(sessions, nil, "10.0.0.1", "ghost", 3600, 0)
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
    it("supprime une session dont heartbeat est expiré (même si expires futur)", function()
      local sessions = {
        ["aa:bb:cc:dd:ee:03"] = {
          user = "hb",
          expires = FUTURE,
          heartbeat = 1
        }
      }
      purge_expired(sessions)
      return assert.is_nil(sessions["aa:bb:cc:dd:ee:03"])
    end)
    it("conserve une session sans expires absolu (heartbeat futur)", function()
      local sessions = {
        ["aa:bb:cc:dd:ee:04"] = {
          user = "noabs",
          heartbeat = FUTURE
        }
      }
      purge_expired(sessions)
      return assert.is_not_nil(sessions["aa:bb:cc:dd:ee:04"])
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
  describe("session_for_ip", function()
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
      local s = session_for_ip(nil, SF_FILE, MAC)
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
      local s = session_for_ip("10.0.0.1", SF_FILE)
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
      local s = session_for_ip("fd00::1", SF_FILE)
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
      local s = session_for_ip("10.0.0.99", SF_FILE, "unknown")
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
      local s = session_for_ip("9.9.9.9", SF_FILE)
      return assert.is_nil(s)
    end)
    it("session expirée → nil", function()
      write_and_reset({
        [MAC] = {
          user = "alice",
          expires = 1
        }
      }, SF_FILE)
      local s = session_for_ip("10.0.0.9", SF_FILE, MAC)
      return assert.is_nil(s)
    end)
    return it("MAC fournie explicitement prime sur scan IP", function()
      write_and_reset({
        [MAC] = {
          user = "j@prn.ovh",
          expires = FUTURE
        }
      }, SF_FILE)
      local s = session_for_ip("10.35.1.53", SF_FILE, MAC)
      assert.is_not_nil(s)
      return assert.equals("j@prn.ovh", s.user)
    end)
  end)
  return describe("user_for_ip", function()
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
      local user = user_for_ip("10.35.1.53", SF_FILE)
      return assert.equals("j@prn.ovh", user)
    end)
    it("IP nil → nil", function()
      local user = user_for_ip(nil, SF_FILE)
      return assert.is_nil(user)
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
      local user = user_for_ip("192.168.99.1", SF_FILE)
      return assert.is_nil(user)
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
      local user = user_for_ip("10.0.0.1", SF_FILE, MAC)
      return assert.is_nil(user)
    end)
  end)
end)
