return describe("filter.conditions.from_authenticated_user", function()
  local from_authenticated_user = require("filter.conditions.from_authenticated_user")
  local init, add_session
  do
    local _obj_0 = require("auth.user_sessions")
    init, add_session = _obj_0.init, _obj_0.add_session
  end
  before_each(function()
    return init(3600)
  end)
  describe("basic usage", function()
    it("matches authenticated user by username", function()
      add_session("alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff")
      local condition = (from_authenticated_user({ }))("alice")
      local req = {
        src_ip = "192.168.1.10",
        mac = "aa:bb:cc:dd:ee:ff"
      }
      local match, reason = condition(req)
      assert.is_true(match)
      return assert.is_string(reason)
    end)
    it("rejects unauthenticated users", function()
      local condition = (from_authenticated_user({ }))("bob")
      local req = {
        src_ip = "192.168.1.10",
        mac = "aa:bb:cc:dd:ee:ff"
      }
      local match, reason = condition(req)
      assert.is_false(match)
      return assert.is_string(reason)
    end)
    return it("rejects request with no username specified", function()
      local condition = (from_authenticated_user({ }))(nil)
      local req = {
        src_ip = "192.168.1.10"
      }
      local match, reason = condition(req)
      assert.is_false(match)
      return assert.is_string(reason)
    end)
  end)
  describe("IP validation", function()
    it("validates source IP matches", function()
      add_session("alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff")
      local condition = (from_authenticated_user({ }))("alice")
      local req1 = {
        src_ip = "192.168.1.10",
        mac = "aa:bb:cc:dd:ee:ff"
      }
      local match1, reason1 = condition(req1)
      assert.is_true(match1)
      local req2 = {
        src_ip = "192.168.1.20",
        mac = "aa:bb:cc:dd:ee:ff"
      }
      local match2, reason2 = condition(req2)
      return assert.is_false(match2)
    end)
    return it("allows request without IP specified", function()
      add_session("alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff")
      local condition = (from_authenticated_user({ }))("alice")
      local req = {
        mac = "aa:bb:cc:dd:ee:ff"
      }
      local match, reason = condition(req)
      return assert.is_true(match)
    end)
  end)
  describe("MAC validation", function()
    it("validates source MAC matches", function()
      add_session("alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff")
      local condition = (from_authenticated_user({ }))("alice")
      local req1 = {
        src_ip = "192.168.1.10",
        mac = "aa:bb:cc:dd:ee:ff"
      }
      local match1, reason1 = condition(req1)
      assert.is_true(match1)
      local req2 = {
        src_ip = "192.168.1.10",
        mac = "11:22:33:44:55:66"
      }
      local match2, reason2 = condition(req2)
      return assert.is_false(match2)
    end)
    it("handles case-insensitive MAC comparison", function()
      add_session("alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff")
      local condition = (from_authenticated_user({ }))("alice")
      local req = {
        src_ip = "192.168.1.10",
        mac = "AA:BB:CC:DD:EE:FF"
      }
      local match, reason = condition(req)
      return assert.is_true(match)
    end)
    return it("allows request without MAC specified", function()
      add_session("alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff")
      local condition = (from_authenticated_user({ }))("alice")
      local req = {
        src_ip = "192.168.1.10"
      }
      local match, reason = condition(req)
      return assert.is_true(match)
    end)
  end)
  return describe("multiple users", function()
    return it("correctly matches different authenticated users", function()
      add_session("alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff")
      add_session("bob", "192.168.1.20", "11:22:33:44:55:66")
      local alice_cond = (from_authenticated_user({ }))("alice")
      local bob_cond = (from_authenticated_user({ }))("bob")
      local alice_req = {
        src_ip = "192.168.1.10",
        mac = "aa:bb:cc:dd:ee:ff"
      }
      local bob_req = {
        src_ip = "192.168.1.20",
        mac = "11:22:33:44:55:66"
      }
      local match_alice_ok, _ = alice_cond(alice_req)
      assert.is_true(match_alice_ok)
      local match_alice_fail
      match_alice_fail, _ = alice_cond(bob_req)
      assert.is_false(match_alice_fail)
      local match_bob_fail
      match_bob_fail, _ = bob_cond(alice_req)
      assert.is_false(match_bob_fail)
      local match_bob_ok
      match_bob_ok, _ = bob_cond(bob_req)
      return assert.is_true(match_bob_ok)
    end)
  end)
end)
