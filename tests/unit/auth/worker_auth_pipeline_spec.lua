return describe("worker_auth_pipeline", function()
  local worker = require("worker_auth_pipeline")
  local user_sessions = require("auth.user_sessions")
  before_each(function()
    user_sessions.init(3600)
    return worker.init({
      auth = {
        session_timeout = 3600,
        user_field = "subject"
      }
    })
  end)
  describe("init", function()
    it("initializes worker with configuration", function()
      local cfg = {
        auth = {
          session_timeout = 7200,
          user_field = "subject"
        }
      }
      return worker.init(cfg)
    end)
    return it("uses defaults when config missing", function()
      return worker.init({ })
    end)
  end)
  describe("process_tls_certificate", function()
    it("extracts username and creates session", function()
      local tls_data = {
        certificate = {
          subject = "C=US,O=Company,CN=alice"
        },
        src_ip = "192.168.1.10",
        mac = "aa:bb:cc:dd:ee:ff"
      }
      local success, reason = worker.process_tls_certificate(tls_data)
      assert.is_true(success)
      assert.is_nil(reason)
      local session = worker.get_user_session("alice")
      assert.is_not_nil(session)
      return assert.equals("alice", session.username)
    end)
    it("returns error for missing certificate", function()
      local tls_data = {
        src_ip = "192.168.1.10",
        mac = "aa:bb:cc:dd:ee:ff"
      }
      local success, reason = worker.process_tls_certificate(tls_data)
      assert.is_false(success)
      return assert.is_not_nil(reason)
    end)
    it("returns error for missing IP", function()
      local tls_data = {
        certificate = {
          subject = "CN=alice"
        },
        mac = "aa:bb:cc:dd:ee:ff"
      }
      local success, reason = worker.process_tls_certificate(tls_data)
      assert.is_false(success)
      return assert.is_not_nil(reason)
    end)
    it("returns error for invalid username", function()
      local tls_data = {
        certificate = {
          subject = "C=US"
        },
        src_ip = "192.168.1.10",
        mac = "aa:bb:cc:dd:ee:ff"
      }
      local success, reason = worker.process_tls_certificate(tls_data)
      assert.is_false(success)
      return assert.is_not_nil(reason)
    end)
    return it("handles case-insensitive username extraction", function()
      local tls_data = {
        certificate = {
          subject = "CN=Alice"
        },
        src_ip = "192.168.1.10",
        mac = "aa:bb:cc:dd:ee:ff"
      }
      local success = worker.process_tls_certificate(tls_data)
      assert.is_true(success)
      local session = worker.get_user_session("alice")
      return assert.is_not_nil(session)
    end)
  end)
  describe("periodic_cleanup", function()
    return it("cleans up expired sessions", function()
      worker.init({
        auth = {
          session_timeout = 0
        }
      })
      local tls_data = {
        certificate = {
          subject = "CN=alice"
        },
        src_ip = "192.168.1.10",
        mac = "aa:bb:cc:dd:ee:ff"
      }
      worker.process_tls_certificate(tls_data)
      assert.is_not_nil(worker.get_user_session("alice"))
      os.execute("sleep 1")
      local count = worker.periodic_cleanup()
      assert.equals(1, count)
      return assert.is_nil(worker.get_user_session("alice"))
    end)
  end)
  return describe("get_user_session", function()
    it("returns session for authenticated user", function()
      local tls_data = {
        certificate = {
          subject = "CN=alice"
        },
        src_ip = "192.168.1.10",
        mac = "aa:bb:cc:dd:ee:ff"
      }
      worker.process_tls_certificate(tls_data)
      local session = worker.get_user_session("alice")
      assert.is_not_nil(session)
      return assert.equals("192.168.1.10", session.src_ip)
    end)
    return it("returns nil for non-existent user", function()
      local session = worker.get_user_session("nonexistent")
      return assert.is_nil(session)
    end)
  end)
end)
