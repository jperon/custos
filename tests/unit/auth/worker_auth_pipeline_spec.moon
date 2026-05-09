-- tests/unit/auth/worker_auth_pipeline_spec.moon
-- Unit tests for the authentication pipeline worker.

describe "worker_auth_pipeline", ->
  worker = require "worker_auth_pipeline"
  user_sessions = require "auth.user_sessions"
  
  before_each ->
    user_sessions.init 3600
    worker.init { auth: { session_timeout: 3600, user_field: "subject" } }
  
  describe "init", ->
    it "initializes worker with configuration", ->
      cfg = {
        auth: {
          session_timeout: 7200
          user_field: "subject"
        }
      }
      -- Just verify no error
      worker.init cfg
    
    it "uses defaults when config missing", ->
      worker.init {}
  
  describe "process_tls_certificate", ->
    it "extracts username and creates session", ->
      tls_data = {
        certificate: {
          subject: "C=US,O=Company,CN=alice"
        }
        src_ip: "192.168.1.10"
        mac: "aa:bb:cc:dd:ee:ff"
      }
      
      success, reason = worker.process_tls_certificate tls_data
      assert.is_true success
      assert.is_nil reason
      
      session = worker.get_user_session "alice"
      assert.is_not_nil session
      assert.equals "alice", session.username
    
    it "returns error for missing certificate", ->
      tls_data = {
        src_ip: "192.168.1.10"
        mac: "aa:bb:cc:dd:ee:ff"
      }
      
      success, reason = worker.process_tls_certificate tls_data
      assert.is_false success
      assert.is_not_nil reason
    
    it "returns error for missing IP", ->
      tls_data = {
        certificate: {
          subject: "CN=alice"
        }
        mac: "aa:bb:cc:dd:ee:ff"
      }
      
      success, reason = worker.process_tls_certificate tls_data
      assert.is_false success
      assert.is_not_nil reason
    
    it "returns error for invalid username", ->
      tls_data = {
        certificate: {
          subject: "C=US"  -- No CN
        }
        src_ip: "192.168.1.10"
        mac: "aa:bb:cc:dd:ee:ff"
      }
      
      success, reason = worker.process_tls_certificate tls_data
      assert.is_false success
      assert.is_not_nil reason
    
    it "handles case-insensitive username extraction", ->
      tls_data = {
        certificate: {
          subject: "CN=Alice"
        }
        src_ip: "192.168.1.10"
        mac: "aa:bb:cc:dd:ee:ff"
      }
      
      success = worker.process_tls_certificate tls_data
      assert.is_true success
      
      session = worker.get_user_session "alice"
      assert.is_not_nil session
  
  describe "periodic_cleanup", ->
    it "cleans up expired sessions", ->
      worker.init { auth: { session_timeout: 0 } }  -- Immediate expiration
      
      tls_data = {
        certificate: {
          subject: "CN=alice"
        }
        src_ip: "192.168.1.10"
        mac: "aa:bb:cc:dd:ee:ff"
      }
      
      worker.process_tls_certificate tls_data
      assert.is_not_nil worker.get_user_session "alice"
      
      os.execute "sleep 1"
      count = worker.periodic_cleanup!
      assert.equals 1, count
      assert.is_nil worker.get_user_session "alice"
  
  describe "get_user_session", ->
    it "returns session for authenticated user", ->
      tls_data = {
        certificate: { subject: "CN=alice" }
        src_ip: "192.168.1.10"
        mac: "aa:bb:cc:dd:ee:ff"
      }
      
      worker.process_tls_certificate tls_data
      session = worker.get_user_session "alice"
      
      assert.is_not_nil session
      assert.equals "192.168.1.10", session.src_ip
    
    it "returns nil for non-existent user", ->
      session = worker.get_user_session "nonexistent"
      assert.is_nil session
