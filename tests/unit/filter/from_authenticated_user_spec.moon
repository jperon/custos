-- tests/unit/filter/from_authenticated_user_spec.moon
-- Unit tests for the from_authenticated_user condition.

describe "filter.conditions.from_authenticated_user", ->
  from_authenticated_user = require "filter.conditions.from_authenticated_user"
  { :init, :add_session } = require "auth.user_sessions"
  
  before_each ->
    init 3600  -- Initialize sessions with 1 hour timeout
  
  describe "basic usage", ->
    it "matches authenticated user by username", ->
      -- Add authenticated user
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      
      -- Create condition checker
      condition = (from_authenticated_user {}) "alice"
      
      -- Check if request matches
      req = { src_ip: "192.168.1.10", mac: "aa:bb:cc:dd:ee:ff" }
      match, reason = condition req
      
      assert.is_true match
      assert.is_string reason
    
    it "rejects unauthenticated users", ->
      condition = (from_authenticated_user {}) "bob"
      req = { src_ip: "192.168.1.10", mac: "aa:bb:cc:dd:ee:ff" }
      
      match, reason = condition req
      assert.is_false match
      assert.is_string reason
    
    it "rejects request with no username specified", ->
      condition = (from_authenticated_user {}) nil
      req = { src_ip: "192.168.1.10" }
      
      match, reason = condition req
      assert.is_false match
      assert.is_string reason
  
  describe "IP validation", ->
    it "validates source IP matches", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      condition = (from_authenticated_user {}) "alice"
      
      -- Correct IP
      req1 = { src_ip: "192.168.1.10", mac: "aa:bb:cc:dd:ee:ff" }
      match1, reason1 = condition req1
      assert.is_true match1
      
      -- Wrong IP
      req2 = { src_ip: "192.168.1.20", mac: "aa:bb:cc:dd:ee:ff" }
      match2, reason2 = condition req2
      assert.is_false match2
    
    it "allows request without IP specified", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      condition = (from_authenticated_user {}) "alice"
      
      -- Request without IP should still match if user is authenticated
      req = { mac: "aa:bb:cc:dd:ee:ff" }
      match, reason = condition req
      assert.is_true match
  
  describe "MAC validation", ->
    it "validates source MAC matches", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      condition = (from_authenticated_user {}) "alice"
      
      -- Correct MAC
      req1 = { src_ip: "192.168.1.10", mac: "aa:bb:cc:dd:ee:ff" }
      match1, reason1 = condition req1
      assert.is_true match1
      
      -- Wrong MAC
      req2 = { src_ip: "192.168.1.10", mac: "11:22:33:44:55:66" }
      match2, reason2 = condition req2
      assert.is_false match2
    
    it "handles case-insensitive MAC comparison", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      condition = (from_authenticated_user {}) "alice"
      
      -- Uppercase MAC should match lowercase stored MAC
      req = { src_ip: "192.168.1.10", mac: "AA:BB:CC:DD:EE:FF" }
      match, reason = condition req
      assert.is_true match
    
    it "allows request without MAC specified", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      condition = (from_authenticated_user {}) "alice"
      
      -- Request without MAC should still match if user is authenticated
      req = { src_ip: "192.168.1.10" }
      match, reason = condition req
      assert.is_true match
  
  describe "multiple users", ->
    it "correctly matches different authenticated users", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      add_session "bob", "192.168.1.20", "11:22:33:44:55:66"
      
      alice_cond = (from_authenticated_user {}) "alice"
      bob_cond = (from_authenticated_user {}) "bob"
      
      alice_req = { src_ip: "192.168.1.10", mac: "aa:bb:cc:dd:ee:ff" }
      bob_req = { src_ip: "192.168.1.20", mac: "11:22:33:44:55:66" }
      
      match_alice_ok, _ = alice_cond alice_req
      assert.is_true match_alice_ok
      
      match_alice_fail, _ = alice_cond bob_req
      assert.is_false match_alice_fail
      
      match_bob_fail, _ = bob_cond alice_req
      assert.is_false match_bob_fail
      
      match_bob_ok, _ = bob_cond bob_req
      assert.is_true match_bob_ok
