-- tests/unit/auth/user_sessions_spec.moon
-- Unit tests for user session management.

describe "auth.user_sessions", ->
  { :init, :add_session, :get_session, :is_authenticated, :refresh_session, :remove_session, :cleanup_expired, :get_all_sessions } = require "auth.user_sessions"
  
  before_each ->
    init 3600  -- 1 hour timeout
  
  describe "add_session", ->
    it "adds a new user session", ->
      result = add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      assert.is_true result
    
    it "returns false for missing username", ->
      result = add_session nil, "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      assert.is_false result
    
    it "returns false for missing IP", ->
      result = add_session "alice", nil, "aa:bb:cc:dd:ee:ff"
      assert.is_false result
    
    it "returns false for missing MAC", ->
      result = add_session "alice", "192.168.1.10", nil
      assert.is_false result
  
  describe "get_session", ->
    it "retrieves an added session", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      session = get_session "alice"
      
      assert.is_not_nil session
      assert.equals "alice", session.username
      assert.equals "192.168.1.10", session.src_ip
      assert.equals "aa:bb:cc:dd:ee:ff", session.mac
    
    it "returns nil for non-existent session", ->
      session = get_session "nonexistent"
      assert.is_nil session
    
    it "case-insensitive username lookup", ->
      add_session "Alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      session = get_session "ALICE"
      assert.is_not_nil session
      assert.equals "alice", session.username
  
  describe "is_authenticated", ->
    it "returns true for authenticated user", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      result = is_authenticated "alice"
      assert.is_true result
    
    it "returns false for unauthenticated user", ->
      result = is_authenticated "bob"
      assert.is_false result
    
    it "validates IP if provided", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      
      result = is_authenticated "alice", "192.168.1.10"
      assert.is_true result
      
      result = is_authenticated "alice", "192.168.1.20"
      assert.is_false result
    
    it "validates MAC if provided", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      
      result = is_authenticated "alice", nil, "aa:bb:cc:dd:ee:ff"
      assert.is_true result
      
      result = is_authenticated "alice", nil, "11:22:33:44:55:66"
      assert.is_false result
  
  describe "refresh_session", ->
    it "extends session timeout", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      session1 = get_session "alice"
      expires1 = session1.expires
      
      os.execute "sleep 1"
      
      refresh_session "alice"
      session2 = get_session "alice"
      expires2 = session2.expires
      
      assert.is_true expires2 > expires1
    
    it "returns false for non-existent session", ->
      result = refresh_session "nonexistent"
      assert.is_false result
  
  describe "remove_session", ->
    it "removes an existing session", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      assert.is_not_nil get_session "alice"
      
      result = remove_session "alice"
      assert.is_true result
      assert.is_nil get_session "alice"
    
    it "returns false for non-existent session", ->
      result = remove_session "nonexistent"
      assert.is_false result
  
  describe "get_all_sessions", ->
    it "returns all active sessions", ->
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      add_session "bob", "192.168.1.20", "11:22:33:44:55:66"
      
      all = get_all_sessions!
      session_count = 0
      for k in pairs all
        session_count += 1
      assert.equals 2, session_count
      assert.is_not_nil all.alice
      assert.is_not_nil all.bob
    
    it "returns empty table when no sessions", ->
      all = get_all_sessions!
      session_count = 0
      for k in pairs all
        session_count += 1
      assert.equals 0, session_count
  
  describe "cleanup_expired", ->
    it "removes expired sessions", ->
      init 0  -- 0 timeout = immediate expiration
      
      add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
      os.execute "sleep 1"
      
      count = cleanup_expired!
      assert.equals 1, count
      assert.is_nil get_session "alice"
