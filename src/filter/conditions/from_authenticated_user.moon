-- src/filter/conditions/from_authenticated_user.moon
-- Condition: Check if source is an authenticated user.
--
-- Checks the user session manager to determine if a user is currently
-- authenticated based on IP or MAC address from TLS certificate auth.

{ :get_session } = require "auth.user_sessions"

--- Factory function for authenticated user condition.
-- @tparam table cfg Configuration object
-- @treturn function Condition factory (username) → checker function
(cfg) ->
  
  --- Condition checker function.
  -- @tparam string username Username to check for
  -- @treturn function Evaluator (req) → (match: boolean, reason: string)
  (username) ->
    
    --- Evaluate if request matches authenticated user condition.
    -- @tparam table req Request context {src_ip: string, mac: string, ...}
    -- @treturn boolean, string Match result and reason
    (req) ->
      return false, "from_authenticated_user: no username specified" unless username
      
      -- Get session for this user
      session = get_session username
      
      unless session
        return false, "from_authenticated_user: user #{username} not authenticated"
      
      -- Verify IP matches (if available)
      if req.src_ip and session.src_ip ~= req.src_ip
        return false, "from_authenticated_user: IP mismatch for #{username}"
      
      -- Verify MAC matches (if available)
      if req.mac and session.mac ~= req.mac\lower()
        return false, "from_authenticated_user: MAC mismatch for #{username}"
      
      true, "from_authenticated_user: user #{username} authenticated"
