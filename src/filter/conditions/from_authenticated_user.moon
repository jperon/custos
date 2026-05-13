-- src/filter/conditions/from_authenticated_user.moon
-- Condition: Check if source is an authenticated user.
-- API enrichie: worker-only (dynamic session lookup).
--
-- Checks the user session manager to determine if a user is currently
-- authenticated based on IP or MAC address from TLS certificate auth.

{ :get_session } = require "auth.user_sessions"

--- @tparam table cfg Configuration
-- @treturn function factory (username) → enriched_condition
(cfg) ->
  (username) ->
    unless username
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        worker_only: true
        eval: (req) -> false, "from_authenticated_user: no username specified"
        compile_nft: -> nil, "username required"
        creates_dynamic_scope: false
      }
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      worker_only: true
      username: username
      eval: (req) ->
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
      compile_nft: -> nil, "from_authenticated_user requires worker (dynamic sessions)"
      creates_dynamic_scope: false
    }
