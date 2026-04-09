return function(cfg)
  return function(user)
    return function(req)
      return false, "from_user not implemented (user=" .. tostring(user) .. ")"
    end
  end
end
