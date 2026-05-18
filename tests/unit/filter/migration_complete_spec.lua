package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path
package.loaded["config"] = {
  nft = {
    ip_timeout = "2m"
  },
  times = {
    business_hours = {
      "09:00",
      "17:00"
    }
  },
  times_lists = {
    workdays = {
      "business_hours"
    }
  },
  nets = {
    office = {
      "192.168.0.0/16"
    }
  },
  macs = {
    printers = {
      "aa:bb:cc:dd:ee:01"
    }
  },
  vlans = {
    corp = {
      100,
      200
    }
  },
  domainlists_dir = "/tmp",
  userlists = {
    admins = {
      "alice",
      "bob"
    }
  },
  auth = {
    sessions_file = "/tmp/sessions.json"
  }
}
package.loaded["filter.lib.ipcalc"] = {
  Net = function(cidr)
    if not (cidr and cidr:find("/")) then
      return nil
    end
    return {
      cidr = cidr,
      contains = function(ip)
        return type(ip) == "string"
      end
    }
  end
}
package.loaded["auth.sessions"] = {
  session_for_mac = function()
    return nil
  end,
  enrich_session_ip = function()
    return nil
  end,
  bind_session_mac = function()
    return nil
  end
}
package.loaded["auth.user_sessions"] = {
  get_session = function()
    return nil
  end
}
package.loaded["log"] = {
  log_debug = function() end
}
local compiler_api = require("filter.compiler_api")
local assert_eq
assert_eq = function(got, expected, msg)
  if not (got == expected) then
    return error(tostring(msg or 'assert_eq failed') .. ": got=" .. tostring(tostring(got)) .. " expected=" .. tostring(tostring(expected)))
  end
end
local assert_is_enriched
assert_is_enriched = function(obj, name)
  if not (type(obj) == "table") then
    error(tostring(name) .. " is not a table (enriched object expected)")
  end
  if not (obj.capabilities) then
    error(tostring(name) .. " missing capabilities (not enriched)")
  end
  if not (obj.eval) then
    error(tostring(name) .. " missing eval function (not enriched)")
  end
  if not (obj.compile_nft) then
    return error(tostring(name) .. " missing compile_nft function (not enriched)")
  end
end
print("=== MIGRATION COMPLETE VERIFICATION ===\n")
local conditions = {
  "from_vlan",
  "from_vlans",
  "from_vlanlist",
  "from_vlanlists",
  "from_net",
  "from_nets",
  "from_netlist",
  "from_netlists",
  "from_subnet",
  "from_mac",
  "from_macs",
  "from_maclist",
  "from_maclists",
  "from_user",
  "from_users",
  "from_userlist",
  "from_userlists",
  "from_authenticated_user",
  "in_time",
  "in_times",
  "in_timelist",
  "in_timelists",
  "to_domain",
  "to_domains",
  "to_domainlist",
  "to_domainlists",
  "stolen_computer"
}
local actions = {
  "allow",
  "deny",
  "dnsonly"
}
print("[1] Checking condition modules...")
for _, name in ipairs(conditions) do
  print("  - " .. tostring(name))
  local factory = compiler_api.load_condition(name)
  assert_eq(type(factory), "function", tostring(name) .. " factory is function")
  local args
  local _exp_0 = name
  if "from_vlan" == _exp_0 then
    args = 100
  elseif "from_vlans" == _exp_0 or "from_vlanlist" == _exp_0 then
    args = {
      100,
      200
    }
  elseif "from_vlanlists" == _exp_0 then
    args = {
      "corp"
    }
  elseif "from_net" == _exp_0 then
    args = "192.168.0.0/16"
  elseif "from_nets" == _exp_0 or "from_netlist" == _exp_0 then
    args = {
      "192.168.0.0/16"
    }
  elseif "from_netlists" == _exp_0 then
    args = {
      "office"
    }
  elseif "from_subnet" == _exp_0 then
    args = {
      net = "10.0.0.0/8"
    }
  elseif "from_mac" == _exp_0 then
    args = "aa:bb:cc:dd:ee:ff"
  elseif "from_macs" == _exp_0 or "from_maclist" == _exp_0 then
    args = {
      "aa:bb:cc:dd:ee:ff"
    }
  elseif "from_maclists" == _exp_0 then
    args = {
      "printers"
    }
  elseif "from_user" == _exp_0 or "from_users" == _exp_0 then
    args = {
      "alice"
    }
  elseif "from_userlist" == _exp_0 then
    args = "admins"
  elseif "from_userlists" == _exp_0 then
    args = {
      "admins"
    }
  elseif "from_authenticated_user" == _exp_0 then
    args = "alice"
  elseif "in_time" == _exp_0 then
    args = "business_hours"
  elseif "in_times" == _exp_0 then
    args = {
      "business_hours"
    }
  elseif "in_timelist" == _exp_0 then
    args = "workdays"
  elseif "in_timelists" == _exp_0 then
    args = {
      "workdays"
    }
  elseif "to_domain" == _exp_0 then
    args = "example.com"
  elseif "to_domains" == _exp_0 then
    args = {
      "example.com"
    }
  elseif "to_domainlist" == _exp_0 then
    args = "blocked"
  elseif "to_domainlists" == _exp_0 then
    args = {
      "blocked"
    }
  elseif "stolen_computer" == _exp_0 then
    args = {
      "aa:bb:cc:dd:ee:01"
    }
  else
    args = { }
  end
  local cond_factory = factory({
    nft = {
      ip_timeout = "2m"
    },
    times = {
      business_hours = {
        "09:00",
        "17:00"
      }
    },
    times_lists = {
      workdays = {
        "business_hours"
      }
    },
    nets = {
      office = {
        "192.168.0.0/16"
      }
    },
    macs = {
      printers = {
        "aa:bb:cc:dd:ee:01"
      }
    },
    vlans = {
      corp = {
        100,
        200
      }
    },
    domainlists_dir = "/tmp",
    userlists = {
      admins = {
        "alice",
        "bob"
      }
    },
    auth = {
      sessions_file = "/tmp/sessions.json"
    }
  })
  local cond_obj = cond_factory(args)
  assert_is_enriched(cond_obj, name)
end
print("  ✓ All " .. tostring(#conditions) .. " condition modules migrated\n")
print("[2] Checking action modules...")
for _, name in ipairs(actions) do
  print("  - " .. tostring(name))
  local factory = compiler_api.load_action(name)
  assert_eq(type(factory), "function", tostring(name) .. " factory is function")
  local action_factory = factory({ })
  local action_obj = action_factory({
    description = "test",
    actions = {
      name
    }
  })
  assert_is_enriched(action_obj, name)
end
print("  ✓ All " .. tostring(#actions) .. " action modules migrated\n")
print("[3] Checking legacy files removed...")
local legacy_files = os.execute("ls src/filter/conditions/_match_*.moon 2>/dev/null")
if legacy_files then
  error("Legacy _match_* files still exist!")
end
print("  ✓ Legacy _match_* files removed\n")
print("=== MIGRATION COMPLETE ✓ ===")
print("\nAll conditions and actions are now using the enriched API:")
print("  • capabilities table with worker/nft/nft_dynamic")
print("  • eval() function for runtime checks")
print("  • compile_nft() function for nft compilation")
print("  • worker_only flag for conditional nft generation")
return print("  • creates_dynamic_scope flag for dns_scope tracking")
