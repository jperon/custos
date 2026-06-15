local socket = require("lib.socket")
local ssl = require("auth.ffi_wolfssl")
local ffi = require("ffi")
local fork_child, reap_one
do
  local _obj_0 = require("lib.process")
  fork_child, reap_one = _obj_0.fork_child, _obj_0.reap_one
end
local load_sessions
load_sessions = require("auth.sessions").load_sessions
local token = require("auth.token")
local load_or_generate_sni, load_static
do
  local _obj_0 = require("auth.cert")
  load_or_generate_sni, load_static = _obj_0.load_or_generate_sni, _obj_0.load_static
end
local extract_sni
extract_sni = require("auth.sni_extractor").extract_sni
local log_info, log_warn, log_error, log_debug
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error, log_debug = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error, _obj_0.log_debug
end
local config = require("config")
local read_request, send_response
do
  local _obj_0 = require("lib.http")
  read_request, send_response = _obj_0.read_request, _obj_0.send_response
end
local get_mac
get_mac = require("mac_learner_ipc").get_mac
local refresh_nft
refresh_nft = require("auth.nft_auth_sets").refresh_nft
local handle_request
handle_request = require("auth.handlers").handle_request
local replay_sessions_to_nft
replay_sessions_to_nft = function(state)
  if not (state.nft_sess and state.sessions_file) then
    return 
  end
  local sessions = load_sessions(state.sessions_file)
  local now = os.time()
  local idle_timeout = (state.auth_cfg and state.auth_cfg.idle_timeout) or 120
  local count = 0
  for mac, s in pairs(sessions) do
    local _continue_0 = false
    repeat
      if s.expires and now > s.expires then
        _continue_0 = true
        break
      end
      local ttl
      if s.expires then
        ttl = math.max(1, s.expires - now)
      else
        ttl = idle_timeout
      end
      if s.ips then
        for _, ip in pairs(s.ips) do
          refresh_nft(state.nft_sess, ip, mac, ttl, s.user)
        end
      else
        if mac and mac ~= "unknown" then
          state.nft_sess.add_authenticated_mac(mac, ttl)
        end
      end
      count = count + 1
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return log_info(function()
    return {
      action = "sessions_replayed_to_nft",
      count = count
    }
  end)
end
local resolve_tls_ctx
resolve_tls_ctx = function(state, local_ip, load_static_fn, load_sni_fn)
  if load_static_fn == nil then
    load_static_fn = load_static
  end
  if load_sni_fn == nil then
    load_sni_fn = load_or_generate_sni
  end
  if state.static_tls_ctx then
    log_debug(function()
      return {
        action = "server_using_static_cert",
        inherited = true
      }
    end)
    return state.static_tls_ctx
  end
  if state.static_cert_paths then
    log_debug(function()
      return {
        action = "server_loading_static_cert_child",
        cert = state.static_cert_paths.cert,
        key = state.static_cert_paths.key
      }
    end)
    local ctx, err = load_static_fn(state.static_cert_paths.key, state.static_cert_paths.cert)
    if ctx then
      log_debug(function()
        return {
          action = "server_using_static_cert",
          inherited = false
        }
      end)
      return ctx
    end
    log_error(function()
      return {
        action = "server_static_cert_load_child_failed",
        err = err
      }
    end)
    error("Cannot load static certificate in child: " .. tostring(err))
  end
  local tls_ctx = nil
  local tls_ctx_ok, tls_ctx_err = pcall(function()
    tls_ctx = load_sni_fn(local_ip, state.cert_cache)
  end)
  if not (tls_ctx_ok) then
    log_error(function()
      return {
        action = "server_cert_generation_failed",
        local_ip = local_ip,
        err = tls_ctx_err
      }
    end)
    error("Cannot generate certificate: " .. tostring(tls_ctx_err))
  end
  return tls_ctx
end
local handle_client
handle_client = function(args)
  local client = args.client
  local state = args.state
  local peer_ip = args.peer_ip or "unknown"
  local ok, err = pcall(function()
    log_debug(function()
      return {
        action = "server_handle_client_start",
        peer = peer_ip,
        fd = client.fd
      }
    end)
    local local_ip = client:getsockname()
    if not (local_ip) then
      local errno = tonumber(ffi.C.__errno_location()[0])
      log_warn(function()
        return {
          action = "server_getsockname_failed",
          peer = peer_ip,
          errno = errno
        }
      end)
      local_ip = "custos"
    end
    log_debug(function()
      return {
        action = "server_local_ip_detected",
        local_ip = local_ip
      }
    end)
    local tls_ctx = resolve_tls_ctx(state, local_ip)
    if not (tls_ctx) then
      log_error(function()
        return {
          action = "server_cert_null",
          local_ip = local_ip
        }
      end)
      error("Certificate context is nil")
    end
    log_debug(function()
      return {
        action = "server_cert_loaded",
        local_ip = local_ip
      }
    end)
    log_debug(function()
      return {
        action = "server_set_blocking_mode"
      }
    end)
    client:settimeout(nil)
    local client_timeout = (state.auth_cfg and tonumber(state.auth_cfg.client_timeout)) or 15
    pcall(function()
      return client:setoption("rcvtimeo", client_timeout)
    end)
    pcall(function()
      return client:setoption("sndtimeo", client_timeout)
    end)
    log_debug(function()
      return {
        action = "server_blocking_mode_set",
        client_timeout = client_timeout
      }
    end)
    log_debug(function()
      return {
        action = "server_ssl_wrap_start"
      }
    end)
    local tls_client, tls_err = ssl.wrap(client, tls_ctx)
    log_debug(function()
      return {
        action = "server_ssl_wrap_done"
      }
    end)
    if not (tls_client) then
      log_warn(function()
        return {
          action = "server_tls_wrap_failed",
          peer = peer_ip,
          err = tls_err
        }
      end)
      client:close()
      return 
    end
    log_debug(function()
      return {
        action = "server_dohandshake_start"
      }
    end)
    local handshake_complete = false
    local handshake_attempts = 0
    local handshake_deadline = os.time() + client_timeout
    while not handshake_complete and handshake_attempts < 50 and os.time() <= handshake_deadline do
      handshake_attempts = handshake_attempts + 1
      log_debug(function()
        return {
          action = "server_handshake_attempt",
          attempt = handshake_attempts
        }
      end)
      local ok_hs, hs_err = tls_client:dohandshake()
      log_debug(function()
        return {
          action = "server_dohandshake_returned",
          ok = ok_hs
        }
      end)
      if ok_hs then
        log_debug(function()
          return {
            action = "server_handshake_complete"
          }
        end)
        handshake_complete = true
      elseif hs_err and hs_err ~= "peer_closed" then
        break
      end
    end
    if not (handshake_complete) then
      if hs_err == "peer_closed" then
        log_warn(function()
          return {
            action = "server_tls_handshake_peer_closed",
            peer = peer_ip,
            attempts = handshake_attempts
          }
        end)
      else
        log_warn(function()
          return {
            action = "server_tls_handshake_failed",
            peer = peer_ip,
            attempts = handshake_attempts,
            err = hs_err or "max attempts reached"
          }
        end)
      end
      tls_client:close()
      return 
    end
    log_debug(function()
      return {
        action = "server_set_http_timeout"
      }
    end)
    local peer_mac = get_mac(peer_ip)
    local req, req_err = read_request(tls_client, {
      timeout = client_timeout
    })
    if not (req) then
      log_warn(function()
        return {
          action = "server_request_read_failed",
          peer = peer_ip,
          err = req_err
        }
      end)
      tls_client:close()
      return 
    end
    local status, headers, body = handle_request(req, peer_ip, peer_mac, state)
    send_response(tls_client, status, headers, body)
    return tls_client:close()
  end)
  if not (ok) then
    log_error(function()
      return {
        action = "server_client_failed",
        peer = peer_ip,
        err = tostring(err)
      }
    end)
    return pcall(function()
      return client:close()
    end)
  end
end
local dispatch_connection
dispatch_connection = function(client, peer_ip, state, fork_fn)
  if fork_fn == nil then
    fork_fn = fork_child
  end
  log_debug(function()
    return {
      action = "server_fork_child_start",
      peer = peer_ip,
      fd = client.fd
    }
  end)
  local fork_ok, pid = pcall(fork_fn, "AUTH-conn", handle_client, {
    client = client,
    peer_ip = peer_ip,
    state = state
  }, {
    log_start = false
  })
  if fork_ok then
    log_debug(function()
      return {
        action = "server_fork_child_done",
        pid = pid
      }
    end)
    log_info(function()
      return {
        action = "server_conn_started",
        pid = pid,
        peer = peer_ip
      }
    end)
  else
    log_error(function()
      return {
        action = "server_fork_child_failed",
        peer = peer_ip,
        err = tostring(pid)
      }
    end)
  end
  pcall(function()
    return client:close()
  end)
  return fork_ok
end
local reload_secrets_if_needed
reload_secrets_if_needed = function(state)
  if not (state.reload_fn) then
    return 
  end
  local new_secrets = state.reload_fn()
  if new_secrets then
    state.secrets = new_secrets
  end
end
local make_server4
make_server4 = function(port)
  local srv = socket.tcp()
  local ok, err = srv:bind("0.0.0.0", port)
  if not (ok) then
    srv:close()
    return nil, err
  end
  srv:listen(32)
  srv:settimeout(1)
  return srv
end
local make_server6
make_server6 = function(port)
  local ok6, srv6 = pcall(socket.tcp6)
  if not (ok6 and srv6) then
    return nil
  end
  srv6:setoption("ipv6-v6only", true)
  local ok62, _ = pcall(srv6.bind, srv6, "::", port)
  if not (ok62) then
    srv6:close()
    return nil
  end
  srv6:listen(32)
  srv6:settimeout(1)
  return srv6
end
local run
run = function(secrets, auth_cfg, reload_fn, nft_sess, secrets_path)
  local port = auth_cfg.port or 33443
  local sessions_file = auth_cfg.sessions_file or config.auth.sessions_file
  log_debug(function()
    return {
      action = "server_startup",
      port = port
    }
  end)
  log_debug(function()
    return {
      action = "server_auth_cfg_received",
      cert = auth_cfg.cert,
      key = auth_cfg.key
    }
  end)
  log_debug(function()
    return {
      action = "server_cert_cache_init"
    }
  end)
  local cert_cache_module = require("auth.cert_cache")
  local cert_cache = cert_cache_module.create_cache(500, 7776000)
  local static_tls_ctx = nil
  if auth_cfg.cert and auth_cfg.key then
    log_info(function()
      return {
        action = "server_loading_static_cert",
        cert = auth_cfg.cert,
        key = auth_cfg.key
      }
    end)
    local ctx, cert_err = load_static(auth_cfg.key, auth_cfg.cert)
    if ctx then
      static_tls_ctx = ctx
      log_info(function()
        return {
          action = "server_static_cert_loaded",
          cert = auth_cfg.cert,
          key = auth_cfg.key
        }
      end)
    else
      log_warn(function()
        return {
          action = "server_static_cert_failed",
          cert = auth_cfg.cert,
          key = auth_cfg.key,
          err = cert_err
        }
      end)
    end
  else
    log_debug(function()
      return {
        action = "server_no_static_cert_configured"
      }
    end)
  end
  local token_key = token.load_key(auth_cfg.session_key or "/etc/custos/session.key")
  log_info(function()
    return {
      action = "server_session_key_loaded"
    }
  end)
  local listen4, err4 = make_server4(port)
  if not (listen4) then
    error("Impossible de démarrer le serveur IPv4 sur port " .. tostring(port) .. " : " .. tostring(err4))
  end
  local listen6 = make_server6(port)
  local all_servers = {
    listen4
  }
  if listen6 then
    all_servers[#all_servers + 1] = listen6
  end
  local state = {
    secrets = secrets or { },
    auth_cfg = auth_cfg,
    reload_fn = reload_fn,
    nft_sess = nft_sess,
    secrets_path = secrets_path,
    sessions_file = sessions_file,
    token_key = token_key,
    admin_users = auth_cfg.admin_users or { },
    admin_allow_all_when_empty = auth_cfg.admin_allow_all_when_empty or false,
    config_path = auth_cfg.config_path or "/etc/custos/config.moon",
    events_dir = config.events and config.events.dir or "/tmp/custos/events",
    started_at = os.time(),
    static_tls_ctx = static_tls_ctx,
    static_cert_paths = (function()
      if auth_cfg.cert and auth_cfg.key then
        return {
          cert = auth_cfg.cert,
          key = auth_cfg.key
        }
      else
        return nil
      end
    end)(),
    cert_cache = cert_cache
  }
  log_info(function()
    return {
      action = "server_listening",
      port = port,
      ipv4 = "0.0.0.0",
      ipv6 = listen6 and "::" or nil,
      sessions_file = sessions_file,
      cert_cache = (function()
        if auth_cfg.cert and auth_cfg.key then
          return "static cert + dynamic SNI cache"
        else
          return "dynamic SNI cache (500 slots, 90d TTL)"
        end
      end)()
    }
  end)
  replay_sessions_to_nft(state)
  while true do
    reload_secrets_if_needed(state)
    while true do
      local dead_pid = reap_one()
      if not (dead_pid and dead_pid > 0) then
        break
      end
    end
    local readable, _ = socket.select(all_servers, nil, 0.1)
    if readable then
      for _index_0 = 1, #readable do
        local srv = readable[_index_0]
        log_debug(function()
          return {
            action = "server_socket_select_readable"
          }
        end)
        local client = srv:accept()
        log_debug(function()
          return {
            action = "server_accept_returned"
          }
        end)
        if client then
          log_debug(function()
            return {
              action = "server_got_client"
            }
          end)
          local peer_ip = client:getpeername() or "unknown"
          log_debug(function()
            return {
              action = "server_getpeername_result",
              peer = peer_ip
            }
          end)
          dispatch_connection(client, peer_ip, state)
        end
      end
    end
  end
end
return {
  run = run,
  replay_sessions_to_nft = replay_sessions_to_nft,
  dispatch_connection = dispatch_connection,
  resolve_tls_ctx = resolve_tls_ctx
}
