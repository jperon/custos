local DEFAULT_CONFIG_PATH = "/etc/custos/config.moon"
local DEFAULTS = {
  runtime = {
    log_level = "INFO",
    benchmark = false,
    af_inet = 2,
    af_inet6 = 10
  },
  nfqueue = {
    questions = "0-1",
    responses = "4",
    captive = "20",
    reject = "10-11",
    auth = "5",
    sni_log = "6",
    sip = "12"
  },
  dns = {
    port = 53,
    ttl_grace = {
      grace = 600,
      min = 60,
      max = 2592000
    }
  },
  nft = {
    family = "bridge",
    family6 = "bridge",
    table = "dns-filter-bridge",
    set_ip4 = "ip4_allowed",
    set_ip6 = "ip6_allowed",
    set_mac4 = "mac4_allowed",
    set_mac6 = "mac6_allowed",
    ip_timeout = "2m",
    sip_session_ttl = "5m",
    add_retry_count = 6,
    add_backoff_ms = {
      20,
      50,
      100,
      200,
      400,
      800
    },
    add_failure_policy = "fail-closed",
    ack_timeout_ms = 150,
    extra_rules = { }
  },
  ipc = {
    pending_ttl = 5,
    match_retry = {
      enabled = true,
      count = 5,
      sleep_ms = 20
    }
  },
  clients = {
    expiry = 300
  },
  mac_learner = {
    query_sock = "/var/run/custos/mac_query.sock",
    learn_msg_size = 22,
    entry_ttl = 300
  },
  auth = {
    host = "::",
    port = 33443,
    captive_port = 33080,
    session_ttl = 0,
    heartbeat_interval = 30,
    idle_timeout = 120,
    secrets = "/etc/custos/secrets",
    sessions_file = "/tmp/sessions.lua",
    sni_verdict = {
      enabled = true,
      mode = "strict-443",
      protocols = "both",
      nft_failure_policy = "fail-closed"
    }
  },
  doh = {
    enabled = true,
    port = 8443,
    upstream_ipv4 = "1.1.1.3",
    upstream_ipv6 = "2606:4700:4700::1113",
    upstream_port = 53,
    upstream_timeout_ms = 2000,
    cert_path = nil,
    key_path = nil,
    prefer_ipv6 = true
  },
  events = {
    dir = "/tmp/custos/events",
    max_age_hours = 168,
    min_free_pct = 30
  },
  metrics = {
    enabled = true,
    flush_interval = 60,
    max_rules = 1000
  },
  filter = {
    domainlists_dir = "/etc/custos/lists",
    custom_lists_dir = nil,
    allow_localnets = false,
    nets = { },
    macs = { },
    times = { },
    sources = { },
    users = { },
    userlists = { },
    rules = { },
    dest_whitelist = { },
    allowed_domains = {
      "local",
      "lan",
      "home.arpa"
    },
    decision = {
      first_match_wins = true,
      continue_to_next_rule = false
    }
  }
}
local is_array
is_array = function(t)
  if not (type(t) == "table") then
    return false
  end
  local n = #t
  if n == 0 then
    return false
  end
  for i = 1, n do
    if t[i] == nil then
      return false
    end
  end
  return true
end
local clone
clone = function(v)
  if not (type(v) == "table") then
    return v
  end
  local out = { }
  for k, item in pairs(v) do
    out[k] = clone(item)
  end
  return out
end
local merge_into
merge_into = function(dst, src)
  if not (type(src) == "table") then
    return dst
  end
  for k, v in pairs(src) do
    if type(v) == "table" and type(dst[k]) == "table" and not is_array(v) then
      merge_into(dst[k], v)
    else
      dst[k] = clone(v)
    end
  end
  return dst
end
local coerce_boolean
coerce_boolean = function(v)
  if type(v) == "boolean" then
    return v
  end
  if v == "1" or v == "true" then
    return true
  end
  if v == "0" or v == "false" then
    return false
  end
  return v
end
local normalize
normalize = function(cfg)
  cfg.runtime = cfg.runtime or { }
  cfg.doh = cfg.doh or { }
  cfg.dns = cfg.dns or { }
  cfg.dns.ttl_grace = cfg.dns.ttl_grace or { }
  cfg.filter = cfg.filter or { }
  cfg.filter.decision = cfg.filter.decision or { }
  cfg.filter.dest_whitelist = cfg.filter.dest_whitelist or { }
  cfg.filter.allowed_domains = cfg.filter.allowed_domains or { }
  cfg.filter.nets = cfg.filter.nets or { }
  cfg.filter.macs = cfg.filter.macs or { }
  cfg.filter.times = cfg.filter.times or { }
  cfg.filter.sources = cfg.filter.sources or { }
  cfg.filter.rules = cfg.filter.rules or { }
  cfg.filter.users = cfg.filter.users or { }
  cfg.filter.userlists = cfg.filter.userlists or cfg.filter.users or { }
  cfg.filter.users = cfg.filter.users or cfg.filter.userlists or { }
  cfg.auth = cfg.auth or { }
  cfg.auth.sni_verdict = cfg.auth.sni_verdict or { }
  local defaults = DEFAULTS
  local decision_defaults = defaults.filter and defaults.filter.decision or { }
  local ttl_defaults = defaults.dns and defaults.dns.ttl_grace or { }
  local auth_defaults = defaults.auth or { }
  local sni_defaults = auth_defaults.sni_verdict or { }
  cfg.doh.enabled = coerce_boolean(cfg.doh.enabled)
  cfg.doh.prefer_ipv6 = coerce_boolean(cfg.doh.prefer_ipv6)
  cfg.runtime.benchmark = coerce_boolean(cfg.runtime.benchmark)
  if cfg.filter.decision.first_match_wins == nil then
    cfg.filter.decision.first_match_wins = decision_defaults.first_match_wins
  else
    cfg.filter.decision.first_match_wins = coerce_boolean(cfg.filter.decision.first_match_wins)
  end
  if cfg.filter.decision.continue_to_next_rule == nil then
    cfg.filter.decision.continue_to_next_rule = decision_defaults.continue_to_next_rule
  else
    cfg.filter.decision.continue_to_next_rule = coerce_boolean(cfg.filter.decision.continue_to_next_rule)
  end
  cfg.filter.allow_localnets = coerce_boolean(cfg.filter.allow_localnets)
  local ttl = cfg.dns.ttl_grace
  ttl.grace = tonumber(ttl.grace) or ttl_defaults.grace
  ttl.min = tonumber(ttl.min) or ttl_defaults.min
  ttl.max = tonumber(ttl.max) or ttl_defaults.max
  cfg.auth.port = tonumber(cfg.auth.port) or auth_defaults.port
  cfg.auth.captive_port = tonumber(cfg.auth.captive_port) or auth_defaults.captive_port
  cfg.auth.session_ttl = tonumber(cfg.auth.session_ttl) or auth_defaults.session_ttl
  cfg.auth.heartbeat_interval = tonumber(cfg.auth.heartbeat_interval) or auth_defaults.heartbeat_interval
  cfg.auth.idle_timeout = tonumber(cfg.auth.idle_timeout) or auth_defaults.idle_timeout
  if cfg.auth.sni_verdict.enabled == nil then
    cfg.auth.sni_verdict.enabled = sni_defaults.enabled
  else
    cfg.auth.sni_verdict.enabled = coerce_boolean(cfg.auth.sni_verdict.enabled)
  end
  cfg.auth.sni_verdict.mode = cfg.auth.sni_verdict.mode or sni_defaults.mode
  cfg.auth.sni_verdict.protocols = cfg.auth.sni_verdict.protocols or sni_defaults.protocols
  cfg.auth.sni_verdict.nft_failure_policy = cfg.auth.sni_verdict.nft_failure_policy or sni_defaults.nft_failure_policy
  return cfg
end
local load_external_config
load_external_config = function(path)
  local moon_base = require("moonscript.base")
  local chunk, load_err = moon_base.loadfile(path)
  if not (chunk) then
    return nil, load_err
  end
  local ok, custom = pcall(chunk)
  if not (ok) then
    return nil, custom
  end
  if not (type(custom) == "table") then
    return nil, "config file must return a table"
  end
  return custom, nil
end
local build
build = function()
  local cfg = clone(DEFAULTS)
  local env_path = os.getenv("CUSTOS_CONFIG_PATH")
  local require_external = os.getenv("CUSTOS_REQUIRE_EXTERNAL_CONFIG")
  require_external = require_external == "1" or require_external == "true"
  local path = env_path or DEFAULT_CONFIG_PATH
  local custom, err = load_external_config(path)
  local load_err = nil
  if custom then
    merge_into(cfg, custom)
  else
    if err then
      load_err = tostring(err)
    end
    if require_external then
      error("config: required external config failed to load " .. tostring(path) .. ": " .. tostring(load_err or 'unknown error'))
    end
    if err and not tostring(err):match("No such file") then
      io.stderr:write("config: failed to load " .. tostring(path) .. ": " .. tostring(tostring(err)) .. "\n")
    end
  end
  normalize(cfg)
  cfg.__meta = {
    path = path,
    env_path = env_path,
    external_loaded = custom ~= nil,
    load_error = load_err
  }
  return cfg
end
return build()
