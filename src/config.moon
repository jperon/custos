-- src/config.moon
-- Configuration runtime hiérarchique.
-- Source de vérité : /etc/custos/config.moon (surcharge partielle des défauts).
--
-- RULES - Filter Conditions and Syntax:
--
-- Conditions supported in rule.conditions array:
--   • to_domain/to_domains/to_domainlist/to_domainlists - DNS name matching
--   • from_net/from_nets/from_netlist/from_netlists - Source IP from named lists
--   • from_subnet/from_subnets - Source IP with inline CIDR notation
--   • from_mac/from_macs/from_maclist/from_maclists - Source MAC address
--   • in_time/in_times/in_timelist/in_timelists - Time window matching
--   • from_user/from_userlist/from_users - User/identity matching
--   • from_vlan/from_vlans/from_vlanlist/from_vlans - VLAN ID matching
--   • stolen_computer - Stolen device detection
--
-- SUBNET CONDITION SYNTAX:
-- from_subnet supports two formats:
--   1. Inline CIDR:    { from_subnet: "10.0.0.0/8" }
--   2. With family:    { from_subnet: { net: "10.0.0.0/8", family: "inet" } }
--   3. Multiple:       { from_subnets: ["10.0.0.0/8", "172.16.0.0/12"] }
--
-- CIDR Notation:
--   • IPv4: x.x.x.x/prefix (e.g., "192.168.0.0/24", "10.0.0.0/8")
--   • IPv6: xxxx::.../prefix (e.g., "fc00::/7", "2001:db8::/32")
--   • Single IP: "192.168.1.1/32" or just "192.168.1.1"
--
-- NFTABLES IMPLEMENTATION:
--   • Subnet sets use "interval" flag for CIDR range matching
--   • Set type: ipv4_addr (IPv4) or ipv6_addr (IPv6)
--   • Elements stored in CIDR notation: { 10.0.0.0/8, 172.16.0.0/12 }
--   • Performance: O(log n) lookup with interval flag
--
-- EXAMPLE:
--   filter:
--     rules:
--       - description: "Allow 10.0.0.0/8 to example.com"
--         conditions:
--           - to_domain: "example.com"
--           - from_subnet: "10.0.0.0/8"
--         actions:
--           - allow
--
--       - description: "Block guest network from internal sites"
--         conditions:
--           - from_subnet: "192.168.100.0/24"
--           - to_domains: ["internal.example.com", "vpn.example.com"]
--         actions:
--           - deny

DEFAULT_CONFIG_PATH = "/etc/custos/config.moon"

DEFAULTS = {
  runtime: {
    log_level: "INFO"
    benchmark: false
    af_inet: 2
    af_inet6: 10
  }

  nfqueue: {
    questions: "0-1"
    responses: "4"
    captive: "20"
    reject: "10-11"
    auth: "5"
    sni_log: "6"
    sip: "12"
  }

  dns: {
    port: 53
    ttl_grace: {
      grace: 600
      min: 60
      max: 2592000
    }
  }

  nft: {
    family: "bridge"
    family6: "bridge"
    table: "dns-filter-bridge"
    ip_timeout: "2m"
    sip_session_ttl: "5m"
    add_retry_count: 6
    add_backoff_ms: {20, 50, 100, 200, 400, 800}
    add_failure_policy: "fail-closed"
    ack_timeout_ms: 150
    extra_rules: {}
  }

  ipc: {
    pending_ttl: 5
    match_retry: {
      enabled: true
      count: 5
      sleep_ms: 20
    }
  }

  clients: {
    expiry: 300
  }

  mac_learner: {
    query_sock: "/var/run/custos/mac_query.sock"
    learn_msg_size: 22
    entry_ttl: 300
  }

  auth: {
    host: "::"
    port: 33443
    captive_port: 33080
    session_ttl: 0
    heartbeat_interval: 30
    idle_timeout: 120
    secrets: "/etc/custos/secrets"
    sessions_file: "/tmp/sessions.lua"
    sni_verdict: {
      enabled: true
      mode: "strict-443"
      protocols: "both"
      nft_failure_policy: "fail-closed"
    }
  }

  doh: {
    enabled: true
    port: 8443
    upstream_ipv4: "1.1.1.3"
    upstream_ipv6: "2606:4700:4700::1113"
    upstream_port: 53
    upstream_timeout_ms: 2000
    cert_path: nil
    key_path: nil
    prefer_ipv6: true
  }

  events: {
    dir: "/tmp/custos/events"
    max_age_hours: 168
    min_free_pct: 30
  }

  metrics: {
    enabled: true
    flush_interval: 60
    max_rules: 1000
  }

  rtp: {
    excluded_ports: { 5060 }
  }

  filter: {
    domainlists_dir: "/etc/custos/lists"
    custom_lists_dir: nil
    allow_localnets: false
    nets: {}
    macs: {}
    times: {}
    sources: {}
    users: {}
    userlists: {}
    rules: {}
    dest_whitelist: {}
    allowed_domains: { "local", "lan", "home.arpa" }
    decision: {
      first_match_wins: true
      continue_to_next_rule: false
    }
  }
}

is_array = (t) ->
  return false unless type(t) == "table"
  n = #t
  return false if n == 0
  for i = 1, n
    return false if t[i] == nil
  true

clone = (v) ->
  return v unless type(v) == "table"
  out = {}
  for k, item in pairs v
    out[k] = clone item
  out

merge_into = (dst, src) ->
  return dst unless type(src) == "table"
  for k, v in pairs src
    if type(v) == "table" and type(dst[k]) == "table" and not is_array(v)
      merge_into dst[k], v
    else
      dst[k] = clone v
  dst

coerce_boolean = (v) ->
  return v if type(v) == "boolean"
  return true if v == "1" or v == "true"
  return false if v == "0" or v == "false"
  v

normalize = (cfg) ->
  cfg.runtime = cfg.runtime or {}
  cfg.doh = cfg.doh or {}
  cfg.dns = cfg.dns or {}
  cfg.dns.ttl_grace = cfg.dns.ttl_grace or {}
  cfg.filter = cfg.filter or {}
  cfg.filter.decision = cfg.filter.decision or {}
  cfg.filter.dest_whitelist = cfg.filter.dest_whitelist or {}
  cfg.filter.allowed_domains = cfg.filter.allowed_domains or {}
  cfg.filter.nets = cfg.filter.nets or {}
  cfg.filter.macs = cfg.filter.macs or {}
  cfg.filter.times = cfg.filter.times or {}
  cfg.filter.sources = cfg.filter.sources or {}
  cfg.filter.rules = cfg.filter.rules or {}
  cfg.filter.users = cfg.filter.users or {}
  cfg.filter.userlists = cfg.filter.userlists or cfg.filter.users or {}
  cfg.filter.users = cfg.filter.users or cfg.filter.userlists or {}
  cfg.auth = cfg.auth or {}
  cfg.auth.sni_verdict = cfg.auth.sni_verdict or {}
  defaults = DEFAULTS
  decision_defaults = defaults.filter and defaults.filter.decision or {}
  ttl_defaults = defaults.dns and defaults.dns.ttl_grace or {}
  auth_defaults = defaults.auth or {}
  sni_defaults = auth_defaults.sni_verdict or {}

  cfg.doh.enabled = coerce_boolean cfg.doh.enabled
  cfg.doh.prefer_ipv6 = coerce_boolean cfg.doh.prefer_ipv6
  cfg.runtime.benchmark = coerce_boolean cfg.runtime.benchmark

  if cfg.filter.decision.first_match_wins == nil
    cfg.filter.decision.first_match_wins = decision_defaults.first_match_wins
  else
    cfg.filter.decision.first_match_wins = coerce_boolean cfg.filter.decision.first_match_wins

  if cfg.filter.decision.continue_to_next_rule == nil
    cfg.filter.decision.continue_to_next_rule = decision_defaults.continue_to_next_rule
  else
    cfg.filter.decision.continue_to_next_rule = coerce_boolean cfg.filter.decision.continue_to_next_rule

  cfg.filter.allow_localnets = coerce_boolean cfg.filter.allow_localnets

  ttl = cfg.dns.ttl_grace
  ttl.grace = tonumber(ttl.grace) or ttl_defaults.grace
  ttl.min = tonumber(ttl.min) or ttl_defaults.min
  ttl.max = tonumber(ttl.max) or ttl_defaults.max

  cfg.auth.port = tonumber(cfg.auth.port) or auth_defaults.port
  cfg.auth.captive_port = tonumber(cfg.auth.captive_port) or auth_defaults.captive_port
  cfg.auth.session_ttl = tonumber(cfg.auth.session_ttl) or auth_defaults.session_ttl
  cfg.auth.heartbeat_interval = tonumber(cfg.auth.heartbeat_interval) or auth_defaults.heartbeat_interval
  cfg.auth.idle_timeout = tonumber(cfg.auth.idle_timeout) or auth_defaults.idle_timeout
  if cfg.auth.sni_verdict.enabled == nil
    cfg.auth.sni_verdict.enabled = sni_defaults.enabled
  else
    cfg.auth.sni_verdict.enabled = coerce_boolean cfg.auth.sni_verdict.enabled
  cfg.auth.sni_verdict.mode = cfg.auth.sni_verdict.mode or sni_defaults.mode
  cfg.auth.sni_verdict.protocols = cfg.auth.sni_verdict.protocols or sni_defaults.protocols
  cfg.auth.sni_verdict.nft_failure_policy = cfg.auth.sni_verdict.nft_failure_policy or sni_defaults.nft_failure_policy

  cfg

load_external_config = (path) ->
  moon_base = require "moonscript.base"
  chunk, load_err = moon_base.loadfile path
  return nil, load_err unless chunk

  ok, custom = pcall chunk
  return nil, custom unless ok
  return nil, "config file must return a table" unless type(custom) == "table"
  custom, nil

build = ->
  cfg = clone DEFAULTS
  env_path = os.getenv "CUSTOS_CONFIG_PATH"
  require_external = os.getenv "CUSTOS_REQUIRE_EXTERNAL_CONFIG"
  require_external = require_external == "1" or require_external == "true"
  path = env_path or DEFAULT_CONFIG_PATH

  custom, err = load_external_config path
  load_err = nil
  if custom
    merge_into cfg, custom
  else
    load_err = tostring err if err
    if require_external
      error "config: required external config failed to load #{path}: #{load_err or 'unknown error'}"
    if err and not tostring(err)\match "No such file"
      io.stderr\write "config: failed to load #{path}: #{tostring(err)}\n"

  normalize cfg
  cfg.__meta = {
    path: path
    env_path: env_path
    external_loaded: custom ~= nil
    load_error: load_err
  }
  cfg

build!
