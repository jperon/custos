local DEFAULT_CONFIG_PATH = "/etc/custos/config.moon"
local CAPTIVE_PROBES = {
  "connectivitycheck.gstatic.com",
  "connectivitycheck.android.com",
  "connectivitycheck.google.com",
  "clients3.google.com",
  "captive.apple.com",
  "msftconnecttest.com",
  "msftncsi.com",
  "detectportal.firefox.com",
  "connectivity-check.ubuntu.com",
  "networkcheck.kde.org"
}
local YOUTUBE_TARGETS = {
  strict = "restrict.youtube.com",
  moderate = "restrictmoderate.youtube.com"
}
local SAFE_SEARCH_GROUPS = {
  {
    name = "Google",
    target = "forcesafesearch.google.com",
    domains = {
      "google.com",
      "google.ac",
      "google.ad",
      "google.ae",
      "google.al",
      "google.am",
      "google.as",
      "google.at",
      "google.az",
      "google.ba",
      "google.be",
      "google.bf",
      "google.bg",
      "google.bi",
      "google.bj",
      "google.bs",
      "google.bt",
      "google.by",
      "google.ca",
      "google.cat",
      "google.cd",
      "google.cf",
      "google.cg",
      "google.ch",
      "google.ci",
      "google.cl",
      "google.cm",
      "google.cn",
      "google.co.ao",
      "google.co.bw",
      "google.co.ck",
      "google.co.cr",
      "google.co.id",
      "google.co.il",
      "google.co.in",
      "google.co.jp",
      "google.co.ke",
      "google.co.kr",
      "google.co.ls",
      "google.co.ma",
      "google.co.mz",
      "google.co.nz",
      "google.co.th",
      "google.co.tz",
      "google.co.ug",
      "google.co.uk",
      "google.co.uz",
      "google.co.ve",
      "google.co.vi",
      "google.co.za",
      "google.co.zm",
      "google.co.zw",
      "google.com.af",
      "google.com.ag",
      "google.com.ai",
      "google.com.ar",
      "google.com.au",
      "google.com.bd",
      "google.com.bh",
      "google.com.bn",
      "google.com.bo",
      "google.com.br",
      "google.com.bz",
      "google.com.co",
      "google.com.cu",
      "google.com.cy",
      "google.com.do",
      "google.com.ec",
      "google.com.eg",
      "google.com.et",
      "google.com.fj",
      "google.com.gh",
      "google.com.gi",
      "google.com.gt",
      "google.com.hk",
      "google.com.jm",
      "google.com.kh",
      "google.com.kw",
      "google.com.lb",
      "google.com.ly",
      "google.com.mm",
      "google.com.mt",
      "google.com.mx",
      "google.com.my",
      "google.com.na",
      "google.com.nf",
      "google.com.ng",
      "google.com.ni",
      "google.com.np",
      "google.com.om",
      "google.com.pa",
      "google.com.pe",
      "google.com.pg",
      "google.com.ph",
      "google.com.pk",
      "google.com.pr",
      "google.com.py",
      "google.com.qa",
      "google.com.sa",
      "google.com.sb",
      "google.com.sg",
      "google.com.sl",
      "google.com.sv",
      "google.com.tj",
      "google.com.tr",
      "google.com.tw",
      "google.com.ua",
      "google.com.uy",
      "google.com.vc",
      "google.com.vn",
      "google.cv",
      "google.cz",
      "google.de",
      "google.dj",
      "google.dk",
      "google.dm",
      "google.dz",
      "google.ee",
      "google.es",
      "google.fi",
      "google.fm",
      "google.fr",
      "google.ga",
      "google.ge",
      "google.gg",
      "google.gl",
      "google.gm",
      "google.gp",
      "google.gr",
      "google.gy",
      "google.hn",
      "google.hr",
      "google.ht",
      "google.hu",
      "google.ie",
      "google.im",
      "google.iq",
      "google.is",
      "google.it",
      "google.je",
      "google.jo",
      "google.kg",
      "google.ki",
      "google.kz",
      "google.la",
      "google.li",
      "google.lk",
      "google.lt",
      "google.lu",
      "google.lv",
      "google.md",
      "google.me",
      "google.mg",
      "google.mk",
      "google.ml",
      "google.mn",
      "google.ms",
      "google.mu",
      "google.mv",
      "google.mw",
      "google.ne",
      "google.nl",
      "google.no",
      "google.nr",
      "google.nu",
      "google.pl",
      "google.pn",
      "google.ps",
      "google.pt",
      "google.ro",
      "google.rs",
      "google.ru",
      "google.rw",
      "google.sc",
      "google.se",
      "google.sh",
      "google.si",
      "google.sk",
      "google.sm",
      "google.sn",
      "google.so",
      "google.sr",
      "google.st",
      "google.td",
      "google.tg",
      "google.tk",
      "google.tl",
      "google.tm",
      "google.tn",
      "google.to",
      "google.tt",
      "google.vg",
      "google.vu",
      "google.ws"
    }
  },
  {
    name = "YouTube",
    youtube = true,
    domains = {
      "youtube.com",
      "youtube-nocookie.com",
      "youtubei.googleapis.com",
      "youtube.googleapis.com"
    }
  },
  {
    name = "Bing",
    target = "strict.bing.com",
    domains = {
      "bing.com"
    }
  },
  {
    name = "DuckDuckGo",
    target = "safe.duckduckgo.com",
    domains = {
      "duckduckgo.com"
    }
  }
}
local build_safesearch_rules
build_safesearch_rules = function(youtube_restrict)
  local rules = { }
  for _index_0 = 1, #SAFE_SEARCH_GROUPS do
    local _continue_0 = false
    repeat
      local group = SAFE_SEARCH_GROUPS[_index_0]
      local target = group.target
      if group.youtube then
        if not (youtube_restrict == "strict" or youtube_restrict == "moderate") then
          _continue_0 = true
          break
        end
        target = YOUTUBE_TARGETS[youtube_restrict]
      end
      local names = { }
      local _list_0 = group.domains
      for _index_1 = 1, #_list_0 do
        local d = _list_0[_index_1]
        names[d] = true
        names["www." .. tostring(d)] = true
        names["images." .. tostring(d)] = true
        names["m." .. tostring(d)] = true
      end
      rules[#rules + 1] = {
        description = "SafeSearch " .. tostring(group.name),
        actions = {
          "cname"
        },
        conditions = {
          to_domains = group.domains
        },
        cname = target,
        cname_names = names
      }
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return rules
end
local DEFAULTS = {
  runtime = {
    log_level = "INFO",
    benchmark = false,
    gc_pause = 110,
    gc_stepmul = 400
  },
  nfqueue = {
    questions = "0-1",
    responses = "4",
    captive = "20",
    reject = "10-11",
    auth = "5",
    sni = "6",
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
    ip_timeout = "2m",
    sip_session_ttl = "5m",
    add_backoff_ms = {
      20,
      50,
      200,
      400,
      800,
      2000
    },
    add_failure_policy = "fail-closed",
    ack_timeout_ms = 150,
    extra_rules = { }
  },
  ipc = {
    pending_ttl = 5,
    match_retry = {
      count = 5,
      sleep_ms = 20
    }
  },
  clients = {
    expiry = 300
  },
  second_opinion = {
    resolvers = {
      "https://dns-doh-no-youtube-safe-search.dnsforfamily.com/dns-query",
      "2a01:4f9:c010:969d::1",
      "2a01:4f8:1c0c:40db::1",
      "2a01:4f8:1c17:4df8::1",
      "167.235.236.107",
      "94.130.180.225",
      "78.47.64.161"
    },
    budget_ms = 80,
    doh_budget_ms = 3000,
    fail_open = true
  },
  mac_learner = {
    query_sock = "/var/run/custos/mac_query.sock",
    entry_ttl = 900
  },
  auth = {
    host = "::",
    port = 33443,
    captive_port = 33080,
    session_ttl = 0,
    heartbeat_interval = 30,
    idle_timeout = 120,
    token_grace_period = 180,
    secrets = "/etc/custos/secrets",
    sessions_file = "/tmp/sessions.lua",
    admin_users = { },
    admin_allow_all_when_empty = true
  },
  sni = {
    enabled = true,
    mode = "strict-443",
    placement = "residual",
    protocols = "both",
    nft_failure_policy = "fail-closed"
  },
  doh = {
    enabled = true,
    port = 8443,
    upstream_ipv4 = "1.1.1.3",
    upstream_ipv6 = "2606:4700:4700::1113",
    upstream_port = 53,
    upstream_timeout_ms = 2000,
    cert = nil,
    key = nil,
    prefer_ipv6 = true,
    upstream_doh_url = nil,
    upstream_doh_tls_verify = false
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
  rtp = {
    excluded_ports = {
      5060
    }
  },
  filter = {
    domainlists_dir = "/tmp/custos/lists",
    custom_lists_dir = nil,
    allow_localnets = false,
    captive_portal = true,
    safe_search = true,
    youtube_restrict = "moderate",
    nets = { },
    macs = { },
    times = { },
    sources = { },
    users = { },
    userlists = { },
    rules = { },
    default_rules = {
      {
        description = "Désactivation DoH (domaine canari Firefox)",
        actions = {
          "nxdomain"
        },
        conditions = {
          to_domain = "use-application-dns.net"
        }
      },
      {
        captive = true,
        description = "Les utilisateurs authentifiés ne sont pas redirigés vers le portail captif",
        actions = {
          "allow"
        },
        conditions = {
          from_user = "_any",
          to_domains = CAPTIVE_PROBES
        }
      },
      {
        captive = true,
        description = "Détection de portail captif (sondes OS/navigateurs : NCSI/MSFT, Apple, Google…)",
        actions = {
          "dnsonly"
        },
        conditions = {
          to_domains = CAPTIVE_PROBES
        }
      }
    },
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
local detect_bridge_ifname
detect_bridge_ifname = function()
  local env = os.getenv("BRIDGE_IFNAME")
  if env then
    return env
  end
  local handle = io.popen("ip -brief link show type bridge 2>/dev/null")
  if not (handle) then
    return "br0"
  end
  local line = handle:read("*l")
  handle:close()
  return (line and line:match("^(%S+)")) or "br0"
end
local is_array
is_array = function(t)
  if not (type(t) == "table") then
    return false
  end
  local n = #t
  if n == 0 then
    return next(t) == nil
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
  cfg.filter.default_rules = cfg.filter.default_rules or { }
  if cfg.filter.captive_portal == nil then
    cfg.filter.captive_portal = DEFAULTS.filter.captive_portal
  else
    cfg.filter.captive_portal = coerce_boolean(cfg.filter.captive_portal)
  end
  local filtered = { }
  for _, r in ipairs(cfg.filter.default_rules) do
    local _continue_0 = false
    repeat
      if r.captive then
        r.captive = nil
        if not (cfg.filter.captive_portal) then
          _continue_0 = true
          break
        end
      end
      filtered[#filtered + 1] = r
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  cfg.filter.default_rules = filtered
  if cfg.filter.safe_search == nil then
    cfg.filter.safe_search = DEFAULTS.filter.safe_search
  else
    cfg.filter.safe_search = coerce_boolean(cfg.filter.safe_search)
  end
  local yr = cfg.filter.youtube_restrict
  if yr == nil then
    yr = DEFAULTS.filter.youtube_restrict
  end
  if yr == false or yr == "false" or yr == "0" then
    yr = false
  end
  cfg.filter.youtube_restrict = yr
  if cfg.filter.safe_search then
    local _list_0 = build_safesearch_rules(yr)
    for _index_0 = 1, #_list_0 do
      local r = _list_0[_index_0]
      cfg.filter.default_rules[#cfg.filter.default_rules + 1] = r
    end
  end
  if #cfg.filter.default_rules > 0 then
    local merged = { }
    for _, r in ipairs(cfg.filter.default_rules) do
      merged[#merged + 1] = r
    end
    for _, r in ipairs(cfg.filter.rules) do
      merged[#merged + 1] = r
    end
    cfg.filter.rules = merged
  end
  cfg.filter.users = cfg.filter.users or { }
  cfg.filter.userlists = cfg.filter.userlists or cfg.filter.users or { }
  cfg.filter.users = cfg.filter.users or cfg.filter.userlists or { }
  cfg.auth = cfg.auth or { }
  cfg.auth.bridge_ifname = cfg.auth.bridge_ifname or detect_bridge_ifname()
  cfg.sni = cfg.sni or { }
  local defaults = DEFAULTS
  local decision_defaults = defaults.filter and defaults.filter.decision or { }
  local ttl_defaults = defaults.dns and defaults.dns.ttl_grace or { }
  local auth_defaults = defaults.auth or { }
  local sni_defaults = defaults.sni or { }
  cfg.doh.enabled = coerce_boolean(cfg.doh.enabled)
  cfg.doh.prefer_ipv6 = coerce_boolean(cfg.doh.prefer_ipv6)
  cfg.runtime.benchmark = coerce_boolean(cfg.runtime.benchmark)
  local runtime_defaults = defaults.runtime or { }
  cfg.runtime.gc_pause = tonumber(cfg.runtime.gc_pause) or runtime_defaults.gc_pause
  cfg.runtime.gc_stepmul = tonumber(cfg.runtime.gc_stepmul) or runtime_defaults.gc_stepmul
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
  cfg.auth.admin_users = cfg.auth.admin_users or auth_defaults.admin_users or { }
  if cfg.auth.admin_allow_all_when_empty == nil then
    cfg.auth.admin_allow_all_when_empty = auth_defaults.admin_allow_all_when_empty or true
  else
    cfg.auth.admin_allow_all_when_empty = coerce_boolean(cfg.auth.admin_allow_all_when_empty)
  end
  cfg.auth.port = tonumber(cfg.auth.port) or auth_defaults.port
  cfg.auth.captive_port = tonumber(cfg.auth.captive_port) or auth_defaults.captive_port
  cfg.auth.session_ttl = tonumber(cfg.auth.session_ttl) or auth_defaults.session_ttl
  cfg.auth.heartbeat_interval = tonumber(cfg.auth.heartbeat_interval) or auth_defaults.heartbeat_interval
  cfg.auth.idle_timeout = tonumber(cfg.auth.idle_timeout) or auth_defaults.idle_timeout
  cfg.auth.token_grace_period = tonumber(cfg.auth.token_grace_period) or auth_defaults.token_grace_period
  if cfg.sni.enabled == nil then
    cfg.sni.enabled = sni_defaults.enabled
  else
    cfg.sni.enabled = coerce_boolean(cfg.sni.enabled)
  end
  cfg.sni.mode = cfg.sni.mode or sni_defaults.mode
  cfg.sni.placement = cfg.sni.placement or sni_defaults.placement
  if not (cfg.sni.placement == "integral" or cfg.sni.placement == "residual") then
    cfg.sni.placement = sni_defaults.placement
  end
  cfg.sni.protocols = cfg.sni.protocols or sni_defaults.protocols
  cfg.sni.nft_failure_policy = cfg.sni.nft_failure_policy or sni_defaults.nft_failure_policy
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
