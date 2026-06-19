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

-- Domaines de sondes de connectivité (captive portal) des OS et navigateurs.
-- Partagés par les règles par défaut « allow (authentifié) » et « dnsonly ».
-- Le match par suffixe couvre les sous-domaines (ex. msftncsi.com couvre
-- dns.msftncsi.com et www.msftncsi.com ; msftconnecttest.com couvre www. et
-- ipv6.msftconnecttest.com). Couverture NCSI/MSFT complète : sonde DNS
-- (dns.msftncsi.com → 131.107.255.255, réponse upstream non altérée par dnsonly)
-- et sonde HTTP active (www.msftconnecttest.com).
CAPTIVE_PROBES = {
  "connectivitycheck.gstatic.com"
  "connectivitycheck.android.com"
  "connectivitycheck.google.com"
  "clients3.google.com"
  "captive.apple.com"
  "msftconnecttest.com"
  "msftncsi.com"
  "detectportal.firefox.com"
  "connectivity-check.ubuntu.com"
  "networkcheck.kde.org"
}

-- SafeSearch : groupes (moteur → variante « safe ») pour la réécriture CNAME.
-- Le match `to_domains` couvre chaque domaine ET ses sous-domaines (suffix
-- match, cf. to_domain.moon) : seuls les domaines enregistrables sont listés
-- (ex. google.com couvre www.google.com). Auto-suffisant (aucune liste externe).
YOUTUBE_TARGETS = {
  strict:   "restrict.youtube.com"
  moderate: "restrictmoderate.youtube.com"
}
SAFE_SEARCH_GROUPS = {
  {
    name:   "Google"
    target: "forcesafesearch.google.com"
    -- google.com + ccTLDs nationaux (liste standard SafeSearch).
    domains: {
      "google.com", "google.ac", "google.ad", "google.ae", "google.al",
      "google.am", "google.as", "google.at", "google.az", "google.ba",
      "google.be", "google.bf", "google.bg", "google.bi", "google.bj",
      "google.bs", "google.bt", "google.by", "google.ca", "google.cat",
      "google.cd", "google.cf", "google.cg", "google.ch", "google.ci",
      "google.cl", "google.cm", "google.cn", "google.co.ao", "google.co.bw",
      "google.co.ck", "google.co.cr", "google.co.id", "google.co.il",
      "google.co.in", "google.co.jp", "google.co.ke", "google.co.kr",
      "google.co.ls", "google.co.ma", "google.co.mz", "google.co.nz",
      "google.co.th", "google.co.tz", "google.co.ug", "google.co.uk",
      "google.co.uz", "google.co.ve", "google.co.vi", "google.co.za",
      "google.co.zm", "google.co.zw", "google.com.af", "google.com.ag",
      "google.com.ai", "google.com.ar", "google.com.au", "google.com.bd",
      "google.com.bh", "google.com.bn", "google.com.bo", "google.com.br",
      "google.com.bz", "google.com.co", "google.com.cu", "google.com.cy",
      "google.com.do", "google.com.ec", "google.com.eg", "google.com.et",
      "google.com.fj", "google.com.gh", "google.com.gi", "google.com.gt",
      "google.com.hk", "google.com.jm", "google.com.kh", "google.com.kw",
      "google.com.lb", "google.com.ly", "google.com.mm", "google.com.mt",
      "google.com.mx", "google.com.my", "google.com.na", "google.com.nf",
      "google.com.ng", "google.com.ni", "google.com.np", "google.com.om",
      "google.com.pa", "google.com.pe", "google.com.pg", "google.com.ph",
      "google.com.pk", "google.com.pr", "google.com.py", "google.com.qa",
      "google.com.sa", "google.com.sb", "google.com.sg", "google.com.sl",
      "google.com.sv", "google.com.tj", "google.com.tr", "google.com.tw",
      "google.com.ua", "google.com.uy", "google.com.vc", "google.com.vn",
      "google.cv", "google.cz", "google.de", "google.dj", "google.dk",
      "google.dm", "google.dz", "google.ee", "google.es", "google.fi",
      "google.fm", "google.fr", "google.ga", "google.ge", "google.gg",
      "google.gl", "google.gm", "google.gp", "google.gr", "google.gy",
      "google.hn", "google.hr", "google.ht", "google.hu", "google.ie",
      "google.im", "google.iq", "google.is", "google.it", "google.je",
      "google.jo", "google.kg", "google.ki", "google.kz", "google.la",
      "google.li", "google.lk", "google.lt", "google.lu", "google.lv",
      "google.md", "google.me", "google.mg", "google.mk", "google.ml",
      "google.mn", "google.ms", "google.mu", "google.mv", "google.mw",
      "google.ne", "google.nl", "google.no", "google.nr", "google.nu",
      "google.pl", "google.pn", "google.ps", "google.pt", "google.ro",
      "google.rs", "google.ru", "google.rw", "google.sc", "google.se",
      "google.sh", "google.si", "google.sk", "google.sm", "google.sn",
      "google.so", "google.sr", "google.st", "google.td", "google.tg",
      "google.tk", "google.tl", "google.tm", "google.tn", "google.to",
      "google.tt", "google.vg", "google.vu", "google.ws"
    }
  }
  {
    name:    "YouTube"
    youtube: true
    domains: {
      "youtube.com", "youtube-nocookie.com",
      "youtubei.googleapis.com", "youtube.googleapis.com"
    }
  }
  {
    name:    "Bing"
    target:  "strict.bing.com"
    domains: { "bing.com" }
  }
  {
    name:    "DuckDuckGo"
    target:  "safe.duckduckgo.com"
    domains: { "duckduckgo.com" }
  }
}

-- Construit les règles cname SafeSearch selon le mode YouTube demandé.
-- @tparam string|boolean youtube_restrict "strict" | "moderate" | false
-- @treturn table Liste de règles { description, actions, conditions, cname }.
build_safesearch_rules = (youtube_restrict) ->
  rules = {}
  for group in *SAFE_SEARCH_GROUPS
    target = group.target
    if group.youtube
      continue unless youtube_restrict == "strict" or youtube_restrict == "moderate"
      target = YOUTUBE_TARGETS[youtube_restrict]
    -- Hôtes éligibles à la réécriture CNAME : le domaine enregistrable lui-même
    -- et ses préfixes de recherche habituels (`www.`, `m.`). La condition
    -- `to_domains` matche par suffixe (donc aussi mail.google.com…), mais seuls
    -- ces noms exacts doivent être réécrits — les autres sous-domaines sont
    -- laissés intacts (cf. filter.actions.cname `cname_names`).
    names = {}
    for d in *group.domains
      names[d] = true
      names["www.#{d}"] = true
      names["images.#{d}"] = true
      names["m.#{d}"] = true
    rules[#rules + 1] = {
      description: "SafeSearch #{group.name}"
      actions:     { "cname" }
      conditions:  { to_domains: group.domains }
      cname:       target
      cname_names: names
    }
  rules

DEFAULTS = {
  runtime: {
    log_level: "INFO"
    benchmark: false
    -- Réglage GC LuaJIT (machines à faible RAM). gc_pause=110 collecte dès
    -- +10 % du tas (défaut LuaJIT 200) ; gc_stepmul=400 fait des pas de GC
    -- plus gros. Voir doc/CONFIG.md.
    gc_pause: 110
    gc_stepmul: 400
  }

  nfqueue: {
    questions: "0-1"
    responses: "4"
    captive: "20"
    reject: "10-11"
    auth: "5"
    sni: "6"
    sip: "12"
    doh_vlan: "13"
  }

  dns: {
    port: 53
    ttl_grace: {
      grace: 600
      min: 60
      max: 2592000
    }
    -- Retry upstream : quand le résolveur renvoie une réponse transitoirement en
    -- échec (SERVFAIL/REFUSED, sans enregistrement), worker_responses ne la
    -- transmet pas au client mais ré-interroge LE MÊME résolveur (requête
    -- dupliquée, src client spoofée) jusqu'à `max_attempts` fois. Évite les
    -- « connexion refusée puis OK au rafraîchissement » dus à un upstream
    -- instable (ex. dynv6). La transaction en attente reste vivante entre essais.
    upstream_retry: {
      enabled:      true
      max_attempts: 2
      rcodes:       { 2, 3, 5 }   -- SERVFAIL, NXDOMAIN, REFUSED (rcodes transitoires)
      -- NXDOMAIN : par défaut on retente tout NXDOMAIN (couvre 1re visite + noms
      -- flaky). Un nom dont MÊME le retry reste NXDOMAIN (genre wpad.lan) est
      -- mémorisé `nxdomain_bad_ttl` secondes pour ne plus gaspiller de retry.
      nxdomain_bad_ttl: 60       -- durée de suppression du retry (s)
      nxdomain_bad_max: 4096     -- taille max du cache de noms « durablement NXDOMAIN »
    }
  }

  nft: {
    family: "bridge"
    family6: "bridge"
    table: "dns-filter-bridge"
    ip_timeout: "2m"
    sip_session_ttl: "5m"
    add_backoff_ms: {20, 50, 200, 400, 800, 2000}
    add_failure_policy: "fail-closed"
    ack_timeout_ms: 150
    extra_rules: {}
  }

  ipc: {
    pending_ttl: 5
    match_retry: {
      count: 5
      sleep_ms: 20
    }
  }

  clients: {
    expiry: 300
  }

  -- Second avis DNS : duplication de chaque question autorisée vers un résolveur
  -- de filtrage (ex. DNSforFamily). worker_responses corrèle les deux réponses
  -- et, si le validateur signale NXDOMAIN (blocage) ou CNAME (réorientation),
  -- spoofe la réponse d'origine. Voir doc/CONFIG.md § second_opinion.
  second_opinion: {
    -- Liste d'IP, v4 et v6 mélangées : la famille du validateur est choisie
    -- selon celle du paquet client (présence de ':' → IPv6).
    -- Activé uniquement pour les règles portant l'action `validate`.
    resolvers: {
      "https://dns-doh-no-youtube-safe-search.dnsforfamily.com/dns-query"  -- DNSforFamily DoH, SafeSearch sans restriction YouTube
      "2a01:4f9:c010:969d::1"  -- DNSforFamily, avec SafeSearch mais pas youtube-rescrict
      "2a01:4f8:1c0c:40db::1"  -- DNSforFamily
      "2a01:4f8:1c17:4df8::1"  -- DNSforFamily
      "167.235.236.107"        -- DNSforFamily, avec SafeSearch mais pas youtube-rescrict
      "94.130.180.225"         -- DNSforFamily
      "78.47.64.161"           -- DNSforFamily
    }
    -- La question dupliquée est émise via un socket RAW routé par le noyau
    -- (src = IP client spoofée) : pas besoin de connaître la MAC de passerelle,
    -- et un IPv6 routé par tunnel est géré nativement. Une famille n'est activée
    -- que si un validateur de cette famille est routable.
    budget_ms: 80        -- attente max de la réponse validateur (UDP) avant fail-open
    doh_budget_ms: 3000  -- attente max pour les endpoints DoH https:// (TLS + HTTP/2)
    fail_open: true      -- pas de réponse validateur à temps → relâcher A intacte
  }

  mac_learner: {
    query_sock: "/var/run/custos/mac_query.sock"
    entry_ttl: 900
  }

  auth: {
    host: "::"
    port: 33443
    captive_port: 33080
    session_ttl: 0
    heartbeat_interval: 30
    idle_timeout: 300
    challenge_ttl: 120
    allow_plaintext_login: true
    secrets: "/etc/custos/secrets"
    sessions_file: "/tmp/sessions.lua"
    admin_users: {}
    admin_allow_all_when_empty: true
  }

  sni: {
    enabled: true
    mode: "strict-443"
    placement: "residual"
    protocols: "both"
    nft_failure_policy: "fail-closed"
  }

  doh: {
    enabled: true
    port: 8443
    upstream_ipv4: "1.1.1.3"
    upstream_ipv6: "2606:4700:4700::1113"
    upstream_port: 53
    upstream_timeout_ms: 2000
    cert: nil
    key: nil
    prefer_ipv6: true
    -- Transport DoH vers l'upstream (opt-in). nil = UDP/53 (comportement par défaut).
    -- Exemple : "https://1.1.1.1/dns-query"
    upstream_doh_url: nil        -- "https://host/dns-query" → transport DoH via libcurl (opt-in)
    upstream_doh_tls_verify: true
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
    domainlists_dir: "/tmp/custos/lists"
    custom_lists_dir: nil
    allow_localnets: false
    -- Active les règles par défaut de détection de portail captif (sondes
    -- NCSI/MSFT, Apple, Google…). false → ces règles ne sont pas injectées
    -- (le canari DoH Firefox reste indépendant). Cf. CAPTIVE_PROBES.
    captive_portal: true
    -- Active SafeSearch (réécriture CNAME des moteurs vers leur variante
    -- « safe » : Google/YouTube/Bing/DuckDuckGo). Cf. SAFE_SEARCH_GROUPS.
    safe_search: true
    -- Mode YouTube Restricted : "strict" | "moderate" | false (désactivé).
    youtube_restrict: "moderate"
    nets: {}
    macs: {}
    times: {}
    sources: {}
    users: {}
    userlists: {}
    rules: {}
    default_rules: {
      {
        description: "Désactivation DoH (domaine canari Firefox)"
        actions: {"nxdomain"}
        conditions: { to_domain: "use-application-dns.net" }
      }
      {
        -- captive: marqueur interne (retiré par normalize) ; gated par filter.captive_portal
        captive: true
        description: "Les utilisateurs authentifiés ne sont pas redirigés vers le portail captif"
        actions: {"allow"}
        conditions: { from_user: "_any", to_domains: CAPTIVE_PROBES }
      }
      {
        captive: true
        description: "Détection de portail captif (sondes OS/navigateurs : NCSI/MSFT, Apple, Google…)"
        actions: {"dnsonly"}
        conditions: { to_domains: CAPTIVE_PROBES }
      }
    }
    dest_whitelist: {}
    allowed_domains: { "local", "lan", "home.arpa" }
    decision: {
      first_match_wins: true
      continue_to_next_rule: false
    }
  }
}

-- Détecte la première interface bridge du système.
-- Priorité : variable d'env BRIDGE_IFNAME → ip link → "br0".
detect_bridge_ifname = ->
  env = os.getenv "BRIDGE_IFNAME"
  return env if env
  handle = io.popen "ip -brief link show type bridge 2>/dev/null"
  return "br0" unless handle
  line = handle\read "*l"
  handle\close!
  (line and line\match "^(%S+)") or "br0"

is_array = (t) ->
  return false unless type(t) == "table"
  n = #t
  if n == 0
    -- {} vide est un tableau (remplaçable) ; { key: val } est un dict (fusionnable).
    return next(t) == nil
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
  cfg.filter.default_rules = cfg.filter.default_rules or {}
  -- Gate des règles captives par défaut (marqueur interne `captive`) selon
  -- filter.captive_portal (défaut true). Le marqueur est toujours retiré pour
  -- ne pas fuiter dans les règles compilées.
  if cfg.filter.captive_portal == nil
    cfg.filter.captive_portal = DEFAULTS.filter.captive_portal
  else
    cfg.filter.captive_portal = coerce_boolean cfg.filter.captive_portal
  filtered = {}
  for _, r in ipairs cfg.filter.default_rules
    if r.captive
      r.captive = nil
      continue unless cfg.filter.captive_portal
    filtered[#filtered + 1] = r
  cfg.filter.default_rules = filtered
  -- SafeSearch : génère les règles cname (réécriture vers les variantes safe).
  -- Gating mirroir de captive_portal ; youtube_restrict choisit la cible YouTube.
  if cfg.filter.safe_search == nil
    cfg.filter.safe_search = DEFAULTS.filter.safe_search
  else
    cfg.filter.safe_search = coerce_boolean cfg.filter.safe_search
  yr = cfg.filter.youtube_restrict
  yr = DEFAULTS.filter.youtube_restrict if yr == nil
  yr = false if yr == false or yr == "false" or yr == "0"
  cfg.filter.youtube_restrict = yr
  if cfg.filter.safe_search
    for r in *build_safesearch_rules yr
      cfg.filter.default_rules[#cfg.filter.default_rules + 1] = r
  if #cfg.filter.default_rules > 0
    merged = {}
    for _, r in ipairs cfg.filter.default_rules
      merged[#merged + 1] = r
    for _, r in ipairs cfg.filter.rules
      merged[#merged + 1] = r
    cfg.filter.rules = merged
  cfg.filter.users = cfg.filter.users or {}
  cfg.filter.userlists = cfg.filter.userlists or cfg.filter.users or {}
  cfg.filter.users = cfg.filter.users or cfg.filter.userlists or {}
  cfg.auth = cfg.auth or {}
  cfg.auth.bridge_ifname = cfg.auth.bridge_ifname or detect_bridge_ifname!
  cfg.sni  = cfg.sni  or {}
  defaults = DEFAULTS
  decision_defaults = defaults.filter and defaults.filter.decision or {}
  ttl_defaults = defaults.dns and defaults.dns.ttl_grace or {}
  auth_defaults = defaults.auth or {}
  sni_defaults = defaults.sni or {}

  cfg.doh.enabled = coerce_boolean cfg.doh.enabled
  cfg.doh.prefer_ipv6 = coerce_boolean cfg.doh.prefer_ipv6
  -- Vérification du certificat TLS du résolveur DoH amont : sécurisée par défaut
  -- (true). Ne désactiver explicitement que pour un résolveur de confiance hors
  -- chaîne PKI (le worker DoH loggue alors un avertissement).
  cfg.doh.upstream_doh_tls_verify = if cfg.doh.upstream_doh_tls_verify == nil
    true
  else
    coerce_boolean cfg.doh.upstream_doh_tls_verify
  cfg.runtime.benchmark = coerce_boolean cfg.runtime.benchmark
  runtime_defaults = defaults.runtime or {}
  cfg.runtime.gc_pause = tonumber(cfg.runtime.gc_pause) or runtime_defaults.gc_pause
  cfg.runtime.gc_stepmul = tonumber(cfg.runtime.gc_stepmul) or runtime_defaults.gc_stepmul

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

  cfg.auth.admin_users = cfg.auth.admin_users or auth_defaults.admin_users or {}
  if cfg.auth.admin_allow_all_when_empty == nil
    cfg.auth.admin_allow_all_when_empty = auth_defaults.admin_allow_all_when_empty or true
  else
    cfg.auth.admin_allow_all_when_empty = coerce_boolean cfg.auth.admin_allow_all_when_empty
  cfg.auth.port = tonumber(cfg.auth.port) or auth_defaults.port
  cfg.auth.captive_port = tonumber(cfg.auth.captive_port) or auth_defaults.captive_port
  cfg.auth.session_ttl = tonumber(cfg.auth.session_ttl) or auth_defaults.session_ttl
  cfg.auth.heartbeat_interval = tonumber(cfg.auth.heartbeat_interval) or auth_defaults.heartbeat_interval
  cfg.auth.idle_timeout = tonumber(cfg.auth.idle_timeout) or auth_defaults.idle_timeout
  cfg.auth.challenge_ttl = tonumber(cfg.auth.challenge_ttl) or auth_defaults.challenge_ttl
  if cfg.auth.allow_plaintext_login == nil
    cfg.auth.allow_plaintext_login = auth_defaults.allow_plaintext_login
  else
    cfg.auth.allow_plaintext_login = coerce_boolean cfg.auth.allow_plaintext_login
  if cfg.sni.enabled == nil
    cfg.sni.enabled = sni_defaults.enabled
  else
    cfg.sni.enabled = coerce_boolean cfg.sni.enabled
  cfg.sni.mode = cfg.sni.mode or sni_defaults.mode
  cfg.sni.placement = cfg.sni.placement or sni_defaults.placement
  unless cfg.sni.placement == "integral" or cfg.sni.placement == "residual"
    cfg.sni.placement = sni_defaults.placement
  cfg.sni.protocols = cfg.sni.protocols or sni_defaults.protocols
  cfg.sni.nft_failure_policy = cfg.sni.nft_failure_policy or sni_defaults.nft_failure_policy

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
