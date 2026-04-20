-- src/uci_config.moon
-- Préprocesseur UCI → génère /var/run/custos/config.lua avant le démarrage.
--
-- Lit /etc/config/custos via la commande `uci` et produit un fichier
-- config.lua complet dans OUTPUT_DIR. En cas d'absence de valeur UCI
-- ou d'erreur, les valeurs par défaut s'appliquent.
-- L'écriture est atomique (rename(2) sur le même filesystem tmpfs).
--
-- Usage (appelé par /etc/init.d/custos) :
--   luajit /usr/share/custos/uci_config.lua

UCI_PKG    = "custos"
UCI_SEC    = "main"
OUTPUT_DIR = "/var/run/custos"

-- ── Valeurs par défaut ────────────────────────────────────────────
-- Reflètent les constantes de config.moon, adaptées à l'environnement OpenWrt.
DEFAULTS = {
  forced_ttl:             60
  nft_ip_timeout:         "2m"
  ipc_pending_ttl:        5
  client_expiry:          300
  neigh_refresh_cooldown: 10
  nft_add_retry_count:    3
  nft_add_backoff_ms:     "20, 50, 100"
  nft_add_failure_policy: "fail-closed"
  ipc_match_retry_enabled: true
  ipc_match_retry_count:  5
  ipc_match_retry_sleep_ms: 20
  allowed_domains: {
    "local", "lan", "home.arpa"
  }
  dest_whitelist:         {}  -- Empty by default, configured via UCI
}

-- ── Lecture UCI ───────────────────────────────────────────────────

--- Lit une option scalaire UCI via `uci get`.
-- Retourne nil si l'option est absente ou si `uci` n'est pas disponible.
-- @tparam string option Nom de l'option UCI
-- @treturn string|nil Valeur brute ou nil
uci_get = (option) ->
  fh = io.popen "uci get #{UCI_PKG}.#{UCI_SEC}.#{option} 2>/dev/null"
  return nil unless fh
  val = fh\read "*l"
  fh\close!
  val if val and val ~= ""

--- Lit une option liste UCI via `uci show`.
-- Format de sortie `uci show` : custos.main.option='valeur' (une ligne par entrée).
-- Retourne toujours une table (vide si l'option est absente), jamais nil.
-- @tparam string option Nom de l'option UCI
-- @treturn table Liste des valeurs brutes
uci_get_list = (option) ->
  fh = io.popen "uci show #{UCI_PKG}.#{UCI_SEC}.#{option} 2>/dev/null"
  return {} unless fh
  content = fh\read "*a"
  fh\close!
  result = {}
  for val in content\gmatch "'([^']*)'"
    table.insert result, val
  result

-- ── Validation ───────────────────────────────────────────────────

--- Valide un entier strictement positif.
-- @tparam string|nil raw Valeur brute UCI
-- @tparam number default Valeur par défaut
-- @treturn number
validate_posint = (raw, default) ->
  return default unless raw
  n = tonumber raw
  return default unless n and math.floor(n) == n and n > 0
  n

--- Valide le format de timeout nftables (entier suivi d'une unité : ms/s/m/h/d/w).
-- @tparam string|nil raw Valeur brute UCI
-- @tparam string default Valeur par défaut
-- @treturn string
validate_nft_timeout = (raw, default) ->
  return default unless raw
  return raw if raw\match "^%d+%a+$"
  io.stderr\write "uci_config: nft_ip_timeout invalide '#{raw}', utilise '#{default}'\n"
  default

--- Valide un nom de domaine (RFC 1035 : lettres, chiffres, tiret, point).
-- @tparam string d Nom de domaine à valider
-- @treturn string|nil Domaine valide ou nil si invalide
validate_domain = (d) ->
  return nil unless d and #d > 0 and #d <= 253
  return nil if d\match "[^%a%d%.%-]"
  d

--- Valide un booléen UCI (0/1/true/false).
-- @tparam string|nil raw Valeur brute UCI
-- @tparam boolean default Valeur par défaut
-- @treturn boolean
validate_bool = (raw, default) ->
  return default unless raw
  return true if raw == "1" or raw == "true"
  return false if raw == "0" or raw == "false"
  default

--- Valide une adresse IP ou CIDR (IPv4 ou IPv6).
-- @tparam string s Adresse IP ou CIDR à valider
-- @treturn string|nil Adresse valide ou nil si invalide
validate_ip_cidr = (s) ->
  return nil unless s and #s > 0
  s = s\gsub "%s+", ""
  return nil if #s == 0
  -- Validation basique : contient ':' pour IPv6, sinon IPv4
  -- Format CIDR : / suivi d'un nombre
  if s\find ":"
    -- IPv6 : hhhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh ou avec CIDR
    return nil if s\match "[^%x:%./]"  -- caractères invalides (autorise / pour CIDR)
    return nil if s\match ":::"  -- triple double-point invalide
  else
    -- IPv4 : a.b.c.d ou a.b.c.d/n
    return nil if s\match "[^%d%./]"  -- caractères invalides (autorise / pour CIDR)
    -- Split manuel pour /
    parts = {}
    for part in s\gmatch "[^/]+"
      table.insert parts, part
    return nil if #parts > 2
    ip = parts[1]
    return nil unless ip
    -- Split manuel pour .
    octets = {}
    for octet in ip\gmatch "[^.]+"
      table.insert octets, octet
    return nil unless #octets == 4
    for octet in *octets
      n = tonumber octet
      return nil unless n and n >= 0 and n <= 255
    if #parts == 2
      mask = tonumber parts[2]
      return nil unless mask and mask >= 0 and mask <= 32
  s

-- ── Génération Lua ────────────────────────────────────────────────

--- Échappe une chaîne pour inclusion dans un littéral Lua entre guillemets doubles.
-- @tparam string s Chaîne à échapper
-- @treturn string
escape_lua_str = (s) ->
  s\gsub("\\", "\\\\")\gsub('"', '\\"')\gsub("\n", "\\n")

--- Génère le contenu complet de config.lua depuis les valeurs résolues.
-- Reproduit exactement les clés exportées par config.moon, avec les valeurs UCI.
-- @tparam table cfg Configuration résolue
-- @treturn string Contenu Lua valide
generate_config = (cfg) ->
  lines = {
    "-- config.lua — généré par uci_config.lua depuis /etc/config/custos"
    "-- Ne pas modifier : écrasé au démarrage/rechargement du service."
    ""
    "local QUEUE_QUESTIONS        = 0"
    "local QUEUE_RESPONSES        = 1"
    "local QUEUE_CAPTIVE          = 2"
    string.format "local FORCED_TTL             = %d",   cfg.forced_ttl
    string.format 'local NFT_IP_TIMEOUT         = "%s"', cfg.nft_ip_timeout
    string.format "local IPC_PENDING_TTL        = %d",   cfg.ipc_pending_ttl
    string.format "local CLIENT_EXPIRY          = %d",   cfg.client_expiry
    string.format "local NEIGH_REFRESH_COOLDOWN = %d",   cfg.neigh_refresh_cooldown
    string.format "local NFT_ADD_RETRY_COUNT    = %d",   cfg.nft_add_retry_count
    string.format "local NFT_ADD_BACKOFF_MS     = { %s }", cfg.nft_add_backoff_ms
    string.format 'local NFT_ADD_FAILURE_POLICY = "%s"', cfg.nft_add_failure_policy
    string.format "local IPC_MATCH_RETRY_ENABLED = %s", if cfg.ipc_match_retry_enabled then "true" else "false"
    string.format "local IPC_MATCH_RETRY_COUNT  = %d",   cfg.ipc_match_retry_count
    string.format "local IPC_MATCH_RETRY_SLEEP_MS = %d", cfg.ipc_match_retry_sleep_ms
    "local NFT_TABLE              = \"dns-filter-bridge\""
    "local NFT_FAMILY              = \"bridge\""
    "local NFT_FAMILY6             = \"bridge\""
    'local NFT_SET_IP4            = "ip4_allowed"'
    'local NFT_SET_IP6            = "ip6_allowed"'
    'local NFT_SET_MAC4           = "mac4_allowed"'
    'local NFT_SET_MAC6           = "mac6_allowed"'
    string.format 'local NFT_IP_TIMEOUT         = "%s"', cfg.nft_ip_timeout
    "local DNS_PORT               = 53"
    "local AF_INET                = 2"
    "local AF_INET6               = 10"
    "local PROTO_UDP              = 17"
    ""
    "local ALLOWED_DOMAINS = {"
  }
  for d in *cfg.allowed_domains
    table.insert lines, string.format('  "%s",', escape_lua_str d)
  table.insert lines, "}"
  table.insert lines, ""
  table.insert lines, "local DEST_WHITELIST = {"
  for ip in *cfg.dest_whitelist
    table.insert lines, string.format('  "%s",', escape_lua_str ip)
  table.insert lines, "}"
  table.insert lines, ""
  table.insert lines, "local NFT_EXTRA_RULES = {"
  for r in *cfg.nft_extra_rules
    table.insert lines, string.format('  "%s",', escape_lua_str r)
  table.insert lines, "}"
  table.insert lines, ""
  table.insert lines, "return {"
  for k in *{
      "QUEUE_QUESTIONS", "QUEUE_RESPONSES", "QUEUE_CAPTIVE",
      "ALLOWED_DOMAINS", "DEST_WHITELIST", "NFT_TABLE", "NFT_FAMILY", "NFT_FAMILY6",
      "NFT_SET_IP4", "NFT_SET_IP6", "NFT_SET_MAC4", "NFT_SET_MAC6",
      "NFT_IP_TIMEOUT", "NFT_EXTRA_RULES", "IPC_PENDING_TTL", "CLIENT_EXPIRY",
      "NEIGH_REFRESH_COOLDOWN", "FORCED_TTL", "DNS_PORT", "AF_INET",
      "AF_INET6", "PROTO_UDP", "NFT_ADD_RETRY_COUNT", "NFT_ADD_BACKOFF_MS",
      "NFT_ADD_FAILURE_POLICY", "IPC_MATCH_RETRY_ENABLED", "IPC_MATCH_RETRY_COUNT",
      "IPC_MATCH_RETRY_SLEEP_MS"
    }
    table.insert lines, string.format("  %-24s = %s,", k, k)
  table.insert lines, "}"
  table.concat lines, "\n"

-- ── Point d'entrée ────────────────────────────────────────────────

--- Résout la configuration UCI et écrit OUTPUT_DIR/config.lua atomiquement.
-- Quitte avec code 1 si le répertoire de sortie ou l'écriture est impossible.
main = ->
  raw_domains = uci_get_list "allowed_domains"
  domains     = {}
  for d in *raw_domains
    valid = validate_domain d
    table.insert domains, valid if valid
  domains = DEFAULTS.allowed_domains if #domains == 0

  raw_whitelist = uci_get_list "dest_whitelist"
  whitelist    = {}
  for ip in *raw_whitelist
    valid = validate_ip_cidr ip
    table.insert whitelist, valid if valid
  whitelist = DEFAULTS.dest_whitelist if #whitelist == 0

  cfg = {
    forced_ttl:             validate_posint(uci_get("forced_ttl"),                   DEFAULTS.forced_ttl)
    nft_ip_timeout:         validate_nft_timeout(uci_get("nft_ip_timeout"),          DEFAULTS.nft_ip_timeout)
    ipc_pending_ttl:        validate_posint(uci_get("ipc_pending_ttl"),              DEFAULTS.ipc_pending_ttl)
    client_expiry:          validate_posint(uci_get("client_expiry"),                DEFAULTS.client_expiry)
    neigh_refresh_cooldown: validate_posint(uci_get("neigh_refresh_cooldown"),       DEFAULTS.neigh_refresh_cooldown)
    nft_add_retry_count:    validate_posint(uci_get("nft_add_retry_count"),          DEFAULTS.nft_add_retry_count)
    nft_add_backoff_ms:     uci_get("nft_add_backoff_ms")                       or DEFAULTS.nft_add_backoff_ms
    nft_add_failure_policy: uci_get("nft_add_failure_policy")                  or DEFAULTS.nft_add_failure_policy
    ipc_match_retry_enabled: validate_bool(uci_get("ipc_match_retry_enabled"),      DEFAULTS.ipc_match_retry_enabled)
    ipc_match_retry_count:  validate_posint(uci_get("ipc_match_retry_count"),       DEFAULTS.ipc_match_retry_count)
    ipc_match_retry_sleep_ms: validate_posint(uci_get("ipc_match_retry_sleep_ms"), DEFAULTS.ipc_match_retry_sleep_ms)
    allowed_domains:        domains
  dest_whitelist:         whitelist
  nft_extra_rules:         uci_get_list "nft_extra_rules"
}

  -- Création du répertoire de sortie (tmpfs sur OpenWrt, recréé après chaque reboot)
  if os.execute("mkdir -p #{OUTPUT_DIR}") ~= 0
    io.stderr\write "uci_config: impossible de créer #{OUTPUT_DIR}\n"
    os.exit 1

  -- Écriture atomique : fichier temporaire puis rename(2)
  tmp_path    = "#{OUTPUT_DIR}/config.lua.tmp"
  output_path = "#{OUTPUT_DIR}/config.lua"

  fh, err = io.open tmp_path, "w"
  unless fh
    io.stderr\write "uci_config: écriture impossible #{tmp_path}: #{err}\n"
    os.exit 1

  fh\write generate_config cfg
  fh\close!

  ok, mv_err = os.rename tmp_path, output_path
  unless ok
    io.stderr\write "uci_config: rename échoué: #{mv_err}\n"
    os.execute "rm -f #{tmp_path}"
    os.exit 1

  io.write "uci_config: #{output_path} écrit\n"

main!
