-- src/webui/schema/config_schema.moon
-- Annotations UI de toutes les sections de configuration.
-- Chaque section décrit ses clés avec { type, label, hint?, values?, default? }.
-- Non chargé dans les workers DNS — uniquement dans le contexte webui.
--
-- Types de champ : "string" | "integer" | "boolean" | "enum" | "path"
--                  "string_list" | "time_window" | "named_map" | "rules_list"

{
  runtime: {
    _label: "Runtime"
    _description: "Paramètres d'exécution généraux"
    log_level: { type: "enum",    label: "Niveau de log",    values: {"DEBUG","INFO","WARN","ERROR"}, default: "INFO" }
    benchmark:  { type: "boolean", label: "Mode benchmark",   default: false }
  }

  nfqueue: {
    _label: "Files de paquets (NFQUEUE)"
    _description: "Avancé — réservé aux experts. Le pare-feu (nftables) remet les paquets à Custos via des « files » Netfilter numérotées ; chaque type de trafic a la sienne. Ne modifiez ces numéros que pour éviter un conflit avec d'autres outils utilisant NFQUEUE sur la même machine. Une plage s'écrit '0-1'."
    questions: { type: "string", label: "Requêtes DNS",        hint: "n° de file, ex: 0-1",   default: "0-1" }
    responses:  { type: "string", label: "Réponses DNS",        hint: "n° de file, ex: 4",     default: "4" }
    captive:    { type: "string", label: "Portail captif",      hint: "n° de file, ex: 20",    default: "20" }
    reject:     { type: "string", label: "Paquets à rejeter",   hint: "n° de file, ex: 10-11", default: "10-11" }
    auth:       { type: "string", label: "Handshakes TLS (auth)", hint: "n° de file, ex: 5",   default: "5" }
    sni:        { type: "string", label: "Verdict SNI TLS/QUIC", hint: "n° de file, ex: 6", default: "6" }
    sip:        { type: "string", label: "Trafic SIP/STUN",      hint: "n° de file, ex: 12",   default: "12" }
  }

  dns: {
    _label: "DNS"
    _description: "Paramètres du traitement DNS"
    port: { type: "integer", label: "Port DNS", default: 53 }
    ttl_grace: {
      _label: "TTL grace"
      grace: { type: "integer", label: "Grace TTL (s)",  hint: "ajouté au TTL DNS",   default: 600 }
      min:   { type: "integer", label: "TTL minimum (s)",                               default: 60 }
      max:   { type: "integer", label: "TTL maximum (s)", hint: "30 jours = 2592000",  default: 2592000 }
    }
  }

  nft: {
    _label: "Pare-feu (nftables)"
    _description: "Avancé. Custos autorise dynamiquement les adresses résolues en les ajoutant à des « ensembles » (sets) nftables. Les valeurs par défaut conviennent à un pont (bridge) standard ; ne les changez que si votre topologie réseau l'impose."
    family:               { type: "enum",    label: "Famille nftables (IPv4)", values: {"bridge","inet","ip","ip6"},       default: "bridge" }
    family6:              { type: "enum",    label: "Famille nftables (IPv6)", values: {"bridge","inet6","ip6"},            default: "bridge" }
    table:                { type: "string",  label: "Nom de la table",                                                  default: "dns-filter-bridge" }
    ip_timeout:           { type: "string",  label: "Durée des autorisations IP", hint: "ex: 2m, 300s",                  default: "2m" }
    sip_session_ttl:      { type: "string",  label: "Durée des sessions SIP",  hint: "ex: 5m",                              default: "5m" }
    add_backoff_ms:       { type: "string",  label: "Délais de réessai (ms)",  hint: "liste, ex: {20,50,200,400,800,2000}", default: "{20,50,200,400,800,2000}" }
    add_failure_policy:   { type: "enum",    label: "En cas d'échec d'ajout", values: {"fail-closed","fail-open"},        default: "fail-closed" }
    ack_timeout_ms:       { type: "integer", label: "Délai d'attente confirmation (ms)",                                  default: 150 }
  }

  ipc: {
    _label: "Communication interne (IPC)"
    _description: "Avancé. Règle le dialogue entre les processus internes de Custos (corrélation requête/réponse DNS). À n'ajuster qu'en cas de problème de performance diagnostiqué."
    pending_ttl: { type: "integer", label: "Durée de conservation d'une requête en attente (s)", default: 5 }
    match_retry: {
      _label: "Corrélation requête/réponse"
      count:    { type: "integer", label: "Nombre de tentatives", default: 5 }
      sleep_ms: { type: "integer", label: "Délai entre tentatives (ms)", default: 20 }
    }
  }

  clients: {
    _label: "Cache clients"
    expiry: { type: "integer", label: "Expiration entrée client (s)", default: 300 }
  }

  mac_learner: {
    _label: "Détection des adresses MAC"
    _description: "Avancé. Custos associe automatiquement chaque IP à son adresse matérielle (MAC) observée sur le réseau, pour les règles « Adresse MAC source ». Les valeurs par défaut conviennent dans la plupart des cas."
    query_sock: { type: "path",    label: "Socket de communication interne", default: "/var/run/custos/mac_query.sock" }
    entry_ttl:  { type: "integer", label: "Durée de mémorisation d'une MAC (s)", default: 900 }
  }

  auth: {
    _label: "Authentification"
    _description: "Portail captif et authentification des utilisateurs"
    host:               { type: "string",  label: "Adresse d'écoute",       hint: ":: = toutes interfaces",   default: "::" }
    port:               { type: "integer", label: "Port HTTPS",                                                 default: 33443 }
    captive_port:       { type: "integer", label: "Port HTTP portail captif",                                   default: 33080 }
    cert:               { type: "path",    label: "Certificat TLS (optionnel)" }
    key:                { type: "path",    label: "Clé privée TLS (optionnel)" }
    session_key:        { type: "path",    label: "Clé HMAC sessions",      hint: "générée si absente",       default: "/etc/custos/session.key" }
    secrets:            { type: "path",    label: "Fichier secrets",                                            default: "/etc/custos/secrets" }
    sessions_file:      { type: "path",    label: "Fichier sessions",                                           default: "/tmp/sessions.lua" }
    session_ttl:        { type: "integer", label: "TTL session (s, 0=illimitée)",                               default: 0 }
    heartbeat_interval: { type: "integer", label: "Intervalle heartbeat (s)",                                    default: 30 }
    idle_timeout:       { type: "integer", label: "Timeout inactivité (s)",                                      default: 120 }
    register_rate_limit:  { type: "integer", label: "Inscriptions max / fenêtre",                               default: 3 }
    register_rate_window: { type: "integer", label: "Fenêtre rate-limit (s)",                                    default: 300 }
    bridge_ifname:      { type: "string",  label: "Interface bridge",                                            default: "br0" }
  }

  sni: {
    _label: "Verdict SNI"
    _description: "Inspection et filtrage du trafic TLS/QUIC sur port 443"
    enabled:            { type: "boolean", label: "Activer verdict SNI",      default: true }
    mode:               { type: "enum",    label: "Mode", values: {"strict-443","permissive"}, default: "strict-443" }
    placement:          { type: "enum",    label: "Placement nft", values: {"integral","residual"}, default: "residual" }
    protocols:          { type: "enum",    label: "Protocoles", values: {"both","tls","quic"}, default: "both" }
    nft_failure_policy: { type: "enum",    label: "Politique d'échec", values: {"fail-closed","fail-open"}, default: "fail-closed" }
  }

  doh: {
    _label: "DNS-over-HTTPS"
    _description: "Proxy DoH vers un résolveur amont"
    enabled:            { type: "boolean", label: "Activer DoH",          default: true }
    port:               { type: "integer", label: "Port DoH",             default: 8443 }
    upstream_ipv4:      { type: "string",  label: "Upstream IPv4",        default: "1.1.1.3" }
    upstream_ipv6:      { type: "string",  label: "Upstream IPv6",        default: "2606:4700:4700::1113" }
    upstream_port:      { type: "integer", label: "Port upstream",        default: 53 }
    upstream_timeout_ms:{ type: "integer", label: "Timeout upstream (ms)",default: 2000 }
    cert_path:          { type: "path",    label: "Certificat TLS DoH (optionnel)" }
    key_path:           { type: "path",    label: "Clé TLS DoH (optionnel)" }
    prefer_ipv6:        { type: "boolean", label: "Préférer IPv6",        default: true }
  }

  events: {
    _label: "Événements"
    _description: "Stockage des événements système"
    dir:           { type: "path",    label: "Répertoire événements", default: "/tmp/custos/events" }
    max_age_hours: { type: "integer", label: "Conservation max (h)",  hint: "168h = 7 jours", default: 168 }
    min_free_pct:  { type: "integer", label: "Espace libre min (%)",  default: 30 }
  }

  metrics: {
    _label: "Métriques"
    enabled:        { type: "boolean", label: "Activer métriques",       default: true }
    flush_interval: { type: "integer", label: "Intervalle vidange (s)",  default: 60 }
    max_rules:      { type: "integer", label: "Max règles tracées",      default: 1000 }
  }

  rtp: {
    _label: "RTP/VoIP"
    excluded_ports: { type: "string_list", label: "Ports exclus du filtrage RTP", hint: "ex: {5060}", default: "{5060}" }
  }

  filter: {
    _label: "Filtre DNS"
    _description: "Section principale : règles, listes, et dictionnaires nommés"
    domainlists_dir: { type: "path",    label: "Répertoire listes domaines", default: "/etc/custos/lists" }
    custom_lists_dir:{ type: "path",    label: "Répertoire listes personnalisées (optionnel)" }
    allow_localnets: { type: "boolean", label: "Autoriser réseaux locaux",   default: false }
    captive_portal:  { type: "boolean", label: "Détection de portail captif (sondes NCSI/MSFT, Apple, Google…)", default: true }
    safe_search:     { type: "boolean", label: "SafeSearch (Google/YouTube/Bing/DuckDuckGo)", default: true }
    youtube_restrict:{ type: "enum",    label: "YouTube Restricted Mode", values: {"strict","moderate","false"}, default: "moderate" }
    dest_whitelist:  { type: "string_list", label: "IPs/CIDRs toujours autorisées" }
    allowed_domains: { type: "string_list", label: "Domaines autorisés par défaut", default: '{"local","lan","home.arpa"}' }
    nets:      { type: "named_map", label: "Réseaux nommés",       value_type: "string_list",  hint: "alias → liste de CIDRs" }
    macs:      { type: "named_map", label: "MACs nommées",         value_type: "string_list",  hint: "alias → liste de MACs" }
    times:     { type: "named_map", label: "Plages horaires",      value_type: "time_window",  hint: "nom → {HH:MM, HH:MM}" }
    users:     { type: "named_map", label: "Utilisateurs",         value_type: "string",       hint: "alias → email" }
    userlists: { type: "named_map", label: "Listes d'utilisateurs",value_type: "string_list",  hint: "alias → liste d'emails" }
    decision: {
      _label: "Politique de décision"
      first_match_wins:      { type: "boolean", label: "Première règle gagne (first-match)", default: true }
      continue_to_next_rule: { type: "boolean", label: "Continuer après match",               default: false }
    }
    rules: { type: "rules_list", label: "Règles de filtrage" }
  }
}
