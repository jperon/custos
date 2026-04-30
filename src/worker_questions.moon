-- src/worker_q0.moon
-- Worker Q0 : traitement des questions DNS (UDP/53 src=LAN, dst=resolver).
--
-- Pour chaque paquet :
--   1. Parse L2 (MAC src via nfq_get_packet_hw)
--   2. Parse L3/L4/L7 via parse/ndpi (IPv4 et IPv6)
--   3. Vérifie allowlist → décide allow ou refuse
--   4. Si autorisé : envoie write_msg (allowed) dans le pipe IPC vers Q1, NF_ACCEPT
--   5. Si refusé   : envoie write_refused_msg dans le pipe IPC vers Q1, NF_ACCEPT
--      Q1 intercepte la réponse du serveur et la transforme en REFUSED+EDE
--   6. Log structuré avec champs nDPI (ndpi_master / ndpi_app)

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :QUEUE_QUESTIONS, :AUTH_SESSIONS_FILE } = require "config"
{ :get_l2 } = require "parse/ethernet"
ndpi                     = require "parse/ndpi"
filter                   = require "filter"
{ :write_msg, :write_refused_msg, :write_dnsonly_msg } = require "ipc"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_allow, :log_block, :log_warn, :log_debug, :log_info } = require "log"
{ :user_for_mac } = require "auth.sessions"
forge_dns = require "forge_dns"
{ detect: detect_captive_ips } = require "captive_ips"
bridge_raw = require "bridge_raw"
{ new: new_eth, proto: {:IP4, :IP6} } = require "ipparse.l2.ethernet"

-- fd d'écriture du pipe IPC Q0→Q1, injecté par main.moon avant fork()
pipe_wfd = nil

-- fd d'écriture du pipe d'apprentissage Q0→mac_learner.
mac_learn_wfd = nil

-- ── Vol de question DNS pour le portail captif ───────────────────
-- Initialisés dans run() depuis filter.get_auth_cfg().
-- captive_domain : hostname en casse basse (ex. "custos.mon-routeur.lan"),
--                 nil si redirect_url absent ou contient une IP brute.
-- captive_ip4/6  : adresses IP du portail captif pour les RR A et AAAA.
-- raw_fd/_ifindex/_bridge_mac : socket AF_PACKET et infos bridge pour
--                 l'injection directe de la réponse DNS vers le client.
captive_domain = nil
captive_ip4    = nil
captive_ip6    = nil
raw_fd         = nil
_ifindex       = nil
_bridge_mac    = nil

--- Extrait le hostname d'une URL https?://host[:port]/...
-- Retourne nil si l'URL contient une IP brute (IPv4 x.x.x.x ou IPv6 [::]).
-- @tparam string|nil url URL du portail captif
-- @treturn string|nil Hostname en casse basse, ou nil
domain_from_url = (url) ->
  return nil unless url
  host = url\match "^https?://([^/:]+)"
  return nil unless host
  return nil if host\match "^%d+%.%d+%.%d+%.%d+$"   -- IPv4 brute
  return nil if host\match "^%["                      -- [IPv6] entre crochets
  host\lower!

-- ── Apprentissage MAC ────────────────────────────────────────────

--- Écrit une association IP→MAC vers le mac_learner.
-- Message binaire fixe : ip16 + mac6 = 22 octets.
-- IPv4 : 4 octets significatifs suivis de 12 zéros.
-- @tparam string ip_raw Adresse IP brute, 4 octets IPv4 ou 16 octets IPv6
-- @tparam string mac_raw Adresse MAC brute, 6 octets
-- @treturn boolean true si l'écriture complète a réussi
write_learn_msg = (ip_raw, mac_raw) ->
  return false unless mac_learn_wfd and mac_learn_wfd >= 0
  return false unless ip_raw and (#ip_raw == 4 or #ip_raw == 16)
  return false unless mac_raw and #mac_raw == 6

  msg = ffi.new "uint8_t[22]"

  if #ip_raw == 4
    for i = 1, 4
      msg[i - 1] = ip_raw\byte i
  else
    for i = 1, 16
      msg[i - 1] = ip_raw\byte i

  for i = 1, 6
    msg[15 + i] = mac_raw\byte i

  n = libc.write mac_learn_wfd, msg, 22
  n == 22

-- ── Callback principal ───────────────────────────────────────────
handle_question = (qh_ptr, nfad, pkt_id) ->
  -- ── Payload brut ─────────────────────────────────────────────
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  return NF_DROP if payload_len <= 0

  raw = ffi.string payload_ptr[0], payload_len

  -- ── L2 ────────────────────────────────────────────────────
  -- MAC source via nfq_get_packet_hw() ; MAC destination non exposée par libnfq.
  l2 = get_l2 nfad

  -- ── L3 / L4 / L7 ───────────────────────────────────────────────
  pkt, parse_status = ndpi.parse_packet raw
  unless pkt
    -- TCP segments arriving before a complete DNS message are buffered; let them through.
    return NF_ACCEPT if parse_status == "buffering"
    -- TCP control segments (SYN/ACK/FIN without DNS payload) must pass.
    return NF_ACCEPT if parse_status == "tcp_control"
    log_warn { action: "parse_failed", mac_src: l2.mac_src }
    return NF_DROP

  -- Log L2 metadata une fois le parse réussi (src_ip disponible pour corrélation).
  -- WARN si mac inconnue (nfq_get_packet_hw n'a rien retourné) pour faciliter
  -- le diagnostic sans avoir à passer en DEBUG.
  if l2.mac_src == "unknown"
    log_warn {
      action:     "l2_mac_missing"
      src_ip:     pkt.ip.src_ip
      in_ifindex: l2.in_ifindex
      vlan:       l2.vlan
    }
  else
    log_debug {
      action:     "l2_info"
      mac_src:    l2.mac_src
      src_ip:     pkt.ip.src_ip
      in_ifindex: l2.in_ifindex
      vlan:       l2.vlan
    }

  -- ── nDPI State Tracking ──────────────────────────────────────
  ndpi.get_flow pkt
  if math.random(1000) == 1
    ndpi.purge_flows!
    ndpi.purge_tcp_buffers!

  -- On ne traite que les questions (QR bit = 0)
  return NF_ACCEPT if pkt.dns.is_response

  -- Alimente le mac_learner avec les associations observées sur le trafic DNS.
  -- Écriture best-effort : l'échec ne doit pas bloquer ni refuser la requête DNS.
  write_learn_msg pkt.ip.src_ip_raw, l2.mac_raw

  -- ── Vol de question DNS pour le portail captif ───────────────────
  -- Si la question porte sur le hostname du portail captif (extrait de
  -- redirect_url), on forge une réponse DNS (A ou AAAA) et on l'injecte
  -- directement via AF_PACKET sur le bridge, comme le fait Q2 pour les TCP.
  -- La question originale est droptée (NF_DROP) ; aucun message IPC vers Q1.
  -- Cette approche est nécessaire car nfq_set_verdict(NF_ACCEPT, payload) ne
  -- peut pas inverser la direction d'un paquet (le paquet resterait sur le
  -- chemin LAN→WAN au lieu d'être renvoyé vers le client).
  if captive_domain and raw_fd and _bridge_mac
    for _, q in ipairs pkt.questions
      norm = q.qname\lower!\gsub "%.+$", ""
      if norm == captive_domain and (q.qtype == 1 or q.qtype == 28)   -- A ou AAAA
        mac_raw = l2.mac_raw
        if not mac_raw or mac_raw == "\0\0\0\0\0\0"
          log_warn {
            action:  "dns_steal_no_mac"
            domain:  q.qname
            src_ip:  pkt.ip.src_ip
          }
          break   -- MAC inconnue : laisser passer normalement
        forged_ip = forge_dns.forge_dns_response pkt, q, captive_ip4, captive_ip6
        if forged_ip
          eth_obj = new_eth {
            src:      _bridge_mac
            dst:      mac_raw
            protocol: pkt.ip.version == 6 and IP6 or IP4
            data:     forged_ip
          }
          ok = bridge_raw.send raw_fd, "#{eth_obj}", _ifindex
          log_info {
            action:   "dns_stolen"
            domain:   q.qname
            qtype:    q.qtype_name
            src_ip:   pkt.ip.src_ip
            resolver: pkt.ip.dst_ip
            mac:      l2.mac_src
            ancount:  (captive_ip4 and q.qtype == 1 or captive_ip6 and q.qtype == 28) and 1 or 0
            sent:     ok
          }
          return NF_DROP
        else
          log_warn {
            action:  "dns_steal_forge_failed"
            domain:  q.qname
            qtype:   q.qtype_name
            src_ip:  pkt.ip.src_ip
          }
          break   -- forge échouée : laisser passer normalement

  -- ── Décision par question ────────────────────────────────────
  -- Un paquet DNS peut contenir plusieurs questions (rare en pratique,
  -- mais prévu par le RFC). On bloque si AU MOINS UNE question est refusée.
  -- Si toutes sont autorisées mais au moins une est "dnsonly", on envoie dnsonly.
  verdict      = NF_ACCEPT
  dnsonly      = false
  block_reason = nil
  allow_reason = nil
  q_fields = {
    mac_src:     l2.mac_src
    vlan:        l2.vlan
    in_if:       tostring l2.in_ifindex
    src_ip:      pkt.ip.src_ip
    dst_ip:      pkt.ip.dst_ip
    src_port:    pkt.l4.src_port
    dst_port:    pkt.l4.dst_port
    txid:        string.format "0x%04x", pkt.dns.txid
    af:          pkt.ip.version == 6 and "ipv6" or "ipv4"
    ndpi_master: pkt.ndpi_master
    ndpi_app:    pkt.ndpi_app
    user:        user_for_mac l2.mac_src, pkt.ip.src_ip, AUTH_SESSIONS_FILE
  }

  for _, q in ipairs pkt.questions
    q_fields.qname = q.qname
    q_fields.qtype = q.qtype_name
    req = {
      domain: q.qname
      src_ip: pkt.ip.src_ip
      mac:    l2.mac_src
      vlan:   l2.vlan
      ts:     os.time!
    }
    allowed, reason, rule = filter.decide req
    q_fields.reason = reason or (allowed == "dnsonly" and "dnsonly") or (allowed and "allowed") or "denied"
    q_fields.rule = rule or ""
    if allowed == "dnsonly"
      log_allow q_fields
      dnsonly = true
      allow_reason = reason
    elseif allowed
      log_allow q_fields
      allow_reason = reason
    else
      log_block q_fields
      verdict = NF_DROP
      block_reason = reason

  -- Enregistre la transaction IPC pour Q1 (toujours NF_ACCEPT — Q1 gère tout).
  -- Si autorisé   : Q1 patche TTL + injecte EDE "Custos vigilat."
  -- Si dnsonly    : Q1 patche TTL + EDE mais n'injecte pas les IPs dans nft
  -- Si refusé     : Q1 transforme la réponse du serveur en REFUSED+EDE Filtered
  ipc_ok = false
  if verdict == NF_ACCEPT
    if dnsonly
      ipc_ok = write_dnsonly_msg pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw, pkt.ip.dst_ip_raw, allow_reason
    else
      ipc_ok = write_msg pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw, pkt.ip.dst_ip_raw, allow_reason
  else
    ipc_ok = write_refused_msg pipe_wfd, pkt.dns.txid, pkt.ip.src_ip_raw, pkt.l4.src_port, l2.mac_raw, pkt.ip.dst_ip_raw, block_reason

  unless ipc_ok
    log_warn {
      action: "ipc_write_failed"
      txid: string.format "0x%04x", pkt.dns.txid
      src_ip: pkt.ip.src_ip
      dst_ip: pkt.ip.dst_ip
      src_port: pkt.l4.src_port
      user: q_fields.user
    }
    return NF_DROP

  NF_ACCEPT


-- ── Point d'entrée ───────────────────────────────────────────────
-- Appelé par main.moon après fork(), avec les fd des pipes IPC.
run = (queue_num, wfd, learn_wfd) ->
  pipe_wfd      = wfd
  mac_learn_wfd = learn_wfd

  -- ── Interception DNS portail captif ─────────────────────────
  -- Lit redirect_url depuis auth_cfg pour extraire le hostname captif.
  -- Ouvre un socket AF_PACKET si un hostname est trouvé (comme Q2).
  do
    auth = filter.get_auth_cfg!
    captive_domain = domain_from_url auth.redirect_url
    captive_ip4, captive_ip6 = detect_captive_ips auth
    if captive_domain
      ifname = auth.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"
      fd, err = bridge_raw.open_socket ifname
      if fd
        raw_fd   = fd
        _ifindex = tonumber ffi.C.if_nametoindex ifname
        _bridge_mac = bridge_raw.read_mac ifname
        log_info {
          action:      "dns_steal_armed"
          domain:      captive_domain
          captive_ip4: captive_ip4 or "none"
          captive_ip6: captive_ip6 or "none"
          ifname:      ifname
        }
      else
        log_warn { action: "dns_steal_socket_failed", err: err, ifname: ifname }
    else
      log_info { action: "dns_steal_disabled", reason: "no hostname in redirect_url" }

  ndpi.warmup!
  run_queue tonumber(queue_num), handle_question
  ndpi.cleanup!

{ :run }
