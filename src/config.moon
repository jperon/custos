-- src/config.moon
-- Configuration centrale : constantes, paramètres runtime, chemins.
-- NOTE : La configuration du filtre (règles, listes de domaines, auth) se trouve
-- dans filter.yml. Ce fichier ne contient que des constantes compile-time.

-- ── Queues NFQUEUE ──────────────────────────────────────────────
QUEUE_QUESTIONS = 0   -- UDP/53 src LAN  (questions sortantes)
QUEUE_RESPONSES = 1   -- UDP/53 dst LAN  (réponses entrantes)
QUEUE_CAPTIVE   = 2   -- TCP SYN/80 non autorisés (mode bridge uniquement)

-- ── Mode bridge ────────────────────────────────────
-- BRIDGE_MODE=1 : active le worker Q2 (portail captif TCP SYN).
-- NFQ_BRIDGE_MODE=1 : NFQUEUE est sur la table bridge nftables.
--   Les workers Q0/Q1 reçoivent des trames Ethernet complètes (eth_offset=14).
--   En mode routeur (table ip/ip6), seul le paquet IP est livré (eth_offset=0).
-- Dans Docker (DOCKER_MODE=1), NFQUEUE est sur table ip (INPUT/OUTPUT) :
--   BRIDGE_MODE peut être 1 (active Q2) mais NFQ_BRIDGE_MODE reste 0.
BRIDGE_MODE     = true
NFQ_BRIDGE_MODE = true

-- ── Docker mode ──────────────────────────────────────────────────
-- When running inside Docker, dnsmasq runs on the filter container itself.
-- NFQUEUE is on INPUT (client queries → Q0) and OUTPUT (dnsmasq responses → Q1).
-- Q0 blocks disallowed queries before dnsmasq sees them, so there will never
-- be a Q1 response for a blocked domain. The IPC correlation check in Q1
-- is therefore redundant and is skipped for simplicity.
-- ── Logging ─────────────────────────────────────────────────────
-- Les messages sont écrits sur stdout (fd=1).
-- Le superviseur de processus les capture vers le système de log natif :
--   OpenWrt / procd  → logread   (procd_set_param stdout 1)
--   systemd          → journalctl
--   Docker           → docker logs

-- ── Noms de sets nftables ────────────────────────────────────────
NFT_FAMILY     = "bridge"
NFT_FAMILY6    = "bridge"
NFT_TABLE      = "dns-filter-bridge"
NFT_SET_IP4    = "ip4_allowed"
NFT_SET_IP6    = "ip6_allowed"
NFT_SET_MAC4   = "mac4_allowed"   -- ether_addr . ipv4_addr (client MAC + dest IPv4)
NFT_SET_MAC6   = "mac6_allowed"   -- ether_addr . ipv6_addr (client MAC + dest IPv6)
NFT_IP_TIMEOUT = "2m"             -- durée de vie des IPs dans les sets

-- ── Politique et retry pour les insertions dynamiques dans nft
NFT_ADD_RETRY_COUNT = 3
NFT_ADD_BACKOFF_MS = {20, 50, 100}
NFT_ADD_FAILURE_POLICY = "fail-closed"  -- options: "fail-open" or "fail-closed"

-- ── Pipe IPC Q0 → Q1 ────────────────────────────────────────────
-- Durée de vie d'une transaction en attente de réponse (secondes)
IPC_PENDING_TTL = 5

-- Retry borné de corrélation IPC côté Q1 (anti-course Q0→Q1)
-- Chemin miss uniquement : pas de busy wait (nanosleep entre tentatives)
IPC_MATCH_RETRY_ENABLED = true
IPC_MATCH_RETRY_COUNT = 5
IPC_MATCH_RETRY_SLEEP_MS = 20

-- ── Client tracking ─────────────────────────────────────────────
-- Durée en secondes sans activité DNS avant qu'un client soit purgé
-- du cache MAC (worker Q1). Le timeout nftables sur les sets gère
-- l'expiration des paires (client, dest) indépendamment.
CLIENT_EXPIRY = 300

-- Délai minimal (secondes) entre deux lectures de `ip neigh show`
-- lors d'un lazy-refresh sur miss cross-family.
NEIGH_REFRESH_COOLDOWN = 10

-- ── TTL forcé ────────────────────────────────────
-- TTL injecté sur tous les RR des réponses autorisées (secondes).
FORCED_TTL = 60

-- ── Constantes réseau ───────────────────────────────────────────
DNS_PORT   = 53
AF_INET    = 2
AF_INET6   = 10
PROTO_UDP  = 17

-- ── Authentification HTTPS ───────────────────────────────────────
-- Chemin du fichier de sessions partagé entre le worker auth et les
-- workers Q0/Q1 (via from_user). Surchargeable via cfg/filter.yml (auth.sessions_file).
AUTH_SESSIONS_FILE = "./tmp/sessions.lua"

-- ── Destination whitelist (CIDR networks bypassing DNS analysis) ─────
-- Configuré via UCI (custos.main.dest_whitelist) ou filter.yml (ip_whitelist).
-- Trafic vers ces réseaux autorisé sans résolution DNS préalable.
-- Note : la source peut être filtrée via les règles filter (from_net, from_netlist, etc.),
-- mais la destination ne peut l'être que via cette whitelist (contournement DNS).
DEST_WHITELIST = {}

-- ── Export ──────────────────────────────────────────────────────
{
  :QUEUE_QUESTIONS, :QUEUE_RESPONSES, :QUEUE_CAPTIVE
  :BRIDGE_MODE, :NFQ_BRIDGE_MODE
  :NFT_FAMILY, :NFT_FAMILY6, :NFT_TABLE, :NFT_SET_IP4, :NFT_SET_IP6, :NFT_SET_MAC4, :NFT_SET_MAC6, :NFT_IP_TIMEOUT
  :NFT_ADD_RETRY_COUNT, :NFT_ADD_BACKOFF_MS, :NFT_ADD_FAILURE_POLICY
  :IPC_PENDING_TTL
  :IPC_MATCH_RETRY_ENABLED, :IPC_MATCH_RETRY_COUNT, :IPC_MATCH_RETRY_SLEEP_MS
  :CLIENT_EXPIRY, :NEIGH_REFRESH_COOLDOWN
  :FORCED_TTL
  :DNS_PORT, :AF_INET, :AF_INET6, :PROTO_UDP
  :AUTH_SESSIONS_FILE
  :DEST_WHITELIST
}
