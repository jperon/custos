-- src/config.moon
-- Configuration centrale : constantes, allowlist qnames, paramètres runtime.
-- C'est le seul fichier à modifier pour adapter le filtre.

-- ── Queues NFQUEUE ──────────────────────────────────────────────
QUEUE_QUESTIONS = 0   -- UDP/53 src LAN  (questions sortantes)
QUEUE_RESPONSES = 1   -- UDP/53 dst LAN  (réponses entrantes)

-- ── Docker mode ──────────────────────────────────────────────────
-- When running inside Docker, dnsmasq runs on the filter container itself.
-- NFQUEUE is on INPUT (client queries → Q0) and OUTPUT (dnsmasq responses → Q1).
-- Q0 blocks disallowed queries before dnsmasq sees them, so there will never
-- be a Q1 response for a blocked domain. The IPC correlation check in Q1
-- is therefore redundant and is skipped for simplicity.
DOCKER_MODE = os.getenv("DOCKER_MODE") == "1"

-- ── Logging ─────────────────────────────────────────────────────
-- Les messages sont écrits sur stdout (fd=1).
-- Le superviseur de processus les capture vers le système de log natif :
--   OpenWrt / procd  → logread   (procd_set_param stdout 1)
--   systemd          → journalctl
--   Docker           → docker logs

-- ── Allowlist des qnames autorisés ──────────────────────────────
-- Correspondance par suffixe : "example.com" autorise aussi "sub.example.com".
-- Recharge à chaud via SIGHUP sur chaque worker.
ALLOWED_DOMAINS = {
  -- Résolution locale et infrastructure
  "local"
  "lan"
  "home.arpa"

  -- Outils de développement
  "github.com"
  "gitlab.com"
  "npmjs.org"
  "pypi.org"
  "debian.org"
  "ubuntu.com"
  "archlinux.org"

  -- CDN et infra commune
  "cloudflare.com"
  "fastly.com"
  "akamaiedge.net"

  -- Exemple de domaine autorisé
  "example.com"
}

-- ── Noms de sets nftables ────────────────────────────────────────
NFT_TABLE      = "dns-filter"
NFT_SET_IP4    = "ip4_allowed"
NFT_SET_IP6    = "ip6_allowed"
NFT_SET_MAC4   = "mac4_allowed"   -- ether_addr . ipv4_addr (client MAC + dest IPv4)
NFT_SET_MAC6   = "mac6_allowed"   -- ether_addr . ipv6_addr (client MAC + dest IPv6)
NFT_IP_TIMEOUT = "2m"             -- durée de vie des IPs dans les sets

-- ── Pipe IPC Q0 → Q1 ────────────────────────────────────────────
-- Taille du message binaire (voir ipc.moon)
IPC_MSG_SIZE = 27   -- 1B type + 2B txid + 16B ip (IPv4 zero-padé) + 2B port + 6B MAC

-- Durée de vie d'une transaction en attente de réponse (secondes)
IPC_PENDING_TTL = 5

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

-- ── Export ──────────────────────────────────────────────────────
{
  :QUEUE_QUESTIONS, :QUEUE_RESPONSES
  :DOCKER_MODE
  :ALLOWED_DOMAINS
  :NFT_TABLE, :NFT_SET_IP4, :NFT_SET_IP6, :NFT_SET_MAC4, :NFT_SET_MAC6, :NFT_IP_TIMEOUT
  :IPC_MSG_SIZE, :IPC_PENDING_TTL, :CLIENT_EXPIRY, :NEIGH_REFRESH_COOLDOWN
  :FORCED_TTL
  :DNS_PORT, :AF_INET, :AF_INET6, :PROTO_UDP
  :AUTH_SESSIONS_FILE
}
