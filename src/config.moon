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
LOG_PATH   = "./tmp/dns-filter.log"
LOG_FLUSH  = true    -- flush après chaque ligne (utile en debug, coût faible)

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
NFT_IP_TIMEOUT = "2m"           -- durée de vie des IPs dans les sets

-- ── Pipe IPC Q0 → Q1 ────────────────────────────────────────────
-- Taille du message binaire (voir ipc.moon)
IPC_MSG_SIZE = 16   -- 1B type + 2B txid + 4 ou 16B ip + 2B port + 1B pad

-- Durée de vie d'une transaction en attente de réponse (secondes)
IPC_PENDING_TTL = 5

-- ── Constantes réseau ───────────────────────────────────────────
DNS_PORT   = 53
AF_INET    = 2
AF_INET6   = 10
PROTO_UDP  = 17

-- ── Export ──────────────────────────────────────────────────────
{
  :QUEUE_QUESTIONS, :QUEUE_RESPONSES
  :DOCKER_MODE
  :LOG_PATH, :LOG_FLUSH
  :ALLOWED_DOMAINS
  :NFT_TABLE, :NFT_SET_IP4, :NFT_SET_IP6, :NFT_IP_TIMEOUT
  :IPC_MSG_SIZE, :IPC_PENDING_TTL
  :DNS_PORT, :AF_INET, :AF_INET6, :PROTO_UDP
}
