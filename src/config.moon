-- src/config.moon
-- Configuration centrale : constantes, paramètres runtime, chemins.
-- NOTE : La configuration du filtre (règles, listes de domaines, auth) se trouve
-- dans filter.yml. Ce fichier ne contient que des constantes compile-time.

-- ── Queues NFQUEUE ──────────────────────────────────────────────
QUEUE_QUESTIONS = "0-1"    -- UDP/53 src LAN (questions)
QUEUE_RESPONSES = "4"      -- UDP/53 dst LAN (réponses)
QUEUE_CAPTIVE   = "20"     -- TCP SYN/80 (captif)
QUEUE_REJECT    = "10-11"  -- Reject rate-limited
QUEUE_AUTH      = "5"      -- TCP 33443 (authentification captive)

-- ── Logging ─────────────────────────────────────────────────────
-- Les messages sont écrits sur stdout (fd=1).
-- Le superviseur de processus les capture vers le système de log natif :
--   OpenWrt / procd  → logread   (procd_set_param stdout 1)
--   systemd          → journalctl
-- Niveau de log par défaut. Peut être surchargé par UCI (custos.main.log_level).
LOG_LEVEL = "INFO" -- ERROR, WARN, INFO, DEBUG, TRACE

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



-- ── TTL forcé ────────────────────────────────────
-- TTL injecté sur tous les RR des réponses autorisées (secondes).
FORCED_TTL = 60

-- ── Constantes réseau ───────────────────────────────────────────
DNS_PORT   = 53
AF_INET    = 2
AF_INET6   = 10

-- ── MAC Learner ─────────────────────────────────────────────────
-- Socket Unix SOCK_STREAM pour les requêtes MAC (AUTH, Q2, …).
MAC_LEARNER_QUERY_SOCK     = "/var/run/custos/mac_query.sock"
-- Taille d'un message de learn binaire (ip16 + mac6).
MAC_LEARNER_LEARN_MSG_SIZE = 22
-- Durée de vie d'une entrée IP→MAC dans la table du learner (secondes).
MAC_LEARNER_ENTRY_TTL      = 300

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

-- ── Domaines DNS autorisés par défaut ───────────────────────────
-- Surchargeables via UCI (custos.main.allowed_domains).
ALLOWED_DOMAINS = { "local", "lan", "home.arpa" }

-- ── Règles nftables supplémentaires ─────────────────────────────
-- Injectées en tête de chaîne `forward` au démarrage.
-- Surchargeables via UCI (custos.main.nft_extra_rules).
NFT_EXTRA_RULES = {}

-- ── Export ──────────────────────────────────────────────────────
{
  :QUEUE_QUESTIONS, :QUEUE_RESPONSES, :QUEUE_CAPTIVE, :QUEUE_REJECT, :QUEUE_AUTH
  :NFT_FAMILY, :NFT_FAMILY6, :NFT_TABLE, :NFT_SET_IP4, :NFT_SET_IP6, :NFT_SET_MAC4, :NFT_SET_MAC6, :NFT_IP_TIMEOUT
  :NFT_ADD_RETRY_COUNT, :NFT_ADD_BACKOFF_MS, :NFT_ADD_FAILURE_POLICY
  :IPC_PENDING_TTL
  :IPC_MATCH_RETRY_ENABLED, :IPC_MATCH_RETRY_COUNT, :IPC_MATCH_RETRY_SLEEP_MS
  :CLIENT_EXPIRY
  :MAC_LEARNER_QUERY_SOCK, :MAC_LEARNER_LEARN_MSG_SIZE, :MAC_LEARNER_ENTRY_TTL
  :FORCED_TTL
  :DNS_PORT, :AF_INET, :AF_INET6
  :AUTH_SESSIONS_FILE
  :DEST_WHITELIST, :ALLOWED_DOMAINS, :NFT_EXTRA_RULES
  :LOG_LEVEL
}
