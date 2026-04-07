local QUEUE_QUESTIONS = 0
local QUEUE_RESPONSES = 1
local DOCKER_MODE = os.getenv("DOCKER_MODE") == "1"
local LOG_PATH = "./tmp/dns-filter.log"
local LOG_FLUSH = true
local ALLOWED_DOMAINS = {
  "local",
  "lan",
  "home.arpa",
  "github.com",
  "gitlab.com",
  "npmjs.org",
  "pypi.org",
  "debian.org",
  "ubuntu.com",
  "archlinux.org",
  "cloudflare.com",
  "fastly.com",
  "akamaiedge.net",
  "example.com"
}
local NFT_TABLE = "dns-filter"
local NFT_SET_IP4 = "ip4_allowed"
local NFT_SET_IP6 = "ip6_allowed"
local NFT_IP_TIMEOUT = "2m"
local IPC_MSG_SIZE = 27
local IPC_PENDING_TTL = 5
local CLIENT_EXPIRY = 300
local NEIGH_REFRESH_COOLDOWN = 10
local FORCED_TTL = 60
local DNS_PORT = 53
local AF_INET = 2
local AF_INET6 = 10
local PROTO_UDP = 17
return {
  QUEUE_QUESTIONS = QUEUE_QUESTIONS,
  QUEUE_RESPONSES = QUEUE_RESPONSES,
  DOCKER_MODE = DOCKER_MODE,
  LOG_PATH = LOG_PATH,
  ALLOWED_DOMAINS = ALLOWED_DOMAINS,
  NFT_TABLE = NFT_TABLE,
  NFT_SET_IP4 = NFT_SET_IP4,
  NFT_SET_IP6 = NFT_SET_IP6,
  NFT_IP_TIMEOUT = NFT_IP_TIMEOUT,
  IPC_MSG_SIZE = IPC_MSG_SIZE,
  IPC_PENDING_TTL = IPC_PENDING_TTL,
  CLIENT_EXPIRY = CLIENT_EXPIRY,
  NEIGH_REFRESH_COOLDOWN = NEIGH_REFRESH_COOLDOWN,
  FORCED_TTL = FORCED_TTL,
  DNS_PORT = DNS_PORT,
  AF_INET = AF_INET,
  AF_INET6 = AF_INET6,
  PROTO_UDP = PROTO_UDP
}
