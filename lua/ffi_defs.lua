local ffi = require("ffi")
ffi.cdef([[  /* ── Types de base ── */
  typedef long          ssize_t;
  typedef unsigned long size_t;
  typedef int           pid_t;

  /* ── Temps ── */
  typedef struct { long tv_sec; long tv_nsec; } timespec_t;
  int clock_gettime(int clk_id, timespec_t *tp);

  /* ── Fichiers ── */
  int     open(const char *path, int flags, ...);
  ssize_t write(int fd, const void *buf, size_t n);
  ssize_t read(int fd, void *buf, size_t n);
  int     close(int fd);

  /* ── Processus ── */
  pid_t getpid(void);
  pid_t fork(void);
  pid_t waitpid(pid_t pid, int *status, int options);
  void  _exit(int status);

  /* ── Signaux ── */
  typedef void (*sighandler_t)(int);
  sighandler_t signal(int signum, sighandler_t handler);

  /* ── Pipe ── */
  int pipe(int pipefd[2]);
  int pipe2(int pipefd[2], int flags);  /* Linux >= 2.6.27 */

  /* fcntl avec arg entier (non-variadique pour compatibilité LuaJIT) */
  int fcntl(int fd, int cmd, long arg);

  /* ── errno (Linux glibc) ── */
  int* __errno_location(void);  /* errno = *__errno_location() */

  /* ── Réseau ── */
  uint32_t ntohl(uint32_t n);
  uint16_t ntohs(uint16_t n);
  uint32_t htonl(uint32_t h);
  uint16_t htons(uint16_t h);
  const char* inet_ntop(int af, const void *src, char *dst, unsigned int size);

  /* ── Sockets UDP (pour send_refused) ── */
  typedef unsigned int socklen_t;

  struct sockaddr {
    uint16_t sa_family;
    char     sa_data[14];
  };

  struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint8_t  sin_addr[4];
    uint8_t  sin_zero[8];
  };

  struct sockaddr_in6 {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t  sin6_addr[16];
    uint32_t sin6_scope_id;
  };

  int     socket(int domain, int type, int protocol);
  int     bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  int     setsockopt(int sockfd, int level, int optname,
                     const void *optval, socklen_t optlen);
  ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                 const struct sockaddr *dest_addr, socklen_t addrlen);
]])
ffi.cdef([[  /* ── Types opaques ── */
  typedef struct nfq_handle   nfq_handle;
  typedef struct nfq_q_handle nfq_q_handle;
  typedef struct nfgenmsg     nfgenmsg;
  typedef struct nfq_data     nfq_data;

  /* ── Métadonnées du paquet nfqueue (L3+) ── */
  typedef struct {
    uint32_t packet_id;    /* id unique dans la queue (big-endian) */
    uint16_t hw_protocol;  /* protocole hw (big-endian) */
    uint8_t  hook;         /* hook netfilter déclencheur */
  } nfqnl_msg_packet_hdr;

  /* ── Métadonnées hardware (L2) ── */
  typedef struct {
    uint16_t hw_addrlen;
    uint16_t pad;
    uint8_t  hw_addr[8];   /* adresse MAC src, 0-paddée à 8 octets */
  } nfqnl_msg_packet_hw;

  /* ── Type du callback ── */
  typedef int (*nfq_callback)(nfq_q_handle *qh,
                               nfgenmsg     *nfmsg,
                               nfq_data     *nfad,
                               void         *data);

  /* ── Cycle de vie ── */
  nfq_handle*   nfq_open(void);
  int           nfq_close(nfq_handle *h);
  int           nfq_bind_pf(nfq_handle *h, uint16_t pf);
  nfq_q_handle* nfq_create_queue(nfq_handle *h, uint16_t num,
                                  nfq_callback cb, void *data);
  int           nfq_destroy_queue(nfq_q_handle *qh);

  /* ── Configuration de la queue ── */
  int nfq_set_mode(nfq_q_handle *qh, uint8_t mode, uint32_t range);

  /* ── Boucle événementielle ── */
  int nfq_fd(nfq_handle *h);
  int nfq_handle_packet(nfq_handle *h, char *buf, int len);

  /* ── Extraction des métadonnées du paquet ── */
  nfqnl_msg_packet_hdr* nfq_get_msg_packet_hdr(nfq_data *nfad);
  int                  nfq_get_payload(nfq_data *nfad, unsigned char **data);
  nfqnl_msg_packet_hw* nfq_get_packet_hw(nfq_data *nfad);
  int                  nfq_get_indev(nfq_data *nfad);  /* index interface entrée */

  /* ── Verdict ── */
  /* verdict simple (sans modification du paquet) */
  int nfq_set_verdict(nfq_q_handle *qh, uint32_t id,
                      uint32_t verdict, uint32_t datalen,
                      const unsigned char *buf);
]])
ffi.cdef([[  typedef struct nft_ctx nft_ctx;

  /* Crée / détruit un contexte nftables */
  nft_ctx* nft_ctx_new(unsigned int flags);
  void     nft_ctx_free(nft_ctx *ctx);

  /* Supprime la sortie standard/erreur (on n'en a pas besoin) */
  void nft_ctx_set_dry_run(nft_ctx *ctx, bool dry);

  /* Exécute une commande nft sous forme de chaîne C */
  /* Retourne 0 en cas de succès */
  int nft_run_cmd_from_buffer(nft_ctx *ctx, const char *buf);
]])
local try_load
try_load = function(names)
  for _index_0 = 1, #names do
    local name = names[_index_0]
    local ok, lib = pcall(ffi.load, name)
    if ok then
      return lib
    end
  end
  return error("ffi_defs: cannot load any of: " .. tostring(table.concat(names, ', ')))
end
local libc = ffi.C
local libnfq = try_load({
  "netfilter_queue",
  "libnetfilter_queue.so.1"
})
local libnft = try_load({
  "nftables",
  "libnftables.so.1"
})
return {
  ffi = ffi,
  libc = libc,
  libnfq = libnfq,
  libnft = libnft
}
