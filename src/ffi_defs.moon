-- src/ffi_defs.moon
-- Déclarations FFI centralisées : libnetfilter_queue, libnftables, libc.
-- Chargé une seule fois par worker via require().
-- Regrouper ici évite les redéclarations et documente l'ABI utilisée.

ffi = require "ffi"

-- ═══════════════════════════════════════════════════════════════
-- libc — primitives POSIX utilisées
-- ═══════════════════════════════════════════════════════════════
ffi.cdef [[
  /* ── Types de base ── */
  typedef long          ssize_t;
  typedef unsigned long size_t;
  typedef int           pid_t;

  /* ── Temps ── */
  typedef struct { long tv_sec; long tv_nsec; } timespec_t;
  int clock_gettime(int clk_id, timespec_t *tp);
  int nanosleep(const timespec_t *req, timespec_t *rem);

  /* ── Fichiers ── */
  int     open(const char *path, int flags, ...);
  ssize_t write(int fd, const void *buf, size_t n);
  ssize_t read(int fd, void *buf, size_t n);
  int     close(int fd);
  long    lseek(int fd, long offset, int whence);

  /* ── statx : signature de fichier portable (ABI noyau stable, identique
        sur toutes les architectures, contrairement à `struct stat`). Sert à
        détecter sans coût qu'un fichier de sessions n'a PAS changé. ── */
  struct statx_timestamp { int64_t tv_sec; uint32_t tv_nsec; int32_t __reserved; };
  struct statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __spare0[1];
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct statx_timestamp stx_atime;
    struct statx_timestamp stx_btime;
    struct statx_timestamp stx_ctime;
    struct statx_timestamp stx_mtime;
    uint32_t stx_rdev_major; uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;  uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;
    uint64_t __spare2;
    uint64_t __spare3[12];
  };
  int statx(int dirfd, const char *pathname, int flags,
            unsigned int mask, struct statx *statxbuf);

  /* ── Mémoire (mmap lecture seule partagée des listes .bin) ── */
  void*   mmap(void *addr, size_t length, int prot, int flags, int fd, long offset);
  int     munmap(void *addr, size_t length);

  /* ── Processus ── */
  pid_t getpid(void);
  pid_t getppid(void);
  pid_t fork(void);
  pid_t waitpid(pid_t pid, int *status, int options);
  void  _exit(int status);
  int   prctl(int option, unsigned long a2, unsigned long a3,
              unsigned long a4, unsigned long a5);
  int   kill(pid_t pid, int sig);

  /* ── signalfd (Linux) — signaux → fd lisible, sans handler async ── */
  typedef struct { uint8_t _opaque[128]; } sigset_t_custos;
  int sigprocmask(int how, const sigset_t_custos *set,
                  sigset_t_custos *oldset);
  int signalfd(int fd, const sigset_t_custos *mask, int flags);
  typedef struct {
    uint32_t ssi_signo;
    uint8_t  _pad[124];
  } signalfd_siginfo;

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

  /* ── Réseau (network utilities) ── */
  uint32_t ntohl(uint32_t n);
  uint16_t ntohs(uint16_t n);
  uint32_t htonl(uint32_t h);
  uint16_t htons(uint16_t h);
  const char* inet_ntop(int af, const void *src, char *dst, unsigned int size);
  int          inet_pton(int af, const char *src, void *dst);

  /* ── I/O multiplexing (poll, select) ── */
  struct pollfd {
    int   fd;
    short events;
    short revents;
  };
  int poll(struct pollfd *fds, unsigned long nfds, int timeout);

  typedef long __fd_mask;
  struct fd_set {
    __fd_mask __fds_bits[16];
  };
  struct timeval {
    long tv_sec;
    long tv_usec;
  };
  int select(int nfds, struct fd_set *readfds, struct fd_set *writefds,
             struct fd_set *exceptfds, struct timeval *timeout);

  /* ── AF_UNIX & AF_PACKET raw sockets (non-TCP) ── */
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

  /* Core socket operations */
  int     socket(int domain, int type, int protocol);
  int     bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  int     listen(int sockfd, int backlog);
  int     accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  int     connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  int     close(int fd);
  ssize_t send(int sockfd, const void *buf, size_t len, int flags);
  ssize_t recv(int sockfd, void *buf, size_t len, int flags);
  int     setsockopt(int sockfd, int level, int optname,
                     const void *optval, socklen_t optlen);
  int     getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  int     getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

  struct sockaddr_un {
    uint16_t sun_family;
    char     sun_path[108];
  };

  unsigned int if_nametoindex(const char *ifname);

  struct sockaddr_ll {
    unsigned short sll_family;
    unsigned short sll_protocol;
    int            sll_ifindex;
    unsigned short sll_hatype;
    unsigned char  sll_pkttype;
    unsigned char  sll_halen;
    unsigned char  sll_addr[8];
  };

  /* ── Packet socket options (SOL_PACKET) ── */
  struct packet_mreq {
    int            mr_ifindex;
    unsigned short mr_type;
    unsigned short mr_alen;
    unsigned char  mr_address[8];
  };

  /* ── Raw operations for AF_PACKET ── */
  ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                 const struct sockaddr *dest_addr, socklen_t addrlen);

  /* ── File operations ── */
  int     unlink(const char *pathname);
]]

-- ═══════════════════════════════════════════════════════════════
-- libnetfilter_queue
-- ═══════════════════════════════════════════════════════════════
ffi.cdef [[
  /* ── Types opaques ── */
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
  uint32_t             nfq_get_nfmark(nfq_data *nfad);

  /* ── Verdict ── */
  /* verdict simple (sans modification du paquet) */
  int nfq_set_verdict(nfq_q_handle *qh, uint32_t id,
                      uint32_t verdict, uint32_t datalen,
                      const unsigned char *buf);
]]

-- ═══════════════════════════════════════════════════════════════
-- libnftables — injection de commandes nft sans fork
-- ═══════════════════════════════════════════════════════════════
ffi.cdef [[
  typedef struct nft_ctx nft_ctx;

  /* Crée / détruit un contexte nftables */
  nft_ctx* nft_ctx_new(unsigned int flags);
  void     nft_ctx_free(nft_ctx *ctx);

  /* Supprime la sortie standard/erreur (on n'en a pas besoin) */
  void nft_ctx_set_dry_run(nft_ctx *ctx, bool dry);
  int  nft_ctx_buffer_error(nft_ctx *ctx);
  const char *nft_ctx_get_error_buffer(nft_ctx *ctx);

  /* Exécute une commande nft sous forme de chaîne C */
  /* Retourne 0 en cas de succès */
  int nft_run_cmd_from_buffer(nft_ctx *ctx, const char *buf);
]]

-- ═══════════════════════════════════════════════════════════════
-- libwolfssl (TLS/SSL library)
-- ═══════════════════════════════════════════════════════════════
ffi.cdef [[
  /* ── Types opaques WolfSSL ── */
  typedef struct WOLFSSL_CTX WOLFSSL_CTX;
  typedef struct WOLFSSL     WOLFSSL;
  typedef struct WOLFSSL_METHOD WOLFSSL_METHOD;

  /* ── Méthodes TLS ── */
  WOLFSSL_METHOD* TLSv1_2_server_method(void);
  WOLFSSL_METHOD* TLSv1_2_client_method(void);
  WOLFSSL_METHOD* TLS_server_method(void);
  WOLFSSL_METHOD* TLS_client_method(void);

  /* ── Gestion du contexte ── */
  WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD *method);
  void         wolfSSL_CTX_free(WOLFSSL_CTX *ctx);
  int          wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX *ctx,
                                                const char *file, int type);
  int          wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX *ctx,
                                               const char *file, int type);

  /* ── Gestion de la connexion ── */
  WOLFSSL* wolfSSL_new(WOLFSSL_CTX *ctx);
  void     wolfSSL_free(WOLFSSL *ssl);
  int      wolfSSL_set_fd(WOLFSSL *ssl, int fd);
  int      wolfSSL_get_fd(WOLFSSL *ssl);

  /* ── Handshake et I/O ── */
  int wolfSSL_connect(WOLFSSL *ssl);
  int wolfSSL_accept(WOLFSSL *ssl);
  int wolfSSL_write(WOLFSSL *ssl, const void *data, int sz);
  int wolfSSL_read(WOLFSSL *ssl, void *data, int sz);
  int wolfSSL_shutdown(WOLFSSL *ssl);

  /* ── Codes d'erreur ── */
  int wolfSSL_get_error(WOLFSSL *ssl, int ret);

  /* ── Constantes ── */
]]

-- ═══════════════════════════════════════════════════════════════
-- Chargement des bibliothèques
-- ═══════════════════════════════════════════════════════════════

--- Tente de charger une bibliothèque parmi plusieurs noms candidats.
-- Utile pour gérer les noms sans version (``netfilter_queue``) et les
-- noms versionnés Debian (``libnetfilter_queue.so.1``).
-- Ajoute un fallback: scanner /usr/lib et /lib pour trouver des fichiers correspondants.
-- @tparam table names  Liste ordonnée de noms à essayer
-- @treturn cdata       Bibliothèque FFI chargée
-- @raise  string       Si aucun nom ne peut être chargé
try_load = (names) ->
  for name in *names
    ok, lib = pcall ffi.load, name
    return lib if ok

  -- Fallback: scan filesystem for any matching library file
  for name in *names
    prefix = name\gsub("%.so.*$", "")  -- Remove version suffix
    cmd = "find /usr/lib /lib -name '" .. prefix .. "*.so*' -type f 2>/dev/null | sort -V | tail -1"
    f = io.popen(cmd)
    path = f\read("*a")\gsub("\n", "")
    f\close!

    if path and path ~= ""
      ok, lib = pcall ffi.load, path
      return lib if ok

  error "ffi_defs: cannot load any of: #{table.concat names, ', '}"

libc    = ffi.C
libnfq  = try_load { "netfilter_queue", "libnetfilter_queue.so.1" }
libnft  = try_load { "nftables", "libnftables.so.1" }

-- ── Export ──────────────────────────────────────────────────────
libwolfssl = try_load { "wolfssl", "libwolfssl.so.5.7.6.e624513f", "libwolfssl.so.5", "libwolfssl.so" }

-- ── Export ──────────────────────────────────────────────────
{ :ffi, :libc, :libnfq, :libnft, :libwolfssl }
