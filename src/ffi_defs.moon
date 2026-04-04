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

  /* ── Fichiers ── */
  int     open(const char *path, int flags, ...);
  ssize_t write(int fd, const void *buf, size_t n);
  ssize_t read(int fd, void *buf, size_t n);
  int     close(int fd);
  int     fcntl(int fd, int cmd, ...);

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

  /* ── Réseau ── */
  uint32_t ntohl(uint32_t n);
  uint16_t ntohs(uint16_t n);
  uint32_t htonl(uint32_t h);
  uint16_t htons(uint16_t h);
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
  uint32_t             nfq_get_msg_packet_hdr(nfq_data *nfad);
  int                  nfq_get_payload(nfq_data *nfad, unsigned char **data);
  nfqnl_msg_packet_hw* nfq_get_packet_hw(nfq_data *nfad);
  int                  nfq_get_indev(nfq_data *nfad);  /* index interface entrée */

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

  /* Exécute une commande nft sous forme de chaîne C */
  /* Retourne 0 en cas de succès */
  int nft_run_cmd_from_buffer(nft_ctx *ctx, const char *buf);
]]

-- ═══════════════════════════════════════════════════════════════
-- Chargement des bibliothèques
-- ═══════════════════════════════════════════════════════════════
libc    = ffi.C
libnfq  = ffi.load "netfilter_queue"
libnft  = ffi.load "nftables"

-- ── Export ──────────────────────────────────────────────────────
{ :ffi, :libc, :libnfq, :libnft }
