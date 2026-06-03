-- src/lib/os_constants.moon
-- Sonde les constantes Linux dépendantes de l'architecture à l'exécution,
-- en interrogeant le noyau plutôt qu'en hardcodant des valeurs x86.
--
-- Méthodes de sonde :
--   fcntl F_SETFL/F_GETFL : O_NONBLOCK, O_APPEND  (flags de statut fd)
--   sigprocmask(how, vide) : SIG_BLOCK             (premier 'how' valide)
--   setsockopt/getsockopt  : SOL_SOCKET, SO_REUSEADDR, SO_REUSEPORT
--   open + unlink sur /tmp : O_CREAT, O_EXCL       (flags d'ouverture)

ffi = require "ffi"
bit = require "bit"

-- Déclarations minimales — pcall par groupe pour tolérer les doublons
-- (ffi_defs ou socket.moon peut avoir chargé certains symboles avant nous).
for _, c in ipairs {
  "typedef struct { uint8_t _opaque[128]; } sigset_t_custos;"
  [[int pipe2(int pipefd[2], int flags);
    int fcntl(int fd, int cmd, long arg);
    int close(int fd);
    int sigprocmask(int how, const sigset_t_custos *set,
                    sigset_t_custos *oldset);]]
  [[int open(const char *path, int flags, ...);
    int unlink(const char *path);]]
  [[int socket(int domain, int type, int protocol);
    int setsockopt(int fd, int level, int optname,
                   const void *optval, unsigned int optlen);
    int getsockopt(int fd, int level, int optname,
                   void *optval, unsigned int *optlen);]]
}
  pcall ffi.cdef, c

C       = ffi.C
F_GETFL = 3
F_SETFL = 4

-- ── Flags fcntl (O_NONBLOCK, O_APPEND) ──────────────────────────────────────
-- Crée un pipe sans flag, applique F_SETFL(candidat), lit F_GETFL :
-- seul le vrai flag de statut persiste dans la réponse du noyau.
probe_fcntl_flag = (candidates) ->
  fds = ffi.new "int[2]"
  return candidates[1] if C.pipe2(fds, 0) != 0
  result = candidates[1]
  for _, v in ipairs candidates
    C.fcntl fds[0], F_SETFL, v
    flags = C.fcntl fds[0], F_GETFL, 0
    if bit.band(flags, v) != 0
      result = v
      break
  C.close fds[0]
  C.close fds[1]
  result

-- ── SIG_BLOCK ────────────────────────────────────────────────────────────────
-- Masque vide → aucun signal modifié. SIG_BLOCK est toujours la plus petite
-- valeur 'how' valide : la première qui retourne 0 est la bonne.
probe_sig_block = ->
  mask = ffi.new "sigset_t_custos"
  ffi.fill mask, 128, 0
  for _, v in ipairs {0, 1, 2, 3}
    return v if C.sigprocmask(v, mask, nil) == 0
  0

-- ── O_CREAT / O_EXCL ────────────────────────────────────────────────────────
-- Tente d'ouvrir un fichier inexistant avec O_WRONLY | candidat :
-- si le fd est valide, le noyau a créé le fichier → candidat = O_CREAT.
-- O_EXCL est ensuite vérifié en combinaison avec le O_CREAT trouvé.
probe_creat_excl = ->
  path    = "/tmp/.custos_ocr_probe"
  o_wronly = 1
  creat, excl = 0x40, 0x80   -- valeurs x86 par défaut

  C.unlink path  -- s'assurer que le fichier n'existe pas
  for _, v in ipairs {0x40, 0x100}  -- x86=64, MIPS=256
    fd = C.open path, bit.bor(o_wronly, v), 0600
    if fd >= 0
      C.close fd
      C.unlink path
      creat = v
      break

  -- O_EXCL : avec le bon O_CREAT, la seconde ouverture doit échouer (fd<0)
  for _, v in ipairs {0x80, 0x400}  -- x86=128, MIPS=1024
    fd1 = C.open path, bit.bor(o_wronly, creat), 0600
    C.close fd1 if fd1 >= 0
    fd2 = C.open path, bit.bor(o_wronly, creat, v), 0600
    if fd2 < 0  -- EEXIST → bonne valeur d'O_EXCL
      C.unlink path
      excl = v
      break
    C.close fd2
    C.unlink path

  creat, excl

-- ── SOL_SOCKET / SO_REUSEADDR / SO_REUSEPORT ────────────────────────────────
-- Socket UDP temporaire : setsockopt(1) + getsockopt → lit 1 en retour
-- si et seulement si (level, optname) sont les bonnes valeurs.
probe_socket_constants = ->
  fd = C.socket 2, 2, 0   -- AF_INET=2, SOCK_DGRAM=2
  if fd < 0
    return 1, 2, 15        -- fallback x86

  val    = ffi.new "int[1]"
  optlen = ffi.new "uint32_t[1]"
  sol, reuseaddr, reuseport = 1, 2, 15

  found = false
  for _, lv in ipairs {1, 0xFFFF}             -- x86=1, MIPS=0xFFFF
    for _, ra in ipairs {2, 4}                  -- x86=2, MIPS=4
      val[0] = 1
      C.setsockopt fd, lv, ra, val, 4
      val[0] = 0
      optlen[0] = 4
      C.getsockopt fd, lv, ra, val, optlen
      if val[0] == 1
        sol, reuseaddr = lv, ra
        found = true
        break
    break if found

  for _, rp in ipairs {15, 0x200}              -- x86=15, MIPS=0x200
    val[0] = 1
    C.setsockopt fd, sol, rp, val, 4
    val[0] = 0
    optlen[0] = 4
    C.getsockopt fd, sol, rp, val, optlen
    if val[0] == 1
      reuseport = rp
      break

  C.close fd
  sol, reuseaddr, reuseport

-- ── Résultats ────────────────────────────────────────────────────────────────

sol, reuseaddr, reuseport = probe_socket_constants!
o_creat, o_excl           = probe_creat_excl!

{
  O_NONBLOCK:   probe_fcntl_flag {0x80, 0x800, 0x4000}   -- MIPS=0x80, x86=0x800
  O_APPEND:     probe_fcntl_flag {0x8, 0x400, 0x2000}    -- MIPS=0x8,  x86=0x400
  O_CREAT:      o_creat
  O_EXCL:       o_excl
  SIG_BLOCK:    probe_sig_block!
  SOL_SOCKET:   sol
  SO_REUSEADDR: reuseaddr
  SO_REUSEPORT: reuseport
}
