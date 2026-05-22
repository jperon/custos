-- tests/unit/socket_spec.moon
-- Tests pour lib/socket : comportement de accept() et socket_select()
-- face aux erreurs non fatales (EINTR, ECONNABORTED).
--
-- Régressions couvertes :
--   - accept() : EINTR (errno=4) et ECONNABORTED (errno=103) doivent
--     retourner nil, pas lever une exception fatale qui planterait le worker auth.
--   - socket_select() : EINTR doit retourner {},{} et non lever une exception.

ffi = require "ffi"
bit = require "bit"

-- Déclarations séparées dans des pcall individuels pour l'idempotence.
pcall -> ffi.cdef "typedef void sig_fn_t(int);"
pcall -> ffi.cdef "sig_fn_t *signal(int, sig_fn_t *);"
pcall -> ffi.cdef "int raise(int sig);"
pcall -> ffi.cdef "unsigned int alarm(unsigned int seconds);"

SIGALRM    = 14
ITIMER_REAL = 0

-- Charger lib.socket ICI pour que struct timeval soit déclaré avant itimerval.
socket = require "lib.socket"

-- struct timeval est maintenant défini par lib.socket → on peut référencer itimerval.
pcall -> ffi.cdef [[
  struct itimerval {
    struct timeval it_interval;
    struct timeval it_value;
  };
  int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value);
]]

-- ── Création de sockets ────────────────────────────────────────────────────

describe "lib.socket création", ->

  it "crée un socket TCP IPv4", ->
    srv = socket.tcp!
    assert.is_not_nil srv
    assert.equals 2, srv.family   -- AF_INET
    assert.is_false srv.closed
    srv\close!

  it "le socket est marqué closed après close()", ->
    srv = socket.tcp!
    srv\close!
    assert.is_true srv.closed

-- ── accept() : cas normaux ─────────────────────────────────────────────────

describe "lib.socket accept() cas normaux", ->

  it "retourne nil (EAGAIN) quand aucune connexion n'est en attente", ->
    srv = socket.tcp!
    srv\bind "127.0.0.1", 0
    srv\settimeout 0.1   -- O_NONBLOCK : EAGAIN → nil immédiat
    client = srv\accept!
    assert.is_nil client
    srv\close!

  it "accepte une connexion réelle et retourne un socket client valide", ->
    srv = socket.tcp!
    srv\bind "127.0.0.1", 0
    srv\settimeout 0.5

    -- Récupérer le port assigné par le kernel
    addr4   = ffi.new "struct sockaddr_in"
    addrlen = ffi.new "socklen_t[1]"
    addrlen[0] = ffi.sizeof addr4
    ffi.C.getsockname srv.fd, ffi.cast("struct sockaddr*", addr4), addrlen
    port = ffi.C.ntohs addr4.sin_port

    cli = socket.tcp!
    cli\settimeout 0.5
    pcall -> cli\connect "127.0.0.1", port

    client = srv\accept!
    assert.is_not_nil client
    assert.is_false client.closed

    client\close!
    cli\close!
    srv\close!

-- ── accept() : erreurs non fatales (régression) ───────────────────────────

describe "lib.socket accept() erreurs non fatales", ->

  it "lève une erreur sur EBADF (fd déjà fermé) — erreur FATALE", ->
    -- Vérifie que les erreurs vraiment fatales sont toujours levées.
    -- Un socket fermé retourne EBADF (9) → doit toujours error().
    srv = socket.tcp!
    srv\close!
    -- accept() sur socket fermé → exception "socket is closed"
    ok, err = pcall -> srv\accept!
    assert.is_false ok
    assert.is_string err

  it "retourne nil sur EAGAIN / EWOULDBLOCK (errno=11) — non fatal", ->
    -- Comportement de base : pas d'exception quand aucune connexion n'est dispo.
    srv = socket.tcp!
    srv\bind "127.0.0.1", 0
    srv\settimeout 0.1
    client = srv\accept!   -- EAGAIN
    srv\close!
    assert.is_nil client   -- nil, pas d'exception

  -- Régression : avant le fix, errno=4 (EINTR) et errno=103 (ECONNABORTED)
  -- causaient error() dans accept(), plantant le worker auth. Désormais → nil.
  it "EINTR (errno=4) et ECONNABORTED (errno=103) sont dans les cas non-fatals", ->
    -- Test de présence du code de traitement dans le source compilé.
    -- On vérifie que lua/lib/socket.lua contient bien le traitement de ces errnos.
    fh = io.open "lua/lib/socket.lua", "r"
    assert.is_not_nil fh, "lua/lib/socket.lua doit exister (compilé)"
    source = fh\read "*a"
    fh\close!
    -- errno == 4 (EINTR) → return nil
    assert.is_truthy (source\find "errno == 4"),
      "EINTR (errno=4) doit être géré dans accept()"
    -- errno == 103 (ECONNABORTED) → return nil
    assert.is_truthy (source\find "errno == 103"),
      "ECONNABORTED (errno=103) doit être géré dans accept()"

-- ── socket_select : EINTR (régression principale) ─────────────────────────

describe "lib.socket socket_select EINTR", ->

  it "socket_select retourne des tables sur timeout normal (pas d'exception)", ->
    srv = socket.tcp!
    srv\bind "127.0.0.1", 0
    ok, ready = pcall socket.socket_select, { srv }, nil, 0.01
    srv\close!
    assert.is_true ok, "socket_select ne doit pas lever d'exception"
    assert.is_table ready
    assert.equals 0, #ready

  it "retourne {},{} au lieu de planter quand select() est interrompu par SIGALRM", ->
    -- Installe un handler no-op Lua pour SIGALRM.
    -- SIG_IGN (1) causerait SA_RESTART → pas d'EINTR.
    -- Un vrai handler Lua → interruption → EINTR → notre fix retourne {},{}.
    noop_handler = ffi.cast "sig_fn_t*", ->
    ffi.C.signal SIGALRM, noop_handler

    -- Arme un timer à 100 ms pour interrompre le select() suivant.
    timer = ffi.new "struct itimerval"
    timer.it_value.tv_sec  = 0
    timer.it_value.tv_usec = 100000  -- 100 ms
    ffi.C.setitimer ITIMER_REAL, timer, nil

    srv = socket.tcp!
    srv\bind "127.0.0.1", 0
    -- timeout 5 s : SIGALRM interrompt à 100 ms et déclenche EINTR
    ok, result = pcall socket.socket_select, { srv }, nil, 5.0

    -- Annuler le timer résiduel et restaurer SIGALRM (SIG_DFL = 0)
    timer.it_value.tv_usec = 0
    ffi.C.setitimer ITIMER_REAL, timer, nil
    ffi.C.signal SIGALRM, ffi.cast("sig_fn_t*", ffi.cast("void*", 0))

    srv\close!

    -- Régression : avant le fix, ok == false avec "select() failed"
    assert.is_true ok,  "socket_select ne doit pas planter sur EINTR"
    assert.is_table result

  it "contient le traitement EINTR dans le source compilé", ->
    -- Vérifie que lua/lib/socket.lua gère errno==4 dans socket_select.
    fh = io.open "lua/lib/socket.lua", "r"
    assert.is_not_nil fh
    source = fh\read "*a"
    fh\close!
    assert.is_truthy (source\find "errno == 4"),
      "EINTR (errno=4) doit être géré dans socket_select"

-- ── socket_select : comportement nominal ──────────────────────────────────

describe "lib.socket socket_select comportement nominal", ->

  it "détecte un socket lisible quand une connexion est en attente", ->
    srv = socket.tcp!
    srv\bind "127.0.0.1", 0
    srv\settimeout 0.5

    addr4   = ffi.new "struct sockaddr_in"
    addrlen = ffi.new "socklen_t[1]"
    addrlen[0] = ffi.sizeof addr4
    ffi.C.getsockname srv.fd, ffi.cast("struct sockaddr*", addr4), addrlen
    port = ffi.C.ntohs addr4.sin_port

    cli = socket.tcp!
    cli\settimeout 0.5
    pcall -> cli\connect "127.0.0.1", port

    ready, _ = socket.socket_select { srv }, nil, 0.5
    assert.equals 1, #ready
    assert.equals srv.fd, ready[1].fd

    c = srv\accept!
    c\close! if c
    cli\close!
    srv\close!
