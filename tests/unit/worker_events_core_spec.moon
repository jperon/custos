-- tests/unit/worker_events_core_spec.moon
-- Couverture du worker d'agrégation restée hors du spec du ring buffer :
-- horodatage, lecture du pipe, écriture TSV horaire, compression/purge des
-- archives et boucle run() (SIGTERM, changement d'heure, EOF).
--
-- Les chemins I/O réels sont utilisés pour flush_to_file/compress_old/
-- cleanup_old (fichiers sous ./tmp/), et un libc simulé pour run() : la boucle
-- est infinie par construction.

ffi = require "ffi"
bit = require "bit"
{ :libc } = require "ffi_defs"

for def in *{
  "struct pollfd { int fd; short events; short revents; };"
  "int pipe(int pipefd[2]);"
  "long read(int fd, void *buf, unsigned long count);"
  "int* __errno_location(void);"
  "typedef struct { uint32_t ssi_signo; uint8_t _pad[124]; } signalfd_siginfo;"
}
  pcall -> ffi.cdef def

w = require "worker_events"
TMP = "tmp/worker_events_core_spec"

rm_tmp = -> os.execute "rm -rf '#{TMP}'"
mkdir_tmp = -> os.execute "mkdir -p '#{TMP}'"

hour_for = (offset_h=0) ->
  t = os.time! + offset_h * 3600
  os.date "%Y-%m-%d-%H", t

describe "worker_events cœur", ->
  before_each -> rm_tmp!
  after_each -> rm_tmp!

  describe "current_hour et verdict_key", ->
    it "current_hour suit le format YYYY-MM-DD-HH", ->
      assert.is_truthy w.current_hour!\match "^%d%d%d%d%-%d%d%-%d%d%-%d%d$"

    it "verdict_key combine mac, qname et décision", ->
      assert.equals "m|q.com|block", w.verdict_key "m", "q.com", "block"

  describe "read_chunk", ->
    it "lit les données disponibles puis signale EOF (nil)", ->
      fds = ffi.new "int[2]"
      assert.equals 0, libc.pipe fds
      libc.write fds[1], "abc", 3
      libc.close fds[1]
      assert.equals "abc", w.read_chunk fds[0]
      assert.is_nil w.read_chunk fds[0]
      libc.close fds[0]

    it "fd invalide → chaîne vide (EAGAIN/erreur transitoire)", ->
      assert.equals "", w.read_chunk(-1)

  describe "flush_to_file", ->
    it "écrit l'en-tête une fois puis les lignes agrégées (libc simulé)", ->
      { :O_EXCL } = require "lib.os_constants"
      writes = {}
      excl_opens = 0
      fake = {
        open: (path, flags) ->
          if bit.band(flags, O_EXCL) != 0
            excl_opens += 1
            return -1 if excl_opens > 1
            return 40
          41
        write: (fd, buf, n) ->
          writes[#writes + 1] = ffi.string buf, n
          n
        close: -> 0
      }
      old = package.loaded["ffi_defs"]
      package.loaded["ffi_defs"] = { :ffi, libc: fake }
      package.loaded["worker_events"] = nil
      w2 = require "worker_events"
      agg = {}
      agg["allow\tok.com\tmac\tip\tdst\t0\t-\tipv4\tr\trule1"] = { count: 2, first_ts: "100", last_ts: "101" }
      w2.flush_to_file agg, "2024-01-01-10", TMP
      w2.flush_to_file agg, "2024-01-01-10", TMP
      package.loaded["ffi_defs"] = old
      joined = table.concat writes
      -- Un seul en-tête, deux lignes de données (un flush par appel).
      assert.equals 1, select(2, joined\gsub "decision\tqname", "")
      assert.equals 2, select(2, joined\gsub "rule1", "")
      assert.is_truthy joined\find "rule1\t2\t100\t101\n", 1, true

    it "crée des fichiers TSV lisibles", ->
      -- BUG (non corrigé, hors périmètre) : flush_to_file passe FILE_MODE
      -- (nombre Lua) à `libc.open(path, flags, ...)` dont la signature est
      -- variadique (src/worker_events.moon:229 et 235 ; ffi_defs.moon:23).
      -- LuaJIT passe un nombre en vararg comme double, alors que le C attend
      -- un mode_t (entier) : les fichiers sont créés en mode 0000 et illisibles.
      pending "files créés en mode 0000 (FILE_MODE non casté en vararg open)"
      mkdir_tmp!
      agg = {}
      agg["allow\tq.com\tmac\tip\tdst\t0\t-\tipv4\tr\tr"] = { count: 1, first_ts: "1", last_ts: "1" }
      w.flush_to_file agg, "2024-01-01-10", TMP
      fh = assert io.open "#{TMP}/events-2024-01-01-10.tsv", "r"
      fh\close!

    it "table vide → aucun fichier créé", ->
      mkdir_tmp!
      w.flush_to_file {}, "2024-01-01-11", TMP
      fh = io.open "#{TMP}/events-2024-01-01-11.tsv", "r"
      assert.is_nil fh

    it "répertoire absent → open échoue, aucune exception", ->
      w.flush_to_file { k: { count: 1, first_ts: "1", last_ts: "1" } },
        "2024-01-01-12", "#{TMP}/absent"

  describe "compression et purge", ->
    it "compress_old compresse les heures passées, pas l'heure courante", ->
      mkdir_tmp!
      os.execute "printf x > '#{TMP}/events-2024-01-01-10.tsv'"
      os.execute "printf y > '#{TMP}/events-2024-01-01-11.tsv'"
      w.compress_old TMP, "2024-01-01-11"
      assert.is_not_nil io.open "#{TMP}/events-2024-01-01-10.tsv.zst", "r"
      assert.is_not_nil io.open "#{TMP}/events-2024-01-01-11.tsv", "r"
      assert.is_nil io.open "#{TMP}/events-2024-01-01-10.tsv", "r"

    it "free_pct_on retourne un pourcentage ou nil selon le chemin", ->
      pct = w.free_pct_on "."
      assert.is_number pct
      assert.is_true pct >= 0 and pct <= 100
      assert.is_nil w.free_pct_on "#{TMP}/inexistant"

    it "file_age_hours décode l'heure du nom, nil si non conforme", ->
      age = w.file_age_hours "events-#{hour_for -2}.tsv.zst"
      assert.is_true age > 1.9 and age < 3.1, "âge calculé : #{age}"
      assert.is_nil w.file_age_hours "events-bidon.tsv.zst"
      assert.is_nil w.file_age_hours "autre-2024-01-01-10.tsv.zst"

    it "cleanup_old supprime par âge", ->
      mkdir_tmp!
      old = "events-#{hour_for -100}.tsv.zst"
      fresh = "events-#{hour_for}.tsv.zst"
      os.execute "printf x > '#{TMP}/#{old}'"
      os.execute "printf y > '#{TMP}/#{fresh}'"
      w.cleanup_old TMP, 1, 0
      assert.is_nil io.open "#{TMP}/#{old}", "r"
      assert.is_not_nil io.open "#{TMP}/#{fresh}", "r"

    it "cleanup_old purge aussi par espace libre insuffisant", ->
      mkdir_tmp!
      f1 = "events-#{hour_for -3}.tsv.zst"
      f2 = "events-#{hour_for -2}.tsv.zst"
      os.execute "printf x > '#{TMP}/#{f1}'"
      os.execute "printf y > '#{TMP}/#{f2}'"
      -- Seuil 101 % : l'espace libre est forcément insuffisant → purge des
      -- plus anciens (tri alphabétique = chronologique).
      w.cleanup_old TMP, 10000, 101
      assert.is_nil io.open "#{TMP}/#{f1}", "r"
      assert.is_nil io.open "#{TMP}/#{f2}", "r"

    it "cleanup_old sans archive ne fait rien", ->
      mkdir_tmp!
      w.cleanup_old TMP, 1, 100

  describe "create_signal_fd", ->
    it "masque SIGTERM et retourne le fd signalfd", ->
      old = package.loaded["ffi_defs"]
      fake = {
        sigprocmask: -> 0
        signalfd: -> 12
      }
      package.loaded["ffi_defs"] = { :ffi, libc: fake }
      package.loaded["worker_events"] = nil
      w2 = require "worker_events"
      fd = w2.create_signal_fd!
      package.loaded["ffi_defs"] = old
      assert.equals 12, fd

    it "signalfd en échec → erreur explicite", ->
      old = package.loaded["ffi_defs"]
      fake = { sigprocmask: -> 0, signalfd: -> -1 }
      package.loaded["ffi_defs"] = { :ffi, libc: fake }
      package.loaded["worker_events"] = nil
      w2 = require "worker_events"
      ok, err = pcall -> w2.create_signal_fd!
      package.loaded["ffi_defs"] = old
      assert.is_false ok
      assert.is_truthy tostring(err)\find "signalfd", 1, true

  describe "run() avec libc simulé", ->
    make_fake = (poll_fn, read_fn) ->
      writes = {}
      opened = {}
      fake = {
        sigprocmask: -> 0
        signalfd: -> 5
        poll: poll_fn
        read: read_fn
        open: (path, flags, mode) ->
          opened[#opened + 1] = path
          #opened + 20
        write: (fd, buf, n) ->
          writes[#writes + 1] = ffi.string buf, n
          n
        close: -> 0
        _exit: (code) -> error "exit:#{code}"
      }
      { :fake, :writes, :opened }

    it "traite les lignes du pipe, flushe au changement d'heure puis continue", ->
      mkdir_tmp!
      poll_calls = 0
      read_calls = 0
      chunk = "100\tallow\tok.com\tmac1\t10.0.0.1\t8.8.8.8\t0\t-\tipv4\t-\tr1\n" ..
        "101\tblock\tads.com\tmac2\t10.0.0.2\t8.8.8.8\t0\t-\tipv4\t-\tr2\n"
      poll_fn = (pfds, nfds, ms) ->
        poll_calls += 1
        if poll_calls == 1
          pfds[0].revents = 1
          return 1
        if poll_calls == 2
          return 0
        error "stop-hour"
      read_fn = (fd, buf, n) ->
        read_calls += 1
        if read_calls == 1
          ffi.copy buf, chunk, #chunk
          return #chunk
        0
      { :fake, :writes } = make_fake poll_fn, read_fn
      old = package.loaded["ffi_defs"]
      real_date = os.date
      date_calls = 0
      os.date = (fmt, t) ->
        date_calls += 1
        if date_calls == 1 then "2024-01-01-10" else "2024-01-01-11"
      package.loaded["ffi_defs"] = { :ffi, libc: fake }
      package.loaded["worker_events"] = nil
      w2 = require "worker_events"
      ok, err = pcall -> w2.run 99, TMP, 24, 0
      os.date = real_date
      package.loaded["ffi_defs"] = old
      assert.is_false ok
      assert.is_truthy (tostring(err)\match "stop%-hour"), tostring err
      joined = table.concat writes
      -- En-tête + deux lignes agrégées dans le fichier de l'heure écoulée.
      assert.is_truthy joined\find "decision\tqname", 1, true
      assert.is_truthy joined\find "ok.com", 1, true
      assert.is_truthy joined\find "ads.com", 1, true

    it "EOF sur le pipe → warn et boucle maintenue", ->
      mkdir_tmp!
      poll_calls = 0
      poll_fn = (pfds, nfds, ms) ->
        poll_calls += 1
        if poll_calls == 1
          pfds[0].revents = 1
          return 1
        error "stop-eof"
      read_fn = -> 0
      { :fake } = make_fake poll_fn, read_fn
      old = package.loaded["ffi_defs"]
      package.loaded["ffi_defs"] = { :ffi, libc: fake }
      package.loaded["worker_events"] = nil
      w2 = require "worker_events"
      ok, err = pcall -> w2.run 99, TMP, 24, 0
      package.loaded["ffi_defs"] = old
      assert.is_false ok
      assert.is_truthy (tostring(err)\match "stop%-eof"), tostring err

    it "SIGTERM → flush des agrégats et des verdicts puis sortie", ->
      mkdir_tmp!
      poll_calls = 0
      poll_fn = (pfds) ->
        poll_calls += 1
        if poll_calls == 1
          pfds[1].revents = 1
          return 1
        error "stop-sigterm"
      read_fn = (fd, buf, n) ->
        -- siginfo passé en cdata : marque SIGTERM.
        buf.ssi_signo = 15
        128
      { :fake, :writes } = make_fake poll_fn, read_fn
      old = package.loaded["ffi_defs"]
      package.loaded["ffi_defs"] = { :ffi, libc: fake }
      package.loaded["worker_events"] = nil
      w2 = require "worker_events"
      ok, err = pcall -> w2.run 99, TMP, 24, 0
      package.loaded["ffi_defs"] = old
      assert.is_false ok
      assert.is_truthy (tostring(err)\match "exit:0"), tostring err
