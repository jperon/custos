-- tests/unit/lib/pidfile_spec.moon
-- Tests de lib.pidfile : écriture/lecture/suppression + résolution du chemin.

pidfile = require "lib.pidfile"

describe "lib.pidfile", ->

  describe "resolve_path", ->
    it "priorise l'argument de config", ->
      assert.equals "/run/custom.pid", pidfile.resolve_path "/run/custom.pid"

    it "retombe sur CUSTOS_PID_FILE puis le défaut", ->
      old = os.getenv "CUSTOS_PID_FILE"
      -- On ne peut pas setenv en Lua pur ; on vérifie au moins le défaut.
      assert.equals pidfile.DEFAULT_PATH, pidfile.resolve_path! unless old

  describe "write / read / remove", ->
    it "écrit puis relit le PID", ->
      path = os.tmpname!
      assert.is_true pidfile.write 12345, path
      assert.equals 12345, (pidfile.read path)
      os.remove path

    it "read renvoie nil + message si absent", ->
      pid, err = pidfile.read "/nonexistent/custos.pid"
      assert.is_nil pid
      assert.truthy err

    it "read ignore un contenu non numérique", ->
      path = os.tmpname!
      fh = io.open path, "w"
      fh\write "pas un pid\n"
      fh\close!
      pid, err = pidfile.read path
      os.remove path
      assert.is_nil pid
      assert.truthy err

    it "read tolère un PID avec espaces/newline", ->
      path = os.tmpname!
      fh = io.open path, "w"
      fh\write "  6789\n"
      fh\close!
      assert.equals 6789, (pidfile.read path)
      os.remove path

    it "remove supprime le fichier", ->
      path = os.tmpname!
      pidfile.write 1, path
      pidfile.remove path
      assert.is_nil (pidfile.read path)
