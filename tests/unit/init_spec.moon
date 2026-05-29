-- tests/unit/init_spec.moon
-- Tests de l'UI redbean (.init.lua) : routes, construction de commandes,
-- sanitisation des entrées et échappement HTML de la sortie.
--
-- Stratégie : charger .init.lua une seule fois avec les globals redbean mockés
-- (GetPath, GetMethod, GetParam, SetHeader, SetStatus, Write).
-- 'html' est stubé vers auth.html (normalement embarqué dans le zip redbean).

-- Stub 'html' → auth.html (disponible dans lua/ via TEST_LUA_PATH)
package.preload["html"] = -> require "auth.html"

-- ── Stubs redbean ────────────────────────────────────────────────────────────

captured = {}

reset_globals = (path, method, params) ->
  captured = { status: 200, headers: {}, body: "" }
  _G.GetPath   = -> path
  _G.GetMethod = -> method
  _G.GetParam  = (k) -> (params or {})[k]
  _G.SetHeader = (k, v) -> captured.headers[k] = v
  _G.SetStatus = (code) -> captured.status = code
  _G.Write     = (s) -> captured.body ..= (s or "")

orig_popen = io.popen

-- ── Chargement du script ──────────────────────────────────────────────────────

setup ->
  reset_globals "/", "GET", {}
  fn = assert loadfile ".init.lua"
  fn!

after_each ->
  io.popen = orig_popen

-- ── Helpers ──────────────────────────────────────────────────────────────────

dispatch = (path, method, params) ->
  reset_globals path, method, params
  _G.OnHttpRequest!
  captured

-- Remplace io.popen par un stub qui capture les commandes exécutées.
-- Retourne la table `cmds` remplie lors des appels suivants.
popen_stub = (output) ->
  cmds = {}
  io.popen = (cmd, _) ->
    table.insert cmds, cmd
    {
      read: (self, _) -> output
      close: ->
    }
  cmds

-- ── Routes GET ───────────────────────────────────────────────────────────────

describe ".init — GET routes", ->

  it "/ sert la page d'accueil avec les liens de navigation", ->
    r = dispatch "/", "GET", {}
    assert.equals 200, r.status
    assert.truthy r.body\find "CustosVirginum"
    assert.truthy r.body\find "/install"
    assert.truthy r.body\find "/sync"
    assert.truthy r.body\find "/uninstall"
    assert.equals "text/html; charset=UTF-8", r.headers["Content-Type"]

  it "GET /install expose un formulaire POST avec tous les champs", ->
    r = dispatch "/install", "GET", {}
    assert.equals 200, r.status
    assert.truthy r.body\find [[action="/install"]]
    assert.truthy r.body\find [[name="host"]]
    assert.truthy r.body\find [[name="port"]]
    assert.truthy r.body\find [[name="user"]]
    assert.truthy r.body\find [[name="dest"]]
    assert.truthy r.body\find [[name="no_build"]]
    assert.truthy r.body\find [[name="no_start"]]
    assert.truthy r.body\find [[name="dry_run"]]

  it "GET /uninstall expose un formulaire POST vers /uninstall", ->
    r = dispatch "/uninstall", "GET", {}
    assert.equals 200, r.status
    assert.truthy r.body\find [[action="/uninstall"]]
    assert.truthy r.body\find [[name="host"]]

  it "GET /sync expose les deux modes radio pull et push", ->
    r = dispatch "/sync", "GET", {}
    assert.equals 200, r.status
    assert.truthy r.body\find [[value="pull"]]
    assert.truthy r.body\find [[value="push"]]

  it "route inconnue retourne 404", ->
    r = dispatch "/inexistant", "GET", {}
    assert.equals 404, r.status
    assert.truthy r.body\find "introuvable"

-- ── POST /install ─────────────────────────────────────────────────────────────

describe ".init — POST /install : validation", ->

  it "retourne 400 si l'hôte est absent", ->
    r = dispatch "/install", "POST", {}
    assert.equals 400, r.status

  it "retourne 400 si l'hôte est vide", ->
    r = dispatch "/install", "POST", { host: "" }
    assert.equals 400, r.status

describe ".init — POST /install : construction de commande", ->

  it "invoque luajit install-owrt.lua avec l'hôte, le port et le user", ->
    cmds = popen_stub "ok"
    dispatch "/install", "POST", { host: "192.168.1.1", port: "2222", user: "admin" }
    assert.equals 1, #cmds
    assert.truthy cmds[1]\find "install%-owrt%.lua"
    assert.truthy cmds[1]\find "192%.168%.1%.1"
    assert.truthy cmds[1]\find "--port 2222"
    assert.truthy cmds[1]\find "--user admin"

  it "ajoute --no-build si la case est cochée", ->
    cmds = popen_stub "ok"
    dispatch "/install", "POST", { host: "10.0.0.1", port: "22", no_build: "1" }
    assert.truthy cmds[1]\find "--no%-build"

  it "n'ajoute pas --no-build si la case est décochée", ->
    cmds = popen_stub "ok"
    dispatch "/install", "POST", { host: "10.0.0.1", port: "22" }
    assert.falsy cmds[1]\find "--no%-build"

  it "ajoute --no-start si la case est cochée", ->
    cmds = popen_stub "ok"
    dispatch "/install", "POST", { host: "10.0.0.1", port: "22", no_start: "1" }
    assert.truthy cmds[1]\find "--no%-start"

  it "ajoute --dry-run si la case est cochée", ->
    cmds = popen_stub "ok"
    dispatch "/install", "POST", { host: "10.0.0.1", port: "22", dry_run: "1" }
    assert.truthy cmds[1]\find "--dry%-run"

  it "utilise root comme user par défaut si absent", ->
    cmds = popen_stub "ok"
    dispatch "/install", "POST", { host: "10.0.0.1", port: "22" }
    assert.truthy cmds[1]\find "--user root"

  it "utilise /usr/share/custos comme dest par défaut si absent", ->
    cmds = popen_stub "ok"
    dispatch "/install", "POST", { host: "10.0.0.1", port: "22" }
    assert.truthy cmds[1]\find "--dest /usr/share/custos"

  it "affiche la commande et la sortie dans la page de résultat", ->
    cmds = popen_stub "Installation réussie."
    r = dispatch "/install", "POST", { host: "192.168.1.1", port: "22" }
    assert.truthy r.body\find "install%-owrt%.lua"
    assert.truthy r.body\find "Installation réussie%."

-- ── POST /uninstall ───────────────────────────────────────────────────────────

describe ".init — POST /uninstall : validation et commande", ->

  it "retourne 400 si l'hôte est manquant", ->
    r = dispatch "/uninstall", "POST", { host: "" }
    assert.equals 400, r.status

  it "invoque install-owrt.lua --uninstall avec l'hôte", ->
    cmds = popen_stub "ok"
    dispatch "/uninstall", "POST", { host: "192.168.1.1", port: "22", user: "root" }
    assert.equals 1, #cmds
    assert.truthy cmds[1]\find "--uninstall"
    assert.truthy cmds[1]\find "192%.168%.1%.1"

  it "utilise root comme user par défaut", ->
    cmds = popen_stub "ok"
    dispatch "/uninstall", "POST", { host: "10.0.0.1", port: "22" }
    assert.truthy cmds[1]\find "--user root"

-- ── POST /sync ────────────────────────────────────────────────────────────────

describe ".init — POST /sync : validation et commande", ->

  it "retourne 400 si l'hôte est manquant", ->
    r = dispatch "/sync", "POST", { host: "", repo: "https://example.com/r" }
    assert.equals 400, r.status

  it "retourne 400 si le dépôt est manquant", ->
    r = dispatch "/sync", "POST", { host: "192.168.1.1", repo: "" }
    assert.equals 400, r.status

  it "utilise sync-init pour le mode pull", ->
    cmds = popen_stub "ok"
    dispatch "/sync", "POST", { host: "192.168.1.1", repo: "https://example.com/r", mode: "pull" }
    assert.truthy cmds[1]\find "sync%-init"
    assert.falsy  cmds[1]\find "sync%-push%-init"

  it "utilise sync-push-init pour le mode push", ->
    cmds = popen_stub "ok"
    dispatch "/sync", "POST", { host: "192.168.1.1", repo: "https://example.com/r", mode: "push" }
    assert.truthy cmds[1]\find "sync%-push%-init"

  it "passe HOST et REPO à make", ->
    cmds = popen_stub "ok"
    dispatch "/sync", "POST", { host: "192.168.1.1", repo: "https://example.com/configs", mode: "pull" }
    assert.truthy cmds[1]\find "HOST=192%.168%.1%.1"
    assert.truthy cmds[1]\find "REPO=https://example%.com/configs"

-- ── Sanitisation des entrées ──────────────────────────────────────────────────

describe ".init — sanitisation des entrées", ->

  it "supprime les métacaractères shell dans l'hôte", ->
    cmds = popen_stub "ok"
    dispatch "/install", "POST", { host: "192.168.1.1;rm -rf /", port: "22" }
    assert.falsy cmds[1]\find ";"

  it "supprime les métacaractères shell dans le user", ->
    cmds = popen_stub "ok"
    dispatch "/install", "POST", { host: "192.168.1.1", port: "22", user: "root;evil" }
    assert.falsy cmds[1]\find ";"

  it "supprime les caractères dangereux dans le chemin dest", ->
    cmds = popen_stub "ok"
    dispatch "/install", "POST", { host: "192.168.1.1", port: "22", dest: "/usr/share;evil" }
    assert.falsy cmds[1]\find ";"

  it "normalise un port invalide à 22", ->
    cmds = popen_stub "ok"
    dispatch "/install", "POST", { host: "192.168.1.1", port: "abc" }
    assert.truthy cmds[1]\find "--port 22"

  it "supprime les caractères dangereux dans le repo", ->
    cmds = popen_stub "ok"
    dispatch "/sync", "POST", { host: "192.168.1.1", repo: "https://example.com/r;evil", mode: "pull" }
    assert.falsy cmds[1]\find ";"

-- ── Échappement HTML de la sortie ────────────────────────────────────────────

describe ".init — échappement HTML de la sortie commande", ->

  it "échappe les balises HTML dans l'output affiché", ->
    io.popen = (cmd, _) ->
      {
        read: (self, _) -> "<script>alert('xss')</script>"
        close: ->
      }
    r = dispatch "/install", "POST", { host: "192.168.1.1", port: "22" }
    assert.falsy  r.body\find "<script>alert"
    assert.truthy r.body\find "&lt;script&gt;"

  it "échappe les esperluettes dans l'output affiché", ->
    io.popen = (cmd, _) ->
      {
        read: (self, _) -> "foo & bar"
        close: ->
      }
    r = dispatch "/install", "POST", { host: "192.168.1.1", port: "22" }
    assert.falsy  r.body\find "foo & bar"
    assert.truthy r.body\find "foo &amp; bar"
