-- tests/unit/install_owrt_spec.moon
-- Tests de l'installeur OpenWrt (install-owrt.lua) : politique de création des
-- listes enfants/adultes selon la préexistence de /etc/custos/config.moon.
--
-- Stratégie : charger install-owrt.lua via loadfile (le script ne lance main!
-- que s'il est exécuté directement), instancier Installer avec un cfg dry-run,
-- puis surcharger ssh_run / ssh_capture sur l'instance pour capturer les
-- commandes distantes sans SSH réel.

mod = assert(loadfile "install-owrt.lua")!
{ :Installer } = mod

-- Construit une instance avec ssh_capture scripté et capture des ssh_run.
make_inst = (capture_map) ->
  inst = Installer { host: "10.0.0.1", port: 22, user: "root", dest: "/usr/share/custos", dry: true }
  runs = {}
  inst.ssh_run = (cmd) =>
    runs[#runs + 1] = cmd
    true
  inst.ssh_capture = (cmd) =>
    for pat, out in pairs capture_map
      return out if cmd\find pat, 1, true
    "no"
  inst, runs

describe "install-owrt — install_etc_custos", ->
  it "mémorise config_existed = true quand config.moon préexiste", ->
    inst = make_inst { "[ -f /etc/custos/config.moon ]": "yes" }
    inst\install_etc_custos!
    assert.is_true inst.config_existed

  it "mémorise config_existed = false sur une nouvelle installation", ->
    inst = make_inst { "[ -f /etc/custos/config.moon ]": "no" }
    inst\install_etc_custos!
    assert.is_false inst.config_existed

describe "install-owrt — install_default_lists", ->
  it "crée les listes enfants/adultes sur une nouvelle installation", ->
    inst, runs = make_inst {}
    inst.config_existed = false
    assert.is_true inst\install_default_lists!
    joined = table.concat runs, "\n"
    assert.truthy joined\find "enfants.txt", 1, true
    assert.truthy joined\find "adultes.txt", 1, true
    assert.truthy joined\find "enfants_allow.txt", 1, true
    assert.truthy joined\find "adultes_block.txt", 1, true

  it "ne crée aucune liste si config.moon préexistait", ->
    inst, runs = make_inst {}
    inst.config_existed = true
    assert.is_true inst\install_default_lists!
    joined = table.concat runs, "\n"
    assert.falsy joined\find "enfants.txt", 1, true
    assert.falsy joined\find "adultes.txt", 1, true

-- ── Régression : bandeau ssh "Warning: Permanently added..." ────────────
-- UserKnownHostsFile=/dev/null ne persistant jamais la clé, ssh imprime ce
-- bandeau sur stderr à CHAQUE appel. capture() fait 2>&1 (stdout+stderr
-- fusionnés) : sans -o LogLevel=ERROR, ce bandeau devient la première ligne
-- de toute sortie ssh_capture — déjà responsable d'un vrai incident en prod
-- (bridge_ifname="Warning:" patché sur 10.35.1.70, crash-loop arp/captive).
describe "install-owrt — ssh_prefix", ->
  it "inclut -o LogLevel=ERROR (supprime le bandeau ssh 'Permanently added')", ->
    inst = Installer { host: "10.0.0.1", port: 22, user: "root", dest: "/usr/share/custos", dry: true }
    assert.truthy inst\ssh_prefix!\find "LogLevel=ERROR", 1, true

describe "install-owrt — patch_bridge_ifname (garde-fou anti-bannière)", ->
  it "rejette une sortie de détection non conforme à un nom d'interface (ex: bannière ssh captée)", ->
    inst, runs = make_inst { "for b in": "Warning:", "grep -o 'bridge_ifname": "no" }
    ok = inst\patch_bridge_ifname!
    assert.is_true ok
    joined = table.concat runs, "\n"
    assert.falsy joined\find 'bridge_ifname: "Warning:"', 1, true

  it "accepte un nom d'interface valide et le patche", ->
    inst, runs = make_inst { "for b in": "br-lan", "grep -o 'bridge_ifname": "no" }
    ok = inst\patch_bridge_ifname!
    assert.is_true ok
    joined = table.concat runs, "\n"
    assert.truthy joined\find 'bridge_ifname: "br-lan"', 1, true

describe "install-owrt — install_hotplug_rps", ->
  it "crée le dossier hotplug, chmod et applique immédiatement le script", ->
    inst, runs = make_inst {}
    assert.is_true inst\install_hotplug_rps!
    joined = table.concat runs, "\n"
    assert.truthy joined\find "mkdir -p /etc/hotplug.d/net", 1, true
    assert.truthy joined\find "chmod +x /etc/hotplug.d/net/30-custos-rps", 1, true
    -- Application immédiate sans attendre un événement net (ACTION=add).
    assert.truthy joined\find "ACTION=add /etc/hotplug.d/net/30-custos-rps", 1, true

  it "supprime le script hotplug lors de la désinstallation", ->
    inst, runs = make_inst {}
    inst\uninstall!
    joined = table.concat runs, "\n"
    assert.truthy joined\find "rm -f /etc/hotplug.d/net/30-custos-rps", 1, true

-- ── Validation des arguments (injection shell) ─────────────────────────────
-- --user/--dest/--port et l'hôte positionnel sont interpolés dans des commandes
-- shell locales et distantes : rejet à l'entrée de tout métacaractère.

{ :parse_args, :shell_quote } = mod

invalid_cfg = (args) ->
  cfg, err = parse_args args
  assert.is_nil cfg
  assert.is_string err
  err

describe "install-owrt — validation parse_args", ->

  it "accepte un utilisateur, un hôte, une destination et un port valides", ->
    cfg, err = parse_args { "--user", "root", "--dest", "/usr/share/custos", "--port", "2222", "192.168.1.1" }
    assert.is_nil err
    assert.equals "root", cfg.user
    assert.equals "/usr/share/custos", cfg.dest
    assert.equals 2222, cfg.port
    assert.equals "192.168.1.1", cfg.host

  it "accepte un hostname, une IPv6 littérale entre crochets et un port explicite", ->
    for host in *{"router.lan", "[fe80::1]"}
      cfg, err = parse_args { host }
      assert.is_nil err, host
      assert.equals host, cfg.host
    cfg = assert parse_args { "--port", "2222", "router.lan" }
    assert.equals 2222, cfg.port

  it "rejette un utilisateur contenant un métacaractère shell", ->
    for user in *{"root;x", "root x", "$(id)", "`id`", "root|x"}
      assert.truthy (invalid_cfg { "--user", user, "10.0.0.1" })\match "Utilisateur invalide"

  it "rejette un hôte contenant un métacaractère ou un espace", ->
    for host in *{"a b", "`id`", "$(id)", "a;b", "a|b"}
      assert.truthy (invalid_cfg { host })\match "Hôte invalide"

  it "rejette une destination relative ou contenant un métacaractère", ->
    for dest in *{"etc/custos", "/etc;reboot", "/etc/$(id)", "/etc/`id`", "/etc/ x"}
      assert.truthy (invalid_cfg { "--dest", dest, "10.0.0.1" })\match "Destination invalide"

  it "rejette un port hors bornes ou non entier", ->
    for port in *{"0", "70000", "22;x", "abc", "-1"}
      assert.truthy (invalid_cfg { "--port", port, "10.0.0.1" })\match "port invalide"

  it "accepte la forme utilisateur@hôte et en déduit l'utilisateur", ->
    cfg, err = parse_args { "admin@router.lan" }
    assert.is_nil err
    assert.equals "admin", cfg.user
    assert.equals "router.lan", cfg.host

  it "accepte un hôte seul et garde root par défaut", ->
    cfg, err = parse_args { "router.lan" }
    assert.is_nil err
    assert.equals "root", cfg.user
    assert.equals "router.lan", cfg.host

  it "--user explicite prime sur utilisateur@hôte, quel que soit l'ordre", ->
    for args in *{
        { "--user", "admin", "root@router.lan" }
        { "root@router.lan", "--user", "admin" }
      }
      cfg, err = parse_args args
      assert.is_nil err
      assert.equals "admin", cfg.user
      assert.equals "router.lan", cfg.host

  it "rejette utilisateur@hôte incomplet ou ambigu", ->
    assert.truthy (invalid_cfg { "@router.lan" })\match "Utilisateur invalide"
    assert.truthy (invalid_cfg { "root@" })\match "Hôte invalide"
    assert.truthy (invalid_cfg { "a@b@c" })\match "Hôte invalide"

  it "rejette un utilisateur invalide dans la forme utilisateur@hôte", ->
    for host in *{"ro ot@router.lan", "root;x@router.lan", "$(id)@router.lan", "`id`@router.lan"}
      assert.truthy (invalid_cfg { host })\match "Utilisateur invalide"

  it "shell_quote neutralise les apostrophes", ->
    assert.equals "'root'", shell_quote "root"
    assert.equals "'a'\\''b'", shell_quote "a'b"

-- ── Dry-run : aucune commande réelle ───────────────────────────────────────
describe "install-owrt — dry-run", ->

  it "capture ne lance aucune commande et renvoie une sortie factice", ->
    inst = Installer { host: "10.0.0.1", port: 22, user: "root", dest: "/usr/share/custos", dry: true }
    original = io.popen
    io.popen = -> error "io.popen interdit en dry-run"
    ok, out = pcall -> inst\capture "uname -a"
    io.popen = original
    assert.is_true ok
    assert.truthy out\match "dry%-run"

  it "check_connectivity ne lance rien et réussit sans SSH", ->
    inst = Installer { host: "10.0.0.1", port: 22, user: "root", dest: "/usr/share/custos", dry: true }
    inst.ssh_capture = -> error "ssh_capture interdit en dry-run"
    assert.is_true inst\check_connectivity!

  it "detect_pkg_manager suppose apk sans SSH", ->
    inst = Installer { host: "10.0.0.1", port: 22, user: "root", dest: "/usr/share/custos", dry: true }
    inst.ssh_capture = -> error "ssh_capture interdit en dry-run"
    assert.is_true inst\detect_pkg_manager!
    assert.equals "apk", inst.cfg.pkg_mgr

describe "install-owrt — install_updater", ->
  it "installe custos-update sans ajouter de cron en double (géré par init.d)", ->
    inst, runs = make_inst {}
    assert.is_true inst\install_updater!
    joined = table.concat runs, "\n"
    assert.falsy joined\find "crontabs/root", 1, true
    assert.falsy joined\find "0 4 * * *", 1, true

-- ── Utilitaires locaux (run) et sémantique os.execute ──────────────────────

describe "install-owrt — run", ->
  original = nil
  before_each -> original = os.execute
  after_each -> os.execute = original

  it "considère 0 (Lua 5.1) comme un succès", ->
    inst = Installer { host: "10.0.0.1", dry: false }
    os.execute = -> 0
    assert.is_true inst\run "true"

  it "considère true (LUA52COMPAT) comme un succès", ->
    inst = Installer { host: "10.0.0.1", dry: false }
    os.execute = -> true, "exit", 0
    assert.is_true inst\run "true"

  it "considère un code non nul comme un échec", ->
    inst = Installer { host: "10.0.0.1", dry: false }
    os.execute = -> nil, "exit", 1
    assert.is_false inst\run "false"

  it "ne lance aucune commande en dry-run", ->
    inst = Installer { host: "10.0.0.1", dry: true }
    os.execute = -> error "os.execute interdit en dry-run"
    assert.is_true inst\run "false"

-- Instance qui enregistre les commandes locales (run) et distantes (ssh_run).
make_inst_records = (opts={}) ->
  inst = Installer { host: "10.0.0.1", port: 22, user: "root", dest: "/usr/share/custos", dry: opts.dry != false }
  cmds = { local: {}, ssh: {} }
  inst.run = (cmd) =>
    cmds.local[#cmds.local + 1] = cmd
    true
  inst.ssh_run = (cmd) =>
    cmds.ssh[#cmds.ssh + 1] = cmd
    true
  inst.ssh_capture = -> ""
  inst, cmds

-- ── Quoting des commandes ssh/scp ─────────────────────────────────────────

describe "install-owrt — quoting des commandes", ->

  it "ssh_prefix quote le port et la cible user@host", ->
    inst = Installer { host: "router.lan", port: 2222, user: "root", dest: "/usr/share/custos", dry: true }
    expected = "ssh -p '2222' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 'root@router.lan'"
    assert.equals expected, inst\ssh_prefix!

  it "ssh_prefix met un IPv6 littéral entre crochets", ->
    inst = Installer { host: "fe80::1", port: 22, user: "root", dest: "/usr/share/custos", dry: true }
    assert.truthy inst\ssh_prefix!\find "'root@[fe80::1]'", 1, true

  it "ssh_prefix neutralise une apostrophe dans le nom d'utilisateur", ->
    inst = Installer { host: "10.0.0.1", port: 22, user: "a'b", dest: "/usr/share/custos", dry: true }
    assert.truthy inst\ssh_prefix!\find "'a'\\''b@10.0.0.1'", 1, true

  it "ssh_run échappe les apostrophes de la commande distante", ->
    inst = Installer { host: "10.0.0.1", port: 22, user: "root", dest: "/usr/share/custos", dry: false }
    calls = {}
    inst.run = (cmd) =>
      calls[#calls + 1] = cmd
      true
    assert.is_true inst\ssh_run "echo 'x'"
    assert.equals "#{inst\ssh_prefix!} #{shell_quote "echo 'x'"}", calls[1]
    assert.truthy calls[1]\find "'echo '\\''x'\\'''", 1, true

  it "ssh_capture passe par la même commande quotée", ->
    inst = Installer { host: "10.0.0.1", port: 22, user: "root", dest: "/usr/share/custos", dry: false }
    calls = {}
    inst.capture = (cmd) =>
      calls[#calls + 1] = cmd
      "ok"
    assert.equals "ok", inst\ssh_capture "uname -a"
    assert.equals "#{inst\ssh_prefix!} 'uname -a'", calls[1]

  it "scp_send quote la source et la cible distante", ->
    inst = Installer { host: "10.0.0.1", port: 22, user: "root", dest: "/usr/share/custos", dry: false }
    calls = {}
    inst.run = (cmd) =>
      calls[#calls + 1] = cmd
      true
    assert.is_true inst\scp_send "src file", "/etc/custos/config.moon"
    expected = "scp -O -P '22' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r 'src file' 'root@10.0.0.1:/etc/custos/config.moon'"
    assert.equals expected, calls[1]

-- ── Compilation locale ────────────────────────────────────────────────────

describe "install-owrt — build_local", ->

  it "ne compile rien avec --no-build", ->
    inst = Installer { host: "10.0.0.1", dry: false, no_build: true }
    inst.run = -> error "run interdit avec --no-build"
    assert.is_true inst\build_local!

  it "lance make all quand make est disponible", ->
    inst = Installer { host: "10.0.0.1", dry: false }
    calls = {}
    inst.have_cmd = (self, cmd) -> cmd == "make"
    inst.run = (cmd) =>
      calls[#calls + 1] = cmd
      true
    assert.is_true inst\build_local!
    assert.same { "make all" }, calls

  it "échoue si make all échoue", ->
    inst = Installer { host: "10.0.0.1", dry: false }
    inst.have_cmd = (self, cmd) -> cmd == "make"
    inst.run = -> false
    assert.is_false inst\build_local!

-- ── Paquets et copie des fichiers ─────────────────────────────────────────

describe "install-owrt — install_pkg_deps", ->

  it "utilise apk update puis apk add avec la liste complète", ->
    inst, cmds = make_inst_records!
    inst.cfg.pkg_mgr = "apk"
    assert.is_true inst\install_pkg_deps!
    assert.equals "apk update", cmds.ssh[1]
    assert.equals "apk add luajit libnetfilter-queue nftables kmod-nft-queue kmod-nft-bridge lpeg libxxhash libwolfssl px5g curl zstd", cmds.ssh[2]

  it "utilise opkg update puis opkg install", ->
    inst, cmds = make_inst_records!
    inst.cfg.pkg_mgr = "opkg"
    assert.is_true inst\install_pkg_deps!
    assert.equals "opkg update", cmds.ssh[1]
    assert.truthy cmds.ssh[2]\find "opkg install luajit ", 1, true

describe "install-owrt — upload_files", ->

  it "produit les commandes tar/scp/mkdir attendues", ->
    inst, cmds = make_inst_records!
    assert.is_true inst\upload_files!
    assert.equals "tar -czf tmp/custos-lua.tar.gz -C lua .", cmds.local[1]
    assert.equals "mkdir -p /usr/share/custos/parse", cmds.ssh[1]
    assert.truthy cmds.local[2]\find("^scp %-O %-P 22 .*tmp/custos%-lua%.tar%.gz root@10%.0%.0%.1:/tmp/custos%-lua%.tar%.gz$"), cmds.local[2]
    assert.equals "tar -xzf /tmp/custos-lua.tar.gz -C /usr/share/custos && rm -f /tmp/custos-lua.tar.gz", cmds.ssh[2]
    assert.truthy cmds.local[3]\find "'nft-rules/dns-filter-bridge.nft' 'root@10.0.0.1:/usr/share/custos'", 1, true

describe "install-owrt — cleanup_stale_files", ->
  original_popen = nil
  before_each -> original_popen = io.popen
  after_each -> io.popen = original_popen

  it "construit le manifest des .lua de l'archive et ignore le reste", ->
    entries = { "./a.lua", "./sub/b.lua", "./notes.txt", "" }
    i = 0
    io.popen = (cmd) ->
      assert.equals "tar -tzf 'tmp/custos-lua.tar.gz'", cmd
      iterator = ->
        i += 1
        entries[i]
      {
        lines: (self) -> iterator
        close: (self) -> true
      }
    inst = Installer { host: "10.0.0.1", dry: true }
    assert.is_true inst\cleanup_stale_files!
    fh = assert io.open "tmp/custos-manifest.txt", "r"
    content = fh\read "*a"
    fh\close!
    assert.equals "a.lua\nsub/b.lua\n", content

describe "install-owrt — service et santé", ->
  original = nil
  before_each -> original = os.execute
  after_each -> os.execute = original

  it "start_service démarre puis vérifie pgrep sur la bonne commande", ->
    os.execute = -> 0
    inst, cmds = make_inst_records!
    captured = {}
    inst.ssh_capture = (cmd) =>
      captured[#captured + 1] = cmd
      "running"
    assert.is_true inst\start_service!
    assert.equals "/etc/init.d/custos stop ; sleep 2 ; /etc/init.d/custos start", cmds.ssh[1]
    assert.equals "pgrep -f main.lua && echo running || echo stopped", captured[1]

  it "start_service respecte --no-start sans rien exécuter", ->
    os.execute = -> error "os.execute interdit avec --no-start"
    inst, cmds = make_inst_records!
    inst.cfg.no_start = true
    assert.is_true inst\start_service!
    assert.equals 0, #cmds.ssh

  it "health_check interroge logread avec la commande attendue", ->
    inst, _ = make_inst_records!
    captured = {}
    inst.ssh_capture = (cmd) =>
      captured[#captured + 1] = cmd
      ""
    assert.is_true inst\health_check!
    assert.equals "logread | grep custos | tail -n 20", captured[1]
