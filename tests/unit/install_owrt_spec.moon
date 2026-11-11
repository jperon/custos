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
