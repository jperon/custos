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
