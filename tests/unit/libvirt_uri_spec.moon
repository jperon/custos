-- tests/unit/libvirt_uri_spec.moon
-- Tests de la décision de connexion libvirt du harnais E2E (libvirt/libvirt_uri.sh).
--
-- La logique est volontairement extraite dans une fonction shell pure
-- `libvirt_pick_uri` (aucun appel virsh) : on la source et on vérifie les
-- quatre cas de sélection. C'est le bug réel corrigé : `virsh` nu visait
-- qemu:///session, où un homelab en qemu:///system est invisible (aucun bail
-- DHCP → aucune IP → timeout SSH).

LIBVIRT_URI_SH = "libvirt/libvirt_uri.sh"

-- Le runner VM (make test-vm) ne copie que lua/ et tests/ : le harnais libvirt
-- n'y est pas. On marque alors les cas pending au lieu d'échouer.
skip_if_absent = ->
  f = io.open LIBVIRT_URI_SH, "r"
  unless f
    pending "#{LIBVIRT_URI_SH} absent de cet environnement"
  f\close!

-- Exécute libvirt_pick_uri dans un bash neuf et renvoie sa sortie nettoyée.
pick_uri = (existing, system_status, session_status) ->
  cmd = string.format(
    "bash -c 'source %s; libvirt_pick_uri %q %q %q'",
    LIBVIRT_URI_SH, existing, system_status, session_status)
  pipe = assert io.popen cmd, "r"
  out = pipe\read "*a"
  pipe\close!
  out = out\gsub "%s+$", ""
  out

describe "libvirt — libvirt_pick_uri", ->
  it "respecte LIBVIRT_DEFAULT_URI déjà défini, sans le remplacer", ->
    skip_if_absent!
    assert.equals "qemu:///custom", pick_uri "qemu:///custom", "1", "1"

  it "respecte LIBVIRT_DEFAULT_URI même si qemu:///system contient le homelab", ->
    skip_if_absent!
    assert.equals "qemu:///session", pick_uri "qemu:///session", "0", "0"

  it "choisit qemu:///system quand le homelab y est visible", ->
    skip_if_absent!
    assert.equals "qemu:///system", pick_uri "", "0", "1"

  it "préfère qemu:///system quand les deux connexions contiennent le homelab", ->
    skip_if_absent!
    assert.equals "qemu:///system", pick_uri "", "0", "0"

  it "bascule sur qemu:///session quand seul le homelab session est présent", ->
    skip_if_absent!
    assert.equals "qemu:///session", pick_uri "", "1", "0"

  it "ne hardcode aucune connexion si le homelab n'est encore visible nulle part", ->
    skip_if_absent!
    assert.equals "", pick_uri "", "1", "1"
