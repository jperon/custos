-- tests/unit/lib/bridge_detect_spec.moon
-- Tests de lib.bridge_detect : énumération sysfs, choix du bridge le plus
-- peuplé, départage déterministe, détection avec priorité env.

ffi = require "ffi"
pcall ffi.cdef, [[int setenv(const char*, const char*, int); int unsetenv(const char*);]]

bridge_detect = require "lib.bridge_detect"

-- Fabrique un faux io.popen renvoyant des lignes selon la commande.
-- @param routes table { motif_lua: { lignes... } } ; 1er motif trouvé gagne.
fake_popen = (routes) ->
  (cmd) ->
    lines = nil
    for pat, out in pairs routes
      if cmd\find pat, 1, true
        lines = out
        break
    lines or= {}
    i = 0
    iter = ->
      i += 1
      lines[i]
    {
      lines: -> iter
      close: -> true
    }

describe "lib.bridge_detect", ->

  describe "pick_bridge", ->
    it "renvoie nil sur liste vide", ->
      assert.is_nil bridge_detect.pick_bridge {}
      assert.is_nil bridge_detect.pick_bridge nil

    it "choisit le bridge avec le plus d'esclaves", ->
      counts = { "br-lan": 3, "br-guest": 1, "br-wan": 0 }
      got = bridge_detect.pick_bridge { "br-guest", "br-lan", "br-wan" },
        (n) -> counts[n] or 0
      assert.equals "br-lan", got

    it "départage à égalité : br-lan > br0 > alpha", ->
      -- Tous à 0 esclave → départage par rang.
      assert.equals "br-lan", bridge_detect.pick_bridge { "br0", "br-lan", "aaa" },
        (-> 0)
      assert.equals "br0", bridge_detect.pick_bridge { "zzz", "br0", "aaa" },
        (-> 0)
      assert.equals "aaa", bridge_detect.pick_bridge { "zzz", "aaa", "mmm" },
        (-> 0)

    it "le nombre d'esclaves prime sur le rang de départage", ->
      counts = { "br-lan": 0, "br-guest": 5 }
      got = bridge_detect.pick_bridge { "br-lan", "br-guest" },
        (n) -> counts[n] or 0
      assert.equals "br-guest", got

  describe "list_bridges", ->
    it "parse les chemins sysfs", ->
      popen = fake_popen {
        ["/sys/class/net/*/bridge"]: {
          "/sys/class/net/br-lan/bridge"
          "/sys/class/net/br-guest/bridge"
        }
      }
      got = bridge_detect.list_bridges popen
      assert.same { "br-lan", "br-guest" }, got

    it "retombe sur `ip` quand sysfs est vide", ->
      popen = fake_popen {
        ["type bridge"]: { "br-lan UP", "br-wan DOWN" }
      }
      got = bridge_detect.list_bridges popen
      assert.same { "br-lan", "br-wan" }, got

    it "renvoie {} si rien n'est trouvé", ->
      assert.same {}, bridge_detect.list_bridges fake_popen {}

  describe "valid_name", ->
    it "accepte des noms d'interface plausibles", ->
      assert.is_true bridge_detect.valid_name "br-lan"
      assert.is_true bridge_detect.valid_name "br0"
      assert.is_true bridge_detect.valid_name "eth0.100"
      assert.is_true bridge_detect.valid_name "lan_0"
    it "rejette les valeurs corrompues", ->
      assert.is_false bridge_detect.valid_name "Warning:"
      assert.is_false bridge_detect.valid_name "br lan"
      assert.is_false bridge_detect.valid_name "a/b"
      assert.is_false bridge_detect.valid_name ""
      assert.is_false bridge_detect.valid_name nil
      assert.is_false bridge_detect.valid_name "0123456789abcdef0"  -- > 15 car.

  describe "count_slaves", ->
    it "compte les entrées brif", ->
      popen = fake_popen {
        ["/sys/class/net/br-lan/brif/"]: { "eth0", "eth1", "wlan0" }
      }
      assert.equals 3, bridge_detect.count_slaves "br-lan", popen
      assert.equals 0, bridge_detect.count_slaves "br-vide", popen

  describe "exists", ->
    it "reconnaît une interface réelle (lo)", ->
      assert.is_true bridge_detect.exists "lo"
    it "rejette une interface absente ou un nom vide", ->
      assert.is_false bridge_detect.exists "br-inexistant-xyz"
      assert.is_false bridge_detect.exists ""
      assert.is_false bridge_detect.exists nil

  describe "robustesse popen", ->
    it "list_bridges renvoie {} si popen échoue (handle nil)", ->
      assert.same {}, bridge_detect.list_bridges (-> nil)

  describe "detect", ->
    after_each -> ffi = require("ffi"); ffi.C.unsetenv "BRIDGE_IFNAME"

    it "BRIDGE_IFNAME env prime", ->
      ffi = require "ffi"
      ffi.C.setenv "BRIDGE_IFNAME", "br-env", 1
      assert.equals "br-env", bridge_detect.detect!

    it "ignore une valeur BRIDGE_IFNAME invalide et retombe sur sysfs", ->
      ffi = require "ffi"
      ffi.C.setenv "BRIDGE_IFNAME", "br0; touch /x", 1
      popen = fake_popen {
        ["/sys/class/net/*/bridge"]: { "/sys/class/net/br-lan/bridge" }
        ["/sys/class/net/br-lan/brif/"]: { "eth0" }
      }
      assert.equals "br-lan", bridge_detect.detect { :popen }

    it "détecte via sysfs sinon", ->
      popen = fake_popen {
        ["/sys/class/net/*/bridge"]: { "/sys/class/net/br-lan/bridge" }
        ["/sys/class/net/br-lan/brif/"]: { "eth0" }
      }
      assert.equals "br-lan", bridge_detect.detect { :popen }

    it "retombe sur le défaut br0 si aucun bridge", ->
      assert.equals "br0", bridge_detect.detect { popen: fake_popen {} }
