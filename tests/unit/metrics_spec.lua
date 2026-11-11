local json = require("lib.json")
local init, record_verdict, get_metrics_json, write_now, purge_files, flush_if_due, maybe_flush, file_path, clear, _get_state
do
  local _obj_0 = require("metrics")
  init, record_verdict, get_metrics_json, write_now, purge_files, flush_if_due, maybe_flush, file_path, clear, _get_state = _obj_0.init, _obj_0.record_verdict, _obj_0.get_metrics_json, _obj_0.write_now, _obj_0.purge_files, _obj_0.flush_if_due, _obj_0.maybe_flush, _obj_0.file_path, _obj_0.clear, _obj_0._get_state
end
local DIR = "tmp/metrics_spec"
local FILE = tostring(DIR) .. "/metrics-w0.json"
local list_dir
list_dir = function()
  local h = io.popen("ls -1 '" .. tostring(DIR) .. "' 2>/dev/null")
  local out = { }
  for name in h:lines() do
    out[#out + 1] = name
  end
  h:close()
  return out
end
local clean_dir
clean_dir = function()
  local _list_0 = list_dir()
  for _index_0 = 1, #_list_0 do
    local name = _list_0[_index_0]
    os.remove(tostring(DIR) .. "/" .. tostring(name))
  end
  return os.remove(DIR)
end
local file_exists
file_exists = function()
  local fh = io.open(FILE, "r")
  if not (fh) then
    return false
  end
  fh:close()
  return true
end
local read_snapshot
read_snapshot = function()
  local fh = assert(io.open(FILE, "r"))
  local content = fh:read("*a")
  fh:close()
  return json.decode(content)
end
return describe("metrics", function()
  before_each(function()
    clean_dir()
    os.execute("mkdir -p '" .. tostring(DIR) .. "'")
    init({
      enabled = true,
      flush_interval = 60
    }, { })
    return clear()
  end)
  after_each(function()
    init({
      enabled = true
    }, { })
    clear()
    return clean_dir()
  end)
  describe("record_verdict", function()
    it("initialise le compteur d'une nouvelle règle", function()
      record_verdict("rule1", "allow")
      local state = _get_state()
      assert.is_not_nil(state["rule1"])
      return assert.equals(1, state["rule1"].allow_count)
    end)
    it("incrémente allow/refuse/dnsonly", function()
      for i = 1, 3 do
        record_verdict("rule1", "allow")
      end
      record_verdict("rule1", "refuse")
      record_verdict("rule1", "refuse")
      record_verdict("rule1", "dnsonly")
      local state = _get_state()
      assert.equals(3, state["rule1"].allow_count)
      assert.equals(2, state["rule1"].refuse_count)
      return assert.equals(1, state["rule1"].dnsonly_count)
    end)
    it("gère plusieurs règles", function()
      record_verdict("rule1", "allow")
      record_verdict("rule2", "refuse")
      record_verdict("rule1", "allow")
      local state = _get_state()
      assert.equals(2, state["rule1"].allow_count)
      return assert.equals(1, state["rule2"].refuse_count)
    end)
    return it("ignore nil et un verdict inconnu", function()
      record_verdict(nil, "allow")
      record_verdict("rule1", nil)
      record_verdict("rule1", "invalid")
      local state = _get_state()
      assert.equals(0, #state)
      return assert.equals(0, state["rule1"].allow_count + state["rule1"].refuse_count + state["rule1"].dnsonly_count)
    end)
  end)
  describe("get_metrics_json", function()
    it("exporte timestamp et compteurs par règle", function()
      record_verdict("rule1", "allow")
      record_verdict("rule1", "allow")
      record_verdict("rule1", "refuse")
      local snap = get_metrics_json()
      assert.equals("number", type(snap.timestamp))
      assert.equals(1, #snap.rules)
      assert.equals("rule1", snap.rules[1].rule_id)
      assert.equals(2, snap.rules[1].verdicts.allow)
      assert.equals(1, snap.rules[1].verdicts.refuse)
      return assert.equals(0, snap.rules[1].verdicts.dnsonly)
    end)
    it("exporte une liste vide sans donnée", function()
      return assert.same({ }, get_metrics_json().rules)
    end)
    return it("n'exporte rien quand désactivé", function()
      init({
        enabled = false
      })
      record_verdict("rule1", "allow")
      return assert.same({ }, get_metrics_json().rules)
    end)
  end)
  describe("export périodique", function()
    it("n'écrit rien avant l'intervalle, puis un instantané", function()
      local now = 0
      init({
        enabled = true,
        flush_interval = 10
      }, {
        dir = DIR,
        name = "w0",
        clock = (function()
          return now
        end),
        check_every = 1
      })
      record_verdict("r1", "allow")
      now = 0
      maybe_flush()
      assert.is_false(file_exists())
      now = 9
      maybe_flush()
      assert.is_false(file_exists())
      now = 10
      maybe_flush()
      local snap = read_snapshot()
      assert.equals(10, snap.timestamp)
      assert.equals("r1", snap.rules[1].rule_id)
      return assert.equals(1, snap.rules[1].verdicts.allow)
    end)
    it("consulte l'horloge seulement tous les check_every paquets", function()
      local now = 0
      local clock_calls = 0
      local fake_clock
      fake_clock = function()
        clock_calls = clock_calls + 1
        return now
      end
      init({
        enabled = true,
        flush_interval = 10
      }, {
        dir = DIR,
        name = "w0",
        clock = fake_clock,
        check_every = 4
      })
      for i = 1, 3 do
        maybe_flush()
      end
      assert.equals(0, clock_calls)
      maybe_flush()
      return assert.equals(1, clock_calls)
    end)
    it("utilise check_every = 32 par défaut", function()
      local clock_calls = 0
      local fake_clock
      fake_clock = function()
        clock_calls = clock_calls + 1
        return 0
      end
      init({
        enabled = true,
        flush_interval = 10
      }, {
        dir = DIR,
        name = "w0",
        clock = fake_clock
      })
      for i = 1, 31 do
        maybe_flush()
      end
      assert.equals(0, clock_calls)
      maybe_flush()
      return assert.equals(1, clock_calls)
    end)
    it("flush_if_due écrit sur le seul passage temporel", function()
      local now = 0
      init({
        enabled = true,
        flush_interval = 10
      }, {
        dir = DIR,
        name = "w0",
        clock = (function()
          return now
        end)
      })
      record_verdict("r1", "allow")
      assert.is_true(write_now())
      now = 9
      assert.is_false(flush_if_due())
      now = 10
      assert.is_true(flush_if_due())
      local snap = read_snapshot()
      return assert.equals(1, snap.rules[1].verdicts.allow)
    end)
    it("write_now produit un instantané vide valide au démarrage", function()
      init({
        enabled = true
      }, {
        dir = DIR,
        name = "w0"
      })
      assert.is_true(write_now())
      local snap = read_snapshot()
      assert.equals("number", type(snap.timestamp))
      return assert.same({ }, snap.rules)
    end)
    it("n'écrit rien quand désactivé", function()
      local now = 1000
      init({
        enabled = false,
        flush_interval = 10
      }, {
        dir = DIR,
        name = "w0",
        clock = (function()
          return now
        end),
        check_every = 1
      })
      record_verdict("r1", "allow")
      maybe_flush()
      assert.is_false(file_exists())
      return assert.is_false(write_now())
    end)
    it("file_path reflète le nom du worker", function()
      init({
        enabled = true
      }, {
        dir = DIR,
        name = "dns-q3"
      })
      assert.equals(tostring(DIR) .. "/metrics-dns-q3.json", file_path())
      init({
        enabled = true
      }, { })
      return assert.is_nil(file_path())
    end)
    return it("échoue sans lever si le répertoire cible n'existe pas", function()
      init({
        enabled = true
      }, {
        dir = tostring(DIR) .. "/absent",
        name = "w0"
      })
      record_verdict("r1", "allow")
      return assert.is_false(write_now())
    end)
  end)
  describe("purge_files", function()
    return it("supprime instantanés et temporaires, laisse les autres fichiers", function()
      local write
      write = function(name, content)
        local fh = assert(io.open(tostring(DIR) .. "/" .. tostring(name), "w"))
        fh:write(content)
        return fh:close()
      end
      write("metrics-a.json", "{}")
      write("metrics-a.json.tmp.1", "x")
      write("metrics-b.json.tmp.7", "x")
      write("notes.txt", "à conserver")
      assert.equals(3, purge_files(DIR))
      assert.same({
        "notes.txt"
      }, list_dir())
      return assert.equals(0, purge_files(nil))
    end)
  end)
  describe("atomicité", function()
    it("ne laisse aucun temporaire après une écriture réussie", function()
      init({
        enabled = true
      }, {
        dir = DIR,
        name = "w0"
      })
      record_verdict("r1", "allow")
      assert.is_true(write_now())
      return assert.same({
        "metrics-w0.json"
      }, list_dir())
    end)
    return it("préserve l'ancien fichier si le renommage échoue", function()
      init({
        enabled = true
      }, {
        dir = DIR,
        name = "w0"
      })
      record_verdict("r1", "allow")
      assert.is_true(write_now())
      local snap = read_snapshot()
      assert.equals(1, snap.rules[1].verdicts.allow)
      record_verdict("r1", "allow")
      local real_rename = os.rename
      local renamed_from = nil
      local fail_rename
      fail_rename = function(src, dst)
        renamed_from = src
        return false
      end
      rawset(os, "rename", fail_rename)
      local ok = write_now()
      rawset(os, "rename", real_rename)
      assert.is_false(ok)
      assert.truthy(renamed_from and renamed_from:find(".tmp.", 1, true))
      snap = read_snapshot()
      assert.equals(1, snap.rules[1].verdicts.allow)
      return assert.same({
        "metrics-w0.json"
      }, list_dir())
    end)
  end)
  describe("mémoire bornée", function()
    return it("évince la règle la moins récemment vue au-delà de max_rules", function()
      init({
        max_rules = 3,
        enabled = true
      })
      for i = 1, 4 do
        record_verdict("rule" .. tostring(i), "allow")
      end
      local snap = get_metrics_json()
      local ids = { }
      local _list_0 = snap.rules
      for _index_0 = 1, #_list_0 do
        local r = _list_0[_index_0]
        ids[r.rule_id] = true
      end
      assert.equals(3, #snap.rules)
      assert.is_nil(ids["rule1"])
      return assert.is_true(ids["rule4"])
    end)
  end)
  return describe("chargement du module (config.metrics)", function()
    local saved_metrics = nil
    local saved_config = nil
    before_each(function()
      saved_metrics = package.loaded["metrics"]
      saved_config = package.loaded["config"]
    end)
    after_each(function()
      package.loaded["metrics"] = saved_metrics
      package.loaded["config"] = saved_config
    end)
    it("honore metrics.enabled = false dès le chargement", function()
      package.loaded["config"] = {
        metrics = {
          enabled = false
        }
      }
      package.loaded["metrics"] = nil
      local fresh = require("metrics")
      fresh.record_verdict("rule1", "allow")
      return assert.equals(0, #fresh.get_metrics_json().rules)
    end)
    it("reste actif quand metrics.enabled est absent", function()
      package.loaded["config"] = { }
      package.loaded["metrics"] = nil
      local fresh = require("metrics")
      fresh.record_verdict("rule1", "allow")
      return assert.equals(1, #fresh.get_metrics_json().rules)
    end)
    return it("reste actif quand metrics.enabled = true", function()
      package.loaded["config"] = {
        metrics = {
          enabled = true
        }
      }
      package.loaded["metrics"] = nil
      local fresh = require("metrics")
      fresh.record_verdict("rule1", "allow")
      return assert.equals(1, #fresh.get_metrics_json().rules)
    end)
  end)
end)
