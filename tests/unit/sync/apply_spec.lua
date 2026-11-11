local TMP = "tmp/apply_spec"
local APPLY = "lua/sync/apply.lua"
local LUA_PATH_VAR = "lua/?.lua;lua/?/init.lua;;"
local write_file
write_file = function(path, content)
  local f = assert(io.open(path, "w"), "impossible d'ouvrir " .. tostring(path))
  f:write(content)
  return f:close()
end
local read_file
read_file = function(path)
  local f = io.open(path, "r")
  if not (f) then
    return nil
  end
  local out = f:read("*a")
  f:close()
  return out
end
local run
run = function(args)
  local out_path = tostring(TMP) .. "/run_out.txt"
  local cmd = "LUA_PATH='" .. tostring(LUA_PATH_VAR) .. "' luajit " .. tostring(APPLY) .. " " .. tostring(args) .. " >'" .. tostring(out_path) .. "' 2>&1"
  local ret = os.execute(cmd)
  local code
  if ret == 0 or ret == true then
    code = 0
  else
    code = 1
  end
  local out = read_file(out_path) or ""
  os.remove(out_path)
  return code, out
end
local load_result
load_result = function(path)
  local moon_base = require("moonscript.base")
  local fn, err = moon_base.loadfile(path)
  if not (fn) then
    return nil, err
  end
  local ok, val = pcall(fn)
  if not (ok) then
    return nil, tostring(val)
  end
  return val, nil
end
setup(function()
  return os.execute("mkdir -p " .. tostring(TMP) .. "/base " .. tostring(TMP) .. "/devices/router1")
end)
after_each(function()
  os.execute("rm -f " .. tostring(TMP) .. "/base/config.moon " .. tostring(TMP) .. "/devices/router1/config.moon")
  return os.execute("rm -f " .. tostring(TMP) .. "/out.moon " .. tostring(TMP) .. "/device-explicit.moon " .. tostring(TMP) .. "/custom-out.moon")
end)
describe("sync/apply — erreurs CLI", function()
  it("échoue si --base est absent", function()
    local ret, out = run("--output " .. tostring(TMP) .. "/out.moon")
    assert.not_equals(0, ret)
    return assert.truthy(out:match("base"))
  end)
  it("échoue si la config de base est introuvable", function()
    local ret, out = run("--base " .. tostring(TMP) .. "/base/nonexistent.moon --output " .. tostring(TMP) .. "/out.moon")
    assert.not_equals(0, ret)
    return assert.truthy(out:match("introuvable"))
  end)
  return it("échoue sur un --hostname qui sortirait du dossier devices/", function()
    write_file(tostring(TMP) .. "/base/config.moon", [[ { runtime: { log_level: "INFO" } } ]])
    local ret, out = run("--base " .. tostring(TMP) .. "/base/config.moon --hostname ../../etc --output " .. tostring(TMP) .. "/out.moon")
    assert.not_equals(0, ret)
    return assert.truthy(out:match("nom d'hôte invalide"))
  end)
end)
describe("sync/apply — comportement nominal", function()
  it("base seule si aucun device ne correspond (hostname inconnu)", function()
    write_file(tostring(TMP) .. "/base/config.moon", [[      { runtime: { log_level: "INFO" }, auth: { port: 33443 } }
    ]])
    local ret, _ = run("--base " .. tostring(TMP) .. "/base/config.moon --hostname nobody --output " .. tostring(TMP) .. "/out.moon")
    assert.equals(0, ret)
    local cfg = assert(load_result(tostring(TMP) .. "/out.moon"))
    assert.equals("INFO", cfg.runtime.log_level)
    return assert.equals(33443, cfg.auth.port)
  end)
  it("les valeurs device écrasent la base (merge superficiel)", function()
    write_file(tostring(TMP) .. "/base/config.moon", [[      { runtime: { log_level: "INFO" }, auth: { port: 33443 } }
    ]])
    write_file(tostring(TMP) .. "/devices/router1/config.moon", [[      { runtime: { log_level: "DEBUG" } }
    ]])
    local ret, _ = run("--base " .. tostring(TMP) .. "/base/config.moon --hostname router1 --output " .. tostring(TMP) .. "/out.moon")
    assert.equals(0, ret)
    local cfg = assert(load_result(tostring(TMP) .. "/out.moon"))
    assert.equals("DEBUG", cfg.runtime.log_level)
    return assert.equals(33443, cfg.auth.port)
  end)
  it("merge profond : sous-tables fusionnées et non remplacées", function()
    write_file(tostring(TMP) .. "/base/config.moon", [[      { nft: { family: "bridge", table: "dns-filter", ip_timeout: "2m" } }
    ]])
    write_file(tostring(TMP) .. "/devices/router1/config.moon", [[      { nft: { ip_timeout: "5m" } }
    ]])
    local ret, _ = run("--base " .. tostring(TMP) .. "/base/config.moon --hostname router1 --output " .. tostring(TMP) .. "/out.moon")
    assert.equals(0, ret)
    local cfg = assert(load_result(tostring(TMP) .. "/out.moon"))
    assert.equals("bridge", cfg.nft.family)
    assert.equals("dns-filter", cfg.nft.table)
    return assert.equals("5m", cfg.nft.ip_timeout)
  end)
  it("les tableaux sont remplacés et non fusionnés", function()
    write_file(tostring(TMP) .. "/base/config.moon", [[      { nft: { add_backoff_ms: { 20, 50, 100 } } }
    ]])
    write_file(tostring(TMP) .. "/devices/router1/config.moon", [[      { nft: { add_backoff_ms: { 10 } } }
    ]])
    local ret, _ = run("--base " .. tostring(TMP) .. "/base/config.moon --hostname router1 --output " .. tostring(TMP) .. "/out.moon")
    assert.equals(0, ret)
    local cfg = assert(load_result(tostring(TMP) .. "/out.moon"))
    assert.equals(1, #cfg.nft.add_backoff_ms)
    return assert.equals(10, cfg.nft.add_backoff_ms[1])
  end)
  it("--device spécifie explicitement le chemin de la config device", function()
    write_file(tostring(TMP) .. "/base/config.moon", [[ { runtime: { log_level: "INFO" } } ]])
    write_file(tostring(TMP) .. "/device-explicit.moon", [[ { runtime: { log_level: "WARN" } } ]])
    local ret, _ = run("--base " .. tostring(TMP) .. "/base/config.moon --device " .. tostring(TMP) .. "/device-explicit.moon --output " .. tostring(TMP) .. "/out.moon")
    assert.equals(0, ret)
    local cfg = assert(load_result(tostring(TMP) .. "/out.moon"))
    return assert.equals("WARN", cfg.runtime.log_level)
  end)
  it("--output spécifie un chemin de sortie personnalisé", function()
    write_file(tostring(TMP) .. "/base/config.moon", [[ { runtime: { log_level: "INFO" } } ]])
    local ret, _ = run("--base " .. tostring(TMP) .. "/base/config.moon --hostname nobody --output " .. tostring(TMP) .. "/custom-out.moon")
    assert.equals(0, ret)
    return assert.truthy(read_file(tostring(TMP) .. "/custom-out.moon"))
  end)
  it("le fichier de sortie est un MoonScript valide rechargeable par moonscript.base.loadfile", function()
    write_file(tostring(TMP) .. "/base/config.moon", [[{
      runtime: { log_level: "INFO", benchmark: false }
      filter:  { rules: {}, allowed_domains: { "local", "lan" } }
    }]])
    local ret, _ = run("--base " .. tostring(TMP) .. "/base/config.moon --hostname nobody --output " .. tostring(TMP) .. "/out.moon")
    assert.equals(0, ret)
    local cfg, err = load_result(tostring(TMP) .. "/out.moon")
    assert.is_nil(err)
    assert.not_nil(cfg)
    assert.equals("INFO", cfg.runtime.log_level)
    assert.is_false(cfg.runtime.benchmark)
    return assert.equals(2, #cfg.filter.allowed_domains)
  end)
  it("affiche un message de confirmation sur la sortie standard", function()
    write_file(tostring(TMP) .. "/base/config.moon", [[ { runtime: { log_level: "INFO" } } ]])
    local ret, out = run("--base " .. tostring(TMP) .. "/base/config.moon --hostname nobody --output " .. tostring(TMP) .. "/out.moon")
    assert.equals(0, ret)
    return assert.truthy(out:match("mis à jour"))
  end)
  return it("--reload ne plante pas si le service est inactif (SIGHUP ignoré)", function()
    write_file(tostring(TMP) .. "/base/config.moon", [[ { runtime: { log_level: "INFO" } } ]])
    local ret, _ = run("--base " .. tostring(TMP) .. "/base/config.moon --hostname nobody --output " .. tostring(TMP) .. "/out.moon --reload")
    assert.equals(0, ret)
    return assert.truthy(read_file(tostring(TMP) .. "/out.moon"))
  end)
end)
local APPLY_MOD = assert(loadfile(APPLY))()
local capture_stderr
capture_stderr = function(fn)
  local captured = { }
  local original = io.stderr
  io.stderr = {
    write = function(self, msg)
      captured[#captured + 1] = msg
    end
  }
  local ok, result = pcall(fn)
  io.stderr = original
  if not (ok) then
    error(result)
  end
  return table.concat(captured), result
end
local fake_read_pid
fake_read_pid = function(pid, err)
  return function(path)
    return pid, err
  end
end
local fake_handle
fake_handle = function(output)
  local fh = { }
  fh.read = function(self, fmt)
    return output
  end
  fh.close = function(self)
    return nil
  end
  return fh
end
describe("sync/apply — reload_supervisor", function()
  it("appelle kill_fn avec le PID du pidfile et SIGHUP (1)", function()
    local calls = { }
    local kill_fn
    kill_fn = function(pid, sig)
      calls[#calls + 1] = {
        pid,
        sig
      }
      return true
    end
    local ok = APPLY_MOD.reload_supervisor("tmp/apply_spec/pidfile", kill_fn, fake_read_pid(4242))
    assert.is_true(ok)
    assert.equals(1, #calls)
    assert.equals(4242, calls[1][1])
    return assert.equals(APPLY_MOD.SIGHUP, calls[1][2])
  end)
  it("n'appelle pas kill_fn et avertit si le pidfile est absent", function()
    local calls = { }
    local kill_fn
    kill_fn = function(pid, sig)
      calls[#calls + 1] = pid
      return true
    end
    local out, ok = capture_stderr(function()
      return APPLY_MOD.reload_supervisor("tmp/apply_spec/absent.pid", kill_fn, fake_read_pid(nil, "pidfile introuvable : tmp/apply_spec/absent.pid"))
    end)
    assert.is_false(ok)
    assert.equals(0, #calls)
    assert.truthy(out:match("SIGHUP non envoyé"))
    return assert.truthy(out:match("pidfile introuvable"))
  end)
  return it("n'émet jamais de pkill (aucune commande shell de repli)", function()
    local src = read_file(APPLY)
    assert.falsy(src:find("pkill", 1, true))
    local seen = { }
    local original = os.execute
    os.execute = function(cmd)
      seen[#seen + 1] = cmd
      return 0
    end
    local out, ok = capture_stderr(function()
      return APPLY_MOD.reload_supervisor("tmp/apply_spec/absent.pid", nil, fake_read_pid(nil, "absent"))
    end)
    os.execute = original
    assert.is_false(ok)
    return assert.equals(0, #seen)
  end)
end)
describe("sync/apply — resolve_hostname", function()
  it("renvoie le nom d'hôte de uname -n", function()
    local popen
    popen = function(cmd)
      return fake_handle("  router1  ")
    end
    return assert.equals("router1", APPLY_MOD.resolve_hostname(popen))
  end)
  it("échoue explicitement si uname -n renvoie une sortie vide", function()
    local popen
    popen = function(cmd)
      return fake_handle("")
    end
    local out, host = capture_stderr(function()
      return APPLY_MOD.resolve_hostname(popen)
    end)
    assert.is_nil(host)
    return assert.truthy(out:match("nom d'hôte vide"))
  end)
  it("échoue explicitement si le lancement de uname -n échoue", function()
    local out, host = capture_stderr(function()
      return APPLY_MOD.resolve_hostname((function()
        return nil
      end))
    end)
    assert.is_nil(host)
    return assert.truthy(out:match("uname %-n indisponible"))
  end)
  return it("rejette une sortie de uname -n non conforme (traversée, slash)", function()
    local _list_0 = {
      "../../etc",
      "a/b",
      "a b"
    }
    for _index_0 = 1, #_list_0 do
      local raw = _list_0[_index_0]
      local out, host = capture_stderr(function()
        return APPLY_MOD.resolve_hostname((function()
          return fake_handle(raw)
        end))
      end)
      assert.is_nil(host, raw)
      assert.truthy(out:match("nom d'hôte invalide"))
    end
  end)
end)
return describe("sync/apply — valid_hostname", function()
  it("accepte les noms usuels (lettres, chiffres, point, tiret, souligné)", function()
    local _list_0 = {
      "router1",
      "router.lan",
      "a_b-c",
      "CUSTOS-01"
    }
    for _index_0 = 1, #_list_0 do
      local h = _list_0[_index_0]
      assert.is_true(APPLY_MOD.valid_hostname(h), h)
    end
  end)
  return it("rejette les composants de traversée et les séparateurs de chemin", function()
    local _list_0 = {
      ".",
      "..",
      "../etc",
      "a/b",
      "a b",
      "a;b",
      ""
    }
    for _index_0 = 1, #_list_0 do
      local h = _list_0[_index_0]
      assert.is_false(APPLY_MOD.valid_hostname(h), h)
    end
    return assert.is_false(APPLY_MOD.valid_hostname(nil))
  end)
end)
