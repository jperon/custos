local popen, execute
do
  local _obj_0 = require("io")
  popen, execute = _obj_0.popen, _obj_0.execute
end
local getenv
getenv = require("os").getenv
local LAB_DIR = "lab"
local HELPER = tostring(LAB_DIR) .. "/custos-lab-helper.sh"
local TESTS = tostring(LAB_DIR) .. "/custos-lab-tests.sh"
local C = {
  green = "\27[32m",
  red = "\27[31m",
  yellow = "\27[33m",
  blue = "\27[34m",
  bold = "\27[1m",
  reset = "\27[0m"
}
local run
run = function(cmd)
  local fh = popen(cmd)
  local out = fh:read("*a")
  local ok = fh:close()
  return ok, out
end
local run_check
run_check = function(cmd)
  local ok, out = run(cmd)
  if not (ok) then
    error("Échec: " .. tostring(cmd) .. "\n" .. tostring(out))
  end
  return out
end
local section
section = function(title)
  return print(tostring(C.bold) .. "==> " .. tostring(title) .. tostring(C.reset))
end
local main
main = function()
  section("[1/5] Démarrage du lab Holos")
  run_check("cd " .. tostring(LAB_DIR) .. " && ./custos-lab-helper.sh up")
  section("[2/5] Déploiement de Custos sur le filtre")
  local custos_bin = "./target/release/custos"
  run_check("make all")
  run_check("cd " .. tostring(LAB_DIR) .. " && ./custos-lab-helper.sh deploy-custos " .. tostring(custos_bin))
  section("[3/5] Attente du démarrage complet")
  run_check("cd " .. tostring(LAB_DIR) .. " && ./custos-lab-helper.sh ps")
  execute("sleep 10")
  section("[4/5] Lancement des tests réseau")
  local ok, out = run("cd " .. tostring(LAB_DIR) .. " && ./custos-lab-helper.sh test-network")
  print(out)
  if not (ok) then
    error("Échec test-network")
  end
  section("[5/5] Lancement des tests de filtrage")
  ok, out = run("cd " .. tostring(LAB_DIR) .. " && ./custos-lab-helper.sh test-filter")
  print(out)
  if not (ok) then
    error("Échec test-filter")
  end
  section("[Résumé] Vérification des logs")
  ok, out = run("cd " .. tostring(LAB_DIR) .. " && ./custos-lab-helper.sh logs openwrt-filter-0")
  print((out:match("(.+)$") or out))
  return print(tostring(C.green) .. "✓ Tous les tests Holos exécutés" .. tostring(C.reset))
end
return main()
