-- e2e_holos.moon : Tests E2E CustosVirginum via Holos
-- À lancer depuis la racine du projet : luajit tests/e2e_holos.lua

import popen, execute from require "io"
import getenv from require "os"

LAB_DIR = "lab"
HELPER  = "#{LAB_DIR}/custos-lab-helper.sh"
TESTS   = "#{LAB_DIR}/custos-lab-tests.sh"

C = {
  green:  "\27[32m"
  red:    "\27[31m"
  yellow: "\27[33m"
  blue:   "\27[34m"
  bold:   "\27[1m"
  reset:  "\27[0m"
}

run = (cmd) ->
  fh = popen cmd
  out = fh\read "*a"
  ok = fh\close!
  ok, out

run_check = (cmd) ->
  ok, out = run cmd
  error "Échec: #{cmd}\n#{out}" unless ok
  out

section = (title) ->
  print "#{C.bold}==> #{title}#{C.reset}"

main = ->
  section "[1/5] Démarrage du lab Holos"
  run_check "cd #{LAB_DIR} && ./custos-lab-helper.sh up"

  section "[2/5] Déploiement de Custos sur le filtre"
  -- À adapter selon la méthode de build/déploiement
  custos_bin = "./target/release/custos"
  run_check "make all"
  run_check "cd #{LAB_DIR} && ./custos-lab-helper.sh deploy-custos #{custos_bin}"

  section "[3/5] Attente du démarrage complet"
  run_check "cd #{LAB_DIR} && ./custos-lab-helper.sh ps"
  execute "sleep 10"

  section "[4/5] Lancement des tests réseau"
  ok, out = run "cd #{LAB_DIR} && ./custos-lab-helper.sh test-network"
  print out
  error "Échec test-network" unless ok

  section "[5/5] Lancement des tests de filtrage"
  ok, out = run "cd #{LAB_DIR} && ./custos-lab-helper.sh test-filter"
  print out
  error "Échec test-filter" unless ok

  section "[Résumé] Vérification des logs"
  ok, out = run "cd #{LAB_DIR} && ./custos-lab-helper.sh logs openwrt-filter-0"
  print (out\match("(.+)$") or out)
  print "#{C.green}✓ Tous les tests Holos exécutés#{C.reset}"

main!
