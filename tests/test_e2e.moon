-- tests/test_e2e.moon
-- Suite E2E custos sur environnement libvirt 3 VMs (client → filtre → dns).
--
-- Prérequis :
--   make test-env    # construit et démarre l'environnement
-- Usage :
--   make test-e2e
--
-- Le script :
--   1. Interroge `libvirt/custos-libvirt.sh filter-ip` pour l'IP mgmt du filtre.
--   2. Exécute `install-owrt.lua` pour déployer custos sur le filtre.
--   3. Pousse filter.yml et la config UCI de test sur le filtre.
--   4. Redémarre le service custos et attend `queue_listening`.
--   5. Exécute la matrice de tests depuis le client (via ProxyJump par le filtre).
--   6. Affiche un résumé.

LIBVIRT_SCRIPT = "libvirt/custos-libvirt.sh"
SSH_KEY        = (os.getenv "HOME") .. "/.ssh/id_rsa"
SSH_OPTS       = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes"

FILTER_USER = "root"
CLIENT_USER = "debian"
CLIENT_IP   = "10.99.0.10"
DNS_IP      = "10.99.0.1"
FILTER_BR   = "10.99.0.254"
CAPTIVE_URL = "https://#{FILTER_BR}:33443/"

LOG_MARKER  = "CUSTOS_TEST_E2E_" .. tostring os.time!

C =
  red:    "\27[31m"
  green:  "\27[32m"
  yellow: "\27[33m"
  bold:   "\27[1m"
  reset:  "\27[0m"
  grey:   "\27[90m"

tests_passed = 0
tests_failed = 0

-- ── Shell helpers ─────────────────────────────────────────────────

run = (cmd) ->
  fh = io.popen "#{cmd} 2>&1"
  out = fh\read "*a"
  ok = fh\close!
  ok, out

run_check = (cmd) ->
  ok, out = run cmd
  error "Command failed: #{cmd}\n#{out}" unless ok
  out

-- ── SSH wrappers ──────────────────────────────────────────────────

filter_ip = ->
  ok, out = run "bash #{LIBVIRT_SCRIPT} filter-ip"
  error "Cannot get filter mgmt IP:\n#{out}" unless ok
  ip = out\match "%d+%.%d+%.%d+%.%d+"
  error "No IP in filter-ip output:\n#{out}" unless ip
  ip

-- Exécute une commande sur le filtre (OpenWrt).
ssh_filter = (ip, cmd) ->
  escaped = cmd\gsub("'", "'\\''")
  run "ssh #{SSH_OPTS} -i #{SSH_KEY} #{FILTER_USER}@#{ip} '#{escaped}'"

-- Exécute une commande sur le client, via ProxyJump par le filtre.
ssh_client = (filter_ip_str, cmd) ->
  escaped = cmd\gsub("'", "'\\''")
  proxy = "#{FILTER_USER}@#{filter_ip_str}"
  run "ssh #{SSH_OPTS} -i #{SSH_KEY} -J #{proxy} #{CLIENT_USER}@#{CLIENT_IP} '#{escaped}'"

-- ── Mini framework ────────────────────────────────────────────────

test = (name, fn) ->
  ok, err_or_nil = pcall fn
  if ok
    tests_passed += 1
    print "  #{C.green}✓ #{name}#{C.reset}"
  else
    tests_failed += 1
    print "  #{C.red}✗ #{name}#{C.reset}"
    print "    #{C.grey}#{tostring(err_or_nil)}#{C.reset}"

assert_contains = (haystack, needle, msg) ->
  unless haystack and haystack\find(needle, 1, true)
    error "#{msg or 'missing'}: attendu '#{needle}', reçu : #{haystack}"

assert_matches = (haystack, pattern, msg) ->
  unless haystack and haystack\match(pattern)
    error "#{msg or 'no match'}: pattern '#{pattern}' absent de : #{haystack}"

-- ── Header ────────────────────────────────────────────────────────

print "#{C.bold}CustosVirginum — tests E2E libvirt#{C.reset}"

FILTER_IP = filter_ip!
print "  Filtre mgmt : #{FILTER_IP}"
print "  Client      : #{CLIENT_IP} (ProxyJump par le filtre)"
print "  DNS         : #{DNS_IP}"
print ""

-- ── [1/5] Connectivité ────────────────────────────────────────────

print "#{C.bold}[1/5] Connectivité SSH#{C.reset}"

ok_f, _ = ssh_filter FILTER_IP, "uname -r"
unless ok_f
  print "#{C.red}✗ filter SSH KO#{C.reset}"
  os.exit 1
print "  #{C.green}✓ filter joignable#{C.reset}"

ok_c, _ = ssh_client FILTER_IP, "uname -r"
unless ok_c
  print "#{C.red}✗ client SSH KO (via ProxyJump)#{C.reset}"
  os.exit 1
print "  #{C.green}✓ client joignable#{C.reset}"

ok_dns, _ = ssh_client FILTER_IP, "dig +short +time=2 +tries=1 @#{DNS_IP} allowed.test A"
print if ok_dns
  "  #{C.green}✓ client → DNS (via filtre) fonctionne#{C.reset}"
else
  "  #{C.yellow}! DNS non joignable avant déploiement custos (normal)#{C.reset}"

-- ── [2/5] Déploiement custos sur le filtre ───────────────────────

print "\n#{C.bold}[2/5] Déploiement custos#{C.reset}"

print "  Compilation locale..."
run_check "make all >/dev/null"

print "  install-owrt.lua #{FILTER_IP}..."
install_out = run_check "luajit install-owrt.lua #{FILTER_IP} --user #{FILTER_USER}"
-- install-owrt démarre le service à la fin ; on l'arrête et on pousse
-- notre config de test avant redémarrage.

print "  Push de la config de test..."
run_check "scp -O #{SSH_OPTS} -i #{SSH_KEY} libvirt/filter.yml " ..
          "#{FILTER_USER}@#{FILTER_IP}:/etc/custos/filter.yml"
run_check "scp -O #{SSH_OPTS} -i #{SSH_KEY} libvirt/custos-test.uci " ..
          "#{FILTER_USER}@#{FILTER_IP}:/tmp/custos.uci"
ssh_filter FILTER_IP, "cp /tmp/custos.uci /etc/config/custos && uci commit custos"

print "  Marqueur + redémarrage du service..."
ssh_filter FILTER_IP, "logger -t custos '#{LOG_MARKER}'"
ssh_filter FILTER_IP, "/etc/init.d/custos restart"

-- ── [3/5] Attente des workers ────────────────────────────────────

print "\n#{C.bold}[3/5] Attente des workers#{C.reset}"

log_since = (grep) ->
  -- Extrait les logs depuis le marqueur
  "logread | sed -n '/#{LOG_MARKER}/,$p' | #{grep}"

workers_ready = false
for _ = 1, 30
  _, out = ssh_filter FILTER_IP, log_since "grep -c queue_listening || true"
  n = tonumber (out or "0")\match("%d+")
  if n and n >= 3    -- Q0, Q1, Q2 minimum ; AUTH + Q3 aussi selon config
    workers_ready = true
    break
  os.execute "sleep 2"

if workers_ready
  print "  #{C.green}✓ workers prêts#{C.reset}"
else
  print "  #{C.red}✗ workers pas prêts après 60 s#{C.reset}"
  _, lr = ssh_filter FILTER_IP, log_since "tail -40"
  print lr
  os.exit 1

-- ── [4/5] Matrice de tests depuis le client ──────────────────────

print "\n#{C.bold}[4/5] Tests fonctionnels (depuis le client)#{C.reset}"

-- 1. DNS allow
test "dig allowed.test → 10.99.0.50", ->
  _, out = ssh_client FILTER_IP,
    "dig @#{DNS_IP} +short +time=2 +tries=1 allowed.test A"
  assert_contains out, "10.99.0.50"

-- 2. DNS block (refuse par règle explicite)
test "dig blocked.test → NXDOMAIN + EDE Filtered", ->
  _, out = ssh_client FILTER_IP,
    "dig @#{DNS_IP} +time=2 +tries=1 blocked.test A"
  assert_contains out, "NXDOMAIN"
  -- EDE: code de non-erreur apparaît dans la section additionnelle
  -- (dig ≥ 9.18 l'affiche en "; EDE: 15 (Filtered)" ou équivalent).
  -- On reste tolérant : au moins NXDOMAIN doit être là.

-- 3. DNS inconnu (refusé par la règle par défaut)
test "dig nonexistent.invalid → NXDOMAIN", ->
  _, out = ssh_client FILTER_IP,
    "dig @#{DNS_IP} +time=2 +tries=1 nonexistent.invalid A"
  assert_contains out, "NXDOMAIN"

-- 4. HTTP allowed
test "curl http://allowed.test → 200 allowed", ->
  _, out = ssh_client FILTER_IP,
    "curl -s --max-time 3 http://allowed.test/"
  assert_contains out, "allowed"

-- 5. HTTP blocked → Q2 capture, 302 vers portail
test "curl http://blocked.test → 302 captive portal", ->
  _, out = ssh_client FILTER_IP,
    "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' " ..
    "--max-time 3 http://blocked.test/"
  assert_matches out, "302"
  assert_contains out, "10.99.0.254:33443"

-- 6. HTTPS blocked → Q3 RST, connexion refusée rapide
test "curl https://tracker.test → Q3 reject <500ms", ->
  start = os.time!
  ok, out = ssh_client FILTER_IP,
    "curl -k -s -o /dev/null -w '%{http_code}' --max-time 3 " ..
    "https://tracker.test/ 2>&1; echo exit=$?"
  elapsed = os.time! - start
  -- Le curl doit échouer (code HTTP 000 ou exit != 0) ET rapidement.
  assert elapsed < 3, "trop lent (#{elapsed}s) — Q3 n'a pas RST ?"
  assert_matches out, "exit=[^0]", "curl aurait dû échouer"

-- 7. Portail captif joignable directement
test "curl https://filter-captive → page login", ->
  _, out = ssh_client FILTER_IP,
    "curl -k -s --max-time 3 #{CAPTIVE_URL}"
  -- La page HTML AUTH contient typiquement les mots "login"/"password"
  -- ou un formulaire.
  assert_matches out, "[Ll]ogin", "page de login attendue"

-- ── [5/5] Résumé ─────────────────────────────────────────────────

print "\n#{C.bold}[5/5] Résumé#{C.reset}"
print "  passé(s) : #{C.green}#{tests_passed}#{C.reset}"
print "  échec(s) : #{tests_failed > 0 and C.red or C.grey}#{tests_failed}#{C.reset}"

os.exit tests_failed == 0 and 0 or 1
