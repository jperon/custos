local RED = "\27[0;31m"
local GREEN = "\27[0;32m"
local YELLOW = "\27[1;33m"
local CYAN = "\27[0;36m"
local BOLD = "\27[1m"
local NC = "\27[0m"
local ok
ok = function(msg)
  return io.write(tostring(GREEN) .. "[+]" .. tostring(NC) .. " " .. tostring(msg) .. "\n")
end
local warn
warn = function(msg)
  return io.write(tostring(YELLOW) .. "[!]" .. tostring(NC) .. " " .. tostring(msg) .. "\n")
end
local fail
fail = function(msg)
  return io.write(tostring(RED) .. "[-]" .. tostring(NC) .. " " .. tostring(msg) .. "\n")
end
local info
info = function(msg)
  return io.write(tostring(CYAN) .. "[*]" .. tostring(NC) .. " " .. tostring(msg) .. "\n")
end
local step
step = function(msg)
  return io.write("\n" .. tostring(BOLD) .. "━━ " .. tostring(msg) .. tostring(NC) .. "\n")
end
local have_cmd
have_cmd = function(cmd)
  local fh = io.popen("command -v " .. tostring(cmd) .. " 2>/dev/null")
  if not (fh) then
    return false
  end
  local out = fh:read("*l")
  fh:close()
  return out ~= nil and out ~= ""
end
local run
run = function(cmd, dry)
  if dry then
    io.write("  " .. tostring(CYAN) .. "DRY" .. tostring(NC) .. " " .. tostring(cmd) .. "\n")
    return true
  end
  local code = os.execute(cmd)
  return code == 0
end
local capture
capture = function(cmd)
  local fh = io.popen(tostring(cmd) .. " 2>&1")
  if not (fh) then
    return nil
  end
  local out = fh:read("*a")
  fh:close()
  return out
end
local ssh_prefix
ssh_prefix = function(cfg)
  return "ssh -p " .. tostring(cfg.port) .. " -o StrictHostKeyChecking=no -o ConnectTimeout=10 " .. tostring(cfg.user) .. "@" .. tostring(cfg.ip)
end
local ssh_run
ssh_run = function(cfg, cmd)
  local escaped = cmd:gsub("'", "'\"'\"'")
  return run(tostring(ssh_prefix(cfg)) .. " '" .. tostring(escaped) .. "'", cfg.dry)
end
local ssh_capture
ssh_capture = function(cfg, cmd)
  local escaped = cmd:gsub("'", "'\"'\"'")
  return capture(tostring(ssh_prefix(cfg)) .. " '" .. tostring(escaped) .. "'")
end
local ssh_run_script
ssh_run_script = function(cfg, name, content)
  local tmplocal = "tmp/owrt-" .. tostring(name) .. ".sh"
  if not (cfg.dry) then
    local fh = io.open(tmplocal, "w")
    if not (fh) then
      fail("Impossible d'écrire " .. tostring(tmplocal))
      return false
    end
    fh:write(content)
    fh:close()
  else
    io.write("  " .. tostring(CYAN) .. "DRY" .. tostring(NC) .. " write " .. tostring(tmplocal) .. "\n")
  end
  local ok_scp = run("scp -P " .. tostring(cfg.port) .. " -o StrictHostKeyChecking=no " .. tostring(tmplocal) .. " " .. tostring(cfg.user) .. "@" .. tostring(cfg.ip) .. ":/tmp/" .. tostring(name) .. ".sh", cfg.dry)
  if not (ok_scp) then
    return false
  end
  return ssh_run(cfg, "sh /tmp/" .. tostring(name) .. ".sh && rm -f /tmp/" .. tostring(name) .. ".sh")
end
local scp_send
scp_send = function(cfg, src, dst)
  return run("scp -P " .. tostring(cfg.port) .. " -o StrictHostKeyChecking=no -r " .. tostring(src) .. " " .. tostring(cfg.user) .. "@" .. tostring(cfg.ip) .. ":" .. tostring(dst), cfg.dry)
end
local check_local_deps
check_local_deps = function(cfg)
  step("Vérification des dépendances locales")
  local ok_all = true
  local _list_0 = {
    "ssh",
    "scp"
  }
  for _index_0 = 1, #_list_0 do
    local cmd = _list_0[_index_0]
    if have_cmd(cmd) then
      ok(tostring(cmd) .. " disponible")
    else
      fail(tostring(cmd) .. " introuvable dans le PATH")
      ok_all = false
    end
  end
  if not cfg.no_build then
    if have_cmd("make") then
      ok("make disponible")
    elseif have_cmd("moonc" and have_cmd("luajit")) then
      ok("moonc + luajit disponibles (make absent)")
    else
      warn("make / moonc introuvables — utiliser --no-build si lua/ est déjà compilé")
      ok_all = false
    end
  end
  return ok_all
end
local build_local
build_local = function(cfg)
  step("Compilation MoonScript → Lua")
  if cfg.no_build then
    warn("--no-build : compilation ignorée (lua/ doit déjà être à jour)")
    return true
  end
  if have_cmd("make") then
    if run("make all", cfg.dry) then
      ok("Compilation réussie")
      return true
    else
      fail("Échec de 'make all'")
      return false
    end
  else
    local ok_all = true
    for _, src in ipairs({
      "config",
      "ffi_defs",
      "log",
      "parse/ethernet",
      "parse/ip",
      "parse/udp",
      "parse/dns",
      "ffi_ndpi",
      "ffi_ndpi_v4",
      "ffi_ndpi_v5",
      "parse/ndpi",
      "parse/ndpi_v4",
      "parse/ndpi_v5",
      "ipc",
      "allowlist",
      "nft",
      "nfq_loop",
      "refuse",
      "worker_q0",
      "worker_q1",
      "main"
    }) do
      local dst = "lua/" .. tostring(src) .. ".lua"
      if not run("moonc -o " .. tostring(dst) .. " src/" .. tostring(src) .. ".moon", cfg.dry) then
        fail("Échec compilation src/" .. tostring(src) .. ".moon")
        ok_all = false
      end
    end
    return ok_all
  end
end
local check_connectivity
check_connectivity = function(cfg)
  step("Vérification de la connectivité SSH (" .. tostring(cfg.user) .. "@" .. tostring(cfg.ip) .. ":" .. tostring(cfg.port) .. ")")
  local out = ssh_capture(cfg, "uname -a")
  if out and out:find("Linux") then
    ok("Connecté : " .. tostring(out:match('%S+%s+%S+%s+(%S+)')))
    return true
  end
  fail("Impossible de joindre le routeur — vérifier ip/port/clé SSH")
  return false
end
local detect_pkg_manager
detect_pkg_manager = function(cfg)
  step("Détection du gestionnaire de paquets")
  local out_apk = ssh_capture(cfg, "command -v apk  2>/dev/null")
  local out_opkg = ssh_capture(cfg, "command -v opkg 2>/dev/null")
  if out_apk and out_apk:match("/apk") then
    cfg.pkg_mgr = "apk"
    ok("Gestionnaire détecté : apk (OpenWrt ≥ 24.10)")
  elseif out_opkg and out_opkg:match("/opkg") then
    cfg.pkg_mgr = "opkg"
    ok("Gestionnaire détecté : opkg (OpenWrt ≤ 23.05)")
  else
    fail("Ni apk ni opkg trouvés sur le routeur")
    return false
  end
  return true
end
local install_pkg_deps
install_pkg_deps = function(cfg)
  local pm = cfg.pkg_mgr
  step("Installation des paquets (" .. tostring(pm) .. ")")
  info("Mise à jour des listes " .. tostring(pm) .. "...")
  local update_cmd = pm == "apk" and "apk update" or "opkg update"
  if not (ssh_run(cfg, update_cmd)) then
    warn(tostring(update_cmd) .. " a échoué — les listes peuvent être périmées, on continue")
  end
  local pkgs_required = {
    "luajit",
    "libnetfilter-queue",
    "nftables",
    "kmod-br-netfilter",
    "kmod-nft-queue"
  }
  local pkgs_optional = {
    "libndpi"
  }
  local install_cmd
  if pm == "apk" then
    install_cmd = function(pkg)
      return "apk add " .. tostring(pkg)
    end
  else
    install_cmd = function(pkg)
      return "opkg install " .. tostring(pkg)
    end
  end
  local check_cmd
  if pm == "apk" then
    check_cmd = function(pkg)
      return "apk info -e " .. tostring(pkg) .. " 2>/dev/null && echo installed"
    end
  else
    check_cmd = function(pkg)
      return "opkg list-installed " .. tostring(pkg) .. " 2>/dev/null"
    end
  end
  local ok_all = true
  for _index_0 = 1, #pkgs_required do
    local pkg = pkgs_required[_index_0]
    info("  " .. tostring(install_cmd(pkg)))
    if not (ssh_run(cfg, install_cmd(pkg))) then
      local installed = ssh_capture(cfg, check_cmd(pkg))
      if installed and installed:find(pkg) then
        ok("  " .. tostring(pkg) .. " déjà installé")
      else
        fail("  Impossible d'installer " .. tostring(pkg))
        ok_all = false
      end
    end
  end
  for _index_0 = 1, #pkgs_optional do
    local pkg = pkgs_optional[_index_0]
    info("  " .. tostring(install_cmd(pkg)) .. " (optionnel)")
    if ssh_run(cfg, install_cmd(pkg)) then
      ok("  " .. tostring(pkg) .. " installé")
    else
      warn("  " .. tostring(pkg) .. " introuvable dans " .. tostring(pm) .. " — ajoutez le feed packages OpenWrt")
      warn("  Sans libndpi, le filtre ne démarrera pas (dépendance ffi.load)")
    end
  end
  return ok_all
end
local upload_files
upload_files = function(cfg)
  step("Copie des fichiers vers " .. tostring(cfg.dest))
  if not (ssh_run(cfg, "mkdir -p " .. tostring(cfg.dest) .. "/parse")) then
    fail("Impossible de créer " .. tostring(cfg.dest) .. "/parse")
    return false
  end
  info("  Envoi de lua/ → " .. tostring(cfg.dest) .. "/")
  if not (scp_send(cfg, "lua/.", cfg.dest)) then
    fail("Échec du transfert de lua/")
    return false
  end
  info("  Envoi de nft-rules/dns-filter.nft → " .. tostring(cfg.dest) .. "/")
  if not (scp_send(cfg, "nft-rules/dns-filter.nft", cfg.dest)) then
    fail("Échec du transfert de dns-filter.nft")
    return false
  end
  ok("Fichiers copiés")
  return true
end
local apply_nft_rules
apply_nft_rules = function(cfg)
  step("Application des règles nftables")
  local script = [[#!/bin/sh
set -e
NFT=]] .. cfg.dest .. [[/dns-filter.nft
TMP=/tmp/dns-filter-owrt.nft

sed \
  -e 's|192\.168\.1\.0/24|]] .. cfg.lan4 .. [[|g' \
  -e 's|fd00::/64|]] .. cfg.lan6 .. [[|g' \
  "$NFT" > "$TMP"

nft -f "$TMP" && echo "nft ok" && rm -f "$TMP"
]]
  if ssh_run_script(cfg, "apply-nft", script) then
    ok("Règles nft appliquées (LAN4=" .. tostring(cfg.lan4) .. "  LAN6=" .. tostring(cfg.lan6) .. ")")
    return true
  end
  fail("Échec de l'application des règles nft")
  return false
end
local enable_br_netfilter
enable_br_netfilter = function(cfg)
  step("Activation de br_netfilter")
  local script = [[#!/bin/sh
# kmod-br-netfilter doit être installé
modprobe br_netfilter 2>/dev/null || true
sysctl -qw net.bridge.bridge-nf-call-iptables=1  2>/dev/null || true
sysctl -qw net.bridge.bridge-nf-call-ip6tables=1 2>/dev/null || true

# Persistance au démarrage via /etc/sysctl.d/
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/10-custos.conf << 'SYSCTL_EOF'
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
SYSCTL_EOF
echo "br_netfilter ok"
]]
  if ssh_run_script(cfg, "br-netfilter", script) then
    ok("br_netfilter activé et persisté")
    return true
  end
  warn("br_netfilter : vérifiez que kmod-br-netfilter est chargé")
  return false
end
local install_initd
install_initd = function(cfg)
  step("Installation du service init.d/custos (procd)")
  local service = [[#!/bin/sh /etc/rc.common
# CustosVirginum — inline DNS filter
# /etc/init.d/custos

USE_PROCD=1
START=95
STOP=05

PROG=/usr/bin/luajit
CUSTOS_DIR=]] .. cfg.dest .. [[

start_service() {
    # S'assurer que br_netfilter est chargé avant le démarrage
    modprobe br_netfilter 2>/dev/null || true
    sysctl -qw net.bridge.bridge-nf-call-iptables=1  2>/dev/null || true
    sysctl -qw net.bridge.bridge-nf-call-ip6tables=1 2>/dev/null || true

    procd_open_instance
    procd_set_param command $PROG $CUSTOS_DIR/main.lua
    procd_set_param respawn ${respawn_threshold:-3600} ${respawn_timeout:-5} ${respawn_retry:-5}
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

reload_service() {
    # Envoie SIGHUP pour recharger la config (allowlist)
    kill -HUP $(pgrep -f "$CUSTOS_DIR/main.lua") 2>/dev/null || true
}
]]
  local tmplocal = "tmp/owrt-custos-initd"
  if not (cfg.dry) then
    local fh = io.open(tmplocal, "w")
    if fh then
      fh:write(service)
      fh:close()
    end
  end
  local ok_scp = run("scp -P " .. tostring(cfg.port) .. " -o StrictHostKeyChecking=no " .. tostring(tmplocal) .. " " .. tostring(cfg.user) .. "@" .. tostring(cfg.ip) .. ":/etc/init.d/custos", cfg.dry)
  if not (ok_scp) then
    fail("Échec de la copie du script init.d")
    return false
  end
  if not (ssh_run(cfg, "chmod +x /etc/init.d/custos && /etc/init.d/custos enable")) then
    fail("Échec activation du service")
    return false
  end
  ok("Service installé et activé au démarrage")
  return true
end
local start_service
start_service = function(cfg)
  step("Démarrage du service custos")
  if cfg.no_start then
    warn("--no-start : démarrage ignoré")
    warn("Lancer manuellement : /etc/init.d/custos start")
    return true
  end
  if not (ssh_run(cfg, "/etc/init.d/custos start")) then
    fail("Échec du démarrage")
    return false
  end
  os.execute("sleep 2")
  local status = ssh_capture(cfg, "pgrep -f main.lua && echo running || echo stopped")
  if status and status:find("running") then
    ok("Service démarré (luajit main.lua actif)")
  else
    warn("Service démarré mais le processus n'est pas encore visible")
    warn("Vérifier avec : ssh " .. tostring(cfg.user) .. "@" .. tostring(cfg.ip) .. " '/etc/init.d/custos status'")
  end
  return true
end
local print_usage
print_usage = function()
  io.write([[Usage: luajit install-owrt.lua <ip-routeur> [options]

Options:
  --port PORT    Port SSH                       (défaut : 22)
  --user USER    Utilisateur SSH                (défaut : root)
  --lan  CIDR    Réseau LAN IPv4                (défaut : 192.168.1.0/24)
  --lan6 CIDR    Réseau LAN IPv6                (défaut : fd00::/64)
  --dest DIR     Dossier de destination         (défaut : /usr/share/custos)
  --no-build     Ne pas recompiler lua/
  --no-start     Installer sans démarrer le service
  --dry-run      Afficher les commandes sans exécuter
  -h, --help     Afficher cette aide

Exemple:
  luajit install-owrt.lua 192.168.1.1
  luajit install-owrt.lua 192.168.1.1 --port 2222 --lan 10.0.0.0/24
  luajit install-owrt.lua 192.168.1.1 --dry-run
]])
  return os.exit(0)
end
local parse_args
parse_args = function()
  local cfg = {
    ip = nil,
    port = 22,
    user = "root",
    lan4 = "192.168.1.0/24",
    lan6 = "fd00::/64",
    dest = "/usr/share/custos",
    no_build = false,
    no_start = false,
    dry = false,
    pkg_mgr = nil
  }
  local i = 1
  while i <= #arg do
    local a = arg[i]
    if a == "-h" or a == "--help" then
      print_usage()
    elseif a == "--no-build" then
      cfg.no_build = true
    elseif a == "--no-start" then
      cfg.no_start = true
    elseif a == "--dry-run" then
      cfg.dry = true
    elseif a == "--port" then
      i = i + 1
      cfg.port = tonumber(arg[i]) or (fail("--port attend un entier") and os.exit(1))
    elseif a == "--user" then
      i = i + 1
      cfg.user = arg[i]
    elseif a == "--lan" then
      i = i + 1
      cfg.lan4 = arg[i]
    elseif a == "--lan6" then
      i = i + 1
      cfg.lan6 = arg[i]
    elseif a == "--dest" then
      i = i + 1
      cfg.dest = arg[i]
    elseif a:sub(1, 1) == "-" then
      fail("Option inconnue : " .. tostring(a))
      os.exit(1)
    else
      cfg.ip = a
    end
    i = i + 1
  end
  return cfg
end
local main
main = function()
  local cfg = parse_args()
  if not (cfg.ip) then
    fail("Adresse IP du routeur manquante.")
    print_usage()
    os.exit(1)
  end
  io.write(tostring(BOLD) .. "╔══════════════════════════════════════════╗\n")
  io.write("║   CustosVirginum — Install OpenWrt       ║\n")
  io.write("╚══════════════════════════════════════════╝" .. tostring(NC) .. "\n")
  info("Cible  : " .. tostring(cfg.user) .. "@" .. tostring(cfg.ip) .. ":" .. tostring(cfg.port))
  info("LAN4   : " .. tostring(cfg.lan4) .. "    LAN6 : " .. tostring(cfg.lan6))
  info("Dest   : " .. tostring(cfg.dest))
  if cfg.dry then
    warn("MODE DRY-RUN — aucune commande réelle exécutée\n")
  end
  local steps = {
    {
      name = "deps locales",
      fn = function()
        return check_local_deps(cfg)
      end
    },
    {
      name = "compilation",
      fn = function()
        return build_local(cfg)
      end
    },
    {
      name = "connectivité SSH",
      fn = function()
        return check_connectivity(cfg)
      end
    },
    {
      name = "détection pkg mgr",
      fn = function()
        return detect_pkg_manager(cfg)
      end
    },
    {
      name = "paquets",
      fn = function()
        return install_pkg_deps(cfg)
      end
    },
    {
      name = "upload fichiers",
      fn = function()
        return upload_files(cfg)
      end
    },
    {
      name = "br_netfilter",
      fn = function()
        return enable_br_netfilter(cfg)
      end
    },
    {
      name = "règles nft",
      fn = function()
        return apply_nft_rules(cfg)
      end
    },
    {
      name = "service init.d",
      fn = function()
        return install_initd(cfg)
      end
    },
    {
      name = "démarrage service",
      fn = function()
        return start_service(cfg)
      end
    }
  }
  for _index_0 = 1, #steps do
    local s = steps[_index_0]
    if not (s.fn()) then
      fail("\nInstallation interrompue à l'étape « " .. tostring(s.name) .. " ».")
      os.exit(1)
    end
  end
  io.write("\n" .. tostring(GREEN) .. tostring(BOLD) .. "✓ Installation terminée." .. tostring(NC) .. "\n")
  info("Statut   : ssh " .. tostring(cfg.user) .. "@" .. tostring(cfg.ip) .. " '/etc/init.d/custos status'")
  info("Logs     : ssh " .. tostring(cfg.user) .. "@" .. tostring(cfg.ip) .. " 'logread | grep custos'")
  return info("Reload   : ssh " .. tostring(cfg.user) .. "@" .. tostring(cfg.ip) .. " '/etc/init.d/custos reload'")
end
return main()
