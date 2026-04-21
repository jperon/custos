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
local Installer
Installer = function(cfg)
  local obj = {
    cfg = cfg,
    have_cmd = function(self, cmd)
      local fh = io.popen("command -v " .. tostring(cmd) .. " 2>/dev/null")
      if not (fh) then
        return false
      end
      local out = fh:read("*l")
      fh:close()
      return out ~= nil and out ~= ""
    end,
    run = function(self, cmd)
      if self.cfg.dry then
        io.write("  " .. tostring(CYAN) .. "DRY" .. tostring(NC) .. " " .. tostring(cmd) .. "\n")
        return true
      end
      local code = os.execute(cmd)
      return code == 0 or code == true
    end,
    capture = function(self, cmd)
      local fh = io.popen(tostring(cmd) .. " 2>&1")
      if not (fh) then
        return nil
      end
      local out = fh:read("*a")
      fh:close()
      return out
    end,
    ssh_host = function(self)
      if self.cfg.host:find(":") then
        return "[" .. tostring(self.cfg.host) .. "]"
      else
        return self.cfg.host
      end
    end,
    ssh_prefix = function(self)
      return "ssh -p " .. tostring(self.cfg.port) .. " -o StrictHostKeyChecking=no -o ConnectTimeout=10 " .. tostring(self.cfg.user) .. "@" .. tostring(self:ssh_host())
    end,
    ssh_run = function(self, cmd)
      local escaped = cmd:gsub("'", "'\"'\"'")
      return self:run(tostring(self:ssh_prefix()) .. " '" .. tostring(escaped) .. "'")
    end,
    ssh_capture = function(self, cmd)
      local escaped = cmd:gsub("'", "'\"'\"'")
      return self:capture(tostring(self:ssh_prefix()) .. " '" .. tostring(escaped) .. "'")
    end,
    ssh_run_script = function(self, name, content)
      local tmplocal = "tmp/owrt-" .. tostring(name) .. ".sh"
      if not (self.cfg.dry) then
        os.execute("mkdir -p tmp")
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
      local ok_scp = self:run("scp -O -P " .. tostring(self.cfg.port) .. " -o StrictHostKeyChecking=no " .. tostring(tmplocal) .. " " .. tostring(self.cfg.user) .. "@" .. tostring(self:ssh_host()) .. ":/tmp/" .. tostring(name) .. ".sh")
      if not (ok_scp) then
        return false
      end
      return self:ssh_run("sh /tmp/" .. tostring(name) .. ".sh && rm -f /tmp/" .. tostring(name) .. ".sh")
    end,
    scp_send = function(self, src, dst)
      return self:run("scp -O -P " .. tostring(self.cfg.port) .. " -o StrictHostKeyChecking=no -r " .. tostring(src) .. " " .. tostring(self.cfg.user) .. "@" .. tostring(self:ssh_host()) .. ":" .. tostring(dst))
    end,
    check_local_deps = function(self)
      step("Vérification des dépendances locales")
      local ok_all = true
      local _list_0 = {
        "ssh",
        "scp",
        "tar"
      }
      for _index_0 = 1, #_list_0 do
        local cmd = _list_0[_index_0]
        if self:have_cmd(cmd) then
          ok(tostring(cmd) .. " disponible")
        else
          fail(tostring(cmd) .. " introuvable dans le PATH")
          ok_all = false
        end
      end
      if not self.cfg.no_build then
        if self:have_cmd("make") then
          ok("make disponible")
        elseif self:have_cmd("moonc" and self:have_cmd("luajit")) then
          ok("moonc + luajit disponibles (make absent)")
        else
          warn("make / moonc introuvables — utiliser --no-build si lua/ est déjà compilé")
          ok_all = false
        end
      end
      return ok_all
    end,
    build_local = function(self)
      step("Compilation MoonScript → Lua")
      if self.cfg.no_build then
        warn("--no-build : compilation ignorée (lua/ doit déjà être à jour)")
        return true
      end
      if self:have_cmd("make") then
        if self:run("make all") then
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
          "worker_q0",
          "worker_q1",
          "main"
        }) do
          local dst = "lua/" .. tostring(src) .. ".lua"
          if not self:run("moonc -o " .. tostring(dst) .. " src/" .. tostring(src) .. ".moon") then
            fail("Échec compilation src/" .. tostring(src) .. ".moon")
            ok_all = false
          end
        end
        return ok_all
      end
    end,
    check_connectivity = function(self)
      step("Vérification de la connectivité SSH (" .. tostring(self.cfg.user) .. "@" .. tostring(self.cfg.host) .. ":" .. tostring(self.cfg.port) .. ")")
      local out = self:ssh_capture("uname -a")
      if out and out:find("Linux") then
        ok("Connecté : " .. tostring(out:match('%S+%s+%S+%s+(%S+)')))
        return true
      end
      fail("Impossible de joindre le routeur — vérifier ip/port/clé SSH")
      return false
    end,
    detect_pkg_manager = function(self)
      step("Détection du gestionnaire de paquets")
      local out_apk = self:ssh_capture("command -v apk  2>/dev/null")
      local out_opkg = self:ssh_capture("command -v opkg 2>/dev/null")
      if out_apk and out_apk:match("/apk") then
        self.cfg.pkg_mgr = "apk"
        ok("Gestionnaire détecté : apk (OpenWrt ≥ 24.10)")
      elseif out_opkg and out_opkg:match("/opkg") then
        self.cfg.pkg_mgr = "opkg"
        ok("Gestionnaire détecté : opkg (OpenWrt ≤ 23.05)")
      else
        fail("Ni apk ni opkg trouvés sur le routeur")
        return false
      end
      return true
    end,
    install_pkg_deps = function(self)
      local pm = self.cfg.pkg_mgr
      step("Installation des paquets (" .. tostring(pm) .. ")")
      info("Mise à jour des listes " .. tostring(pm) .. "...")
      local update_cmd = pm == "apk" and "apk update" or "opkg update"
      if not (self:ssh_run(update_cmd)) then
        warn(tostring(update_cmd) .. " a échoué — les listes peuvent être périmées, on continue")
      end
      local pkgs_required = {
        "luajit",
        "libnetfilter-queue",
        "nftables",
        "kmod-nft-queue",
        "lyaml",
        "luasec",
        "libxxhash",
        "openssl-util",
        "libndpi"
      }
      local pkg_list = table.concat(pkgs_required, " ")
      local install_cmd
      if pm == "apk" then
        install_cmd = "apk add " .. tostring(pkg_list)
      else
        install_cmd = "opkg install " .. tostring(pkg_list)
      end
      info("  " .. tostring(install_cmd))
      if self:ssh_run(install_cmd) then
        ok("Tous les paquets installés")
        return true
      else
        fail("Impossible d'installer les paquets")
        return false
      end
    end,
    upload_files = function(self)
      step("Copie des fichiers vers " .. tostring(self.cfg.dest))
      info("  Compression de lua/...")
      local archive = "tmp/custos-lua.tar.gz"
      if not (self:run("tar -czf " .. tostring(archive) .. " -C lua .")) then
        fail("Échec de la compression de lua/")
        return false
      end
      if not (self:ssh_run("mkdir -p " .. tostring(self.cfg.dest) .. "/parse")) then
        fail("Impossible de créer " .. tostring(self.cfg.dest) .. "/parse")
        return false
      end
      info("  Envoi de l'archive → /tmp/")
      if not (self:run("scp -O -P " .. tostring(self.cfg.port) .. " -o StrictHostKeyChecking=no " .. tostring(archive) .. " " .. tostring(self.cfg.user) .. "@" .. tostring(self:ssh_host()) .. ":/tmp/custos-lua.tar.gz")) then
        fail("Échec du transfert de l'archive")
        return false
      end
      info("  Extraction sur le routeur → " .. tostring(self.cfg.dest) .. "/")
      if not (self:ssh_run("tar -xzf /tmp/custos-lua.tar.gz -C " .. tostring(self.cfg.dest) .. " && rm -f /tmp/custos-lua.tar.gz")) then
        fail("Échec de l'extraction sur le routeur")
        return false
      end
      local nft_file = "nft-rules/dns-filter-bridge.nft"
      info("  Envoi de " .. tostring(nft_file) .. " → " .. tostring(self.cfg.dest) .. "/")
      if not (self:scp_send(nft_file, self.cfg.dest)) then
        fail("Échec du transfert de " .. tostring(nft_file))
        return false
      end
      ok("Fichiers copiés")
      return true
    end,
    install_initd = function(self)
      step("Installation du service init.d/custos (procd)")
      local init_src = "packaging/openwrt/custos/files/etc/init.d/custos"
      local tmplocal = "tmp/owrt-custos-initd"
      if not (self.cfg.dry) then
        local fh = io.open(init_src, "r")
        if not (fh) then
          fail("Impossible de lire " .. tostring(init_src))
          return false
        end
        local content = fh:read("*a")
        fh:close()
        content = content:gsub("/usr/share/custos", self.cfg.dest)
        os.execute("mkdir -p tmp")
        fh = io.open(tmplocal, "w")
        if not (fh) then
          fail("Impossible d'écrire " .. tostring(tmplocal))
          return false
        end
        fh:write(content)
        fh:close()
      else
        io.write("  " .. tostring(CYAN) .. "DRY" .. tostring(NC) .. " adapt " .. tostring(init_src) .. " → " .. tostring(tmplocal) .. "\n")
      end
      if not (self:run("scp -O -P " .. tostring(self.cfg.port) .. " -o StrictHostKeyChecking=no " .. tostring(tmplocal) .. " " .. tostring(self.cfg.user) .. "@" .. tostring(self:ssh_host()) .. ":/etc/init.d/custos")) then
        fail("Échec de la copie du script init.d")
        return false
      end
      if not (self:ssh_run("chmod +x /etc/init.d/custos && /etc/init.d/custos enable")) then
        fail("Échec activation du service")
        return false
      end
      ok("Service installé et activé au démarrage")
      return true
    end,
    install_etc_custos = function(self)
      step("Configuration /etc/custos/")
      self:ssh_run("mkdir -p /etc/custos")
      local _list_0 = {
        {
          src = "cfg/filter.yml",
          dst = "/etc/custos/filter.yml"
        },
        {
          src = "cfg/secrets",
          dst = "/etc/custos/secrets"
        }
      }
      for _index_0 = 1, #_list_0 do
        local _continue_0 = false
        repeat
          local entry = _list_0[_index_0]
          local exists = self:ssh_capture("[ -f " .. tostring(entry.dst) .. " ] && echo yes || echo no")
          if exists and exists:find("yes") then
            warn(tostring(entry.dst) .. " existe deja -- fichier preserve")
            _continue_0 = true
            break
          end
          if not (self:run("scp -O -P " .. tostring(self.cfg.port) .. " -o StrictHostKeyChecking=no " .. tostring(entry.src) .. " " .. tostring(self.cfg.user) .. "@" .. tostring(self:ssh_host()) .. ":" .. tostring(entry.dst))) then
            fail("Echec de la copie de " .. tostring(entry.dst))
            return false
          end
          self:ssh_run("chmod 600 " .. tostring(entry.dst))
          ok(tostring(entry.dst) .. " installe")
          _continue_0 = true
        until true
        if not _continue_0 then
          break
        end
      end
      return true
    end,
    install_uci_config = function(self)
      step("Configuration UCI (/etc/config/custos)")
      local exists = self:ssh_capture("[ -f /etc/config/custos ] && echo yes || echo no")
      if exists and exists:find("yes") then
        warn("/etc/config/custos existe déjà — configuration préservée")
        return true
      end
      local uci_cfg = [[config custos 'main'
	option enabled           '1'
	option forced_ttl        '60'
	option nft_ip_timeout    '2m'
	option ipc_pending_ttl   '5'
	option client_expiry     '300'
	option neigh_refresh_cooldown '10'
	list   allowed_domains   'local'
	list   allowed_domains   'lan'
	list   allowed_domains   'home.arpa'
]]
      local tmplocal = "tmp/owrt-custos-uci"
      if not (self.cfg.dry) then
        local fh = io.open(tmplocal, "w")
        if fh then
          fh:write(uci_cfg)
          fh:close()
        end
      end
      if not (self:run("scp -O -P " .. tostring(self.cfg.port) .. " -o StrictHostKeyChecking=no " .. tostring(tmplocal) .. " " .. tostring(self.cfg.user) .. "@" .. tostring(self:ssh_host()) .. ":/etc/config/custos")) then
        fail("Échec de la copie de /etc/config/custos")
        return false
      end
      ok("/etc/config/custos installé")
      return true
    end,
    start_service = function(self)
      step("Démarrage du service custos")
      if self.cfg.no_start then
        warn("--no-start : démarrage ignoré")
        return true
      end
      if not (self:ssh_run("/etc/init.d/custos restart")) then
        fail("Échec du démarrage")
        return false
      end
      os.execute("sleep 2")
      local status = self:ssh_capture("pgrep -f main.lua && echo running || echo stopped")
      if status and status:find("running") then
        ok("Service démarré (luajit main.lua actif)")
      else
        warn("Service démarré mais le processus n'est pas encore visible")
      end
      return true
    end,
    health_check = function(self)
      step("Vérification de la santé (logread)")
      local out = self:ssh_capture("logread | grep custos | tail -n 20")
      if out and out:find("error") then
        warn("Des erreurs ont été détectées dans les logs :")
        info(out)
      elseif out then
        ok("Le service semble fonctionner correctement")
      else
        warn("Aucun log trouvé pour 'custos' — vérifiez le démarrage")
      end
      return true
    end,
    install_updater = function(self)
      step("Script de mise à jour des listes (custos-update)")
      local script = [[#!/bin/sh
CUSTOS_DIR=]] .. self.cfg.dest .. "\n" .. [[
CONFIG=/etc/custos/filter.yml
PID_FILE=/var/run/custos.pid

PROG=$(command -v luajit2 2>/dev/null || command -v luajit 2>/dev/null)
[ -z "$PROG" ] && { echo "custos-update: luajit introuvable"; exit 1; }
[ -f "$CONFIG" ] || { echo "custos-update: $CONFIG introuvable"; exit 1; }

export LUA_PATH="$CUSTOS_DIR/?.lua;$CUSTOS_DIR/?/init.lua;;"

PID_ARG=""
[ -f "$PID_FILE" ] && PID_ARG="--pid $PID_FILE"

exec "$PROG" "$CUSTOS_DIR/filter/updater.lua" \
    --config "$CONFIG" \
    $PID_ARG \
    "$@"
]]
      local tmplocal = "tmp/owrt-custos-update"
      if not (self.cfg.dry) then
        local fh = io.open(tmplocal, "w")
        if fh then
          fh:write(script)
          fh:close()
        end
      end
      if not (self:run("scp -O -P " .. tostring(self.cfg.port) .. " -o StrictHostKeyChecking=no " .. tostring(tmplocal) .. " " .. tostring(self.cfg.user) .. "@" .. tostring(self:ssh_host()) .. ":/usr/sbin/custos-update")) then
        fail("Échec de la copie de custos-update")
        return false
      end
      if not (self:ssh_run("chmod +x /usr/sbin/custos-update")) then
        fail("Échec du chmod +x custos-update")
        return false
      end
      local cron_entry = "0 4 * * * /usr/sbin/custos-update 2>&1"
      self:ssh_run("mkdir -p /etc/crontabs")
      if not (self:ssh_run("grep -qF 'custos-update' /etc/crontabs/root 2>/dev/null || echo '" .. tostring(cron_entry) .. "' >> /etc/crontabs/root")) then
        warn("Impossible d'ajouter l'entrée cron — configurez manuellement")
      end
      self:ssh_run("/etc/init.d/cron enable 2>/dev/null || true")
      self:ssh_run("/etc/init.d/cron restart 2>/dev/null || true")
      ok("custos-update installé (/usr/sbin/custos-update) + cron lundi 4h")
      return true
    end,
    uninstall = function(self)
      step("Désinstallation de CustosVirginum")
      info("  Arrêt du service...")
      self:ssh_run("/etc/init.d/custos stop 2>/dev/null || true")
      self:ssh_run("/etc/init.d/custos disable 2>/dev/null || true")
      info("  Suppression des fichiers...")
      self:ssh_run("rm -rf " .. tostring(self.cfg.dest))
      self:ssh_run("rm -f /etc/init.d/custos")
      self:ssh_run("rm -f /usr/sbin/custos-update")
      self:ssh_run("sed -i '/custos-update/d' /etc/crontabs/root 2>/dev/null || true")
      self:ssh_run("/etc/init.d/cron restart 2>/dev/null || true")
      info("  Nettoyage de sysctl...")
      self:ssh_run("rm -f /etc/sysctl.d/10-custos.conf")
      self:ssh_run("sysctl -w net.bridge.bridge-nf-call-iptables=0 2>/dev/null || true")
      self:ssh_run("sysctl -w net.bridge.bridge-nf-call-ip6tables=0 2>/dev/null || true")
      info("  Nettoyage nftables...")
      self:ssh_run("nft delete table bridge dns-filter-bridge 2>/dev/null || true")
      info("  Suppression de la configuration UCI...")
      self:ssh_run("rm -f /etc/config/custos")
      self:ssh_run("rm -rf /var/run/custos")
      ok("Désinstallation terminée")
      return true
    end
  }
  setmetatable(obj, {
    __index = Installer
  })
  return obj
end
local print_usage
print_usage = function()
  io.write([[Usage: luajit install-owrt.lua <hôte> [options]

  <hôte> : hostname, adresse IPv4 ou adresse IPv6 littérale

Options:
  --port PORT    Port SSH                       (défaut : 22)
  --user USER    Utilisateur SSH                (défaut : root)
  --dest DIR     Dossier de destination         (défaut : /usr/share/custos)
  --no-build     Ne pas recompiler lua/
  --no-start     Installer sans démarrer le service
  --dry-run      Afficher les commandes sans exécuter
  --uninstall    Supprimer CustosVirginum du routeur
  -h, --help     Afficher cette aide

Exemple:
  luajit install-owrt.lua router.local
  luajit install-owrt.lua 192.168.1.1 --port 2222
  luajit install-owrt.lua 192.168.1.1 --uninstall
]])
  return os.exit(0)
end
local parse_args
parse_args = function()
  local cfg = {
    host = nil,
    port = 22,
    user = "root",
    dest = "/usr/share/custos",
    no_build = false,
    no_start = false,
    dry = false,
    uninstall = false,
    pkg_mgr = nil
  }
  local i = 1
  while i <= #arg do
    local a = arg[i]
    local _exp_0 = a
    if "-h" == _exp_0 or "--help" == _exp_0 then
      print_usage()
    elseif "--no-build" == _exp_0 then
      cfg.no_build = true
    elseif "--no-start" == _exp_0 then
      cfg.no_start = true
    elseif "--dry-run" == _exp_0 then
      cfg.dry = true
    elseif "--uninstall" == _exp_0 then
      cfg.uninstall = true
    elseif "--port" == _exp_0 then
      i = i + 1
      cfg.port = tonumber(arg[i]) or (fail("--port attend un entier") and os.exit(1))
    elseif "--user" == _exp_0 then
      i = i + 1
      cfg.user = arg[i]
    elseif "--dest" == _exp_0 then
      i = i + 1
      cfg.dest = arg[i]
    else
      if a:sub(1, 1) == "-" then
        fail("Option inconnue : " .. tostring(a))
        os.exit(1)
      else
        cfg.host = a
      end
    end
    i = i + 1
  end
  if cfg.host and cfg.host:match("%s") then
    fail("Hôte invalide (contient des espaces) : " .. tostring(cfg.host))
    os.exit(1)
  end
  return cfg
end
local main
main = function()
  local cfg = parse_args()
  if not (cfg.host) then
    fail("Adresse du routeur manquante (hostname, IPv4 ou IPv6).")
    print_usage()
    os.exit(1)
  end
  io.write(tostring(BOLD) .. "╔══════════════════════════════════════════╗\n")
  io.write("║   CustosVirginum — Setup OpenWrt           ║\n")
  io.write("╚══════════════════════════════════════════╝" .. tostring(NC) .. "\n")
  local inst = Installer(cfg)
  if cfg.uninstall then
    if inst:check_connectivity() then
      if inst:uninstall() then
        io.write("\n" .. tostring(GREEN) .. tostring(BOLD) .. "✓ Désinstallation terminée." .. tostring(NC) .. "\n")
      end
    else
      fail("\nÉchec : Impossible de joindre le routeur pour désinstaller.")
      os.exit(1)
    end
    return 
  end
  info("Cible  : " .. tostring(cfg.user) .. "@" .. tostring(cfg.host) .. ":" .. tostring(cfg.port))
  info("Dest   : " .. tostring(cfg.dest))
  if cfg.dry then
    warn("MODE DRY-RUN — aucune commande réelle exécutée\n")
  end
  local steps = {
    {
      name = "deps locales",
      fn = function()
        return inst:check_local_deps()
      end
    },
    {
      name = "compilation",
      fn = function()
        return inst:build_local()
      end
    },
    {
      name = "connectivité SSH",
      fn = function()
        return inst:check_connectivity()
      end
    },
    {
      name = "détection pkg mgr",
      fn = function()
        return inst:detect_pkg_manager()
      end
    },
    {
      name = "paquets",
      fn = function()
        return inst:install_pkg_deps()
      end
    },
    {
      name = "upload fichiers",
      fn = function()
        return inst:upload_files()
      end
    },
    {
      name = "service init.d",
      fn = function()
        return inst:install_initd()
      end
    },
    {
      name = "/etc/custos/",
      fn = function()
        return inst:install_etc_custos()
      end
    },
    {
      name = "config UCI",
      fn = function()
        return inst:install_uci_config()
      end
    },
    {
      name = "script update",
      fn = function()
        return inst:install_updater()
      end
    },
    {
      name = "démarrage service",
      fn = function()
        return inst:start_service()
      end
    },
    {
      name = "santé",
      fn = function()
        return inst:health_check()
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
  info("Statut   : ssh " .. tostring(cfg.user) .. "@" .. tostring(cfg.host) .. " '/etc/init.d/custos status'")
  info("Logs     : ssh " .. tostring(cfg.user) .. "@" .. tostring(cfg.host) .. " 'logread | grep custos'")
  return info("Restart   : ssh " .. tostring(cfg.user) .. "@" .. tostring(cfg.host) .. " '/etc/init.d/custos restart'")
end
return main()
