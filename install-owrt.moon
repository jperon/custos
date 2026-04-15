#!/usr/bin/env luajit
--- install-owrt.moon — Installe/Désinstalle CustosVirginum sur un routeur OpenWrt.
--
-- Usage : luajit install-owrt.lua <ip-routeur> [options]
--
-- Options :
--   --port PORT    Port SSH (défaut : 22)
--   --user USER    Utilisateur SSH (défaut : root)
--   --dest DIR     Dossier de destination sur le routeur (défaut : /usr/share/custos)
--   --no-build     Ne pas recompiler les sources MoonScript localement
--   --no-start     Copier et configurer sans démarrer le service
--   --dry-run      Afficher les commandes sans les exécuter
--   --uninstall    Supprimer CustosVirginum du routeur
--
-- Prérequis locaux : ssh, scp, tar, make (ou moonc+luajit)
-- Prérequis distants : opkg/apk (OpenWrt), accès SSH par clé

-- ── Couleurs ANSI ────────────────────────────────────────────────
RED    = "\27[0;31m"
GREEN  = "\27[0;32m"
YELLOW = "\27[1;33m"
CYAN   = "\27[0;36m"
BOLD   = "\27[1m"
NC     = "\27[0m"

ok   = (msg) -> io.write "#{GREEN}[+]#{NC} #{msg}\n"
warn = (msg) -> io.write "#{YELLOW}[!]#{NC} #{msg}\n"
fail = (msg) -> io.write "#{RED}[-]#{NC} #{msg}\n"
info = (msg) -> io.write "#{CYAN}[*]#{NC} #{msg}\n"
step = (msg) -> io.write "\n#{BOLD}━━ #{msg}#{NC}\n"

-- ── Installer Object ────────────────────────────────────────────────

Installer = (cfg) ->
  obj = {
    cfg: cfg

    -- Utilitaires locaux
    have_cmd: (cmd) =>
      fh = io.popen "command -v #{cmd} 2>/dev/null"
      return false unless fh
      out = fh\read "*l"
      fh\close!
      out ~= nil and out ~= ""

    run: (cmd) =>
      if @cfg.dry
        io.write "  #{CYAN}DRY#{NC} #{cmd}\n"
        return true
      code = os.execute cmd
      code == 0 or code == true

    capture: (cmd) =>
      fh = io.popen "#{cmd} 2>&1"
      return nil unless fh
      out = fh\read "*a"
      fh\close!
      out

    -- Retourne le host entre crochets si IPv6 littéral (contient ':'), sinon tel quel.
    ssh_host: =>
      if @cfg.host\find ":"
        "[#{@cfg.host}]"
      else
        @cfg.host

    -- Utilitaires SSH / SCP
    ssh_prefix: =>
      "ssh -p #{@cfg.port} -o StrictHostKeyChecking=no -o ConnectTimeout=10 #{@cfg.user}@#{@ssh_host!}"

    ssh_run: (cmd) =>
      escaped = cmd\gsub("'", "'\"'\"'")
      @run "#{ @ssh_prefix! } '#{escaped}'"

    ssh_capture: (cmd) =>
      escaped = cmd\gsub("'", "'\"'\"'")
      @capture "#{ @ssh_prefix! } '#{escaped}'"

    ssh_run_script: (name, content) =>
      tmplocal = "tmp/owrt-#{name}.sh"
      unless @cfg.dry
        os.execute "mkdir -p tmp"
        fh = io.open tmplocal, "w"
        unless fh
          fail "Impossible d'écrire #{tmplocal}"
          return false
        fh\write content
        fh\close!
      else
        io.write "  #{CYAN}DRY#{NC} write #{tmplocal}\n"

      ok_scp = @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no #{tmplocal} #{@cfg.user}@#{@ssh_host!}:/tmp/#{name}.sh"
      return false unless ok_scp
      @ssh_run "sh /tmp/#{name}.sh && rm -f /tmp/#{name}.sh"

    scp_send: (src, dst) =>
      @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no -r #{src} #{@cfg.user}@#{@ssh_host!}:#{dst}"

    -- ── Étapes d'installation ────────────────────────────────────────

    check_local_deps: =>
      step "Vérification des dépendances locales"
      ok_all = true
      for cmd in *{"ssh", "scp", "tar"}
        if @have_cmd cmd
          ok "#{cmd} disponible"
        else
          fail "#{cmd} introuvable dans le PATH"
          ok_all = false

      if not @cfg.no_build
        if @have_cmd "make"
          ok "make disponible"
        elseif @have_cmd "moonc" and @have_cmd "luajit"
          ok "moonc + luajit disponibles (make absent)"
        else
          warn "make / moonc introuvables — utiliser --no-build si lua/ est déjà compilé"
          ok_all = false
      ok_all

    build_local: =>
      step "Compilation MoonScript → Lua"
      if @cfg.no_build
        warn "--no-build : compilation ignorée (lua/ doit déjà être à jour)"
        return true

      if @have_cmd "make"
        if @run "make all"
          ok "Compilation réussie"
          return true
        else
          fail "Échec de 'make all'"
          return false
      else
        ok_all = true
        for _, src in ipairs {
            "config", "ffi_defs", "log",
            "parse/ethernet", "parse/ip", "parse/udp", "parse/dns",
            "ffi_ndpi", "ffi_ndpi_v4", "ffi_ndpi_v5",
            "parse/ndpi", "parse/ndpi_v4", "parse/ndpi_v5",
            "ipc", "allowlist", "nft", "nfq_loop",
            "worker_q0", "worker_q1", "main"
          }
          dst = "lua/#{src}.lua"
          if not @run "moonc -o #{dst} src/#{src}.moon"
            fail "Échec compilation src/#{src}.moon"
            ok_all = false
        ok_all

    check_connectivity: =>
      step "Vérification de la connectivité SSH (#{@cfg.user}@#{@cfg.host}:#{@cfg.port})"
      out = @ssh_capture "uname -a"
      if out and out\find "Linux"
        ok "Connecté : #{out\match '%S+%s+%S+%s+(%S+)'}"
        return true
      fail "Impossible de joindre le routeur — vérifier ip/port/clé SSH"
      false

    detect_pkg_manager: =>
      step "Détection du gestionnaire de paquets"
      out_apk  = @ssh_capture "command -v apk  2>/dev/null"
      out_opkg = @ssh_capture "command -v opkg 2>/dev/null"

      if out_apk and out_apk\match "/apk"
        @cfg.pkg_mgr = "apk"
        ok "Gestionnaire détecté : apk (OpenWrt ≥ 24.10)"
      elseif out_opkg and out_opkg\match "/opkg"
        @cfg.pkg_mgr = "opkg"
        ok "Gestionnaire détecté : opkg (OpenWrt ≤ 23.05)"
      else
        fail "Ni apk ni opkg trouvés sur le routeur"
        return false
      true

    install_pkg_deps: =>
      pm = @cfg.pkg_mgr
      step "Installation des paquets (#{pm})"
      info "Mise à jour des listes #{pm}..."
      update_cmd = pm == "apk" and "apk update" or "opkg update"
      unless @ssh_run update_cmd
        warn "#{update_cmd} a échoué — les listes peuvent être périmées, on continue"

      pkgs_required = {
        "luajit", "libnetfilter-queue", "nftables",
        "kmod-br-netfilter", "kmod-nft-queue",
        "lyaml", "luasec", "libxxhash", "openssl-util"
      }
      pkgs_optional = { "libndpi" }

      install_cmd = if pm == "apk"
        (pkg) -> "apk add #{pkg}"
      else
        (pkg) -> "opkg install #{pkg}"

      check_cmd = if pm == "apk"
        (pkg) -> "apk info -e #{pkg} 2>/dev/null && echo installed"
      else
        (pkg) -> "opkg list-installed #{pkg} 2>/dev/null"

      ok_all = true
      for pkg in *pkgs_required
        info "  #{install_cmd pkg}"
        unless @ssh_run install_cmd pkg
          installed = @ssh_capture check_cmd pkg
          if installed and installed\find pkg
            ok "  #{pkg} déjà installé"
          else
            fail "  Impossible d'installer #{pkg}"
            ok_all = false

      for pkg in *pkgs_optional
        info "  #{install_cmd pkg} (optionnel)"
        if @ssh_run install_cmd pkg
          ok "  #{pkg} installé"
        else
          warn "  #{pkg} introuvable dans #{pm} — ajoutez le feed packages OpenWrt"
          warn "  Sans libndpi, le filtre ne démarrera pas (dépendance ffi.load)"
      ok_all

    upload_files: =>
      step "Copie des fichiers vers #{@cfg.dest}"
      info "  Compression de lua/..."
      archive = "tmp/custos-lua.tar.gz"
      unless @run "tar -czf #{archive} -C lua ."
        fail "Échec de la compression de lua/"
        return false

      unless @ssh_run "mkdir -p #{@cfg.dest}/parse"
        fail "Impossible de créer #{@cfg.dest}/parse"
        return false

      info "  Envoi de l'archive → /tmp/"
      unless @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no #{archive} #{@cfg.user}@#{@ssh_host!}:/tmp/custos-lua.tar.gz"
        fail "Échec du transfert de l'archive"
        return false

      info "  Extraction sur le routeur → #{@cfg.dest}/"
      unless @ssh_run "tar -xzf /tmp/custos-lua.tar.gz -C #{@cfg.dest} && rm -f /tmp/custos-lua.tar.gz"
        fail "Échec de l'extraction sur le routeur"
        return false

      info "  Envoi de nft-rules/dns-filter.nft → #{@cfg.dest}/"
      unless @scp_send "nft-rules/dns-filter.nft", @cfg.dest
        fail "Échec du transfert de dns-filter.nft"
        return false

      ok "Fichiers copiés"
      true

    apply_nft_rules: =>
      step "Application des règles nftables"
      script = [[
#!/bin/sh
set -e
NFT=]] .. @cfg.dest .. [[/dns-filter.nft
nft -f "$NFT" && echo "nft ok"
]]
      if @ssh_run_script "apply-nft", script
        ok "Règles nft appliquées"
        return true
      fail "Échec de l'application des règles nft"
      false

    enable_br_netfilter: =>
      step "Activation de br_netfilter"
      script = [[
#!/bin/sh
modprobe br_netfilter 2>/dev/null || true
sysctl -qw net.bridge.bridge-nf-call-iptables=1  2>/dev/null || true
sysctl -qw net.bridge.bridge-nf-call-ip6tables=1 2>/dev/null || true

mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/10-custos.conf << 'SYSCTL_EOF'
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
SYSCTL_EOF
echo "br_netfilter ok"
]]
      if @ssh_run_script "br-netfilter", script
        ok "br_netfilter activé et persisté"
        return true
      warn "br_netfilter : vérifiez que kmod-br-netfilter est chargé"
      false

    install_initd: =>
      step "Installation du service init.d/custos (procd)"
      service = [[
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=95
STOP=05
PROG=$(command -v luajit 2>/dev/null || command -v luajit2 2>/dev/null)
CUSTOS_DIR=]] .. @cfg.dest .. "\n" .. [[
start_service() {
    [ "$(uci get custos.main.enabled 2>/dev/null)" = "0" ] && return 0
    [ -z "$PROG" ] && { echo "custos: luajit introuvable"; return 1; }

    modprobe br_netfilter 2>/dev/null || true
    sysctl -qw net.bridge.bridge-nf-call-iptables=1  2>/dev/null || true
    sysctl -qw net.bridge.bridge-nf-call-ip6tables=1 2>/dev/null || true

    $PROG $CUSTOS_DIR/uci_config.lua || \
        echo "custos: avertissement — génération config UCI échouée, utilise les défauts compilés"

    # Charge les règles nftables
    _nft_load || echo "custos: avertissement — règles nft non chargées, démarrage en mode dégradé"

    procd_open_instance
    procd_set_param command $PROG $CUSTOS_DIR/main.lua
    procd_set_param env LUA_PATH="/usr/lib/lua/?.lua;/usr/lib/lua/?/init.lua;/var/run/custos/?.lua;$CUSTOS_DIR/?.lua;$CUSTOS_DIR/?/init.lua;;" LUA_CPATH="/usr/lib/lua/?.so;;" CUSTOS_FILTER_CONFIG="/etc/custos/filter.yml"
    procd_set_param respawn ${respawn_threshold:-3600} ${respawn_timeout:-5} ${respawn_retry:-5}
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

stop_service() {
    nft delete table ip  dns-filter 2>/dev/null || true
    nft delete table ip6 dns-filter 2>/dev/null || true
}

_nft_load() {
    NFT_SRC="$CUSTOS_DIR/dns-filter.nft"
    [ -f "$NFT_SRC" ] || { echo "custos: $NFT_SRC introuvable"; return 1; }
    nft -f "$NFT_SRC"
}

reload_service() {
    stop
    start
}

service_triggers() {
    procd_add_reload_trigger "custos"
}
]]
      tmplocal = "tmp/owrt-custos-initd"
      unless @cfg.dry
        fh = io.open tmplocal, "w"
        if fh
          fh\write service
          fh\close!

      ok_scp = @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no #{tmplocal} #{@cfg.user}@#{@ssh_host!}:/etc/init.d/custos"
      unless ok_scp
        fail "Échec de la copie du script init.d"
        return false

      unless @ssh_run "chmod +x /etc/init.d/custos && /etc/init.d/custos enable"
        fail "Échec activation du service"
        return false
      ok "Service installé et activé au démarrage"
      true

    -- Installe /etc/custos/filter.yml et /etc/custos/secrets (preserve si existants).
    install_etc_custos: =>
      step "Configuration /etc/custos/"
      @ssh_run "mkdir -p /etc/custos"

      for entry in *{ { src: "cfg/filter.yml", dst: "/etc/custos/filter.yml" },
                      { src: "cfg/secrets",    dst: "/etc/custos/secrets"    } }
        exists = @ssh_capture "[ -f #{entry.dst} ] && echo yes || echo no"
        if exists and exists\find "yes"
          warn "#{entry.dst} existe deja -- fichier preserve"
          continue
        unless @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no #{entry.src} #{@cfg.user}@#{@ssh_host!}:#{entry.dst}"
          fail "Echec de la copie de #{entry.dst}"
          return false
        @ssh_run "chmod 600 #{entry.dst}"
        ok "#{entry.dst} installe"
      true

    -- Installe /etc/config/custos si absent (préserve la config existante).
    install_uci_config: =>
      step "Configuration UCI (/etc/config/custos)"
      exists = @ssh_capture "[ -f /etc/config/custos ] && echo yes || echo no"
      if exists and exists\find "yes"
        warn "/etc/config/custos existe déjà — configuration préservée"
        return true

      uci_cfg = [[
config custos 'main'
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
      tmplocal = "tmp/owrt-custos-uci"
      unless @cfg.dry
        fh = io.open tmplocal, "w"
        if fh
          fh\write uci_cfg
          fh\close!

      unless @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no #{tmplocal} #{@cfg.user}@#{@ssh_host!}:/etc/config/custos"
        fail "Échec de la copie de /etc/config/custos"
        return false

      ok "/etc/config/custos installé"
      true

    start_service: =>
      step "Démarrage du service custos"
      if @cfg.no_start
        warn "--no-start : démarrage ignoré"
        return true

      unless @ssh_run "/etc/init.d/custos start"
        fail "Échec du démarrage"
        return false

      os.execute "sleep 2"
      status = @ssh_capture "pgrep -f main.lua && echo running || echo stopped"
      if status and status\find "running"
        ok "Service démarré (luajit main.lua actif)"
      else
        warn "Service démarré mais le processus n'est pas encore visible"
      true

    health_check: =>
      step "Vérification de la santé (logread)"
      out = @ssh_capture "logread | grep custos | tail -n 20"
      if out and out\find "error"
        warn "Des erreurs ont été détectées dans les logs :"
        info out
      elseif out
        ok "Le service semble fonctionner correctement"
      else
        warn "Aucun log trouvé pour 'custos' — vérifiez le démarrage"
      true

    -- Installe custos-update et configure le cron.
    install_updater: =>
      step "Script de mise à jour des listes (custos-update)"

      script = [[
#!/bin/sh
CUSTOS_DIR=]] .. @cfg.dest .. [[

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
      tmplocal = "tmp/owrt-custos-update"
      unless @cfg.dry
        fh = io.open tmplocal, "w"
        if fh
          fh\write script
          fh\close!

      unless @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no #{tmplocal} #{@cfg.user}@#{@ssh_host!}:/usr/sbin/custos-update"
        fail "Échec de la copie de custos-update"
        return false
      unless @ssh_run "chmod +x /usr/sbin/custos-update"
        fail "Échec du chmod +x custos-update"
        return false

      -- Cron quotidien (à 4h)
      cron_entry = "0 4 * * * /usr/sbin/custos-update 2>&1"
      @ssh_run "mkdir -p /etc/crontabs"
      -- Ajouter l'entrée si elle n'existe pas déjà
      unless @ssh_run "grep -qF 'custos-update' /etc/crontabs/root 2>/dev/null || echo '#{cron_entry}' >> /etc/crontabs/root"
        warn "Impossible d'ajouter l'entrée cron — configurez manuellement"
      @ssh_run "/etc/init.d/cron enable 2>/dev/null || true"
      @ssh_run "/etc/init.d/cron restart 2>/dev/null || true"

      ok "custos-update installé (/usr/sbin/custos-update) + cron lundi 4h"
      true

    uninstall: =>
      step "Désinstallation de CustosVirginum"
      
      -- 1. Arrêt et désactivation du service
      info "  Arrêt du service..."
      @ssh_run "/etc/init.d/custos stop 2>/dev/null || true"
      @ssh_run "/etc/init.d/custos disable 2>/dev/null || true"
      
      -- 2. Suppression des fichiers
      info "  Suppression des fichiers..."
      @ssh_run "rm -rf #{@cfg.dest}"
      @ssh_run "rm -f /etc/init.d/custos"
      @ssh_run "rm -f /usr/sbin/custos-update"
      -- Supprimer l'entrée cron
      @ssh_run "sed -i '/custos-update/d' /etc/crontabs/root 2>/dev/null || true"
      @ssh_run "/etc/init.d/cron restart 2>/dev/null || true"
      
      -- 3. Nettoyage sysctl
      info "  Nettoyage de sysctl..."
      @ssh_run "rm -f /etc/sysctl.d/10-custos.conf"
      @ssh_run "sysctl -w net.bridge.bridge-nf-call-iptables=0 2>/dev/null || true"
      @ssh_run "sysctl -w net.bridge.bridge-nf-call-ip6tables=0 2>/dev/null || true"
      
      -- 4. Nettoyage nftables (on tente de supprimer les tables si elles existent)
      info "  Nettoyage nftables..."
      @ssh_run "nft delete table ip  dns-filter 2>/dev/null || true"
      @ssh_run "nft delete table ip6 dns-filter 2>/dev/null || true"

      -- 5. Suppression de la configuration UCI et des fichiers runtime
      info "  Suppression de la configuration UCI..."
      @ssh_run "rm -f /etc/config/custos"
      @ssh_run "rm -rf /var/run/custos"
      
      ok "Désinstallation terminée"
      true
  }
  setmetatable obj, { __index: Installer }
  obj

-- ── Parsing des arguments ────────────────────────────────────────

--- Affiche l'aide et quitte.
print_usage = ->
  io.write [[
Usage: luajit install-owrt.lua <hôte> [options]

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
]]
  os.exit 0

--- Parse les arguments de la ligne de commande.
-- @treturn table|nil cfg ou nil en cas d'erreur
parse_args = ->
  cfg = {
    host:     nil
    port:     22
    user:     "root"
    dest:     "/usr/share/custos"
    no_build: false
    no_start: false
    dry:      false
    uninstall: false
    pkg_mgr:  nil
  }

  i = 1
  while i <= #arg
    a = arg[i]
    switch a
      when "-h", "--help"
        print_usage!
      when "--no-build"
        cfg.no_build = true
      when "--no-start"
        cfg.no_start = true
      when "--dry-run"
        cfg.dry = true
      when "--uninstall"
        cfg.uninstall = true
      when "--port"
        i += 1
        cfg.port = tonumber(arg[i]) or (fail("--port attend un entier") and os.exit(1))
      when "--user"
        i += 1
        cfg.user = arg[i]
      when "--dest"
        i += 1
        cfg.dest = arg[i]
      else
        if a\sub(1, 1) == "-"
          fail "Option inconnue : #{a}"
          os.exit 1
        else
          cfg.host = a
    i += 1

  if cfg.host and cfg.host\match "%s"
    fail "Hôte invalide (contient des espaces) : #{cfg.host}"
    os.exit 1
  cfg

-- ── Point d'entrée ───────────────────────────────────────────────

main = ->
  cfg = parse_args!
  unless cfg.host
    fail "Adresse du routeur manquante (hostname, IPv4 ou IPv6)."
    print_usage!
    os.exit 1

  io.write "#{BOLD}╔══════════════════════════════════════════╗\n"
  io.write "║   CustosVirginum — Setup OpenWrt           ║\n"
  io.write "╚══════════════════════════════════════════╝#{NC}\n"
  
  inst = Installer cfg
  
  if cfg.uninstall
    if inst\check_connectivity!
      if inst\uninstall!
        io.write "\n#{GREEN}#{BOLD}✓ Désinstallation terminée.#{NC}\n"
    else
      fail "\nÉchec : Impossible de joindre le routeur pour désinstaller."
      os.exit 1
    return

  info "Cible  : #{cfg.user}@#{cfg.host}:#{cfg.port}"
  info "Dest   : #{cfg.dest}"
  if cfg.dry
    warn "MODE DRY-RUN — aucune commande réelle exécutée\n"

  steps = {
    { name: "deps locales",      fn: -> inst\check_local_deps!    }
    { name: "compilation",       fn: -> inst\build_local!         }
    { name: "connectivité SSH",  fn: -> inst\check_connectivity!  }
    { name: "détection pkg mgr", fn: -> inst\detect_pkg_manager!  }
    { name: "paquets",           fn: -> inst\install_pkg_deps!    }
    { name: "upload fichiers",   fn: -> inst\upload_files!        }
    { name: "br_netfilter",      fn: -> inst\enable_br_netfilter! }
    { name: "règles nft",        fn: -> inst\apply_nft_rules!     }
    { name: "service init.d",    fn: -> inst\install_initd!       }
    { name: "/etc/custos/",      fn: -> inst\install_etc_custos!  }
    { name: "config UCI",        fn: -> inst\install_uci_config!  }
    { name: "script update",     fn: -> inst\install_updater!     }
    { name: "démarrage service", fn: -> inst\start_service!       }
    { name: "santé",             fn: -> inst\health_check!        }
  }

  for s in *steps
    unless s.fn!
      fail "\nInstallation interrompue à l'étape « #{s.name} »."
      os.exit 1

  io.write "\n#{GREEN}#{BOLD}✓ Installation terminée.#{NC}\n"
  info "Statut   : ssh #{cfg.user}@#{cfg.host} '/etc/init.d/custos status'"
  info "Logs     : ssh #{cfg.user}@#{cfg.host} 'logread | grep custos'"
  info "Reload   : ssh #{cfg.user}@#{cfg.host} '/etc/init.d/custos reload'"

main!
