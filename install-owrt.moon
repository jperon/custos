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
      "ssh -p #{@cfg.port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 #{@cfg.user}@#{@ssh_host!}"

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

      ok_scp = @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null #{tmplocal} #{@cfg.user}@#{@ssh_host!}:/tmp/#{name}.sh"
      return false unless ok_scp
      @ssh_run "sh /tmp/#{name}.sh && rm -f /tmp/#{name}.sh"

    scp_send: (src, dst) =>
      @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r #{src} #{@cfg.user}@#{@ssh_host!}:#{dst}"

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
            "nfq/packet", "nfq/packet_v4", "nfq/packet_v5",
            "ipc", "allowlist", "nft", "nfq_loop",
            "worker_questions", "worker_responses", "worker_auth_queue", "main"
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
        "kmod-nft-queue", "kmod-nft-bridge",
        "lpeg", "libxxhash",
        "libwolfssl", "px5g",
        -- custos-update : téléchargement + décompression des releases custos-lists
        "curl", "zstd"
      }

      pkg_list = table.concat pkgs_required, " "
      install_cmd = if pm == "apk"
        "apk add #{pkg_list}"
      else
        "opkg install #{pkg_list}"

      info "  #{install_cmd}"
      if @ssh_run install_cmd
        ok "Tous les paquets installés"
        return true
      else
        fail "Impossible d'installer les paquets"
        return false

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
      unless @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null #{archive} #{@cfg.user}@#{@ssh_host!}:/tmp/custos-lua.tar.gz"
        fail "Échec du transfert de l'archive"
        return false

      info "  Extraction sur le routeur → #{@cfg.dest}/"
      unless @ssh_run "tar -xzf /tmp/custos-lua.tar.gz -C #{@cfg.dest} && rm -f /tmp/custos-lua.tar.gz"
        fail "Échec de l'extraction sur le routeur"
        return false

      nft_file = "nft-rules/dns-filter-bridge.nft"
      info "  Envoi de #{nft_file} → #{@cfg.dest}/"
      unless @scp_send nft_file, @cfg.dest
        fail "Échec du transfert de #{nft_file}"
        return false

      ok "Fichiers copiés"
      true

    -- Supprime les fichiers .lua présents dans @cfg.dest mais absents de l'archive
    -- locale lua/. Évite l'accumulation de modules obsolètes entre versions.
    cleanup_stale_files: =>
      step "Nettoyage des fichiers obsolètes dans #{@cfg.dest}"
      archive = "tmp/custos-lua.tar.gz"

      -- Construire le manifest depuis l'archive (chemins relatifs, sans ./)
      fh = io.popen "tar -tzf '#{archive}'"
      unless fh
        warn "Impossible de lire l'archive — nettoyage ignoré"
        return true
      entries = {}
      for line in fh\lines!
        path = line\gsub "^%./", ""
        entries[#entries + 1] = path if path\match("%.lua$") and path != ""
      fh\close!
      table.sort entries

      unless #entries > 0
        warn "Manifest vide — nettoyage ignoré"
        return true

      info "  #{#entries} fichiers .lua dans la version courante"

      -- Écrire le manifest localement et l'envoyer sur le routeur
      manifest_path = "tmp/custos-manifest.txt"
      fh = io.open manifest_path, "w"
      unless fh
        warn "Impossible d'écrire le manifest — nettoyage ignoré"
        return true
      fh\write table.concat(entries, "\n") .. "\n"
      fh\close!

      if @cfg.dry
        io.write "  #{CYAN}DRY#{NC} scp manifest → routeur puis suppression des .lua absents du manifest\n"
        return true

      unless @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null #{manifest_path} #{@cfg.user}@#{@ssh_host!}:/tmp/custos-manifest.txt"
        warn "Impossible d'envoyer le manifest — nettoyage ignoré"
        return true

      -- Identifier les fichiers obsolètes (présents sur le routeur, absents du manifest)
      dest = @cfg.dest
      out = @ssh_capture "find '#{dest}' -name '*.lua' | sed 's|^#{dest}/||' | while read f; do grep -qxF \"$f\" /tmp/custos-manifest.txt || echo \"$f\"; done; rm -f /tmp/custos-manifest.txt"

      stale = {}
      if out
        for line in out\gmatch "[^\n]+"
          -- Ignorer les messages d'erreur grep (manifest absent, etc.)
          stale[#stale + 1] = line if #line > 0 and not line\match "^grep:"

      if #stale == 0
        ok "Aucun fichier obsolète"
        return true

      for f in *stale
        info "  supprimé : #{f}"
        @ssh_run "rm -f '#{dest}/#{f}'"

      ok "#{#stale} fichier(s) obsolète(s) supprimé(s)"
      true

    install_initd: =>
      step "Installation du service init.d/custos (procd)"
      init_src = "packaging/openwrt/custos/files/etc/init.d/custos"
      tmplocal = "tmp/owrt-custos-initd"

      unless @cfg.dry
        fh = io.open init_src, "r"
        unless fh
          fail "Impossible de lire #{init_src}"
          return false
        content = fh\read "*a"
        fh\close!

        content = content\gsub "/usr/share/custos", @cfg.dest

        os.execute "mkdir -p tmp"
        fh = io.open tmplocal, "w"
        unless fh
          fail "Impossible d'écrire #{tmplocal}"
          return false
        fh\write content
        fh\close!
      else
        io.write "  #{CYAN}DRY#{NC} adapt #{init_src} → #{tmplocal}\n"

      unless @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null #{tmplocal} #{@cfg.user}@#{@ssh_host!}:/etc/init.d/custos"
        fail "Échec de la copie du script init.d"
        return false

      unless @ssh_run "chmod +x /etc/init.d/custos && /etc/init.d/custos enable"
        fail "Échec activation du service"
        return false
      ok "Service installé et activé au démarrage"
      true

    -- Installe /etc/custos/config.moon et /etc/custos/secrets (preserve si existants).
    install_etc_custos: =>
      step "Configuration /etc/custos/"
      @ssh_run "mkdir -p /etc/custos"

      for entry in *{ { src: "cfg/config.moon", dst: "/etc/custos/config.moon" },
                      { src: "cfg/secrets",    dst: "/etc/custos/secrets"    } }
        exists = @ssh_capture "[ -f #{entry.dst} ] && echo yes || echo no"
        if exists and exists\find "yes"
          warn "#{entry.dst} existe deja -- fichier preserve"
          continue
        unless @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null #{entry.src} #{@cfg.user}@#{@ssh_host!}:#{entry.dst}"
          fail "Echec de la copie de #{entry.dst}"
          return false
        @ssh_run "chmod 600 #{entry.dst}"
        ok "#{entry.dst} installe"
      true

    start_service: =>
      step "Démarrage du service custos"
      if @cfg.no_start
        warn "--no-start : démarrage ignoré"
        return true

      unless @ssh_run "/etc/init.d/custos stop ; sleep 2 ; /etc/init.d/custos start"
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

      -- Le script canonique (téléchargement des releases custos-lists) est versionné
      -- dans le paquet OpenWrt ; on le copie tel quel, sans substitution.
      src = "packaging/openwrt/custos/files/usr/sbin/custos-update"
      unless @run "scp -O -P #{@cfg.port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null #{src} #{@cfg.user}@#{@ssh_host!}:/usr/sbin/custos-update"
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

      -- 3. Nettoyage nftables (on tente de supprimer les tables si elles existent)
      info "  Nettoyage nftables..."
      @ssh_run "nft delete table bridge dns-filter-bridge 2>/dev/null || true"

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
    host:       nil
    port:       22
    user:       "root"
    dest:       "/usr/share/custos"
    no_build:   false
    no_start:   false
    dry:        false
    uninstall:  false
    pkg_mgr:    nil
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
    { name: "nettoyage obsolètes", fn: -> inst\cleanup_stale_files! }
    { name: "service init.d",    fn: -> inst\install_initd!       }
    { name: "/etc/custos/",      fn: -> inst\install_etc_custos!  }
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
  info "Restart   : ssh #{cfg.user}@#{cfg.host} '/etc/init.d/custos restart'"

main!
