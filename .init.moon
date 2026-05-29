-- SPDX-License-Identifier: MIT
--- Redbean web UI pour l'installation de CustosVirginum sur routeurs OpenWrt.
-- Lancer : ./redbean.com depuis la racine du projet, puis ouvrir http://localhost:8080/
-- Empaqueter : make redbean-ui (requiert que redbean.com soit présent à la racine).
-- @script .init

H = require "html"

-- ── Utilitaires ──────────────────────────────────────────────────────────────

html_esc = (s) ->
  (s or "")\gsub("&", "&amp;")\gsub("<", "&lt;")\gsub(">", "&gt;")

-- Les fonctions safe_* suppriment les caractères hors de leur liste blanche pour
-- prévenir l'injection shell : les valeurs filtrées sont interpolées dans des
-- commandes exécutées via io.popen.
safe_host = (s) -> (s or "")\gsub "[^%w%.%-_:%[%]]", ""
safe_port = (s) -> tostring (tonumber(s) or 22)
safe_path = (s) -> (s or "")\gsub "[^%w%.%-_/]", ""
safe_url  = (s) -> (s or "")\gsub "[^%w%.%-_:/@%%?=&#%+]", ""
safe_user = (s) -> (s or "")\gsub "[^%w%.%-_]", ""

run_cmd = (cmd) ->
  fh = io.popen "#{cmd} 2>&1", "r"
  return cmd, "Impossible d'exécuter la commande." unless fh
  out = fh\read "*a"
  fh\close!
  cmd, out

-- ── CSS ──────────────────────────────────────────────────────────────────────

css = [[
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  line-height: 1.5; color: #333; background: #f5f5f5;
  display: flex; min-height: 100vh;
}
nav {
  width: 185px; background: #1a1a2e; color: #eee;
  padding: 1.5rem 1rem; flex-shrink: 0;
}
nav h2 { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;
          color: #888; margin-bottom: 0.75rem; }
nav a { display: block; color: #ccd6f6; text-decoration: none;
         padding: 0.35rem 0.5rem; border-radius: 4px; font-size: 0.9rem;
         margin-bottom: 0.1rem; }
nav a:hover { background: #2d2d5f; }
main { flex: 1; padding: 2rem; max-width: 800px; }
h1 { margin-bottom: 1.5rem; font-size: 1.4rem; }
form { background: white; padding: 2rem; border-radius: 8px;
       box-shadow: 0 2px 4px rgba(0,0,0,.1); }
.ff { margin-bottom: 1rem; }
label { display: block; margin-bottom: 0.3rem; font-weight: 500; font-size: 0.9rem; }
input[type="text"], input[type="number"], input[type="url"] {
  width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #ddd;
  border-radius: 4px; font-size: 1rem;
}
.note { font-size: 0.8rem; color: #777; margin-top: 0.2rem; }
.cbrow { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
.cbrow input { width: auto; }
.cbrow label { font-weight: normal; margin: 0; }
.rrow { display: flex; gap: 1.5rem; margin-bottom: 1rem; }
.rrow label { font-weight: normal; display: flex; align-items: center;
               gap: 0.4rem; margin: 0; }
button[type="submit"] {
  background: #007bff; color: white; border: none;
  padding: 0.7rem 1.5rem; border-radius: 4px; font-size: 1rem; cursor: pointer;
  margin-top: 0.5rem;
}
button[type="submit"]:hover { background: #0056b3; }
pre.out {
  background: #1e1e1e; color: #d4d4d4; padding: 1.5rem; border-radius: 6px;
  overflow-x: auto; white-space: pre-wrap; font-size: 0.82rem;
  font-family: 'SFMono-Regular', Consolas, monospace;
  margin: 1rem 0; max-height: 60vh; overflow-y: auto;
}
.cmd { font-family: monospace; font-size: 0.85rem; background: #eee;
        padding: 0.5rem 0.75rem; border-radius: 4px; margin-bottom: 1rem;
        word-break: break-all; }
.back { margin-top: 1rem; }
.back a { color: #007bff; text-decoration: none; }
.back a:hover { text-decoration: underline; }
.intro { background: white; padding: 1.5rem 2rem; border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,.1); margin-bottom: 1rem; }
.intro ul { margin: 0.5rem 0 0 1.5rem; }
.intro li { margin-bottom: 0.3rem; }
#spinner {
  display: none; position: fixed; inset: 0; background: rgba(0,0,0,.5);
  align-items: center; justify-content: center; z-index: 999; color: white;
  font-size: 1.2rem; flex-direction: column; gap: 1rem;
}
]]

-- ── Page wrapper ─────────────────────────────────────────────────────────────

page = (title, content) ->
  "<!DOCTYPE html>\n" .. H.html { lang: "fr",
    H.head {
      H.meta { charset: "UTF-8" }
      H.meta { name: "viewport", content: "width=device-width, initial-scale=1" }
      H.title "CustosVirginum — #{title}"
      H.style css
    }
    H.body {
      H.nav {
        H.h2 "Custos"
        H.a { href: "/", "Accueil" }
        H.a { href: "/install", "Installer" }
        H.a { href: "/sync", "Sync config" }
        H.a { href: "/uninstall", "Désinstaller" }
      }
      H.div { id: "spinner", "⏳ En cours, veuillez patienter…" }
      H.main content
      H.script "function showSpinner(){document.getElementById('spinner').style.display='flex';}"
    }
  }

html_resp = (title, content) ->
  SetHeader "Content-Type", "text/html; charset=UTF-8"
  Write page title, content

-- ── Helpers de formulaire ────────────────────────────────────────────────────

ff = (lbl, name, t, dflt, note) ->
  note_el  = if note then H.p({ class: "note" }, note) else ""
  label_el = H.label lbl
  input_el = H.input { type: t, name: name, value: (dflt or ""), placeholder: (dflt or "") }
  H.div { class: "ff", label_el, input_el, note_el }

cb = (lbl, name) ->
  inp_el = H.input { type: "checkbox", name: name, value: "1", id: name }
  lbl_el = H.label { ["for"]: name, lbl }
  H.div { class: "cbrow", inp_el, lbl_el }

-- ── Pages GET ────────────────────────────────────────────────────────────────

home_page = ->
  H.div {
    H.h1 "CustosVirginum — Installateur"
    H.div { class: "intro",
      H.p "Interface locale pour déployer CustosVirginum sur un routeur OpenWrt via SSH."
      H.ul {
        H.li H.a { href: "/install", "Installer Custos sur un routeur" }
        H.li H.a { href: "/sync", "Configurer la synchronisation de configuration" }
        H.li H.a { href: "/uninstall", "Désinstaller Custos d'un routeur" }
      }
      H.p { style: "margin-top:1rem;color:#666;font-size:.9rem;",
            "Prérequis locaux : ssh, scp, tar, make (ou moonc+luajit), accès SSH par clé au routeur." }
    }
  }

install_page = ->
  H.div {
    H.h1 "Installer CustosVirginum"
    H.form { method: "POST", action: "/install", onsubmit: "showSpinner()",
      ff "Hôte (IP ou hostname du routeur) *", "host", "text", "", "Ex. : 192.168.1.1 ou router.local"
      ff "Port SSH", "port", "number", "22", nil
      ff "Utilisateur SSH", "user", "text", "root", nil
      ff "Dossier de destination sur le routeur", "dest", "text", "/usr/share/custos", nil
      cb "--no-build (lua/ déjà compilé, ignorer make all)", "no_build"
      cb "--no-start (installer sans démarrer le service)", "no_start"
      cb "--dry-run (simuler sans exécuter)", "dry_run"
      H.button { type: "submit", "Lancer l'installation" }
    }
  }

uninstall_page = ->
  H.div {
    H.h1 "Désinstaller CustosVirginum"
    H.form { method: "POST", action: "/uninstall", onsubmit: "showSpinner()",
      ff "Hôte (IP ou hostname du routeur) *", "host", "text", "", "Ex. : 192.168.1.1"
      ff "Port SSH", "port", "number", "22", nil
      ff "Utilisateur SSH", "user", "text", "root", nil
      H.button { type: "submit", "Lancer la désinstallation" }
    }
  }

sync_page = ->
  pull_lbl = H.label { class: "rrow-item",
    H.input { type: "radio", name: "mode", value: "pull", checked: "checked" }
    " Pull-only (device secondaire)"
  }
  push_lbl = H.label { class: "rrow-item",
    H.input { type: "radio", name: "mode", value: "push" }
    " Push + Pull (filtre de référence)"
  }
  mode_ff = H.div { class: "ff",
    H.label "Type de synchronisation"
    H.div { class: "rrow", pull_lbl, push_lbl }
  }
  H.div {
    H.h1 "Synchronisation de configuration"
    H.form { method: "POST", action: "/sync", onsubmit: "showSpinner()",
      ff "Hôte (IP ou hostname du routeur) *", "host", "text", "", "Ex. : 192.168.1.1"
      ff "URL du dépôt Git de configurations *", "repo", "url", "", "Ex. : https://git.example.com/custos-configs"
      mode_ff
      H.button { type: "submit", "Configurer la synchronisation" }
    }
  }

result_page = (title, cmd, output, back) ->
  H.div {
    H.h1 title
    H.p "Commande exécutée :"
    H.p { class: "cmd", cmd }
    H.pre { class: "out", html_esc output }
    H.div { class: "back",
      H.a { href: back, "← Retour" }
    }
  }

-- ── Handlers POST ─────────────────────────────────────────────────────────────

handle_install = ->
  host = safe_host GetParam "host"
  port = safe_port GetParam "port"
  user = safe_user GetParam "user"
  dest = safe_path GetParam "dest"
  user = "root"            if user == ""
  dest = "/usr/share/custos" if dest == ""

  unless host ~= ""
    SetStatus 400
    html_resp "Erreur", H.div {
      H.p "L'hôte est requis."
      H.p H.a { href: "/install", "← Retour" }
    }
    return

  flags = ""
  flags ..= " --no-build" if GetParam "no_build"
  flags ..= " --no-start" if GetParam "no_start"
  flags ..= " --dry-run"  if GetParam "dry_run"

  cmd, out = run_cmd "luajit install-owrt.lua #{host} --port #{port} --user #{user} --dest #{dest}#{flags}"
  html_resp "Résultat de l'installation", result_page "Installation — #{host}", cmd, out, "/install"

handle_uninstall = ->
  host = safe_host GetParam "host"
  port = safe_port GetParam "port"
  user = safe_user GetParam "user"
  user = "root" if user == ""

  unless host ~= ""
    SetStatus 400
    html_resp "Erreur", H.div {
      H.p "L'hôte est requis."
      H.p H.a { href: "/uninstall", "← Retour" }
    }
    return

  cmd, out = run_cmd "luajit install-owrt.lua #{host} --port #{port} --user #{user} --uninstall"
  html_resp "Résultat de la désinstallation", result_page "Désinstallation — #{host}", cmd, out, "/uninstall"

handle_sync = ->
  host = safe_host GetParam "host"
  repo = safe_url  GetParam "repo"
  mode = GetParam "mode"

  unless host ~= "" and repo ~= ""
    SetStatus 400
    html_resp "Erreur", H.div {
      H.p "L'hôte et l'URL du dépôt sont requis."
      H.p H.a { href: "/sync", "← Retour" }
    }
    return

  target = if mode == "push" then "sync-push-init" else "sync-init"
  cmd, out = run_cmd "make #{target} HOST=#{host} REPO=#{repo}"
  html_resp "Résultat de la synchronisation", result_page "Synchronisation — #{host}", cmd, out, "/sync"

-- ── Dispatch ─────────────────────────────────────────────────────────────────

--- Point d'entrée redbean : appelé pour chaque requête HTTP.
-- Route sur path + method et délègue aux handlers GET/POST correspondants.
export OnHttpRequest
OnHttpRequest = ->
  path   = GetPath!
  method = GetMethod!

  switch path
    when "/"
      html_resp "Accueil", home_page!
    when "/install"
      if method == "POST" then handle_install! else html_resp "Installer", install_page!
    when "/uninstall"
      if method == "POST" then handle_uninstall! else html_resp "Désinstaller", uninstall_page!
    when "/sync"
      if method == "POST" then handle_sync! else html_resp "Sync config", sync_page!
    else
      SetStatus 404
      html_resp "Page introuvable", H.div {
        H.p "Page introuvable."
        H.p H.a { href: "/", "← Accueil" }
      }
