local H = require("html")
local html_esc
html_esc = function(s)
  return (s or ""):gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
end
local safe_host
safe_host = function(s)
  return (s or ""):gsub("[^%w%.%-_:%[%]]", "")
end
local safe_port
safe_port = function(s)
  return tostring((tonumber(s) or 22))
end
local safe_path
safe_path = function(s)
  return (s or ""):gsub("[^%w%.%-_/]", "")
end
local safe_url
safe_url = function(s)
  return (s or ""):gsub("[^%w%.%-_:/@%%?=&#%+]", "")
end
local safe_user
safe_user = function(s)
  return (s or ""):gsub("[^%w%.%-_]", "")
end
local run_cmd
run_cmd = function(cmd)
  local fh = io.popen(tostring(cmd) .. " 2>&1", "r")
  if not (fh) then
    return cmd, "Impossible d'exécuter la commande."
  end
  local out = fh:read("*a")
  fh:close()
  return cmd, out
end
local css = [[* { margin: 0; padding: 0; box-sizing: border-box; }
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
local page
page = function(title, content)
  return "<!DOCTYPE html>\n" .. H.html({
    lang = "fr",
    H.head({
      H.meta({
        charset = "UTF-8"
      }),
      H.meta({
        name = "viewport",
        content = "width=device-width, initial-scale=1"
      }),
      H.title("CustosVirginum — " .. tostring(title)),
      H.style(css)
    }),
    H.body({
      H.nav({
        H.h2("Custos"),
        H.a({
          href = "/",
          "Accueil"
        }),
        H.a({
          href = "/install",
          "Installer"
        }),
        H.a({
          href = "/sync",
          "Sync config"
        }),
        H.a({
          href = "/uninstall",
          "Désinstaller"
        })
      }),
      H.div({
        id = "spinner",
        "⏳ En cours, veuillez patienter…"
      }),
      H.main(content),
      H.script("function showSpinner(){document.getElementById('spinner').style.display='flex';}")
    })
  })
end
local html_resp
html_resp = function(title, content)
  SetHeader("Content-Type", "text/html; charset=UTF-8")
  return Write(page(title, content))
end
local ff
ff = function(lbl, name, t, dflt, note)
  local note_el
  if note then
    note_el = H.p({
      class = "note"
    }, note)
  else
    note_el = ""
  end
  local label_el = H.label(lbl)
  local input_el = H.input({
    type = t,
    name = name,
    value = (dflt or ""),
    placeholder = (dflt or "")
  })
  return H.div({
    class = "ff",
    label_el,
    input_el,
    note_el
  })
end
local cb
cb = function(lbl, name)
  local inp_el = H.input({
    type = "checkbox",
    name = name,
    value = "1",
    id = name
  })
  local lbl_el = H.label({
    ["for"] = name,
    lbl
  })
  return H.div({
    class = "cbrow",
    inp_el,
    lbl_el
  })
end
local home_page
home_page = function()
  return H.div({
    H.h1("CustosVirginum — Installateur"),
    H.div({
      class = "intro",
      H.p("Interface locale pour déployer CustosVirginum sur un routeur OpenWrt via SSH."),
      H.ul({
        H.li(H.a({
          href = "/install",
          "Installer Custos sur un routeur"
        })),
        H.li(H.a({
          href = "/sync",
          "Configurer la synchronisation de configuration"
        })),
        H.li(H.a({
          href = "/uninstall",
          "Désinstaller Custos d'un routeur"
        }))
      }),
      H.p({
        style = "margin-top:1rem;color:#666;font-size:.9rem;",
        "Prérequis locaux : ssh, scp, tar, make (ou moonc+luajit), accès SSH par clé au routeur."
      })
    })
  })
end
local install_page
install_page = function()
  return H.div({
    H.h1("Installer CustosVirginum"),
    H.form({
      method = "POST",
      action = "/install",
      onsubmit = "showSpinner()",
      ff("Hôte (IP ou hostname du routeur) *", "host", "text", "", "Ex. : 192.168.1.1 ou router.local"),
      ff("Port SSH", "port", "number", "22", nil),
      ff("Utilisateur SSH", "user", "text", "root", nil),
      ff("Dossier de destination sur le routeur", "dest", "text", "/usr/share/custos", nil),
      cb("--no-build (lua/ déjà compilé, ignorer make all)", "no_build"),
      cb("--no-start (installer sans démarrer le service)", "no_start"),
      cb("--dry-run (simuler sans exécuter)", "dry_run"),
      H.button({
        type = "submit",
        "Lancer l'installation"
      })
    })
  })
end
local uninstall_page
uninstall_page = function()
  return H.div({
    H.h1("Désinstaller CustosVirginum"),
    H.form({
      method = "POST",
      action = "/uninstall",
      onsubmit = "showSpinner()",
      ff("Hôte (IP ou hostname du routeur) *", "host", "text", "", "Ex. : 192.168.1.1"),
      ff("Port SSH", "port", "number", "22", nil),
      ff("Utilisateur SSH", "user", "text", "root", nil),
      H.button({
        type = "submit",
        "Lancer la désinstallation"
      })
    })
  })
end
local sync_page
sync_page = function()
  local pull_lbl = H.label({
    class = "rrow-item",
    H.input({
      type = "radio",
      name = "mode",
      value = "pull",
      checked = "checked"
    }),
    " Pull-only (device secondaire)"
  })
  local push_lbl = H.label({
    class = "rrow-item",
    H.input({
      type = "radio",
      name = "mode",
      value = "push"
    }),
    " Push + Pull (filtre de référence)"
  })
  local mode_ff = H.div({
    class = "ff",
    H.label("Type de synchronisation"),
    H.div({
      class = "rrow",
      pull_lbl,
      push_lbl
    })
  })
  return H.div({
    H.h1("Synchronisation de configuration"),
    H.form({
      method = "POST",
      action = "/sync",
      onsubmit = "showSpinner()",
      ff("Hôte (IP ou hostname du routeur) *", "host", "text", "", "Ex. : 192.168.1.1"),
      ff("URL du dépôt Git de configurations *", "repo", "url", "", "Ex. : https://git.example.com/custos-configs"),
      mode_ff,
      H.button({
        type = "submit",
        "Configurer la synchronisation"
      })
    })
  })
end
local result_page
result_page = function(title, cmd, output, back)
  return H.div({
    H.h1(title),
    H.p("Commande exécutée :"),
    H.p({
      class = "cmd",
      cmd
    }),
    H.pre({
      class = "out",
      html_esc(output)
    }),
    H.div({
      class = "back",
      H.a({
        href = back,
        "← Retour"
      })
    })
  })
end
local handle_install
handle_install = function()
  local host = safe_host(GetParam("host"))
  local port = safe_port(GetParam("port"))
  local user = safe_user(GetParam("user"))
  local dest = safe_path(GetParam("dest"))
  if user == "" then
    user = "root"
  end
  if dest == "" then
    dest = "/usr/share/custos"
  end
  if not (host ~= "") then
    SetStatus(400)
    html_resp("Erreur", H.div({
      H.p("L'hôte est requis."),
      H.p(H.a({
        href = "/install",
        "← Retour"
      }))
    }))
    return 
  end
  local flags = ""
  if GetParam("no_build") then
    flags = flags .. " --no-build"
  end
  if GetParam("no_start") then
    flags = flags .. " --no-start"
  end
  if GetParam("dry_run") then
    flags = flags .. " --dry-run"
  end
  local cmd, out = run_cmd("luajit install-owrt.lua " .. tostring(host) .. " --port " .. tostring(port) .. " --user " .. tostring(user) .. " --dest " .. tostring(dest) .. tostring(flags))
  return html_resp("Résultat de l'installation", result_page("Installation — " .. tostring(host), cmd, out, "/install"))
end
local handle_uninstall
handle_uninstall = function()
  local host = safe_host(GetParam("host"))
  local port = safe_port(GetParam("port"))
  local user = safe_user(GetParam("user"))
  if user == "" then
    user = "root"
  end
  if not (host ~= "") then
    SetStatus(400)
    html_resp("Erreur", H.div({
      H.p("L'hôte est requis."),
      H.p(H.a({
        href = "/uninstall",
        "← Retour"
      }))
    }))
    return 
  end
  local cmd, out = run_cmd("luajit install-owrt.lua " .. tostring(host) .. " --port " .. tostring(port) .. " --user " .. tostring(user) .. " --uninstall")
  return html_resp("Résultat de la désinstallation", result_page("Désinstallation — " .. tostring(host), cmd, out, "/uninstall"))
end
local handle_sync
handle_sync = function()
  local host = safe_host(GetParam("host"))
  local repo = safe_url(GetParam("repo"))
  local mode = GetParam("mode")
  if not (host ~= "" and repo ~= "") then
    SetStatus(400)
    html_resp("Erreur", H.div({
      H.p("L'hôte et l'URL du dépôt sont requis."),
      H.p(H.a({
        href = "/sync",
        "← Retour"
      }))
    }))
    return 
  end
  local target
  if mode == "push" then
    target = "sync-push-init"
  else
    target = "sync-init"
  end
  local cmd, out = run_cmd("make " .. tostring(target) .. " HOST=" .. tostring(host) .. " REPO=" .. tostring(repo))
  return html_resp("Résultat de la synchronisation", result_page("Synchronisation — " .. tostring(host), cmd, out, "/sync"))
end
OnHttpRequest = function()
  local path = GetPath()
  local method = GetMethod()
  local _exp_0 = path
  if "/" == _exp_0 then
    return html_resp("Accueil", home_page())
  elseif "/install" == _exp_0 then
    if method == "POST" then
      return handle_install()
    else
      return html_resp("Installer", install_page())
    end
  elseif "/uninstall" == _exp_0 then
    if method == "POST" then
      return handle_uninstall()
    else
      return html_resp("Désinstaller", uninstall_page())
    end
  elseif "/sync" == _exp_0 then
    if method == "POST" then
      return handle_sync()
    else
      return html_resp("Sync config", sync_page())
    end
  else
    SetStatus(404)
    return html_resp("Page introuvable", H.div({
      H.p("Page introuvable."),
      H.p(H.a({
        href = "/",
        "← Accueil"
      }))
    }))
  end
end
