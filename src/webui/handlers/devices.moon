-- src/webui/handlers/devices.moon
-- GET/POST /admin/config/devices
-- Liste les appareils vus sur le réseau (recent-devices.tsv écrit par
-- worker_events) et permet d'enregistrer une MAC sous un nom dans filter.macs.

H = require "auth.html"
{ :page } = require "webui.handlers.dashboard"
{ :read_config, :write_config } = require "webui.serializer"

-- parse_form minimal (cf. webui.handlers.filter) : décode un corps urlencodé.
parse_form = (body) ->
  return {} unless body
  out = {}
  dec = (s) -> (s\gsub "%%(%x%x)", (h) -> string.char tonumber h, 16)\gsub "+", " "
  for k, v in body\gmatch "([^&=]+)=([^&]*)"
    out[dec k] = dec v
  out

-- Échappe le texte destiné au contenu/attribut HTML (le DSL n'échappe rien).
esc = (s) ->
  s = tostring s or ""
  (s\gsub "[&<>\"']", { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })

--- Détermine le répertoire des events (priorité au state, repli config/défaut).
events_dir_for = (state, cfg) ->
  state.events_dir or (cfg and cfg.events and cfg.events.dir) or "/tmp/custos/events"

--- Lit recent-devices.tsv et renvoie une liste de records d'appareils.
-- @tparam string events_dir Répertoire des events
-- @treturn table Liste { {mac, ip, user, qname, decision, count, first_ts, last_ts}, … }
read_devices = (events_dir) ->
  fh = io.open "#{events_dir}/recent-devices.tsv", "r"
  return {} unless fh
  out = {}
  for line in fh\lines!
    mac, ip, user, qname, decision, count, first_ts, last_ts = line\match(
      "^([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)$")
    continue unless mac and mac ~= ""
    out[#out + 1] = {
      :mac, :ip, :user, :qname, :decision
      count:    tonumber(count) or 0
      first_ts: tonumber(first_ts) or 0
      last_ts:  tonumber(last_ts) or 0
    }
  fh\close!
  out

--- Construit la map inverse MAC(minuscule) → nom depuis cfg.filter.macs.
-- Gère les valeurs string (contrat actuel) et table (configs héritées).
-- @tparam table cfg Config chargée
-- @treturn table { mac_lower → nom }
mac_name_index = (cfg) ->
  idx = {}
  macs = (cfg and cfg.filter and cfg.filter.macs) or {}
  for name, val in pairs macs
    if type(val) == "table"
      for m in *val
        idx[tostring(m)\lower!] = name if type(m) == "string"
    elseif type(val) == "string"
      idx[val\lower!] = name
  idx

-- Bloc JS inline : recherche plein-texte + tri par clic d'en-tête (sans dépendance).
DEVICES_JS = [[
(function(){
  var tbl = document.getElementById('devtbl');
  if (!tbl) return;
  var q = document.getElementById('devfilter');
  q.addEventListener('input', function(){
    var f = q.value.toLowerCase();
    Array.prototype.forEach.call(tbl.tBodies[0].rows, function(r){
      r.style.display = r.textContent.toLowerCase().indexOf(f) >= 0 ? '' : 'none';
    });
  });
  var cell = function(td){
    var s = td.getAttribute('data-sort');
    return s !== null ? parseFloat(s) : td.textContent.trim().toLowerCase();
  };
  Array.prototype.forEach.call(tbl.tHead.rows[0].cells, function(th, i){
    if (th.classList.contains('nosort')) return;
    th.style.cursor = 'pointer';
    var asc = true;
    th.addEventListener('click', function(){
      var rows = Array.prototype.slice.call(tbl.tBodies[0].rows);
      rows.sort(function(a, b){
        var x = cell(a.cells[i]), y = cell(b.cells[i]);
        if (x < y) return asc ? -1 : 1;
        if (x > y) return asc ? 1 : -1;
        return 0;
      });
      asc = !asc;
      rows.forEach(function(r){ tbl.tBodies[0].appendChild(r); });
    });
  });
})();
]]

fmt_ts = (ts) ->
  return "" if not ts or ts == 0
  os.date "%Y-%m-%d %H:%M:%S", ts

-- Rend une ligne du tableau pour un appareil.
-- Le formulaire est toujours rendu : champ pré-rempli si la MAC est déjà nommée
-- (édition du nom), vide sinon (enregistrement).
render_row = (d, name) ->
  name_attrs = { type: "text", name: "name", placeholder: "nom", required: "required", style: "margin:0; flex:1 1 auto; min-width:10rem; width:auto" }
  name_attrs.value = esc name if name and name ~= ""
  name_cell = H.form { method: "POST", action: "/admin/config/devices", style: "margin:0; display:flex; gap:.25rem; min-width:14rem" }, {
    H.input { type: "hidden", name: "mac", value: esc d.mac }
    H.input name_attrs
    H.button { type: "submit", class: "btn btn-sm", title: "Enregistrer" }, "+"
  }
  H.tr {
    H.td name_cell
    H.td (esc d.mac)
    H.td (esc d.ip)
    H.td (esc d.user)
    H.td (esc d.qname)
    H.td (esc d.decision)
    H.td { "data-sort": tostring d.count }, tostring d.count
    H.td { "data-sort": tostring d.last_ts }, fmt_ts d.last_ts
  }

handle_devices_get = (req, state) ->
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  devices = read_devices events_dir_for state, cfg
  idx     = mac_name_index cfg

  rows = {}
  for d in *devices
    rows[#rows + 1] = render_row d, idx[d.mac\lower!]

  body = H.section {
    H.h2 "Appareils vus sur le réseau"
    H.p { style: "color:#555" },
      "Liste des appareils observés (source : worker_events). Une ligne sans nom n'est pas encore enregistrée : saisir un nom puis « Enregistrer » l'ajoute à #{H.code 'filter.macs'}, réutilisable dans les règles et maclists."
    H.p { H.input { type: "search", id: "devfilter", placeholder: "Filtrer…", style: "width:100%; box-sizing:border-box" } }
    H.table { id: "devtbl" }, {
      H.thead {
        H.tr {
          H.th "Nom", H.th "MAC", H.th "IP", H.th "User"
          H.th "Dernier domaine", H.th "Décision"
          H.th "Vus", H.th "Dernière activité"
        }
      }
      H.tbody {}, table.concat rows
    }
    H.script DEVICES_JS
    " "
    H.a { class: "btn btn-secondary", href: "/admin/config/" }, "Retour"
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Appareils", body

-- Envoie SIGHUP au superviseur (cf. webui.handlers.system.handle_reload).
default_reload = ->
  ffi = require "ffi"
  pcall -> ffi.cdef "int kill(int, int); int getppid(void);"
  pcall -> ffi.C.kill ffi.C.getppid!, 1

-- Valide une adresse MAC (6 octets hex séparés par ':').
valid_mac = (mac) ->
  mac and mac\match "^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$"

handle_devices_post = (req, state) ->
  form = parse_form req.body
  mac  = (form.mac or "")\lower!
  name = (form.name or "")\match "^%s*(.-)%s*$"
  return 400, {}, "MAC invalide" unless valid_mac mac
  return 400, {}, "Nom requis"   if name == ""

  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  cfg.filter or= {}
  cfg.filter.macs or= {}
  -- Retire un éventuel nom existant pour cette MAC (renommage idempotent).
  for n, v in pairs cfg.filter.macs
    cfg.filter.macs[n] = nil if type(v) == "string" and v\lower! == mac
  cfg.filter.macs[name] = mac

  ok, e = write_config cfg, state.config_path
  return 500, {}, "Erreur écriture : #{e}" unless ok

  -- Reload SIGHUP au superviseur (injectable via state.reload pour les tests).
  (state.reload or default_reload)!

  302, { ["Location"]: "/admin/config/devices" }, ""

{
  :handle_devices_get, :handle_devices_post
  :read_devices, :mac_name_index, :valid_mac, :events_dir_for
}
