-- src/webui/handlers/verdicts.moon
-- GET /admin/config/verdicts
-- Liste en lecture seule tous les derniers verdicts DNS (allow ET block),
-- source : recent-verdicts.tsv écrit par worker_events. Tableau triable et
-- filtrable (JS inline, sans dépendance), comme la page Appareils.

H = require "auth.html"
{ :page } = require "webui.handlers.dashboard"
{ :read_config } = require "webui.serializer"
{ :events_dir_for } = require "webui.handlers.devices"
{ :bidirectional } = require "ipparse.fun"

-- Échappe le texte destiné au contenu/attribut HTML (le DSL n'échappe rien).
esc = (s) ->
  s = tostring s or ""
  (s\gsub "[&<>\"']", { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })

--- Lit recent-verdicts.tsv et renvoie la liste brute des verdicts (un par ligne).
-- @tparam string events_dir Répertoire des events
-- @treturn table Liste { {mac, ip, user, qname, decision, reason, count,
--                  first_ts, last_ts}, … }
read_verdicts = (events_dir) ->
  fh = io.open "#{events_dir}/recent-verdicts.tsv", "r"
  return {} unless fh
  out = {}
  for line in fh\lines!
    mac, ip, user, qname, decision, reason, count, first_ts, last_ts = line\match(
      "^([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)$")
    continue unless mac and mac ~= ""
    out[#out + 1] = {
      :mac, :ip, :user, :qname, :decision, :reason
      count:    tonumber(count) or 0
      first_ts: tonumber(first_ts) or 0
      last_ts:  tonumber(last_ts) or 0
    }
  fh\close!
  out

-- Bloc JS inline : recherche plein-texte + tri par clic d'en-tête (sans dépendance).
VERDICTS_JS = [[
(function(){
  var tbl = document.getElementById('verdtbl');
  if (!tbl) return;
  var q = document.getElementById('verdfilter');
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

--- Construit le résolveur MAC(minuscule) → nom depuis cfg.filter.macs.
-- `filter.macs` = nom→MAC (string unique, contrat actuel) ; `bidirectional`
-- d'ipparse.fun ajoute l'accès inverse `idx[mac] → nom` sans index explicite.
-- @tparam table cfg Config chargée
-- @treturn table Map paresseuse { mac_lower → nom }
name_by_mac_for = (cfg) ->
  macs  = (cfg and cfg.filter and cfg.filter.macs) or {}
  lower = {}
  for name, mac in pairs macs
    lower[name] = mac\lower! if type(mac) == "string"
  bidirectional lower

-- Cellule MAC / IP sur deux lignes (+ nom sur une 3ᵉ ligne si défini).
mac_cell = (v, name_by_mac) ->
  mac_l = (v.mac or "")\lower!
  cell  = {
    "data-sort": mac_l
    (esc v.mac)
    H.br!
    H.span { class: "muted" }, esc v.ip
  }
  name = name_by_mac[mac_l]
  if name and name != ""
    cell[#cell + 1] = H.br!
    cell[#cell + 1] = H.strong esc name
  H.td cell

render_row = (v, name_by_mac) ->
  H.tr {
    mac_cell v, name_by_mac
    H.td (esc v.user)
    H.td (esc v.qname)
    H.td (esc v.decision)
    H.td (esc v.reason)
    H.td { "data-sort": tostring v.count }, tostring v.count
    H.td { "data-sort": tostring v.first_ts }, fmt_ts v.first_ts
    H.td { "data-sort": tostring v.last_ts }, fmt_ts v.last_ts
  }

handle_verdicts_get = (req, state) ->
  cfg, err = read_config state.config_path
  return 500, {}, "Erreur config : #{err}" unless cfg
  verdicts    = read_verdicts events_dir_for state, cfg
  name_by_mac = name_by_mac_for cfg

  rows = {}
  for v in *verdicts
    rows[#rows + 1] = render_row v, name_by_mac

  body = H.section {
    H.h2 "Verdicts récents"
    H.p { style: "color:#555" },
      "Tous les derniers verdicts DNS (autorisés et refusés), source : worker_events. Un verdict répété pour un même appareil n'est gardé qu'une fois (le plus récent), avec son nombre d'occurrences."
    H.p { H.input { type: "search", id: "verdfilter", placeholder: "Filtrer…", style: "width:100%; box-sizing:border-box" } }
    H.table { id: "verdtbl" }, {
      H.thead {
        H.tr {
          H.th "MAC / IP", H.th "User", H.th "Domaine"
          H.th "Décision", H.th "Raison"
          H.th "Vus", H.th "Première", H.th "Dernière"
        }
      }
      H.tbody {}, table.concat rows
    }
    H.script VERDICTS_JS
    " "
    H.a { class: "btn btn-secondary", href: "/admin/config/" }, "Retour"
  }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Verdicts", body

{
  :handle_verdicts_get, :read_verdicts
}
