local H = require("auth.html")
local page
page = require("webui.handlers.dashboard").page
local read_config
read_config = require("webui.serializer").read_config
local events_dir_for
events_dir_for = require("webui.handlers.devices").events_dir_for
local bidirectional
bidirectional = require("ipparse.fun").bidirectional
local esc
esc = function(s)
  s = tostring(s or "")
  return (s:gsub("[&<>\"']", {
    ["&"] = "&amp;",
    ["<"] = "&lt;",
    [">"] = "&gt;",
    ['"'] = "&quot;",
    ["'"] = "&#39;"
  }))
end
local read_verdicts
read_verdicts = function(events_dir)
  local fh = io.open(tostring(events_dir) .. "/recent-verdicts.tsv", "r")
  if not (fh) then
    return { }
  end
  local out = { }
  for line in fh:lines() do
    local _continue_0 = false
    repeat
      local mac, ip, user, qname, decision, reason, count, first_ts, last_ts = line:match("^([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)$")
      if not (mac and mac ~= "") then
        _continue_0 = true
        break
      end
      out[#out + 1] = {
        mac = mac,
        ip = ip,
        user = user,
        qname = qname,
        decision = decision,
        reason = reason,
        count = tonumber(count) or 0,
        first_ts = tonumber(first_ts) or 0,
        last_ts = tonumber(last_ts) or 0
      }
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  fh:close()
  return out
end
local VERDICTS_JS = [[(function(){
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
local fmt_ts
fmt_ts = function(ts)
  if not ts or ts == 0 then
    return ""
  end
  return os.date("%Y-%m-%d %H:%M:%S", ts)
end
local name_by_mac_for
name_by_mac_for = function(cfg)
  local macs = (cfg and cfg.filter and cfg.filter.macs) or { }
  local lower = { }
  for name, mac in pairs(macs) do
    if type(mac) == "string" then
      lower[name] = mac:lower()
    end
  end
  return bidirectional(lower)
end
local mac_cell
mac_cell = function(v, name_by_mac)
  local mac_l = (v.mac or ""):lower()
  local cell = {
    ["data-sort"] = mac_l,
    (esc(v.mac)),
    H.br(),
    H.span({
      class = "muted"
    }, esc(v.ip))
  }
  local name = name_by_mac[mac_l]
  if name and name ~= "" then
    cell[#cell + 1] = H.br()
    cell[#cell + 1] = H.strong(esc(name))
  end
  return H.td(cell)
end
local render_row
render_row = function(v, name_by_mac)
  return H.tr({
    mac_cell(v, name_by_mac),
    H.td((esc(v.user))),
    H.td((esc(v.qname))),
    H.td((esc(v.decision))),
    H.td((esc(v.reason))),
    H.td({
      ["data-sort"] = tostring(v.count)
    }, tostring(v.count)),
    H.td({
      ["data-sort"] = tostring(v.first_ts)
    }, fmt_ts(v.first_ts)),
    H.td({
      ["data-sort"] = tostring(v.last_ts)
    }, fmt_ts(v.last_ts))
  })
end
local handle_verdicts_get
handle_verdicts_get = function(req, state)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  local verdicts = read_verdicts(events_dir_for(state, cfg))
  local name_by_mac = name_by_mac_for(cfg)
  local rows = { }
  for _index_0 = 1, #verdicts do
    local v = verdicts[_index_0]
    rows[#rows + 1] = render_row(v, name_by_mac)
  end
  local body = H.section({
    H.h2("Verdicts récents"),
    H.p({
      style = "color:#555"
    }, "Tous les derniers verdicts DNS (autorisés et refusés), source : worker_events. Un verdict répété pour un même appareil n'est gardé qu'une fois (le plus récent), avec son nombre d'occurrences."),
    H.p({
      H.input({
        type = "search",
        id = "verdfilter",
        placeholder = "Filtrer…",
        style = "width:100%; box-sizing:border-box"
      })
    }),
    H.table({
      id = "verdtbl"
    }, {
      H.thead({
        H.tr({
          H.th("MAC / IP", H.th("User", H.th("Domaine"))),
          H.th("Décision", H.th("Raison")),
          H.th("Vus", H.th("Première", H.th("Dernière")))
        })
      }),
      H.tbody({ }, table.concat(rows))
    }),
    H.script(VERDICTS_JS),
    " ",
    H.a({
      class = "btn btn-secondary",
      href = "/admin/config/"
    }, "Retour")
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Verdicts", body)
end
return {
  handle_verdicts_get = handle_verdicts_get,
  read_verdicts = read_verdicts
}
