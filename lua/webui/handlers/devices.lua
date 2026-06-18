local H = require("auth.html")
local page
page = require("webui.handlers.dashboard").page
local read_config, write_config
do
  local _obj_0 = require("webui.serializer")
  read_config, write_config = _obj_0.read_config, _obj_0.write_config
end
local parse_form
parse_form = function(body)
  if not (body) then
    return { }
  end
  local out = { }
  local dec
  dec = function(s)
    return (s:gsub("%%(%x%x)", function(h)
      return string.char(tonumber(h, 16))
    end)):gsub("+", " ")
  end
  for k, v in body:gmatch("([^&=]+)=([^&]*)") do
    out[dec(k)] = dec(v)
  end
  return out
end
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
local events_dir_for
events_dir_for = function(state, cfg)
  return state.events_dir or (cfg and cfg.events and cfg.events.dir) or "/tmp/custos/events"
end
local read_devices
read_devices = function(events_dir)
  local fh = io.open(tostring(events_dir) .. "/recent-verdicts.tsv", "r")
  if not (fh) then
    return { }
  end
  local by_mac = { }
  local order = { }
  for line in fh:lines() do
    local _continue_0 = false
    repeat
      local mac, ip, user, qname, decision, _reason, count, first_ts, last_ts = line:match("^([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)$")
      if not (mac and mac ~= "") then
        _continue_0 = true
        break
      end
      local cnt = tonumber(count) or 0
      local fst = tonumber(first_ts) or 0
      local lst = tonumber(last_ts) or 0
      local e = by_mac[mac]
      if not (e) then
        e = {
          mac = mac,
          ip = ip,
          user = user,
          qname = qname,
          decision = decision,
          count = 0,
          first_ts = fst,
          last_ts = lst
        }
        by_mac[mac] = e
        order[#order + 1] = e
      end
      e.count = e.count + cnt
      if fst < e.first_ts then
        e.first_ts = fst
      end
      if lst > e.last_ts then
        e.last_ts = lst
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  fh:close()
  return order
end
local mac_name_index
mac_name_index = function(cfg)
  local idx = { }
  local macs = (cfg and cfg.filter and cfg.filter.macs) or { }
  for name, val in pairs(macs) do
    if type(val) == "table" then
      for _index_0 = 1, #val do
        local m = val[_index_0]
        if type(m) == "string" then
          idx[tostring(m):lower()] = name
        end
      end
    elseif type(val) == "string" then
      idx[val:lower()] = name
    end
  end
  return idx
end
local DEVICES_JS = [[(function(){
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
local fmt_ts
fmt_ts = function(ts)
  if not ts or ts == 0 then
    return ""
  end
  return os.date("%Y-%m-%d %H:%M:%S", ts)
end
local render_row
render_row = function(d, name)
  local name_attrs = {
    type = "text",
    name = "name",
    placeholder = "nom",
    required = "required",
    style = "margin:0; flex:1 1 auto; min-width:10rem; width:auto"
  }
  if name and name ~= "" then
    name_attrs.value = esc(name)
  end
  local name_cell = H.form({
    method = "POST",
    action = "/admin/config/devices",
    style = "margin:0; display:flex; gap:.25rem; min-width:14rem"
  }, {
    H.input({
      type = "hidden",
      name = "mac",
      value = esc(d.mac)
    }),
    H.input(name_attrs),
    H.button({
      type = "submit",
      class = "btn btn-sm",
      title = "Enregistrer"
    }, "+")
  })
  return H.tr({
    H.td(name_cell),
    H.td((esc(d.mac))),
    H.td((esc(d.ip))),
    H.td((esc(d.user))),
    H.td((esc(d.qname))),
    H.td((esc(d.decision))),
    H.td({
      ["data-sort"] = tostring(d.count)
    }, tostring(d.count)),
    H.td({
      ["data-sort"] = tostring(d.last_ts)
    }, fmt_ts(d.last_ts))
  })
end
local handle_devices_get
handle_devices_get = function(req, state)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  local devices = read_devices(events_dir_for(state, cfg))
  local idx = mac_name_index(cfg)
  local rows = { }
  for _index_0 = 1, #devices do
    local d = devices[_index_0]
    rows[#rows + 1] = render_row(d, idx[d.mac:lower()])
  end
  local body = H.section({
    H.h2("Appareils vus sur le réseau"),
    H.p({
      style = "color:#555"
    }, "Liste des appareils observés (source : worker_events). Une ligne sans nom n'est pas encore enregistrée : saisir un nom puis « Enregistrer » l'ajoute à " .. tostring(H.code('filter.macs')) .. ", réutilisable dans les règles et maclists."),
    H.p({
      H.input({
        type = "search",
        id = "devfilter",
        placeholder = "Filtrer…",
        style = "width:100%; box-sizing:border-box"
      })
    }),
    H.table({
      id = "devtbl"
    }, {
      H.thead({
        H.tr({
          H.th("Nom", H.th("MAC", H.th("IP", H.th("User")))),
          H.th("Dernier domaine", H.th("Décision")),
          H.th("Vus", H.th("Dernière activité"))
        })
      }),
      H.tbody({ }, table.concat(rows))
    }),
    H.script(DEVICES_JS),
    " ",
    H.a({
      class = "btn btn-secondary",
      href = "/admin/config/"
    }, "Retour")
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Appareils", body)
end
local default_reload
default_reload = function()
  local ffi = require("ffi")
  pcall(function()
    return ffi.cdef("int kill(int, int); int getppid(void);")
  end)
  return pcall(function()
    return ffi.C.kill(ffi.C.getppid(), 1)
  end)
end
local valid_mac
valid_mac = function(mac)
  return mac and mac:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$")
end
local REDIRECT_WHITELIST = {
  ["/admin/config/devices"] = true,
  ["/admin/config/verdicts"] = true
}
local handle_devices_post
handle_devices_post = function(req, state)
  local form = parse_form(req.body)
  local mac = (form.mac or ""):lower()
  local name = (form.name or ""):match("^%s*(.-)%s*$")
  local back = REDIRECT_WHITELIST[form.redirect] and form.redirect or "/admin/config/devices"
  if not (valid_mac(mac)) then
    return 400, { }, "MAC invalide"
  end
  if name == "" then
    return 400, { }, "Nom requis"
  end
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  cfg.filter = cfg.filter or { }
  cfg.filter.macs = cfg.filter.macs or { }
  for n, v in pairs(cfg.filter.macs) do
    if type(v) == "string" and v:lower() == mac then
      cfg.filter.macs[n] = nil
    end
  end
  cfg.filter.macs[name] = mac
  local ok, e = write_config(cfg, state.config_path)
  if not (ok) then
    return 500, { }, "Erreur écriture : " .. tostring(e)
  end
  (state.reload or default_reload)()
  return 302, {
    ["Location"] = back
  }, ""
end
return {
  handle_devices_get = handle_devices_get,
  handle_devices_post = handle_devices_post,
  read_devices = read_devices,
  mac_name_index = mac_name_index,
  valid_mac = valid_mac,
  events_dir_for = events_dir_for
}
