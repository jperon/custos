local H = require("auth.html")
local page
page = require("webui.handlers.dashboard").page
local read_config
read_config = require("webui.serializer").read_config
local esc
esc = require("webui.util").esc
local json = require("lib.json")
local pidfile = require("lib.pidfile")
local shquote
shquote = require("lib.shquote").shquote
local STALE_FACTOR = 3
local STALE_MIN = 180
local runtime_dir_for
runtime_dir_for = function(state, cfg)
  if state.runtime_dir then
    return state.runtime_dir
  end
  local pid_path = pidfile.resolve_path(cfg and cfg.runtime and cfg.runtime.pid_file)
  return pid_path:match("^(.*)/") or "."
end
local counter
counter = function(v)
  local n = tonumber(v)
  if not (n and n >= 0 and n <= 1e15 and n == math.floor(n)) then
    return 0
  end
  return n
end
local valid_snapshot
valid_snapshot = function(snap)
  if not (type(snap) == "table") then
    return false
  end
  if not (type(snap.timestamp) == "number") then
    return false
  end
  if not (snap.timestamp > 0 and snap.timestamp < 4102444800) then
    return false
  end
  return type(snap.rules) == "table"
end
local read_snapshots
read_snapshots = function(dir)
  local h = io.popen("ls -1 " .. tostring(shquote(dir)) .. "/metrics-*.json 2>/dev/null")
  if not (h) then
    return { }, 0
  end
  local out = { }
  local ignored = 0
  for path in h:lines() do
    local _continue_0 = false
    repeat
      local fh = io.open(path, "r")
      if not (fh) then
        ignored = ignored + 1
        _continue_0 = true
        break
      end
      local content = fh:read("*a")
      fh:close()
      local snap = nil
      local ok = pcall(function()
        snap = json.decode(content)
      end)
      if not (ok and valid_snapshot(snap)) then
        ignored = ignored + 1
        _continue_0 = true
        break
      end
      local name = path:match("([^/]+)$" or path)
      out[#out + 1] = {
        name = name,
        timestamp = snap.timestamp,
        rules = snap.rules
      }
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  h:close()
  return out, ignored
end
local total_of
total_of = function(e)
  return e.allow + e.refuse + e.dnsonly
end
local valid_rule
valid_rule = function(r)
  return type(r) == "table" and type(r.rule_id) == "string" and type(r.verdicts) == "table"
end
local aggregate
aggregate = function(snapshots)
  local totals = {
    allow = 0,
    refuse = 0,
    dnsonly = 0
  }
  local by_rule = { }
  local order = { }
  for _index_0 = 1, #snapshots do
    local snap = snapshots[_index_0]
    local _list_0 = snap.rules
    for _index_1 = 1, #_list_0 do
      local _continue_0 = false
      repeat
        local r = _list_0[_index_1]
        if not (valid_rule(r)) then
          _continue_0 = true
          break
        end
        local entry = by_rule[r.rule_id]
        if not (entry) then
          entry = {
            rule_id = r.rule_id,
            allow = 0,
            refuse = 0,
            dnsonly = 0
          }
          by_rule[r.rule_id] = entry
          order[#order + 1] = entry
        end
        local _list_1 = {
          "allow",
          "refuse",
          "dnsonly"
        }
        for _index_2 = 1, #_list_1 do
          local key = _list_1[_index_2]
          local n = counter(r.verdicts[key])
          local _update_0 = key
          entry[_update_0] = entry[_update_0] + n
          local _update_1 = key
          totals[_update_1] = totals[_update_1] + n
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
  end
  table.sort(order, function(a, b)
    local ta, tb = total_of(a), total_of(b)
    if ta ~= tb then
      return ta > tb
    else
      return a.rule_id < b.rule_id
    end
  end)
  return {
    totals = totals,
    rules = order,
    total = total_of(totals)
  }
end
local fmt_ts
fmt_ts = function(ts)
  local ok, s = pcall(os.date, "%Y-%m-%d %H:%M:%S", ts)
  return ok and s or "date inconnue"
end
local render_workers
render_workers = function(snapshots, now, stale_after)
  local rows = { }
  for _index_0 = 1, #snapshots do
    local snap = snapshots[_index_0]
    local age = math.max(0, now - snap.timestamp)
    local stale = age > stale_after
    local state
    if stale then
      state = "périmé (ignoré)"
    else
      state = "à jour"
    end
    rows[#rows + 1] = H.tr({
      H.td((esc(snap.name))),
      H.td((esc(fmt_ts(snap.timestamp)))),
      H.td(tostring(age) .. " s"),
      H.td((esc(state)))
    })
  end
  if #rows == 0 then
    return H.p({
      style = "color:#555"
    }, "Aucun instantané de worker trouvé.")
  else
    return H.table({
      H.thead({
        H.tr({
          H.th("Worker", H.th("Dernier instantané", H.th("Âge", H.th("État"))))
        })
      }),
      H.tbody({ }, table.concat(rows))
    })
  end
end
local render_totals
render_totals = function(agg)
  return H.table({
    H.thead({
      H.tr({
        H.th("Verdict", H.th("Total"))
      })
    }),
    H.tbody({ }, table.concat({
      H.tr({
        H.td("Autorisés (allow)", H.td(tostring(agg.totals.allow)))
      }),
      H.tr({
        H.td("Refusés (refuse)", H.td(tostring(agg.totals.refuse)))
      }),
      H.tr({
        H.td("DNS seul (dnsonly)", H.td(tostring(agg.totals.dnsonly)))
      }),
      H.tr({
        H.td((H.strong("Total verdicts")), H.td((H.strong(tostring(agg.total)))))
      })
    }))
  })
end
local render_rules
render_rules = function(agg)
  local rows = { }
  local _list_0 = agg.rules
  for _index_0 = 1, #_list_0 do
    local r = _list_0[_index_0]
    rows[#rows + 1] = H.tr({
      H.td((esc(r.rule_id))),
      H.td(tostring(r.allow)),
      H.td(tostring(r.refuse)),
      H.td(tostring(r.dnsonly)),
      H.td(tostring(total_of(r)))
    })
  end
  if #rows == 0 then
    return H.p({
      style = "color:#555"
    }, "Aucun verdict enregistré pour l'instant.")
  else
    return H.table({
      H.thead({
        H.tr({
          H.th("Règle", H.th("Allow", H.th("Refuse", H.th("DNS only", H.th("Total")))))
        })
      }),
      H.tbody({ }, table.concat(rows))
    })
  end
end
local handle_metrics_get
handle_metrics_get = function(req, state)
  local cfg, err = read_config(state.config_path)
  if not (cfg) then
    return 500, { }, "Erreur config : " .. tostring(err)
  end
  local cfg_metrics = cfg.metrics or { }
  local enabled = cfg_metrics.enabled ~= false
  local now = state.now or os.time()
  local dir = runtime_dir_for(state, cfg)
  if not enabled then
    local body = H.section({
      H.h2("Métriques"),
      H.p("Métriques désactivées (metrics.enabled = false) : aucun instantané n'est écrit par les workers.")
    })
    return 200, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, page("Métriques", body)
  end
  local snapshots, ignored = read_snapshots(dir)
  local interval = tonumber(cfg_metrics.flush_interval or 60)
  local stale_after = math.max(interval * STALE_FACTOR, STALE_MIN)
  local fresh
  do
    local _accum_0 = { }
    local _len_0 = 1
    for _index_0 = 1, #snapshots do
      local s = snapshots[_index_0]
      if now - s.timestamp <= stale_after then
        _accum_0[_len_0] = s
        _len_0 = _len_0 + 1
      end
    end
    fresh = _accum_0
  end
  local agg = aggregate(fresh)
  local notices = { }
  notices[#notices + 1] = H.p({
    style = "color:#555"
  }, "Instantanés lus dans " .. tostring(esc(dir)) .. " ; un fichier périmé (plus de " .. tostring(stale_after) .. " s) ou corrompu est ignoré.")
  if #fresh == 0 then
    notices[#notices + 1] = H.p({
      style = "color:#a00"
    }, "Aucun instantané à jour : démarrez le service ou vérifiez le répertoire d'exécution.")
  end
  if ignored > 0 then
    notices[#notices + 1] = H.p({
      style = "color:#a00"
    }, tostring(ignored) .. " fichier(s) illisible(s) ou corrompu(s) ignoré(s).")
  end
  local parts = { }
  parts[#parts + 1] = H.section({
    H.h2("Totaux"),
    table.concat(notices),
    render_totals(agg)
  })
  parts[#parts + 1] = H.section({
    H.h2("Par règle"),
    render_rules(agg)
  })
  parts[#parts + 1] = H.section({
    H.h2("Workers"),
    render_workers(snapshots, now, stale_after),
    " ",
    H.a({
      class = "btn btn-secondary",
      href = "/admin/"
    }, "Retour")
  })
  local body = table.concat(parts)
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Métriques", body)
end
return {
  handle_metrics_get = handle_metrics_get,
  runtime_dir_for = runtime_dir_for,
  read_snapshots = read_snapshots,
  aggregate = aggregate
}
