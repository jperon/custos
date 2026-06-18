-- src/webui/router.moon
-- Dispatch des requêtes HTTP sous /admin/* vers les handlers webui.

{ :check_admin_session, :forbidden_page } = require "webui.handlers.admin_auth"
{ :handle_dashboard }           = require "webui.handlers.dashboard"
{ :handle_reload, :handle_status } = require "webui.handlers.system"
{ :handle_config_index,
  :handle_config_section_get,
  :handle_config_section_post,
  :handle_filter_general_get,
  :handle_filter_general_post } = require "webui.handlers.config"
{ :handle_nets_get,   :handle_nets_post,
  :handle_macs_get,   :handle_macs_post,
  :handle_users_get,  :handle_users_post,
  :handle_times_get,  :handle_times_post,
  :handle_decision_get, :handle_decision_post } = require "webui.handlers.filter"
{ :handle_rules_list,
  :handle_rules_new_get,  :handle_rules_new_post,
  :handle_rules_edit_get, :handle_rules_edit_post,
  :handle_rules_delete,   :handle_rules_move }  = require "webui.handlers.rules"
{ :handle_lists_index,
  :handle_lists_type,
  :handle_list_get,     :handle_list_post,
  :handle_list_new_get, :handle_list_new_post } = require "webui.handlers.lists"
{ :handle_devices_get, :handle_devices_post } = require "webui.handlers.devices"

-- Sections scalaires éditables via le handler générique
SCALAR_SECTIONS = {
  runtime:true, nfqueue:true, dns:true, nft:true, ipc:true, clients:true,
  mac_learner:true, auth:true, doh:true, events:true, metrics:true, rtp:true
}

--- Dispatch une requête /admin/* vers le handler approprié.
-- Vérifie d'abord que l'utilisateur est connecté (portail captif) et admin.
-- @tparam table req   Requête HTTP {method, path, headers, body}
-- @tparam table state État du serveur (token_key, admin_users, secrets, auth_cfg, config_path)
-- @treturn number, table, string  (status, headers, body)
dispatch = (req, state) ->
  method = req.method
  path   = req.path

  admin, reason = check_admin_session req, state
  unless admin
    if reason == "forbidden"
      cookie_val = (require "auth.token").get_cookie req.headers.cookie or "", "custos_session"
      p = (require "auth.token").verify cookie_val, state.token_key
      user = p and p.user or "?"
      return 403, { ["Content-Type"]: "text/html; charset=UTF-8" }, forbidden_page user
    -- pas de session → portail captif
    return 302, { ["Location"]: "/login" }, ""

  -- Dashboard
  if path == "/admin/" or path == "/admin"
    return handle_dashboard req, state

  -- Statut et rechargement
  if path == "/admin/system/status"
    return handle_status req, state
  if path == "/admin/system/reload" and method == "POST"
    return handle_reload req, state

  -- Appareils vus sur le réseau (enregistrement MAC → filter.macs)
  if path == "/admin/config/devices"
    return handle_devices_get(req, state)  if method == "GET"
    return handle_devices_post(req, state) if method == "POST"

  -- Index config
  if path == "/admin/config/" or path == "/admin/config"
    return handle_config_index req, state

  -- Sections scalaires /admin/config/:section
  m = path\match "^/admin/config/([a-z_]+)$"
  if m and SCALAR_SECTIONS[m]
    return handle_config_section_get(req, m, state)  if method == "GET"
    return handle_config_section_post(req, m, state) if method == "POST"

  -- Filtre DNS — champs scalaires généraux (SafeSearch, YouTube, listes…)
  if path == "/admin/config/filter/general"
    return handle_filter_general_get(req, state)  if method == "GET"
    return handle_filter_general_post(req, state) if method == "POST"

  -- Filtre DNS — dictionnaires nommés
  if path == "/admin/config/filter/nets"
    return handle_nets_get(req, state)  if method == "GET"
    return handle_nets_post(req, state) if method == "POST"
  if path == "/admin/config/filter/macs"
    return handle_macs_get(req, state)  if method == "GET"
    return handle_macs_post(req, state) if method == "POST"
  if path == "/admin/config/filter/users"
    return handle_users_get(req, state)  if method == "GET"
    return handle_users_post(req, state) if method == "POST"
  if path == "/admin/config/filter/times"
    return handle_times_get(req, state)  if method == "GET"
    return handle_times_post(req, state) if method == "POST"
  if path == "/admin/config/filter/decision"
    return handle_decision_get(req, state)  if method == "GET"
    return handle_decision_post(req, state) if method == "POST"

  -- Listes (from_xxx_list)
  if path == "/admin/config/filter/lists" or path == "/admin/config/filter/lists/"
    return handle_lists_index req, state

  type_m = path\match "^/admin/config/filter/lists/([a-z][a-z0-9_]*)$"
  if type_m
    return handle_lists_type req, type_m, state

  type_new = path\match "^/admin/config/filter/lists/([a-z][a-z0-9_]*)/new$"
  if type_new
    return handle_list_new_get(req, type_new, state)  if method == "GET"
    return handle_list_new_post(req, type_new, state) if method == "POST"

  type_n, name_n = path\match "^/admin/config/filter/lists/([a-z][a-z0-9_]*)/([a-zA-Z0-9][a-zA-Z0-9_%-]*)$"
  if type_n and name_n
    return handle_list_get(req, type_n, name_n, state)  if method == "GET"
    return handle_list_post(req, type_n, name_n, state) if method == "POST"

  -- Filtre DNS — index
  if path == "/admin/config/filter" or path == "/admin/config/filter/"
    return 302, { ["Location"]: "/admin/config/filter/rules" }, ""

  -- Règles
  if path == "/admin/config/filter/rules"
    return handle_rules_list req, state
  if path == "/admin/config/filter/rules/new"
    return handle_rules_new_get(req, state)  if method == "GET"
    return handle_rules_new_post(req, state) if method == "POST"

  -- /admin/config/filter/rules/:n/edit|delete|move
  n_str, action = path\match "^/admin/config/filter/rules/(%d+)/([a-z]+)$"
  if n_str and action
    n = tonumber n_str
    return 400, {}, "Numéro de règle invalide" unless n
    if action == "edit"
      return handle_rules_edit_get(req, n, state)  if method == "GET"
      return handle_rules_edit_post(req, n, state) if method == "POST"
    if action == "delete" and method == "POST"
      return handle_rules_delete req, n, state
    if action == "move" and method == "POST"
      return handle_rules_move req, n, state

  -- Fallback
  302, { ["Location"]: "/admin/" }, ""

{ :dispatch }
