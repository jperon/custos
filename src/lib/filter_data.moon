-- src/lib/filter_data.moon
-- Construit la table `filter_data` transmise aux workers DNS/response/DoH/SNI.
-- Extrait de main.moon pour éviter la duplication qui avait fait oublier
-- `sni_cfg_cache` lors du rechargement SIGHUP (worker_tls retombait alors sur
-- les défauts de la politique SNI). Fonction pure, sans effet de bord.
--
-- Doit lister TOUTES les clés lues par les workers :
--   worker_questions : rules, auth_cfg_cache, decision_cfg
--   worker_responses : (reçoit rules_metadata séparément)
--   worker_doh       : rules, auth_cfg_cache, decision_cfg
--   worker_tls       : rules, auth_cfg_cache, sni_cfg_cache, decision_cfg

--- Construit filter_data à partir du module filter (déjà chargé).
-- @tparam table filter Module filter (get_rules, auth_cfg_cache, sni_cfg_cache, decision_cfg)
-- @treturn table { rules, auth_cfg_cache, sni_cfg_cache, decision_cfg }
build_filter_data = (filter) ->
  {
    rules: filter.get_rules!
    auth_cfg_cache: filter.auth_cfg_cache
    sni_cfg_cache: filter.sni_cfg_cache
    decision_cfg: filter.decision_cfg
  }

{ :build_filter_data }
