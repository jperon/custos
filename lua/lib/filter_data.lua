local build_filter_data
build_filter_data = function(filter)
  return {
    rules = filter.get_rules(),
    auth_cfg_cache = filter.auth_cfg_cache,
    sni_cfg_cache = filter.sni_cfg_cache,
    decision_cfg = filter.decision_cfg
  }
end
return {
  build_filter_data = build_filter_data
}
