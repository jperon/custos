-- src/auth/nft_auth_sets.moon
-- Gestion des sous-chaînes nft d'authentification par règle (sets `_auth_mac`,
-- `_auth_ip4`, `_auth_ip6`) et des sets globaux d'authentification.
-- Extrait de auth/server.moon pour isoler la logique nft des handlers HTTP.

config = require "config"
{ :log_info, :log_warn } = require "log"
{ :user_qualifies_for_rule, :rule_requires_auth } = require "auth.rule_user"
rule_id_mod = require "filter.rule_id"
generate_rule_id = rule_id_mod.generate

-- Lit userlists depuis la config live et délègue à auth.rule_user.
qualifies_for_rule = (user, rule) ->
  filter_cfg = config.filter or {}
  user_qualifies_for_rule user, rule, filter_cfg.userlists or {}

auth_set_names = (ip) ->
  return "_auth_mac", nil unless ip and ip ~= "unknown"
  if ip\find ":"
    "_auth_mac", "_auth_ip6"
  else
    "_auth_mac", "_auth_ip4"

run_auth_set_op = (nft_sess, rule_id, mac, ip, op, ttl=nil) ->
  return unless nft_sess
  mac_set, ip_set = auth_set_names ip
  timeout = if ttl then " timeout #{ttl}s" else ""
  ok, err = pcall ->
    nft_sess.run_nft "#{op} element bridge dns-filter-bridge #{rule_id}_auth_mac { #{mac}#{timeout} }", { quiet: true }
    if ip_set
      nft_sess.run_nft "#{op} element bridge dns-filter-bridge #{rule_id}#{ip_set} { #{ip}#{timeout} }", { quiet: true }
  unless ok
    log_warn -> { action: "auth_set_#{op}_failed", rule_id: rule_id, mac: mac, ip: ip, err: tostring(err) }
  ok

for_qualifying_auth_rules = (user, fn) ->
  filter_cfg = config.filter or {}
  rules = filter_cfg.rules or {}
  for idx, rule in ipairs rules
    continue unless rule_requires_auth rule
    continue unless qualifies_for_rule user, rule
    fn generate_rule_id(rule, idx), rule

refresh_rule_auth_sets = (nft_sess, ip, mac, ttl, user) ->
  for_qualifying_auth_rules user, (rule_id, rule) ->
    ok = run_auth_set_op nft_sess, rule_id, mac, ip, "add", ttl
    log_info -> { action: "server_auth_set_add_mac", rule_id: rule_id, mac: mac } if ok
    log_info -> { action: "server_auth_set_add_ip4", rule_id: rule_id, ip: ip } if ok and ip and ip\find ":" == nil and ip ~= "unknown"
    log_info -> { action: "server_auth_set_add_ip6", rule_id: rule_id, ip: ip } if ok and ip and (ip\find ":") and ip ~= "unknown"

delete_rule_auth_sets = (nft_sess, ip, mac, user) ->
  for_qualifying_auth_rules user, (rule_id, rule) ->
    run_auth_set_op nft_sess, rule_id, mac, ip, "delete"

-- Rafraîchit les sets nft globaux d'authentification (appelé par ping et login).
refresh_nft = (nft_sess, ip, mac, ttl, user) ->
  return unless nft_sess
  nft_sess.add_authenticated ip, ttl if ip and ip ~= "unknown"
  nft_sess.add_authenticated_mac mac, ttl if mac and mac ~= "unknown"

{
  :qualifies_for_rule, :auth_set_names, :run_auth_set_op, :for_qualifying_auth_rules
  :refresh_rule_auth_sets, :delete_rule_auth_sets, :refresh_nft
}
