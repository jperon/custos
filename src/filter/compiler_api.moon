-- src/filter/compiler_api.moon
-- API interne pour la compilation multi-backend des conditions et actions.
--
-- Les modules conditions/actions peuvent exposer soit :
--   • Ancien style : une factory function `(cfg) -> (args) -> checker`
--   • Nouveau style : un objet/table avec :
--       - capabilities : table des backends supportés { worker, nft_static, nft_dynamic }
--       - eval         : fonction d'évaluation runtime (checker)
--       - compile_nft  : fonction de compilation nft (optionnel)
--       - creates_dynamic_scope : boolean (true si condition DNS)
--
-- Note: worker_only est DÉDUIT de capabilities.nft_static (pas de champ explicite)

--- Détecte si un objet est au nouveau style enrichi.
-- @tparam any obj Objet retourné par la factory après application cfg/args
-- @treturn boolean true si nouveau style (objet avec capabilities)
is_new_style = (obj) ->
  return false unless type(obj) == "table"
  return false unless obj.capabilities
  true

--- Déduit si une condition/action est worker-only de ses capabilities.
-- @tparam table obj Objet enrichi avec capabilities
-- @treturn boolean true si worker-only (pas de support nft_static)
compute_worker_only = (obj) ->
  return true unless type(obj) == "table"
  return true unless obj.capabilities
  return not obj.capabilities.nft_static

--- Charge un module condition avec adaptation automatique.
-- Retourne une factory (cfg) -> (args) -> enriched_obj
-- Détecte le style au moment de l'appel (le module exporte toujours une factory).
-- @tparam string name Nom du module (ex: "from_net")
-- @treturn function|nil Factory (cfg) -> (args) -> enriched_obj
load_condition = (name) ->
  ok, factory_outer = pcall require, "filter.conditions.#{name}"
  return nil, factory_outer unless ok

  (cfg) ->
    (args) ->
      -- Appelle la factory pour obtenir le résultat
      factory_inner = factory_outer cfg
      result = factory_inner args

      if is_new_style result
        -- Nouveau style: result est déjà l'objet enrichi
        return result
      else
        -- Ancien style: result est la fonction checker, on wrappe
        -- worker_only est déduit de capabilities.nft_static (false ici)
        {
          capabilities: { worker: true, nft_static: false, nft_dynamic: false }
          eval: result
          compile_nft: -> nil, "unsupported"
          creates_dynamic_scope: false
        }

--- Charge un module action avec adaptation automatique.
-- Retourne une factory (cfg) -> (rule) -> enriched_obj
-- Détecte le style au moment de l'appel.
-- @tparam string name Nom du module (ex: "allow")
-- @treturn function|nil Factory (cfg) -> (rule) -> enriched_obj
load_action = (name) ->
  ok, factory_outer = pcall require, "filter.actions.#{name}"
  return nil, factory_outer unless ok

  (cfg) ->
    (rule) ->
      -- Appelle la factory pour obtenir le résultat
      factory_inner = factory_outer cfg
      result = factory_inner rule

      if is_new_style result
        -- Nouveau style: result est déjà l'objet enrichi
        return result
      else
        -- Ancien style: result est la fonction checker, on wrappe
        -- worker_only est déduit de capabilities.nft (false ici)
        {
          capabilities: { worker: true, nft: false }
          eval: result
          compile_nft: -> nil, "unsupported"
          verdict: -> nil
        }

--- Crée une condition enrichie pour source IP statique (nft compatible).
-- Exemple de migration vers nouveau style pour from_net.
-- @tparam string prop Propriété à matcher ("src_ip")
-- @tparam string net_cidr CIDR réseau
-- @treturn table Objet API enrichie
create_net_condition = (prop, net_cidr) ->
  {
    capabilities: { worker: true, nft_static: true, nft_dynamic: false }
    prop: prop
    net_cidr: net_cidr
    eval: (req) ->
      ip = req[prop]
      return false, "Missing #{prop}" unless ip
      { :Net } = require "filter.lib.ipcalc"
      net = Net net_cidr
      return false, "Invalid CIDR" unless net
      if net\contains ip
        true, "#{ip} in #{net_cidr}"
      else
        false, "#{ip} not in #{net_cidr}"
    compile_nft: (family) ->
      -- Retourne l'expression nft pour cette condition
      if family == "inet" or family == "ip"
        return "ip saddr #{net_cidr}", nil
      if family == "inet6" or family == "ip6"
        return "ip6 saddr #{net_cidr}", nil
      return nil, "unsupported family #{family}"
    creates_dynamic_scope: false
  }

--- Crée une action enrichie "allow".
-- @treturn table Objet API enrichie
create_allow_action = ->
  {
    capabilities: { worker: true, nft: true }
    worker_only: false
    eval: (req) -> true, "Allowed"
    compile_nft: -> "accept", nil
    verdict: -> "accept"
    creates_dynamic_scope: false
  }

--- Crée une action enrichie "deny".
-- @treturn table Objet API enrichie
create_deny_action = ->
  {
    capabilities: { worker: true, nft: true }
    worker_only: false
    eval: (req) -> false, "Denied"
    compile_nft: -> "drop", nil
    verdict: -> "drop"
    creates_dynamic_scope: false
  }

--- Crée une action enrichie "dnsonly".
-- Cette action ne crée pas d'injection nft (pas de scope dynamique).
-- @treturn table Objet API enrichie
create_dnsonly_action = ->
  {
    capabilities: { worker: true, nft: false }
    worker_only: true
    eval: (req) -> "dnsonly", "DNS only (no nft)"
    compile_nft: -> nil, "dnsonly requires worker"
    verdict: -> "dnsonly"
    creates_dynamic_scope: false
  }

{
  :is_new_style
  :load_condition
  :load_action
  :create_net_condition
  :create_allow_action
  :create_deny_action
  :create_dnsonly_action
}
