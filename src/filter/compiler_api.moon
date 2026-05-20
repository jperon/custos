-- src/filter/compiler_api.moon
-- API interne pour la compilation multi-backend des conditions et actions.
--
-- Les modules conditions/actions peuvent exposer soit :
--   • Ancien style : une factory function `(cfg) -> (args) -> checker`
--   • Nouveau style : un objet/table avec :
--       - capabilities : table des backends supportés { worker, nft }
--       - eval         : fonction d'évaluation runtime (checker)
--       - compile_nft  : fonction de compilation nft (optionnel)
--       - creates_dynamic_scope : boolean (true si condition DNS)
--
-- Note: worker_only est DÉDUIT de capabilities.nft (pas de champ explicite)

--- Détecte si un objet est au nouveau style enrichi.
-- @tparam any obj Objet retourné par la factory après application cfg/args
-- @treturn boolean true si nouveau style (objet avec capabilities)
is_new_style = (obj) ->
  return false unless type(obj) == "table"
  return false unless obj.capabilities
  true

--- Déduit si une condition/action est worker-only de ses capabilities.
-- @tparam table obj Objet enrichi avec capabilities
-- @treturn boolean true si worker-only (pas de support nft)
compute_worker_only = (obj) ->
  return true unless type(obj) == "table"
  return true unless obj.capabilities
  return not obj.capabilities.nft

rule_id = require "filter.rule_id"

sanitize_ascii = rule_id.sanitize_ascii
sanitize_id    = rule_id.sanitize_id

rule_id_base = rule_id.generate

unique_rule_id = (rule, idx, used) ->
  base = rule_id_base rule, idx
  rid = base
  n = 1
  while used and used[rid]
    n += 1
    rid = "#{base}_#{n}"
  used[rid] = true if used
  rid

--- Lit un fichier texte ligne par ligne (ignore vides et commentaires #).
-- @tparam string filepath Chemin du fichier
-- @treturn table Liste des lignes valides
read_lines = (filepath) ->
  lines = {}
  f = io.open filepath, "r"
  return lines unless f
  for line in f\lines!
    line = line\match "^%s*(.-)%s*$"
    lines[#lines + 1] = line unless line == "" or line\sub(1, 1) == "#"
  f\close!
  lines

--- Enveloppe un module factory brut dans l'interface standard enrichie.
-- @tparam function factory_outer Factory brute du module (cfg) -> (args) -> result
-- @treturn function Factory enrichie (cfg) -> (args) -> enriched_obj
wrap_factory = (factory_outer) ->
  (cfg) ->
    (args) ->
      factory_inner = factory_outer cfg
      result = factory_inner args
      if is_new_style result
        result
      else
        {
          capabilities: { worker: true, nft: false }
          eval: result
          compile_nft: -> nil, "unsupported"
        }

--- Génère une condition plurielle (OR) depuis une condition de base.
-- @tparam function base_factory Factory enrichie (cfg) -> (args) -> enriched_obj
-- @treturn function Factory (cfg) -> (items) -> enriched_obj
make_plural = (base_factory) ->
  (cfg) ->
    (items) ->
      items = {items} unless type(items) == "table"
      conds = [base_factory(cfg)(item) for item in *items]

      all_nft = #conds > 0
      requires_auth = false
      for cond in *conds
        caps = cond.capabilities
        all_nft = false unless caps and caps.nft
        requires_auth = true if caps and caps.requires_auth

      -- Fusion en ensemble inline nft ("ip saddr { v1, v2, … }") quand toutes
      -- les sous-conditions partagent un même préfixe (left-side de l'expression).
      compile_nft_merged = nil
      if all_nft
        compile_nft_merged = (family) ->
          prefix = nil
          vals = {}
          has_failures = false
          for cond in *conds
            expr, _err = cond.compile_nft family
            if expr
              p, v = expr\match "^(.+ )([^ ]+)$"
              return nil, "unmergeable nft expr: #{expr}" unless p
              if prefix == nil
                prefix = p
              elseif prefix != p
                return nil, nil
              vals[#vals + 1] = v
            else
              has_failures = true
          -- Liste mixte IPv4/IPv6 sous "inet" : laisser match_exprs scinder par famille.
          return nil, nil if family == "inet" and has_failures and #vals > 0
          return nil, nil if #vals == 0
          if #vals == 1
            "#{prefix}#{vals[1]}", nil
          else
            "#{prefix}{ #{table.concat vals, ', '} }", nil

      {
        capabilities: { worker: true, nft: all_nft, nft_dynamic: false, :requires_auth }
        eval: (req) ->
          for cond in *conds
            ok, msg = cond.eval req
            return true, msg if ok
          false, "no match in plural condition"
        compile_nft: compile_nft_merged or (-> nil, "unsupported")
      }

--- Génère une condition depuis un fichier texte (1 item valide par ligne).
-- from_xxx_list "name" lit {lists_dir}/{type_name}/{name}.txt
-- @tparam function base_factory Factory enrichie (cfg) -> (args) -> enriched_obj
-- @tparam string type_name Sous-répertoire du type (ex: "net", "user")
-- @treturn function Factory (cfg) -> (list_name) -> enriched_obj
make_from_file = (base_factory, type_name) ->
  (cfg) ->
    (list_name) ->
      lists_dir = (cfg.lists_dir) or
                  (cfg.filter and cfg.filter.lists_dir) or
                  "/etc/custos/lists"
      filepath = "#{lists_dir}/#{type_name}/#{list_name}.txt"
      items = read_lines filepath
      make_plural(base_factory)(cfg)(items)

--- Génère une condition depuis plusieurs fichiers texte (OR sur les fichiers).
-- from_xxx_lists {"name1", "name2"} lit plusieurs fichiers et fait un OR.
-- @tparam function base_factory Factory enrichie (cfg) -> (args) -> enriched_obj
-- @tparam string type_name Sous-répertoire du type (ex: "net", "user")
-- @treturn function Factory (cfg) -> (names) -> enriched_obj
make_from_files = (base_factory, type_name) ->
  (cfg) ->
    (names) ->
      names = {names} unless type(names) == "table"
      file_factory = make_from_file(base_factory, type_name)(cfg)
      conds = [file_factory(name) for name in *names]
      {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) ->
          for cond in *conds
            ok, msg = cond.eval req
            return true, msg if ok
          false, "no match in any list file"
        compile_nft: -> nil, "unsupported"
      }

--- Charge un module condition avec adaptation automatique.
-- Si le module n'existe pas, tente d'auto-générer la variante depuis le module de base :
--   from_xxx_lists → make_from_files(from_xxx)
--   from_xxx_list  → make_from_file(from_xxx)
--   from_xxxs      → make_plural(from_xxx)
-- @tparam string name Nom du module (ex: "from_net")
-- @treturn function|nil Factory (cfg) -> (args) -> enriched_obj
load_condition = (name) ->
  -- 1. Chargement direct (les fichiers existants ont priorité)
  ok, factory_outer = pcall require, "filter.conditions.#{name}"
  if ok
    return wrap_factory factory_outer

  -- 2. Suffixe _lists : "from_net_lists" → base "from_net", type "net"
  base_name = name\match "^(.+)_lists$"
  if base_name
    type_name = base_name\match "^[^_]+_(.+)$"
    base_ok, base_mod = pcall require, "filter.conditions.#{base_name}"
    if base_ok and type_name
      return make_from_files (wrap_factory base_mod), type_name

  -- 3. Suffixe _list : "from_net_list" → base "from_net", type "net"
  base_name = name\match "^(.+)_list$"
  if base_name
    type_name = base_name\match "^[^_]+_(.+)$"
    base_ok, base_mod = pcall require, "filter.conditions.#{base_name}"
    if base_ok and type_name
      return make_from_file (wrap_factory base_mod), type_name

  -- 4. Suffixe s : "from_nets" → base "from_net"
  base_name = name\match "^(.+)s$"
  if base_name
    base_ok, base_mod = pcall require, "filter.conditions.#{base_name}"
    return make_plural (wrap_factory base_mod) if base_ok

  nil, "Condition '#{name}' not found"

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
    capabilities: { worker: true, nft: true, nft_dynamic: false }
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
  }

--- Crée une action enrichie "allow".
-- @treturn table Objet API enrichie
create_allow_action = ->
  {
    capabilities: { worker: true, nft: true }
    eval: (req) -> true, "Allowed"
    compile_nft: -> "accept", nil
    verdict: -> "accept"
  }

--- Crée une action enrichie "deny".
-- @treturn table Objet API enrichie
create_deny_action = ->
  {
    capabilities: { worker: true, nft: true }
    eval: (req) -> false, "Denied"
    compile_nft: -> "drop", nil
    verdict: -> "drop"
  }

--- Crée une action enrichie "dnsonly".
-- Cette action ne crée pas d'injection nft (pas de scope dynamique).
-- @treturn table Objet API enrichie
create_dnsonly_action = ->
  {
    capabilities: { worker: true, nft: false }
    eval: (req) -> "dnsonly", "DNS only (no nft)"
    verdict: -> "dnsonly"
    compile_nft: -> nil, "dnsonly is worker-only"
  }

{
  :is_new_style
  :compute_worker_only
  :sanitize_ascii
  :sanitize_id
  :rule_id_base
  :unique_rule_id
  :load_condition
  :load_action
  :create_net_condition
  :create_allow_action
  :create_deny_action
  :create_dnsonly_action
}
