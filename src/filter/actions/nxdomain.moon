-- src/filter/actions/nxdomain.moon
-- Action : bloquer la requête avec réponse NXDOMAIN (rcode 3).
-- Utile pour les canary domains (ex: use-application-dns.net)
-- qui exigent NXDOMAIN plutôt que REFUSED pour avoir l'effet attendu.

(require "ipc").register_modifier "nxdomain"

_schema = {
  label:       "NXDOMAIN"
  description: "Bloque la requête DNS (réponse NXDOMAIN, sans enregistrement synthétique)"
  arg_type:    nil
}

_factory = (cfg) ->
  (rule) ->
    {
      capabilities:    { worker: true, nft: true }
      block_modifiers: { nxdomain: true }
      eval: (req) ->
        false, "Denied by rule: #{rule.description or '?'}"
      compile_nft: ->
        "drop", nil
      verdict: ->
        "drop"
    }

{ schema: _schema, factory: _factory }
