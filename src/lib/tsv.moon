-- src/lib/tsv.moon
-- Formatage des champs des lignes TSV écrites sur le pipe worker_events
-- (verdicts DNS, événements SNI, événements de blocage validateur).

--- Formate un champ TSV : valeur textuelle, ou "-" si nil/vide.
-- Le "-" est le marqueur de champ absent partagé par tous les producteurs
-- (webui : /admin/config/verdicts, /refusals).
-- @tparam any v Valeur à formater
-- @treturn string Valeur formatée pour TSV
tsv_field = (v) ->
  s = if v ~= nil then tostring v else ""
  if #s == 0 then "-" else s

{ :tsv_field }
