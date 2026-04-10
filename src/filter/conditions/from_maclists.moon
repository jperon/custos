-- src/filter/conditions/from_maclists.moon
-- Condition : l'adresse MAC source appartient à l'une des listes nommées (cfg.macs).
-- Analogue de from_netlists pour les adresses MAC.

(require "filter.conditions._match_maclists") "mac"
