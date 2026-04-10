-- src/filter/conditions/from_maclist.moon
-- Condition : l'adresse MAC source appartient à une liste nommée (cfg.macs).
-- Analogue de from_netlist pour les adresses MAC.

(require "filter.conditions._match_maclist") "mac"
