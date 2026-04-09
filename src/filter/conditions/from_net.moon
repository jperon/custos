-- src/filter/conditions/from_net.moon
-- Condition : l'adresse IP source appartient au réseau CIDR configuré.
-- Port direct de shelterfilter conditions/from_net.moon.

(require "filter.conditions._match_net") "src_ip"
