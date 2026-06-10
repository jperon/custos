-- src/lib/packet_parsing.moon
-- Agrégateur des primitives de parsing L3/L4/L7 issues d'ipparse, partagées par
-- les workers NFQUEUE qui décodent un paquet (worker_questions, worker_responses).
-- Évite de répéter le même bloc de `require` (un par module ipparse) dans chaque
-- worker. Ne fait que ré-exporter ; aucune logique propre.

{ parse: parse_ip4 }            = require "ipparse.l3.ip4"
{ parse: parse_ip6 }            = require "ipparse.l3.ip6"
{ parse: parse_udp }            = require "ipparse.l4.udp"
{ parse: parse_tcp }            = require "ipparse.l4.tcp"
{ parse: parse_dns, :types }    = require "ipparse.l7.dns"
{ :ip2s }                       = require "ipparse.l3.ip"

{ :parse_ip4, :parse_ip6, :parse_udp, :parse_tcp, :parse_dns, :ip2s, dns_types: types }
