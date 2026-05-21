#!/bin/sh
# via : routeur OpenWrt.
#   eth0 → homelab-wan     (DHCP, NAT vers internet par l'hôte)
#   eth1 → homelab-up      (LAN 10.42.0.1/24 + fd42:42:0:1::1/64, dnsmasq + DHCP serveur)
#   eth2 → homelab-mgmt    (DHCP, SSH depuis l'hôte)
#   eth3 → homelab-ext-up  (LAN 10.43.0.1/24 + fd42:42:0:2::1/64, 2ème pont custos)

uci -q delete network.wan
uci -q delete network.wan6
uci -q delete network.lan
uci -q delete network.lan6
while uci -q delete network.@device[0]; do :; done

uci set network.wan=interface
uci set network.wan.device='eth0'
uci set network.wan.proto='dhcp'

uci set network.lan=interface
uci set network.lan.device='eth1'
uci set network.lan.proto='static'
uci set network.lan.ipaddr='10.42.0.1'
uci set network.lan.netmask='255.255.255.0'
uci set network.lan.ip6addr='fd42:42:0:1::1/64'

uci set network.mgmt=interface
uci set network.mgmt.device='eth2'
uci set network.mgmt.proto='dhcp'
uci set network.mgmt.peerdns='0'
uci set network.mgmt.defaultroute='0'

# 2ème réseau LAN pour cliens (derrière le 2ème pont de custos)
uci set network.ext=interface
uci set network.ext.device='eth3'
uci set network.ext.proto='static'
uci set network.ext.ipaddr='10.43.0.1'
uci set network.ext.netmask='255.255.255.0'
uci set network.ext.ip6addr='fd42:42:0:2::1/64'

uci commit network

# DHCP + RA/DHCPv6 sur lan.
uci -q delete dhcp.lan
uci set dhcp.lan=dhcp
uci set dhcp.lan.interface='lan'
uci set dhcp.lan.start='100'
uci set dhcp.lan.limit='50'
uci set dhcp.lan.leasetime='1h'
uci set dhcp.lan.dhcpv6='server'
uci set dhcp.lan.ra='server'
uci set dhcp.lan.ra_slaac='1'

# DHCP + RA/DHCPv6 sur ext (2ème LAN).
uci -q delete dhcp.ext
uci set dhcp.ext=dhcp
uci set dhcp.ext.interface='ext'
uci set dhcp.ext.start='100'
uci set dhcp.ext.limit='50'
uci set dhcp.ext.leasetime='1h'
uci set dhcp.ext.dhcpv6='server'
uci set dhcp.ext.ra='server'
uci set dhcp.ext.ra_slaac='1'

# DHCP relais désactivé sur mgmt (l'hôte fournit déjà du DHCP côté NAT).
uci set dhcp.mgmt=dhcp
uci set dhcp.mgmt.interface='mgmt'
uci set dhcp.mgmt.ignore='1'

# Noms DNS de test : A (IPv4) et AAAA (IPv6) — IPv6 premier classe.
uci -q delete dhcp.@dnsmasq[0].address
uci add_list dhcp.@dnsmasq[0].address='/site-a.lan/fd42:42:0:1::50'
uci add_list dhcp.@dnsmasq[0].address='/site-a.lan/10.42.0.50'
uci add_list dhcp.@dnsmasq[0].address='/site-b.lan/fd42:42:0:1::51'
uci add_list dhcp.@dnsmasq[0].address='/site-b.lan/10.42.0.51'
uci add_list dhcp.@dnsmasq[0].address='/blocked.lan/fd42:42:0:1::52'
uci add_list dhcp.@dnsmasq[0].address='/blocked.lan/10.42.0.52'
uci add_list dhcp.@dnsmasq[0].address='/via.lan/fd42:42:0:1::1'
uci add_list dhcp.@dnsmasq[0].address='/via.lan/10.42.0.1'

uci commit dhcp

# Firewall : masquerade lan→wan, accepte SSH sur mgmt.
uci -q delete firewall.@zone[1]
uci -q delete firewall.@zone[0]

uci add firewall zone >/dev/null
uci set firewall.@zone[-1].name='lan'
uci set firewall.@zone[-1].network='lan ext mgmt'
uci set firewall.@zone[-1].input='ACCEPT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='ACCEPT'

uci add firewall zone >/dev/null
uci set firewall.@zone[-1].name='wan'
uci set firewall.@zone[-1].network='wan'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='REJECT'
uci set firewall.@zone[-1].masq='1'
uci set firewall.@zone[-1].mtu_fix='1'

uci -q delete firewall.@forwarding[0]
uci add firewall forwarding >/dev/null
uci set firewall.@forwarding[-1].src='lan'
uci set firewall.@forwarding[-1].dest='wan'

# DHCP statique pour le serveur DNS fictif site-a.lan (évite dépendance ARP).
# Pas de reservation MAC — via répond à toute requête DNS pour ces noms.

uci commit firewall

# Hostname
uci set system.@system[0].hostname='via'
uci commit system

# Dropbear : autorise root sans password (clé seulement).
uci set dropbear.@dropbear[0].PasswordAuth='off'
uci set dropbear.@dropbear[0].RootPasswordAuth='off'
uci commit dropbear

mkdir -p /etc/dropbear
cat > /etc/dropbear/authorized_keys <<'EOF'
__SSH_PUBKEY__
EOF
chmod 600 /etc/dropbear/authorized_keys

exit 0
