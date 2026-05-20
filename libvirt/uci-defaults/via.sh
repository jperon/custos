#!/bin/sh
# via : routeur OpenWrt.
#   eth0 → homelab-wan (DHCP, NAT vers internet par l'hôte)
#   eth1 → homelab-up  (LAN 10.42.0.1/24, dnsmasq + DHCP serveur)
#   eth2 → homelab-mgmt (DHCP, SSH depuis l'hôte)

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

uci set network.mgmt=interface
uci set network.mgmt.device='eth2'
uci set network.mgmt.proto='dhcp'
uci set network.mgmt.peerdns='0'
uci set network.mgmt.defaultroute='0'

uci commit network

# DHCP serveur sur lan, noms DNS de test pour les essais custos.
uci -q delete dhcp.lan
uci set dhcp.lan=dhcp
uci set dhcp.lan.interface='lan'
uci set dhcp.lan.start='100'
uci set dhcp.lan.limit='50'
uci set dhcp.lan.leasetime='1h'

# DHCP relais désactivé sur mgmt (l'hôte fournit déjà du DHCP côté NAT).
uci set dhcp.mgmt=dhcp
uci set dhcp.mgmt.interface='mgmt'
uci set dhcp.mgmt.ignore='1'

uci -q delete dhcp.@dnsmasq[0].address
uci add_list dhcp.@dnsmasq[0].address='/site-a.lan/10.42.0.50'
uci add_list dhcp.@dnsmasq[0].address='/site-b.lan/10.42.0.51'
uci add_list dhcp.@dnsmasq[0].address='/blocked.lan/10.42.0.52'
uci add_list dhcp.@dnsmasq[0].address='/via.lan/10.42.0.1'

uci commit dhcp

# Firewall : masquerade lan→wan, accepte SSH sur mgmt.
uci -q delete firewall.@zone[1]
uci -q delete firewall.@zone[0]

uci add firewall zone >/dev/null
uci set firewall.@zone[-1].name='lan'
uci set firewall.@zone[-1].network='lan mgmt'
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
