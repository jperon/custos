#!/bin/sh
# cliens : 2ème client OpenWrt derrière le 2ème pont de custos.
#   eth0 → homelab-ext-dn (DHCP, reçu de via à travers br-ext de custos, 10.43.0.0/24)
#   eth1 → homelab-mgmt (DHCP, SSH depuis l'hôte)

uci -q delete network.wan
uci -q delete network.wan6
uci -q delete network.lan
uci -q delete network.lan6
while uci -q delete network.@device[0]; do :; done

# Le réseau de "production" (à travers custos) est servi en DHCP par via.
uci set network.wan=interface
uci set network.wan.device='eth0'
uci set network.wan.proto='dhcp'

# mgmt : SSH depuis l'hôte.
uci set network.mgmt=interface
uci set network.mgmt.device='eth1'
uci set network.mgmt.proto='dhcp'
uci set network.mgmt.peerdns='0'
uci set network.mgmt.defaultroute='0'

uci commit network

# Firewall et dnsmasq désactivés : machine de test pure.
/etc/init.d/firewall disable 2>/dev/null
/etc/init.d/firewall stop    2>/dev/null

/etc/init.d/dnsmasq disable 2>/dev/null
/etc/init.d/dnsmasq stop    2>/dev/null

# Hostname
uci set system.@system[0].hostname='cliens'
uci commit system

# Dropbear : root par clé uniquement.
uci set dropbear.@dropbear[0].PasswordAuth='off'
uci set dropbear.@dropbear[0].RootPasswordAuth='off'
uci commit dropbear

mkdir -p /etc/dropbear
cat > /etc/dropbear/authorized_keys <<'EOF'
__SSH_PUBKEY__
EOF
chmod 600 /etc/dropbear/authorized_keys

exit 0
