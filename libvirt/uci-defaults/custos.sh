#!/bin/sh
# custos : pont L2 transparent.
#   eth0 + eth1 → esclaves de br-lan (sans IP, proto='none')
#   eth2       → homelab-mgmt (DHCP, SSH depuis l'hôte)
# Le filtrage nftables est installé séparément par homelab.sh redeploy.

uci -q delete network.wan
uci -q delete network.wan6
uci -q delete network.lan
uci -q delete network.lan6
while uci -q delete network.@device[0]; do :; done

# Définit le device pont br-lan agrégeant eth0 + eth1.
uci add network device >/dev/null
uci set network.@device[-1].name='br-lan'
uci set network.@device[-1].type='bridge'
uci add_list network.@device[-1].ports='eth0'
uci add_list network.@device[-1].ports='eth1'

# Interface br-lan sans IP (pont pur).
uci set network.lan=interface
uci set network.lan.device='br-lan'
uci set network.lan.proto='none'

# mgmt : SSH depuis l'hôte.
uci set network.mgmt=interface
uci set network.mgmt.device='eth2'
uci set network.mgmt.proto='dhcp'
# mgmt = unique sortie internet de custos (br-lan n'a pas d'IP) : on garde
# DNS et default route fournis par libvirt.

uci commit network

# Pas de DHCP serveur, pas de dnsmasq actif côté lan/mgmt :
# custos n'a pas vocation à servir DHCP/DNS, juste à filtrer.
/etc/init.d/dnsmasq disable 2>/dev/null
/etc/init.d/dnsmasq stop    2>/dev/null

# Firewall OpenWrt désactivé : custos pose ses propres règles en family bridge.
/etc/init.d/firewall disable 2>/dev/null
/etc/init.d/firewall stop    2>/dev/null

# Hostname
uci set system.@system[0].hostname='custos'
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
