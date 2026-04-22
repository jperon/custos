#!/bin/sh
# openwrt-uci-defaults.sh — exécuté une seule fois au premier boot.
# Prépare la VM filtre pour les tests E2E (pas d'installation custos ici,
# c'est `make test-e2e` qui s'en charge via install-owrt.lua).

# Désactive le pare-feu : on teste custos, pas OpenWrt fw. nftables reste
# disponible pour les règles custos.
/etc/init.d/firewall disable 2>/dev/null
/etc/init.d/firewall stop    2>/dev/null

# Autorise dropbear à écouter sur toutes les interfaces (LAN, mgmt).
uci set dropbear.@dropbear[0].Interface=''
uci set dropbear.@dropbear[0].Port='22'
uci set dropbear.@dropbear[0].PasswordAuth='off'
uci set dropbear.@dropbear[0].RootPasswordAuth='off'
uci commit dropbear

# Garantit que /etc/config/custos existe (sera réécrit par test-e2e).
[ -f /etc/config/custos ] || cat > /etc/config/custos <<'EOF'
config main 'main'
	option enabled '0'
EOF

# Redémarre dropbear avec la nouvelle config.
/etc/init.d/dropbear restart 2>/dev/null

exit 0
