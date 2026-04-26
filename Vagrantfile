# Vagrantfile corrigé pour CustosVirginum E2E tests
Vagrant.configure("2") do |config|
  config.vm.box_check_update = false
  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.vm.provider "libvirt" do |libvirt|
    libvirt.management_network_name = "vagrant-libvirt"
    libvirt.cpu_mode = "host-passthrough"
  end

  # =============================================
  # DÉCLARATION DES RÉSEAUX LIBVIRT (correction ici)
  # =============================================

  # Réseau custos-up : réseau "upstream" isolé (pas de NAT par défaut)
  # On désactive complètement le forwarding NAT car le DNS VM va gérer le DHCP
  config.vm.network "private_network",
    libvirt__network_name: "custos-up",
    libvirt__network_address: "10.99.0.0/24",
    libvirt__dhcp_enabled: false,
    libvirt__forward_mode: "none",     # ← Important : évite le NAT
    auto_config: false

  # Réseau custos-lan : réseau LAN derrière le filter (bridge)
  config.vm.network "private_network",
    libvirt__network_name: "custos-lan",
    libvirt__network_address: "192.168.1.0/24",
    libvirt__dhcp_enabled: false,
    libvirt__forward_mode: "none",     # ← Important aussi
    auto_config: false

  # =============================================
  # 1. DNS VM (doit être créée en premier)
  # =============================================
  config.vm.define "dns", primary: true do |dns|
    dns.vm.box = "cheretbe/openwrt-25"
    dns.vm.hostname = "custos-dns"

    dns.vm.network "private_network",
      type: "dhcp",
      libvirt__network_name: "custos-up",
      auto_config: false

    dns.vm.provider "libvirt" do |lv|
      lv.memory = 512
      lv.cpus = 1
      lv.nic_model_type = "virtio"
    end

    dns.vm.provision "shell", inline: <<-SHELL
      set -e
      echo "=== DNS VM Provisioning ==="

      INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo' | head -n1)
      echo "Interface détectée : $INTERFACE"

      uci revert network 2>/dev/null || true
      uci revert dhcp 2>/dev/null || true
      uci commit

      uci set network.$INTERFACE=interface
      uci set network.$INTERFACE.proto=static
      uci set network.$INTERFACE.ipaddr=10.99.0.1
      uci set network.$INTERFACE.netmask=255.255.255.0
      uci commit network

      uci set dhcp.$INTERFACE=dhcp
      uci set dhcp.$INTERFACE.interface=$INTERFACE
      uci set dhcp.$INTERFACE.start=100
      uci set dhcp.$INTERFACE.limit=150
      uci set dhcp.$INTERFACE.leasetime=12h
      uci commit dhcp

      /etc/init.d/network restart
      /etc/init.d/dnsmasq restart 2>/dev/null || true
      /etc/init.d/dnsmasq enable 2>/dev/null || true

      echo "✓ DNS prêt (10.99.0.1)"
      ip addr show $INTERFACE
    SHELL
  end

  # =============================================
  # 2. Filter VM
  # =============================================
  config.vm.define "filter" do |filter|
    filter.vm.box = "cheretbe/openwrt-25"
    filter.vm.hostname = "custos-filter"

    filter.vm.network "private_network",
      type: "dhcp",
      libvirt__network_name: "custos-lan",
      auto_config: false

    filter.vm.network "private_network",
      type: "dhcp",
      libvirt__network_name: "custos-up",
      auto_config: false

    filter.vm.provider "libvirt" do |lv|
      lv.memory = 1024
      lv.cpus = 2
      lv.nic_model_type = "virtio"
    end

    filter.vm.provision "shell", inline: <<-SHELL
      set -e
      echo "=== Filter VM Provisioning ==="

      INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo' | head -n2)
      ETH0=$(echo "$INTERFACES" | sed -n '1p')
      ETH1=$(echo "$INTERFACES" | sed -n '2p')

      echo "Bridge → $ETH0 + $ETH1"

      uci revert network 2>/dev/null || true
      uci revert firewall 2>/dev/null || true
      uci commit

      uci set network.br0=interface
      uci set network.br0.type=bridge
      uci set network.br0.proto=dhcp
      uci set network.br0.ifname="$ETH0 $ETH1"
      uci commit network

      uci set network.$ETH0=interface; uci set network.$ETH0.proto=none
      uci set network.$ETH1=interface; uci set network.$ETH1.proto=none
      uci commit network

      /etc/init.d/firewall stop 2>/dev/null || true
      /etc/init.d/firewall disable 2>/dev/null || true

      /etc/init.d/network restart

      echo "✓ Bridge br0 configuré"
      ip link show br0 || echo "br0 en cours de création..."
    SHELL
  end

  # =============================================
  # 3. Client VM
  # =============================================
  config.vm.define "client" do |client|
    client.vm.box = "debian/bullseye64"
    client.vm.hostname = "custos-client"

    client.vm.network "private_network",
      type: "dhcp",
      libvirt__network_name: "custos-lan"

    client.vm.provider "libvirt" do |lv|
      lv.memory = 512
      lv.cpus = 1
      lv.nic_model_type = "virtio"
    end

    client.vm.provision "shell", inline: <<-SHELL
      echo "=== Client VM ==="
      echo "Attente d'adresse IP sur custos-lan..."
      timeout 40 sh -c 'until ip addr show | grep -q "192.168.1."; do sleep 3; done' || true
      ip addr show
    SHELL
  end

  # Forcer l'ordre de création
  config.vm.define "dns"
  config.vm.define "filter", depends_on: { "dns" => true }
  config.vm.define "client", depends_on: { "filter" => true }
end
