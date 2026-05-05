# Vagrantfile refondu pour CustosVirginum E2E tests
# Topologie : 3 VMs Debian (dns, filter, client) sur réseaux libvirt isolés.
# Le filtre fait un pont transparent L2 entre custos-lan et custos-up.
Vagrant.configure("2") do |config|
  config.vm.box_check_update = false
  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.vm.provider "libvirt" do |libvirt|
    libvirt.management_network_name = "vagrant-libvirt"
    libvirt.cpu_mode = "host-passthrough"
  end

  # =============================================
  # Réseaux libvirt isolés (forward none)
  # =============================================

  # custos-lan : côté client (segment L2 isolé)
  config.vm.network "private_network",
    libvirt__network_name: "custos-lan",
    libvirt__network_address: "10.99.0.0/24",
    libvirt__dhcp_enabled: false,
    libvirt__forward_mode: "none",
    auto_config: false

  # custos-up : côté DNS / upstream (segment L2 isolé)
  config.vm.network "private_network",
    libvirt__network_name: "custos-up",
    libvirt__network_address: "10.99.0.0/24",
    libvirt__dhcp_enabled: false,
    libvirt__forward_mode: "none",
    auto_config: false

  # =============================================
  # 1. DNS VM
  # =============================================
  config.vm.define "dns", primary: true do |dns|
    dns.vm.box = "debian/bullseye64"
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

      INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE 'lo|virbr' | sed -n '2p')
      [ -z "$INTERFACE" ] && INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo' | head -n1)
      echo "Interface détectée : $INTERFACE"

      apt-get update -qq
      apt-get install -y -qq dnsmasq curl

      cat > /etc/dnsmasq.d/custos-dns.conf <<EOF
interface=$INTERFACE
bind-interfaces
listen-address=10.99.0.1
no-dhcp-interface=$INTERFACE
address=/allowed.test/10.99.0.50
address=/blocked.test/10.99.0.51
address=/tracker.test/10.99.0.52
EOF

      cat > /etc/network/interfaces.d/$INTERFACE <<EOF
auto $INTERFACE
iface $INTERFACE inet static
    address 10.99.0.1/24
EOF

      ip addr flush dev $INTERFACE 2>/dev/null || true
      ip addr add 10.99.0.1/24 dev $INTERFACE
      ip link set $INTERFACE up

      systemctl restart dnsmasq
      systemctl enable dnsmasq

      echo "✓ DNS prêt (10.99.0.1)"
      ip addr show $INTERFACE
    SHELL
  end

  # =============================================
  # 2. Filter VM
  # =============================================
  config.vm.define "filter" do |filter|
    filter.vm.box = "debian/bullseye64"
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

      INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE 'lo|virbr' | sed -n '2,3p')
      ETH0=$(echo "$INTERFACES" | sed -n '1p')
      ETH1=$(echo "$INTERFACES" | sed -n '2p')
      [ -z "$ETH0" ] && ETH0=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo' | sed -n '2p')
      [ -z "$ETH1" ] && ETH1=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo' | sed -n '3p')

      echo "Bridge → $ETH0 + $ETH1"

      apt-get update -qq
      apt-get install -y -qq curl nftables luajit libnetfilter-queue1 libnftables1 \
        lua-socket lua-sec lua-yaml bridge-utils build-essential autoconf libtool

      # Compilation de wolfssl (nécessaire pour le portail captif TLS)
      if [ ! -f /usr/lib/x86_64-linux-gnu/libwolfssl.so ]; then
        echo "  Compilation de wolfssl..."
        cd /tmp
        curl -sL https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.6-stable.tar.gz | tar -xz
        cd wolfssl-5.7.6-stable
        ./autogen.sh >/dev/null 2>&1 || true
        ./configure --enable-all --prefix=/usr >/dev/null
        make -j$(nproc) >/dev/null
        make install >/dev/null
        ldconfig
      fi

      # Création du bridge
      ip link add br0 type bridge || true
      ip link set $ETH0 master br0
      ip link set $ETH1 master br0
      ip link set $ETH0 up
      ip link set $ETH1 up
      ip link set br0 up
      ip addr flush dev br0 2>/dev/null || true
      ip addr add 10.99.0.254/24 dev br0

      # Désactiver le forwarding IP (mode pont pur L2)
      sysctl -w net.ipv4.ip_forward=0
      sysctl -w net.ipv6.conf.all.forwarding=0

      # S'assurer que nftables est actif
      systemctl enable nftables || true
      systemctl start nftables || true

      echo "✓ Bridge br0 configuré (10.99.0.254)"
      ip link show br0
      ip addr show br0
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
      libvirt__network_name: "custos-lan",
      auto_config: false

    client.vm.provider "libvirt" do |lv|
      lv.memory = 512
      lv.cpus = 1
      lv.nic_model_type = "virtio"
    end

    client.vm.provision "shell", inline: <<-SHELL
      set -e
      echo "=== Client VM ==="

      INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE 'lo|virbr' | sed -n '2p')
      [ -z "$INTERFACE" ] && INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo' | head -n1)
      echo "Interface détectée : $INTERFACE"

      apt-get update -qq
      apt-get install -y -qq curl dnsutils

      cat > /etc/network/interfaces.d/$INTERFACE <<EOF
auto $INTERFACE
iface $INTERFACE inet static
    address 10.99.0.10/24
    gateway 10.99.0.254
    dns-nameservers 10.99.0.1
EOF

      ip addr flush dev $INTERFACE 2>/dev/null || true
      ip addr add 10.99.0.10/24 dev $INTERFACE
      ip link set $INTERFACE up

      echo "✓ Client prêt (10.99.0.10)"
      ip addr show $INTERFACE
    SHELL
  end

  # Forcer l'ordre de création
  config.vm.define "dns"
  config.vm.define "filter", depends_on: { "dns" => true }
  config.vm.define "client", depends_on: { "filter" => true }
end
