#!/bin/bash
set -e

VAGRANT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Setting up CustosVirginum E2E test environment ==="
echo ""

# Vérifier que libvirt est disponible
if ! command -v virsh &> /dev/null; then
    echo "ERROR: virsh not found. Please install libvirt."
    exit 1
fi

# Définir les réseaux à créer
NETWORKS=("custos-lan" "custos-up")

echo "Creating libvirt networks..."
for NET in "${NETWORKS[@]}"; do
    if virsh net-list --all | grep -q "^[[:space:]]*$NET[[:space:]]"; then
        echo "✓ Network '$NET' already exists"
    else
        echo "  Creating network '$NET'..."
        
        # Déterminer le subnet basé sur le nom du réseau
        if [ "$NET" = "custos-lan" ]; then
            SUBNET="192.168.1.0"
            GATEWAY="192.168.1.1"
            DHCP_START="192.168.1.100"
            DHCP_END="192.168.1.249"
        elif [ "$NET" = "custos-up" ]; then
            SUBNET="10.99.0.0"
            GATEWAY="10.99.0.1"
            DHCP_START="10.99.0.100"
            DHCP_END="10.99.0.249"
        fi
        
        # Créer le XML pour le réseau
        cat > "/tmp/${NET}-network.xml" << EOF
<network>
  <name>$NET</name>
  <forward mode='nat'>
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
  <bridge name='virbr-${NET}' stp='on' delay='0'/>
  <ip address='$GATEWAY' netmask='255.255.255.0'>
    <dhcp>
      <range start='$DHCP_START' end='$DHCP_END'/>
    </dhcp>
  </ip>
</network>
EOF
        
        virsh net-define "/tmp/${NET}-network.xml"
        virsh net-start "$NET" 2>/dev/null || true
        virsh net-autostart "$NET"
        echo "  ✓ Network '$NET' created"
    fi
done

echo ""
echo "Networks ready. Starting Vagrant..."
echo ""

# Lancer Vagrant
cd "$VAGRANT_DIR"
vagrant up "$@"

echo ""
echo "=== CustosVirginum E2E environment is ready! ==="
echo ""
echo "To access the VMs:"
echo "  vagrant ssh dns"
echo "  vagrant ssh filter"
echo "  vagrant ssh client"
echo ""
echo "To check network status:"
echo "  virsh net-list"
echo "  virsh net-dumpxml custos-lan"
echo "  virsh net-dumpxml custos-up"