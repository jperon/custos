#!/bin/bash
set -e

echo "Modifying tests to run inside a KVM virtual machine..."

# Make sure we have a fresh SSH key to use for the VM
if [ ! -f ~/.ssh/id_rsa_vm ]; then
    ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa_vm
fi
PUB_KEY=$(cat ~/.ssh/id_rsa_vm.pub)

# Download the debian cloud image if we don't have it
if [ ! -f debian-12-generic-amd64.qcow2 ]; then
  wget -q https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2
fi

# Clean up any existing VM
virsh --connect qemu:///system destroy test-vm >/dev/null 2>&1 || true
virsh --connect qemu:///system undefine test-vm >/dev/null 2>&1 || true
sudo rm -f /tmp/test-vm.qcow2 /tmp/cidata.iso /tmp/user-data /tmp/meta-data /tmp/network-config

# Create a fresh copy in /tmp where qemu can read it
cp debian-12-generic-amd64.qcow2 /tmp/test-vm.qcow2
qemu-img resize /tmp/test-vm.qcow2 +5G

# Create a cloud-init ISO
cat > /tmp/user-data <<EOF
#cloud-config
users:
  - name: debian
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - "$PUB_KEY"
    groups: [sudo, docker]
    shell: /bin/bash
    lock_passwd: false
ssh_authorized_keys:
  - "$PUB_KEY"
chpasswd:
  list: |
    debian:password
    root:password
  expire: false
packages:
  - docker.io
  - docker-compose
  - make
  - gcc
  - luajit
  - lua5.3
  - lua5.3-dev
  - libnetfilter-queue-dev
  - libnftnl-dev
  - libmnl-dev
  - luarocks
  - rsync
runcmd:
  - luarocks install moonscript
  - systemctl start docker
  - systemctl enable docker
  - usermod -aG docker debian
EOF

cat > /tmp/meta-data <<EOF
instance-id: test-vm
local-hostname: test-vm
EOF

cat > /tmp/network-config <<EOF
network:
  version: 2
  ethernets:
    all-en:
      match:
        name: e*
      dhcp4: true
EOF

echo "Starting libvirt VM 'test-vm'..."
virt-install --connect qemu:///system \
  --name test-vm \
  --memory 2048 \
  --vcpus 2 \
  --disk /tmp/test-vm.qcow2,device=disk,bus=virtio \
  --os-variant debian12 \
  --network default \
  --graphics none \
  --cloud-init user-data=/tmp/user-data \
  --import \
  --noautoconsole >/dev/null

echo "Waiting for VM to boot and acquire an IP address..."
IP=""
max_tries=60
tries=0
while [ -z "$IP" ] && [ $tries -lt $max_tries ]; do
  sleep 2
  IP=$(virsh --connect qemu:///system domifaddr test-vm 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
  tries=$((tries+1))
done

if [ -z "$IP" ]; then
    echo "Failed to get VM IP address."
    exit 1
fi

echo "VM IP is $IP. Waiting for SSH to become ready and cloud-init to finish..."
SSH_CMD="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ~/.ssh/id_rsa_vm debian@$IP"

max_ssh_tries=30
ssh_tries=0
while ! $SSH_CMD 'echo SSH ready' >/dev/null 2>&1; do
  sleep 2
  ssh_tries=$((ssh_tries+1))
  if [ $ssh_tries -gt $max_ssh_tries ]; then
      echo "Timeout waiting for SSH."
      exit 1
  fi
done

echo "Waiting for cloud-init (this installs docker, luajit, moonscript, etc. and can take a minute)..."
$SSH_CMD 'cloud-init status --wait' >/dev/null 2>&1 || true

echo "Syncing code to the VM..."
rsync -aP -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ~/.ssh/id_rsa_vm" \
    --exclude '.git' \
    --exclude 'debian-12-nocloud-amd64.qcow2' \
    --exclude 'test-vm.qcow2' \
    --exclude 'cidata.iso' \
    . debian@$IP:~/custos/ >/dev/null

if [ "$TEST_VM" = "1" ]; then
    echo "Running tests in the isolated VM..."
    $SSH_CMD 'cd ~/custos && make test'
else
    echo "Running tests in the isolated VM..."
    $SSH_CMD 'cd ~/custos && make test'
fi
RESULT=$?

echo "Cleaning up..."
virsh --connect qemu:///system destroy test-vm >/dev/null 2>&1 || true
virsh --connect qemu:///system undefine test-vm >/dev/null 2>&1 || true
sudo rm -f /tmp/test-vm.qcow2 /tmp/cidata.iso /tmp/user-data /tmp/meta-data /tmp/network-config

if [ $RESULT -eq 0 ]; then
    echo "SUCCESS: Tests passed inside the VM!"
else
    echo "ERROR: Tests failed inside the VM."
    exit $RESULT
fi
