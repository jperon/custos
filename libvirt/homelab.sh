#!/usr/bin/env bash
# homelab.sh — orchestre le homelab libvirt 3 VMs OpenWrt pour tester custos
# bout-en-bout : servus → custos (bridge L2) → via (routeur) → internet.
#
# Sous-commandes :
#   ensure    télécharge image OpenWrt, prépare les qcow2, définit réseaux et VMs (idempotent)
#   start     démarre les 3 VMs, attend que SSH réponde sur mgmt
#   stop      arrêt propre (shutdown ACPI, puis destroy si trop long)
#   nuke      supprime VMs, réseaux, images dérivées (laisse l'image de base en cache)
#   ssh <vm>  ouvre une session SSH sur via | custos | servus
#   ip <vm>   imprime l'IP mgmt courante
#   redeploy  recompile MoonScript et pousse custos dans la VM custos
#   test      lance la suite E2E (résolution DNS via la chaîne, règles de filtrage)

set -e

export LIBVIRT_DEFAULT_URI="${LIBVIRT_DEFAULT_URI:-qemu:///system}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IMG_DIR="$SCRIPT_DIR/images"
LIBVIRT_IMG_DIR="/var/lib/libvirt/images"

OPENWRT_VERSION="${OPENWRT_VERSION:-25.12.4}"
OPENWRT_FILE="openwrt-${OPENWRT_VERSION}-x86-64-generic-ext4-combined.img.gz"
OPENWRT_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/x86/64/${OPENWRT_FILE}"
# SHA256 officiel (depuis sha256sums du miroir OpenWrt 25.12.4).
OPENWRT_SHA256="${OPENWRT_SHA256:-9d080bcae28d7cdf86dabb4b29c10d36d89e0bd79e20a4799454380bc1619695}"
BASE_IMG="$IMG_DIR/openwrt-${OPENWRT_VERSION}-base.img"

SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
[ -f "$SSH_KEY" ] || SSH_KEY="$HOME/.ssh/id_rsa"
SSH_PUBKEY_FILE="${SSH_KEY}.pub"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=5 -o BatchMode=yes -o LogLevel=ERROR"

VMS=(via custos servus cliens)

# MAC mgmt (NIC de gestion) par VM ; sert au lookup d'IP via les leases libvirt.
mac_mgmt() {
    case "$1" in
        via)    echo "52:54:00:fe:01:03" ;;
        custos) echo "52:54:00:fe:02:03" ;;
        servus) echo "52:54:00:fe:03:02" ;;
        cliens) echo "52:54:00:fe:04:02" ;;
        *) echo ""; return 1 ;;
    esac
}

domain_name() { echo "homelab-$1"; }

# ─── Helpers ──────────────────────────────────────────────────────

log()  { echo "[homelab] $*"; }
err()  { echo "[homelab] ERROR: $*" >&2; exit 1; }

virsh_has() { virsh dominfo "$1" &>/dev/null; }
net_has()   { virsh net-info "$1" &>/dev/null; }

need() { command -v "$1" >/dev/null 2>&1 || err "outil manquant : $1"; }

check_deps() {
    need virsh
    need qemu-img
    need guestfish
    need curl
    need ssh
    need scp
    [ -f "$SSH_PUBKEY_FILE" ] || err "clé publique SSH absente : $SSH_PUBKEY_FILE"
}

# ─── Image de base ────────────────────────────────────────────────

download_base() {
    mkdir -p "$IMG_DIR"
    if [ -f "$BASE_IMG" ]; then
        log "image de base déjà présente : $BASE_IMG"
        return
    fi
    log "téléchargement de $OPENWRT_FILE..."
    curl -fL "$OPENWRT_URL" -o "$IMG_DIR/$OPENWRT_FILE"
    if [ -n "$OPENWRT_SHA256" ]; then
        log "vérification SHA256..."
        actual=$(sha256sum "$IMG_DIR/$OPENWRT_FILE" | awk '{print $1}')
        if [ "$actual" != "$OPENWRT_SHA256" ]; then
            err "SHA256 mismatch : attendu $OPENWRT_SHA256, obtenu $actual"
        fi
    fi
    log "décompression..."
    gunzip -k "$IMG_DIR/$OPENWRT_FILE"
    mv "$IMG_DIR/${OPENWRT_FILE%.gz}" "$BASE_IMG"
    # OpenWrt génère une image de 256 Mo ; on agrandit pour disposer de place.
    qemu-img resize -f raw "$BASE_IMG" 1G
}

# ─── Réseaux libvirt ──────────────────────────────────────────────

ensure_network() {
    local name="$1" xml="$SCRIPT_DIR/networks/$1.xml"
    [ -f "$xml" ] || err "XML réseau absent : $xml"
    if ! net_has "$name"; then
        log "définition du réseau $name..."
        virsh net-define "$xml" >/dev/null
    fi
    virsh net-autostart "$name" >/dev/null 2>&1 || true
    virsh net-start     "$name" >/dev/null 2>&1 || true
}

# ─── Images VM ────────────────────────────────────────────────────

vm_qcow2() { echo "$LIBVIRT_IMG_DIR/homelab-$1.qcow2"; }

ensure_vm_image() {
    local vm="$1"
    local qcow2 ; qcow2=$(vm_qcow2 "$vm")
    # /var/lib/libvirt/images est généralement lisible par tous ; sinon, on
    # tombe en sudo -n (non-interactif) avant la création.
    if [ -f "$qcow2" ] || sudo -n test -f "$qcow2" 2>/dev/null; then
        log "image VM déjà présente : $qcow2"
        return
    fi
    log "création image qcow2 pour $vm (backing : $BASE_IMG)..."
    # On copie l'image de base plutôt que d'utiliser un backing read-only :
    # guestfish doit la modifier (uci-defaults), et un backing pointant sur
    # un chemin user serait inaccessible à libvirtd qui tourne en root.
    local tmp ; tmp=$(mktemp --suffix=.qcow2)
    qemu-img convert -f raw -O qcow2 "$BASE_IMG" "$tmp"
    qemu-img resize "$tmp" 1G

    log "injection uci-defaults dans $vm.qcow2..."
    local pubkey ; pubkey=$(cat "$SSH_PUBKEY_FILE")
    "$SCRIPT_DIR/inject.sh" "$tmp" "$SCRIPT_DIR/uci-defaults/$vm.sh" "$pubkey"

    sudo install -m 0644 -o root -g root "$tmp" "$qcow2"
    rm -f "$tmp"
}

# ─── Domaines libvirt ─────────────────────────────────────────────

ensure_domain() {
    local vm="$1"
    local dom ; dom=$(domain_name "$vm")
    local xml="$SCRIPT_DIR/domains/$vm.xml"
    [ -f "$xml" ] || err "XML domaine absent : $xml"
    if ! virsh_has "$dom"; then
        log "définition du domaine $dom..."
        virsh define "$xml" >/dev/null
    fi
}

# ─── IP discovery ─────────────────────────────────────────────────

vm_ip() {
    local vm="$1"
    local mac ; mac=$(mac_mgmt "$vm") || err "VM inconnue : $vm"
    local ip
    ip=$(virsh net-dhcp-leases homelab-mgmt 2>/dev/null \
         | awk -v m="$mac" '$0 ~ m {split($5,a,"/"); print a[1]; exit}')
    if [ -z "$ip" ]; then
        ip=$(ip neigh show 2>/dev/null \
             | awk -v m="$mac" '$0 ~ m {print $1; exit}')
    fi
    echo "$ip"
}

wait_ssh() {
    local vm="$1" tries=0 max=60 ip
    log "attente SSH sur $vm..."
    while [ $tries -lt $max ]; do
        ip=$(vm_ip "$vm")
        if [ -n "$ip" ] && ssh $SSH_OPTS -i "$SSH_KEY" "root@$ip" true 2>/dev/null; then
            log "$vm joignable : $ip"
            return 0
        fi
        sleep 2
        tries=$((tries + 1))
    done
    err "timeout SSH sur $vm"
}

# ─── Commandes ────────────────────────────────────────────────────

cmd_ensure() {
    check_deps
    download_base
    for net in homelab-wan homelab-up homelab-lan homelab-mgmt homelab-ext-up homelab-ext-dn; do
        ensure_network "$net"
    done
    for vm in "${VMS[@]}"; do
        ensure_vm_image "$vm"
        ensure_domain "$vm"
    done
    log "ensure ok."
}

cmd_start() {
    for vm in "${VMS[@]}"; do
        local dom ; dom=$(domain_name "$vm")
        virsh_has "$dom" || err "domaine $dom non défini ; lance 'ensure' d'abord"
        if ! virsh domstate "$dom" 2>/dev/null | grep -q running; then
            log "démarrage de $dom..."
            virsh start "$dom" >/dev/null
        fi
    done
    for vm in "${VMS[@]}"; do
        wait_ssh "$vm"
    done
    log "homelab opérationnel."
    for vm in "${VMS[@]}"; do
        printf "  %-8s %s\n" "$vm" "$(vm_ip "$vm")"
    done
}

cmd_stop() {
    for vm in "${VMS[@]}"; do
        local dom ; dom=$(domain_name "$vm")
        virsh_has "$dom" || continue
        if virsh domstate "$dom" 2>/dev/null | grep -q running; then
            log "shutdown $dom..."
            virsh shutdown "$dom" >/dev/null 2>&1 || true
        fi
    done
    # Laisse 20 s pour shutdown propre, puis destroy ce qui reste.
    sleep 20
    for vm in "${VMS[@]}"; do
        local dom ; dom=$(domain_name "$vm")
        virsh_has "$dom" || continue
        if virsh domstate "$dom" 2>/dev/null | grep -q running; then
            virsh destroy "$dom" >/dev/null 2>&1 || true
        fi
    done
}

cmd_nuke() {
    cmd_stop || true
    for vm in "${VMS[@]}"; do
        local dom ; dom=$(domain_name "$vm")
        virsh_has "$dom" && virsh undefine "$dom" >/dev/null 2>&1 || true
        local qcow2 ; qcow2=$(vm_qcow2 "$vm")
        sudo rm -f "$qcow2"
    done
    for net in homelab-wan homelab-up homelab-lan homelab-mgmt homelab-ext-up homelab-ext-dn; do
        if net_has "$net"; then
            virsh net-destroy  "$net" >/dev/null 2>&1 || true
            virsh net-undefine "$net" >/dev/null 2>&1 || true
        fi
    done
    log "nuke terminé (image de base conservée dans $IMG_DIR)"
}

cmd_ssh() {
    local vm="$1" ; shift || true
    local ip ; ip=$(vm_ip "$vm")
    [ -n "$ip" ] || err "IP de $vm introuvable"
    exec ssh $SSH_OPTS -i "$SSH_KEY" "root@$ip" "$@"
}

cmd_ip() {
    local ip ; ip=$(vm_ip "$1")
    [ -n "$ip" ] && echo "$ip" || err "IP de $1 introuvable"
}

cmd_redeploy() {
    log "compilation MoonScript..."
    (cd "$PROJECT_DIR" && make -s)
    local ip ; ip=$(vm_ip custos)
    [ -n "$ip" ] || err "IP de custos introuvable"
    log "push custos vers $ip..."
    (cd "$PROJECT_DIR" && luajit install-owrt.lua "$ip" --no-build)
}

cmd_test_unit() {
    local ip ; ip=$(vm_ip custos)
    [ -n "$ip" ] || err "IP de custos introuvable"

    log "compilation des specs..."
    (cd "$PROJECT_DIR" && make -s compile-specs)

    # Bootstrap : installe luajit sur la VM si absent (idempotent).
    # Sur OpenWrt 25.12 le binaire s'appelle luajit2 ; on crée un symlink.
    ssh $SSH_OPTS -i "$SSH_KEY" "root@$ip" '
        need_install=""
        command -v luajit >/dev/null 2>&1 || need_install="$need_install luajit"
        luajit -e "require \"lyaml\"" 2>/dev/null   || need_install="$need_install lyaml"
        [ -e /usr/lib/libwolfssl.so ] || need_install="$need_install libuhttpd-wolfssl"
        command -v px5g >/dev/null 2>&1  || need_install="$need_install px5g"
        if [ -n "$need_install" ]; then
            apk update >/dev/null 2>&1
            apk add $need_install >/dev/null
            [ -e /usr/bin/luajit ] || ln -s luajit2 /usr/bin/luajit
            # libuhttpd-wolfssl installe libwolfssl.so.<version> mais pas le lien générique.
            if [ ! -e /usr/lib/libwolfssl.so ]; then
                v=$(ls /usr/lib/libwolfssl.so.* 2>/dev/null | sort -V | tail -1)
                [ -n "$v" ] && ln -sf "$(basename "$v")" /usr/lib/libwolfssl.so
            fi
        fi'

    log "push lua/ + tests/ vers custos..."
    local remote_dir="/root/custos-tests"
    ssh $SSH_OPTS -i "$SSH_KEY" "root@$ip" "rm -rf $remote_dir && mkdir -p $remote_dir"
    # OpenWrt n'a pas sftp-server : scp -O force le protocole legacy.
    # rsync absent par défaut : on packe en tar.gz côté hôte, on dépacke côté VM.
    local tarball ; tarball=$(mktemp --suffix=.tar.gz)
    trap "rm -f $tarball" RETURN
    (cd "$PROJECT_DIR" && tar czf "$tarball" lua tests)
    scp -O $SSH_OPTS -i "$SSH_KEY" -q "$tarball" "root@$ip:$remote_dir/payload.tar.gz"
    ssh $SSH_OPTS -i "$SSH_KEY" "root@$ip" \
        "cd $remote_dir && tar xzf payload.tar.gz && rm payload.tar.gz"

    log "exécution des tests unitaires sur custos..."
    ssh $SSH_OPTS -i "$SSH_KEY" "root@$ip" \
        "cd $remote_dir && luajit tests/run_vm_tests.lua"
}

cmd_test() {
    log "test E2E : résolution DNS de bout en bout..."
    local ssh_via=( ssh $SSH_OPTS -i "$SSH_KEY" "root@$(vm_ip via)" )
    local ssh_servus=( ssh $SSH_OPTS -i "$SSH_KEY" "root@$(vm_ip servus)" )

    log "1. via résout site-a.lan en local"
    "${ssh_via[@]}" 'nslookup site-a.lan 127.0.0.1' \
        | grep -q '10.42.0.50' || err "via ne résout pas site-a.lan"

    log "2. servus a reçu une IP via DHCP (à travers custos)"
    "${ssh_servus[@]}" 'ip -4 -o addr show eth0 | grep -q "inet "' \
        || err "servus n'a pas d'IP sur eth0"

    log "3. servus résout site-a.lan via la chaîne servus → custos → via"
    "${ssh_servus[@]}" 'nslookup site-a.lan' \
        | grep -q '10.42.0.50' || err "servus ne résout pas site-a.lan"

    log "tests E2E ok."
}

cmd_test_e2e() {
    # Vérifier que toutes les VMs sont définies et démarrées avant tout.
    for _vm in "${VMS[@]}"; do
        local _dom ; _dom=$(domain_name "$_vm")
        virsh_has "$_dom" \
            || err "VM $_dom non définie — lance '$0 ensure' puis '$0 start' d'abord"
        virsh domstate "$_dom" 2>/dev/null | grep -q running \
            || err "VM $_dom non démarrée — lance '$0 start' d'abord"
    done

    local ip_custos ip_servus ip_cliens ip_via
    ip_custos=$(vm_ip custos)  ; [ -n "$ip_custos" ]  || err "IP de custos introuvable (DHCP en attente ?)"
    ip_servus=$(vm_ip servus)  ; [ -n "$ip_servus" ]  || err "IP de servus introuvable (DHCP en attente ?)"
    ip_cliens=$(vm_ip cliens)  ; [ -n "$ip_cliens" ]  || err "IP de cliens introuvable (DHCP en attente ?)"
    ip_via=$(vm_ip via)        ; [ -n "$ip_via" ]      || err "IP de via introuvable (DHCP en attente ?)"

    log "déploiement config E2E sur custos..."
    scp -O $SSH_OPTS -i "$SSH_KEY" \
        "$SCRIPT_DIR/homelab-e2e.moon" "root@$ip_custos:/etc/custos/config.moon"
    ssh $SSH_OPTS -i "$SSH_KEY" "root@$ip_custos" \
        '/etc/init.d/custos restart 2>/dev/null; sleep 3'

    log "bootstrap outils de test (idempotent)..."
    for vm_name in servus cliens; do
        local _ip ; _ip=$(vm_ip "$vm_name")
        ssh $SSH_OPTS -i "$SSH_KEY" "root@$_ip" \
            'command -v dig >/dev/null || { apk update -q 2>/dev/null; apk add -q bind-dig 2>/dev/null; }' || true
    done

    log "bootstrap certificat TLS sur custos (idempotent)..."
    ssh $SSH_OPTS -i "$SSH_KEY" "root@$ip_custos" '
        [ -f /etc/custos/cert.pem ] || {
            mkdir -p /etc/custos
            px5g selfsigned -days 3650 -newkey ec \
                -keyout /etc/custos/key.pem \
                -out /etc/custos/cert.pem \
                -subj "/CN=custos.lan" 2>/dev/null
        }
        [ -f /etc/custos/sessions.lua ] || echo "{}" > /etc/custos/sessions.lua' || true

    log "exécution de la suite E2E..."
    export SSH_OPTS SSH_KEY PROJECT_DIR SCRIPT_DIR
    export E2E_IP_CUSTOS="$ip_custos" E2E_IP_SERVUS="$ip_servus"
    export E2E_IP_CLIENS="$ip_cliens" E2E_IP_VIA="$ip_via"
    bash "$PROJECT_DIR/tests/e2e/homelab_e2e.sh"
    local rc=$?

    log "restauration config minimale (homelab-test.moon)..."
    scp -O $SSH_OPTS -i "$SSH_KEY" \
        "$SCRIPT_DIR/homelab-test.moon" "root@$ip_custos:/etc/custos/config.moon"
    ssh $SSH_OPTS -i "$SSH_KEY" "root@$ip_custos" \
        '/etc/init.d/custos restart 2>/dev/null; sleep 2' || true

    return $rc
}

# ─── Dispatch ─────────────────────────────────────────────────────

case "${1:-}" in
    ensure)   shift; cmd_ensure   "$@" ;;
    start)    shift; cmd_start    "$@" ;;
    stop)     shift; cmd_stop     "$@" ;;
    nuke)     shift; cmd_nuke     "$@" ;;
    ssh)      shift; cmd_ssh      "$@" ;;
    ip)       shift; cmd_ip       "$@" ;;
    redeploy) shift; cmd_redeploy "$@" ;;
    test)      shift; cmd_test      "$@" ;;
    test-unit) shift; cmd_test_unit "$@" ;;
    test-e2e)  shift; cmd_test_e2e  "$@" ;;
    *)
        cat >&2 <<EOF
Usage : $0 <ensure|start|stop|nuke|ssh|ip|redeploy|test|test-unit|test-e2e> [args]
EOF
        exit 2
        ;;
esac
