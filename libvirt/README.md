# Homelab libvirt — tests de bout en bout de custos

Trois VMs OpenWrt orchestrées par `homelab.sh` pour reproduire la topologie de
production en local :

```
            ┌─────────────┐  homelab-wan  ┌────────┐
  internet ─┤ host (NAT)  ├──────────────┤  via   │  OpenWrt routeur
            └─────────────┘   (libvirt)   │ wan    │
                                          │  lan ──┼─┐
                                          └────────┘ │  homelab-up
                                                     │  (L2 isolé)
                                                  ┌──┴──┐
                                                  │eth1 │
                                       custos ────│br-lan│  OpenWrt pont L2
                                                  │eth0 │
                                                  └──┬──┘  homelab-lan
                                                     │     (L2 isolé)
                                                ┌────┴───┐
                                                │ servus │  OpenWrt client
                                                └────────┘
```

`homelab-mgmt` est un quatrième réseau (NAT, DHCP libvirt) attaché en plus à
chaque VM pour SSH depuis l'hôte sans passer par la chaîne testée.

## Pré-requis

- libvirt + qemu-kvm (utilisateur dans le groupe `libvirt`)
- `qemu-img`, `virsh`, `curl`, `gunzip`
- `guestfish` (paquet `libguestfs-tools` Debian / `guestfs-tools` Arch ; fourni
  par le devShell Nix : `nix develop`)
- Clé SSH publique disponible (`~/.ssh/id_ed25519.pub` ou `~/.ssh/id_rsa.pub`)
- `sudo` pour installer les qcow2 dans `/var/lib/libvirt/images/`

## Usage

```bash
# 1. Préparation (1ère fois : ~3 min, télécharge l'image OpenWrt)
./libvirt/homelab.sh ensure

# 2. Démarrage et attente SSH sur les 3 VMs
./libvirt/homelab.sh start

# 3. Déploiement de custos sur la VM custos
./libvirt/homelab.sh redeploy

# 4. Pousse la config de test et redémarre custos
scp -i ~/.ssh/id_ed25519 libvirt/homelab-test.moon \
    root@$(./libvirt/homelab.sh ip custos):/etc/custos/config.moon
./libvirt/homelab.sh ssh custos '/etc/init.d/custos restart'

# 5. Tests E2E
./libvirt/homelab.sh test

# 6. Sessions interactives au besoin
./libvirt/homelab.sh ssh via       # routeur
./libvirt/homelab.sh ssh custos    # pont/filtre
./libvirt/homelab.sh ssh servus    # client
```

## Tests unitaires dans la VM custos

Pour exécuter tous les specs unitaires dans la VM `custos` (utile quand
l'environnement local n'a pas busted ou les bonnes versions de Lua) :

```bash
./libvirt/homelab.sh test-unit          # ou : make test-vm
```

La commande :
1. Recompile localement les `*_spec.moon` → `.lua`.
2. Installe `luajit` et `lyaml` dans la VM si absents (apk, idempotent).
3. Copie `lua/` et `tests/` dans `/root/custos-tests/` via tar+scp.
4. Exécute `tests/run_vm_tests.lua`, un runner Busted-compatible minimal en
   pur Lua (`tests/helpers/mini_busted.lua`). Aucun rock externe requis,
   busted n'étant pas packagé pour OpenWrt.

Le runner couvre l'API Busted utilisée par les specs :
`describe / it / before_each / after_each / setup / pending` et
`assert.equals / same / truthy / is_* / has_error / has_no.errors / match /
not_equals`.

## Boucle de dev

Modification de code MoonScript → recompilation + push :

```bash
./libvirt/homelab.sh redeploy
```

Pour redéfinir les règles de filtrage, éditer `libvirt/homelab-test.moon` puis
`scp` + restart comme à l'étape 4.

## Topologie réseau détaillée

| Réseau         | Bridge hôte    | Mode      | DHCP    | CIDR              | Rôle |
|----------------|----------------|-----------|---------|-------------------|------|
| `homelab-wan`  | `hl-wan-br`    | NAT       | libvirt | 192.168.250.0/24  | via→internet |
| `homelab-up`   | `hl-up-br`     | isolé L2  | aucun   | (servi par via)   | via↔custos |
| `homelab-lan`  | `hl-lan-br`    | isolé L2  | aucun   | (relayé via custos)| custos↔servus |
| `homelab-mgmt` | `hl-mgmt-br`   | NAT       | libvirt | 192.168.251.0/24  | SSH depuis hôte |

Côté OpenWrt :

| VM     | eth0           | eth1         | eth2          |
|--------|----------------|--------------|---------------|
| via    | wan (DHCP)     | lan static 10.42.0.1/24 + DHCP serveur + dnsmasq | mgmt (DHCP) |
| custos | esclave br-lan | esclave br-lan | mgmt (DHCP) |
| servus | wan (DHCP)     | mgmt (DHCP)  | —             |

Noms DNS définis sur via (`uci-defaults/via.sh`) :
- `via.lan` → 10.42.0.1
- `site-a.lan` → 10.42.0.50
- `site-b.lan` → 10.42.0.51
- `blocked.lan` → 10.42.0.52

## Dépannage

### libvirtd ne démarre pas les réseaux

```bash
virsh net-list --all
# si "homelab-wan" est en "inactive" :
sudo virsh net-start homelab-wan
```

NetworkManager peut interférer avec les bridges libvirt. Si les VMs n'ont pas
de connectivité, vérifier qu'aucun `nm-connection` n'a pris la main sur les
bridges `hl-*-br`.

### Une VM ne reçoit pas d'IP sur mgmt

```bash
virsh net-dhcp-leases homelab-mgmt
# si vide :
sudo virsh net-destroy homelab-mgmt && sudo virsh net-start homelab-mgmt
```

### SSH refuse la clé

`uci-defaults/<vm>.sh` substitue `__SSH_PUBKEY__` à partir du fichier pubkey
détecté (`SSH_KEY=...`). Vérifier que la bonne clé est utilisée :
```bash
SSH_KEY=~/.ssh/ma_cle ./libvirt/homelab.sh ensure  # ré-injecte
```

### custos ne voit pas les frames DHCP

Le filtrage L2 nécessite que la VM `custos` reçoive toutes les frames du
segment, sans flou MAC. Vérifier que le mode de bridge libvirt préserve les
MACs sources :

```bash
./libvirt/homelab.sh ssh custos 'tcpdump -i br-lan -e -n -c 10 port 67 or port 68'
```

Le `ether src` doit être la MAC de servus (`52:54:00:fe:03:01`), pas celle du
bridge libvirt.

### libguestfs manquant

```
homelab.sh: outil manquant : guestfish
```

Solutions :
- `nix develop` (fournit `pkgs.libguestfs`)
- Debian : `sudo apt install libguestfs-tools`
- Arch : `sudo pacman -S guestfs-tools`

Sur certaines distros, `/boot/vmlinuz-*` doit être lisible par l'utilisateur :
```bash
sudo chmod 0644 /boot/vmlinuz-*
```

## Nettoyage

```bash
./libvirt/homelab.sh stop    # arrêt propre
./libvirt/homelab.sh nuke    # supprime VMs, réseaux, qcow2 dérivés
```

L'image de base décompressée reste dans `libvirt/images/` (réutilisable).
