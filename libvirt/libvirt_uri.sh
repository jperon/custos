#!/usr/bin/env bash
# libvirt_uri.sh — décision pure de la connexion libvirt utilisée par homelab.sh.
#
# Ce fichier ne fait que définir des fonctions : il est sourcé par
# libvirt/homelab.sh et testé unitairement sans virsh réel
# (tests/unit/libvirt_uri_spec.moon).
#
# Contexte : `virsh` sans `-c` utilise la connexion par défaut de libvirt, qui
# est le plus souvent `qemu:///session`. Un homelab provisionné en
# `qemu:///system` (le cas courant, cf. libvirt/README.md) est alors invisible :
# `net-dhcp-leases` ne renvoie aucun bail, donc aucune IP, et l'attente SSH part
# en timeout. À l'inverse, un setup volontairement en `qemu:///session` (moins
# de droits, pas de sudo) ne doit pas être cassé par un hardcode `system`.
#
# Règle de sélection (dans l'ordre) :
#   1. `LIBVIRT_DEFAULT_URI` déjà défini par l'environnement → respecté tel quel.
#   2. `qemu:///system` joignable ET contient les domaines `homelab-*` → system.
#   3. `qemu:///session` joignable ET contient les domaines `homelab-*` → session.
#   4. Sinon → chaîne vide : `virsh` utilisera sa connexion par défaut.
#
# `libvirt_pick_uri` est volontairement pure (aucun appel virsh) : les sondes
# sont faites par l'appelant, qui passe les statuts 0 (domaines trouvés) ou 1.
#
# Usage :
#   source libvirt/libvirt_uri.sh
#   uri=$(libvirt_pick_uri "$existing" "$system_status" "$session_status")

# libvirt_pick_uri <existing_uri> <system_status> <session_status>
# Affiche l'URI à utiliser (chaîne vide = connexion libvirt par défaut).
libvirt_pick_uri() {
    local existing="${1:-}"
    local system_status="${2:-1}"
    local session_status="${3:-1}"

    # 1. L'environnement fait autorité : ne jamais l'écraser.
    if [ -n "$existing" ]; then
        printf '%s\n' "$existing"
        return 0
    fi

    # 2. Le homelab est visible en system : c'est la connexion à utiliser.
    if [ "$system_status" -eq 0 ]; then
        printf '%s\n' "qemu:///system"
        return 0
    fi

    # 3. Homelab visible en session (setup sans privilèges).
    if [ "$session_status" -eq 0 ]; then
        printf '%s\n' "qemu:///session"
        return 0
    fi

    # 4. Aucun homelab détecté (première installation) : laisser virsh choisir
    # sa connexion par défaut plutôt que d'imposer un hardcode.
    printf '\n'
}
