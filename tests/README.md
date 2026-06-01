# Tests — CustosVirginum

## Arborescence

```
tests/
  unit/                       ← specs Busted (runner principal)
    auth/
      cert_cache_spec.moon    cert, cache LRU/TTL
      cert_generator_spec.moon  génération px5g
      cert_spec.moon          charge / génère certificats TLS
      credentials_spec.moon   PBKDF2, hash, vérification
      html_spec.moon          portail captif HTML
      sessions_spec.moon      sérialise, charge, purge, lookup
      sni_extractor_spec.moon parse ClientHello TLS SNI
    ffi/
      ffi_defs_spec.moon      disponibilité des fonctions FFI
    filter/
      allowlist_spec.moon     correspondance par suffixe DNS
      convert_spec.moon       CLI convert.lua : hash 48 bits + tri binaire
      lib/bin48_spec.moon     format .bin 48 bits (pack/rec_at/bsearch)
      filter_spec.moon        ipcalc, conditions (domain/mac/net/
                              user/vlan/time), règles, actions, parse_domains,
                              load_config, first_match_wins
    ipc/
      ipc_spec.moon           encode/decode IPv4/IPv6, make_key, drain_pipe,
                              refused/dnsonly, reason, rule_id, timeout, expiry
      nft_queue_spec.moon     cmd_for, ligne IPC avec rule_id + timeout
      worker_responses_spec.moon rr_timeout, EDE conditionnel
    parse/
      mac_learner_spec.moon   mac_from_eui64, get_mac (fallback EUI-64)
      packet_spec.moon        parse_packet UDP/TCP/IPv6+ext, patch_and_checksum,
                              extract/patch/replace DNS payload
  helpers/
    busted_setup.lua          stubs globaux (ffi_defs, config, log, ethernet)
  test_ffi_socket.moon        FFI socket (luajit direct, hors Busted)
  test_ffi_wolfssl.moon       FFI WolfSSL (luajit direct)
  test_ffi_integration.moon   tests d'intégration socket+SSL
  test_openwrt.moon           E2E via SSH sur routeur OpenWrt
  test_e2e.moon               E2E libvirt (3 VMs)
```

---

## Commandes rapides

```bash
# Tous les tests locaux (Busted + FFI, sans root)
make test

# Specs Busted uniquement
make test-unit

# Couverture luacov → tmp/coverage/luacov.report.out
make coverage

# Tests FFI hors-Busted (socket, WolfSSL, intégration)
make test-ffi

# E2E via SSH OpenWrt
make test-openwrt HOST=root@<routeur>

# E2E KVM (environnement libvirt 3 VMs)
make test-env        # crée/démarre les VMs (~5 min la première fois)
make test-kvm        # exécute la suite E2E
make test-env-down   # arrête les VMs
make test-env-nuke   # supprime tout
```

---

## Specs Busted — détail

### Résultat courant

Le nombre de succès varie selon les binaires installés. Un `pending` peut rester
sur la génération px5g si l'outil n'est pas disponible.

### Lancer un sous-ensemble

```bash
# Toutes les specs auth
PATH="$HOME/.luarocks/bin:$PATH" \
LUA_PATH="$HOME/.luarocks/share/lua/5.1/?.lua;$HOME/.luarocks/share/lua/5.1/?/init.lua;lua/?.lua;lua/?/init.lua;;" \
LUA_CPATH="$HOME/.luarocks/lib/lua/5.1/?.so;;" \
busted --lua=luajit --loaders=lua --helper=tests/helpers/busted_setup.lua \
  tests/unit/auth/

# Un seul spec
busted --lua=luajit --loaders=lua --helper=tests/helpers/busted_setup.lua \
  tests/unit/ipc/ipc_spec.lua

# Pipeline IPC/NFT (rule_id + timeout)
busted --lua=luajit --loaders=lua --helper=tests/helpers/busted_setup.lua \
  tests/unit/nft_queue_spec.lua tests/unit/worker_responses_spec.lua
```

### Stubs injectés par `busted_setup.lua`

Le helper est chargé automatiquement via `.busted` (clé `helper`). Il injecte :

| `package.loaded` | Contenu |
|---|---|
| `ffi_defs` | stub vide (pas de `ffi.cdef` global) |
| `config`   | constantes réseau (PROTO_TCP/UDP, AF_INET/6, DNS_PORT, …) |
| `log`      | nop (toutes les fonctions no-op) |
| `parse/ethernet` | stub pass-through |

---

## Couverture

```bash
make coverage
# → tmp/coverage/luacov.report.out
```

Seul le code sous `lua/` est mesuré. Les stubs FFI bas-niveau
(`ffi_defs`, `ffi_xxhash`, `auth/ffi_*`) sont exclus car
ils nécessitent les bibliothèques natives pour être exercés.

---


Tests : parsing L3/L4/L7, décompression DNS, patch TTL + recalcul checksum,
détection de version (4.x vs 5.x).

---

## Tests E2E OpenWrt via SSH

```bash
make test-openwrt HOST=root@<routeur>
```

Prérequis : accès SSH, LuaJIT + nftables installés sur le routeur.

---

## Tests E2E KVM (libvirt)

Environnement 3 VMs : client Debian, filtre OpenWrt, serveur DNS Debian.

```bash
make test-env    # premier démarrage
make test-kvm    # suite exhaustive
```

Prérequis : `qemu-kvm`, `libvirt-daemon-system`, `virsh`, `genisoimage`,
~2 Go d'espace disque, accès sudo.

Voir `libvirt/README.md` pour la documentation complète.
