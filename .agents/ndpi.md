# nDPI — Intégration Pure FFI

Le projet utilise **libndpi** pour l'inspection applicative, chargée à
l'exécution via `ffi.load "ndpi"` — **pas de bridge C, pas d'étape de
compilation** au-delà de MoonScript.

---

## Architecture

| Fichier | Rôle |
|---------|------|
| `src/ffi_ndpi.moon` | Façade : charge libndpi, détecte la version via `ndpi_revision()`, dispatch vers v4 ou v5 |
| `src/ffi_ndpi_v4.moon` | `ffi.cdef` pour nDPI 4.2–4.8 (5 ou 6 args `process_packet`) |
| `src/ffi_ndpi_v5.moon` | `ffi.cdef` pour nDPI 5.0+ (`ndpi_protocol` opaque, pas de bitmask2) |
| `src/parse/ndpi.moon` | Façade partagée L3/L4/L7 + dispatch vers le backend |
| `src/parse/ndpi_v4.moon` | Backend nDPI 4.2–4.8 (init avec bitmask, detect, cleanup) |
| `src/parse/ndpi_v5.moon` | Backend nDPI 5.0+ (sans bitmask, accesseurs pour les IDs de protocole) |
| `tests/test_ndpi.moon` | Tests unitaires (`make test-ndpi`) |

> **Note :** les parsers de couche par couche (L2/L3/L4/L7) sont fournis par
> la bibliothèque `src/ipparse/` et restent utilisés directement par certains
> workers (ex. `worker_responses` utilise `ipparse.l7.dns`).

---

## Tolérance de version

La version est détectée une fois au chargement depuis `ndpi_revision()` :

```
ffi_ndpi.moon → ndpi_revision() → major >= 5 ?
                   ├── oui → ffi_ndpi_v5 cdef + parse.ndpi_v5
                   └── non → ffi_ndpi_v4 cdef + parse.ndpi_v4
                                └── minor >= 6 ? → 5 ou 6 args
```

| Versions | Différences gérées |
|----------|--------------------|
| 4.2–4.4 | `ndpi_detection_process_packet` à 5 args |
| 4.6–4.8 | 6 args (ajout `ndpi_flow_input_info*`) ; `bitmask2` retourne `int` |
| 5.0+ | `ndpi_init_detection_module(ndpi_global_context*)` ; pas de `NDPI_PROTOCOL_BITMASK` ; `ndpi_protocol` redessiné (lire via `ndpi_get_flow_masterprotocol`/`ndpi_get_flow_appprotocol`) |

---

## Patterns FFI utilisés

### Allocation de struct opaque

`ndpi_flow_struct` a une taille dépendant des options de compilation.
Allouer dynamiquement :

```custos/.agents/ndpi.md#L1-1
flow_size = ndpi_lib.ndpi_detection_get_sizeof_ndpi_flow_struct!
flow_buf  = ffi.new "uint8_t[?]", flow_size
-- Zéroïser et caster avant chaque usage :
ffi.fill flow_buf, flow_size, 0
flow = ffi.cast "ndpi_flow_struct*", flow_buf
```

### Bitmask (v4 uniquement)

`NDPI_PROTOCOL_BITMASK` est `{ uint32_t fds_bits[16] }` (64 octets, 512 bits).
Absent en nDPI 5.0 (tous les protocoles activés par défaut) :

```custos/.agents/ndpi.md#L1-1
bitmask = ffi.new "NDPI_PROTOCOL_BITMASK"
ffi.fill bitmask, ffi.sizeof(bitmask), 0xFF
ndpi_lib.ndpi_set_protocol_detection_bitmask2 ctx, bitmask
```

### Type de retour opaque (v5)

nDPI 5.0 déclare `ndpi_protocol` comme blob opaque de 128 octets, puis lit les
IDs via des accesseurs :

```custos/.agents/ndpi.md#L1-1
-- ffi_ndpi_v5 : typedef struct { uint8_t _opaque[128]; } ndpi_protocol;
ndpi_lib.ndpi_detection_process_packet ctx, flow, p, len, 0ULL, nil
master = tonumber ndpi_lib.ndpi_get_flow_masterprotocol ctx, flow
app    = tonumber ndpi_lib.ndpi_get_flow_appprotocol ctx, flow
```

### Arithmétique de pointeurs pour le parsing

Caster les strings Lua en `const uint8_t*` et utiliser la bibliothèque `bit`
pour les lectures big-endian (JIT-compilable, pas d'appel C) :

```custos/.agents/ndpi.md#L1-1
r16 = (p, o) ->
  bit.bor bit.lshift(p[o], 8), p[o + 1]

p = ffi.cast "const uint8_t*", raw
src_port = r16 p, udp_off
```

### Contexte singleton

Le module de détection nDPI est initialisé une seule fois et réutilisé.
Le `flow_struct` est pré-alloué et mis à zéro avant chaque paquet.

---

## Détection de protocole

nDPI retourne deux IDs de protocole par paquet :
- `master_protocol` — niveau transport (ex. `5` = DNS)
- `app_protocol` — niveau applicatif (ex. `203` = Github)

---

## API exportée (`src/parse/ndpi.moon`)

| Fonction | Description |
|----------|-------------|
| `parse_packet(raw)` | Parse L3+L4+L7 + détection nDPI → table ou nil |
| `parse_answers(raw, pkt)` | RRs de réponse DNS → tableau d'enregistrements |
| `patch_and_checksum(raw, pkt, answers, ttl)` | Réécriture TTL + recalcul checksum → string |
| `extract_dns_payload(raw, pkt)` | Extrait le payload DNS d'un paquet UDP ou TCP → string |
| `patch_ttl_in_dns(dns_str, answers, new_ttl)` | Réécriture des TTLs dans une string DNS → string |
| `replace_dns_payload(raw, pkt, new_dns)` | Reconstruit le paquet IP avec un nouveau payload DNS (taille variable) → string |
| `cleanup()` | Libère le contexte nDPI |
