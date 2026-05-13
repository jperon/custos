# Bilan de la Migration - CustosVirginum NFT Rules

## Date: 2026-05-13

---

## 1. Vue d'ensemble

**Migration 100% terminée** - Tous les modules legacy ont été supprimés et remplacés par l'API enrichie multi-backend.

---

## 2. Modules Conditions Migrés (24 modules)

### ✅ NFT-Compatibles (nft_static: true)

| Module | Worker | NFT | Expression générée |
|--------|--------|-----|-------------------|
| `from_vlan` | ✅ | ✅ | `vlan id <id>` |
| `from_vlans` | ✅ | ✅ | `vlan id { <id1>, <id2>, ... }` |
| `from_vlanlist` | ✅ | ✅ | `vlan id @<set>` |
| `from_net` | ✅ | ✅ | `ip saddr <cidr>` / `ip6 saddr <cidr>` |
| `from_nets` | ✅ | ✅ | `ip saddr { <cidr1>, <cidr2> }` |
| `from_netlist` | ✅ | ✅ | `ip saddr @<set>` |
| `from_subnet` | ✅ | ✅ | `ip saddr <cidr>` |
| `from_mac` | ✅ | ✅ | `ether saddr <mac>` |
| `from_macs` | ✅ | ✅ | `ether saddr { <mac1>, <mac2> }` |
| `from_maclist` | ✅ | ✅ | `ether saddr @<set>` |
| `stolen_computer` | ✅ | ✅ | `ether saddr { <mac1>, <mac2> }` |

### 🔒 Worker-Only (worker_only: true)

| Module | Raison |
|--------|--------|
| `from_vlanlists` | Multiple VLAN lists - complexe en NFT |
| `from_netlists` | Multiple netlists - complexe en NFT |
| `from_maclists` | Multiple MAC lists - complexe en NFT |
| `from_user` | Sessions dynamiques (fichier ou TLS via `source` param) |
| `from_users` | Sessions dynamiques |
| `from_userlist` | Sessions dynamiques |
| `from_userlists` | Sessions dynamiques |
| `in_time` | Time-based - nécessite worker |
| `in_times` | Time-based - nécessite worker |
| `in_timelist` | Time-based - nécessite worker |
| `in_timelists` | Time-based - nécessite worker |
| `to_domain` | DNS matching - nécessite NFQUEUE |
| `to_domains` | DNS matching - nécessite NFQUEUE |
| `to_domainlist` | DNS hash lookup - nécessite NFQUEUE |
| `to_domainlists` | DNS hash lookup - nécessite NFQUEUE |

---

## 3. Modules Actions Migrés (3 modules)

| Module | Worker | NFT | Verdict |
|--------|--------|-----|---------|
| `allow` | ✅ | ✅ | `accept` |
| `deny` | ✅ | ✅ | `drop` |
| `dnsonly` | ✅ | ❌ | worker-only |

---

## 4. Modules Legacy Supprimés (9 modules)

Les modules abstraits `_match_*` ont été supprimés:
- ❌ `_match_int.moon`
- ❌ `_match_intlist.moon`
- ❌ `_match_intlists.moon`
- ❌ `_match_mac.moon`
- ❌ `_match_maclist.moon`
- ❌ `_match_maclists.moon`
- ❌ `_match_net.moon`
- ❌ `_match_netlist.moon`
- ❌ `_match_netlists.moon`

---

## 5. Architecture API Enrichie

Tous les modules retournent maintenant un objet avec:

```moonscript
{
  capabilities: {
    worker: true        -- Supporte le worker
    nft_static: true     -- Supporte NFT statique
    nft_dynamic: false  -- Supporte NFT dynamique
  }
  worker_only: false     -- Fallback worker si true
  creates_dynamic_scope: false  -- Crée un scope DNS si true
  eval: (req) -> ...    -- Fonction d'évaluation runtime
  compile_nft: (family) -> ...  -- Génère expression NFT
}
```

---

## 6. Core Modules Modifiés

| Module | Changements |
|--------|-------------|
| `filter/compiler_api.moon` | ✅ Créé - Détection auto ancien/nouveau style |
| `filter/rule.moon` | ✅ Modifié - Utilise compiler_api |
| `filter/nft_compiler.moon` | ✅ Modifié - Supporte compile_nft() des conditions |
| `filter/nft_rules.moon` | ✅ Modifié - Intègre métadonnées enrichies |
| `nft_queue.moon` | ✅ Modifié - Noms sets dynamiques corrigés |
| `filter/nft_dynamic_sets.moon` | ✅ Modifié - Sets par règle mac4/mac6 |

---

## 7. Tests Créés (10 fichiers)

| Test | Description |
|------|-------------|
| `compiler_api_spec.moon` | Tests de l'API multi-backend |
| `actions_enriched_spec.moon` | Tests des actions migrées |
| `rule_simple_spec.moon` | Tests de rétrocompatibilité |
| `conditions_enriched_spec.moon` | Tests des conditions de base |
| `nft_compiler_enriched_spec.moon` | Tests compilation NFT avec métadonnées |
| `deny_rules_spec.moon` | Tests des règles deny |
| `compile_metrics_spec.moon` | Tests des métriques |
| `all_conditions_migration_spec.moon` | Tests de toutes les conditions |
| `filter_nft_integration_spec.moon` | Test E2E complet |
| `migration_complete_spec.moon` | ✅ Test final de migration |

---

## 8. Fonctionnalités Clés

### Sets Dynamiques par Règle
```
rule_<id>_ip4   (ipv4_addr . ipv4_addr, timeout)
rule_<id>_ip6   (ipv6_addr . ipv6_addr, timeout)
rule_<id>_mac4  (ether_addr . ipv4_addr, timeout)
rule_<id>_mac6  (ether_addr . ipv6_addr, timeout)
```

### Compilation NFT avec Métadonnées
- `compile_conditions_nft()` - Compile les conditions enrichies
- `compile_action_nft()` - Extrait le verdict de l'action
- `match_exprs()` - Utilise métadonnées quand disponibles

### Métriques de Compilation
```lua
{
  total_rules = N
  nft_compilable = X
  worker_only = Y
  conditions_compiled = A
  conditions_worker_only = B
}
```

---

## 9. Rétrocompatibilité

✅ **Maintenue** - L'adaptateur dans `compiler_api.moon` détecte automatiquement:
- Nouveau style: objet avec `capabilities`
- Ancien style: fonction checker → wrappe automatiquement

---

## 10. Statut Final

| Élément | Statut |
|---------|--------|
| Tous modules conditions migrés | ✅ 24/24 |
| Tous modules actions migrés | ✅ 3/3 |
| Modules legacy supprimés | ✅ 9/9 |
| Tests passants | ✅ 10/10 |
| Documentation API | ✅ Complète |
| Rétrocompatibilité | ✅ Maintenue |

---

## 11. Consolidation des Modules

- `from_authenticated_user.moon` → fusionné dans `from_user` avec paramètre `source: "tls"`
- API unifiée: `from_user "alice"` (fichier) ou `from_user { user: "alice", source: "tls" }`

---

**Migration 100% complète. Aucun code legacy ne subsiste.**
