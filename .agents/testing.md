# Tests

---

## Suites disponibles

| Commande | Prérequis | Description |
|----------|-----------|-------------|
| `make test` | aucun (pas de root) | Tests unitaires : compile `tests/unit/*_spec.moon` puis exécute Busted. Couvre parsing, `filter.rule`, `ipc`, `nft_queue`, `dns_ede` et les helpers de workers. |
| `make test-ndpi` | libndpi installée | Tests du wrapper nDPI et du dispatch de version. |
| `make test-openwrt HOST=root@<host>` | SSH + OpenWrt avec LuaJIT + nftables | Déploie les fichiers Lua + règles nft via `scp`, démarre les workers via `logger -t custos`, puis lance les vérifications DNS/auth depuis la machine locale. |
| `make test-e2e` | environnement VM démarré (`make test-env`) | Suite E2E complète via SSH (`FILTER_SSH=... CLIENT_SSH=... [CLIENT2_SSH=...]`). |
| `make test-e2e-ci` | idem | Idem, avec logs dans `tmp/test-e2e.log`. |
| `make test-kvm` | KVM disponible | Variante KVM de la suite E2E. |

---

## Pièges OpenWrt

### Logging sur OpenWrt

Les workers sont lancés avec `2>&1 | logger -t custos` (pas de fichier log).
Les vérifications utilisent `logread` (buffer circulaire syslog). Pour filtrer
les entrées de la session de test courante, insérer un marqueur dans syslog
avant de démarrer le démon :

```custos/.agents/testing.md#L1-1
ssh "logger -t custos '#{LOG_MARKER}'"
ssh "(cd #{CUSTOS_DIR} && luajit2 main.lua </dev/null 2>&1 | logger -t custos) &"
-- puis interroger :
ssh "logread | sed -n '/#{LOG_MARKER}/,$p' | grep queue_listening"
```

Les logs utiles pour valider l'architecture courante sont `questions_*`
(champ `rule` + `timeout`) et `response_*` (champ `nft_rule_id` +
`payload_modified`).

### `grep -c` vs `wc -l`

`grep -c` retourne le code de sortie 1 quand le compte est 0, ce qui fait
échouer l'appel SSH (`ok=false`). Utiliser `grep PATTERN | wc -l` (toujours
code 0) pour les vérifications de comptage.
