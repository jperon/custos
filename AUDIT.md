# Audit CustosVirginum — Plan d'action

Généré le 6 avril 2026. Cases à cocher pour le suivi d'avancement.

---

## A. Bugs de correctness

**A1. EINTR brise la boucle NFQUEUE** — [src/nfq_loop.moon](src/nfq_loop.moon#L82-L84)

La branche `rv < 0` breake inconditionnellement. Importer `errno` via `ffi.C.__errno_location` (Linux), tester `errno == 4` (EINTR) pour `continue` au lieu de `break`.

- [x] Déclarer `errno` dans `src/ffi_defs.moon`
- [x] Dans `nfq_loop.moon` L82–84 : `if errno == EINTR then continue else break`
- [x] Vérifier que `SIGHUP` ne tue plus le worker (`make test-docker`)

---

**A2. PID figé avant fork** — [src/log.moon](src/log.moon#L30)

`pid = tonumber ffi.C.getpid()` est évalué au chargement (avant `fork()`). Tous les workers héritent du PID du superviseur.

- [x] Dans `write_log` L45 : remplacer `pid` capturé par `tonumber(ffi.C.getpid())` inline
- [x] Supprimer la variable module-level `pid`
- [x] Vérifier dans les logs docker que Q0 et Q1 émettent des PIDs distincts

---

**A3. Double déclaration `fcntl`** — [src/ffi_defs.moon](src/ffi_defs.moon#L26) et [L43](src/ffi_defs.moon#L43)

Deux signatures incompatibles dans le même `ffi.cdef` : variadic L26 et `long arg` L43.

- [x] Supprimer la déclaration variadic L26 (`int fcntl(int fd, int cmd, ...)`)
- [x] Conserver uniquement L43 (`int fcntl(int fd, int cmd, long arg)`)
- [x] Mettre à jour le commentaire associé
- [x] `make` sans erreur

---

**A4. IPC race sur paquets multi-questions** — [src/worker_q0.moon](src/worker_q0.moon#L80-L96)

`write_msg` est appelé sur les questions autorisées avant que le verdict global ne soit connu. Si le verdict final est `NF_DROP`, des tokens IPC orphelins sont créés (valides pendant `IPC_PENDING_TTL` = 5 s).

- [x] Accumuler les questions autorisées dans un tableau local `to_write` pendant la boucle
- [x] N'appeler `write_msg` qu'après la boucle, uniquement si `verdict == NF_ACCEPT`
- [x] Ajouter un test unitaire pour le cas mixte allow/block dans un même paquet

---

**A5. Bypass IPC sur RCODE=REFUSED** — [src/worker_q1.moon](src/worker_q1.moon)

`rcode == RCODE.REFUSED → NF_ACCEPT` sans corrélation IPC. Un attaquant WAN peut injecter une réponse REFUSED forgée vers un client LAN et la faire accepter.

- [x] Ajouter dans [nft-rules/dns-filter.nft](nft-rules/dns-filter.nft) une règle excluant les paquets UDP/53 émis par l'adresse locale du filtre de la queue Q1
- [x] Retirer le bypass Lua `rcode == RCODE.REFUSED` dans `worker_q1.moon`
- [x] Vérifier que le test docker "blocked → REFUSED" passe toujours (`make test-docker`)

---

**A6. `sendto` silencieux** — [src/refuse.moon](src/refuse.moon#L92-L101)

La valeur de retour de `libc.sendto` est ignorée. Un envoi échoué (ENOBUFS, ENETUNREACH) est invisible dans les logs.

- [x] IPv4 L92–93 : capturer retour, si `< 0` appeler `log_warn { action:"sendto_failed", af:"ipv4", dst:... }`
- [x] IPv6 L100–101 : même traitement
- [x] `make test` sans régression

---

## B. Code mort

**B1. `LOG_FLUSH` mort** — [src/config.moon](src/config.moon#L19), [src/log.moon](src/log.moon#L9)

`LOG_FLUSH = true` est exporté et importé mais jamais utilisé (`fsync`/`fflush` absents de `log.moon`).

- [x] Supprimer `LOG_FLUSH` de l'export de `config.moon`
- [x] Supprimer l'import de `LOG_FLUSH` dans `log.moon`

---

**B2. `ndpi_get_proto_name` jamais appelé** — [src/ffi_ndpi_v4.moon](src/ffi_ndpi_v4.moon), [src/ffi_ndpi_v5.moon](src/ffi_ndpi_v5.moon)

Déclaré dans les deux fichiers FFI mais aucun appel dans le code.

- [x] Supprimer la déclaration dans `ffi_ndpi_v4.moon`
- [x] Supprimer la déclaration dans `ffi_ndpi_v5.moon`

---

## C. Tests

**C1. `eq()` unidirectionnel** — [tests/run_tests.lua](tests/run_tests.lua#L34-L42)

`eq(a, b)` vérifie les clés de `b` dans `a` mais pas l'inverse. Des champs supplémentaires dans `a` passent silencieusement.

- [x] Ajouter dans `eq()` : `for k in pairs(a) do if b[k] == nil then return false end end`
- [x] Re-jouer tous les tests existants

---

**C2. `patch_ttl` sans test unitaire** — [src/parse/dns.moon](src/parse/dns.moon)

La réécriture TTL n'a pas de test unitaire propre (seul `test_ndpi.lua` teste le chemin nDPI).

- [x] Construire une réponse DNS synthétique avec un RR A à TTL connu via `ffi.cast "uint8_t*"`
- [x] Appeler `patch_ttl` et vérifier les 4 octets TTL résultants

---

**C3. `parse_ipv6` sans test unitaire** — [src/parse/ip.moon](src/parse/ip.moon#L86-L109)

`parse_ipv4` est testé ; `parse_ipv6` ne l'est pas.

- [x] Ajouter `parse_ipv6 — paquet UDP minimal` : faux header IPv6 40 B (next_header=17) + payload UDP
- [x] Vérifier `ip_hdr.version == 6`, `ip_hdr.src_ip`, `ip_hdr.dst_ip`, `ip_hdr.ihl == 40`

---

**C4. Expiration IPC non testée** — [src/ipc.moon](src/ipc.moon)

Seul le happy path (token présent juste après write) est testé. La purge paresseuse et le rejet en cas d'expiration sont non couverts.

- [x] Ajouter test `ipc — token expiré rejeté` : écrire un message, forcer `pending[key] = 0`, appeler `is_pending` avec `now_fn = function() return 999999999 end` → doit retourner `false`

---

**C5. CLI flags ignorés dans test docker** — [tests/test_docker.moon](tests/test_docker.moon#L6)

`arg = { ... }` capture les varargs MoonScript (vide) au lieu du vrai `arg` global.

- [x] Remplacer `arg = { ... }` par `arg = (arg or {})` en ligne 6
- [x] Vérifier `moon tests/test_docker.moon --verbose`

---

**C6. TTL Docker test trompeur** — [tests/test_docker.moon](tests/test_docker.moon#L249-L254)

Le test "TTL is patched to 60s" vérifie uniquement que la résolution réussit, sans parser ni vérifier la valeur TTL.

- [x] Utiliser `dig +noall +answer` et extraire la valeur TTL avec une pattern Lua
- [x] Asserter `ttl == 60`

---

## D. Documentation

**D1. README — Flow bloqué incorrect** — [README.md](README.md#L82-L84)

Ligne 84 : `nft REJECT with icmp port-unreachable` ne correspond pas au code. Le filtre émet une réponse UDP REFUSED puis `NF_DROP`.

- [x] Remplacer L82–84 par le flux réel :
  ```
  worker Q0 : build_refused → refuse.send_refused → UDP REFUSED (EDE=15) → client
           └► NF_DROP → question packet discarded
  ```

---

**D2. README — nDPI présenté comme actif dans les workers** — [README.md](README.md#L8-L10) et [L31](README.md#L31)

`worker_q0` et `worker_q1` utilisent toujours les parsers per-layer, pas `parse/ndpi`.

- [x] L8–10 : préciser que `parse/ndpi` est disponible mais les workers actuels utilisent encore les parsers per-layer
- [x] Diagramme L31 : retirer "nDPI protocol detection" de la description Q0

---

**D3. `FORCED_TTL` non exposé dans config** — [src/worker_q1.moon](src/worker_q1.moon#L17)

`FORCED_TTL = 60` est une constante hardcodée dans `worker_q1.moon`, non rechargeable via SIGHUP.

- [x] Déplacer dans [src/config.moon](src/config.moon) et exporter
- [x] Mettre à jour l'import dans `worker_q1.moon`
- [x] Mettre à jour la section Config du README

---

**D4. LDoc manquant** — multiple fichiers

Fonctions publiques sans `@tparam`/`@treturn` :

- [x] `src/log.moon` : `write_log`, `log_allow`, `log_block`, `log_info`, `log_warn`, `log_error`, `now`
- [x] `src/allowlist.moon` : `build_index`, `is_allowed`, `check_reload`
- [x] `src/ipc.moon` : `encode_msg`, `decode_msg`, `write_msg`, `drain_pipe`, `is_pending`, `consume`
- [x] `src/nft.moon` : `add_ip4`, `add_ip6`, `add_ip`, `cleanup`
- [x] `src/parse/ip.moon` : `read_u8`, `read_u16`, `read_u32`, `format_ipv4`, `format_ipv6`
- [x] `src/parse/udp.moon` : `parse_udp`, `pseudo_header_sum_v4`
- [x] `src/parse/ethernet.moon` : `get_l2`, `format_mac`
- [x] `src/nfq_loop.moon` : `run_queue`
- [x] `src/parse/ndpi_v4.moon` : corriger `@treturn` de `init_ndpi` (retourne `flow_buf`, pas le contexte)
- [x] `src/parse/ndpi_v5.moon` : idem

---

## E. Intégration parse/ndpi dans les workers

Remplacer les parsers per-layer (`parse/ip` + `parse/udp` + `parse/dns`) par `parse/ndpi` dans les deux workers. Résout aussi la divergence de format IPv6 (`format_ipv6` non-canonique vs `inet_ntop`).

**E1. Déplacer `inet_ntop` dans ffi_defs** — [src/ffi_ndpi.moon](src/ffi_ndpi.moon), [src/ffi_defs.moon](src/ffi_defs.moon)

- [x] Ajouter `char* inet_ntop(int af, const void *src, char *dst, unsigned int size)` dans le `ffi.cdef` de `ffi_defs.moon`
- [x] Retirer la déclaration de `ffi_ndpi.moon`
- [x] `make test` sans erreur

---

**E2. `nfq_loop.moon` — bind IPv6** — [src/nfq_loop.moon](src/nfq_loop.moon#L36)

`nfq_bind_pf` n'est appelé qu'avec `AF_INET`.

- [x] Ajouter `libnfq.nfq_bind_pf h, AF_INET6` après le bind IPv4 L36

---

**E3. worker_q0 — migration parse/ndpi** — [src/worker_q0.moon](src/worker_q0.moon)

- [ ] Remplacer les imports `parse/ip`, `parse/udp`, `parse/dns` par `ndpi = require "parse/ndpi"`
- [ ] Remplacer `parse_ip` + `parse_udp` + `parse_dns` par `ndpi.parse_packet(raw)` → `pkt.ip`, `pkt.udp`, `pkt.dns`, `pkt.questions`
- [ ] Ajouter `ndpi_master` et `ndpi_app` dans `q_fields` pour les logs
- [ ] Appeler `ndpi.cleanup()` dans `run()` on exit
- [ ] `make test-docker` : vérifier les champs `ndpi_master`/`ndpi_app` dans les logs

> Non démarré.

---

**E4. worker_q1 — migration parse/ndpi** — [src/worker_q1.moon](src/worker_q1.moon)

- [x] Remplacer les imports legacy par `ndpi = require "parse/ndpi"`
- [x] Remplacer `parse_ip` + `parse_udp` + `parse_dns` par `ndpi.parse_packet`
- [x] Remplacer `parse_answers` par `ndpi.parse_answers`
- [x] Remplacer `patch_packet` (~30 lignes) par `ndpi.patch_and_checksum(raw, pkt, answers, FORCED_TTL)`
- [x] Supprimer le calcul manuel de `dns_offset_0`
- [x] `fix_udp6_cksum` ajouté dans `parse/ndpi.moon` (RFC 2460 §8.1) — IPv6 est un citoyen de première classe
- [x] Tests IPv6 ajoutés dans `tests/test_ndpi.moon` : `parse_packet IPv6` + `patch_and_checksum IPv6`
- [x] Tester profil ndpi4 : `make test-docker`
- [x] Tester profil ndpi5 : `make test-docker-ndpi5`

---

## Vérification finale

- [x] `make` — compilation sans erreur
- [x] `make test` — 36 tests, 0 échec
- [x] `make test-docker` — 7 scénarios E2E, TTL=60 vérifié, REFUSED reçu
- [x] `make test-docker-ndpi5` — profil nDPI 5.x passe
- [x] Logs docker : champs `ndpi_master`/`ndpi_app` présents dans les lignes ALLOW (après E3/E4)
- [x] PID distincts dans les logs pour Q0 et Q1 (supervisor=7, Q0=11, Q1=12)
