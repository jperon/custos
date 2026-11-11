# CustosVirginum Makefile
# Compilation, tests, and deployment for the inline DNS filter on Linux bridge.
#
# Targets:
#   all          - Compile all .moon files to .lua
#   check        - Syntax check generated Lua files + lectures de globales non déclarées
#   test         - Unit tests (Busted: all specs in tests/unit/, no root required)
#   test-openwrt - OpenWrt live tests via SSH (HOST=user@host required)
#   homelab-up    - Create/start 3-VM OpenWrt homelab (via/custos/servus)
#   homelab-down  - Shutdown the homelab
#   homelab-nuke  - Delete VMs, networks, derived images
#   homelab-redeploy - Recompile MoonScript and push to custos VM
#   test-e2e      - Suite E2E complète via homelab libvirt (G0-G13, dont admin webui)
#   test-e2e-rebuild - Reconstruction complète du homelab puis suite E2E
#   coverage     - Unit tests + luacov report in tmp/coverage/
#   coverage-quick - Alternative rapide (échantillonnage) : tmp/coverage_quick/
#   run          - Start supervisor (requires root + nft rules)
#   clean        - Remove compiled Lua files
#   reload       - SIGHUP to restart config
#   update-lists - Download and compile domain lists
#   logs         - Tail logs with human-readable timestamps
#   help         - Show this help

# HOST/REPO sont des variables de ligne de commande : make les exporte par
# défaut vers l'environnement de TOUTE fonction $(shell …) et de toute recette,
# en développant leur valeur. Une valeur `$(shell …)` s'exécuterait donc avant
# la validation des cibles sync. `unexport` doit être posé AVANT le premier
# $(shell …) du Makefile (lignes MOONS/FILTER_MOONS… ci-dessous).
unexport HOST REPO

MOONC   ?= moonc
LUAJIT  ?= luajit
BUSTED  ?= busted
SRC     := src
LUA     := lua
SYNC    := sync
MOONSCRIPT_SUBMODULE := $(SRC)/lib/moonscript
MOONTASTIK_SUBMODULE := $(SRC)/lib/moontastik

# `tee` renvoie toujours 0 : sans pipefail, le code retour de Busted (premier
# élément du pipeline) serait masqué et une suite EN ÉCHEC pourrait faire
# retourner 0 à `make test` — faux positif inacceptable pour la Definition of
# Done. Toute recette qui pipe vers `tee` (ou un autre filtre) préfixe son
# pipeline par $(PIPE_FAIL) et ne se fie jamais à `$$?` nu après un pipe.
SHELL := bash
PIPE_FAIL = set -o pipefail;

# Chemins Lua pour les tests (modules compilés + rocks locaux)
LUAROCKS_PATH := $(HOME)/.luarocks/share/lua/5.1/?.lua;$(HOME)/.luarocks/share/lua/5.1/?/init.lua
LUAROCKS_CPATH := $(HOME)/.luarocks/lib/lua/5.1/?.so
TEST_LUA_PATH := tests/helpers/?.lua;tests/?.lua;$(LUA)/?.lua;$(LUA)/?/init.lua;$(LUAROCKS_PATH);;
TEST_LUA_CPATH := $(LUAROCKS_CPATH);;

# List of project modules to compile (excluding embedded moonscript submodule)
# On élague aussi le sous-module moontastik : ses sources ipparse sont
# compilées séparément via le lien symbolique src/ipparse (cf. IPPARSE_MOONS),
# et le reste (hexdump…) ne doit pas produire de lua/lib/moontastik/.
MOONS := $(shell find $(SRC) -path '$(MOONSCRIPT_SUBMODULE)' -prune -o -path '$(MOONTASTIK_SUBMODULE)' -prune -o -name '*.moon' -print | sort)
LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(MOONS))

# Lua vérifiés par `check`. On exclut le code ipparse (sous-module moontastik,
# lié en src/ipparse) qui n'est PAS destiné à LuaJIT : exemples et tests amont
# (certains ciblent le noyau lunatik), et `lib/bit53` qui utilise
# délibérément la syntaxe Lua 5.3
# (`&`, `|`, `<<`) que LuaJIT (5.1) ne sait pas parser. Ces fichiers ne font
# pas partie du runtime déployé ; les inclure rendrait `check` rouge en
# permanence sur du code hérité non modifiable.
CHECK_LUAS = $(filter-out $(LUA)/ipparse/examples/% $(LUA)/ipparse/tests/% $(LUA)/ipparse/lib/bit53.lua,$(LUAS) $(FILTER_LUAS) $(AUTH_LUAS))

# Embedded MoonScript runtime (from git submodule)
MOONSCRIPT_RUNTIME_MOONS := $(shell find $(MOONSCRIPT_SUBMODULE)/moonscript $(MOONSCRIPT_SUBMODULE)/moon -name '*.moon' 2>/dev/null | sort)
MOONSCRIPT_RUNTIME_LUAS  := $(patsubst $(MOONSCRIPT_SUBMODULE)/%.moon,$(LUA)/%.lua,$(MOONSCRIPT_RUNTIME_MOONS))

# Filter modules (auto-discovered)
FILTER_MOONS := $(shell find $(SRC)/filter -name '*.moon' 2>/dev/null) \
  $(SRC)/ffi_xxhash.moon
FILTER_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(FILTER_MOONS))

# Auth modules (auto-discovered)
AUTH_MOONS := $(shell find $(SRC)/auth -name '*.moon' 2>/dev/null)
AUTH_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(AUTH_MOONS))

# JS embarqué du portail (source unique : src/auth/portal_client.js)
GEN_LUAS := $(LUA)/auth/portal_client_js.lua

$(LUA)/auth/portal_client_js.lua: $(SRC)/auth/portal_client.js tools/embed_js.lua
	@mkdir -p $(LUA)/auth
	$(LUAJIT) tools/embed_js.lua $< $@

# ipparse modules (auto-discovered, exclude examples)
# `find` ne suit pas un lien symbolique passé comme point de départ sans -H :
# src/ipparse est un lien vers lib/moontastik/ipparse. -H suit uniquement le
# point de départ (pas les liens rencontrés ensuite, donc pas de boucle sur
# l'auto-lien ipparse/ipparse -> .).
IPPARSE_MOONS := $(shell find -H $(SRC)/ipparse -name '*.moon' 2>/dev/null | grep -v examples)
IPPARSE_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(IPPARSE_MOONS))
IPPARSE_STATIC_SRCS := $(SRC)/ipparse/lib/sha.lua $(SRC)/ipparse/lib/sha2.lua
IPPARSE_STATIC_LUAS := $(patsubst $(SRC)/%.lua,$(LUA)/%.lua,$(IPPARSE_STATIC_SRCS))

# Specs unitaires (tous les *_spec.moon dans tests/unit/)
UNIT_SPEC_MOONS := $(shell find tests/unit -name '*_spec.moon' 2>/dev/null | sort)
UNIT_SPEC_LUAS  := $(patsubst %.moon,%.lua,$(UNIT_SPEC_MOONS))

# Helpers de tests écrits en MoonScript (busted_setup, mini_busted, …)
TEST_HELPER_MOONS := $(shell find tests/helpers -name '*.moon' 2>/dev/null | sort)
TEST_HELPER_LUAS  := $(patsubst %.moon,%.lua,$(TEST_HELPER_MOONS))

# Sync infrastructure (sync/*.moon → lua/sync/*.lua)
SYNC_MOONS := $(shell find $(SYNC) -name '*.moon' 2>/dev/null | sort)
SYNC_LUAS  := $(patsubst $(SYNC)/%.moon,$(LUA)/sync/%.lua,$(SYNC_MOONS))

.PHONY: all clean check test test-unit test-js test-vm test-openwrt test-e2e test-e2e-rebuild \
        homelab-up homelab-down homelab-nuke homelab-redeploy \
        coverage coverage-quick run reload update-lists make-secret logs \
        bench bench-micro bench-load \
        sync-init sync-push-init redbean-ui help

all: $(LUA)/nfq $(LUAS) $(FILTER_LUAS) $(AUTH_LUAS) $(GEN_LUAS) $(IPPARSE_LUAS) $(IPPARSE_STATIC_LUAS) $(MOONSCRIPT_RUNTIME_LUAS) $(SYNC_LUAS) install-owrt.lua .init.lua
	@echo "Compilation terminée → $(LUA)/"

install-owrt.lua: install-owrt.moon
	$(MOONC) -o $@ $<

.init.lua: .init.moon
	$(MOONC) -o $@ $<

# Empaquette .init.lua + lua/auth/html.lua dans redbean.com (redbean.com requis à la racine)
redbean-ui: .init.lua
	@[ -f redbean.com ] || (echo "ERREUR : redbean.com absent. Télécharger depuis https://redbean.dev/" ; exit 1)
	mkdir -p tmp/.lua
	cp lua/auth/html.lua tmp/.lua/html.lua
	cd tmp && zip ../redbean.com .lua/html.lua
	zip redbean.com .init.lua
	rm -rf tmp/.lua
	@echo "UI packagée dans redbean.com — lancer : ./redbean.com"

$(LUA)/nfq:
	mkdir -p $(LUA)/nfq

# Create parent directory before compiling (idempotent)
$(LUA)/%.lua: $(SRC)/%.moon
	mkdir -p $(@D)
	$(MOONC) -o $@ $<

$(LUA)/%.lua: $(MOONSCRIPT_SUBMODULE)/%.moon
	mkdir -p $(@D)
	$(MOONC) -o $@ $<

$(LUA)/%.lua: $(SRC)/%.lua
	mkdir -p $(@D)
	cp $< $@

$(LUA)/sync/%.lua: $(SYNC)/%.moon
	mkdir -p $(@D)
	$(MOONC) -o $@ $<

# Compile a spec .moon → .lua (rule for tests/unit/**/*_spec.moon)
tests/unit/%.lua: tests/unit/%.moon
	$(MOONC) -o $@ $<

# Compile helpers .moon → .lua (rule for tests/helpers/*.moon)
tests/helpers/%.lua: tests/helpers/%.moon
	$(MOONC) -o $@ $<

# Cible pour compiler tous les helpers de tests
compile-helpers: $(TEST_HELPER_LUAS)

# Syntax check all generated Lua files (BLOQUANT).
# Toute la liste est vérifiée (rapport complet, pas d'arrêt au premier échec) ;
# chaque échec positionne rc=1, propagé en `exit $$rc` en fin de recette — sans
# cela un fichier cassé n'affichait que `FAIL` et `make check` retournait 0.
# Puis contrôle des globales non déclarées : une variable lue hors de la portée
# où MoonScript l'a rendue locale compile en globale (nil silencieux) ; cf.
# tools/check_globals.sh et .agents/testing.md.
check: all
	@echo "Vérification syntaxique..."
	@rc=0; \
	for f in $(CHECK_LUAS); do \
	  luajit -e "local ok,e=loadfile('$$f'); if not ok then print('FAIL '..e); os.exit(1) else print('OK   $$f') end" || rc=1; \
	done; \
	exit $$rc
	@echo "Vérification des globales non déclarées..."
	@tools/check_globals.sh

# ── Tests unitaires (Busted) ──────────────────────────────────────────────

# Compile tous les specs .moon → .lua, puis lance Busted
compile-specs: $(UNIT_SPEC_LUAS)

test-unit: all compile-specs compile-helpers
	@mkdir -p tmp/test-logs
	@$(PIPE_FAIL) LUA_PATH="$(TEST_LUA_PATH)" LUA_CPATH="$(TEST_LUA_CPATH)" \
	  $(BUSTED) --lua=luajit --loaders=lua --helper=tests/helpers/busted_setup.lua \
	    tests/unit 2>&1 | tee tmp/test-logs/unit.log

# Tests JS du client portail (Node natif, sans dépendance npm)
test-js:
	node --test tests/unit/auth/portal_client.test.js

# Cible publique : tous les tests unitaires locaux (pas root, pas VM)
test: all compile-specs compile-helpers test-unit test-js

# ── Couverture ────────────────────────────────────────────────────────────

coverage: all compile-specs compile-helpers
	@mkdir -p tmp/coverage tmp/test-logs
	@rm -f tmp/coverage/luacov.stats.out tmp/coverage/luacov.report.out
	@# rc capture le statut Busted malgré le `tee` ; le rapport est généré même
	@# en cas d'échec (diagnostic), puis rc est propagé en fin de recette.
	@$(PIPE_FAIL) LUA_PATH="$(TEST_LUA_PATH)" LUA_CPATH="$(TEST_LUA_CPATH)" \
	  $(BUSTED) --lua=luajit --loaders=lua --helper=tests/helpers/busted_setup.lua \
	    --coverage --coverage-config-file=.luacov \
	    tests/unit 2>&1 | tee tmp/test-logs/coverage.log; \
	  rc=$$?; \
	  LUA_PATH="$(TEST_LUA_PATH)" LUA_CPATH="$(TEST_LUA_CPATH)" \
	    luacov -c .luacov 2>/dev/null || true; \
	  echo ""; \
	  echo "Rapport de couverture : tmp/coverage/luacov.report.out"; \
	  if [ -f tmp/coverage/luacov.report.out ]; then \
	    grep -E "^Total" tmp/coverage/luacov.report.out || true; \
	  fi; \
	  exit $$rc

# Alternative rapide à `coverage` : hook debug.sethook en mode *count*
# (échantillonnage) plutôt que *line* (luacov, exhaustif mais ~4x plus lent
# sur cette suite, cf. AGENTS.md § Corrections d'audit 2026-07-16). Donne un
# ordre de grandeur, pas un pourcentage exact — utile pour repérer rapidement
# les fichiers jamais exercés par aucun test.
coverage-quick: all compile-specs compile-helpers
	@mkdir -p tmp/coverage_quick tmp/test-logs
	@rm -f tmp/coverage_quick/quick_coverage.lua
	@# Même motif que `coverage` : rc de Busted préservé, rapport toujours émis.
	@$(PIPE_FAIL) LUA_PATH="$(TEST_LUA_PATH)" LUA_CPATH="$(TEST_LUA_CPATH)" \
	  $(BUSTED) --lua=luajit --loaders=lua --helper=tests/helpers/quick_coverage_setup.lua \
	    tests/unit 2>&1 | tee tmp/test-logs/coverage-quick.log; \
	  rc=$$?; \
	  echo ""; \
	  LUA_PATH="$(TEST_LUA_PATH)" LUA_CPATH="$(TEST_LUA_CPATH)" \
	    luajit tools/quick_coverage_report.lua | tail -50; \
	  rrc=$$?; \
	  if [ $$rc -ne 0 ]; then exit $$rc; fi; \
	  exit $$rrc

# ── OpenWrt live tests via SSH ────────────────────────────────────────────

test-openwrt: all
	@[ -n "$(HOST)" ] || (echo "ERREUR : HOST requis. Ex: make test-openwrt HOST=root@DEST"; exit 1)
	@echo "Tests OpenWrt end-to-end..."
	$(MOONC) -o tests/test_openwrt.lua tests/test_openwrt.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_openwrt.lua $(HOST) $(ARGS)

# ── Homelab libvirt (3 VMs OpenWrt : via, custos, servus) ────────────────
# Voir libvirt/README.md pour la topologie et le dépannage.

homelab-up:
	bash libvirt/homelab.sh ensure
	bash libvirt/homelab.sh start

homelab-down:
	bash libvirt/homelab.sh stop

homelab-nuke:
	bash libvirt/homelab.sh nuke

homelab-redeploy: all
	bash libvirt/homelab.sh redeploy

test-e2e: all
	bash libvirt/homelab.sh ensure
	bash libvirt/homelab.sh start
	bash libvirt/homelab.sh redeploy
	bash libvirt/homelab.sh test-e2e

# Reconstruction complète du homelab (images qcow2 recréées depuis la base)
# puis suite E2E. À utiliser quand les uci-defaults ont changé.
test-e2e-rebuild: all
	bash libvirt/homelab.sh stop
	bash libvirt/homelab.sh nuke
	bash libvirt/homelab.sh ensure
	bash libvirt/homelab.sh start
	bash libvirt/homelab.sh redeploy
	bash libvirt/homelab.sh test-e2e

test-vm: all
	bash libvirt/homelab.sh test-unit

# ── Utilitaires ───────────────────────────────────────────────────────────

# Generate PBKDF2-SHA256 hash for secrets file
make-secret: all
	@[ -n "$(USER)" ] || (echo "ERREUR : USER requis. Ex: make make-secret USER=alice PASS=..."; exit 1)
	@[ -n "$(PASS)" ] || (echo "ERREUR : PASS requis. Ex: make make-secret USER=alice PASS=..."; exit 1)
	@LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) -e "local c=require'auth.credentials'; local u=os.getenv'USER'; local p=os.getenv'PASS'; print(u..':'..c.hash_password(p))"

# Start supervisor (requires root)
run: all
	@[ "$$(id -u)" = "0" ] || (echo "ERREUR : root requis"; exit 1)
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) $(LUA)/main.lua

# ── Benchmarks ────────────────────────────────────────────────────────────
# Harnais de stress test / mesure de performances (cf. src/bench/README.md).
# Variables : ITERS, TARGET, DURATION, RATE, DOMAINS, SAVE_BASELINE.
ITERS    ?= 1000000
DURATION ?= 5
RATE     ?=
DOMAINS  ?=
TARGET   ?=
BENCH_ENV = LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;"
BENCH_ARGS = --iters $(ITERS) --duration $(DURATION) \
  $(if $(RATE),--rate $(RATE),) $(if $(DOMAINS),--domains $(DOMAINS),) \
  $(if $(SAVE_BASELINE),--save-baseline,)

# Volet micro-bench seul (aucune infra requise, lançable partout).
bench-micro: all
	@$(BENCH_ENV) $(LUAJIT) $(LUA)/bench/cli.lua --micro $(BENCH_ARGS)

# Volet charge DNS bout-en-bout (requiert TARGET=host[:port]).
bench-load: all
	@[ -n "$(TARGET)" ] || (echo "ERREUR : TARGET=host[:port] requis"; exit 1)
	@$(BENCH_ENV) $(LUAJIT) $(LUA)/bench/cli.lua --load --target $(TARGET) $(BENCH_ARGS)

# Défaut : micro-bench (le volet charge reste opt-in via bench-load).
bench: bench-micro

# Clean compiled files
clean:
	rm -rf $(LUA)
	@# Supprimer les .lua générés depuis des .moon dans tests/
	rm -f $(UNIT_SPEC_LUAS) $(TEST_HELPER_LUAS)

# Reload config (SIGHUP) — cible : superviseur, via le pidfile (jamais pkill :
# le motif viserait aussi les workers forkés, sans handler SIGHUP).
reload:
	@PIDFILE="$${CUSTOS_PID_FILE:-/var/run/custos.pid}"; \
	if [ ! -f "$$PIDFILE" ]; then \
	  echo "pidfile absent ($$PIDFILE) — service inactif ?" >&2; exit 1; \
	fi; \
	PID="$$(cat "$$PIDFILE")"; \
	kill -HUP "$$PID" && echo "SIGHUP envoyé au superviseur (PID $$PID)"

# Update domain lists from sources defined in config.moon
update-lists: all
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) $(LUA)/filter/updater.lua \
	  --config $(or $(CONFIG),cfg/config.moon) \
	  $(if $(PID),--pid $(PID),)

# Tail logs with human-readable timestamps
logs:
	@tail -f /tmp/dns-filter.log | awk '{ts=$$1+0; gsub(/\[/,""); cmd="date -d @"ts" +%H:%M:%S"; cmd | getline t; close(cmd); sub($$1, "["t]"); print}'

# E2E tests via SSH (FILTER_SSH=user@host CLIENT_SSH=user@host [CLIENT2_SSH=user@host])
test-e2e-ssh: all
	@echo "Usage: make test-e2e-ssh FILTER_SSH=... CLIENT_SSH=... [CLIENT2_SSH=...]"
	@[ -n "$(FILTER_SSH)" ] || (echo "ERREUR: FILTER_SSH requis"; exit 1)
	@[ -n "$(CLIENT_SSH)" ] || (echo "ERREUR: CLIENT_SSH requis"; exit 1)
	@mkdir -p tmp/e2e-logs
	$(MOONC) -o tests/run_e2e.lua tests/run_e2e.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/run_e2e.lua \
	    --filter "$(FILTER_SSH)" \
	    --client "$(CLIENT_SSH)" \
	    $(if $(CLIENT2_SSH),--client2 "$(CLIENT2_SSH)",)
	@echo "Rapport généré : tmp/test-e2e-report.moon"
	@echo "Logs dans tmp/e2e-logs/"

# ── Synchronisation de config multi-appareils ────────────────────────────────
# Voir sync/ pour les scripts et doc/CONFIG.md pour la structure du dépôt.

# Valide HOST/REPO avant tout ssh/scp. Les valeurs sont passées par
# l'ENVIRONNEMENT (SYNC_HOST/SYNC_REPO, cf. export target-specific ci-dessous),
# jamais interpolées dans le texte du shell avant validation : une valeur comme
# REPO='$(touch tmp/x)' ou '`touch tmp/x`' doit être lue comme donnée, pas
# exécutée. $(value HOST) empêche make de ré-expanser la valeur (fonctions
# $(shell …) éventuelles). Jeu de caractères strict ; REPO est ensuite écrit
# entre apostrophes simples dans sync.conf (sûr car validé).
sync-init sync-push-init: export SYNC_HOST := $(value HOST)
sync-init sync-push-init: export SYNC_REPO := $(value REPO)

SYNC_VALIDATE = \
	[ -n "$$SYNC_HOST" ] || { echo "ERREUR : HOST requis." >&2; exit 1; }; \
	[ -n "$$SYNC_REPO" ] || { echo "ERREUR : REPO requis." >&2; exit 1; }; \
	case "$$SYNC_HOST" in *[!A-Za-z0-9._@:-]*) printf '%s\n' "ERREUR : HOST invalide : $$SYNC_HOST" >&2; exit 1;; esac; \
	case "$$SYNC_REPO" in *[!A-Za-z0-9._~:/@%+=-]*) printf '%s\n' "ERREUR : REPO invalide : $$SYNC_REPO" >&2; exit 1;; esac

# Ligne cron custos-sync ajoutée seulement si absente (idempotent).
SYNC_CRON = crontab -l 2>/dev/null | grep -qF "/usr/share/custos/sync/custos-sync.sh" || { crontab -l 2>/dev/null | { cat; echo "*/15 * * * * /usr/share/custos/sync/custos-sync.sh"; } | crontab -; }

# Initialise la sync pull-only sur un device OpenWrt (HOST=user@host requis)
# Toutes les lignes utilisent les variables d'environnement validées
# ($$SYNC_HOST/$$SYNC_REPO), jamais $(HOST)/$(REPO) : make développe
# l'intégralité de la recette avant d'exécuter la première ligne, donc une
# valeur `$(shell …)` serait exécutée même si la validation échoue.
sync-init: all
	@$(SYNC_VALIDATE)
	ssh "$$SYNC_HOST" 'mkdir -p /usr/share/custos/sync'
	scp $(LUA)/sync/apply.lua      "$$SYNC_HOST":/usr/share/custos/sync/apply.lua
	scp sync/custos-sync.sh        "$$SYNC_HOST":/usr/share/custos/sync/custos-sync.sh
	ssh "$$SYNC_HOST" 'chmod +x /usr/share/custos/sync/custos-sync.sh'
	ssh "$$SYNC_HOST" "echo \"CUSTOS_CONFIG_REPO='$$SYNC_REPO'\" > /etc/custos/sync.conf"
	ssh "$$SYNC_HOST" '$(SYNC_CRON)'
	@echo "Sync initialisée sur $$SYNC_HOST — cron toutes les 15 min"

# Initialise la sync push sur un filtre de référence (HOST=user@host, REPO=url requis)
sync-push-init: all
	@$(SYNC_VALIDATE)
	ssh "$$SYNC_HOST" 'mkdir -p /usr/share/custos/sync'
	scp $(LUA)/sync/apply.lua      "$$SYNC_HOST":/usr/share/custos/sync/apply.lua
	scp sync/custos-sync.sh        "$$SYNC_HOST":/usr/share/custos/sync/custos-sync.sh
	scp sync/custos-sync-push.sh   "$$SYNC_HOST":/usr/share/custos/sync/custos-sync-push.sh
	ssh "$$SYNC_HOST" 'chmod +x /usr/share/custos/sync/custos-sync.sh /usr/share/custos/sync/custos-sync-push.sh'
	ssh "$$SYNC_HOST" "echo \"CUSTOS_CONFIG_REPO='$$SYNC_REPO'\" > /etc/custos/sync.conf"
	ssh "$$SYNC_HOST" '$(SYNC_CRON)'
	@echo "Sync push initialisée sur $$SYNC_HOST — lancer custos-sync-push.sh manuellement pour publier"

# Help
help:
	@echo "Cibles disponibles:"
	@echo "  all          - Compile tous les fichiers .moon"
	@echo "  check        - Vérification syntaxique des fichiers Lua"
	@echo "  test         - Tests unitaires Busted (pas root requis)"
	@echo "  test-unit    - Tests unitaires Busted uniquement (sans FFI)"
	@echo "  test-ffi     - Tests FFI socket/WolfSSL/intégration"
	@echo "  coverage     - Tests unitaires + rapport luacov (tmp/coverage/)"
	@echo "  coverage-quick - Alternative rapide par échantillonnage (tmp/coverage_quick/)"
	@echo "  test-openwrt - Tests OpenWrt live via SSH (HOST=user@host requis)"
	@echo "  homelab-up    - Crée/démarre les 3 VMs OpenWrt (via/custos/servus)"
	@echo "  homelab-down  - Arrête les VMs"
	@echo "  homelab-nuke  - Supprime VMs, réseaux, qcow2 dérivés"
	@echo "  homelab-redeploy - Recompile et pousse custos dans la VM custos"
	@echo "  test-e2e         - Suite E2E complète via homelab libvirt (G0-G13, dont admin webui)"
	@echo "  test-e2e-rebuild - Reconstruit le homelab (nuke+ensure) puis suite E2E"
	@echo "  test-vm       - Tests unitaires exécutés dans la VM custos (mini_busted)"
	@echo "  test-e2e-ssh  - Suite E2E via SSH distant (FILTER_SSH=... CLIENT_SSH=... [CLIENT2_SSH=...])"
	@echo "  run          - Lance le superviseur (root requis)"
	@echo "  clean        - Nettoie les fichiers compilés"
	@echo "  make-secret  - Génère un hash PBKDF2-SHA256 pour cfg/secrets (USER=, PASS=)"
	@echo "  update-lists - Télécharge et compile les listes de domaines"
	@echo "  logs         - Affiche les logs en temps réel"
	@echo "  sync-init    - Init sync pull sur un device (HOST=... REPO=... requis)"
	@echo "  sync-push-init - Init sync push sur un filtre de référence (HOST=... REPO=... requis)"
	@echo "  redbean-ui   - Empaquète l'UI d'installation dans redbean.com (redbean.com requis)"
