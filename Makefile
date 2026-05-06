# CustosVirginum Makefile
# Compilation, tests, and deployment for the inline DNS filter on Linux bridge.
#
# Targets:
#   all          - Compile all .moon files to .lua
#   check        - Syntax check generated Lua files
#   test         - Unit tests (Busted: all specs in tests/unit/, no root required)
#   test-ndpi    - nDPI wrapper tests (requires libndpi)
#   test-openwrt - OpenWrt live tests via SSH (HOST=user@host required)
#   test-env     - Create/start libvirt 3-VM environment (Debian client, OpenWrt filter, Debian DNS)
#   test-env-down- Stop VMs (keep disks)
#   test-env-nuke- Delete everything
#   test-e2e     - End-to-end tests via SSH (FILTER_SSH=... CLIENT_SSH=... [CLIENT2_SSH=...])
#   test-kvm     - Full KVM E2E suite (requires test-env running)
#   coverage     - Unit tests + luacov report in tmp/coverage/
#   run          - Start supervisor (requires root + nft rules)
#   clean        - Remove compiled Lua files
#   reload       - SIGHUP to restart config
#   update-lists - Download and compile domain lists
#   logs         - Tail logs with human-readable timestamps
#   help         - Show this help

MOONC   ?= moonc
LUAJIT  ?= luajit
BUSTED  ?= busted
SRC     := src
LUA     := lua

# Chemins Lua pour les tests (modules compilés + rocks locaux)
LUAROCKS_PATH := $(HOME)/.luarocks/share/lua/5.1/?.lua;$(HOME)/.luarocks/share/lua/5.1/?/init.lua
LUAROCKS_CPATH := $(HOME)/.luarocks/lib/lua/5.1/?.so
TEST_LUA_PATH := tests/helpers/?.lua;tests/?.lua;$(LUA)/?.lua;$(LUA)/?/init.lua;$(LUAROCKS_PATH);;
TEST_LUA_CPATH := $(LUAROCKS_CPATH);;

# List of modules to compile (order respects dependencies)
MOONS := $(shell find $(SRC) -name '*.moon' | sort)
LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(MOONS))

# Filter modules (auto-discovered)
FILTER_MOONS := $(shell find $(SRC)/filter -name '*.moon' 2>/dev/null) \
  $(SRC)/ffi_xxhash.moon
FILTER_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(FILTER_MOONS))

# Auth modules (auto-discovered)
AUTH_MOONS := $(shell find $(SRC)/auth -name '*.moon' 2>/dev/null)
AUTH_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(AUTH_MOONS))

# ipparse modules (auto-discovered, exclude examples)
IPPARSE_MOONS := $(shell find $(SRC)/ipparse -name '*.moon' 2>/dev/null | grep -v examples)
IPPARSE_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(IPPARSE_MOONS))

# Specs unitaires (tous les *_spec.moon dans tests/unit/)
UNIT_SPEC_MOONS := $(shell find tests/unit -name '*_spec.moon' 2>/dev/null | sort)
UNIT_SPEC_LUAS  := $(patsubst %.moon,%.lua,$(UNIT_SPEC_MOONS))

.PHONY: all clean check test test-unit test-ndpi test-openwrt \
        test-env test-env-down test-env-nuke test-e2e test-e2e-ci test-kvm \
        coverage run reload update-lists make-secret logs help debug-env

all: $(LUA)/parse $(LUAS) $(FILTER_LUAS) $(AUTH_LUAS) $(IPPARSE_LUAS) install-owrt.lua
	@echo "Compilation terminée → $(LUA)/"

install-owrt.lua: install-owrt.moon
	$(MOONC) -o $@ $<

$(LUA)/parse:
	mkdir -p $(LUA)/parse

# Create parent directory before compiling (idempotent)
$(LUA)/%.lua: $(SRC)/%.moon
	mkdir -p $(@D)
	$(MOONC) -o $@ $<

# Compile a spec .moon → .lua (rule for tests/unit/**/*_spec.moon)
tests/unit/%.lua: tests/unit/%.moon
	$(MOONC) -o $@ $<

# Syntax check all generated Lua files
check: all
	@echo "Vérification syntaxique..."
	@for f in $(LUAS) $(FILTER_LUAS) $(AUTH_LUAS); do \
	  luajit -e "local ok,e=loadfile('$$f'); if not ok then print('FAIL '..e) else print('OK   $$f') end"; \
	done

# ── Tests unitaires (Busted) ──────────────────────────────────────────────

# Compile tous les specs .moon → .lua, puis lance Busted
compile-specs: $(UNIT_SPEC_LUAS)

test-unit: all compile-specs
	@mkdir -p tmp/test-logs
	@LUA_PATH="$(TEST_LUA_PATH)" LUA_CPATH="$(TEST_LUA_CPATH)" \
	  $(BUSTED) --lua=luajit --loaders=lua --helper=tests/helpers/busted_setup.lua \
	    tests/unit 2>&1 | tee tmp/test-logs/unit.log; \
	  rc=$$?; exit $$rc

# Cible publique : tous les tests unitaires locaux (pas root, pas VM)
test: all compile-specs test-unit

# ── Couverture ────────────────────────────────────────────────────────────

coverage: all compile-specs
	@mkdir -p tmp/coverage tmp/test-logs
	@rm -f tmp/coverage/luacov.stats.out tmp/coverage/luacov.report.out
	@LUA_PATH="$(TEST_LUA_PATH)" LUA_CPATH="$(TEST_LUA_CPATH)" \
	  $(BUSTED) --lua=luajit --loaders=lua --helper=tests/helpers/busted_setup.lua \
	    --coverage --coverage-config-file=.luacov \
	    tests/unit 2>&1 | tee tmp/test-logs/coverage.log
	@# Générer le rapport (luacov lit statsfile/reportfile depuis .luacov)
	@LUA_PATH="$(TEST_LUA_PATH)" LUA_CPATH="$(TEST_LUA_CPATH)" \
	  $(HOME)/.luarocks/bin/luacov -c .luacov 2>/dev/null || true
	@echo ""
	@echo "Rapport de couverture : tmp/coverage/luacov.report.out"
	@if [ -f tmp/coverage/luacov.report.out ]; then \
	  grep -E "^Total" tmp/coverage/luacov.report.out || true; \
	fi

# ── nDPI wrapper tests (requires libndpi) ────────────────────────────────

test-ndpi: all
	@echo "Tests nDPI wrapper..."
	$(MOONC) -o tests/test_ndpi.lua tests/test_ndpi.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_ndpi.lua

# ── OpenWrt live tests via SSH ────────────────────────────────────────────

test-openwrt: all
	@[ -n "$(HOST)" ] || (echo "ERREUR : HOST requis. Ex: make test-openwrt HOST=root@DEST"; exit 1)
	@echo "Tests OpenWrt end-to-end..."
	$(MOONC) -o tests/test_openwrt.lua tests/test_openwrt.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_openwrt.lua $(HOST) $(ARGS)

# ── Libvirt environment (3 VMs: client, filter, dns) ─────────────────────

test-env:
	bash libvirt/custos-libvirt.sh ensure
	@echo ""
	@bash libvirt/custos-libvirt.sh show

test-env-down:
	bash libvirt/custos-libvirt.sh stop

test-env-nuke:
	bash libvirt/custos-libvirt.sh nuke

# ── End-to-end tests (requires test-env running) ──────────────────────────

test-e2e: all
	@bash libvirt/custos-libvirt.sh filter-ip >/dev/null 2>&1 \
	  || (echo "ERREUR : environnement non démarré. Exécute d'abord: make test-env"; exit 1)
	$(MOONC) -o tests/test_e2e.lua tests/test_e2e.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_e2e.lua

# End-to-end tests with logs
test-e2e-ci: all
	@mkdir -p tmp
	@bash libvirt/custos-libvirt.sh filter-ip >/dev/null 2>&1 \
	  || (echo "ERREUR : environnement non démarré"; exit 1)
	$(MOONC) -o tests/test_e2e.lua tests/test_e2e.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_e2e.lua 2>&1 | tee tmp/test-e2e.log

# KVM exhaustive E2E suite
test-kvm: all
	@bash libvirt/custos-libvirt.sh filter-ip >/dev/null 2>&1 \
	  || (echo "ERREUR : environnement non démarré. Exécute d'abord: make test-env"; exit 1)
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) lua/test_kvm.lua

# Debug libvirt environment
debug-env:
	@bash libvirt/debug.sh $(ARGS)

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

# Clean compiled files
clean:
	rm -rf $(LUA)

# Reload config (SIGHUP)
reload:
	@pkill -SIGHUP -f "luajit.*main" && echo "SIGHUP envoyé" || echo "Processus introuvable"

# Update domain lists from sources defined in cfg/filter.yml
update-lists: all
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) $(LUA)/filter/updater.lua \
	  --config $(or $(CONFIG),cfg/filter.yml) \
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

# Help
help:
	@echo "Cibles disponibles:"
	@echo "  all          - Compile tous les fichiers .moon"
	@echo "  check        - Vérification syntaxique des fichiers Lua"
	@echo "  test         - Tests unitaires Busted (pas root requis)"
	@echo "  test-unit    - Tests unitaires Busted uniquement (sans FFI)"
	@echo "  test-ffi     - Tests FFI socket/WolfSSL/intégration"
	@echo "  coverage     - Tests unitaires + rapport luacov (tmp/coverage/)"
	@echo "  test-ndpi    - Tests nDPI wrapper (libndpi requis)"
	@echo "  test-openwrt - Tests OpenWrt live via SSH (HOST=user@host requis)"
	@echo "  test-env     - Crée/démarre l'environnement libvirt 3 VMs pour E2E"
	@echo "  test-env-down - Arrête les VMs (conserve les disques)"
	@echo "  test-env-nuke - Supprime VMs, réseaux, images (scratch)"
	@echo "  test-e2e     - Suite E2E complète (requiert test-env déjà démarré)"
	@echo "  test-e2e-ci  - Suite E2E avec logs dans tmp/test-e2e.log"
	@echo "  test-kvm     - Suite E2E KVM exhaustive (requiert test-env)"
	@echo "  test-e2e-ssh - Suite E2E via SSH (FILTER_SSH=... CLIENT_SSH=... [CLIENT2_SSH=...])"
	@echo "  debug-env    - Outil de diagnostic libvirt (Usage: make debug-env ARGS=logs)"
	@echo "  run          - Lance le superviseur (root requis)"
	@echo "  clean        - Nettoie les fichiers compilés"
	@echo "  make-secret  - Génère un hash PBKDF2-SHA256 pour cfg/secrets (USER=, PASS=)"
	@echo "  update-lists - Télécharge et compile les listes de domaines"
	@echo "  logs         - Affiche les logs en temps réel"
