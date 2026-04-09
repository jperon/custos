## dns-filter — Makefile

MOONC   ?= moonc
LUAJIT  ?= luajit
SRC     := src
LUA     := lua

## Liste des modules à compiler (ordre de dépendance respecté pour les tests)
MOONS := \
  $(SRC)/config.moon \
  $(SRC)/uci_config.moon \
  $(SRC)/ffi_defs.moon \
  $(SRC)/log.moon \
  $(SRC)/parse/ethernet.moon \
  $(SRC)/parse/ip.moon \
  $(SRC)/parse/udp.moon \
  $(SRC)/parse/dns.moon \
  $(SRC)/ffi_ndpi.moon \
  $(SRC)/ffi_ndpi_v4.moon \
  $(SRC)/ffi_ndpi_v5.moon \
  $(SRC)/parse/ndpi.moon \
  $(SRC)/parse/ndpi_v4.moon \
  $(SRC)/parse/ndpi_v5.moon \
  $(SRC)/ipc.moon \
  $(SRC)/neigh.moon \
  $(SRC)/allowlist.moon \
  $(SRC)/nft.moon \
  $(SRC)/nfq_loop.moon \
  $(SRC)/worker_q0.moon \
  $(SRC)/worker_q1.moon \
  $(SRC)/main.moon

LUAS := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(MOONS))

## Modules filter/ (découverte automatique)
FILTER_MOONS := $(shell find $(SRC)/filter -name '*.moon' 2>/dev/null) \
  $(SRC)/ffi_xxhash.moon
FILTER_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(FILTER_MOONS))

## Modules auth/ (découverte automatique)
AUTH_MOONS := $(shell find $(SRC)/auth -name '*.moon' 2>/dev/null)
AUTH_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(AUTH_MOONS))

.PHONY: all clean check test test-ndpi test-docker test-docker-ndpi5 test-kvm test-kvm-up test-kvm-run test-kvm-down run reload update-lists make-secret logs help

all: $(LUA)/parse $(LUAS) $(FILTER_LUAS) $(AUTH_LUAS)
	@echo "Compilation terminée → $(LUA)/"

$(LUA)/parse:
	mkdir -p $(LUA)/parse

## Crée le répertoire parent avant de compiler (idempotent)
$(LUA)/%.lua: $(SRC)/%.moon
	mkdir -p $(@D)
	$(MOONC) -o $@ $<

## Vérification syntaxique de tous les fichiers Lua générés
check: all
	@echo "Vérification syntaxique..."
	@for f in $(LUAS) $(FILTER_LUAS) $(AUTH_LUAS); do \
	  luajit -e "local ok,e=loadfile('$$f'); if not ok then print('FAIL '..e) else print('OK   $$f') end"; \
	done

## Tests unitaires (parsing DNS, IPC, allowlist) — pas besoin de root
test: all
	@echo "Tests unitaires..."
	$(MOONC) -o tests/run_tests.lua tests/run_tests.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/run_tests.lua

## Tests nDPI wrapper (requires libndpi installed)
test-ndpi: all
	@echo "Tests nDPI wrapper..."
	$(MOONC) -o tests/test_ndpi.lua tests/test_ndpi.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_ndpi.lua

## Tests Docker end-to-end (requires Docker)
test-docker: all
	@echo "Tests Docker end-to-end (nDPI 4.x)..."
	$(MOONC) -o tests/test_docker.lua tests/test_docker.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_docker.lua

## Tests Docker end-to-end avec nDPI 5.0 (requires Docker)
test-docker-ndpi5: all
	@echo "Tests Docker end-to-end (nDPI 5.0)..."
	$(MOONC) -o tests/test_docker.lua tests/test_docker.moon
	NDPI_VERSION=5.0 LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_docker.lua

## Tests KVM/libvirt end-to-end (requires KVM + libvirt)
test-kvm: test-kvm-up test-kvm-run test-kvm-down

test-kvm-up:
	@echo "Démarrage des VMs KVM..."
	@virsh dominfo custos-filter >/dev/null 2>&1 || sudo bash libvirt/custos-libvirt.sh create
	bash libvirt/custos-libvirt.sh start

test-kvm-run: all
	@echo "Tests KVM end-to-end..."
	$(MOONC) -o tests/test_kvm.lua tests/test_kvm.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_kvm.lua

test-kvm-down:
	@echo "Arrêt des VMs KVM..."
	bash libvirt/custos-libvirt.sh stop

## Génère un hash PBKDF2-SHA256 pour un utilisateur (écrire dans cfg/secrets)
## Usage : make make-secret USER=alice PASS=motdepasse
make-secret: all
	@[ -n "$(USER)" ] || (echo "ERREUR : USER requis. Ex: make make-secret USER=alice PASS=..."; exit 1)
	@[ -n "$(PASS)" ] || (echo "ERREUR : PASS requis. Ex: make make-secret USER=alice PASS=..."; exit 1)
	@LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) -e "local c=require'auth.credentials'; print('$(USER):'..c.hash_password('$(PASS)'))"

## Lance le superviseur (nécessite root + règles nft en place)
run: all
	@[ "$$(id -u)" = "0" ] || (echo "ERREUR : root requis"; exit 1)
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) $(LUA)/main.lua

clean:
	rm -rf $(LUA)

## Rechargement à chaud de la config (envoie SIGHUP aux workers)
reload:
	@pkill -SIGHUP -f "luajit.*main" && echo "SIGHUP envoyé" || echo "Processus introuvable"

## Télécharge et compile les listes de domaines (sources définies dans cfg/filter.yml)
## Usage : make update-lists [PID=/run/custos.pid] [CONFIG=cfg/filter.yml]
update-lists: all
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) $(LUA)/filter/updater.lua \
	  --config $(or $(CONFIG),cfg/filter.yml) \
	  $(if $(PID),--pid $(PID),)

## Affiche les logs en temps réel avec horodatage lisible
logs:
	@tail -f /tmp/dns-filter.log | awk '{ts=$$1+0; gsub(/\[/,""); cmd="date -d @"ts" +%H:%M:%S"; cmd | getline t; close(cmd); sub($$1, "["t]"); print}'

## Affiche l'aide
help:
	@echo "Cibles disponibles:"
	@echo "  all          - Compile tous les fichiers .moon"
	@echo "  check        - Vérification syntaxique des fichiers Lua"
	@echo "  test         - Tests unitaires (pas root requis)"
	@echo "  test-ndpi    - Tests nDPI wrapper (libndpi requis)"
	@echo "  test-docker  - Tests Docker end-to-end (nDPI 4.x, Docker requis)"
	@echo "  test-docker-ndpi5 - Tests Docker end-to-end (nDPI 5.0, Docker requis)"
	@echo "  test-kvm     - Tests KVM end-to-end complets (up+run+down, libvirt requis)"
	@echo "  test-kvm-up  - Démarre les VMs KVM"
	@echo "  test-kvm-run - Exécute les tests KVM (VMs déjà démarrées)"
	@echo "  test-kvm-down - Arrête les VMs KVM"
	@echo "  run          - Lance le superviseur (root requis)"
	@echo "  clean        - Nettoie les fichiers compilés"
	@echo "  make-secret  - Génère un hash PBKDF2-SHA256 pour cfg/secrets (USER=, PASS=)"
	@echo "  update-lists - Télécharge et compile les listes de domaines"
	@echo "  logs         - Affiche les logs en temps réel"
	@echo "  help         - Affiche cette aide"
