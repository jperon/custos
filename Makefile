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
  $(SRC)/ip_whitelist.moon \
  $(SRC)/nft.moon \
  $(SRC)/parse/tcp.moon \
  $(SRC)/nfq_loop.moon \
  $(SRC)/worker_q0.moon \
  $(SRC)/worker_q1.moon \
  $(SRC)/worker_q2.moon \
  $(SRC)/main.moon

LUAS := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(MOONS))

## Modules filter/ (découverte automatique)
FILTER_MOONS := $(shell find $(SRC)/filter -name '*.moon' 2>/dev/null) \
  $(SRC)/ffi_xxhash.moon
FILTER_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(FILTER_MOONS))

## Modules auth/ (découverte automatique)
AUTH_MOONS := $(shell find $(SRC)/auth -name '*.moon' 2>/dev/null)
AUTH_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(AUTH_MOONS))

.PHONY: all clean check test test-ndpi test-openwrt run reload update-lists make-secret logs help

all: $(LUA)/parse $(LUAS) $(FILTER_LUAS) $(AUTH_LUAS) install-owrt.lua
	@echo "Compilation terminée → $(LUA)/"

install-owrt.lua: install-owrt.moon
	$(MOONC) -o $@ $<

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


## Tests OpenWrt end-to-end (accès SSH à un routeur déployé requis)
## Usage : make test-openwrt HOST=root@esm.y [ARGS=--no-restart]
## Usage bridge : make test-openwrt HOST=root@esm.y ARGS=--bridge
test-openwrt: all
	@[ -n "$(HOST)" ] || (echo "ERREUR : HOST requis. Ex: make test-openwrt HOST=root@esm.y"; exit 1)
	@echo "Tests OpenWrt end-to-end..."
	$(MOONC) -o tests/test_openwrt.lua tests/test_openwrt.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_openwrt.lua $(HOST) $(ARGS)

## Génère un hash PBKDF2-SHA256 pour un utilisateur (écrire dans cfg/secrets)
## Usage : make make-secret USER=alice PASS=motdepasse
make-secret: all
	@[ -n "$(USER)" ] || (echo "ERREUR : USER requis. Ex: make make-secret USER=alice PASS=..."; exit 1)
	@[ -n "$(PASS)" ] || (echo "ERREUR : PASS requis. Ex: make make-secret USER=alice PASS=..."; exit 1)
	@LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) -e "local c=require'auth.credentials'; local u=os.getenv'USER'; local p=os.getenv'PASS'; print(u..':'..c.hash_password(p))"

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
	@echo "  test-openwrt - Tests OpenWrt live via SSH (HOST=user@host requis)"
	@echo "  run          - Lance le superviseur (root requis)"
	@echo "  clean        - Nettoie les fichiers compilés"
	@echo "  make-secret  - Génère un hash PBKDF2-SHA256 pour cfg/secrets (USER=, PASS=)"
	@echo "  update-lists - Télécharge et compile les listes de domaines"
	@echo "  logs         - Affiche les logs en temps réel"
	@echo "  help         - Affiche cette aide"
