## dns-filter — Makefile

MOONC   ?= moonc
LUAJIT  ?= luajit
SRC     := src
LUA     := lua

## Liste des modules à compiler (ordre de dépendance respecté pour les tests)
MOONS := \
  $(SRC)/config.moon \
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
  $(SRC)/allowlist.moon \
  $(SRC)/nft.moon \
  $(SRC)/nfq_loop.moon \
  $(SRC)/worker_q0.moon \
  $(SRC)/worker_q1.moon \
  $(SRC)/main.moon

LUAS := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(MOONS))

.PHONY: all clean check test test-ndpi run

all: $(LUA)/parse $(LUAS)
	@echo "Compilation terminée → $(LUA)/"

$(LUA)/parse:
	mkdir -p $(LUA)/parse

$(LUA)/%.lua: $(SRC)/%.moon
	$(MOONC) -o $@ $<

## Vérification syntaxique de tous les fichiers Lua générés
check: all
	@echo "Vérification syntaxique..."
	@for f in $(LUAS); do \
	  luajit -e "local ok,e=loadfile('$$f'); if not ok then print('FAIL '..e) else print('OK   '..$$f) end"; \
	done

## Tests unitaires (parsing DNS, IPC, allowlist) — pas besoin de root
test: all
	@echo "Tests unitaires..."
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/run_tests.lua

## Tests nDPI wrapper (requires libndpi installed)
test-ndpi: all
	@echo "Tests nDPI wrapper..."
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_ndpi.lua

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

## Affiche les logs en temps réel avec horodatage lisible
logs:
	@tail -f /tmp/dns-filter.log | awk '{ts=$$1+0; gsub(/\[/,""); cmd="date -d @"ts" +%H:%M:%S"; cmd | getline t; close(cmd); sub($$1, "["t"]"); print}'
