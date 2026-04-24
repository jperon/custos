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
  $(SRC)/ipparse/lib/bit_compat.moon \
  $(SRC)/ipparse/lib/pack_compat.moon \
  $(SRC)/ipparse/lib/sha.lua \
  $(SRC)/ipparse/lib/sha2.lua \
  $(SRC)/ipparse/fun.moon \
  $(SRC)/ipparse/init.moon \
  $(SRC)/ipparse/l3/lib.moon \
  $(SRC)/ipparse/l3/ip4.moon \
  $(SRC)/ipparse/l3/ip6.moon \
  $(SRC)/ipparse/l3/ip.moon \
  $(SRC)/ipparse/l2/ethernet.moon \
  $(SRC)/ipparse/l4/tcp.moon \
	$(SRC)/ipparse/l7/dns.moon \
  $(SRC)/parse/ethernet.moon \
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
  $(SRC)/nft_add_helper.moon \
  $(SRC)/nft_extra_rules.moon \
  $(SRC)/nfq_loop.moon \
  $(SRC)/worker_q0.moon \
  $(SRC)/worker_q1.moon \
  $(SRC)/worker_q2.moon \
  $(SRC)/worker_q3.moon \
  $(SRC)/main.moon

LUAS := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(MOONS))

## Modules filter/ (découverte automatique)
FILTER_MOONS := $(shell find $(SRC)/filter -name '*.moon' 2>/dev/null) \
  $(SRC)/ffi_xxhash.moon
FILTER_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(FILTER_MOONS))

## Modules auth/ (découverte automatique)
AUTH_MOONS := $(shell find $(SRC)/auth -name '*.moon' 2>/dev/null)
AUTH_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(AUTH_MOONS))

## Modules ipparse/ (découverte automatique, exclude examples)
IPPARSE_MOONS := $(shell find $(SRC)/ipparse -name '*.moon' 2>/dev/null | grep -v examples)
IPPARSE_LUAS  := $(patsubst $(SRC)/%.moon,$(LUA)/%.lua,$(IPPARSE_MOONS))

.PHONY: all clean check test test-ndpi test-openwrt test-env test-env-down test-env-nuke test-e2e test-e2e-ci test-kvm run reload update-lists make-secret logs help debug-env

all: $(LUA)/parse $(LUAS) $(FILTER_LUAS) $(AUTH_LUAS) $(IPPARSE_LUAS) install-owrt.lua
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

## Environnement libvirt 3 VMs (client → filtre OpenWrt → DNS).
## Premier run : télécharge Debian + OpenWrt (~500 Mo), injecte la clé
## SSH dans l'image OpenWrt (sudo requis pour losetup/mount), démarre les
## VMs et attend la connectivité SSH du filtre. ~5 min le premier coup,
## ~30 s les suivants.
test-env:
	bash libvirt/custos-libvirt.sh ensure
	bash libvirt/custos-libvirt.sh start
	@echo ""
	@bash libvirt/custos-libvirt.sh show

## Arrête les VMs sans les supprimer (les conserve pour relance rapide).
test-env-down:
	bash libvirt/custos-libvirt.sh stop

## Supprime VMs, réseaux, cloud-init ISOs et images de base. Scratch complet.
test-env-nuke:
	bash libvirt/custos-libvirt.sh nuke

## Suite E2E complète : déploie custos sur le filtre et exécute la matrice
## de tests depuis le client. Prérequis : make test-env.
test-e2e: all
	@bash libvirt/custos-libvirt.sh filter-ip >/dev/null 2>&1 \
	  || (echo "ERREUR : environnement non démarré. Exécute d'abord: make test-env"; exit 1)
	$(MOONC) -o tests/test_e2e.lua tests/test_e2e.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_e2e.lua

## Exécute test-e2e avec sortie log dans tmp/ (utile pour CI)
test-e2e-ci: all
	@mkdir -p tmp
	@bash libvirt/custos-libvirt.sh filter-ip >/dev/null 2>&1 \
	  || (echo "ERREUR : environnement non démarré"; exit 1)
	$(MOONC) -o tests/test_e2e.lua tests/test_e2e.moon
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) tests/test_e2e.lua 2>&1 | tee tmp/test-e2e.log

## Suite E2E KVM exhaustive (plus de tests que test-e2e)
## Prérequis : make test-env (environnement libvirt démarré)
test-kvm: all
	@bash libvirt/custos-libvirt.sh filter-ip >/dev/null 2>&1 \
	  || (echo "ERREUR : environnement non démarré. Exécute d'abord: make test-env"; exit 1)
	LUA_PATH="$(LUA)/?.lua;$(LUA)/?/init.lua;;" \
	  $(LUAJIT) lua/test_kvm.lua

## Lance l'outil de diagnostic libvirt
debug-env:
	@bash libvirt/debug.sh $(ARGS)

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
	@echo "  test-env     - Crée/démarre l'environnement libvirt 3 VMs pour E2E"
	@echo "  test-env-down- Arrête les VMs (conserve les disques)"
	@echo "  test-env-nuke- Supprime VMs, réseaux, images (scratch)"
	@echo "  test-e2e     - Suite E2E complète (requiert test-env déjà démarré)"
	@echo "  test-e2e-ci  - Suite E2E avec logs dans tmp/test-e2e.log"
	@echo "  test-kvm     - Suite E2E KVM exhaustive (requiert test-env)"
	@echo "  debug-env    - Outil de diagnostic libvirt (Usage: make debug-env ARGS=logs)"
	@echo "  run          - Lance le superviseur (root requis)"
	@echo "  clean        - Nettoie les fichiers compilés"
	@echo "  make-secret  - Génère un hash PBKDF2-SHA256 pour cfg/secrets (USER=, PASS=)"
	@echo "  update-lists - Télécharge et compile les listes de domaines"
	@echo "  logs         - Affiche les logs en temps réel"
	@echo "  help         - Affiche cette aide"
