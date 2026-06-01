# tools/classifier/Dockerfile
#
# Image autonome pour classifier.moon : classification IA de domaines + détection
# des domaines tiers via Playwright + compilation des listes .bin custos.
#
# Le contexte de build DOIT être la racine du dépôt custos :
#   docker build -f tools/classifier/Dockerfile -t custos-classifier .
#
# L'image embarque le lua/ compilé du projet (ffi_xxhash, filter.lib.parse_domains)
# afin que la génération .bin soit octet-pour-octet identique à src/filter/updater.moon.

# Base Playwright Python : Chromium + dépendances navigateur déjà installés.
FROM mcr.microsoft.com/playwright/python:v1.49.0-noble

# Outils Lua/MoonScript + xxhash + git + curl.
# build-essential + lua5.1-dev : luarocks compile lpeg (dépendance de moonscript)
# depuis les sources, donc gcc et les en-têtes Lua sont nécessaires.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        luajit luarocks libxxhash0 curl git ca-certificates make \
        build-essential lua5.1 liblua5.1-0-dev && \
    rm -rf /var/lib/apt/lists/*

# MoonScript via luarocks (fournit `moonc` pour compiler .moon → .lua au build).
RUN luarocks install moonscript

# Copie du dépôt et compilation du runtime lua/ (nécessaire à compile_bin).
WORKDIR /opt/custos
COPY . /opt/custos/
RUN make all

# classifier/simplifier requièrent ffi/ffi_xxhash → ils doivent tourner sous
# LuaJIT (pas le `moon` lua5.1 de luarocks). On précompile tous les modules
# MoonScript de l'outil en .lua et on les exécute via luajit.
RUN for m in common descriptions simplify_lib simplify classifier simplifier; do \
        moonc -o /opt/custos/tools/classifier/$m.lua \
              /opt/custos/tools/classifier/$m.moon; \
    done

# Le script trouve le lua/ compilé via CUSTOS_LUA.
ENV CUSTOS_LUA=/opt/custos/lua

# Répertoire de travail : on y monte le dépôt de listes (volume) et le fichier
# de domaines d'entrée.
WORKDIR /work

# Entrypoint par défaut : classifier. Pour lancer le simplifier :
#   docker run --rm --entrypoint luajit … custos-classifier \
#     /opt/custos/tools/classifier/simplifier.lua [<list-name>] [options]
ENTRYPOINT ["luajit", "/opt/custos/tools/classifier/classifier.lua"]
