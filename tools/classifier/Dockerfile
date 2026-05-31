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

# classifier.moon requiert ffi/ffi_xxhash → il doit tourner sous LuaJIT (pas le
# `moon` lua5.1 de luarocks). On le précompile en .lua et on l'exécute via luajit.
RUN moonc -o /opt/custos/tools/classifier/classifier.lua \
          /opt/custos/tools/classifier/classifier.moon

# Le script trouve le lua/ compilé via CUSTOS_LUA.
ENV CUSTOS_LUA=/opt/custos/lua

# Répertoire de travail : on y monte le dépôt de listes (volume) et le fichier
# de domaines d'entrée.
WORKDIR /work

ENTRYPOINT ["luajit", "/opt/custos/tools/classifier/classifier.lua"]
