#!/usr/bin/env bash
# tools/check_globals.sh — détecte les lectures de globales non déclarées.
#
# MoonScript rend locale au bloc toute variable assignée dans un bloc : lue
# ensuite hors de ce bloc (ou hors de la fonction qui l'assigne), elle compile
# en lecture de globale — donc nil, sans aucune erreur de compilation. Ce
# contrôle balaie le bytecode LuaJIT du Lua compilé (lua/**.lua) et échoue sur
# toute lecture de globale hors liste blanche. La liste des globales standard
# est explicite : une nouvelle globale lue par erreur est signalée, pas tolérée.
#
# Usage :
#   tools/check_globals.sh                  # tout lua/ (hors périmètres exclus)
#   tools/check_globals.sh lua/foo.lua ...  # fichiers ciblés
#
# Sortie : une ligne « GLOBALE <fichier> <nom> » par lecture inconnue, puis un
# résumé sur stderr ; code retour 1 s'il y en a au moins une.
#
# Périmètres exclus (comme le balayage qui a motivé ce contrôle) :
#   - lua/ipparse/     : sous-module moontastik (code amont non modifiable ici) ;
#   - lua/moonscript/, lua/moon/ : runtime MoonScript embarqué (tiers).
set -u

LUAJIT="${LUAJIT:-luajit}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

# Globales légitimes : base Lua 5.1, bibliothèques standard, extensions
# LuaJIT (bit et jit sont fournies en globales par LuaJIT) et arg (arguments
# de ligne de commande). `ffi` n'y figure PAS : LuaJIT ne l'expose pas en
# globale, donc un fichier qui lit `ffi` sans le requérir a exactement le bug
# que ce contrôle recherche.
STANDARD_GLOBALS='
  _G _VERSION arg
  assert collectgarbage dofile error gcinfo getfenv getmetatable ipairs
  load loadfile loadstring module newproxy next pairs pcall print
  rawequal rawget rawset require select setfenv setmetatable tonumber
  tostring type unpack xpcall
  coroutine debug io math os package string table
  bit jit
'
declare -A STANDARD
for g in $STANDARD_GLOBALS; do
  STANDARD[$g]=1
done

files=("$@")
if [ ${#files[@]} -eq 0 ]; then
  if [ ! -d lua ]; then
    echo "check_globals : dossier lua/ absent (lancer make all d'abord)." >&2
    exit 2
  fi
  while IFS= read -r f; do
    files+=("$f")
  done < <(
    find lua -name '*.lua' \
      ! -path 'lua/ipparse/*' \
      ! -path 'lua/moonscript/*' \
      ! -path 'lua/moon/*' | sort
  )
fi

rc=0
found=0
for f in "${files[@]}"; do
  # `luajit -bl` liste le bytecode sur stdout quand aucun fichier de sortie
  # n'est donné. Les lignes GGET portent le nom de la globale entre guillemets.
  if ! listing="$("$LUAJIT" -bl "$f" 2>/dev/null)"; then
    echo "ERREUR  $f : impossible de lister le bytecode" >&2
    rc=1
    continue
  fi
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    if [ -z "${STANDARD[$name]:-}" ]; then
      echo "GLOBALE $f $name"
      found=$((found + 1))
      rc=1
    fi
  done < <(
    printf '%s\n' "$listing" \
      | sed -n 's/.*GGET[^"]*"\([A-Za-z_][A-Za-z_0-9]*\)".*/\1/p' \
      | sort -u
  )
done

if [ "$rc" -ne 0 ]; then
  echo "check_globals : $found globale(s) non déclarée(s) lue(s)." >&2
  exit 1
fi
echo "check_globals : OK (${#files[@]} fichiers, aucune globale inconnue)"
