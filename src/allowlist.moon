-- src/allowlist.moon
-- Table des qnames autorisés.
-- Correspondance par suffixe, insensible à la casse.
-- Rechargeable à chaud via SIGHUP sans redémarrer le worker.

{ :libc, :ffi } = require "ffi_defs"
{ :ALLOWED_DOMAINS } = require "config"
{ :log_info } = require "log"

-- ── Construction de l'index ──────────────────────────────────────
-- On stocke les domaines dans une table Lua inversée pour lookup O(1)
-- sur le suffixe exact. La correspondance sous-domaine est gérée dans
-- is_allowed() par itération sur les longueurs possibles — le nombre
-- de labels d'un nom DNS est borné à ~127, soit négligeable en pratique.

allowed_set = {}

build_index = (domains) ->
  t = {}
  for _, d in ipairs domains
    t[d\lower!] = true
  t

allowed_set = build_index ALLOWED_DOMAINS

-- ── Vérification ─────────────────────────────────────────────────
-- Retourne true si qname (ou un de ses ancêtres) est dans la liste.
-- Exemples :
--   is_allowed("www.github.com")  → true  (suffixe "github.com" autorisé)
--   is_allowed("github.com")      → true  (exact match)
--   is_allowed("evil.com")        → false
is_allowed = (qname) ->
  name = qname\lower!

  -- Test exact d'abord
  return true if allowed_set[name]

  -- Test des suffixes : on retire un label à chaque itération.
  -- find() avec plain=true (3ème argument booléen) pour chercher un '.' littéral.
  -- Sans plain=true, '.' est un pattern Lua qui matche n'importe quel caractère.
  pos = name\find ".", 1, true
  while pos
    suffix = name\sub pos + 1
    return true if allowed_set[suffix]
    pos = name\find ".", pos + 1, true

  false

-- ── Rechargement SIGHUP ──────────────────────────────────────────
-- Installe un handler SIGHUP qui reconstruit l'index depuis config.moon.
-- Note : en LuaJIT, les signal handlers C ne peuvent pas appeler du Lua
-- directement. On utilise un flag global testé dans la boucle principale.

reload_requested = false

-- Handler C minimaliste : positionne un flag (safe depuis un handler signal)
-- On utilise ffi.cast pour créer un pointeur de fonction C.
sighup_handler = ffi.cast "sighandler_t", (sig) ->
  reload_requested = true

libc.signal 1, sighup_handler   -- SIGHUP = 1

-- Appelé depuis la boucle principale avant chaque paquet
check_reload = ->
  if reload_requested
    reload_requested = false
    -- Recharge config (invalide le cache require via package.loaded)
    package.loaded["config"] = nil
    ok, new_cfg = pcall require, "config"
    if ok
      allowed_set = build_index new_cfg.ALLOWED_DOMAINS
      log_info { action: "allowlist_reloaded", count: #new_cfg.ALLOWED_DOMAINS }
    else
      log_info { action: "allowlist_reload_failed", err: tostring new_cfg }

{ :is_allowed, :check_reload, :allowed_set }
