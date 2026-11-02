-- src/lib/os_exec.moon
-- Normalisation du retour de `os.execute` compatible Lua 5.1 et Lua 5.2+.
--
-- Lua 5.1 / LuaJIT sans LUA52COMPAT : `os.execute` renvoie le code de sortie
--   numérique (0 = succès, ≠ 0 = échec).
-- Lua 5.2+ / LuaJIT compilé avec LUA52COMPAT (ex. luajit d'Ubuntu 26.04) :
--   `os.execute` renvoie `true, "exit", 0` en cas de succès et
--   `nil, "exit", code` (ou `nil, "signal", sig`) en cas d'échec.
--
-- Tester `ret == 0` seul est donc faux sur la seconde sémantique : un succès
-- (`true`) y est traité comme un échec.

--- Indique si le retour de `os.execute` correspond à un succès.
-- @tparam number|boolean|nil ret Retour (première valeur) de `os.execute`
-- @treturn boolean true si la commande a réussi
exec_ok = (ret) ->
  ret == 0 or ret == true

{ :exec_ok }
