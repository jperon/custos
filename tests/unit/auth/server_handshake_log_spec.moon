-- tests/unit/auth/server_handshake_log_spec.moon
-- Régression : `hs_err` était assignée dans la boucle de handshake de
-- handle_client (donc locale à cette boucle en MoonScript) puis lue après :
-- la lecture compilait en globale (nil), si bien que le log
-- `server_tls_handshake_failed` perdait toujours l'erreur réelle
-- (« max attempts reached » à la place).
--
-- handle_client n'est pas exporté : on le déclenche via dispatch_connection
-- (dont le paramètre fork_fn est injectable) avec un fork_fn qui exécute le
-- handler dans le processus de test.

-- Recharge auth.server en substituant `ssl` et `log`, puis restaure
-- package.loaded immédiatement : le module capture ses dépendances au
-- chargement, et les autres specs du même processus gardent les vraies.
-- auth.server est d'abord chargé avec le vrai `log` pour que ses dépendances
-- (auth.handlers, …) capturent les vraies fonctions ; seule la ré-exécution de
-- auth.server voit les stubs.
reload_server_with_stubs = (ssl_stub, log_stub) ->
  require "auth.server"
  saved_server = package.loaded["auth.server"]
  saved_ssl    = package.loaded["auth.ffi_wolfssl"]
  saved_log    = package.loaded["log"]
  package.loaded["auth.ffi_wolfssl"] = ssl_stub
  package.loaded["log"]              = log_stub
  package.loaded["auth.server"]      = nil
  server = require "auth.server"
  package.loaded["auth.server"]      = saved_server
  package.loaded["auth.ffi_wolfssl"] = saved_ssl
  package.loaded["log"]              = saved_log
  server

describe "auth/server handshake log", ->

  it "conserve l'erreur du handshake dans server_tls_handshake_failed", ->
    entries = {}
    log_stub = setmetatable({}, { __index: require "log" })
    for level in *{ "log_info", "log_warn", "log_error", "log_debug" }
      log_stub[level] = (thunk) -> entries[#entries + 1] = thunk!

    tls_client = {
      dohandshake: -> false, "tls_error"
      close: ->
    }
    client = {
      fd: 7
      getsockname: -> "127.0.0.1"
      settimeout: ->
      setoption: ->
      close: ->
    }
    ssl_stub = {
      wrap: (c, ctx) -> tls_client, nil
    }

    server = reload_server_with_stubs ssl_stub, log_stub
    state = { static_tls_ctx: {} }
    -- fork_fn synchrone : exécute handle_client dans le processus courant.
    fork_fn = (name, fn, arg, opts) -> fn arg

    server.dispatch_connection client, "127.0.0.1", state, fork_fn

    warn = nil
    for e in *entries
      warn = e if e.action == "server_tls_handshake_failed"
    assert.is_not_nil warn, "server_tls_handshake_failed doit être loggé"
    assert.equals "tls_error", warn.err
