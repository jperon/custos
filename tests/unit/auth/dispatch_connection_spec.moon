-- tests/unit/auth/dispatch_connection_spec.moon
-- Vérifie que dispatch_connection isole un échec transitoire de fork() :
-- la connexion est fermée et le serveur continue (pas d'erreur propagée).
-- Régression : un fork() EAGAIN/ENOMEM ne doit jamais tuer le worker AUTH.

{ :dispatch_connection } = require "auth.server"

make_client = ->
  closed = { v: false }
  client = {
    fd: 42
    close: => closed.v = true
    getsockname: => "203.0.113.1"
  }
  client, closed

describe "auth/server dispatch_connection", ->

  it "retourne true et n'émet pas d'erreur quand fork réussit", ->
    client, closed = make_client!
    fork_calls = {}
    fork_ok = nil
    ok, err = pcall ->
      fork_ok = dispatch_connection client, "203.0.113.1", {}, (name, fn, arg, opts) ->
        fork_calls[#fork_calls + 1] = name
        12345  -- pid simulé
    assert.is_true ok, err
    assert.is_true fork_ok
    assert.equals 1, #fork_calls
    assert.equals "AUTH-conn", fork_calls[1]
    assert.is_true closed.v  -- le parent ferme toujours sa copie du fd

  it "n'éclate pas si fork() échoue (EAGAIN/ENOMEM) et ferme la connexion", ->
    client, closed = make_client!
    fork_ok = nil
    ok, err = pcall ->
      fork_ok = dispatch_connection client, "203.0.113.1", {}, ->
        error "fork() échoué pour AUTH-conn"
    -- L'appel ne doit PAS propager l'erreur (sinon le serveur crasherait)
    assert.is_true ok, "dispatch_connection ne doit pas propager l'erreur de fork : #{err}"
    assert.is_false fork_ok
    -- La connexion doit être fermée malgré l'échec
    assert.is_true closed.v

  it "ferme la connexion même si close() est appelé après un fork échoué", ->
    -- close() qui lui-même lève ne doit pas faire échouer dispatch_connection
    client = { fd: 7, close: => error "close boom" }
    ok = pcall ->
      dispatch_connection client, "203.0.113.1", {}, -> error "fork boom"
    assert.is_true ok
