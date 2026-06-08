-- tests/unit/auth/token_grace_period_spec.moon
-- Régression : le cookie custos_session expire strictement à now + idle_timeout.
-- Quand un ping est retardé par le navigateur (file d'attente, throttling
-- background), le token arrive au serveur après expiration et est rejeté 401.
-- Fix : le token a une durée de vie de idle_timeout + token_grace_period,
-- tandis que la session (fichier + nft) reste à idle_timeout.

token = require "auth.token"

KEY = token.load_key "tmp/token_grace_spec.key"
BASE_TIME = 1780919758

describe "token grace period", ->
  original_os_time = os.time

  after_each ->
    os.time = original_os_time

  it "token avec grace period reste valide pendant la marge", ->
    os.time = -> BASE_TIME
    tok = token.generate "user", "alice@test.lan", "aa:bb:cc:dd:ee:ff",
      BASE_TIME + 10 + 5, KEY  -- idle=10, grace=5

    os.time = -> BASE_TIME + 12  -- après idle (10) mais dans la grace (15)
    p, err = token.verify tok, KEY
    assert.is_not_nil p, "token devrait être valide dans la grace period"
    assert.is_nil err

  it "token avec grace period invalide après la marge totale", ->
    os.time = -> BASE_TIME
    tok = token.generate "user", "alice@test.lan", "aa:bb:cc:dd:ee:ff",
      BASE_TIME + 10 + 5, KEY

    os.time = -> BASE_TIME + 16  -- après idle + grace (15)
    p, err = token.verify tok, KEY
    assert.is_nil p
    assert.equals "token expiré", err

  it "token sans grace period invalide immédiatement après idle", ->
    os.time = -> BASE_TIME
    tok = token.generate "user", "alice@test.lan", "aa:bb:cc:dd:ee:ff",
      BASE_TIME + 10, KEY  -- pas de grace

    os.time = -> BASE_TIME + 11
    p, err = token.verify tok, KEY
    assert.is_nil p
    assert.equals "token expiré", err
