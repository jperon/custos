-- tests/unit/auth/token_grace_period_spec.moon
-- Régression : le cookie custos_session expire EXACTEMENT à session_expires
-- (= now + idle_timeout). Il n'y a plus de token_grace_period : cookie et
-- session DNS (fichier + sets nft) partagent la même échéance, ce qui supprime
-- la fenêtre où la page indiquerait « connecté » alors que l'accès DNS a expiré.
-- La tolérance aux pings retardés passe désormais par un idle_timeout plus large.

token = require "auth.token"

KEY = token.load_key "tmp/token_grace_spec.key"
BASE_TIME = 1780919758

describe "cookie expiry unifié (sans grace period)", ->
  original_os_time = os.time

  after_each ->
    os.time = original_os_time

  it "le token reste valide jusqu'à session_expires", ->
    os.time = -> BASE_TIME
    idle_timeout = 300
    session_expires = BASE_TIME + idle_timeout
    -- Le serveur émet token_expires = session_expires (cf. server.moon).
    tok = token.generate "user", "alice@test.lan", "aa:bb:cc:dd:ee:ff",
      session_expires, KEY

    os.time = -> session_expires - 1
    p, err = token.verify tok, KEY
    assert.is_not_nil p, "token valide avant son échéance"
    assert.is_nil err

  it "le token expire exactement à session_expires (pas de marge)", ->
    os.time = -> BASE_TIME
    idle_timeout = 300
    session_expires = BASE_TIME + idle_timeout
    tok = token.generate "user", "alice@test.lan", "aa:bb:cc:dd:ee:ff",
      session_expires, KEY

    os.time = -> session_expires + 1
    p, err = token.verify tok, KEY
    assert.is_nil p, "token invalide dès que la session DNS expire"
    assert.equals "token expiré", err
