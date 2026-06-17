-- tests/unit/auth/challenge_spec.moon
-- Tests du challenge-réponse sans état : nonce signé/borné/lié à la MAC,
-- et salt déterministe anti-énumération.

{ :make_nonce, :verify_nonce, :salt_iter_for } = require "auth.challenge"
credentials = require "auth.credentials"

KEY = ("k")\rep 32
MAC = "AA:BB:CC:DD:EE:FF"

describe "auth/challenge", ->
  describe "make_nonce / verify_nonce", ->
    it "nonce frais accepté pour la même MAC (insensible à la casse)", ->
      n = make_nonce KEY, MAC, 120
      ok = verify_nonce KEY, "aa:bb:cc:dd:ee:ff", n
      assert.is_true ok

    it "rejette une MAC différente", ->
      n = make_nonce KEY, MAC, 120
      ok, err = verify_nonce KEY, "11:22:33:44:55:66", n
      assert.is_false ok
      assert.equals "mac inattendue", err

    it "rejette une signature falsifiée", ->
      n = make_nonce KEY, MAC, 120
      forged = n\sub(1, #n - 4) .. "0000"
      ok, err = verify_nonce KEY, MAC, forged
      assert.is_false ok
      assert.equals "signature invalide", err

    it "rejette un nonce expiré", ->
      n = make_nonce KEY, MAC, -1
      ok, err = verify_nonce KEY, MAC, n
      assert.is_false ok
      assert.equals "nonce expiré", err

    it "rejette un nonce malformé ou absent", ->
      assert.is_false (verify_nonce KEY, MAC, "garbage")
      assert.is_false (verify_nonce KEY, MAC, nil)
      assert.is_false (verify_nonce KEY, MAC, "")

    it "rejette une signature de longueur incorrecte", ->
      ok, err = verify_nonce KEY, MAC, "ab.9999999999.#{MAC}.bb"
      assert.is_false ok
      assert.equals "signature invalide", err

    it "TTL par défaut (sans argument) accepté", ->
      n = make_nonce KEY, MAC
      assert.is_true (verify_nonce KEY, MAC, n)

    it "MAC absente (unknown) cohérente entre génération et vérification", ->
      n = make_nonce KEY, nil
      assert.is_true (verify_nonce KEY, nil, n)

    it "rejette avec une autre clé", ->
      n = make_nonce KEY, MAC, 120
      ok, err = verify_nonce (("x")\rep 32), MAC, n
      assert.is_false ok
      assert.equals "signature invalide", err

  describe "salt_iter_for", ->
    it "renvoie le salt/iter réels pour un user connu", ->
      stored = credentials.hash_password "secret123"
      rec = credentials.parse_record stored
      secrets = { ["alice@x.lan"]: stored }
      si = salt_iter_for secrets, KEY, "alice@x.lan"
      assert.equals rec.salt_hex, si.salt
      assert.equals rec.iter, si.iter

    it "user inconnu → salt factice déterministe (anti-énumération)", ->
      a = salt_iter_for {}, KEY, "ghost@x.lan"
      b = salt_iter_for {}, KEY, "ghost@x.lan"
      assert.equals a.salt, b.salt
      assert.equals credentials.DEFAULT_ITER, a.iter
      assert.equals credentials.DEFAULT_SALT_LEN * 2, #a.salt

    it "salts factices différents pour des users différents", ->
      a = salt_iter_for {}, KEY, "ghost1@x.lan"
      b = salt_iter_for {}, KEY, "ghost2@x.lan"
      assert.not_equals a.salt, b.salt
