-- tests/unit/auth/challenge_login_spec.moon
-- Tests d'intégration des handlers du flux challenge-réponse :
-- handle_challenge, handle_login (voie challenge + repli plaintext),
-- handle_password_change.

token = require "auth.token"
credentials = require "auth.credentials"
{ :handle_challenge, :handle_login, :handle_password_change, :handle_request,
  :COOKIE_NAME } = require "auth.handlers"

KEY = token.load_key "tmp/challenge_login_spec.key"
MAC = "aa:bb:cc:11:22:33"
IP  = "10.42.0.50"
USER = "alice@test.lan"
PASS = "supersecret"

make_state = ->
  stored = credentials.hash_password PASS
  {
    token_key: KEY
    sessions_file: "tmp/challenge_login_sessions_#{os.time!}_#{math.random 1e6}.lua"
    secrets: { [USER]: stored }
    secrets_path: "tmp/challenge_login_secrets_#{os.time!}_#{math.random 1e6}.txt"
    auth_cfg: { idle_timeout: 300, challenge_ttl: 120 }
    notify_reload: -> true
  }

-- Calcule la réponse comme le ferait le client (PBKDF2 déjà = hash stocké).
client_response = (stored, nonce) ->
  rec = credentials.parse_record stored
  credentials.bin_to_hex credentials.hmac_bin credentials.hex_to_bin(rec.hash_hex), nonce

extract_nonce = (json) -> json\match '"nonce":"([^"]+)"'

req_form = (body) -> { body: body, headers: {} }

after_each_cleanup = (state) ->
  os.remove state.sessions_file
  os.remove state.secrets_path

describe "auth/handlers challenge-réponse", ->
  describe "handle_challenge", ->
    it "renvoie nonce/salt/iter en JSON pour un user connu", ->
      state = make_state!
      status, headers, body = handle_challenge (req_form "user=#{USER}"), IP, MAC, state
      assert.equals 200, status
      assert.equals "application/json", headers["Content-Type"]
      assert.truthy extract_nonce body
      rec = credentials.parse_record state.secrets[USER]
      assert.truthy body\find rec.salt_hex, 1, true

    it "anti-énumération : réponse pour user inconnu (200 + nonce + salt)", ->
      state = make_state!
      status, _, body = handle_challenge (req_form "user=ghost@test.lan"), IP, MAC, state
      assert.equals 200, status
      assert.truthy extract_nonce body
      assert.truthy body\find '"iter":', 1, true

    it "user manquant → 400", ->
      state = make_state!
      status = handle_challenge (req_form ""), IP, MAC, state
      assert.equals 400, status

  describe "handle_login (voie challenge)", ->
    it "réponse correcte → 200 + cookie de session", ->
      state = make_state!
      _, _, cbody = handle_challenge (req_form "user=#{USER}"), IP, MAC, state
      nonce = extract_nonce cbody
      resp = client_response state.secrets[USER], nonce
      body = "user=#{USER}&nonce=#{nonce}&response=#{resp}"
      status, headers = handle_login (req_form body), IP, MAC, state
      assert.equals 200, status
      assert.truthy headers["Set-Cookie"]\find COOKIE_NAME, 1, true
      after_each_cleanup state

    it "réponse fausse → 401", ->
      state = make_state!
      _, _, cbody = handle_challenge (req_form "user=#{USER}"), IP, MAC, state
      nonce = extract_nonce cbody
      body = "user=#{USER}&nonce=#{nonce}&response=00deadbeef"
      status = handle_login (req_form body), IP, MAC, state
      assert.equals 401, status

    it "nonce falsifié → 401", ->
      state = make_state!
      resp = client_response state.secrets[USER], "x"
      body = "user=#{USER}&nonce=forged.1.aa:bb&response=#{resp}"
      status = handle_login (req_form body), IP, MAC, state
      assert.equals 401, status

    it "user inconnu avec nonce valide → 401 (temps constant)", ->
      state = make_state!
      _, _, cbody = handle_challenge (req_form "user=ghost@test.lan"), IP, MAC, state
      nonce = extract_nonce cbody
      body = "user=ghost@test.lan&nonce=#{nonce}&response=deadbeef"
      status = handle_login (req_form body), IP, MAC, state
      assert.equals 401, status

  describe "handle_login (repli plaintext)", ->
    it "accepté si allow_plaintext_login (mot de passe correct)", ->
      state = make_state!
      state.auth_cfg.allow_plaintext_login = true
      status, headers = handle_login (req_form "user=#{USER}&password=#{PASS}"), IP, MAC, state
      assert.equals 200, status
      assert.truthy headers["Set-Cookie"]
      after_each_cleanup state

    it "refusé si allow_plaintext_login = false", ->
      state = make_state!
      state.auth_cfg.allow_plaintext_login = false
      status = handle_login (req_form "user=#{USER}&password=#{PASS}"), IP, MAC, state
      assert.equals 401, status

    it "défaut (clé absente) = autorisé", ->
      state = make_state!
      state.auth_cfg.allow_plaintext_login = nil
      status = handle_login (req_form "user=#{USER}&password=#{PASS}"), IP, MAC, state
      assert.equals 200, status
      after_each_cleanup state

  describe "routage (handle_request)", ->
    valid_cookie = -> token.generate "user", USER, MAC, os.time! + 300, KEY

    it "GET / sans session → page de login", ->
      state = make_state!
      status, _, body = handle_request { path: "/", method: "GET", headers: {} }, IP, MAC, state
      assert.equals 200, status
      assert.truthy body\find "login-form", 1, true

    it "GET / avec session valide → page de succès", ->
      state = make_state!
      -- créer la session en base pour la MAC
      sessions = require("auth.sessions")
      s = sessions.load_sessions state.sessions_file
      sessions.add_session s, MAC, IP, USER, os.time! + 300
      sessions.write_sessions s, state.sessions_file
      req = { path: "/", method: "GET", headers: { cookie: "#{COOKIE_NAME}=#{valid_cookie!}" } }
      status, _, body = handle_request req, IP, MAC, state
      assert.equals 200, status
      assert.truthy body\find "Connexion réussie", 1, true
      after_each_cleanup state

    it "GET /password sans session → 302", ->
      state = make_state!
      status, headers = handle_request { path: "/password", method: "GET", headers: {} }, IP, MAC, state
      assert.equals 302, status
      assert.equals "/", headers["Location"]

    it "GET /password avec session → formulaire (ancien + nouveau)", ->
      state = make_state!
      req = { path: "/password", method: "GET", headers: { cookie: "#{COOKIE_NAME}=#{valid_cookie!}" } }
      status, _, body = handle_request req, IP, MAC, state
      assert.equals 200, status
      assert.truthy body\find "password-form", 1, true
      assert.truthy body\find "oldpassword", 1, true

    it "GET /register → formulaire d'inscription", ->
      state = make_state!
      status, _, body = handle_request { path: "/register", method: "GET", headers: {} }, IP, MAC, state
      assert.equals 200, status
      assert.truthy body\find "register-form", 1, true

    it "POST /challenge routé", ->
      state = make_state!
      status = handle_request { path: "/challenge", method: "POST", body: "user=#{USER}", headers: {} }, IP, MAC, state
      assert.equals 200, status

  describe "handle_password_change", ->
    valid_cookie = -> token.generate "user", USER, MAC, os.time! + 300, KEY
    cookie_hdr = -> { cookie: "#{COOKIE_NAME}=#{valid_cookie!}" }

    -- Récupère un nonce via /challenge (replié sur l'utilisateur de la session).
    fresh_nonce = (state) ->
      _, _, cbody = handle_challenge { body: "", headers: cookie_hdr! }, IP, MAC, state
      extract_nonce cbody

    new_record_parts = ->
      newrec = credentials.hash_password "brandnew123"
      algo, iter, salt_hex, hash_hex = newrec\match "^([^:]+):(%d+):([0-9a-f]+):([0-9a-f]+)$"
      iter, salt_hex, hash_hex

    it "sans cookie → 401", ->
      state = make_state!
      status = handle_password_change { body: "salt=aa&iter=10000&hash=bb", headers: {} }, IP, MAC, state
      assert.equals 401, status

    it "change le mot de passe (ancien mot de passe correct)", ->
      state = make_state!
      credentials.set_record USER, state.secrets[USER], state.secrets_path
      nonce = fresh_nonce state
      old_resp = client_response state.secrets[USER], nonce
      iter, salt_hex, hash_hex = new_record_parts!
      req = {
        body: "nonce=#{nonce}&response=#{old_resp}&salt=#{salt_hex}&iter=#{iter}&hash=#{hash_hex}"
        headers: cookie_hdr!
      }
      status = handle_password_change req, IP, MAC, state
      assert.equals 200, status
      secrets = credentials.load_secrets state.secrets_path
      assert.is_true credentials.verify_password "brandnew123", secrets[USER]
      after_each_cleanup state

    it "ancien mot de passe incorrect → 401 (et pas de changement)", ->
      state = make_state!
      credentials.set_record USER, state.secrets[USER], state.secrets_path
      nonce = fresh_nonce state
      iter, salt_hex, hash_hex = new_record_parts!
      req = {
        body: "nonce=#{nonce}&response=00deadbeef&salt=#{salt_hex}&iter=#{iter}&hash=#{hash_hex}"
        headers: cookie_hdr!
      }
      status = handle_password_change req, IP, MAC, state
      assert.equals 401, status
      secrets = credentials.load_secrets state.secrets_path
      assert.is_true credentials.verify_password PASS, secrets[USER]
      after_each_cleanup state

    it "champs manquants → 400", ->
      state = make_state!
      req = { body: "salt=aa", headers: cookie_hdr! }
      status = handle_password_change req, IP, MAC, state
      assert.equals 400, status
