-- tests/unit/auth/register_spec.moon
-- Tests de auth.handlers.handle_register : voie « hachage côté client »,
-- repli plaintext, validation de l'enregistrement, doublon (409) et échec
-- d'écriture du fichier secrets (500).

credentials = require "auth.credentials"
{ :handle_register } = require "auth.handlers"

USER = "alice@test.lan"
PASS = "supersecret"
SALT = "00112233445566778899aabbccddeeff"
HASH = string.rep "ab", 32
IP   = "10.42.0.50"
MAC  = "aa:bb:cc:11:22:33"

new_state = (opts = {}) ->
  base = "tmp/register_spec_#{os.time!}_#{math.random 1000000}"
  state = {
    token_key:     string.rep "\x42", 32
    secrets:       {}
    secrets_path:  "#{base}_secrets.txt"
    sessions_file: "#{base}_sessions.lua"
    auth_cfg:      { allow_plaintext_login: true }
  }
  state.reload_calls = 0
  state.notify_reload = ->
    state.reload_calls += 1
    true
  for k, v in pairs opts
    state[k] = v
  state

req = (body) -> { method: "POST", path: "/register", headers: {}, body: body }

file_exists = (path) ->
  fh = io.open path, "r"
  fh\close! if fh
  fh != nil

cleanup = (state) ->
  os.remove state.secrets_path
  os.remove state.secrets_path .. ".lock"
  os.remove state.sessions_file
  os.remove state.sessions_file .. ".lock"
  os.remove state.sessions_file .. ".ratelimit"
  os.remove state.sessions_file .. ".ratelimit.lock"

client_hash_body = ->
  "user=#{USER}&salt=#{SALT}&iter=10000&hash=#{HASH}"

describe "auth/handlers handle_register", ->

  describe "voie hachage côté client", ->

    it "inscrit l'utilisateur (200, record écrit, état et reload mis à jour)", ->
      state = new_state!
      status, headers, body = handle_register (req client_hash_body!), IP, MAC, state
      assert.equals 200, status
      assert.equals "text/html; charset=UTF-8", headers["Content-Type"]
      assert.truthy body\find "Compte créé", 1, true
      assert.equals 1, state.reload_calls

      expected = "pbkdf2-sha256:10000:#{SALT}:#{HASH}"
      assert.equals expected, state.secrets[USER]
      secrets = credentials.load_secrets state.secrets_path
      assert.equals expected, secrets[USER]
      cleanup state

    it "refuse un nom d'utilisateur invalide (400) sans écrire de fichier", ->
      state = new_state!
      status, _, body = handle_register (req "user=bob&salt=#{SALT}&iter=10000&hash=#{HASH}"), IP, MAC, state
      assert.equals 400, status
      assert.truthy body\find "courriel invalide", 1, true
      assert.is_nil (io.open state.secrets_path, "r")
      assert.equals 0, state.reload_calls
      cleanup state

    it "refuse un enregistrement invalide (hash non hexadécimal) sans écrire", ->
      state = new_state!
      status, _, body = handle_register (req "user=#{USER}&salt=#{SALT}&iter=10000&hash=zz"), IP, MAC, state
      assert.equals 400, status
      assert.equals "Invalid record", body
      assert.is_false file_exists state.secrets_path
      assert.equals 0, state.reload_calls
      cleanup state

    it "refuse un doublon (409) sans réécrire le fichier ni l'état", ->
      state = new_state!
      state.secrets[USER] = "pbkdf2-sha256:10000:#{SALT}:#{string.rep "cd", 32}"
      status, _, body = handle_register (req client_hash_body!), IP, MAC, state
      assert.equals 409, status
      assert.truthy body\find "déjà pris", 1, true
      assert.is_false file_exists state.secrets_path
      assert.equals "pbkdf2-sha256:10000:#{SALT}:#{string.rep "cd", 32}", state.secrets[USER]
      assert.equals 0, state.reload_calls
      cleanup state

    it "échec set_record (chemin inscriptible inexistant) → 500 sans état modifié", ->
      state = new_state { secrets_path: "/nonexistent/register_spec/secrets.txt" }
      status, _, body = handle_register (req client_hash_body!), IP, MAC, state
      assert.equals 500, status
      assert.is_string body
      assert.is_nil state.secrets[USER]
      assert.equals 0, state.reload_calls

    it "un échec de signal de reload n'empêche pas l'inscription (200)", ->
      state = new_state!
      state.notify_reload = -> false
      status, _, _ = handle_register (req client_hash_body!), IP, MAC, state
      assert.equals 200, status
      assert.is_true file_exists state.secrets_path
      cleanup state

  describe "limitation des inscriptions (register_rate_limit)", ->

    it "refuse la (N+1)e tentative avec 429 + Retry-After sans écrire de compte", ->
      state = new_state!
      state.auth_cfg = { allow_plaintext_login: true, register_rate_limit: 2, register_rate_window: 300 }
      now = 1000
      state.now = -> now
      body = (u) -> "user=#{u}&salt=#{SALT}&iter=10000&hash=#{HASH}"

      s1 = handle_register (req body "u1@test.lan"), IP, MAC, state
      s2 = handle_register (req body "u2@test.lan"), IP, MAC, state
      assert.equals 200, s1
      assert.equals 200, s2
      assert.equals 2, state.reload_calls

      status, headers, resp = handle_register (req body "u3@test.lan"), IP, MAC, state
      assert.equals 429, status
      assert.equals "300", headers["Retry-After"]
      assert.truthy resp\find "Trop de tentatives", 1, true
      assert.equals 2, state.reload_calls
      assert.is_nil state.secrets["u3@test.lan"]
      secrets = credentials.load_secrets state.secrets_path
      assert.is_nil secrets["u3@test.lan"]
      cleanup state

    it "fenêtre expirée → une nouvelle inscription est acceptée", ->
      state = new_state!
      state.auth_cfg = { allow_plaintext_login: true, register_rate_limit: 1, register_rate_window: 300 }
      now = 2000
      state.now = -> now
      body = (u) -> "user=#{u}&salt=#{SALT}&iter=10000&hash=#{HASH}"

      assert.equals 200, (handle_register (req body "v1@test.lan"), IP, MAC, state)
      assert.equals 429, (handle_register (req body "v2@test.lan"), IP, MAC, state)

      now = 2300
      assert.equals 200, (handle_register (req body "v3@test.lan"), IP, MAC, state)
      cleanup state

    it "deux clients distincts ne partagent pas leur compteur", ->
      state = new_state!
      state.auth_cfg = { allow_plaintext_login: true, register_rate_limit: 1, register_rate_window: 300 }
      now = 3000
      state.now = -> now
      body = (u) -> "user=#{u}&salt=#{SALT}&iter=10000&hash=#{HASH}"

      assert.equals 200, (handle_register (req body "w1@test.lan"), IP, MAC, state)
      assert.equals 429, (handle_register (req body "w2@test.lan"), IP, MAC, state)
      assert.equals 200, (handle_register (req body "w3@test.lan"), "10.42.0.51", "aa:bb:cc:11:22:44", state)
      cleanup state

    it "register_rate_limit = 0 désactive la limitation", ->
      state = new_state!
      state.auth_cfg = { allow_plaintext_login: true, register_rate_limit: 0, register_rate_window: 300 }
      state.now = -> 4000
      body = (u) -> "user=#{u}&salt=#{SALT}&iter=10000&hash=#{HASH}"

      for i = 1, 5
        assert.equals 200, (handle_register (req body "x#{i}@test.lan"), IP, MAC, state)
      assert.equals 5, state.reload_calls
      cleanup state

  describe "repli plaintext (JavaScript désactivé)", ->

    it "inscrit l'utilisateur et stocke un hash vérifiable", ->
      state = new_state!
      status, _, body = handle_register (req "user=#{USER}&password=#{PASS}"), IP, MAC, state
      assert.equals 200, status
      assert.truthy body\find "Compte créé", 1, true
      assert.equals 1, state.reload_calls

      secrets = credentials.load_secrets state.secrets_path
      assert.is_true credentials.verify_password PASS, secrets[USER]
      assert.equals secrets[USER], state.secrets[USER]
      cleanup state

    it "refusé si allow_plaintext_login=false (401) sans écriture", ->
      state = new_state { auth_cfg: { allow_plaintext_login: false } }
      status, _, body = handle_register (req "user=#{USER}&password=#{PASS}"), IP, MAC, state
      assert.equals 401, status
      assert.equals "Plaintext registration disabled", body
      assert.is_false file_exists state.secrets_path
      assert.equals 0, state.reload_calls
      cleanup state

    it "champs manquants → 400 sans écriture", ->
      state = new_state!
      status, _, body = handle_register (req "user=#{USER}"), IP, MAC, state
      assert.equals 400, status
      assert.equals "Missing credentials", body
      assert.is_false file_exists state.secrets_path
      cleanup state

    it "doublon → 409 sans réécriture", ->
      state = new_state!
      state.secrets[USER] = credentials.hash_password PASS
      status, _, body = handle_register (req "user=#{USER}&password=#{PASS}"), IP, MAC, state
      assert.equals 409, status
      assert.truthy body\find "déjà pris", 1, true
      assert.is_false file_exists state.secrets_path
      assert.same { [USER]: state.secrets[USER] }, state.secrets
      cleanup state
