-- tests/unit/auth/rate_limit_spec.moon
-- Tests du limiteur d'inscription partagé entre enfants AUTH (auth/rate_limit) :
-- fenêtre fixe, horloge injectée (aucun sleep), indépendance par client,
-- purge des entrées expirées, fichier absent/corrompu, limite 0 et plafond.

{ :check, :key_for, :MAX_ENTRIES, :DEFAULT_LIMIT, :DEFAULT_WINDOW } = require "auth.rate_limit"

BASE = "tmp/rate_limit_spec_#{os.time!}_#{math.random 1000000}"

MAC_A = "aa:bb:cc:00:00:01"
MAC_B = "aa:bb:cc:00:00:02"
IP_A  = "10.42.0.10"
IP_B  = "10.42.0.11"

new_path = ->
  BASE = BASE .. "_x"
  BASE

cleanup = (path) ->
  os.remove path
  os.remove path .. ".lock"

read_file = (path) ->
  fh = io.open path, "r"
  return nil unless fh
  content = fh\read "*a"
  fh\close!
  content

count_entries = (path) ->
  content = read_file path
  return 0 unless content
  n = 0
  for line in content\gmatch "[^\n]+"
    n += 1 if line\match "^[^\t]+\t%d+\t%d+$"
  n

describe "auth/rate_limit", ->

  describe "key_for", ->

    it "privilégie la MAC (normalisée en minuscules)", ->
      assert.equals "mac:aa:bb:cc:00:00:01", key_for MAC_A, IP_A
      assert.equals "mac:aa:bb:cc:00:00:01", key_for "AA:BB:CC:00:00:01", IP_A

    it "retombe sur l'IP si la MAC est inconnue ou absente", ->
      assert.equals "ip:#{IP_A}", key_for "unknown", IP_A
      assert.equals "ip:#{IP_A}", key_for nil, IP_A
      assert.equals "ip:#{IP_A}", key_for "", IP_A

    it "clé de repli partagée si ni MAC ni IP", ->
      assert.equals "unknown", key_for nil, nil

  describe "fenêtre fixe", ->

    it "autorise N tentatives puis refuse la (N+1)e avec le délai restant", ->
      path = new_path!
      now = 1000
      for i = 1, 3
        allowed, retry = check path, key_for(MAC_A, IP_A), 3, 300, now
        assert.is_true allowed
        assert.equals 0, retry
      allowed, retry = check path, key_for(MAC_A, IP_A), 3, 300, now
      assert.is_false allowed
      assert.equals 300, retry
      cleanup path

    it "fenêtre expirée → de nouveau autorisé (horloge injectée)", ->
      path = new_path!
      key = key_for MAC_A, IP_A
      for i = 1, 3
        assert.is_true check path, key, 3, 300, 1000
      assert.is_false check path, key, 3, 300, 1299
      -- reset_at vaut 1300 : à 1300 la fenêtre est expirée
      assert.is_true check path, key, 3, 300, 1300
      assert.is_true check path, key, 3, 300, 1300
      assert.is_true check path, key, 3, 300, 1300
      assert.is_false check path, key, 3, 300, 1300
      cleanup path

    it "deux clients distincts ont des compteurs indépendants", ->
      path = new_path!
      key_a, key_b = key_for(MAC_A, IP_A), key_for(MAC_B, IP_B)
      for i = 1, 3
        assert.is_true check path, key_a, 3, 300, 2000
      assert.is_false check path, key_a, 3, 300, 2000
      assert.is_true check path, key_b, 3, 300, 2000
      cleanup path

    it "purge les entrées expirées à chaque écriture", ->
      path = new_path!
      key_a, key_b = key_for(MAC_A, IP_A), key_for(MAC_B, IP_B)
      for i = 1, 3
        check path, key_a, 3, 300, 1000
      assert.is_true check path, key_b, 3, 300, 1400
      content = read_file path
      assert.is_nil content\find key_a, 1, true
      assert.is_true (content\find key_b, 1, true) != nil
      cleanup path

  describe "robustesse", ->

    it "fichier absent → repart de vide et autorise", ->
      path = new_path!
      os.remove path
      assert.is_true check path, key_for(MAC_A, IP_A), 3, 300, 1000
      cleanup path

    it "fichier corrompu → repart de vide sans planter", ->
      path = new_path!
      fh = assert io.open path, "w"
      fh\write "pas un état valide\n???\n\xff\x00"
      fh\close!
      assert.is_true check path, key_for(MAC_A, IP_A), 2, 300, 1000
      assert.is_true check path, key_for(MAC_A, IP_A), 2, 300, 1000
      assert.is_false check path, key_for(MAC_A, IP_A), 2, 300, 1000
      cleanup path

    it "limite 0 désactive la limitation et n'écrit aucun fichier", ->
      path = new_path!
      for i = 1, 10
        allowed, retry = check path, key_for(MAC_A, IP_A), 0, 300, 1000
        assert.is_true allowed
        assert.equals 0, retry
      assert.is_nil (io.open path, "r")
      cleanup path

    it "plafonne le nombre d'entrées conservées", ->
      path = new_path!
      parts = {}
      for i = 1, MAX_ENTRIES + 10
        parts[#parts + 1] = "mac:bulk#{i}\t1\t9999999999\n"
      fh = assert io.open path, "w"
      fh\write table.concat parts
      fh\close!
      assert.is_true check path, key_for(MAC_A, IP_A), 3, 300, 1000
      assert.is_true count_entries(path) <= MAX_ENTRIES
      cleanup path

  describe "valeurs par défaut", ->

    it "limit/window nil → défauts du schéma (3 / 300)", ->
      assert.equals 3, DEFAULT_LIMIT
      assert.equals 300, DEFAULT_WINDOW
      path = new_path!
      for i = 1, 3
        assert.is_true check path, key_for(MAC_A, IP_A), nil, nil, 1000
      allowed, retry = check path, key_for(MAC_A, IP_A), nil, nil, 1000
      assert.is_false allowed
      assert.equals 300, retry
      cleanup path
