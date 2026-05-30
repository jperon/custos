-- tests/unit/classifier_spec.moon
-- Busted spec pour le classifieur de domaines OpenRouter (src/classifier.moon).
-- Charge depuis lua/ (pas de surcharge src/) pour alimenter luacov.
-- L'appel réseau (curl via io.popen) est mocké : aucune requête réelle.

C = require "classifier"

-- Réponse OpenRouter type (contenu en bloc ```json), telle que renvoyée par un
-- modèle « free ». Les guillemets internes sont échappés comme dans le vrai flux.
OPENROUTER_RESPONSE = [[{
  "id": "gen-1",
  "model": "nvidia/nemotron:free",
  "choices": [
    {
      "index": 0,
      "finish_reason": "stop",
      "message": {
        "role": "assistant",
        "content": "```json\n{\n  \"google.com\": [\"moteur_de_recherche\", \"information\"],\n  \"fsspx.news\": [\"information\", \"religieux\"]\n}\n```"
      }
    }
  ],
  "usage": { "total_tokens": 42, "cost": 0 }
}]]

-- Installe un mock de io.popen renvoyant `output` et un close `ok`.
mock_popen = (output, close_ok) ->
  io.popen = (cmd) ->
    {
      read: (self, fmt) -> output
      close: (self) -> close_ok
    }

describe "classifier", ->

  -- ═══════════════════════════════════════════════════════════════════════
  -- JSON : encode / decode
  -- ═══════════════════════════════════════════════════════════════════════

  describe "json_decode", ->
    it "décode un objet imbriqué avec tableaux", ->
      v = C.json_decode '{"a":1,"b":[true,false,null,"x"]}'
      assert.are.equal 1, v.a
      assert.are.equal true, v.b[1]
      assert.are.equal false, v.b[2]
      assert.are.equal C.JSON_NULL, v.b[3]
      assert.are.equal "x", v.b[4]

    it "décode nombres négatifs / flottants / exposants", ->
      v = C.json_decode '[-3, 2.5, 1e3, -1.5e-2]'
      assert.are.equal -3, v[1]
      assert.are.equal 2.5, v[2]
      assert.are.equal 1000, v[3]
      assert.are.equal -0.015, v[4]

    it "gère les échappements de chaîne", ->
      v = C.json_decode '"a\\tb\\nc\\"d\\\\e"'
      assert.are.equal 'a\tb\nc"d\\e', v

    it "décode un échappement unicode \\u (BMP)", ->
      v = C.json_decode '"caf\\u00e9"'
      assert.are.equal "café", v

    it "décode une paire de substitution UTF-16", ->
      -- U+1F600 😀
      v = C.json_decode '"\\ud83d\\ude00"'
      assert.are.equal "\240\159\152\128", v

    it "objet et tableau vides", ->
      assert.are.same {}, C.json_decode "{}"
      assert.are.same {}, C.json_decode "[]"

    it "entrée vide → nil + erreur", ->
      v, err = C.json_decode ""
      assert.is_nil v
      assert.is_string err

    it "chaîne non terminée → nil + erreur", ->
      v, err = C.json_decode '"abc'
      assert.is_nil v
      assert.is_string err

    it "caractère inattendu → nil + erreur", ->
      v, err = C.json_decode "{bad}"
      assert.is_nil v
      assert.is_string err

    it "littéraux tronqués → erreur", ->
      for bad in *{ "tru", "fals", "nul" }
        v, err = C.json_decode bad
        assert.is_nil v, "devrait échouer : #{bad}"
        assert.is_string err

    it "objet : ':' manquant → erreur", ->
      v, err = C.json_decode '{"a" 1}'
      assert.is_nil v
      assert.is_string err

    it "objet : séparateur invalide → erreur", ->
      v, err = C.json_decode '{"a":1 "b":2}'
      assert.is_nil v
      assert.is_string err

    it "tableau : séparateur invalide → erreur", ->
      v, err = C.json_decode '[1 2]'
      assert.is_nil v
      assert.is_string err

    it "tous les échappements simples", ->
      v = C.json_decode '"\\/\\b\\f\\r"'
      assert.are.equal "/\b\f\r", v

    it "unicode 1 octet et 3 octets", ->
      assert.are.equal "A", C.json_decode '"\\u0041"'
      assert.are.equal "€", C.json_decode '"\\u20ac"'

  describe "json_encode", ->
    it "encode un objet (clés triées) et échappe", ->
      out = C.json_encode { b: "x\"y", a: { 1, 2 } }
      assert.are.equal '{"a":[1,2],"b":"x\\"y"}', out

    it "encode booleans / null sentinel", ->
      assert.are.equal "true", C.json_encode true
      assert.are.equal "false", C.json_encode false
      assert.are.equal "null", C.json_encode C.JSON_NULL

    it "roundtrip decode∘encode stable", ->
      src = '{"d.com":["a","b"],"e.org":[]}'
      assert.are.equal src, C.json_encode C.json_decode src

    it "nil et type non sérialisable → null", ->
      assert.are.equal "null", C.json_encode nil
      assert.are.equal "null", C.json_encode (-> nil)

    it "échappe les caractères de contrôle en \\u", ->
      assert.are.equal '"a\\u0001b"', C.json_encode "a\1b"

  -- ═══════════════════════════════════════════════════════════════════════
  -- Construction de la requête
  -- ═══════════════════════════════════════════════════════════════════════

  describe "sh_quote", ->
    it "entoure de quotes simples et échappe les apostrophes", ->
      assert.are.equal "'ab'", C.sh_quote "ab"
      assert.are.equal "'a'\"'\"'b'", C.sh_quote "a'b"

  describe "build_prompt", ->
    it "inclut catégories et domaines", ->
      p = C.build_prompt { "a.com", "b.net" }, { "info", "jeux" }
      assert.is_truthy p\find "info, jeux", 1, true
      assert.is_truthy p\find "a.com, b.net", 1, true

    it "utilise les catégories par défaut si absentes", ->
      p = C.build_prompt { "a.com" }
      assert.is_truthy p\find "moteur_de_recherche", 1, true

  describe "build_payload", ->
    it "produit un JSON valide qui round-trip", ->
      payload = C.build_payload "openrouter/free", 'salut "toi"\nligne2'
      data = C.json_decode payload
      assert.are.equal "openrouter/free", data.model
      assert.are.equal "user", data.messages[1].role
      assert.are.equal 'salut "toi"\nligne2', data.messages[1].content

  describe "build_curl_cmd", ->
    it "contient l'auth, le content-type, le payload et l'endpoint", ->
      cmd = C.build_curl_cmd '{"x":1}', "sk-test", "https://api/x", 30
      assert.is_truthy cmd\find "Authorization: Bearer sk-test", 1, true
      assert.is_truthy cmd\find "Content-Type: application/json", 1, true
      assert.is_truthy cmd\find "https://api/x", 1, true
      assert.is_truthy cmd\find "--max-time 30", 1, true

  -- ═══════════════════════════════════════════════════════════════════════
  -- request : curl mocké via io.popen
  -- ═══════════════════════════════════════════════════════════════════════

  describe "request", ->
    local orig_popen
    before_each -> orig_popen = io.popen
    after_each -> io.popen = orig_popen

    it "sans clé API → nil + erreur", ->
      v, err = C.request "prompt", { api_key: "" }
      assert.is_nil v
      assert.is_string err
      assert.is_truthy err\find "OPENROUTER_API_KEY", 1, true

    it "succès → retourne le corps brut", ->
      mock_popen OPENROUTER_RESPONSE, true
      body, err = C.request "prompt", { api_key: "sk-x" }
      assert.is_nil err
      assert.are.equal OPENROUTER_RESPONSE, body

    it "curl échoue (close nil) → nil + erreur", ->
      mock_popen "", nil
      body, err = C.request "prompt", { api_key: "sk-x" }
      assert.is_nil body
      assert.is_string err

    it "io.popen renvoie nil → nil + erreur", ->
      io.popen = (cmd) -> nil
      body, err = C.request "prompt", { api_key: "sk-x" }
      assert.is_nil body
      assert.is_string err

  -- ═══════════════════════════════════════════════════════════════════════
  -- Analyse de la réponse
  -- ═══════════════════════════════════════════════════════════════════════

  describe "extract_content", ->
    it "extrait le contenu du premier choix", ->
      content, err = C.extract_content OPENROUTER_RESPONSE
      assert.is_nil err
      assert.is_truthy content\find "google.com", 1, true

    it "champ error → nil + message", ->
      v, err = C.extract_content '{"error":{"message":"clé invalide"}}'
      assert.is_nil v
      assert.is_truthy err\find "clé invalide", 1, true

    it "error en chaîne simple → nil + message", ->
      v, err = C.extract_content '{"error":"boom"}'
      assert.is_nil v
      assert.is_truthy err\find "boom", 1, true

    it "JSON invalide → nil + erreur", ->
      v, err = C.extract_content "pas du json"
      assert.is_nil v
      assert.is_string err

    it "sans choices → nil + erreur", ->
      v, err = C.extract_content '{"id":"x"}'
      assert.is_nil v
      assert.is_string err

    it "content non textuel → nil + erreur", ->
      v, err = C.extract_content '{"choices":[{"message":{"content":42}}]}'
      assert.is_nil v
      assert.is_string err

    it "JSON non-objet (nombre) → nil + erreur", ->
      v, err = C.extract_content "42"
      assert.is_nil v
      assert.is_string err

    it "choix sans message → nil + erreur", ->
      v, err = C.extract_content '{"choices":[{"index":0}]}'
      assert.is_nil v
      assert.is_string err

  describe "strip_code_fences", ->
    it "retire un bloc ```json", ->
      assert.are.equal '{"a":1}', C.strip_code_fences '```json\n{"a":1}\n```'

    it "retire un bloc ``` nu", ->
      assert.are.equal '{"a":1}', C.strip_code_fences '```\n{"a":1}\n```'

    it "laisse intact un JSON sans bloc", ->
      assert.are.equal '{"a":1}', C.strip_code_fences '  {"a":1}  '

  describe "parse_classification", ->
    it "parse un contenu cloturé en ```json", ->
      cls, err = C.parse_classification '```json\n{"x.com":["info"]}\n```'
      assert.is_nil err
      assert.are.same { "info" }, cls["x.com"]

    it "rejette un tableau JSON (pas un objet)", ->
      v, err = C.parse_classification '["a","b"]'
      assert.is_nil v
      assert.is_string err

    it "JSON invalide → nil + erreur", ->
      v, err = C.parse_classification "{nope"
      assert.is_nil v
      assert.is_string err

  -- ═══════════════════════════════════════════════════════════════════════
  -- classify : pipeline complet (io.popen mocké)
  -- ═══════════════════════════════════════════════════════════════════════

  describe "classify", ->
    local orig_popen
    before_each -> orig_popen = io.popen
    after_each -> io.popen = orig_popen

    it "domaines vides → nil + erreur", ->
      v, err = C.classify {}, { api_key: "sk-x" }
      assert.is_nil v
      assert.is_string err

    it "succès → table domaine→catégories + meta", ->
      mock_popen OPENROUTER_RESPONSE, true
      result, err, meta = C.classify { "google.com", "fsspx.news" }, { api_key: "sk-x" }
      assert.is_nil err
      assert.are.same { "moteur_de_recherche", "information" }, result["google.com"]
      assert.are.same { "information", "religieux" }, result["fsspx.news"]
      assert.is_truthy meta.raw
      assert.is_truthy meta.content

    it "propage une erreur de request", ->
      mock_popen "", nil
      v, err = C.classify { "a.com" }, { api_key: "sk-x" }
      assert.is_nil v
      assert.is_string err

    it "propage une erreur d'extraction (réponse non-JSON)", ->
      mock_popen "pas du json", true
      v, err = C.classify { "a.com" }, { api_key: "sk-x" }
      assert.is_nil v
      assert.is_string err

    it "propage une erreur de classification (contenu invalide)", ->
      bad = '{"choices":[{"message":{"content":"ceci n\'est pas du json"}}]}'
      mock_popen bad, true
      v, err = C.classify { "a.com" }, { api_key: "sk-x" }
      assert.is_nil v
      assert.is_string err

  -- ═══════════════════════════════════════════════════════════════════════
  -- Helpers CLI
  -- ═══════════════════════════════════════════════════════════════════════

  describe "split_csv", ->
    it "découpe et nettoie", ->
      assert.are.same { "a", "b", "c" }, C.split_csv "a, b ,c"

    it "ignore les éléments vides", ->
      assert.are.same { "a" }, C.split_csv "a,,"

  describe "parse_args", ->
    it "sépare options et domaines", ->
      o = C.parse_args { "--model", "m1", "--timeout", "5", "a.com", "b.net" }
      assert.are.equal "m1", o.model
      assert.are.equal 5, o.timeout
      assert.are.same { "a.com", "b.net" }, o.domains

    it "--categories, --endpoint et --out-dir", ->
      o = C.parse_args { "--categories", "x,y", "--endpoint", "https://api/z", "--out-dir", "tmp/out" }
      assert.are.same { "x", "y" }, o.categories
      assert.are.equal "https://api/z", o.endpoint
      assert.are.equal "tmp/out", o.out_dir

    it "--help", ->
      o = C.parse_args { "--help" }
      assert.is_true o.help

  describe "read_domains", ->
    it "lit, nettoie, ignore vides et commentaires", ->
      lines = { "a.com", "  b.net ", "", "# commentaire", "c.org" }
      i = 0
      fake = {
        lines: (self) -> ->
          i += 1
          lines[i]
      }
      assert.are.same { "a.com", "b.net", "c.org" }, C.read_domains fake

  -- ═══════════════════════════════════════════════════════════════════════
  -- write_lists : écriture des listes par catégorie
  -- ═══════════════════════════════════════════════════════════════════════

  describe "write_lists", ->
    out_dir = "tmp/classifier_test_lists"
    after_each -> os.execute "rm -rf #{out_dir}"

    it "écrit un fichier trié par catégorie", ->
      result = {
        "z.com": { "info", "jeux" }
        "a.com": { "info" }
      }
      written = C.write_lists result, out_dir
      assert.are.equal 2, #written
      fh = io.open "#{out_dir}/info.txt", "r"
      assert.is_truthy fh
      content = fh\read "*a"
      fh\close!
      assert.are.equal "a.com\nz.com\n", content

  -- ═══════════════════════════════════════════════════════════════════════
  -- main : CLI de bout en bout (io.popen + io.write mockés)
  -- ═══════════════════════════════════════════════════════════════════════

  describe "main", ->
    local orig_popen, orig_write, orig_getenv, orig_stdin
    captured = nil
    before_each ->
      orig_popen  = io.popen
      orig_write  = io.write
      orig_getenv = os.getenv
      orig_stdin  = io.stdin
      captured = {}
      io.write = (...) -> captured[#captured + 1] = table.concat { ... }
      os.getenv = (name) -> name == "OPENROUTER_API_KEY" and "sk-x" or orig_getenv name
    after_each ->
      io.popen  = orig_popen
      io.write  = orig_write
      os.getenv = orig_getenv
      io.stdin  = orig_stdin

    it "--help → code 0", ->
      assert.are.equal 0, C.main { "--help" }

    it "classe les domaines passés en arguments → code 0 + JSON émis", ->
      mock_popen OPENROUTER_RESPONSE, true
      code = C.main { "google.com", "fsspx.news" }
      assert.are.equal 0, code
      out = table.concat captured
      decoded = C.json_decode out
      assert.are.same { "moteur_de_recherche", "information" }, decoded["google.com"]

    it "lit les domaines sur stdin si aucun argument", ->
      mock_popen OPENROUTER_RESPONSE, true
      lines = { "google.com", "fsspx.news" }
      i = 0
      io.stdin = {
        lines: (self) -> ->
          i += 1
          lines[i]
      }
      assert.are.equal 0, C.main {}
      assert.is_truthy (table.concat captured)\find "google.com", 1, true

    it "aucun domaine (stdin vide) → code 1", ->
      io.stdin = { lines: (self) -> -> nil }
      assert.are.equal 1, C.main {}

    it "--out-dir écrit les listes → code 0", ->
      mock_popen OPENROUTER_RESPONSE, true
      out_dir = "tmp/classifier_test_main"
      code = C.main { "--out-dir", out_dir, "google.com" }
      assert.are.equal 0, code
      fh = io.open "#{out_dir}/information.txt", "r"
      assert.is_truthy fh
      fh\close!
      os.execute "rm -rf #{out_dir}"

    it "erreur de classification → code 1", ->
      mock_popen "", nil
      assert.are.equal 1, C.main { "a.com" }
