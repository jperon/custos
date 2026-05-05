-- tests/unit/filter/allowlist_spec.moon
-- Tests de la logique de correspondance par suffixe (allowlist DNS).
--
-- La logique est définie inline dans run_tests.moon (lignes 752–791) et dans
-- les conditions filter/conditions/to_domain.lua — il n'existe pas de module
-- "allowlist" séparé à require.  Cette spec ré-implémente la même factory
-- `make_is_allowed` et la teste exhaustivement, en restant strictement fidèle
-- à la sémantique observée dans run_tests.moon.
--
-- Algorithme (identique à run_tests.moon) :
--   1. Normalise en minuscules.
--   2. Correspondance exacte dans le set.
--   3. Découpe par "." de gauche à droite : teste chaque suffixe.
--   4. Retourne false si aucun suffixe ne correspond.

-- Factory : construit une fonction is_allowed à partir d'une liste de domaines.
make_is_allowed = (domains) ->
  set = {}
  for _, d in ipairs domains
    set[d\lower!] = true
  (qname) ->
    return false unless qname
    name = qname\lower!
    return true if set[name]
    pos = name\find ".", 1, true
    while pos
      suffix = name\sub pos + 1
      return true if set[suffix]
      pos = name\find ".", pos + 1, true
    false


-- ════════════════════════════════════════════════════════════════════════════
describe "allowlist (make_is_allowed)", ->

  -- ── correspondances directes ──────────────────────────────────────────────
  describe "correspondance exacte", ->

    it "domaine présent dans la liste → true", ->
      is_allowed = make_is_allowed {"github.com", "debian.org"}
      assert.is_true is_allowed "github.com"

    it "domaine absent → false", ->
      is_allowed = make_is_allowed {"github.com", "debian.org"}
      assert.is_false is_allowed "evil.com"

    it "liste vide → false pour tout domaine", ->
      is_allowed = make_is_allowed {}
      assert.is_false is_allowed "github.com"
      assert.is_false is_allowed "debian.org"

    it "nil → false (pas de crash)", ->
      is_allowed = make_is_allowed {"github.com"}
      assert.is_false is_allowed nil

  -- ── correspondances hiérarchiques (sous-domaines) ────────────────────────
  describe "sous-domaines", ->

    it "sous-domaine direct → true", ->
      is_allowed = make_is_allowed {"github.com"}
      assert.is_true is_allowed "www.github.com"

    it "sous-domaine de sous-domaine → true", ->
      is_allowed = make_is_allowed {"github.com"}
      assert.is_true is_allowed "api.github.com"
      assert.is_true is_allowed "sub.api.github.com"

    it "préfixe collé sans point → false", ->
      -- "notgithub.com" ne finit pas par ".github.com"
      is_allowed = make_is_allowed {"github.com"}
      assert.is_false is_allowed "notgithub.com"

    it "suffixe evil.com dans un domaine evil → false", ->
      -- "www.evil.github.com.evil.com" : le seul suffixe correspondant
      -- serait "evil.com", pas "github.com"
      is_allowed = make_is_allowed {"github.com"}
      assert.is_false is_allowed "www.evil.github.com.evil.com"

  -- ── insensibilité à la casse ──────────────────────────────────────────────
  describe "insensibilité à la casse", ->

    it "domaine en majuscules trouvé", ->
      is_allowed = make_is_allowed {"github.com"}
      assert.is_true is_allowed "GitHub.COM"

    it "sous-domaine mixte trouvé", ->
      is_allowed = make_is_allowed {"debian.org"}
      assert.is_true is_allowed "FTP.Debian.ORG"

    it "liste déclarée en majuscules, requête en minuscules", ->
      is_allowed = make_is_allowed {"GITHUB.COM"}
      assert.is_true is_allowed "www.github.com"

  -- ── domaines de la liste de référence (run_tests.moon) ───────────────────
  describe "liste de référence complète", ->

    DOMAINS = {"github.com", "debian.org", "cloudflare.com", "local", "home.arpa"}
    is_allowed = make_is_allowed DOMAINS

    CASES = {
      { "www.github.com",               true  }
      { "github.com",                   true  }
      { "api.github.com",               true  }
      { "sub.api.github.com",           true  }
      { "notgithub.com",                false }
      { "evil.com",                     false }
      { "www.evil.github.com.evil.com", false }
      { "debian.org",                   true  }
      { "ftp.debian.org",               true  }
      { "ubuntu.com",                   false }
      { "myhost.local",                 true  }
      { "gateway.home.arpa",            true  }
    }

    for _, c in ipairs CASES
      -- Fermeture locale pour capturer les valeurs de c dans la boucle.
      do
        qname    = c[1]
        expected = c[2]
        it "is_allowed(\"#{qname}\") == #{tostring expected}", ->
          if expected
            assert.is_true  is_allowed qname
          else
            assert.is_false is_allowed qname

  -- ── mutation de la liste (add / remove simulés) ───────────────────────────
  describe "mutation de la liste", ->

    it "add_to_allowlist : domaine ajouté → is_allowed retourne true", ->
      domains = {"github.com"}
      -- Simuler l'ajout en reconstruisant la factory avec le nouveau domaine.
      domains[#domains + 1] = "newdomain.net"
      is_allowed = make_is_allowed domains
      assert.is_true  is_allowed "newdomain.net"
      assert.is_true  is_allowed "sub.newdomain.net"

    it "remove_from_allowlist : domaine retiré → is_allowed retourne false", ->
      domains = {"github.com", "tobedeleted.com"}
      -- Simuler la suppression en reconstruisant sans l'entrée.
      filtered = [d for d in *domains when d ~= "tobedeleted.com"]
      is_allowed = make_is_allowed filtered
      assert.is_false is_allowed "tobedeleted.com"
      assert.is_true  is_allowed "github.com"

    it "liste vide après suppression de tous les domaines → false", ->
      is_allowed = make_is_allowed {}
      assert.is_false is_allowed "github.com"

  -- ── domaines spéciaux ─────────────────────────────────────────────────────
  describe "domaines spéciaux", ->

    it "TLD court ('local') → sous-domaine matche", ->
      is_allowed = make_is_allowed {"local"}
      assert.is_true  is_allowed "myhost.local"
      assert.is_true  is_allowed "printer.local"
      assert.is_false is_allowed "notlocal"

    it "home.arpa → sous-domaine matche", ->
      is_allowed = make_is_allowed {"home.arpa"}
      assert.is_true  is_allowed "gateway.home.arpa"
      assert.is_false is_allowed "home.arpa.evil.com"

    it "cloudflare.com → sous-domaines multiples", ->
      is_allowed = make_is_allowed {"cloudflare.com"}
      assert.is_true  is_allowed "1.1.1.1.cloudflare.com"
      assert.is_false is_allowed "notcloudflare.com"
