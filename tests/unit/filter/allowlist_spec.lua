local make_is_allowed
make_is_allowed = function(domains)
  local set = { }
  for _, d in ipairs(domains) do
    set[d:lower()] = true
  end
  return function(qname)
    if not (qname) then
      return false
    end
    local name = qname:lower()
    if set[name] then
      return true
    end
    local pos = name:find(".", 1, true)
    while pos do
      local suffix = name:sub(pos + 1)
      if set[suffix] then
        return true
      end
      pos = name:find(".", pos + 1, true)
    end
    return false
  end
end
return describe("allowlist (make_is_allowed)", function()
  describe("correspondance exacte", function()
    it("domaine présent dans la liste → true", function()
      local is_allowed = make_is_allowed({
        "github.com",
        "debian.org"
      })
      return assert.is_true(is_allowed("github.com"))
    end)
    it("domaine absent → false", function()
      local is_allowed = make_is_allowed({
        "github.com",
        "debian.org"
      })
      return assert.is_false(is_allowed("evil.com"))
    end)
    it("liste vide → false pour tout domaine", function()
      local is_allowed = make_is_allowed({ })
      assert.is_false(is_allowed("github.com"))
      return assert.is_false(is_allowed("debian.org"))
    end)
    return it("nil → false (pas de crash)", function()
      local is_allowed = make_is_allowed({
        "github.com"
      })
      return assert.is_false(is_allowed(nil))
    end)
  end)
  describe("sous-domaines", function()
    it("sous-domaine direct → true", function()
      local is_allowed = make_is_allowed({
        "github.com"
      })
      return assert.is_true(is_allowed("www.github.com"))
    end)
    it("sous-domaine de sous-domaine → true", function()
      local is_allowed = make_is_allowed({
        "github.com"
      })
      assert.is_true(is_allowed("api.github.com"))
      return assert.is_true(is_allowed("sub.api.github.com"))
    end)
    it("préfixe collé sans point → false", function()
      local is_allowed = make_is_allowed({
        "github.com"
      })
      return assert.is_false(is_allowed("notgithub.com"))
    end)
    return it("suffixe evil.com dans un domaine evil → false", function()
      local is_allowed = make_is_allowed({
        "github.com"
      })
      return assert.is_false(is_allowed("www.evil.github.com.evil.com"))
    end)
  end)
  describe("insensibilité à la casse", function()
    it("domaine en majuscules trouvé", function()
      local is_allowed = make_is_allowed({
        "github.com"
      })
      return assert.is_true(is_allowed("GitHub.COM"))
    end)
    it("sous-domaine mixte trouvé", function()
      local is_allowed = make_is_allowed({
        "debian.org"
      })
      return assert.is_true(is_allowed("FTP.Debian.ORG"))
    end)
    return it("liste déclarée en majuscules, requête en minuscules", function()
      local is_allowed = make_is_allowed({
        "GITHUB.COM"
      })
      return assert.is_true(is_allowed("www.github.com"))
    end)
  end)
  describe("liste de référence complète", function()
    local DOMAINS = {
      "github.com",
      "debian.org",
      "cloudflare.com",
      "local",
      "home.arpa"
    }
    local is_allowed = make_is_allowed(DOMAINS)
    local CASES = {
      {
        "www.github.com",
        true
      },
      {
        "github.com",
        true
      },
      {
        "api.github.com",
        true
      },
      {
        "sub.api.github.com",
        true
      },
      {
        "notgithub.com",
        false
      },
      {
        "evil.com",
        false
      },
      {
        "www.evil.github.com.evil.com",
        false
      },
      {
        "debian.org",
        true
      },
      {
        "ftp.debian.org",
        true
      },
      {
        "ubuntu.com",
        false
      },
      {
        "myhost.local",
        true
      },
      {
        "gateway.home.arpa",
        true
      }
    }
    for _, c in ipairs(CASES) do
      do
        local qname = c[1]
        local expected = c[2]
        it("is_allowed(\"" .. tostring(qname) .. "\") == " .. tostring(tostring(expected)), function()
          if expected then
            return assert.is_true(is_allowed(qname))
          else
            return assert.is_false(is_allowed(qname))
          end
        end)
      end
    end
  end)
  describe("mutation de la liste", function()
    it("add_to_allowlist : domaine ajouté → is_allowed retourne true", function()
      local domains = {
        "github.com"
      }
      domains[#domains + 1] = "newdomain.net"
      local is_allowed = make_is_allowed(domains)
      assert.is_true(is_allowed("newdomain.net"))
      return assert.is_true(is_allowed("sub.newdomain.net"))
    end)
    it("remove_from_allowlist : domaine retiré → is_allowed retourne false", function()
      local domains = {
        "github.com",
        "tobedeleted.com"
      }
      local filtered
      do
        local _accum_0 = { }
        local _len_0 = 1
        for _index_0 = 1, #domains do
          local d = domains[_index_0]
          if d ~= "tobedeleted.com" then
            _accum_0[_len_0] = d
            _len_0 = _len_0 + 1
          end
        end
        filtered = _accum_0
      end
      local is_allowed = make_is_allowed(filtered)
      assert.is_false(is_allowed("tobedeleted.com"))
      return assert.is_true(is_allowed("github.com"))
    end)
    return it("liste vide après suppression de tous les domaines → false", function()
      local is_allowed = make_is_allowed({ })
      return assert.is_false(is_allowed("github.com"))
    end)
  end)
  return describe("domaines spéciaux", function()
    it("TLD court ('local') → sous-domaine matche", function()
      local is_allowed = make_is_allowed({
        "local"
      })
      assert.is_true(is_allowed("myhost.local"))
      assert.is_true(is_allowed("printer.local"))
      return assert.is_false(is_allowed("notlocal"))
    end)
    it("home.arpa → sous-domaine matche", function()
      local is_allowed = make_is_allowed({
        "home.arpa"
      })
      assert.is_true(is_allowed("gateway.home.arpa"))
      return assert.is_false(is_allowed("home.arpa.evil.com"))
    end)
    return it("cloudflare.com → sous-domaines multiples", function()
      local is_allowed = make_is_allowed({
        "cloudflare.com"
      })
      assert.is_true(is_allowed("1.1.1.1.cloudflare.com"))
      return assert.is_false(is_allowed("notcloudflare.com"))
    end)
  end)
end)
