local CONV_INPUT = "tmp/test_convert_spec.domains"
local CONV_OUTPUT = "tmp/test_convert_spec.bin"
local LUA_CMD = "LUA_PATH='lua/?.lua;lua/?/init.lua;;' luajit lua/filter/convert.lua"
local run_convert
run_convert = function(args)
  local code = os.execute(tostring(LUA_CMD) .. " " .. tostring(args) .. " 2>/dev/null")
  return code == 0 or code == true
end
local read_bin
read_bin = function(path)
  local fh = io.open(path, "rb")
  if not (fh) then
    return nil
  end
  local data = fh:read("*a")
  fh:close()
  return data
end
local rec48_le
rec48_le = function(s, i, j)
  for b = 5, 0, -1 do
    local ai = string.byte(s, i * 6 + b + 1)
    local aj = string.byte(s, j * 6 + b + 1)
    if ai < aj then
      return true
    end
    if ai > aj then
      return false
    end
  end
  return true
end
local sorted_rec48
sorted_rec48 = function(s)
  local n = math.floor(#s / 6)
  if n <= 1 then
    return true
  end
  for i = 0, n - 2 do
    if not (rec48_le(s, i, i + 1)) then
      return false
    end
  end
  return true
end
local cleanup
cleanup = function()
  os.remove(CONV_INPUT)
  return os.remove(CONV_OUTPUT)
end
local xxhash_ok = (pcall(require, "ffi_xxhash"))
return describe("filter/convert (CLI)", function()
  after_each(function()
    return cleanup()
  end)
  describe("sans arguments", function()
    return it("exit non nul si aucun argument", function()
      return assert.is_false(run_convert(""))
    end)
  end)
  describe("fichier d'entrée absent", function()
    return it("exit non nul si le fichier source n'existe pas", function()
      return assert.is_false(run_convert("tmp/__nonexistent__.domains " .. tostring(CONV_OUTPUT)))
    end)
  end)
  if not (xxhash_ok) then
    it("libxxhash non disponible → tests CLI ignorés", function()
      return pending("libxxhash non disponible")
    end)
    return 
  end
  describe("domaines valides", function()
    it("produit un fichier binaire (exit 0)", function()
      local fh = io.open(CONV_INPUT, "w")
      fh:write("github.com\nfacebook.com\ngoogle.com\n")
      fh:close()
      return assert.is_true(run_convert(tostring(CONV_INPUT) .. " " .. tostring(CONV_OUTPUT)))
    end)
    it("taille = nb_domaines × 6 octets", function()
      local fh = io.open(CONV_INPUT, "w")
      fh:write("github.com\nfacebook.com\ngoogle.com\n")
      fh:close()
      run_convert(tostring(CONV_INPUT) .. " " .. tostring(CONV_OUTPUT))
      local data = read_bin(CONV_OUTPUT)
      assert.is_not_nil(data)
      return assert.equals(3 * 6, #data)
    end)
    return it("les hashes sont triés (ordre croissant 48 bits)", function()
      local fh = io.open(CONV_INPUT, "w")
      fh:write("github.com\nfacebook.com\ngoogle.com\n")
      fh:close()
      run_convert(tostring(CONV_INPUT) .. " " .. tostring(CONV_OUTPUT))
      local data = read_bin(CONV_OUTPUT)
      assert.is_not_nil(data)
      return assert.is_true(sorted_rec48(data))
    end)
  end)
  describe("déduplication", function()
    return it("trois lignes identiques → un seul hash (6 octets)", function()
      local fh = io.open(CONV_INPUT, "w")
      fh:write("github.com\ngithub.com\ngithub.com\n")
      fh:close()
      local ok = run_convert(tostring(CONV_INPUT) .. " " .. tostring(CONV_OUTPUT))
      assert.is_true(ok)
      local data = read_bin(CONV_OUTPUT)
      assert.is_not_nil(data)
      return assert.equals(6, #data)
    end)
  end)
  describe("commentaires et lignes vides", function()
    return it("commentaires # et lignes vides ignorés → seul github.com compté", function()
      local fh = io.open(CONV_INPUT, "w")
      fh:write("# ce fichier a des commentaires\n")
      fh:write("\n")
      fh:write("github.com  # commentaire inline\n")
      fh:write("   \n")
      fh:close()
      local ok = run_convert(tostring(CONV_INPUT) .. " " .. tostring(CONV_OUTPUT))
      assert.is_true(ok)
      local data = read_bin(CONV_OUTPUT)
      assert.is_not_nil(data)
      return assert.equals(6, #data)
    end)
  end)
  describe("fichier sans domaine valide", function()
    return it("exit non nul si tous les lignes sont des commentaires ou vides", function()
      local fh = io.open(CONV_INPUT, "w")
      fh:write("# seulement des commentaires\n")
      fh:write("\n")
      fh:close()
      return assert.is_false(run_convert(tostring(CONV_INPUT) .. " " .. tostring(CONV_OUTPUT)))
    end)
  end)
  return describe("cohérence du hash", function()
    return it("deux exécutions sur le même domaine produisent le même binaire", function()
      local fh = io.open(CONV_INPUT, "w")
      fh:write("example.com\n")
      fh:close()
      local run1_out = "tmp/test_convert_spec_run1.bin"
      local run2_out = "tmp/test_convert_spec_run2.bin"
      run_convert(tostring(CONV_INPUT) .. " " .. tostring(run1_out) .. " 2>/dev/null")
      run_convert(tostring(CONV_INPUT) .. " " .. tostring(run2_out) .. " 2>/dev/null")
      local d1 = read_bin(run1_out)
      local d2 = read_bin(run2_out)
      assert.is_not_nil(d1)
      assert.is_not_nil(d2)
      assert.equals(d1, d2)
      os.remove(run1_out)
      return os.remove(run2_out)
    end)
  end)
end)
