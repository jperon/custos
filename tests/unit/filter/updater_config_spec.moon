-- tests/unit/filter/updater_config_spec.moon
-- Couvre le correctif : updater.lua doit honorer --config (et donc
-- CUSTOS_CONFIG_PATH), alors qu'auparavant `config` était requis en tête de
-- fichier — avant l'application de --config — et restait épinglé au chemin par
-- défaut /etc/custos/config.moon.

-- Répertoire de travail temporaire dans ./tmp/ (cf. AGENTS.md : jamais /tmp).
TMP = "tmp/updater_config_spec"

run = (cmd) ->
  fh = assert io.popen cmd, "r"
  out = fh\read "*a"
  fh\close!
  out

write_file = (path, content) ->
  f = assert io.open path, "w"
  f\write content
  f\close!

describe "updater.lua --config", ->
  setup ->
    os.execute "rm -rf #{TMP}; mkdir -p #{TMP}/custom #{TMP}/out"
    -- Une liste custom minimale, pour avoir une sortie déterministe.
    write_file "#{TMP}/custom/demo.txt", "example.com\nexample.org\n"
    -- Config externe : aucune source réseau, chemins entièrement sous ./tmp.
    write_file "#{TMP}/config.moon", [[
{
  filter: {
    domainlists_dir: "]] .. TMP .. [[/out"
    custom_lists_dir: "]] .. TMP .. [[/custom"
    sources: {}
  }
}
]]

  teardown ->
    os.execute "rm -rf #{TMP}"

  it "honore le chemin passé à --config (chemins sous ./tmp, pas /etc/custos)", ->
    -- Propager le package.path courant (lua/ + helpers) au sous-process.
    lua_path = package.path
    cmd = "LUA_PATH='#{lua_path}' luajit lua/filter/updater.lua " ..
      "--config #{TMP}/config.moon --dry-run 2>&1"
    out = run cmd
    -- Le scan custom doit cibler le répertoire de la config externe…
    assert.truthy out\find("#{TMP}/out/custom", 1, true),
      "sortie attendue sous #{TMP}/out ; obtenu :\n#{out}"
    -- …et surtout PAS le chemin par défaut (preuve que --config est honoré).
    assert.falsy out\find("/etc/custos/lists", 1, true)
