-- tests/unit/sync/custos_sync_spec.moon
-- Tests de sync/custos-sync.sh : refus d'une URL non HTTPS et arguments du
-- téléchargement. Le script est exécuté via `sh` avec un PATH factice (faux
-- curl/wget) et un sync.conf dont le chemin est surchargé par CUSTOS_SYNC_CONF.
-- Aucune requête réseau, aucun accès à /etc.

TMP = "tmp/custos_sync_spec"
SCRIPT = "sync/custos-sync.sh"

read_file = (path) ->
  f = io.open path, "r"
  return nil unless f
  out = f\read "*a"
  f\close!
  out

write_file = (path, content) ->
  f = assert io.open(path, "w"), "impossible d'écrire #{path}"
  f\write content
  f\close!

-- os.execute renvoie 0 / true selon la sémantique Lua (cf. apply_spec).
code_of = (ret) -> if ret == 0 or ret == true then 0 else 1

-- Exécute le script avec les variables d'environnement fournies.
run_sync = (env, path) ->
  out_path = "#{TMP}/out.txt"
  vars = {}
  for k, v in pairs env
    vars[#vars + 1] = "#{k}='#{v}'"
  cmd = "PATH='#{path}' #{table.concat vars, ' '} sh #{SCRIPT} >'#{out_path}' 2>&1"
  ret = os.execute cmd
  code_of(ret), read_file(out_path) or ""

setup ->
  os.execute "mkdir -p #{TMP}/bin"
  -- Faux curl : enregistre chaque argument sur une ligne et échoue (on ne
  -- teste pas le téléchargement lui-même).
  write_file "#{TMP}/bin/curl", [[
#!/bin/sh
printf '%s\n' "$@" > "$CURL_LOG"
exit 1
]]
  -- Faux wget : ne doit jamais être appelé quand curl est présent.
  write_file "#{TMP}/bin/wget", [[
#!/bin/sh
printf '%s\n' "$@" > "$WGET_LOG"
exit 1
]]
  os.execute "chmod +x #{TMP}/bin/curl #{TMP}/bin/wget"

after_each ->
  os.remove "#{TMP}/out.txt"
  os.remove "#{TMP}/curl.log"
  os.remove "#{TMP}/wget.log"
  os.remove "#{TMP}/sync.conf"

describe "sync/custos-sync.sh — téléchargement de la configuration", ->

  it "refuse une URL CUSTOS_CONFIG_REPO en http:// sans appeler curl", ->
    write_file "#{TMP}/sync.conf", "CUSTOS_CONFIG_REPO=http://example.invalid/repo\n"
    path = "#{TMP}/bin:#{os.getenv 'PATH'}"
    code, out = run_sync {
      CUSTOS_SYNC_CONF: "#{TMP}/sync.conf"
      CUSTOS_CONFIG_HOSTNAME: "testhost"
      CURL_LOG: "#{TMP}/curl.log"
      WGET_LOG: "#{TMP}/wget.log"
    }, path
    assert.not_equals 0, code
    assert.truthy out\match "https://"
    assert.truthy out\match "refus"
    assert.is_nil read_file "#{TMP}/curl.log"

  it "télécharge via curl avec TLS https contraint et vérification par défaut", ->
    repo = "https://example.invalid/repo"
    write_file "#{TMP}/sync.conf", "CUSTOS_CONFIG_REPO=#{repo}\n"
    path = "#{TMP}/bin:#{os.getenv 'PATH'}"
    code, out = run_sync {
      CUSTOS_SYNC_CONF: "#{TMP}/sync.conf"
      CUSTOS_CONFIG_HOSTNAME: "testhost"
      CURL_LOG: "#{TMP}/curl.log"
      WGET_LOG: "#{TMP}/wget.log"
    }, path
    -- Le faux curl échoue : le script doit sortir en erreur après l'appel.
    assert.not_equals 0, code
    assert.truthy out\match "échec téléchargement"

    log = assert read_file "#{TMP}/curl.log", "curl non appelé"
    args = {}
    for line in log\gmatch "[^\n]+"
      args[#args + 1] = line

    has_arg = (want) ->
      for a in *args
        return true if a == want
      false

    -- Options exigées (TLS contraint, échec HTTP = échec, redirections https).
    for opt in *{"--fail", "--silent", "--show-error", "--location"}
      assert.is_true has_arg(opt), "option curl absente : #{opt}"
    -- `--proto '=https'` et `--proto-redir '=https'` : la valeur doit suivre
    -- immédiatement l'option.
    proto_https = (opt) ->
      for i = 1, #args - 1
        return true if args[i] == opt and args[i + 1] == "=https"
      false
    assert.is_true proto_https("--proto"), "--proto '=https' absent"
    assert.is_true proto_https("--proto-redir"), "--proto-redir '=https' absent"
    -- Aucune option désactivant la vérification des certificats.
    for forbidden in *{"--insecure", "-k", "--no-check-certificate"}
      assert.is_false has_arg(forbidden), "option interdite : #{forbidden}"
    -- L'URL du tarball est le dernier argument.
    assert.equals "#{repo}/archive/main.tar.gz", args[#args]

    -- curl présent : wget ne doit pas avoir été utilisé.
    assert.is_nil read_file "#{TMP}/wget.log"
