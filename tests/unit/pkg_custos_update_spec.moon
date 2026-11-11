-- tests/unit/pkg_custos_update_spec.moon
-- Exerce les scripts shell du paquet OpenWrt sans routeur :
--   * packaging/openwrt/custos/files/usr/sbin/custos-update avec un PATH truqué
--     (curl, zstd, tar, sha256sum, custos, pgrep… factices) : la compilation
--     locale des .txt est lancée après l'extraction de la release, même quand
--     curl échoue, et le code de sortie reflète les échecs ;
--   * _cron_remove de l'init.d : retire toutes les lignes custos-update (avec
--     ou sans marqueur) sans toucher au reste du crontab.
--
-- Toutes les sorties restent sous ./tmp/ (cf. AGENTS.md) : les chemins du
-- script sont surchargés par variables d'environnement.

-- Chemin absolu : le script fait `cd` dans son répertoire temporaire avant de
-- lancer sha256sum ; un PATH relatif n'y résoudrait plus les outils factices.
ROOT = os.getenv("PWD") or "."
TMP = "#{ROOT}/tmp/pkg_custos_update_spec"
SCRIPT = "packaging/openwrt/custos/files/usr/sbin/custos-update"
INITD = "packaging/openwrt/custos/files/etc/init.d/custos"

read = (path) ->
  f = assert io.open path, "r"
  data = f\read "*a"
  f\close!
  data

write_file = (path, content) ->
  f = assert io.open path, "w"
  f\write content
  f\close!

write_exec = (path, content) ->
  write_file path, content
  os.execute "chmod 755 #{path}"

spawn_sleeper = (pid_file) ->
  os.execute "sh -c 'sleep 60 & echo $! > #{pid_file}'"

describe "custos-update (script de paquet)", ->
  setup ->
    os.execute "rm -rf #{TMP}"
    os.execute "mkdir -p #{TMP}/bin #{TMP}/scratch"
    write_file "#{TMP}/config.moon", "-- config de test\n{\n  filter: {}\n}\n"
    write_file "#{TMP}/updater.lua", "-- updater factice\n"

    -- Arguments : … -o DEST URL ; FAIL_CURL force un code d'échec curl.
    write_exec "#{TMP}/bin/curl", [[
#!/bin/sh
dest=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) dest="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "${FAIL_CURL:-}" ] && exit "${FAIL_CURL}"
[ -n "$dest" ] || exit 2
case "$dest" in
    *SHA256SUMS) printf 'deadbeef  custos-lists-full.tar.zst\n' > "$dest" ;;
    *) : > "$dest" ;;
esac
exit 0
]]

    write_exec "#{TMP}/bin/zstd", [[
#!/bin/sh
cat /dev/null
exit 0
]]

    -- Écrit un fichier marqueur dans le dossier d'extraction (-C DEST) : sa
    -- présence prouve que l'extraction a eu lieu avant l'appel à custos.
    write_exec "#{TMP}/bin/tar", [[
#!/bin/sh
dest=""
while [ $# -gt 0 ]; do
    case "$1" in
        -C) dest="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$dest" ] || exit 2
mkdir -p "$dest/custom" || exit 1
: > "$dest/custom/from_release.bin"
exit 0
]]

    write_exec "#{TMP}/bin/sha256sum", [[
#!/bin/sh
cat >/dev/null 2>&1 || true
exit 0
]]

    -- Journalise l'appel et l'état de l'extraction au moment de l'appel.
    write_exec "#{TMP}/bin/custos", [[
#!/bin/sh
{
    echo "called"
    echo "args=$*"
    if [ -f "${CUSTOS_LISTS_DIR:-/nonexistent}/custom/from_release.bin" ]; then
        echo "release_present=1"
    else
        echo "release_present=0"
    fi
} >> "${CUSTOS_FAKE_LOG:?}"
[ -n "${FAIL_CUSTOS:-}" ] && exit "${FAIL_CUSTOS}"
exit 0
]]

    write_exec "#{TMP}/bin/uci", "#!/bin/sh\nexit 1\n"
    write_exec "#{TMP}/bin/pgrep", "#!/bin/sh\nexit 1\n"
    write_exec "#{TMP}/bin/pkill", "#!/bin/sh\nexit 1\n"

  teardown ->
    os.execute "kill $(cat #{TMP}/custos.pid) 2>/dev/null || true"
    os.execute "rm -rf #{TMP}"

  before_each ->
    os.execute "rm -rf #{TMP}/lists #{TMP}/calls.log #{TMP}/out.log #{TMP}/custos.pid"
    os.execute "mkdir -p #{TMP}/lists"

  cmd_for = (extra) ->
    "PATH='#{TMP}/bin:" .. (os.getenv("PATH") or "/usr/bin:/bin") .. "' " ..
      "TMPDIR='#{TMP}/scratch' CUSTOS_LISTS_DIR='#{TMP}/lists' " ..
      "CUSTOS_FAKE_LOG='#{TMP}/calls.log' CUSTOS_PID_FILE='#{TMP}/custos.pid' " ..
      "CUSTOS_BIN='#{TMP}/bin/custos' CUSTOS_UPDATER='#{TMP}/updater.lua' " ..
      "CUSTOS_CONFIG_PATH='#{TMP}/config.moon' #{extra}" ..
      "sh #{SCRIPT} full v1 > '#{TMP}/out.log' 2>&1; echo EXIT=$?"

  it "compile les listes locales après l'extraction de la release", ->
    spawn_sleeper "#{TMP}/custos.pid"
    fh = assert io.popen cmd_for(""), "r"
    out = fh\read "*a"
    fh\close!
    assert.truthy out\find("EXIT=0", 1, true), out .. "\n" .. read("#{TMP}/out.log")
    calls = read "#{TMP}/calls.log"
    -- Appel avec --custom-only et le release déjà extrait (marqueur présent).
    assert.truthy (calls\find "--custom-only", 1, true), calls
    assert.truthy (calls\find "release_present=1", 1, true), calls
    log = read "#{TMP}/out.log"
    assert.truthy (log\find "SIGHUP envoyé", 1, true), log

  it "tente quand même la compilation locale si curl échoue, puis sort non nul", ->
    spawn_sleeper "#{TMP}/custos.pid"
    fh = assert io.popen cmd_for("FAIL_CURL=7 "), "r"
    out = fh\read "*a"
    fh\close!
    assert.truthy out\find "EXIT=7", 1, true
    calls = read "#{TMP}/calls.log"
    assert.truthy calls\find "--custom-only", 1, true
    assert.truthy calls\find "release_present=0", 1, true
    log = read "#{TMP}/out.log"
    assert.truthy log\find "échec du déploiement de la release", 1, true
    assert.truthy log\find "SIGHUP envoyé", 1, true

  it "sort non nul si la compilation locale échoue, après la release et le SIGHUP", ->
    spawn_sleeper "#{TMP}/custos.pid"
    fh = assert io.popen cmd_for("FAIL_CUSTOS=1 "), "r"
    out = fh\read "*a"
    fh\close!
    assert.truthy out\find "EXIT=1", 1, true
    calls = read "#{TMP}/calls.log"
    assert.truthy calls\find "release_present=1", 1, true
    log = read "#{TMP}/out.log"
    assert.truthy log\find "échec de la compilation des listes locales", 1, true
    assert.truthy log\find "SIGHUP envoyé", 1, true

describe "init.d _cron_remove", ->
  it "retire les lignes custos-update avec ou sans marqueur, garde les autres", ->
    root = "#{TMP}/crontab"
    os.execute "mkdir -p #{TMP}"
    write_file root, table.concat({
      "0 3 * * * /usr/sbin/custos-update # custos-update-lists"
      "0 4 * * * /usr/sbin/custos-update 2>&1"
      "*/5 * * * * /usr/bin/autre --option"
      "17 1 * * * echo bonjour"
    }, "\n") .. "\n"

    fn = assert read(INITD)\match("_cron_remove%(%)%s*%{(.-)\n}")
    script = "CRONTABS_ROOT='#{root}'\n" ..
      "CUSTOS_CRON_MARKER='# custos-update-lists'\n" ..
      "_cron_remove() {\n" .. fn .. "\n}\n_cron_remove\n"
    write_file "#{TMP}/cron.sh", script
    os.execute "sh #{TMP}/cron.sh"

    content = read root
    assert.falsy content\find "custos-update", 1, true
    assert.truthy content\find "/usr/bin/autre", 1, true
    assert.truthy content\find "echo bonjour", 1, true