-- tests/unit/worker_events_spec.moon
-- Tests du ring buffer des refus récents de worker_events :
-- note_block (dédup, ordre récent-d'abord, troncature, ignore allow),
-- flush_recent (format TSV, écriture atomique) et l'extraction par process_line.

{ :process_line, :note_block, :flush_recent, :note_device, :flush_devices } = require "worker_events"

count_keys = (t) ->
  n = 0
  n += 1 for _ in pairs t
  n

TMP = "tmp/worker_events_recent_spec"

describe "worker_events.note_block", ->
  it "ignore les décisions non-block", ->
    recent = {}
    assert.is_false note_block recent, "allow", "ex.com", "aa:bb", "", "100"
    assert.equals 0, #recent

  it "ignore mac ou qname vide", ->
    recent = {}
    assert.is_false note_block recent, "block", "", "aa:bb", "r", "1"
    assert.is_false note_block recent, "block", "ex.com", "", "r", "1"
    assert.equals 0, #recent

  it "insère une nouvelle entrée en tête", ->
    recent = {}
    assert.is_true note_block recent, "block", "ads.com", "aa:bb", "blocklist", "100"
    assert.equals 1, #recent
    assert.equals "ads.com", recent[1].qname
    assert.equals 1, recent[1].count

  it "dédup (mac+qname) : incrémente count, met à jour last_ts, remonte en tête", ->
    recent = {}
    note_block recent, "block", "a.com", "mac1", "r", "100"
    note_block recent, "block", "b.com", "mac1", "r", "101"
    note_block recent, "block", "a.com", "mac1", "r2", "102"
    assert.equals 2, #recent
    assert.equals "a.com", recent[1].qname      -- remontée en tête
    assert.equals 2, recent[1].count
    assert.equals "102", recent[1].last_ts
    assert.equals "r2", recent[1].reason        -- raison rafraîchie

  it "distingue les MAC différentes pour un même qname", ->
    recent = {}
    note_block recent, "block", "a.com", "mac1", "r", "100"
    note_block recent, "block", "a.com", "mac2", "r", "101"
    assert.equals 2, #recent

  it "tronque à 50 entrées (RECENT_MAX)", ->
    recent = {}
    for i = 1, 60
      note_block recent, "block", "d#{i}.com", "mac1", "r", tostring i
    assert.equals 50, #recent
    -- La plus récente est en tête, la plus ancienne conservée est d11
    assert.equals "d60.com", recent[1].qname
    assert.equals "d11.com", recent[50].qname

describe "worker_events.flush_recent", ->
  path = "#{TMP}/recent-blocks.tsv"

  before_each -> os.execute "mkdir -p '#{TMP}'"
  after_each ->
    os.remove path
    os.remove "#{path}.tmp"

  it "écrit une ligne TSV par entrée au bon format", ->
    recent = {
      { mac: "aa:bb", qname: "x.com", reason: "blk", count: 3, last_ts: "200" }
      { mac: "cc:dd", qname: "y.com", reason: "", count: 1, last_ts: "201" }
    }
    flush_recent recent, TMP
    fh = io.open path, "r"
    assert.is_not_nil fh
    content = fh\read "*a"
    fh\close!
    assert.equals "aa:bb\tx.com\tblk\t3\t200\ncc:dd\ty.com\t\t1\t201\n", content

  it "écrit atomiquement (pas de .tmp résiduel)", ->
    flush_recent { { mac: "m", qname: "q", reason: "r", count: 1, last_ts: "1" } }, TMP
    tmp_fh = io.open "#{path}.tmp", "r"
    assert.is_nil tmp_fh
    if tmp_fh then tmp_fh\close!

  it "buffer vide → fichier vide", ->
    flush_recent {}, TMP
    fh = io.open path, "r"
    assert.equals "", fh\read "*a"
    fh\close!

describe "worker_events.process_line (extraction des refus)", ->
  it "note un refus pour une ligne block", ->
    agg, recent = {}, {}
    line = "150\tblock\tads.com\taa:bb:cc:dd:ee:ff\t10.0.0.1\t8.8.8.8\t0\t-\tipv4\tMatched blocklist\trule1"
    assert.is_true process_line line, agg, recent
    assert.equals 1, #recent
    assert.equals "ads.com", recent[1].qname
    assert.equals "aa:bb:cc:dd:ee:ff", recent[1].mac
    assert.equals "Matched blocklist", recent[1].reason

  it "ne note rien pour une ligne allow", ->
    agg, recent = {}, {}
    line = "150\tallow\tok.com\taa:bb\t10.0.0.1\t8.8.8.8\t0\t-\tipv4\t\trule1"
    assert.is_false process_line line, agg, recent
    assert.equals 0, #recent
    -- mais l'agrégation reste effectuée
    cnt = 0
    for _ in pairs agg
      cnt += 1
    assert.equals 1, cnt

  it "agrège toujours, même sans buffer recent", ->
    agg = {}
    line = "150\tblock\tads.com\taa:bb\t10.0.0.1\t8.8.8.8\t0\t-\tipv4\tr\trule1"
    assert.is_false process_line line, agg, nil
    cnt = 0
    for _ in pairs agg
      cnt += 1
    assert.equals 1, cnt

  it "note l'appareil (2e valeur de retour) pour toute décision", ->
    agg, devices = {}, {}
    line = "150\tallow\tok.com\taa:bb:cc:dd:ee:ff\t10.0.0.1\t8.8.8.8\t0\tbob\tipv4\t\trule1"
    _blocked, device_noted = process_line line, agg, nil, devices
    assert.is_true device_noted
    d = devices["aa:bb:cc:dd:ee:ff"]
    assert.is_not_nil d
    assert.equals "10.0.0.1", d.last_ip
    assert.equals "bob", d.last_user
    assert.equals "ok.com", d.last_qname
    assert.equals "allow", d.last_decision

describe "worker_events.note_device", ->
  it "ignore mac vide ou unknown", ->
    devices = {}
    assert.is_false note_device devices, "", "ip", "u", "q", "allow", "1"
    assert.is_false note_device devices, "unknown", "ip", "u", "q", "allow", "1"
    assert.equals 0, count_keys devices

  it "insère un nouvel appareil", ->
    devices = {}
    assert.is_true note_device devices, "mac1", "10.0.0.1", "bob", "ex.com", "allow", "100"
    d = devices.mac1
    assert.equals 1, d.count
    assert.equals "100", d.first_ts
    assert.equals "100", d.last_ts
    assert.equals "ex.com", d.last_qname

  it "upsert : incrémente count et met à jour les champs last_*", ->
    devices = {}
    note_device devices, "mac1", "10.0.0.1", "bob", "a.com", "allow", "100"
    note_device devices, "mac1", "10.0.0.2", "bob", "b.com", "block", "150"
    d = devices.mac1
    assert.equals 2, d.count
    assert.equals "100", d.first_ts        -- inchangé
    assert.equals "150", d.last_ts
    assert.equals "10.0.0.2", d.last_ip
    assert.equals "b.com", d.last_qname
    assert.equals "block", d.last_decision

  it "tronque à DEVICES_MAX (256) en évinçant le plus ancien last_ts", ->
    devices = {}
    for i = 1, 300
      note_device devices, "mac#{i}", "ip", "u", "q", "allow", tostring i
    assert.equals 256, count_keys devices
    assert.is_nil devices.mac1            -- le plus ancien a été évincé
    assert.is_not_nil devices.mac300

describe "worker_events.flush_devices", ->
  path = "#{TMP}/recent-devices.tsv"

  before_each -> os.execute "mkdir -p '#{TMP}'"
  after_each ->
    os.remove path
    os.remove "#{path}.tmp"

  it "écrit une ligne TSV au bon format", ->
    devices = {
      mac1: { mac: "aa:bb", last_ip: "10.0.0.1", last_user: "bob", last_qname: "x.com",
              last_decision: "allow", count: 4, first_ts: "100", last_ts: "200" }
    }
    flush_devices devices, TMP
    fh = io.open path, "r"
    assert.is_not_nil fh
    content = fh\read "*a"
    fh\close!
    assert.equals "aa:bb\t10.0.0.1\tbob\tx.com\tallow\t4\t100\t200\n", content

  it "écrit atomiquement (pas de .tmp résiduel)", ->
    flush_devices { m: { mac: "m", last_ip: "i", last_user: "u", last_qname: "q",
                         last_decision: "allow", count: 1, first_ts: "1", last_ts: "1" } }, TMP
    tmp_fh = io.open "#{path}.tmp", "r"
    assert.is_nil tmp_fh
    if tmp_fh then tmp_fh\close!

  it "map vide → fichier vide", ->
    flush_devices {}, TMP
    fh = io.open path, "r"
    assert.equals "", fh\read "*a"
    fh\close!
