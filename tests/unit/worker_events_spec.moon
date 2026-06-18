-- tests/unit/worker_events_spec.moon
-- Tests du ring buffer des verdicts récents de worker_events :
-- note_verdict (dédup allow+block, ordre récent-d'abord, compteur, troncature),
-- flush_verdicts (format TSV, écriture atomique) et l'extraction par process_line.

{ :process_line, :note_verdict, :flush_verdicts } = require "worker_events"

TMP = "tmp/worker_events_recent_spec"

describe "worker_events.note_verdict", ->
  it "ignore mac/qname vide ou mac unknown", ->
    verdicts = {}
    assert.is_false note_verdict verdicts, "block", "", "aa:bb", "ip", "u", "r", "1"
    assert.is_false note_verdict verdicts, "block", "ex.com", "", "ip", "u", "r", "1"
    assert.is_false note_verdict verdicts, "allow", "ex.com", "unknown", "ip", "u", "r", "1"
    assert.equals 0, #verdicts

  it "note allow ET block", ->
    verdicts = {}
    assert.is_true note_verdict verdicts, "allow", "ok.com", "aa:bb", "ip", "u", "", "100"
    assert.is_true note_verdict verdicts, "block", "ads.com", "aa:bb", "ip", "u", "blk", "101"
    assert.equals 2, #verdicts

  it "insère une nouvelle entrée en tête", ->
    verdicts = {}
    note_verdict verdicts, "block", "ads.com", "aa:bb", "10.0.0.1", "bob", "blocklist", "100"
    assert.equals 1, #verdicts
    assert.equals "ads.com", verdicts[1].qname
    assert.equals "10.0.0.1", verdicts[1].ip
    assert.equals "bob", verdicts[1].user
    assert.equals 1, verdicts[1].count

  it "dédup (mac+qname+decision) : compteur, maj champs, remontée en tête", ->
    verdicts = {}
    note_verdict verdicts, "allow", "a.com", "mac1", "ip1", "u", "r", "100"
    note_verdict verdicts, "allow", "b.com", "mac1", "ip1", "u", "r", "101"
    note_verdict verdicts, "allow", "a.com", "mac1", "ip2", "u2", "r2", "102"
    assert.equals 2, #verdicts
    assert.equals "a.com", verdicts[1].qname    -- remontée en tête
    assert.equals 2, verdicts[1].count
    assert.equals "102", verdicts[1].last_ts
    assert.equals "ip2", verdicts[1].ip
    assert.equals "u2", verdicts[1].user
    assert.equals "r2", verdicts[1].reason
    assert.equals "100", verdicts[1].first_ts   -- inchangé

  it "distingue la décision pour un même (mac, qname)", ->
    verdicts = {}
    note_verdict verdicts, "allow", "a.com", "mac1", "ip", "u", "r", "100"
    note_verdict verdicts, "block", "a.com", "mac1", "ip", "u", "r", "101"
    assert.equals 2, #verdicts

  it "tronque à 8192 entrées (VERDICTS_MAX)", ->
    verdicts = {}
    for i = 1, 8200
      note_verdict verdicts, "allow", "d#{i}.com", "mac1", "ip", "u", "r", tostring i
    assert.equals 8192, #verdicts
    assert.equals "d8200.com", verdicts[1].qname

describe "worker_events.flush_verdicts", ->
  path = "#{TMP}/recent-verdicts.tsv"

  before_each -> os.execute "mkdir -p '#{TMP}'"
  after_each ->
    os.remove path
    os.remove "#{path}.tmp"

  it "écrit une ligne TSV par entrée au bon format", ->
    verdicts = {
      { mac: "aa:bb", ip: "10.0.0.1", user: "bob", qname: "x.com", decision: "block",
        reason: "blk", count: 3, first_ts: "150", last_ts: "200" }
      { mac: "cc:dd", ip: "", user: "", qname: "y.com", decision: "allow",
        reason: "", count: 1, first_ts: "201", last_ts: "201" }
    }
    flush_verdicts verdicts, TMP
    fh = io.open path, "r"
    assert.is_not_nil fh
    content = fh\read "*a"
    fh\close!
    assert.equals "aa:bb\t10.0.0.1\tbob\tx.com\tblock\tblk\t3\t150\t200\ncc:dd\t\t\ty.com\tallow\t\t1\t201\t201\n", content

  it "écrit atomiquement (pas de .tmp résiduel)", ->
    flush_verdicts { { mac: "m", ip: "i", user: "u", qname: "q", decision: "allow",
                       reason: "r", count: 1, first_ts: "1", last_ts: "1" } }, TMP
    tmp_fh = io.open "#{path}.tmp", "r"
    assert.is_nil tmp_fh
    if tmp_fh then tmp_fh\close!

  it "buffer vide → fichier vide", ->
    flush_verdicts {}, TMP
    fh = io.open path, "r"
    assert.equals "", fh\read "*a"
    fh\close!

describe "worker_events.process_line", ->
  it "note un verdict block", ->
    agg, verdicts = {}, {}
    line = "150\tblock\tads.com\taa:bb:cc:dd:ee:ff\t10.0.0.1\t8.8.8.8\t0\t-\tipv4\tMatched blocklist\trule1"
    assert.is_true process_line line, agg, verdicts
    assert.equals 1, #verdicts
    assert.equals "ads.com", verdicts[1].qname
    assert.equals "aa:bb:cc:dd:ee:ff", verdicts[1].mac
    assert.equals "10.0.0.1", verdicts[1].ip
    assert.equals "Matched blocklist", verdicts[1].reason

  it "note aussi un verdict allow (toutes décisions)", ->
    agg, verdicts = {}, {}
    line = "150\tallow\tok.com\taa:bb:cc:dd:ee:ff\t10.0.0.1\t8.8.8.8\t0\tbob\tipv4\t\trule1"
    assert.is_true process_line line, agg, verdicts
    assert.equals 1, #verdicts
    assert.equals "ok.com", verdicts[1].qname
    assert.equals "allow", verdicts[1].decision
    assert.equals "bob", verdicts[1].user

  it "agrège toujours, même sans buffer verdicts", ->
    agg = {}
    line = "150\tblock\tads.com\taa:bb\t10.0.0.1\t8.8.8.8\t0\t-\tipv4\tr\trule1"
    assert.is_false process_line line, agg, nil
    cnt = 0
    for _ in pairs agg
      cnt += 1
    assert.equals 1, cnt

  it "déduplique l'agrégation pour une clé identique (count++)", ->
    agg = {}
    line = "150\tblock\tads.com\taa:bb\t10.0.0.1\t8.8.8.8\t0\t-\tipv4\tr\trule1"
    process_line line, agg, nil
    process_line "151\t#{line\match "^%d+\t(.+)$"}", agg, nil
    cnt, entry = 0, nil
    for _, e in pairs agg
      cnt += 1
      entry = e
    assert.equals 1, cnt
    assert.equals 2, entry.count
    assert.equals "151", entry.last_ts

  it "ignore une ligne sans tabulation", ->
    assert.is_false process_line "pas-de-tab", {}, {}

  it "ignore une ligne à clé vide", ->
    assert.is_false process_line "150\t", {}, {}

  it "ignore une clé sans les champs attendus (decision nil)", ->
    assert.is_false process_line "150\tx", {}, {}
