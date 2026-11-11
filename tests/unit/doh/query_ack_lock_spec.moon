-- tests/unit/doh/query_ack_lock_spec.moon
-- Sérialisation inter-processus de la section critique ACK nft du plan DoH.
-- Les enfants DOH-conn d'un même worker partagent le tube ACK de worker_nft :
-- sans verrou, deux enfants se volent les octets (l'un répond avant que ses IP
-- soient dans nft, l'autre attend le timeout). On vérifie ici que le helper
-- encadre bien drain_ack → injection → wait_ack par lib.filelock.with_lock,
-- qu'il retombe sans verrou si l'ouverture du verrou échoue, et que le verrou
-- réel (flock) ne laisse pas deux processus s'entrelacer.

ffi = require "ffi"

events = {}
log_events = {}

package.loaded["config"] = {
  dns: { ttl_grace: { grace: 0, min: 60, max: 900 } }
  nft: { ip_timeout: "5m", add_failure_policy: "fail-closed" }
  auth: { sessions_file: "/tmp/none" }
}
package.loaded["log"] = {
  log_allow: (->)
  log_block: ((f) -> f!)
  log_warn: ((f) -> log_events[#log_events + 1] = f!)
  log_debug: (->)
  log_info: (->)
}
package.loaded["filter"] = {
  decide_meta: -> nil
  run_on_response: (rule_id, dns_raw) -> { dns_raw: dns_raw, modified: false, inject_nft: true }
}
package.loaded["auth.sessions"] = { user_for_mac: -> nil }
package.loaded["doh.upstream"]  = { query: -> nil }
package.loaded["doh.validator"] = { query_classified: -> nil }

-- Vrai module conservé pour le test à deux processus ; query.moon ne voit que
-- le stub ci-dessous.
package.loaded["lib.filelock"] = nil
real_filelock = require "lib.filelock"

lock_stub = nil
package.loaded["lib.filelock"] = {
  with_lock: (path, fn) -> lock_stub path, fn
}

nft_stub = {
  get_worker_idx: -> 3
  drain_ack: (-> events[#events + 1] = "drain")
  get_last_seq: ->
    events[#events + 1] = "seq"
    7
  wait_ack: (seq, corr) -> events[#events + 1] = "wait"
  add_ip4: (key, dest, rule_id, timeout, corr) ->
    events[#events + 1] = "add"
    true
  add_ip6: (key, dest, rule_id, timeout, corr) ->
    events[#events + 1] = "add"
    true
  add_mac4: (key, dest, rule_id, timeout, corr) -> true
  add_mac6: (key, dest, rule_id, timeout, corr) -> true
}
package.loaded["nft_queue"] = nft_stub

query_mod = require "doh.query"

-- `doh.query` a capturé le stub de with_lock ; on restaure le vrai module dans
-- package.loaded pour ne pas polluer les autres specs chargées dans le même
-- processus Lua (auth.sessions, filelock_spec…).
package.loaded["lib.filelock"] = real_filelock

answers = { { family: "ipv4", addr: "1.2.3.4", ttl: 60 } }

make_opts = (inject_nft=true) -> {
  :inject_nft
  client_addr: -> "10.0.0.5"
  client_mac: "aa:bb:cc:dd:ee:ff"
  rule_id: "r_main"
  wildcard_ids: {}
  ack_corr: "c1"
  mac_valid: -> false
  add_ip:  { ipv4: nft_stub.add_ip4, ipv6: nft_stub.add_ip6 }
  add_mac: { ipv4: nft_stub.add_mac4, ipv6: nft_stub.add_mac6 }
}

describe "doh.query.inject_nft_and_wait", ->
  before_each ->
    events = {}
    log_events = {}
    lock_stub = (path, fn) ->
      events[#events + 1] = "lock_enter:#{path}"
      res = fn!
      events[#events + 1] = "lock_exit"
      res

  it "exécute drain → injection → wait_ack sous un verrou par worker", ->
    res = query_mod.inject_nft_and_wait answers, make_opts!
    assert.equals 1, res.records_to_add
    assert.equals 6, #events
    assert.truthy events[1]\find "lock_enter:", 1, true
    assert.truthy events[1]\find "custos-doh-nft-ack-3", 1, true
    assert.equals "drain", events[2]
    assert.equals "add", events[3]
    assert.equals "seq", events[4]
    assert.equals "wait", events[5]
    assert.equals "lock_exit", events[6]

  it "repli sans verrou si with_lock lève, avec log_warn", ->
    lock_stub = (path, fn) -> error "with_lock: impossible d'ouvrir le verrou"
    res = query_mod.inject_nft_and_wait answers, make_opts!
    assert.equals 1, res.records_to_add
    assert.same { "drain", "add", "seq", "wait" }, events
    assert.equals 1, #log_events
    assert.equals "doh_ack_lock_failed_fallback", log_events[1].action

  it "inject_nft=false : ni drain, ni wait, ni verrou", ->
    res = query_mod.inject_nft_and_wait answers, make_opts false
    assert.equals 0, res.records_to_add
    assert.same {}, events
    assert.same {}, log_events

describe "lib.filelock (flock) sous deux processus", ->
  LOCK = "tmp/doh_ack_fork.lock"
  LOG  = "tmp/doh_ack_fork.log"

  after_each ->
    os.remove LOCK
    os.remove LOG

  it "les sections critiques ne s'entrelacent pas", ->
    os.remove LOCK
    os.remove LOG
    req = ffi.new "timespec_t[1]"
    sleep_ms = (ms) ->
      req[0].tv_sec  = 0
      req[0].tv_nsec = ms * 1000000
      ffi.C.nanosleep req, nil
    section = (tag) ->
      real_filelock.with_lock LOCK, ->
        fh = io.open LOG, "a"
        fh\write "#{tag}-start\n"
        fh\flush!
        sleep_ms 2   -- fenêtre large : sans verrou, l'autre s'intercalerait
        fh\write "#{tag}-end\n"
        fh\flush!
        fh\close!
    spawn = (tag) ->
      pid = ffi.C.fork!
      if pid == 0
        ok = pcall ->
          for _ = 1, 20
            section tag
        ffi.C._exit(ok and 0 or 1)
        0
      else
        pid
    -- Parenthèses obligatoires : `{ spawn "A", spawn "B" }` compile en
    -- `spawn("A", spawn("B"))` (appel implicite à arguments multiples), donc un
    -- seul PID serait attendu et l'autre enfant écrirait pendant la lecture.
    pids = { spawn("A"), spawn("B") }
    for pid in *pids
      status = ffi.new "int[1]"
      ffi.C.waitpid pid, status, 0
      assert.equals 0, status[0] / 256   -- WEXITSTATUS

    lines = {}
    for line in io.lines LOG
      lines[#lines + 1] = line
    assert.equals 80, #lines
    i = 1
    while i <= #lines
      tag = lines[i]\match "^(%u)%-start$"
      assert.truthy tag
      assert.equals "#{tag}-end", lines[i + 1]
      i += 2
