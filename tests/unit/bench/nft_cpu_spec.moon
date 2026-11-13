-- tests/unit/bench/nft_cpu_spec.moon
-- Tests des helpers du banc CPU du worker nft (aucun fork, aucune charge).

{ :ffi, :libc } = require "ffi_defs"

for decl in *{
  "pid_t getpid(void);"
  "struct pollfd { int fd; short events; short revents; };"
}
  pcall ffi.cdef, decl

bench = require "bench.nft_cpu"
nq = require "nft_queue"

--- Nombre d'occurrences du motif (compte rendu par gsub, sans troncature).
-- @tparam string s   Chaîne
-- @tparam string pat Motif Lua
-- @treturn number Compte
count_matches = (s, pat) ->
  _, n = s\gsub pat, ""
  n

describe "bench/nft_cpu", ->

  describe "build_line_fallback", ->
    it "produit exactement le format de nft_queue.build_line", ->
      -- nft_queue.build_line n'est exporté que depuis d-alloc ; le repli doit
      -- rester identique à l'octet près pour comparer deux versions.
      args = { "ip4", "10.35.1.2", "100.64.0.11", "r_utilisateurs", "660s",
               "\1\2\3\4\5\6\7\8\9\10\11\12\13\14\15\16", 42, 1 }
      expected = nq.build_line args[1], args[2], args[3], args[4], args[5],
        args[6], args[7], args[8]
      got = bench.build_line_fallback args[1], args[2], args[3], args[4], args[5],
        args[6], args[7], args[8]
      assert.equals expected, got
      assert.equals 8, count_matches got, "|"
      assert.equals "\n", got\sub -1

  describe "corr_of", ->
    it "rend 16 octets, distincts d'un appel à l'autre", ->
      a = bench.corr_of 1
      b = bench.corr_of 2
      assert.equals 16, #a
      assert.equals 16, #b
      assert.are_not.equal a, b

  describe "build_turn", ->
    it "rend lignes/réponse × tours lignes, seq monotone, 9 champs chacune", ->
      data, seq = bench.build_turn nq, 1, 2, 16, 0
      -- 2 réponses × 16 lignes, chacune terminée par "\n".
      lines = {}
      for line in data\gmatch "[^\n]+"
        lines[#lines + 1] = line
      assert.equals 32, #lines
      assert.equals 32, seq
      for i, line in ipairs lines
        fields = {}
        for f in line\gmatch "([^|]*)|"
          fields[#fields + 1] = f
        assert.equals "v1", fields[1]
        -- Alternance ip4/mac4 comme response_inject (add_ip puis add_mac).
        expected_kind = if i % 2 == 1 then "ip4" else "mac4"
        assert.equals expected_kind, fields[2]
        -- 9 champs = 8 séparateurs ; le 9e (corrélateur) n'est pas suivi de "|".
        assert.equals 8, count_matches line, "|"
        assert.is_truthy line\match "|%d+|%d+|%x+$"

  describe "parse_args", ->
    it "lit les tailles de tour et les surcharges GC", ->
      o = bench.parse_args { "--turns", "1,8", "--qps", "350", "--gc-pause", "110",
                             "--gc-idle-step", "0", "--legacy-gc", "--no-cpu" }
      assert.same { 1, 8 }, o.turns
      assert.equals 350, o.qps
      assert.equals 110, o.gc_pause
      assert.equals 0, o.gc_idle_step
      assert.is_true o.legacy_gc
      assert.is_false o.cpu

    it "défauts : deux tailles de tour, CPU activé, GC du code mesuré", ->
      o = bench.parse_args {}
      assert.same { 1, 8 }, o.turns
      assert.is_true o.cpu
      assert.is_false o.legacy_gc
      assert.is_nil o.gc_pause

  describe "stat_cpu_ticks", ->
    it "lit utime+stime du processus courant", ->
      ticks = bench.stat_cpu_ticks tonumber libc.getpid!
      assert.is_number ticks
      assert.is_true ticks >= 0
