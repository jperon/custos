-- Valide le programme cBPF (BPF_PROG) attaché aux sockets AF_PACKET du
-- worker ARP/NDP : seuls les trames ARP et IPv6/ICMPv6 NS/NA doivent passer,
-- tout le reste du plan de données doit être rejeté avant recv().
--
-- On exécute le programme cBPF dans un interpréteur minimal (chargement absolu
-- BPF_LD H/B, sauts BPF_JEQ, retours BPF_RET) sur des trames forgées : cela
-- vérifie offsets et cibles de saut sans nécessiter de socket réel (ni root).

{ :BPF_PROG } = dofile "lua/worker_arp_sniffer.lua"

-- Interpréteur cBPF restreint aux opcodes utilisés par BPF_PROG.
run_bpf = (prog, frame) ->
  byte = (off) -> frame\byte(off + 1) or 0   -- offsets BPF 0-based
  pc = 1
  acc = 0
  while pc <= #prog
    ins = prog[pc]
    { code, jt, jf, k } = ins
    switch code
      when 0x28  -- ldh [k]
        acc = byte(k) * 256 + byte(k + 1)
        pc += 1
      when 0x30  -- ldb [k]
        acc = byte(k)
        pc += 1
      when 0x15  -- jeq #k
        pc += (acc == k and jt or jf) + 1
      when 0x06  -- ret #k
        return k
      else
        error "opcode cBPF non géré: #{code}"
  0

-- Helpers de forge de trames (offsets 0-based comme dans BPF_PROG).
eth = (ethertype) ->
  dst = string.rep "\xaa", 6
  src = string.rep "\xbb", 6
  hi = math.floor ethertype / 256
  lo = ethertype % 256
  dst .. src .. string.char(hi, lo)

ipv6_ndp = (icm6_type, next_header=58) ->
  -- En-tête Ethernet (14) + IPv6 (40) ; next header à l'offset 20,
  -- type ICMPv6 à l'offset 54.
  hdr = eth 0x86DD
  ip6 = string.char(0x60, 0, 0, 0, 0, 8, next_header, 64) .. string.rep("\0", 32)
  hdr .. ip6 .. string.char(icm6_type, 0)

describe "worker_arp_sniffer BPF_PROG", ->
  it "accepte les trames ARP", ->
    -- une trame ARP minimale : EtherType 0x0806 suffit pour le filtre
    frame = eth(0x0806) .. string.rep("\0", 28)
    assert.equal 0xFFFF, run_bpf BPF_PROG, frame

  it "rejette l'IPv4 (plan de données)", ->
    frame = eth(0x0800) .. string.rep("\0", 40)
    assert.equal 0, run_bpf BPF_PROG, frame

  it "accepte les Neighbor Solicitation (135)", ->
    assert.equal 0xFFFF, run_bpf BPF_PROG, ipv6_ndp 135

  it "accepte les Neighbor Advertisement (136)", ->
    assert.equal 0xFFFF, run_bpf BPF_PROG, ipv6_ndp 136

  it "rejette l'IPv6 non-ICMPv6 (ex. TCP)", ->
    assert.equal 0, run_bpf BPF_PROG, ipv6_ndp 0, 6

  it "rejette l'ICMPv6 hors NS/NA (ex. echo request 128)", ->
    assert.equal 0, run_bpf BPF_PROG, ipv6_ndp 128
