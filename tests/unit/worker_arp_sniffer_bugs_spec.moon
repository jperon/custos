-- tests/unit/worker_arp_sniffer_bugs_spec.moon
-- Régressions des bugs constatés par la campagne de couverture (branche
-- d-bugs3) : TLLA finale ignorée et tableau pollfd initialisé en 1-based.
-- Chaque test cite fichier:ligne, entrée et attendu.

ffi = require "ffi"

-- Le helper de test stube ffi_defs (sans les structs AF_PACKET) : déclarer ici
-- ce qu'utilise attach_filter/open_socket, comme worker_arp_sniffer_core_spec.
for def in *{
  "struct sock_filter { uint16_t code; uint8_t jt; uint8_t jf; uint32_t k; };"
  "struct sock_fprog { unsigned short len; struct sock_filter *filter; };"
  [[struct packet_mreq {
    int            mr_ifindex;
    unsigned short mr_type;
    unsigned short mr_alen;
    unsigned char  mr_address[8];
  };]]
}
  pcall -> ffi.cdef def

wa = require "worker_arp_sniffer"
REAL_SOCKET = package.loaded["lib.socket"]
REAL_WA = package.loaded["worker_arp_sniffer"]
SRC_MAC = "\2\0\0\0\0\1"
opt = (type, len_units, mac) -> string.char(type, len_units) .. mac

describe "worker_arp_sniffer bugs connus", ->
  it "extract_tlla ignore une TLLA qui termine exactement la trame", ->
    -- src/worker_arp_sniffer.moon:101 exigeait `len >= opt_start + 8` (un
    -- octet de trop) et :109 rejetait `offset + opt_len > len` alors que le
    -- dernier octet est à `offset + opt_len - 1`.
    -- Entrée : trame de 86 octets (14 Eth + 40 IPv6 + 24 NA + 8 TLLA),
    -- opt_start=79. Avant correctif : nil (repli sur la MAC source Ethernet).
    -- Attendu : les 6 octets de la MAC TLLA.
    raw = string.rep("\0", 78) .. opt(2, 1, SRC_MAC)
    assert.equals SRC_MAC, wa.extract_tlla raw, 79, #raw

  it "run() initialise le tableau pollfd en 0-based (pas de débordement)", ->
    -- src/worker_arp_sniffer.moon:410-413 : `pfds = ffi.new "struct pollfd[?]", #fds`
    -- alloue des indices 0..#fds-1, mais la boucle `for i, fd in ipairs fds`
    -- écrivait `pfds[i]` pour i = 1..#fds. Conséquences avec une interface :
    -- pfds[0] (lu par poll, ligne 425) n'était jamais initialisé (fd=0 →
    -- stdin) et pfds[1] était écrit hors bornes (corruption mémoire).
    -- Attendu : pfds[i-1].fd / .events initialisés, poll sur le bon fd.
    seen = nil
    fake_C = {
      htons: (v) -> v
      socket: -> 10
      bind: -> 0
      setsockopt: -> 0
      if_nametoindex: -> 5
      poll: (pfds, nfds, ms) ->
        seen = { nfds: nfds, fd: pfds[0].fd, events: pfds[0].events }
        error "stop-run"   -- run() est une boucle infinie : on sort par erreur
      recv: -> 0
    }
    package.loaded["lib.socket"] = { C: fake_C, AF_PACKET: 17, SOCK_RAW: 3 }
    package.loaded["worker_arp_sniffer"] = nil
    w = require "worker_arp_sniffer"
    ok, err = pcall -> w.run "br0", 99
    package.loaded["lib.socket"] = REAL_SOCKET
    package.loaded["worker_arp_sniffer"] = REAL_WA

    assert.is_false ok
    assert.is_truthy (tostring(err)\match "stop%-run"), tostring err
    assert.is_not_nil seen
    assert.equals 1, seen.nfds
    assert.equals 10, seen.fd      -- pfds[0] = socket simulé, pas stdin (0)
    assert.equals 1, seen.events   -- POLLIN
