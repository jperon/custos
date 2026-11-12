-- tests/unit/worker_arp_sniffer_bugs_spec.moon
-- Bugs constatés par la campagne de couverture, non corrigés (hors périmètre).
-- Chaque test est marqué pending et décrit fichier:ligne, entrée, attendu/obtenu.

wa = require "worker_arp_sniffer"
SRC_MAC = "\2\0\0\0\0\1"
opt = (type, len_units, mac) -> string.char(type, len_units) .. mac

describe "worker_arp_sniffer bugs connus", ->
  it "extract_tlla ignore une TLLA qui termine exactement la trame", ->
    -- src/worker_arp_sniffer.moon:101 (`len < opt_start + NDP_OPT_MIN_LEN`)
    -- exige un octet de plus que nécessaire, et :109 (`offset + opt_len >
    -- len`) rejette l'option dont le dernier octet est à l'offset len.
    -- Entrée : trame de 86 octets (14 Eth + 40 IPv6 + 24 NA + 8 TLLA),
    -- opt_start=79. Obtenu : nil (et process_ipv6 retombe sur la MAC source
    -- Ethernet). Attendu : les 6 octets de MAC TLLA.
    pending "TLLA en fin exacte de trame ignoré (off-by-one lignes 101/109)"
    raw = string.rep("\0", 78) .. opt(2, 1, SRC_MAC)
    assert.equals SRC_MAC, wa.extract_tlla raw, 79, #raw

  it "run() initialise le tableau pollfd avec des indices 1-based (débordement)", ->
    -- src/worker_arp_sniffer.moon:410-413 : `pfds = ffi.new "struct pollfd[?]", #fds`
    -- alloue des indices 0..#fds-1, mais la boucle `for i, fd in ipairs fds`
    -- écrit `pfds[i]` pour i = 1..#fds. Conséquences avec une interface :
    -- pfds[0] (utilisé ensuite par poll, ligne 425) n'est jamais initialisé
    -- (fd=0 → stdin) et pfds[1] est écrit hors bornes (corruption mémoire).
    -- Obtenu au test : le processus de test se termine anormalement (code 1,
    -- sans rapport) après 3 appels à run() avec un socket simulé. Attendu :
    -- pfds[i-1].fd / .events initialisés, poll sur les bons descripteurs.
    pending "run() écrit pfds[1..#fds] hors bornes (indices 0-based), lignes 410-413"
    fake_C = {
      htons: (v) -> v
      socket: -> 10
      bind: -> 0
      setsockopt: -> 0
      if_nametoindex: -> 5
      poll: -> 0
      recv: -> 0
    }
    package.loaded["lib.socket"] = { C: fake_C, AF_PACKET: 17, SOCK_RAW: 3 }
    package.loaded["worker_arp_sniffer"] = nil
    w = require "worker_arp_sniffer"
    w.run "br0", 99
