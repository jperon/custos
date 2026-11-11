-- tests/unit/auth/sni_peek_spec.moon
-- Lecture du ClientHello par MSG_PEEK (sans consommation) et extraction SNI.
-- Aucun descripteur réel : le peek et l'attente sont injectés.

bit = require "bit"
ffi = require "ffi"
pcall ffi.cdef, [[
  int socketpair(int domain, int type, int protocol, int sv[2]);
  int write(int fd, const void *buf, unsigned long count);
  int read(int fd, void *buf, unsigned long count);
]]
{
  :read_client_hello
  :extract_client_sni
  :record_target
  :PEEK_MAX_BYTES
} = require "auth.sni_peek"

-- ── Helper : construit un TLS ClientHello minimal avec SNI ──────────────────
make_clienthello_sni = (hostname) ->
  ver            = string.char 0x03, 0x03
  random         = string.rep "\x00", 32
  session_id_len = string.char 0x00
  cipher_suites  = string.char 0x00, 0x02, 0x13, 0x01
  compression    = string.char 0x01, 0x00

  sni_entry = string.char(0x00) ..
    string.char(bit.rshift(#hostname, 8), bit.band(#hostname, 0xFF)) ..
    hostname
  sni_list = string.char(bit.rshift(#sni_entry, 8), bit.band(#sni_entry, 0xFF)) .. sni_entry
  sni_ext = string.char(0x00, 0x00) ..
    string.char(bit.rshift(#sni_list, 8), bit.band(#sni_list, 0xFF)) ..
    sni_list

  extensions = sni_ext
  ch_body = ver .. random .. session_id_len .. cipher_suites .. compression ..
    string.char(bit.rshift(#extensions, 8), bit.band(#extensions, 0xFF)) ..
    extensions
  ch_len = #ch_body
  handshake = string.char(0x01) ..
    string.char(bit.rshift(ch_len, 16), bit.rshift(bit.band(ch_len, 0xFF00), 8), bit.band(ch_len, 0xFF)) ..
    ch_body
  rec_len = #handshake
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

fake_wait = -> true
fake_now = -> 0
sock = -> { fd: 9 }

read = (opts) -> read_client_hello sock!, opts
sni_of = (opts) -> extract_client_sni sock!, opts

describe "auth/sni_peek record_target", ->

  it "retourne nil tant que l'en-tête TLS n'est pas complet", ->
    assert.is_nil record_target ""
    assert.is_nil record_target string.rep("\x16", 4)
    assert.is_nil record_target nil

  it "retourne 5 + record_length pour un en-tête lisible", ->
    header = string.char 0x16, 0x03, 0x01, 0x00, 0x2a
    assert.equals 47, record_target header

  it "plafonne la lecture à PEEK_MAX_BYTES", ->
    header = string.char 0x16, 0x03, 0x01, 0xFF, 0xFF
    assert.equals PEEK_MAX_BYTES, record_target header

describe "auth/sni_peek read_client_hello", ->

  it "retourne nil sans socket ou sans fd", ->
    assert.is_nil read_client_hello nil
    assert.is_nil read_client_hello {}

  it "lit un ClientHello complet en un seul peek", ->
    ch = make_clienthello_sni "example.com"
    waits = 0
    wait_fn = ->
      waits += 1
      true
    data = read {
      wait_fn: wait_fn
      peek_fn: (fd, len) -> ch
      now_fn: fake_now
    }
    assert.equals ch, data
    assert.equals 1, waits

  it "accumule un ClientHello arrivé en plusieurs morceaux (MSG_PEEK relit le préfixe)", ->
    ch = make_clienthello_sni "portal.example"
    chunks = { ch\sub(1, 5), ch }
    calls = 0
    data = read {
      wait_fn: fake_wait
      peek_fn: (fd, len) ->
        calls += 1
        chunks[calls]
      now_fn: fake_now
    }
    assert.equals ch, data
    assert.equals 2, calls

  it "retourne nil si aucune donnée n'est disponible", ->
    data = read {
      wait_fn: -> false
      peek_fn: -> error "ne doit pas être appelé"
      now_fn: fake_now
    }
    assert.is_nil data

  it "s'arrête au délai sans boucler sur un ClientHello tronqué", ->
    ch = make_clienthello_sni "tronque.example"
    partial = ch\sub 1, 40
    now = 0
    wait_fn = ->
      now = 100  -- le délai expire pendant l'attente
      true
    data = read {
      wait_fn: wait_fn
      peek_fn: (fd, len) -> partial
      now_fn: -> now
      timeout: 15
    }
    assert.equals partial, data
    assert.is_nil sni_of {
      wait_fn: fake_wait
      peek_fn: (fd, len) -> partial
      now_fn: fake_now
    }

  it "s'arrête si le peek ne progresse plus", ->
    partial = string.rep "\x16", 7
    calls = 0
    peek_fn = (fd, len) ->
      calls += 1
      partial
    data = read {
      wait_fn: fake_wait
      peek_fn: peek_fn
      now_fn: fake_now
    }
    assert.equals partial, data
    assert.equals 2, calls  -- 5 octets puis 7, puis arrêt (pas de croissance)

  it "ne consomme pas les octets observés (socketpair réel)", ->
    -- AF_UNIX=1, SOCK_STREAM=1
    fds = ffi.new "int[2]"
    assert.equals 0, ffi.C.socketpair 1, 1, 0, fds
    ch = make_clienthello_sni "peek.example"
    written = ffi.C.write fds[1], ch, #ch
    assert.equals #ch, tonumber written

    data = read_client_hello { fd: fds[0] }
    assert.equals ch, data

    -- Le ClientHello doit toujours être dans la file : WolfSSL le relira.
    buf = ffi.new "uint8_t[?]", #ch
    n = ffi.C.read fds[0], buf, #ch
    assert.equals #ch, tonumber n
    assert.equals ch, ffi.string(buf, n)

    ffi.C.close fds[0]
    ffi.C.close fds[1]

describe "auth/sni_peek extract_client_sni", ->

  it "extrait le SNI d'un ClientHello complet", ->
    ch = make_clienthello_sni "portal.example"
    sni = sni_of {
      wait_fn: fake_wait
      peek_fn: (fd, len) -> ch
      now_fn: fake_now
    }
    assert.equals "portal.example", sni

  it "retourne nil si le ClientHello n'a pas de SNI", ->
    ch = make_clienthello_sni "portal.example"
    -- Tronque après l'en-tête : aucune extension lisible
    sni = sni_of {
      wait_fn: fake_wait
      peek_fn: (fd, len) -> ch\sub 1, 12
      now_fn: fake_now
    }
    assert.is_nil sni

  it "ne propage jamais une exception du lecteur", ->
    sni = sni_of {
      wait_fn: fake_wait
      peek_fn: -> error "descripteur cassé"
      now_fn: fake_now
    }
    assert.is_nil sni
