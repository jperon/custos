-- src/doh/upstream_doh_curl.moon
-- Client DoH via libcurl : HTTP/2 (avec fallback HTTP/1.1) géré nativement.
-- Contrat identique à doh.upstream : new_client / query / close.
-- Chaque appel query crée et détruit sa propre session curl (pas de persistance).

ffi = require "ffi"
{ :log_debug } = require "log"

pcall ffi.cdef, [[
  typedef void CURL;
  struct curl_slist { char *data; struct curl_slist *next; };

  CURL              *curl_easy_init(void);
  void               curl_easy_cleanup(CURL *handle);
  int                curl_easy_setopt(CURL *handle, int option, ...);
  int                curl_easy_perform(CURL *handle);
  int                curl_easy_getinfo(CURL *handle, int info, ...);
  struct curl_slist *curl_slist_append(struct curl_slist *list, const char *string);
  void               curl_slist_free_all(struct curl_slist *list);
  const char        *curl_easy_strerror(int errornum);
]]

libcurl = nil
for name in *{ "curl", "libcurl.so.4", "libcurl.so.4.8.0" }
  ok, lib = pcall ffi.load, name
  if ok
    libcurl = lib
    break
error "upstream_doh_curl: libcurl introuvable (curl / libcurl.so.4)" unless libcurl

-- Option codes (curl.h, stables depuis libcurl 7.x)
CURLOPT_WRITEDATA      = 10001
CURLOPT_URL            = 10002
CURLOPT_POST           = 47
CURLOPT_POSTFIELDS     = 10015
CURLOPT_POSTFIELDSIZE  = 60
CURLOPT_HTTPHEADER     = 10023
CURLOPT_WRITEFUNCTION  = 20011
CURLOPT_TIMEOUT_MS     = 155
CURLOPT_SSL_VERIFYPEER = 64
CURLOPT_HTTP_VERSION   = 84

-- HTTP/2 sur TLS avec repli transparent sur HTTP/1.1 si non disponible.
-- ALPN est négocié par libcurl/OpenSSL automatiquement.
CURL_HTTP_VERSION_2TLS = 4

CURLINFO_RESPONSE_CODE = 0x200002
CURLE_OK               = 0

-- Buffer de réponse réinitialisé à chaque query.
-- Safe car architecture fork : un seul appel query actif par processus.
recv_buf = {}

recv_cb = ffi.cast "size_t (*)(char*, size_t, size_t, void*)", (ptr, sz, nmemb, ud) ->
  n = tonumber(sz) * tonumber(nmemb)
  recv_buf[#recv_buf + 1] = ffi.string ptr, n
  n

M = {}

--- Crée un handle de configuration pour l'upstream curl DoH.
-- @tparam string url        URL DoH, ex. "https://9.9.9.9/dns-query".
-- @tparam number timeout_ms Délai maximum par requête en ms (défaut 2000).
-- @tparam bool   verify_tls Vérification du certificat TLS (défaut false).
-- @treturn table Handle {url, timeout_ms, verify_tls, _mod}.
new_client = (url, timeout_ms=2000, verify_tls=false) ->
  { :url, :timeout_ms, :verify_tls, _mod: M }

--- Envoie une requête DNS via libcurl et retourne la réponse brute.
-- @tparam table  client  Handle retourné par new_client().
-- @tparam string dns_raw Requête DNS wire format.
-- @treturn string|nil Réponse DNS brute, ou nil + erreur.
query = (client, dns_raw) ->
  -- Les deux closures (recv_cb et query) partagent le même upvalue recv_buf.
  recv_buf = {}

  curl = libcurl.curl_easy_init!
  return nil, "upstream_doh_curl: init_failed" unless curl != nil

  hdrs = libcurl.curl_slist_append nil, "Content-Type: application/dns-message"
  hdrs = libcurl.curl_slist_append hdrs, "Accept: application/dns-message"

  -- Les fonctions variadiques FFI ne font pas de conversion automatique des
  -- strings Lua en char * : cast explicite requis pour tous les pointeurs.
  libcurl.curl_easy_setopt curl, CURLOPT_URL,            ffi.cast "const char *", client.url
  libcurl.curl_easy_setopt curl, CURLOPT_POST,           ffi.cast "long", 1
  libcurl.curl_easy_setopt curl, CURLOPT_POSTFIELDS,     ffi.cast "const char *", dns_raw
  libcurl.curl_easy_setopt curl, CURLOPT_POSTFIELDSIZE,  ffi.cast "long", #dns_raw
  libcurl.curl_easy_setopt curl, CURLOPT_HTTPHEADER,     hdrs
  libcurl.curl_easy_setopt curl, CURLOPT_WRITEFUNCTION,  recv_cb
  libcurl.curl_easy_setopt curl, CURLOPT_TIMEOUT_MS,     ffi.cast "long", client.timeout_ms
  libcurl.curl_easy_setopt curl, CURLOPT_SSL_VERIFYPEER, ffi.cast "long", (client.verify_tls and 1 or 0)
  libcurl.curl_easy_setopt curl, CURLOPT_HTTP_VERSION,   ffi.cast "long", CURL_HTTP_VERSION_2TLS

  rc = libcurl.curl_easy_perform curl

  code_buf = ffi.new "long[1]"
  libcurl.curl_easy_getinfo curl, CURLINFO_RESPONSE_CODE, code_buf
  status = tonumber code_buf[0]

  libcurl.curl_slist_free_all hdrs
  libcurl.curl_easy_cleanup curl

  if rc != CURLE_OK
    err_ptr = libcurl.curl_easy_strerror rc
    return nil, "upstream_doh_curl: rc=#{tonumber rc} #{ffi.string err_ptr}"

  unless status == 200
    return nil, "upstream_doh_curl: http_status_#{status}"

  body = table.concat recv_buf
  return nil, "upstream_doh_curl: empty_body" unless #body > 0

  log_debug -> { action: "upstream_doh_curl_response", url: client.url, body_bytes: #body }
  body

--- Ferme le handle (no-op : chaque query gère son propre cycle curl).
close = (_) ->

M.new_client = new_client
M.query      = query
M.close      = close
M
