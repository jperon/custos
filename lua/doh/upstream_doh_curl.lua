local ffi = require("ffi")
local log_debug
log_debug = require("log").log_debug
pcall(ffi.cdef, [[  typedef void CURL;
  struct curl_slist { char *data; struct curl_slist *next; };

  CURL              *curl_easy_init(void);
  void               curl_easy_cleanup(CURL *handle);
  int                curl_easy_setopt(CURL *handle, int option, ...);
  int                curl_easy_perform(CURL *handle);
  int                curl_easy_getinfo(CURL *handle, int info, ...);
  struct curl_slist *curl_slist_append(struct curl_slist *list, const char *string);
  void               curl_slist_free_all(struct curl_slist *list);
  const char        *curl_easy_strerror(int errornum);
]])
local libcurl = nil
local _list_0 = {
  "curl",
  "libcurl.so.4",
  "libcurl.so.4.8.0"
}
for _index_0 = 1, #_list_0 do
  local name = _list_0[_index_0]
  local ok, lib = pcall(ffi.load, name)
  if ok then
    libcurl = lib
    break
  end
end
if not (libcurl) then
  error("upstream_doh_curl: libcurl introuvable (curl / libcurl.so.4)")
end
local CURLOPT_WRITEDATA = 10001
local CURLOPT_URL = 10002
local CURLOPT_POST = 47
local CURLOPT_POSTFIELDS = 10015
local CURLOPT_POSTFIELDSIZE = 60
local CURLOPT_HTTPHEADER = 10023
local CURLOPT_WRITEFUNCTION = 20011
local CURLOPT_TIMEOUT_MS = 155
local CURLOPT_SSL_VERIFYPEER = 64
local CURLOPT_HTTP_VERSION = 84
local CURL_HTTP_VERSION_2TLS = 4
local CURLINFO_RESPONSE_CODE = 0x200002
local CURLE_OK = 0
local recv_buf = { }
local recv_cb = ffi.cast("size_t (*)(char*, size_t, size_t, void*)", function(ptr, sz, nmemb, ud)
  local n = tonumber(sz) * tonumber(nmemb)
  recv_buf[#recv_buf + 1] = ffi.string(ptr, n)
  return n
end)
local M = { }
local new_client
new_client = function(url, timeout_ms, verify_tls)
  if timeout_ms == nil then
    timeout_ms = 2000
  end
  if verify_tls == nil then
    verify_tls = false
  end
  return {
    url = url,
    timeout_ms = timeout_ms,
    verify_tls = verify_tls,
    _mod = M
  }
end
local query
query = function(client, dns_raw)
  recv_buf = { }
  local curl = libcurl.curl_easy_init()
  if not (curl ~= nil) then
    return nil, "upstream_doh_curl: init_failed"
  end
  local hdrs = libcurl.curl_slist_append(nil, "Content-Type: application/dns-message")
  hdrs = libcurl.curl_slist_append(hdrs, "Accept: application/dns-message")
  libcurl.curl_easy_setopt(curl, CURLOPT_URL, ffi.cast("const char *", client.url))
  libcurl.curl_easy_setopt(curl, CURLOPT_POST, ffi.cast("long", 1))
  libcurl.curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ffi.cast("const char *", dns_raw))
  libcurl.curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, ffi.cast("long", #dns_raw))
  libcurl.curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs)
  libcurl.curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recv_cb)
  libcurl.curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, ffi.cast("long", client.timeout_ms))
  libcurl.curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, ffi.cast("long", (client.verify_tls and 1 or 0)))
  libcurl.curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, ffi.cast("long", CURL_HTTP_VERSION_2TLS))
  local rc = libcurl.curl_easy_perform(curl)
  local code_buf = ffi.new("long[1]")
  libcurl.curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, code_buf)
  local status = tonumber(code_buf[0])
  libcurl.curl_slist_free_all(hdrs)
  libcurl.curl_easy_cleanup(curl)
  if rc ~= CURLE_OK then
    local err_ptr = libcurl.curl_easy_strerror(rc)
    return nil, "upstream_doh_curl: rc=" .. tostring(tonumber(rc)) .. " " .. tostring(ffi.string(err_ptr))
  end
  if not (status == 200) then
    return nil, "upstream_doh_curl: http_status_" .. tostring(status)
  end
  local body = table.concat(recv_buf)
  if not (#body > 0) then
    return nil, "upstream_doh_curl: empty_body"
  end
  log_debug(function()
    return {
      action = "upstream_doh_curl_response",
      url = client.url,
      body_bytes = #body
    }
  end)
  return body
end
local close
close = function(_) end
M.new_client = new_client
M.query = query
M.close = close
return M
