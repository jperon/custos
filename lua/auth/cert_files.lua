local ffi = require("ffi")
local log_debug
log_debug = require("log").log_debug
local with_lock
with_lock = require("lib.filelock").with_lock
pcall(ffi.cdef, "int getpid(void);")
local _tmp_seq = 0
local tmp_path
tmp_path = function(path)
  _tmp_seq = _tmp_seq + 1
  return tostring(path) .. ".tmp." .. tostring(tonumber(ffi.C.getpid())) .. "_" .. tostring(_tmp_seq)
end
local read_file
read_file = function(path)
  local fh = io.open(path, "r")
  if not (fh) then
    return nil
  end
  local content = fh:read("*a")
  fh:close()
  return content
end
local file_complete
file_complete = function(path)
  local content = read_file(path)
  return content and #content > 0
end
local write_pem_atomic
write_pem_atomic = function(path, content, rename_fn)
  if rename_fn == nil then
    rename_fn = os.rename
  end
  local tmp = tmp_path(path)
  local fh, err = io.open(tmp, "w")
  if not (fh) then
    return false, "Impossible d'ouvrir " .. tostring(tmp) .. " : " .. tostring(err)
  end
  local ok_w, write_err = pcall(function()
    return fh:write(content)
  end)
  fh:close()
  if not (ok_w) then
    pcall(os.remove, tmp)
    return false, "Impossible d'écrire " .. tostring(tmp) .. " : " .. tostring(write_err)
  end
  local ok_r, rename_err = rename_fn(tmp, path)
  if not (ok_r) then
    pcall(os.remove, tmp)
    return false, "Impossible de renommer " .. tostring(tmp) .. " → " .. tostring(path) .. " : " .. tostring(rename_err)
  end
  return true, nil
end
local materialize_pair
materialize_pair = function(key_path, cert_path, key_pem, cert_pem, opts)
  if opts == nil then
    opts = { }
  end
  local rename_fn = opts.rename_fn or os.rename
  local lock_path = tostring(cert_path) .. ".lock"
  local status = nil
  with_lock(lock_path, function()
    if file_complete(key_path) and file_complete(cert_path) then
      status = "existing"
    else
      local ok_key, err_key = write_pem_atomic(key_path, key_pem, rename_fn)
      if not (ok_key) then
        error("Écriture de la clé SNI impossible (" .. tostring(key_path) .. ") : " .. tostring(err_key))
      end
      local ok_cert, err_cert = write_pem_atomic(cert_path, cert_pem, rename_fn)
      if not (ok_cert) then
        pcall(os.remove, key_path)
        error("Écriture du certificat SNI impossible (" .. tostring(cert_path) .. ") : " .. tostring(err_cert))
      end
      status = "written"
    end
  end)
  local disk_key = read_file(key_path)
  local disk_cert = read_file(cert_path)
  if not (disk_key and disk_cert and #disk_key > 0 and #disk_cert > 0) then
    error("Paire clé/certificat illisible après écriture (" .. tostring(key_path) .. ")")
  end
  log_debug(function()
    return {
      action = "cert_pair_materialized",
      key_file = key_path,
      status = status
    }
  end)
  return disk_key, disk_cert
end
return {
  write_pem_atomic = write_pem_atomic,
  materialize_pair = materialize_pair,
  read_file = read_file,
  file_complete = file_complete
}
