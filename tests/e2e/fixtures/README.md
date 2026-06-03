# Fixtures E2E

## `quic_initial.bin`

Charge utile UDP brute (1232 octets) du **premier paquet QUIC Initial** (long
header, type Initial — premier octet `0xcc`) de la capture
`src/ipparse/quic.pcapng`. Utilisée par le groupe G14 de
`tests/e2e/homelab_e2e.sh` (test T125) : elle est rejouée depuis servus en un
datagramme UDP vers `10.42.0.50:443`, ce qui exerce le chemin QUIC du worker
`worker_tls` (classification `protocol=quic`, extraction SNI RFC 9001).

Régénération (depuis la racine du dépôt, après `make` pour disposer de `lua/`) :

```sh
luajit - src/ipparse/quic.pcapng tests/e2e/fixtures/quic_initial.bin <<'LUA'
package.path = package.path .. ";lua/?.lua;lua/?/init.lua"
local eth = require "ipparse.l2.ethernet"
local ip  = require "ipparse.l3.ip"
local udp = require "ipparse.l4.udp"
local su  = string.unpack
if not su then local pc = require "ipparse.lib.pack_compat"; pc.inject(); su = string.unpack end
local f = assert(io.open(arg[1], "rb")); local data = f:read("*a"); f:close()
local offset, endian = 1, nil
while offset + 11 <= #data do
  local bt = su("<I4", data, offset); local block = bt
  if bt == 0x0A0D0D0A then
    endian = (su("<I4", data, offset + 8) == 0x1A2B3C4D) and "<" or ">"; block = bt
  end
  if not endian then break end
  local blen = su(endian.."I4", data, offset + 4)
  if blen < 12 or offset + blen - 1 > #data then break end
  if block == 0x00000006 then
    local _,_,_, clen = su(endian.."I4I4I4I4", data, offset + 8)
    local ps = offset + 28; local pe = ps + clen - 1
    if pe <= #data then
      local pdata = data:sub(ps, pe)
      local ef, l3 = eth.parse(pdata)
      if ef then
        local ipp, l4 = ip.parse(pdata, l3)
        if ipp and ipp.protocol == 17 then
          local u = udp.parse(pdata, l4)
          if u and (u.dpt == 443 or u.spt == 443) then
            local payload = pdata:sub(u.data_off)
            if #payload >= 5 then
              local o = assert(io.open(arg[2], "wb")); o:write(payload); o:close()
              os.exit(0)
            end
          end
        end
      end
    end
  end
  offset = offset + blen
end
error("aucun paquet UDP/443 trouvé")
LUA
```
