# AGENTS.md — CustosVirginum

## Project Purpose

**CustosVirginum** is an inline DNS filter on Linux bridge, written in MoonScript and executed by LuaJIT. It:
- Blocks all DNS traffic except explicitly allowed domains
- Logs L2/L3/L4/L7 information
- Dynamically builds nftables allowlists as DNS resolutions occur

See [README.md](README.md) for the full architecture.

---

## Agent Rules

- **Ne jamais écrire en dehors du dossier du projet.** Toutes les sorties
  temporaires (fichiers de debug, redirections, captures de commandes) doivent
  être placées dans `./tmp/`. Ne jamais utiliser `/tmp/`, `~/.cache/` ou tout
  autre chemin extérieur au projet.

---

## Test Suites

### Unit Tests (`make test`)

Compile from `tests/run_tests.moon` → `tests/run_tests.lua`. No root required.
Tests parsing modules (`dns`, `ip`, `udp`, `ipc`, `allowlist`).

### nDPI Tests (`make test-ndpi`)

Requires libndpi installed. Tests the `parse/ndpi` facade and version dispatch.

### Docker E2E (`make test-docker` / `make test-docker-ndpi5`)

Requires Docker. Spins up filter, client, router, wan-dns containers.
Tests DNS ALLOW/REFUSED, set population, per-client isolation.

### OpenWrt E2E (`make test-openwrt HOST=root@<host>`)

Requires SSH access to an OpenWrt router with CustosVirginum installed
(or at least LuaJIT + nftables). Deploys the latest Lua files + nft rules
via `scp`, starts workers via `logger -t custos`, then runs DNS/auth checks
from the local machine.

```bash
make test-openwrt HOST=root@esm.y
```

#### OpenWrt test pitfalls

**`$` in MoonScript strings**

In MoonScript, `\$` in a double-quoted string compiles to `\$` in Lua, which
is an invalid escape sequence. Lua strings do not treat `$` as special — write
`$` directly:

```moonscript
-- WRONG: \$p is an invalid Lua escape
"sed -n '/#{MARKER}/,\$p'"
-- CORRECT:
"sed -n '/#{MARKER}/,$p'"
```

**Logging on OpenWrt**

Workers are launched with `2>&1 | logger -t custos` (no log file). Log checks
use `logread` (circular syslog buffer). To filter entries from the current test
run, insert a marker into syslog before starting the daemon:

```moonscript
ssh "logger -t custos '#{LOG_MARKER}'"
ssh "(cd #{CUSTOS_DIR} && luajit2 main.lua </dev/null 2>&1 | logger -t custos) &"
-- then query:
ssh "logread | sed -n '/#{LOG_MARKER}/,$p' | grep queue_listening"
```

**`grep -c` vs `wc -l`**

`grep -c` exits with code 1 when count is 0, causing the SSH call to return
`ok=false`. Use `grep PATTERN | wc -l` (always exits 0) for count checks.

---

Requires KVM + libvirt. Runs 47 tests against four VMs:
- `custos-filter` (Debian) — runs CustosVirginum natively
- `custos-router` (OpenWrt) — DHCPv4 + SLAAC upstream
- `custos-client` (Debian, `10.99.0.10`) — sends DNS queries, pings
- `custos-client2` (Debian, `10.99.0.11`) — second client for MAC-based isolation tests

**First run**: `sudo bash libvirt/custos-libvirt.sh create` (downloads images).
**Subsequent runs**: `make test-kvm` (up → run → down).

#### Prérequis : `images/debian-client-base.qcow2`

`custos-client2` uses a flattened copy of `custos-client.qcow2` as its backing
image so packages (`qemu-guest-agent`, `dnsutils`, etc.) are already installed
— no apt install at boot, agent ready in ~10s. Create it once:

```bash
virsh -c qemu:///system shutdown custos-client
sudo qemu-img convert -f qcow2 -O qcow2 \
  /var/lib/libvirt/images/custos-client.qcow2 \
  images/debian-client-base.qcow2
virsh -c qemu:///system start custos-client
```

`custos-libvirt.sh create` errors out with instructions if this file is missing.

#### Variables d'environnement LuaJIT en KVM

LuaJIT is launched in `test_kvm.moon` with:

```
BRIDGE_MODE=1       # activates worker Q2 (captive portal TCP/80 intercept)
BRIDGE_IFNAME=br0   # interface name for raw socket in worker_q2
```

**Do NOT set `NFQ_BRIDGE_MODE=1`** — NFQUEUE is hooked in the `ip forward`
chain (not `bridge forward`), so packet payloads have no Ethernet header.
`NFQ_BRIDGE_MODE` would cause Q0/Q1 to mis-parse every packet.

#### KVM test pitfalls

**`guest_exec_on` and single quotes**

`guest_exec_on(vm, cmd, timeout)` (in `tests/test_kvm.moon`) wraps the virsh
JSON payload in shell single-quotes. Commands containing single-quoted arguments
(e.g. `awk '{print $2}'`) break the shell quoting. Fix: escape via
`exec_payload\gsub("'", "'\"'\"'")`. Prevention: avoid single quotes in
guest commands — use `sed -En "..."` double-quoted expressions instead.

`guest_exec` and `guest_exec2` are thin wrappers around `guest_exec_on` for
`custos-client` and `custos-client2` respectively. Pass `exec_fn` to `ping_from`
/ `dig_from` to choose the VM.

**Backslash escaping (4-backslash rule)**

`safe_cmd` replaces each `\` with `\\\\`. For sed backreferences, write
`\\1` in the MoonScript source string → `\\\\1` after `safe_cmd` →
`\\1` in the JSON string → shell strips one `\` → sed sees `\1`. ✓

**IP matching in log output**

Use `string.find(str, ip_literal, 1, true)` (plain match) instead of
`str\match(ip\gsub("%.", "\\."))` — the gsub pattern can fail silently
when the Lua string escaping chain is complex. Example:

```moonscript
-- WRONG (fragile gsub escaping):
has_ip = log_out\match(CLIENT_IP\gsub("%.", "\\.")) != nil
-- CORRECT (plain string search):
has_ip = log_out\find("ip=#{CLIENT_IP} ", 1, true) != nil
```

**curl anycast re-resolution**

`curl_from(url)` performs its own DNS resolution inside the guest. For
domains with anycast IPs (e.g. github.com), the IP curl resolves may differ
from the one already in `ip4_allowed`, causing a TCP block. Pass `resolve_ip`
to force curl to use the known IP:

```moonscript
-- Force the IP already in ip4_allowed:
curl_from "http://github.com/", 5, allowed_ip
-- Internally adds: --resolve github.com:80:<ip> --resolve github.com:443:<ip>
```

**Client interface name**

Debian cloud images use predictive names (`ens2`, not `eth0`). Always
auto-detect: `ip route get <dst> | sed -En "s/.*dev ([^ ]+).*/\\1/p"`.

**Log file ownership**

If `/tmp/custos-kvm.log` is root-owned and `fs.protected_regular=2` is
set, the `debian` user cannot truncate it. The nohup redirect silently
fails → LuaJIT never starts. Fix: delete the stale file, or use a path
under `/opt/custos/tmp/` (not sticky, no `protected_regular` restriction).

**`from_user` post-inscription DNS test**

The `filter.yml` `from_user` rules only cover named accounts (`testuser`,
`newuser`). After registering a new ephemeral user (`NEW_USER_KVM`), re-login
as `testuser` before testing `auth-required.test` DNS resolution — `testuser`
has a matching rule, the ephemeral account does not.

---

## MoonScript Syntax Guidelines

This project **avoids the `class` keyword** of MoonScript. The compiled code must be independent of the MoonScript library (no `require "moon"`).

### Significant Indentation

MoonScript uses **significant whitespace** — indentation defines blocks. Use consistent spaces (not tabs) for indentation.

### Necessary Omission of Keywords

- **No `local`** — all variable declarations are local by default
- **No `end`** — blocks are closed by returning to the previous indentation level
- **No `then`** — follows `if` directly on the same line or next line with indentation
- **No `do`** — after `while` and `for`, the block starts on the next line with indentation. But `do` can be used for a block that is not a control structure.

```moonscript
if condition
  -- body
else
  -- else body

for i = 1, 10
  -- loop body

while true
  -- loop body

switch value
  when 1
    -- case 1
  when 2
    -- case 2
  else
    -- default case

a = 1
do
  b = 2
  a = 2
assert a == 2  -- OK
assert b == 2  -- Error: b is not defined outside the `do` block
```

### Functional Style (Recommended)

Prefer functions and modules that export functions:

```moonscript
parse_ip = (raw) ->
  -- ...

{ :parse_ip }
```

### Fat Arrow and `@` Shorthand

When appropriate, use `=>` (fat arrow) instead of `->`. It creates a function where `self` is automatically bound:

- `(...) =>` is equivalent to `(self, ...) ->`
- `@` is equivalent to `self`
- `@prop` is equivalent to `self.prop`
- `@method ...` is equivalent to `self\method(self, ...)`

```moonscript
-- All equivalent:
increment = (self, amount) -> self.value += amount
increment = (@, amount) -> @value += amount
increment = (amount) =>
  @value += amount

-- Using @ in table literal
obj = {
  value: 10
  increment: (amount) => @value += amount
}
```

So `parse_ip` above could be rewritten as:

```moonscript
parse_ip = =>
  -- ... (replace `raw` with `@`)
```

### Object with `new` and `setmetatable`

To create objects with state, use a factory function with a `new` method:

```moonscript
MaTable = (prop1) ->
  obj = {
    value: prop1
    increment: (amount) =>
      @value += amount
  }
  setmetatable obj, { __index: MaTable }
  obj

obj = MaTable 10
obj\increment 5
```

---

## LDoc Comments

All functions must be documented with LDoc-style comments. Use typed `@tparam` and `@treturn` tags:

```moonscript
--- Parses a raw IPv4 header from a packet.
-- @tparam string raw The raw packet data
-- @tparam number offset Offset where the IP header starts
-- @treturn table|nil Parsed IP header or nil on error
parse_ip = (raw, offset) ->
  -- ...
```

### Type Tags

| Tag | Description |
|-----|-------------|
| `@tparam` | Typed parameter: `@tparam type name description` |
| `@treturn` | Typed return: `@treturn type description` |
| `@raise` | Exceptions that may be raised |

### Basic Types

- `string`, `number`, `boolean`, `nil`
- `table` (Lua table)
- `function`
- `cdata` (FFI pointer/struct)
- `thread`

### Optional Parameters

Mark optional parameters with brackets: `[opt]`

```moonscript
--- Logs a message.
-- @tparam string level Log level (INFO, WARN, ERROR)
-- @tparam string message The message to log
-- @tparam table|nil [fields] Optional table of key-value fields
log_message = (level, message, fields) ->
  -- ...
```

---

## nDPI Integration (Pure FFI)

The project uses **libndpi** for deep packet inspection, loaded at runtime
via `ffi.load "ndpi"` — **no C bridge, no compilation step** beyond MoonScript.

### Architecture

| File | Role |
|------|------|
| `src/ffi_ndpi.moon` | Facade: loads libndpi, detects version via `ndpi_revision()`, dispatches to v4 or v5 |
| `src/ffi_ndpi_v4.moon` | `ffi.cdef` declarations for nDPI 4.2–4.8 (conditional 5/6-arg `process_packet`) |
| `src/ffi_ndpi_v5.moon` | `ffi.cdef` declarations for nDPI 5.0+ (opaque `ndpi_protocol`, no bitmask2) |
| `src/parse/ndpi.moon` | Facade: shared L3/L4/L7 parsing + dispatches detection to backend |
| `src/parse/ndpi_v4.moon` | nDPI 4.2–4.8 detection backend (init with bitmask, detect, cleanup) |
| `src/parse/ndpi_v5.moon` | nDPI 5.0+ detection backend (no bitmask, accessors for protocol IDs) |
| `tests/test_ndpi.lua` | Unit tests (`make test-ndpi`) |

The old per-layer parsers (`parse/ip`, `parse/udp`, `parse/dns`) remain
for reference. The `parse/ndpi` module replaces them with a single-call API.

### Version Tolerance

The version is detected once at load time from `ndpi_revision()`:

```
ffi_ndpi.moon → ndpi_revision() → major >= 5?
                   ├── yes → ffi_ndpi_v5 cdef + parse.ndpi_v5
                   └── no  → ffi_ndpi_v4 cdef + parse.ndpi_v4
                                └── minor >= 6? → 5-arg or 6-arg
```

| Versions | Changes handled |
|----------|----------------|
| 4.2–4.4  | 5-arg `ndpi_detection_process_packet` |
| 4.6–4.8  | 6-arg (added `ndpi_flow_input_info*`), `bitmask2` returns `int` |
| 5.0+     | `ndpi_init_detection_module(ndpi_global_context*)`, no `NDPI_PROTOCOL_BITMASK`, `ndpi_protocol` struct redesigned (read via `ndpi_get_flow_masterprotocol`/`ndpi_get_flow_appprotocol` accessors) |

### FFI Patterns Used

**Opaque struct allocation** — nDPI's `ndpi_flow_struct` has a compile-time
size that depends on build options. Allocate dynamically:

```moonscript
flow_size = ndpi_lib.ndpi_detection_get_sizeof_ndpi_flow_struct!
flow_buf  = ffi.new "uint8_t[?]", flow_size
-- Zero and cast before each use:
ffi.fill flow_buf, flow_size, 0
flow = ffi.cast "ndpi_flow_struct*", flow_buf
```

**Bitmask reproduction (v4 only)** — `NDPI_PROTOCOL_BITMASK` is
`{ uint32_t fds_bits[16] }` (64 bytes, 512 protocol bits). Set all bits
with `ffi.fill`. Removed in nDPI 5.0 (all protocols enabled by default):

```moonscript
bitmask = ffi.new "NDPI_PROTOCOL_BITMASK"
ffi.fill bitmask, ffi.sizeof(bitmask), 0xFF
ndpi_lib.ndpi_set_protocol_detection_bitmask2 ctx, bitmask
```

**Opaque return type (v5)** — nDPI 5.0 redesigned `ndpi_protocol` with
compile-time-dependent fields. The v5 wrapper declares a 128-byte opaque
blob for ABI-correct function calls, then reads protocol IDs via accessors:

```moonscript
-- ffi_ndpi_v5: typedef struct { uint8_t _opaque[128]; } ndpi_protocol;
ndpi_lib.ndpi_detection_process_packet ctx, flow, p, len, 0ULL, nil
master = tonumber ndpi_lib.ndpi_get_flow_masterprotocol ctx, flow
app    = tonumber ndpi_lib.ndpi_get_flow_appprotocol ctx, flow
```

**Pointer arithmetic for packet parsing** — cast Lua strings to `const uint8_t*`
and use `bit` library for big-endian reads (JIT-compilable, no C function call):

```moonscript
r16 = (p, o) ->
  bit.bor bit.lshift(p[o], 8), p[o + 1]

p = ffi.cast "const uint8_t*", raw
src_port = r16 p, udp_off
```

**Singleton context** — nDPI detection module is initialised once and reused.
The flow struct is pre-allocated and zeroed before each packet.

### nDPI Protocol Detection

nDPI returns two protocol IDs per packet:
- `master_protocol` — transport-level (e.g. `5` = DNS)
- `app_protocol` — application-level (e.g. `203` = Github)

### Exported API (`parse/ndpi`)

| Function | Description |
|----------|-------------|
| `parse_packet(raw)` | L3+L4+L7 parse + nDPI detection → table or nil |
| `parse_answers(raw, pkt)` | DNS answer RRs → array of records |
| `patch_and_checksum(raw, pkt, answers, ttl)` | TTL rewrite + checksum fix → string |
| `extract_dns_payload(raw, pkt)` | Extract DNS payload from UDP or TCP packet → string |
| `patch_ttl_in_dns(dns_str, answers, new_ttl)` | Rewrite TTLs in a DNS string → string |
| `replace_dns_payload(raw, pkt, new_dns)` | Rebuild IP packet with a new DNS payload (variable size) → string |
| `cleanup()` | Release nDPI context |

---

## Summary

| Need | Approach |
|------|----------|
| Pure functions | Module exporting functions |
| Object with state | Factory function + `setmetatable` + method `new` |
| Documentation | LDoc comments with typed `@tparam`/`@treturn` |
| Syntax | Significant indentation, `=>` fat arrow, `@` for `self` |
| FFI external lib | `ffi.load` + `ffi.cdef` (no C bridge) |
| Opaque C struct | `ffi.new("uint8_t[?]", size)` + `ffi.cast` |
| Packet parsing | `ffi.cast("const uint8_t*", raw)` + `bit` library |
| Log rate-limiting | `log.moon` counts identical (action, key) pairs; emits one entry per burst window |
| Shell `$` in strings | Write `$` directly — `\$` is an invalid Lua escape |

**Do not use**: `class`, `extends`, `new` (MoonScript class-based syntax), `require "moon"`.
