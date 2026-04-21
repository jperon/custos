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

### OpenWrt E2E (`make test-openwrt HOST=root@<host>`)

This is the only supported deployment mode. It requires SSH access to an OpenWrt router with CustosVirginum installed
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

### MAC-primary Sessions

User sessions are indexed by **MAC address** rather than IP. This ensures seamless tracking of clients across IPv4 and IPv6 (cross-family) and handles privacy extensions gracefully.
- Use `session_for_mac(mac, ip, path, sessions_table)` instead of IP-based lookups.
- Workers extract the client MAC from NFQUEUE metadata (`get_l2(nfad)` → `nfq_get_packet_hw()`).
- If the MAC cannot be extracted from the packet (e.g. `l2.mac_dst` is missing — it always is), workers MUST fallback to `neigh.get_mac(ip)`.
- If `neigh.get_mac(ip)` also fails, `session_for_mac` performs a fallback by searching the active sessions for the provided IP.

---

## Worker I/O Reference

Authoritative spec for what each worker receives, how it responds, and which channels it uses. Custos runs exclusively on nftables **table `bridge`**; there is no router mode.

### NFQUEUE payload format (all queues)

- `nfq_get_payload()` returns a buffer starting at the **IP header**. There is **no Ethernet header** in the payload, even for bridge hooks (contrary to the ebtables convention).
- Parse at offset 0 (or 1 in Lua 1-based slicing).
- `nfq_set_verdict(qh, id, NF_ACCEPT, len, buf)` replacement payload must also start at the IP header. NFQUEUE cannot reverse the direction of a packet: the skb keeps its original L2 header and the bridge forwards according to the original dst MAC.

### NFQUEUE metadata (libnfq accessors)

| Accessor | Returns | Notes |
|----------|---------|-------|
| `nfq_get_msg_packet_hdr` | `nfqnl_msg_packet_hdr*` | Big-endian `packet_id`. |
| `nfq_get_payload(nfad, &ptr)` | `int` length + pointer | IP header onwards. |
| `nfq_get_packet_hw(nfad)` | `nfqnl_msg_packet_hw*` | Source MAC (6 bytes). Destination MAC is **not** exposed. |
| `nfq_get_indev(nfad)` | `u32` | Ingress ifindex. |
| `nfq_get_outdev(nfad)` | `u32` | Egress ifindex (0 on pre-routing). |
| `nfq_get_nfmark(nfad)` | `u32` | Mark set by nftables. Here it carries the VLAN ID (`meta mark set @ll,112,16 & 0xfff`). |

### Queue map

| Queue | Worker | nft rule (table `bridge`) | Payload | Verdict strategy | Response injection |
|-------|--------|---------------------------|---------|------------------|--------------------|
| 0 | `worker_q0` | `th dport 53 queue to 0` | IP + UDP/TCP + DNS question | `NF_ACCEPT` (always, except fail-closed on parse error) | None on the wire; drops a 43-byte transaction in the Q0→Q1 pipe. |
| 1 | `worker_q1` | `th sport 53 queue to 1` | IP + UDP/TCP + DNS response | `NF_ACCEPT`, optionally `nfq_set_verdict(NF_ACCEPT, payload)` | Replacement payload: TTL-patched DNS + EDE `Custos vigilat`, or forged NXDOMAIN + EDE `Filtered` + synthetic `0.0.0.0`/`::`. |
| 2 | `worker_q2` | `tcp dport 80 tcp flags & (fin\|syn\|rst\|ack) == syn queue to 2` | IP + TCP SYN | `NF_DROP` | Three Ethernet frames (SYN-ACK, HTTP 302, FIN-ACK) built with `ipparse` and sent on `br` via `AF_PACKET`/`SOCK_RAW`. AF_PACKET is mandatory because NFQUEUE cannot invert direction and cannot inject three packets. |
| 3 | `worker_q3` | `limit rate 10/second burst 5 packets queue to 3` (and similar on auth-drop paths) | IP + any L4 | `nfq_set_verdict(NF_ACCEPT, payload)` (via `VERDICT_DONE`) | Replacement payload: forged TCP RST/ACK (swap src/dst, flags=RST+ACK, correct seq/ack) for TCP; ICMPv4 type 3/code 13 or ICMPv6 type 1/code 1 (admin-prohibited) quoting the original IP header + 8 bytes, for all other L4. |

### Per-worker I/O

- **Q0 (`worker_q0.moon`)**
  - In: NFQUEUE 0, pipe write-end from `main.moon` (IPC to Q1), `filter.yml` (hot-reloadable on SIGHUP).
  - Out: `NF_ACCEPT`/`NF_DROP`, IPC message via `ipc.write_msg` / `write_refused_msg` / `write_dnsonly_msg`.
  - Side effects: calls `ndpi.get_flow` for flow tracking; logs via `log_allow`/`log_block`.

- **Q1 (`worker_q1.moon`)**
  - In: NFQUEUE 1, pipe read-end (drained via `drain_pipe`), `sessions.lua` (mtime-cached), `filter` (for TTL config).
  - Out: `NF_ACCEPT` or `nfq_set_verdict(NF_ACCEPT, patched_payload)` (TTL + EDE) or built NXDOMAIN+EDE payload for refused transactions.
  - Side effects: adds DNS-resolved IPs to nft sets `ip4_allowed`, `ip6_allowed`, `mac4_allowed`, `mac6_allowed` with `timeout 2m`. Refreshes neighbour table (`ip neigh show`) at most every `NEIGH_REFRESH_COOLDOWN` seconds.

- **Q2 (`worker_q2.moon`)**
  - In: NFQUEUE 2 (TCP SYN/80 not authenticated), `AF_PACKET`/`SOCK_RAW` socket bound to ifindex `br` (opened once at startup), `sessions.lua`.
  - Out: `NF_DROP` on the SYN; 3 Ethernet frames injected via `sendto()` on the raw socket. Bridge MAC read from `/sys/class/net/br/address`.
  - Config: `auth_cfg.captive_ip4` / `captive_ip6` / `port` (default 33443) build the redirect URL.

- **Q3 (`worker_q3.moon`)**
  - In: NFQUEUE 3 (residual drop traffic, rate-limited by nft to avoid flood).
  - Out: `nfq_set_verdict(NF_ACCEPT, forged_ip_pkt)` for TCP (RST/ACK) or any other L4 (ICMP admin-prohibited).
  - The forged packet has src/dst IPs swapped relative to the original. Empirically the client receives the RST/ICMP (e.g. `curl https://1.1.1.1` returns "Connexion refusée" in <5 ms). The exact delivery path — bridge FDB lookup on the forged dst IP, kernel re-hook, or something else — has not been reverse-engineered; do not assume a particular mechanism when touching this worker.

- **AUTH (`auth/worker.moon`)**
  - In: `AF_INET` + `AF_INET6` `SOCK_STREAM` listen socket on `auth_cfg.port` (HTTPS, TLS via `luasec`), `/etc/custos/secrets`, `sessions.lua`.
  - Out: writes sessions into `sessions.lua` (atomic rename), applies nft entries to `authenticated_macs`, `authenticated_ips`, `authenticated_ips6`.
  - Signals: `SIGHUP` reloads secrets (flag set in handler, processed at next request).

### Q0 → Q1 IPC wire format

Binary fixed 43 bytes, written with `libc.write` on a `pipe2(O_NONBLOCK)` pipe. Atomicity guaranteed (< `PIPE_BUF = 4096`).

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | Type — `'A'` (0x41) IPv4 accept · `'6'` (0x36) IPv6 accept · `'R'` (0x52) IPv4 refused · `'r'` (0x72) IPv6 refused · `'D'` (0x44) IPv4 dnsonly · `'d'` (0x64) IPv6 dnsonly |
| 1–2 | 2 | DNS `txid` (big-endian) |
| 3–18 | 16 | Client IP — IPv4 left-padded with `0x00`×12, or full IPv6 |
| 19–20 | 2 | Client UDP/TCP source port (big-endian) |
| 21–26 | 6 | Client MAC (zeros if unknown) |
| 27–42 | 16 | Resolver IP — same padding convention |

### Sockets, pipes, files

| Component | Endpoint | Purpose |
|-----------|----------|---------|
| Q2 | `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` on ifindex `br` | Injects 3 Ethernet frames per captive redirect |
| AUTH | `socket(AF_INET/AF_INET6, SOCK_STREAM)` on `auth_cfg.port` | HTTPS captive portal |
| nftables | `libnftables` FFI (`nft_ctx_new`, `nft_run_cmd_from_buffer`) | Manages allowlist sets |
| Q0→Q1 pipe | `pipe2(O_NONBLOCK)` created in `main.moon` before fork | Binary IPC |
| `/var/run/custos/config.lua` | Read at startup | Generated by `uci_config.lua` from `/etc/config/custos` |
| `/etc/custos/secrets` | Read by AUTH | User credentials |
| `tmp/sessions.lua` (UCI-configurable) | Written by AUTH, read by Q0/Q1/Q2 (mtime cache) | MAC-indexed auth sessions |

### nft sets

| Set | Writer | Reader (nft rule) |
|-----|--------|-------------------|
| `ip4_allowed`, `ip6_allowed` | Q1 | `ip saddr . ip daddr @ip4_allowed accept` |
| `mac4_allowed`, `mac6_allowed` | Q1 | `ether saddr . ip daddr @mac4_allowed accept` |
| `authenticated_macs`, `authenticated_ips`, `authenticated_ips6` | AUTH (`nft_sessions`) | Bypasses captive queue (Q2) for authenticated clients |
| `ip4_dest_whitelist`, `ip6_dest_whitelist` | Static (`.nft`) | `ip daddr @ip4_dest_whitelist accept` |

### Supervisor & signals (`main.moon`)

- Forks each worker (Q0, Q1, AUTH, Q2, Q3) and watches via `waitpid(-1, …, WNOHANG)`; restarts on crash after a 1-second backoff.
- `signalfd`-based loop for `SIGHUP` / `SIGTERM`.
- `SIGHUP` → propagated to Q0 (reloads `filter`) and AUTH (reloads secrets).
- `SIGTERM` → shuts down all workers, removes extra nft rules installed at startup.

---

**Do not use**: `class`, `extends`, `new` (MoonScript class-based syntax), `require "moon"`.
