# CustosVirginum

Inline DNS filter on Linux bridge, written in **MoonScript** and executed by
**LuaJIT**. Blocks all DNS traffic except explicitly allowed domains,
logs L2/L3/L4/L7 information, and dynamically builds nftables allowlists
as DNS resolutions occur.

Packet parsing uses **pure LuaJIT FFI pointer arithmetic** for L3/L4/L7
decoding, combined with **libndpi** for deep packet inspection and protocol
detection — all without any C compilation step.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  Linux bridge machine                                          │
│                                                                │
│  nftables (kernel)                                             │
│  ├── policy DROP + REJECT LAN                                  │
│  ├── set ip4_allowed  { client_ip . dst_ip timeout 2m }        │
│  ├── set ip6_allowed  { client_ip . dst_ip timeout 2m }        │
│  ├── UDP/53 + TCP/53 src=LAN → NFQUEUE 0  (questions)          │
│  └── UDP/53 + TCP/53 dst=LAN → NFQUEUE 1  (responses)          │
│                                                                │
│  LuaJIT (userspace)                                            │
│  ├── main.lua        supervisor + fork                         │
│  ├── worker Q0  ─────────────────── pipe IPC ──► worker Q1    │
│  │   parse L2/L3/L4/L7 (FFI)                    drain pipe     │
│  │   lookup allowlist                           verify txid    │
│  │   log + ACCEPT/REJECT                        patch TTL→60s  │
│  │   write(pipe, txid+ip+port+mac)              nft set add    │
│  │   or send REFUSED (socket UDP/53)            ACCEPT+payload │
│  └── ./tmp/dns-filter.log                                      │
└────────────────────────────────────────────────────────────────┘
```

### Allowed packet flow

```
DNS Client (LAN)
   │  question UDP/53 → www.github.com ?
   ▼
nft FORWARD → NFQUEUE 0
   ▼
worker Q0 : parse L2+L3+L4+DNS → qname="www.github.com"
   │  is_allowed("www.github.com") → true (suffix "github.com")
   │  log: ALLOW mac_src=aa:bb:.. src_ip=192.168.1.42 qname=www.github.com
   │  write(pipe, txid=0x1234, ip=192.168.1.42, port=54321, mac=aa:bb:cc:dd:ee:ff)
   └► NF_ACCEPT → question forwarded to resolver
   ▼
DNS Resolver (8.8.8.8) responds
   ▼
nft FORWARD → NFQUEUE 1
   ▼
worker Q1 : drain pipe → pending[0x1234:192.168.1.42:54321] found (refused=false)
   │  parse response → A 140.82.121.4
   │  patch TTL → 60s + append EDE code 0 "Custos vigilat." + recalc checksums
   │  nft add element ip dns-filter ip4_allowed { 192.168.1.42 . 140.82.121.4 timeout 2m }
   │  log: ALLOW action=response_patched answers=1 ttl_set=60
   └► NF_ACCEPT + modified payload
   ▼
Client receives response (TTL=60s)
   ▼
Client opens TCP connection → 140.82.121.4
   ▼
nft FORWARD : ip saddr . ip daddr @ip4_allowed accept → allowed through
```

### Blocked packet flow

```
DNS Client (LAN)
   │  question UDP/53 → www.facebook.com ?
   ▼
nft FORWARD → NFQUEUE 0
   ▼
worker Q0 : qname="www.facebook.com"
   │  is_allowed("www.facebook.com") → false
   │  log: BLOCK reason=not_in_allowlist
   │  write_refused_msg(pipe, txid=0x1234|REFUSED, ip, port, mac)
   └► NF_ACCEPT → question forwarded to resolver
   ▼
DNS Resolver (8.8.8.8) responds
   ▼
nft FORWARD → NFQUEUE 1
   ▼
worker Q1 : drain pipe → pending[0x1234:192.168.1.42:54321] found (refused=true)
   │  transform response → RCODE=5 REFUSED + EDE code 15 "Filtered" + "Custos vigilat."
   │  replace DNS payload, recalc checksums
   │  log: BLOCK action=response_refused
   └► NF_ACCEPT + REFUSED payload (client receives REFUSED + EDE)
```

---

## Project Structure

```
custos/
├── cfg/
│   └── filter.yml           Filter authorization config (YAML)
├── src/
│   ├── config.moon          Configuration: allowlist, constants
│   ├── uci_config.moon      OpenWrt UCI config loader
│   ├── ffi_defs.moon        Centralized FFI declarations
│   ├── log.moon             Structured key=value logging
│   ├── allowlist.moon       qname lookup + SIGHUP reload
│   ├── ipc.moon             pipe Q0→Q1 protocol
│   ├── neigh.moon           Kernel neighbor table reader (ip neigh show)
│   ├── nft.moon             nftables set injection via libnftables
│   ├── nfq_loop.moon        Generic NFQUEUE loop
│   ├── worker_q0.moon       DNS questions worker
│   ├── worker_q1.moon       DNS responses worker
│   ├── main.moon            Supervisor + fork
│   ├── ffi_ndpi.moon        Version-detecting facade (loads v4 or v5)
│   ├── ffi_ndpi_v4.moon     FFI cdef for nDPI 4.2–4.8
│   ├── ffi_ndpi_v5.moon     FFI cdef for nDPI 5.0+
│   ├── filter/
│   │   ├── init.moon        Filter engine entry point (load/decide/reload)
│   │   ├── rule.moon        Rule evaluator (conditions + actions)
│   │   ├── convert.moon     YAML → engine type converters
│   │   ├── updater.moon     CLI: download + parse + atomic-write domain lists
│   │   ├── actions/         Action modules (allow, deny, mail)
│   │   ├── conditions/      Condition modules (from_net, to_domain, in_time, …)
│   │   └── lib/
│   │       ├── bsearch.moon     Binary search in sorted domain list files
│   │       ├── ipcalc.moon      CIDR membership check
│   │       ├── load_config.moon YAML config loader (lyaml wrapper)
│   │       └── parse_domains.moon Multi-format domain list parser
│   └── parse/
│       ├── ethernet.moon    L2: MAC src via nfq_get_packet_hw
│       ├── ip.moon          L3: IPv4 + IPv6 + checksums
│       ├── udp.moon         L4: UDP + checksum recalculation
│       ├── dns.moon         L7: RFC 1035 complete + TTL patch
│       ├── ndpi.moon        L3-L7 unified parser (facade)
│       ├── ndpi_v4.moon     nDPI 4.2–4.8 detection backend
│       └── ndpi_v5.moon     nDPI 5.0+ detection backend
├── lua/                     Lua generated by moonc (do not edit)
├── nft-rules/
│   └── dns-filter.nft       Universal nftables ruleset (bridge + router)
├── tests/
│   ├── run_tests.moon       Unit tests source (no root required)
│   ├── run_tests.lua        Unit tests compiled
│   ├── test_ndpi.moon       nDPI wrapper tests source
│   ├── test_ndpi.lua        nDPI wrapper tests compiled
│   ├── test_docker.moon     Docker E2E tests source
│   ├── test_docker.lua      Docker E2E tests compiled
│   ├── test_kvm.moon        KVM/libvirt E2E tests source (20 tests)
│   └── test_kvm.lua         KVM/libvirt E2E tests compiled
├── libvirt/
│   ├── *.xml                Libvirt VM configs (filter/client/router)
│   └── custos-libvirt.sh    VM management script
├── Dockerfile               Multi-stage Docker build
├── docker-compose.yml       Complete test environment
├── LICENSE                  MIT license
├── Makefile
├── setup.sh
└── README.md
```

---

## Prerequisites

### System Packages

| Package                  | Role                                    |
|--------------------------|-----------------------------------------|
| `luajit`                 | Compiled Lua execution                  |
| `moonscript`             | `.moon` → `.lua` compilation            |
| `lua-yaml`               | YAML config loader (`lyaml`, LuaJIT)    |
| `libnetfilter-queue1`    | NFQUEUE C library                       |
| `libnftables1`           | nftables library (set injection)        |
| `libndpi-dev`            | nDPI deep packet inspection (FFI)       |
| `nftables`               | `nft` tool                              |
| `kmod: br_netfilter`     | Bridge packets visible to netfilter     |

**Debian/Ubuntu:**
```bash
apt install luajit lua-yaml libnetfilter-queue1 libnftables1 libndpi-dev nftables
luarocks install moonscript
```

**OpenWrt:**
```bash
opkg install luajit lyaml libnetfilter-queue nftables kmod-br-netfilter
# moonscript via luarocks or build from source
```

**Docker (build image):**
```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    luajit lua-yaml libnetfilter-queue1 libnftables1 nftables \
    lua5.1 luarocks build-essential \
    && luarocks install moonscript \
    && rm -rf /var/lib/apt/lists/*
```

**Docker (runtime):**
```bash
# Docker and Docker Compose
apt install docker.io docker-compose-plugin

# Add user to docker group (logout/login required)
usermod -aG docker $USER
```

---

## Installation

```bash
git clone <repo> custos
cd custos

# Compile MoonScript → Lua
make

# Run unit tests (no root required)
make test

# Run nDPI wrapper tests (requires libndpi)
make test-ndpi

# Load br_netfilter, check deps, apply nft rules
sudo ./setup.sh up
```

---

## Configuration

All configuration is in `src/config.moon`:

```moonscript
-- Allowed domains (suffix matching)
ALLOWED_DOMAINS = {
  "github.com"
  "debian.org"
  -- add more here...
}

-- IP timeout in nft sets after resolution
NFT_IP_TIMEOUT = "2m"

-- Forced TTL injected on all passing DNS responses (seconds)
FORCED_TTL = 60   -- in src/config.moon (imported by worker_q1)
```

After modification:
```bash
make          # recompile
make reload   # send SIGHUP to workers (hot reload)
```

---

## Running

```bash
# Verify nft rules are in place
sudo ./setup.sh status

# Start the filter (stays in foreground)
sudo make run

# In another terminal, watch logs
make logs
```

Example log:
```
[1718100000] [1234] INFO  action=dns-filter_start version=1.0.0
[1718100001] [1235] INFO  action=queue_listening queue=0
[1718100001] [1236] INFO  action=queue_listening queue=1
[1718100010] [1235] ALLOW mac_src=aa:bb:cc:dd:ee:ff in_if=3 src_ip=192.168.1.42
                          dst_ip=8.8.8.8 src_port=54321 dst_port=53
                          txid=0x1234 qname=www.github.com qtype=A
[1718100010] [1236] ALLOW action=response_patched src_ip=8.8.8.8
                          dst_ip=192.168.1.42 txid=0x1234
                          qnames=www.github.com answers=2 ttl_set=60
[1718100015] [1235] BLOCK mac_src=aa:bb:cc:dd:ee:ff src_ip=192.168.1.42
                          qname=www.facebook.com qtype=A reason=not_in_allowlist
```

---

## IPC Protocol Q0 → Q1

The Unix pipe (created before `fork()`) carries 27-byte messages.
Atomicity is guaranteed by POSIX for messages ≤ PIPE_BUF (4096 bytes).

```
Byte  0      : type  — 0x41 ('A') = IPv4 allowed,    0x36 ('6') = IPv6 allowed
                       0x52 ('R') = IPv4 refused,     0x72 ('r') = IPv6 refused
Bytes 1-2    : DNS txid (big-endian uint16)
Bytes 3-18   : source IP — 16 bytes
                 IPv4 : 4 bytes address + 12 zero bytes (padding)
                 IPv6 : 16 bytes address (complete, no truncation)
Bytes 19-20  : source port (big-endian uint16)
Bytes 21-26  : source MAC (6 bytes, zeroed if unavailable)
```

Q1 maintains a table `pending[txid:ip:port] = {expire, refused}` (TTL 5s).
`refused=true` means Q0 determined the query must be blocked; Q1 transforms
the upstream response into a REFUSED reply instead of patching TTL.
Purge is **lazy**: an expired entry is removed at lookup time,
without a separate timer.

---

## TTL Patch

Each allowed DNS response is modified before being returned to the client:

1. All Resource Record TTLs are rewritten to 60 seconds
2. An EDNS OPT option EDE code 0 "Other" with extra-text `"Custos vigilat."`
   is appended to the response's OPT RR, signalling that TTL was clamped
3. L4 checksum is recalculated (`UDP` or `TCP`, IPv4/IPv6 pseudo-header)
4. IPv4 header checksum is recalculated when applicable
5. `NF_ACCEPT` verdict is set with modified payload via
   `nfq_set_verdict(qh, pkt_id, NF_ACCEPT, len, patched_ptr)`

Each blocked DNS response (where Q0 sent `refused=true`) is replaced by
a REFUSED reply with EDE code 15 "Filtered" and extra-text `"Custos vigilat."`,
reconstructed from the upstream server's TCP/UDP framing (so no raw-socket
spoofing is needed).

For multi-segment TCP DNS responses, Q1 buffers segments, patches the fully
assembled DNS payload once complete, then reinjects a single coalesced
`PSH|ACK` segment (with corrected checksums and initial sequence number).

The goal is to force clients to re-validate resolution every 60 seconds,
ensuring IPs authorized in nft sets (2-minute timeout) remain valid
as long as the client actively resolves the name.

---

## nDPI Integration

The `parse/ndpi` module replaces the separate `parse/ip` + `parse/udp` +
`parse/dns` pipeline with a single unified parser. It uses:

- **Pure FFI pointer arithmetic** (`uint8_t*` + `bit` library) for
  L3/L4/L7 header decoding — no `string.byte()`, no C bridge, no
  compilation step.
- **libndpi** (loaded at runtime via `ffi.load "ndpi"`) for protocol
  detection. nDPI provides two levels of classification:
  - `ndpi_master` — transport protocol (e.g. `5` = DNS)
  - `ndpi_app` — application behind the query (e.g. `203` = Github)
- **Pre-allocated buffers** (`flow_buf`, `ipv6_str`) reused across calls
  to avoid GC pressure in the hot path.
- **DNS name decompression** (RFC 1035 §4.1.4) implemented in MoonScript
  with FFI pointers — JIT-compilable by LuaJIT.

### Version Tolerance

The wrapper auto-detects the installed libndpi version via
`ndpi_revision()` at load time, then dispatches to the appropriate
backend:

| Versions | Backend | Key differences |
|----------|---------|----------------|
| 4.2–4.4  | `v4`    | 5-arg `ndpi_detection_process_packet` |
| 4.6–4.8  | `v4`    | 6-arg (added `input_info`), `bitmask2` returns `int` |
| 5.0+     | `v5`    | No `NDPI_PROTOCOL_BITMASK`, different `ndpi_init_detection_module` signature, opaque `ndpi_protocol` struct (read via accessors) |

```
ffi_ndpi.moon       → ndpi_revision() → major >= 5?
                       ├── yes → ffi_ndpi_v5 cdef + parse.ndpi_v5
                       └── no  → ffi_ndpi_v4 cdef + parse.ndpi_v4
                                  └── minor >= 6? → 5-arg or 6-arg
```

### API

```moonscript
ndpi = require "parse.ndpi"

-- Single-call L3+L4+L7 parse + nDPI detection
-- Returns (pkt, nil) on success, (nil, "buffering") while reassembling a
-- multi-segment TCP DNS stream, (nil, "tcp_control") for TCP control packets
-- without DNS payload (SYN/ACK/FIN), or (nil, nil) on unrecognised packets.
pkt, status = ndpi.parse_packet raw
-- pkt.ip    (version, ihl, src_ip, dst_ip, src_ip_raw, ...)
-- pkt.l4    (proto, src_port, dst_port, len, off, payload_len)
--   proto = "udp" or "tcp"
--   TCP extras: pkt.tcp_dns_raw        (assembled DNS payload, multi-segment)
--               pkt.tcp_single_segment  (bool — false when reassembled from N segments)
--               pkt.tcp_init_seq        (uint32 — TCP seq of first segment; used to
--                                        reinject a coalesced+TTL-patched reply)
-- pkt.dns   (txid, is_response, qdcount, ancount, rcode, ...)
-- pkt.questions  [{qname, qtype, qclass, qtype_name}, ...]
-- pkt.ndpi_master, pkt.ndpi_app

-- Parse DNS answer RRs
answers = ndpi.parse_answers raw, pkt
-- [{name, rtype, ttl, ttl_offset, rdata_str, rdata_raw}, ...]

-- Patch TTLs + fix checksums, return modified packet
patched = ndpi.patch_and_checksum raw, pkt, answers, 60

-- Cleanup
ndpi.cleanup!
```

The old per-layer modules (`parse/ip`, `parse/udp`, `parse/dns`) remain
available for reference or fallback.

---

## Authentication

CustosVirginum includes an HTTPS authentication server that maps LAN client IPs to user
accounts. The `from_user` filter condition allows rules such as
"only user alice can reach github.com".

### Process model

A third worker (`AUTH`) is forked by the supervisor alongside Q0 and Q1:

```
main (supervisor)
├── worker Q0 (DNS questions)
├── worker Q1 (DNS answers)
└── worker AUTH (HTTPS login server)
```

Sessions are shared via a Lua-evaluable file (`tmp/sessions.lua`). Q0/Q1 workers
reload it every 5 seconds (TTL cache). No inter-process socket is needed.

### TLS certificate

On first start the AUTH worker generates a **self-signed certificate** via
`openssl req` and stores it in `tmp/auth.crt` / `tmp/auth.key`.

To use your own certificate, set `cert` and `key` in `cfg/filter.yml`:

```yaml
auth:
  port: 8443
  cert: /etc/custos/auth.crt
  key:  /etc/custos/auth.key
  secrets: cfg/secrets
  session_ttl: 86400        # seconds (default: 24 h)
```

### Secrets file

Each line holds one credential in the format:

```
user:pbkdf2-sha256:<iterations>:<salt_hex>:<hash_hex>
```

Generate an entry with:

```bash
make make-secret USER=alice PASS=hunter2
# → append the printed line to cfg/secrets
```

See `cfg/secrets.sample` for a full example.

### Logging in

Navigate to `https://<router>:8443/` in a browser (accept the self-signed cert
warning). After a successful login the client IP is recorded in the session
store. Sessions expire after `session_ttl` seconds or on explicit logout.

### Using `from_user` in rules

```yaml
rules:
  - name: alice-only
    conditions:
      from_user: alice
    action: allow
    domains: [github.com, pypi.org]
```

Multiple users can be listed (logical OR):

```yaml
    conditions:
      from_user: [alice, bob]
```

### Captive portal (future)

Automatic redirect of HTTP traffic to the login page is **not yet implemented**.
Users must navigate to the auth URL manually.

---

## Known Limitations

- **DoH / DoT**: not covered (ports 443/853).
- **Single-threaded per worker**: one worker per queue. For very
  high throughput, use `--queue-balance N-M` with N workers per range.

## nft Ruleset

The single file `nft-rules/dns-filter.nft` is a **universal ruleset** that
works in bridge mode, router mode, or any combination (including IPv4 bridge +
IPv6 WireGuard tunnel for SLAAC distribution). It has **no dependency on
interface names or IP address ranges**.

### How it works

- DNS (UDP/TCP port 53) from LAN → **NFQUEUE 0** (questions, worker Q0)
- DNS responses (sport 53) to LAN → **NFQUEUE 1** (responses, worker Q1)
- LuaJIT decides ACCEPT or REFUSED; sets `ip4_allowed`/`ip6_allowed` on success
- All other forwarded traffic matching a set entry → ACCEPT; rest → DROP

### Prerequisites

```bash
# Load br_netfilter so bridge packets reach netfilter hooks
modprobe br_netfilter
sysctl -w net.bridge.bridge-nf-call-iptables=1
sysctl -w net.bridge.bridge-nf-call-ip6tables=1

# Apply (no parameters needed)
sudo nft -f nft-rules/dns-filter.nft
# or
sudo ./setup.sh up
```

### IPv6 / ICMPv6

The IPv6 FORWARD chain explicitly passes NDP messages (neighbor-solicit,
neighbor-advert, router-solicit) and ICMPv6 echo — required when
`br_netfilter` intercepts L2 neighbor discovery frames.

---

## Docker Tests

The filter runs in a privileged Docker container with host networking.
The `docker-compose.yml` includes `client`, `filter`, `router`, and
`wan-dns` (CoreDNS) containers.

```bash
make test-docker          # nDPI 4.x (Debian image)
make test-docker-ndpi5    # nDPI 5.0 (Arch AUR image)
```

Manual inspection:
```bash
docker exec -it custos-client nslookup github.com
docker exec -it custos-client nslookup facebook.com  # → REFUSED
docker logs -f custos-filter
docker compose down
```

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│   client     │      │   filter     │      │    router    │
│ (container)  ├──────┤ (Docker,     ├──────┤ (container)  │
│              │      │  host net)   │      │              │
└──────────────┘      └──────────────┘      └──────────────┘
                              │
                     ┌──────────────┐
                     │  wan-dns     │
                     │ (CoreDNS)    │
                     └──────────────┘
```

---

## KVM/Libvirt End-to-End Tests

A full test suite (20 tests) runs against three KVM virtual machines.
The filter VM runs CustosVirginum natively (no container).

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│   client     │      │   filter     │      │    router    │
│   (Debian)   ├──────┤ (Debian,     ├──────┤  (OpenWrt)   │
│  10.99.0.10  │      │  native nft) │      │              │
│  fd99::10    │      │              │      │              │
└──────────────┘      └──────────────┘      └──────────────┘
```

### Running

```bash
make test-kvm          # full cycle: up + 20 tests + down
make test-kvm-up       # start VMs (creates them on first run)
make test-kvm-run      # run tests only (VMs already up)
make test-kvm-down     # stop VMs
```

### What the 20 tests cover

| Category | Examples |
|----------|---------|
| DNS ALLOW | `github.com` → `ip4_allowed` populated; ping works after |
| DNS REFUSED | `facebook.com` → RCODE 5 + EDE 15; ping stays blocked |
| IPv6 AAAA | `cloudflare.com` AAAA → `ip6_allowed` populated; ping6 works |
| TTL patch | Response TTL forced to 60s |
| Per-client isolation | client2 (10.99.0.11) blocked until it resolves independently |
| Log validation | `action=ALLOW`, `action=REFUSED` present in log file |

### One-time VM setup

```bash
sudo bash libvirt/custos-libvirt.sh create
```

Downloads Debian cloud image and OpenWrt 25.12, creates three domains
(`custos-filter`, `custos-router`, `custos-client`) with cloud-init.

### Cleanup

```bash
sudo bash libvirt/custos-libvirt.sh delete
```
