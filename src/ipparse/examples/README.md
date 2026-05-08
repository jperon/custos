# ipparse Examples

## parse_real_quic.moon

Demonstrates complete L2-L7 packet parsing from a real QUIC packet captured in a `.pcap` or `.pcapng` file.

### Running the Example

**Direct (from anywhere):**
```bash
/PATH/TO/ipparse/examples/parse_real_quic.moon /path/to/capture.pcap
```

**Via Make (default: `quic.pcapng` at project root):**
```bash
make example
```

**Via Shell Script:**
```bash
./examples/parse_real_quic.sh /path/to/capture.pcapng
```

### What It Does

Parses a real CloudFlare QUIC packet and displays:

- **Layer 2 (Ethernet):** Source and destination MAC addresses, protocol type
- **Layer 3 (IPv6):** Source and destination IPv6 addresses, next header type
- **Layer 4 (UDP):** Source and destination ports, packet length
- **Layer 7 (QUIC):** Long header flag, version, DCID, encrypted packet length

### Sample Output

```
================================================================================
QUIC Packet Parser - Real Packet from quic.pcapng
================================================================================

Layer 2 (Ethernet):
  src MAC: e08f4cc891fa
  dst MAC: a42bb0f2c1fc
  protocol: 0x86dd

Layer 3 (IPv6):
  src: 2001:0867:000f:a009:0000:0000:0000:0f13
  dst: 2606:4700:4400:0000:0000:0000:ac40:996e
  next header: 17

Layer 4 (UDP):
  src port: 44339
  dst port: 443

Layer 7 (QUIC):
  long header: true
  version: 0x00000001
  DCID: 133a971cdef32a97
  packet length: 949

Layer 7 (SNI Extraction - RFC 9001):
  ✓ Initial secret derived from DCID
  ✓ Decryption keys derived (3x)
    - Key: 98d052be30563aff8180f7cbbaf04a8d
    - IV: 9a872f755c9c173df6d21846
    - HP Key: b7ee662400b75622ffa4835cf37930cd

  ℹ SNI extraction requires header protection removal
    and packet number recovery (see RFC 9001 §5.4)

================================================================================
✓ Successfully parsed QUIC packet from L2 to L7
================================================================================
```

### Technical Details

- **Source:** Real packet from [QaCafe CloudFlare QUIC samples](https://www.qacafe.com/resources/sample-captures-for-quic-doh-communityid-wpa3-cloudshark-3-10/)
- **Format:** Hex string embedded in code (avoids binary I/O dependencies)
- **Language:** MoonScript (compiles to Lua)
- **Requires:** luajit (for FFI-based binary operations)
