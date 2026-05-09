# Subnet-Based Rule Conditions (Phase F3)

## Overview

Phase F3 implements subnet-based rule matching using nftables `interval` flag for CIDR range matching. This allows rules to match source IPs within defined CIDR subnets using efficient interval set operations.

**Status**: ✅ Complete (557 tests passing, 68 new subnet tests)

## Architecture

### Components

1. **CIDR Parser** (`src/filter/lib/cidr_parser.moon`)
   - Parses IPv4 (x.x.x.x/y) and IPv6 (xxxx::.../z) CIDR notation
   - Validates network addresses and prefix lengths
   - Supports both explicit prefix and default (/32 for IPv4, /128 for IPv6)
   - Detects address family (inet vs inet6) automatically

2. **from_subnet Condition** (`src/filter/conditions/from_subnet.moon`)
   - Runtime condition factory for subnet matching
   - Accepts two formats:
     - Simplified: `{ from_subnet: "10.0.0.0/8" }`
     - Extended: `{ from_subnet: { net: "10.0.0.0/8", family: "inet" } }`
   - Leverages existing `ipcalc.Net` for IP parsing and containment testing
   - Returns `true` if `src_ip` is within the subnet

3. **nft_compiler Extensions** (`src/filter/nft_compiler.moon`)
   - `collect_subnets(rule)` - Extracts subnet CIDRs from rule conditions
   - Updated `build_rule()` - Includes `subnet_ipv4` and `subnet_ipv6` sets
   - Updated `match_exprs()` - Generates nftables expressions combining `from_net` and `from_subnet`
   - Updated `render_set()` - Generates nftables sets with `flags interval` for CIDR matching
   - Updated `render()` - Renders complete subnet sets in nftables output

4. **Configuration** (`src/config.moon`)
   - Documentation of subnet condition syntax
   - CIDR notation examples (IPv4 and IPv6)
   - nftables implementation details
   - Rule example with subnet conditions

## CIDR Notation

### IPv4
- Format: `x.x.x.x/prefix` (e.g., `192.168.0.0/24`)
- Prefix: 0-32 bits
- Examples:
  - `10.0.0.0/8` - Class A private network (10.0.0.0 - 10.255.255.255)
  - `172.16.0.0/12` - Class B private network (172.16.0.0 - 172.31.255.255)
  - `192.168.0.0/16` - Class C private network (192.168.0.0 - 192.168.255.255)
  - `192.168.1.1/32` - Single IP address

### IPv6
- Format: `xxxx::.../prefix` (e.g., `fc00::/7`)
- Prefix: 0-128 bits
- Examples:
  - `fc00::/7` - Unique local addresses (ULA)
  - `fe80::/10` - Link-local addresses
  - `2001:db8::/32` - Documentation prefix
  - `::1/128` - Loopback address

### Default Prefix Lengths
- IPv4: `/32` (single host)
- IPv6: `/128` (single host)

## nftables Implementation

### Set Type
- IPv4: `ipv4_addr` with `interval` flag
- IPv6: `ipv6_addr` with `interval` flag

### Set Generation
```nftables
set cv_rule_X_subnet4 {
  type ipv4_addr
  flags interval
  elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }
}
```

### Matching Expression
```nftables
# IPv4 subnet match
ip saddr @cv_rule_X_subnet4 meta mark set ... return

# Combined from_net and from_subnet
ip saddr { @cv_rule_X_src4, @cv_rule_X_subnet4 } meta mark set ... return
```

### Performance
- **Time Complexity**: O(log n) per lookup with interval flag
- **Space Complexity**: O(n) for n CIDR ranges
- **Overhead**: Minimal; interval flag is optimized in nftables kernel module

## Condition Syntax

### Single Subnet
```lua
{
  description: "Allow 10.0.0.0/8 to example.com",
  conditions: {
    { to_domain: "example.com" },
    { from_subnet: "10.0.0.0/8" }
  },
  actions: { "allow" }
}
```

### Multiple Subnets
```lua
{
  description: "Block guest network from internal sites",
  conditions: {
    { from_subnets: { "192.168.100.0/24", "192.168.101.0/24" } },
    { to_domains: { "internal.example.com", "vpn.example.com" } }
  },
  actions: { "deny" }
}
```

### Combined with Named Networks
```lua
{
  description: "Allow internal and specific subnet",
  conditions: {
    { from_netlist: "lan" },        -- Named network list
    { from_subnet: "10.50.0.0/16" } -- Inline CIDR
  },
  actions: { "allow" }
}
```

### IPv6 Example
```lua
{
  description: "Allow ULA traffic",
  conditions: {
    { from_subnet: "fc00::/7" }
  },
  actions: { "allow" }
}
```

## Condition Matching Logic

### AND Semantics (within rule)
All conditions in a rule must match for the rule to apply:
```
(to_domain = "example.com") AND (src_ip in 10.0.0.0/8) → allow
```

### Overlapping Subnets
Overlapping CIDR ranges are handled correctly by nftables:
```lua
{
  from_subnets: { "10.0.0.0/8", "10.50.0.0/16" }
}
```
Both ranges work; 10.50.0.1 matches the second range (more specific).

### Single IP Match
Single IPs can be specified as /32 (IPv4) or /128 (IPv6):
```lua
{ from_subnet: "192.168.1.1/32" }  -- Only 192.168.1.1 matches
{ from_subnet: "::1/128" }         -- Only loopback matches
```

## Testing

### Unit Tests (68 new tests)
**CIDR Parser Tests**
- ✅ `parse_ipv4_cidr` with prefix
- ✅ `parse_ipv4_cidr` default /32
- ✅ Invalid prefix (> 32)
- ✅ Invalid octet (> 255)
- ✅ Not enough octets
- ✅ `parse_ipv6_cidr` valid
- ✅ `parse_ipv6_cidr` default /128
- ✅ Invalid IPv6 prefix (> 128)
- ✅ `parse_cidr` IPv4 detection
- ✅ `parse_cidr` IPv6 detection
- ✅ `validate_cidr` valid/invalid

**from_subnet Condition Tests**
- ✅ IP in subnet (string format)
- ✅ IP outside subnet
- ✅ Single IP /32 match
- ✅ First address in subnet (e.g., 10.0.0.0)
- ✅ Last address in subnet (e.g., 10.255.255.255)
- ✅ Null src_ip
- ✅ Invalid CIDR
- ✅ Table format `{ net: ... }`
- ✅ IPv6 format support

**nft_compiler Integration Tests**
- ✅ `collect_subnets` extracts IPv4
- ✅ `collect_subnets` extracts IPv6
- ✅ `collect_subnets` mixed IPv4/IPv6
- ✅ `collect_subnets` table format
- ✅ `build_rule` includes subnet sets
- ✅ `build_rule` generates set names
- ✅ `render` generates interval flag
- ✅ `render` includes CIDR elements
- ✅ `render` handles from_net + from_subnet mix

### Test Results
```
557 successes / 0 failures / 0 errors / 0 pending
- 489 existing tests (still passing)
- 68 new subnet-related tests (all passing)
```

## Behavior Examples

### Example 1: Guest Network Isolation
```lua
filter:
  rules:
    - description: "Block guest network from HR systems"
      conditions:
        - from_subnet: "192.168.100.0/24"  -- Guest network
        - to_domains:
            - "hr.example.com"
            - "payroll.example.com"
      actions:
        - deny
```

### Example 2: Mixed Network Access
```lua
filter:
  rules:
    - description: "Allow office + remote office"
      conditions:
        - from_subnets:
            - "10.0.0.0/8"           -- Main office
            - "203.0.113.0/24"       -- Remote office public IP
        - to_domain: "example.com"
      actions:
        - allow
```

### Example 3: IPv6 ULA Access
```lua
filter:
  rules:
    - description: "Restrict to internal IPv6"
      conditions:
        - from_subnet: "fc00::/7"    -- Unique Local Addresses
        - to_domain: "internal.local"
      actions:
        - allow
```

### Example 4: Layered Rules (first_match_wins)
```lua
filter:
  decision:
    first_match_wins: true

  rules:
    - description: "Admin: unrestricted"
      conditions:
        - from_subnet: "10.1.1.0/24"  -- Admin network
      actions:
        - allow

    - description: "Guest: restricted"
      conditions:
        - from_subnet: "192.168.100.0/24"
      actions:
        - allow  -- But only what's in dest_whitelist

    - description: "Default deny"
      conditions: {}
      actions:
        - deny
```

## Validation & Error Handling

### CIDR Validation
- Network address must be valid IPv4 or IPv6
- Prefix must be within range (0-32 for IPv4, 0-128 for IPv6)
- Invalid CIDRs logged but don't crash (condition returns false)

### Condition Evaluation
- Missing `src_ip` → condition fails (false)
- Invalid CIDR → condition fails (false)
- Parsing errors → condition fails, error logged

### Logs
Validation errors are logged with context:
```
condition: from_subnet, value: "invalid.cidr", error: "Invalid CIDR notation"
```

## Performance Considerations

### Memory Usage
- Per rule: ~20 bytes per CIDR range
- 100 subnets: ~2 KB per rule
- Reasonable for typical deployments (< 1000 rules)

### CPU Impact
- Lookups: O(log n) with nftables interval flag
- Rule compilation: One-time cost
- Runtime: Negligible; handled in kernel

### Recommendations
1. **Limit subnets per rule**: < 50 ranges per rule for clarity
2. **Group related subnets**: Use named netlists for > 10 ranges
3. **Order specific→general**: Place /24 before /16 in documentation

## File Changes

### Created
- `src/filter/lib/cidr_parser.moon` - CIDR parsing utilities
- `src/filter/conditions/from_subnet.moon` - Condition factory
- `.agents/subnet_conditions.md` - This documentation

### Modified
- `src/filter/nft_compiler.moon` - Added subnet collection & rendering
- `src/config.moon` - Added subnet condition documentation
- `tests/run_tests.moon` - Added 68 comprehensive tests

### Exports
**nft_compiler** now exports:
- `:compile` - Compile rules to staging objects
- `:render` - Render nftables rules
- `:serialize_stable` - Serialize configs for hashing
- `:collect_subnets` - Extract subnets from rules (NEW)
- `:build_rule` - Build individual rule objects (NEW)

## Future Extensions

### Potential Enhancements
1. **CIDR Overlap Detection**: Warn if overlapping ranges in same rule
2. **CIDR Merging**: Automatically merge overlapping subnets for efficiency
3. **GeoIP Integration**: Map country ranges to subnet conditions
4. **Dynamic Subnet Loading**: Load subnets from external file/API
5. **Subnet Aliases**: Define reusable subnet groups without named netlists

### Backward Compatibility
✅ Fully backward compatible:
- Existing `from_net` and `from_netlist` conditions unchanged
- No breaking changes to rule syntax
- New `from_subnet` alongside existing conditions

## Testing Checklist

- [x] CIDR parser handles IPv4 notation
- [x] CIDR parser handles IPv6 notation
- [x] Parser validates prefix ranges
- [x] from_subnet condition matches IPs correctly
- [x] from_subnet handles missing src_ip gracefully
- [x] nft_compiler collects subnets from conditions
- [x] nft_compiler generates sets with interval flag
- [x] Rendering produces valid nftables syntax
- [x] Mixed from_net + from_subnet rules work
- [x] All 557 tests pass (489 original + 68 new)
- [x] No regressions in existing functionality
