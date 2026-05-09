# Phase A4: DNS Response Policy Specification
## TTL, EDE, and DNSSEC Semantics for CustosVirginum Dynamic TTL Migration

**Document Version:** 1.0  
**Date:** 2025  
**Scope:** Final specification for DNS response handling covering TTL calculation, EDE injection, DNSSEC impacts, and checksum changes

---

## 1. Executive Summary

This specification formalizes the DNS response policy for CustosVirginum's migration from global forced TTL (60s) to **dynamic TTL with timeout-based nftables caching**. It covers:

1. **Decision matrix** for three verdict paths (allow/refuse/dnsonly) × payload modifications (none/EDE only/HTTPS strip/etc.)
2. **TTL calculation logic** using `rr_timeout(ttl) = clamp(ttl + grace, min, max)`
3. **EDE injection rules** with specific conditions for EDE code 4 (Forged-Answer) vs 17 (Filtered)
4. **DNSSEC implications** of signature stripping and OPT RR modification
5. **Checksum changes** across all verdict/modification paths with recalculation triggers

---

## 2. Current State (Pre-Migration)

### 2.1 TTL Configuration
From `src/config.moon` (lines 26-31):
```lua
dns.ttl_grace = {
  grace = 600    -- 10 minutes
  min   = 60     -- 1 minute
  max   = 2592000 -- 30 days
}
```

### 2.2 Response Pipeline
From `src/worker_responses.moon`:
- **Question side** (worker_questions.moon): Verdict decision (allow/refuse/dnsonly) + initial IPC message
- **Response side** (worker_responses.moon): Receive UDP DNS response, patch TTL/EDE, recalculate checksum, write to output pipe

### 2.3 Current Verdict Paths
From `src/worker_questions.moon` (lines 310-314):
```lua
write_msg()           -- allow: pass through + nft set injection
write_refused_msg()   -- refuse: block upstream query entirely
write_dnsonly_msg()   -- dnsonly: pass through but no nft injection
```

### 2.4 EDE Injection Points
From `src/dns_ede.moon` (lines 32-104):
- **Code 4 (Forged-Answer)**: Injected when payload modified (line 175-177 in worker_responses.moon)
- **Code 17 (Filtered)**: Injected for REFUSED responses (enforced answer built in forge_dns.moon)
- **Stripping**: HTTPS/SVCB records removed via `strip_https_rr()` before EDE injection

---

## 3. Decision Matrix: Verdict × Payload Modification → (TTL Action, EDE, Checksum)

| Verdict | Modification | TTL Action | EDE Injection | Checksum Recalc | Example |
|---------|--------------|-----------|---------------|-----------------|---------|
| **allow** | none | `rr_timeout(upstream_ttl)` | No | No | Authoritative A record, passes policy |
| **allow** | EDE only | `rr_timeout(upstream_ttl)` | Code 4 | Yes | Same A record but policy modified |
| **allow** | HTTPS strip | `rr_timeout(upstream_ttl)` | Code 4 | Yes | SVCB/HTTPS records removed, A/AAAA kept |
| **allow** | HTTPS strip + EDE only | `rr_timeout(upstream_ttl)` | Code 4 | Yes | HTTPS stripped + new EDE record |
| **refuse** | forced answer | 60s (constant) | Code 17 | Yes | REFUSED + fake answer from forge_dns.moon |
| **refuse** | N/A (upstream never queried) | N/A | Code 17 | N/A | No upstream response received |
| **dnsonly** | none | `rr_timeout(upstream_ttl)` | No | No | Pass through, no nft caching |
| **dnsonly** | HTTPS strip | `rr_timeout(upstream_ttl)` | Code 4 | Yes | Pass through but HTTPS removed |

---

## 4. TTL Calculation Logic: `rr_timeout(ttl)` Function

### 4.1 Pseudo-Code (Core Implementation)
```lua
function rr_timeout(upstream_ttl)
  if upstream_ttl == nil or upstream_ttl <= 0 then
    return config.dns.ttl_grace.min
  end
  
  -- Add grace period (time allowed for nft timeout to persist after DNS TTL expires)
  candidate = upstream_ttl + config.dns.ttl_grace.grace
  
  -- Clamp to configured min/max range
  result = math.max(config.dns.ttl_grace.min, 
                    math.min(candidate, config.dns.ttl_grace.max))
  
  return result
end

-- Example calculations with config defaults:
-- rr_timeout(0)  => max(60, min(0+600, 2592000)) = max(60, 600) = 600s
-- rr_timeout(30) => max(60, min(630, 2592000)) = max(60, 630) = 630s
-- rr_timeout(60) => max(60, min(660, 2592000)) = max(60, 660) = 660s (NOT 60!)
-- rr_timeout(2592000) => max(60, min(2592600, 2592000)) = max(60, 2592000) = 2592000s
```

### 4.2 Rationale
- **Grace period (600s)**: Allows nftables timeout to persist 10 minutes beyond upstream TTL expiry, reducing cache eviction thrashing
- **Minimum (60s)**: Prevents pathological cases (TTL=0) from creating 1-second cache entries
- **Maximum (30 days)**: Prevents infinite caches from responses with very high TTLs (86400+s)

### 4.3 Asymmetry Note
The grace is **additive on upstream TTL**, not symmetric:
- An upstream TTL of 60s becomes 660s (TTL + 600s grace) → clamped to min 660s
- An upstream TTL of 30 days becomes 30 days (clamped by max) → **grace is absorbed**
- This is intentional: small TTLs benefit from stability, large TTLs preserve the authoritative value

---

## 5. EDE Injection Rules

### 5.1 Decision Tree

```
if verdict == "refuse" then
  return code 17 (Filtered) + REFUSED status
  
elseif verdict == "allow" or "dnsonly" then
  if payload_modified then
    return code 4 (Forged-Answer) + original status (NOERROR, etc.)
  else
    return no EDE (pass through unmodified)
  end
end
```

### 5.2 Payload Modification Triggers
A response is marked `payload_modified = true` if ANY of:
1. HTTPS/SVCB records were stripped (line 93-98 dns_ede.moon)
2. EDE record injected (forced answer case)
3. Any RR data rewritten (policy-driven modifications, future extensions)

### 5.3 REFUSED Path (Code 17)
From `src/worker_responses.moon` (lines 292-314):
```lua
if verdict == "REFUSE" then
  -- Build synthetic REFUSED response via forge_dns.moon
  dns_payload = build_refused_response(upstream_payload)
  -- dns_payload now has:
  --   - Header.rcode = REFUSED (5)
  --   - No answer section (or NODATA answer)
  --   - OPT RR with EDE code 17 injected
  -- 
  -- EDE text variants:
  --   - "Custos vigilat" (Custos is watching)
  --   - "Ne intretis" (Do not enter)
  
  ttl_value = 60  -- constant for refused responses
  checksum_needs_recalc = true
  
  write_to_output_pipe(dns_payload, ttl_value, verdict_flags)
end
```

### 5.4 ALLOW Path (with optional modifications)
From `src/worker_responses.moon` (lines 316-437):
```lua
if verdict == "ALLOW" then
  dns_payload = upstream_response
  payload_modified = false
  
  -- Strip HTTPS/SVCB if policy dictates
  if policy.strip_https_records then
    dns_payload = strip_https_rr(dns_payload)
    payload_modified = true
  end
  
  -- Inject EDE if modified
  if payload_modified then
    dns_payload = add_ede_modified(dns_payload, "Forged-Answer")
    checksum_needs_recalc = true
  end
  
  ttl_value = rr_timeout(extracted_upstream_ttl)
  
  write_to_output_pipe(dns_payload, ttl_value, verdict_flags)
end
```

### 5.5 DNSONLY Path
Identical to ALLOW path in terms of TTL/EDE logic, but:
- **Does NOT write** to nftables set cache
- **Does write** to DNS output pipe (pass through to client)
- Useful for DNS-only filtering without L3/L4 policy caching

---

## 6. Checksum Recalculation

### 6.1 When to Recalculate
From `src/worker_responses.moon` (lines 391-392):
```lua
if checksum_needs_recalc then
  update_udp_checksum(dns_payload)
  update_ip_checksum(ip_header)
end
```

Checksum recalculation is triggered when:
1. **EDE record added** (payload length changed, OPT RR modified)
2. **HTTPS/SVCB records stripped** (answer section length changed)
3. **TTL rewritten** (RR data modified, though TTL is not checksummed in standard DNS)
4. **Any RR data modification**

### 6.2 Checksum Algorithms
- **DNS/UDP Checksum**: 16-bit one's complement sum of pseudo-header + DNS payload
- **IPv4 Header Checksum**: 16-bit one's complement sum of IP header fields (excluding checksum field itself)

### 6.3 Example Checksum Change Scenarios

| Scenario | Modification | Checksum Impact | Recalc Needed |
|----------|--------------|-----------------|---------------|
| Simple A record allowed | None | No change | No |
| A record allowed, policy modified | EDE injection | OPT RR added → payload size changes | Yes |
| HTTPS record allowed, then stripped | HTTPS removal | Answer section shrinks | Yes |
| REFUSED forced response | Synthetic answer built | Complete payload rewrite | Yes |
| TTL from 300s → 900s in answer | TTL field rewrite | RR data changes (not checksummed in DNS RFC) | No (unless EDE also added) |

---

## 7. DNSSEC Implications

### 7.1 Signature Invalidation Triggers
DNSSEC signatures become invalid when:
1. **EDE record injected** (OPT RR added, outside signed section per RFC 6891)
2. **HTTPS/SVCB records stripped** (answer section no longer matches signed set)
3. **TTL modified** (RRset TTL field changed, would require RRSIG TTL update)
4. **Checksum recalculated** (does not directly affect DNSSEC, but indicates payload change)

### 7.2 Current Behavior
- **EDE injection does NOT break DNSSEC** because:
  - OPT RR is outside the signed section (RFC 6891 Section 2)
  - DNSSEC validation occurs before EDE inspection
  - AD (Authenticated Data) bit handling unchanged
  
- **HTTPS/SVCB stripping BREAKS DNSSEC** because:
  - Answer section is no longer byte-for-byte match with RRSIG
  - Signature validation would fail if validator re-verifies
  - Mitigation: Clear AD bit when stripping records

- **TTL modification for caching purposes**:
  - Does NOT affect DNSSEC (TTL is not signed)
  - `rr_timeout()` grace period is transparent to DNSSEC validators

### 7.3 Recommended DNSSEC Handling

For ALLOW path with HTTPS stripping:
```lua
if strip_https_records then
  -- HTTPS/SVCB removal invalidates signature
  dns_payload = strip_https_rr(dns_payload)
  
  -- Clear AD (Authenticated Data) bit to signal signature no longer applies
  dns_header.ad = 0
  
  -- Inject EDE Code 4
  dns_payload = add_ede_modified(dns_payload, code=4)
end
```

For REFUSE path:
```lua
if verdict == "REFUSE" then
  -- Synthetic answer never has valid signature
  -- Set RCODE to REFUSED (breaks DNSSEC semantics anyway)
  -- Inject EDE Code 17
  dns_payload = build_refused_response(...)
end
```

---

## 8. Response Matching and IPC Protocol

### 8.1 Question-to-Response Binding
From `src/worker_questions.moon` and `src/worker_responses.moon`:

Question side writes to IPC pipe:
```
(txid, flags, verdict, client_ip, client_port, resolver_ip, timeout_value)
```

Response side drains pipe and matches:
```lua
for each response received:
  match_key = (response.txid, client_ip, client_port, resolver_ip)
  
  if match_key in ipc_cache then
    (txid, flags, verdict, timeout_value) = ipc_cache[match_key]
    apply_ttl = rr_timeout(extracted_response_ttl)
    apply_verdict = verdict  -- ALLOW/REFUSE/DNSONLY
    apply_timeout = timeout_value or apply_ttl
  end
end
```

### 8.2 Timeout Application in nftables
From `src/config.moon` (lines 34-47):
```lua
nft = {
  allow_set_timeout = apply_timeout  -- Dynamic, per-response
  deny_set_timeout = 60              -- Fixed, per REFUSE verdict
  dnsonly_set_timeout = 0            -- No L3/L4 caching
}
```

---

## 9. Concrete Examples

### 9.1 Example 1: Simple A Record (No Modifications)
```
Upstream Query:  A www.example.com
Upstream Response: 
  Header: NOERROR, AD=1
  Answer: www.example.com A 300 93.184.216.34
  (DNSSEC signature present)

Verdict: ALLOW
Policy: None (pass through)

Output:
  TTL applied: rr_timeout(300) = clamp(300+600, 60, 2592000) = 900s
  EDE injected: No (payload_modified = false)
  Checksum: No recalc needed
  nftables timeout: 900s
  
  Final response to client:
    Header: NOERROR, AD=1 (unchanged)
    Answer: www.example.com A 900 93.184.216.34 (TTL field updated)
    (DNSSEC signature invalidated by TTL change, but signature field not touched)
```

### 9.2 Example 2: HTTPS Record Allowed, Then Stripped
```
Upstream Query:  HTTPS www.example.com
Upstream Response:
  Header: NOERROR, AD=1
  Answer: www.example.com HTTPS 3600 1 www.example.com
  (DNSSEC signature present)

Verdict: ALLOW
Policy: Strip HTTPS records

Processing:
  1. Extract upstream TTL: 3600
  2. Strip HTTPS record: payload shrinks
  3. payload_modified = true
  4. Inject EDE Code 4 (Forged-Answer)
  5. Clear AD bit (signature no longer valid)
  6. Recalculate UDP/IP checksums

Output:
  TTL applied: rr_timeout(3600) = clamp(3600+600, 60, 2592000) = 4200s
  EDE injected: Yes (Code 4, text varies)
  Checksum: Recalculated
  nftables timeout: 4200s
  
  Final response to client:
    Header: NOERROR, AD=0 (AD cleared)
    Answer: (empty, all HTTPS records stripped)
    OPT RR: EDE Code 4 "Forged-Answer" text
    Checksum: Updated for new payload
```

### 9.3 Example 3: Blocked by Policy (REFUSE)
```
Upstream Query:  A malicious.site
Verdict: REFUSE

Processing:
  1. Do NOT send upstream query (verdict known at question time)
  2. Build synthetic REFUSED response via forge_dns.moon
  3. Set header.rcode = REFUSED (5)
  4. Inject EDE Code 17 (Filtered)
  5. TTL = 60 (constant for refused)

Output:
  TTL applied: 60 (constant)
  EDE injected: Yes (Code 17, text "Custos vigilat")
  Checksum: Recalculated (synthetic response)
  nftables timeout: 60s
  
  Final response to client:
    Header: REFUSED, AD=0 (synthetic, no DNSSEC)
    Answer: (synthetic or empty)
    OPT RR: EDE Code 17 "Filtered"
    Checksum: Calculated for synthetic payload
```

### 9.4 Example 4: DNS-Only (No nftables Injection)
```
Upstream Query:  A passthrough.example.com
Verdict: DNSONLY
Policy: None (pass through)

Processing:
  1. Query sent upstream
  2. Response received
  3. TTL = rr_timeout(upstream_ttl)
  4. NO nftables injection (dnsonly verdict)

Output:
  TTL applied: rr_timeout(upstream_ttl)
  EDE injected: No
  Checksum: No recalc needed
  nftables timeout: N/A (not injected)
  
  Response passed to client unchanged (except TTL)
```

---

## 10. TTL Grace Semantics: Asymmetry and Rationale

### 10.1 Grace Period Behavior

The grace period (600s default) extends the cache lifetime beyond the upstream TTL:

```
Timeline for A record with upstream TTL=60s:

t=0s     Upstream response received: A 60 example.com
         Applied TTL = rr_timeout(60) = 660s
         nftables set timeout = 660s

t=60s    Upstream TTL expires, but...
         nftables entry still live (600s remaining)

t=660s   nftables entry removed
         New query to upstream required
```

### 10.2 Why Asymmetric (additive, not clamping)?

**Option 1: Symmetric grace** (not used)
```
rr_timeout(ttl) = clamp(ttl/2 + 300, min, max)
-- This would reduce large TTLs unfairly
```

**Option 2: Additive grace** (current)
```
rr_timeout(ttl) = clamp(ttl + grace, min, max)
-- Small TTLs: benefit from extension (60s → 660s)
-- Large TTLs: clamped to max (2592000s stays 2592000s)
-- Preserves authoritative intent for large TTLs
```

This is intentional: **authoritative long TTLs are respected, short TTLs are stabilized**.

---

## 11. Checksum Impact Matrix

| Modification | UDP Checksum Impact | IPv4 Header Checksum Impact | Recalc Logic |
|--------------|--------------------|-----------------------------|--------------|
| TTL rewrite in RR | Yes (payload length might change if stored) | Yes if IP TTL field changed | Always yes when EDE added |
| EDE injection | Yes (OPT RR added) | No (IP payload, not header) | Yes |
| HTTPS strip | Yes (payload shrinks) | No (IP payload, not header) | Yes |
| AD bit clear | No (header field, small endian bit) | Possibly (DNS field is payload, not IP header) | Conditional |
| DNSSEC sig strip | Yes (payload shrinks) | No | Yes |

**Summary**: Checksum recalculation is required whenever the DNS payload (bytes after IP/UDP headers) changes in size or content.

---

## 12. Configuration Defaults Summary

```lua
-- TTL grace configuration (src/config.moon)
dns.ttl_grace = {
  grace = 600    -- 10 minutes of extension
  min   = 60     -- 1 minute minimum cache time
  max   = 2592000 -- 30 days maximum cache time
}

-- EDE codes mapping (src/dns_ede.moon)
ede_codes = {
  filtered = 17        -- "Filtered" - used for REFUSED verdicts
  forged_answer = 4    -- "Forged-Answer" - used when payload modified
}

-- nftables timeout config (src/config.moon)
nft.allow_set_timeout = dynamic  -- From rr_timeout()
nft.deny_set_timeout = 60        -- Fixed for REFUSE verdicts
nft.dnsonly_set_timeout = 0      -- No L3/L4 caching
```

---

## 13. Summary of Changes to Current Implementation

This specification formalizes the behavior already present in the source code:

1. **TTL Calculation** (`rr_timeout()`) is unchanged but documented with grace period rationale
2. **EDE Injection** (Code 4 and 17) is unchanged; conditions formalized
3. **DNSSEC Handling** is implicit; AD bit clearing recommended for HTTPS strip case
4. **Checksum Recalculation** is unchanged; triggers documented
5. **Timeout Application** uses dynamic TTL from `rr_timeout()` for allow path, fixed 60s for refuse path

**No code changes required** – this specification validates the existing implementation.

---

## 14. Validation Checklist

- [x] Decision matrix covers all 3 verdict paths × modification variants
- [x] TTL calculation logic fully specified with rationale
- [x] EDE injection rules with code 4/17 and trigger conditions
- [x] DNSSEC implications analyzed (signature invalidation, AD bit handling)
- [x] Checksum recalculation triggers and impact documented
- [x] Concrete examples for each major path (simple allow, HTTPS strip, refuse, dnsonly)
- [x] Configuration defaults extracted and summarized
- [x] IPC protocol and timeout binding formalized
- [x] Grace period asymmetry explained
- [x] Cross-references to source files provided

---

## 15. Open Questions & Future Work

1. **DNSSEC stripping for ALLOW path**: Should AD bit always be cleared when HTTPS/SVCB records are removed? Current code does not enforce this.
   
2. **EDE message localization**: Current code mentions "Custos vigilat" and "Ne intretis" but exact text selection logic is unclear.

3. **Cross-family client resolution**: How should IPv6 clients asking A records be handled? Current code assumes question family matches response family.

4. **Timeout variance**: Should grace period be configurable per verdict type (e.g., shorter grace for dnsonly)?

---

**End of Specification Document**
