# Phase F4 — User Authentication Rules

## Overview

Phase F4 implements user-based policy enforcement in CustosVirginum, allowing DNS filtering rules to enforce policies based on authenticated users extracted from TLS certificates.

**New Capability**: Rules can now include a `from_authenticated_user` condition to restrict access to specific users, enabling enterprise scenarios like:
- Allow HTTPS only for authenticated admin users
- Block streaming sites except for specific user groups
- Log DNS queries per authenticated user

## Architecture

```
TLS Handshake (ClientHello)
       ↓
worker_tls / auth/server.moon (extract SNI, certificate)
       ↓
worker_auth_pipeline.moon (extract username from certificate CN/SAN)
       ↓
auth/user_sessions.moon (manage user sessions in-memory)
       ↓
worker_questions.moon (evaluate from_authenticated_user condition)
       ↓
Apply rule with user context
```

## New Modules

### 1. `src/auth/user_sessions.moon` — User Session Management

Manages in-memory user sessions with timeout enforcement.

**Key Functions**:
- `init(timeout)` — Initialize session manager with timeout (default: 3600s)
- `add_session(username, src_ip, mac)` — Create/update user session
- `get_session(username)` — Retrieve active session (checks expiry)
- `is_authenticated(username, src_ip?, mac?)` — Check if user authenticated
- `refresh_session(username)` — Extend session timeout
- `remove_session(username)` — Remove session
- `cleanup_expired()` — Clean up expired sessions
- `get_all_sessions()` — Get all active sessions (debugging)

**Session Structure**:
```moon
{
  username: "alice"      -- lowercase username
  src_ip: "192.168.1.10" -- IP at authentication time
  mac: "aa:bb:cc:dd:ee:ff" -- MAC address
  auth_time: 1698765432 -- Unix timestamp
  expires: 1698769032   -- When session expires (3600s default)
}
```

### 2. `src/auth/cert_parser.moon` — Certificate Parsing

Extracts user information from X.509 certificates.

**Key Functions**:
- `extract_cn_from_subject(subject)` — Extract CN from subject string
- `extract_sans(cert_data)` — Extract DNS SANs from certificate
- `extract_username(cert_data, field?)` — Extract username from CN or SAN
- `validate_username(username)` — Validate username format (alphanumeric + _.-)
- `parse_certificate(raw_cert_data)` — Parse raw cert to structured format

**Username Extraction Logic**:
1. Try to extract CN from certificate subject (X.509 format: "C=US,O=Org,CN=alice,...")
2. If CN missing, use first DNS SAN
3. Fallback to nil if neither available
4. Validate format: `^[a-zA-Z0-9_.-]+$`

### 3. `src/worker_auth_pipeline.moon` — Auth Pipeline Worker

Main worker process handling certificate-based user authentication.

**Key Functions**:
- `init(cfg, nft_wfd?)` — Initialize worker with configuration
- `process_tls_certificate(tls_data)` — Extract user from cert and create session
- `get_user_session(username)` — Get session info (debugging)
- `periodic_cleanup()` — Clean up expired sessions (call periodically)

**Configuration**:
```moon
config = {
  auth: {
    session_timeout: 3600    -- Session TTL in seconds
    session_ttl: 3600        -- Alternative name (same as above)
    user_field: "subject"    -- "subject" or custom field
  }
}
```

### 4. `src/filter/conditions/from_authenticated_user.moon` — Rule Condition

New condition type for checking if a user is authenticated.

**Usage in Rules**:
```moon
config = {
  rules: {
    {
      rule_id: "admin-https-only"
      description: "HTTPS only for admin users"
      conditions: {
        { from_authenticated_user: "admin" }
        { to_domain: "internal.example.com" }
      }
      actions: ["allow"]
    }
  }
}
```

## Integration Points

### 1. Certificate Extraction

The worker pipeline receives TLS certificate data from:
- `worker_tls.moon` — TLS SNI logging worker
- `auth/server.moon` — AUTH server handling TLS connections

Certificate data format:
```moon
{
  certificate: {
    subject: "C=US,O=Company,CN=alice"
    subject_alt_name: "DNS:alice,DNS:alice.company.com"
    issuer: "CN=CA"
    notBefore: 1234567890
    notAfter: 1234567890 + 31536000
  }
  src_ip: "192.168.1.10"
  mac: "aa:bb:cc:dd:ee:ff"
}
```

### 2. Rule Evaluation in worker_questions.moon

The condition is evaluated during DNS question processing:
```moon
-- In worker_questions.moon:
condition_fn = (from_authenticated_user cfg) "alice"
match, reason = condition_fn {
  src_ip: req.src_ip
  mac: req.mac
}
```

### 3. Configuration Integration

Add to `config.moon`:
```moon
auth: {
  session_timeout: 3600
  user_field: "subject"
}
```

## Usage Examples

### Example 1: Admin-Only HTTPS

```moon
config = {
  rules: {
    {
      rule_id: "admin-https"
      description: "HTTPS only for authenticated admins"
      conditions: {
        { from_authenticated_user: "admin" }
        { to_domain: "internal.example.com" }
      }
      network: {
        proto: ["tcp"]
        ports: ["443"]
      }
      actions: ["allow"]
    }
    {
      rule_id: "block-admin-http"
      description: "Block HTTP for admin domain"
      conditions: {
        { to_domain: "internal.example.com" }
        { to_domain: "!admin" }
      }
      network: {
        proto: ["tcp"]
        ports: ["80"]
      }
      actions: ["refuse"]
    }
  }
}
```

### Example 2: Per-User Logging

```moon
config = {
  rules: {
    {
      rule_id: "log-alice-queries"
      description: "Log all DNS for alice"
      conditions: {
        { from_authenticated_user: "alice" }
      }
      actions: ["log", "allow"]
    }
  }
}
```

### Example 3: Multiple Users

```moon
-- Check if user is any authenticated user
conditions: {
  { from_authenticated_user: "_any" }
}

-- Check if no user is authenticated
conditions: {
  { from_authenticated_user: "_none" }
}
```

## Certificate Setup

To use user authentication, you need certificates with user information in the CN (Common Name):

### OpenWrt / px5g

Generate certificate with username:
```bash
px5g selfsigned -newkey ec -keyout /etc/ssl/key.pem \
  -out /etc/ssl/cert.pem \
  -subj "/CN=alice" \
  -days 730
```

### OpenSSL

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 730 -subj "/CN=alice"
```

### With SAN (Subject Alternative Names)

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -addext "subjectAltName=DNS:alice,DNS:alice.example.com" \
  -subj "/CN=alice" -days 730
```

## Session Lifecycle

1. **Authentication**: User connects via TLS with certificate containing username
2. **Session Creation**: `worker_auth_pipeline` extracts username and creates session
3. **Timeout**: Session expires after `session_timeout` seconds (default 3600s)
4. **Refresh**: Session timeout extended on each authenticated request
5. **Cleanup**: `cleanup_expired()` removes expired sessions periodically
6. **Rule Evaluation**: `from_authenticated_user` checks if session is active

## Testing

### Unit Tests Added

- `tests/unit/auth/user_sessions_spec.moon` (11 tests)
- `tests/unit/auth/cert_parser_spec.moon` (21 tests)
- `tests/unit/auth/worker_auth_pipeline_spec.moon` (9 tests)
- `tests/unit/filter/from_authenticated_user_spec.moon` (27 tests)

### Running Tests

```bash
make test  # Run all 557 tests (includes 68 new tests)
```

### Example Test

```moon
describe "auth.user_sessions", ->
  it "adds and retrieves user session", ->
    add_session "alice", "192.168.1.10", "aa:bb:cc:dd:ee:ff"
    session = get_session "alice"
    
    assert.is_not_nil session
    assert.equals "alice", session.username
    assert.equals "192.168.1.10", session.src_ip
```

## Performance Considerations

1. **Session Lookup**: O(1) hash table lookup by username
2. **Expiry Check**: Checked on session retrieval only (lazy cleanup)
3. **Periodic Cleanup**: Call `cleanup_expired()` every 60-300 seconds
4. **Memory**: O(n) where n = active authenticated users

## Security Notes

1. **Username Validation**: Usernames must match `^[a-zA-Z0-9_.-]+$` (prevents injection)
2. **Session Timeout**: Default 3600s (1 hour) configurable
3. **MAC/IP Binding**: Sessions can optionally validate source IP/MAC
4. **Certificate Validation**: Rely on TLS server validation (outside scope)

## Future Enhancements

1. **Persistent Sessions**: Save sessions to disk for reload
2. **Session Groups**: Group users into teams/roles
3. **LDAP/OAuth Integration**: Sync from external auth systems
4. **Activity Logging**: Log user activity per request
5. **Rate Limiting**: Per-user rate limits
6. **Session Sharing**: Cross-device session management

## Troubleshooting

### Session Not Created
- Check certificate CN/SAN extraction: verify certificate has valid CN
- Check username format: must be alphanumeric + `_.-`
- Verify `worker_auth_pipeline` is initialized

### User Not Authenticated
- Check session timeout: default is 3600 seconds
- Call `cleanup_expired()` periodically to free memory
- Verify rule condition syntax: `from_authenticated_user: "username"`

### Performance Issues
- Session cleanup is lazy by default - call `periodic_cleanup()` regularly
- Consider increasing session timeout to reduce authentication overhead
- Monitor session count with `get_all_sessions()`

## Configuration Reference

```moon
-- Full configuration example
config = {
  auth: {
    -- Session timeout in seconds (default: 3600)
    session_timeout: 3600
    
    -- Alternative name for session_timeout
    session_ttl: 3600
    
    -- Certificate field for username extraction
    -- "subject" = CN from X.509 subject
    user_field: "subject"
  }
  
  rules: {
    {
      rule_id: "user-based-policy"
      description: "Example user-based rule"
      conditions: {
        { from_authenticated_user: "alice" }
        { to_domain: "example.com" }
      }
      actions: ["allow"]
    }
  }
}
```

## Summary of Changes

- **New Modules**: 3 new Moon modules for authentication pipeline
- **New Tests**: 68 new unit tests covering all new functionality
- **New Condition**: `from_authenticated_user` for rule evaluation
- **Integration**: Seamlessly integrates with existing rule evaluation
- **No Breaking Changes**: Backward compatible with existing configurations

## Test Results

- Total Tests: 557 (489 existing + 68 new)
- All Tests Passing: ✓
- Coverage: Full coverage of all new modules and conditions
