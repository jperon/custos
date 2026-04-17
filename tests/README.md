# Tests for CustosVirginum

This directory contains test scripts for the DNS filter.

## Unit Tests

### `run_tests.lua`
General unit tests that don't require root privileges:
- Configuration parsing
- IPC communication
- Allowlist management

Run with:
```bash
make test
# or
LUA_PATH="lua/?.lua;lua/?/init.lua;;" luajit tests/run_tests.lua
```

## nDPI Integration Tests

### `test_ndpi.lua`
Tests for the pure FFI nDPI wrapper:
- Packet parsing (L3/L4/L7)
- DNS name decompression
- TTL patching and checksum recalculation
- Version detection (4.2–4.8 vs 5.0+)

Requires libndpi installed:
```bash
make test-ndpi
# or
LUA_PATH="lua/?.lua;lua/?/init.lua;;" luajit tests/test_ndpi.lua
```

## OpenWrt End-to-End Tests

### `test_openwrt.moon`
Automated end-to-end testing on OpenWrt routers via SSH:
- Deploys Lua files and nft rules
- Tests DNS filtering (allowed/blocked domains)
- Verifies nftables allowlist sets
- Checks filter logs for protocol information
- Tests authentication and captive portal

Usage:
```bash
make test-openwrt HOST=root@<router>
# or
LUA_PATH="lua/?.lua;lua/?/init.lua;;" luajit tests/test_openwrt.lua HOST=root@<router>
```

Prerequisites:
- SSH access to OpenWrt router with LuaJIT and nftables installed
- Router must be reachable from the test machine
