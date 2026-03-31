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

## Docker End-to-End Tests

### `test_docker.moon`
Automated end-to-end testing using Docker:
- Builds Docker image
- Starts docker-compose environment
- Tests DNS filtering (allowed/blocked domains)
- Verifies nftables allowlist sets
- Checks filter logs for protocol information
- Tests TTL patching

Usage:
```bash
# Full test suite
moonc tests/test_docker.moon && luajit tests/test_docker.lua

# With options
luajit tests/test_docker.lua --verbose    # Show all commands
luajit tests/test_docker.lua --keep       # Leave containers running
luajit tests/test_docker.lua --no-build   # Skip image rebuild
luajit tests/test_docker.lua --help       # Show help
```

Prerequisites:
- Docker and Docker Compose installed
- User in docker group (or run with sudo)

The script uses only standard Lua I/O (`io.execute`, `io.popen`) to orchestrate Docker commands as requested.
