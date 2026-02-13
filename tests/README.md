# SafeNet Test Suite

This directory contains all validation tests for the SafeNet SOHO Security Framework.

## Running Tests

### Individual Phase Tests

```powershell
# Phase 1: In-Memory Cryptography Engine
python tests\test_phase1.py

# Phase 2: YAML Policy Parser & Database
python tests\test_phase2.py

# Phase 3: WireGuard Subprocess Driver (not yet implemented)
python tests\test_phase3.py
```

### Run All Tests

```powershell
python tests\run_all_tests.py
```

## Test Coverage

### Phase 1: In-Memory Cryptography Engine ✅
- [x] Async key generation via `asyncio.subprocess`
- [x] WireGuard key format validation (44-char Base64)
- [x] Cryptographic randomness verification
- [x] Zero-disk-key architecture validation

**Status**: ✅ PASSING

### Phase 2: YAML Policy Parser & Database ✅
- [x] Pydantic schema validation
- [x] YAML policy parser (`yaml.safe_load`)
- [x] Async SQLite database (aiosqlite)
- [x] SQL injection protection
- [x] Command injection protection (device name validation)
- [x] Foreign key constraints
- [x] Group membership queries

**Status**: ✅ PASSING

### Phase 3: WireGuard Subprocess Driver 🔨
- [ ] WireGuard config file generation
- [ ] Tunnel lifecycle management
- [ ] IP address assignment
- [ ] Configuration validation

**Status**: 🔨 NOT YET IMPLEMENTED

### Phase 4: FastAPI Endpoints & Authentication 🔨
**Status**: 🔨 NOT YET IMPLEMENTED

### Phase 5: Typer CLI Interface 🔨
**Status**: 🔨 NOT YET IMPLEMENTED

## Test Organization

```
tests/
├── __init__.py              # Test package initialization
├── test_phase1.py           # Phase 1 validation tests
├── test_phase2.py           # Phase 2 validation tests
├── test_phase3.py           # Phase 3 validation tests (placeholder)
└── run_all_tests.py         # Test runner for all phases
```

## Requirements

All tests require the project dependencies to be installed:

```powershell
pip install -r requirements.txt
```

Phase 1 tests additionally require:
- WireGuard for Windows installed
- `wg.exe` in system PATH

## Expected Output

All tests should print validation results with `[PASS]` or `[FAIL]` markers.

Successful test completion shows:
```
Phase X Status: VALIDATED
```

Failed tests will print error details and exit with code 1.
