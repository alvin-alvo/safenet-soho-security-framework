# SafeNet Test Suite

This directory contains all validation tests for the SafeNet SOHO Security Framework.

## Running Tests

### Phase 1: Cryptography Engine
```powershell
python tests\test_phase1.py
```

### Phase 2: Database & Policy
```powershell
python tests\test_phase2.py
```

### Phase 3: WireGuard Driver
```powershell
python tests\test_phase3.py
```

### Phase 4: API & Authentication
```powershell
python tests\test_api.py
```

### Phase 5: CLI
```powershell
python tests\test_cli.py
```

---

## Manual Tunnel Tests (Admin Only)

**File**: `test_engine.py` (Recommended)
```powershell
python tests\test_engine.py
```
*Creates a real 30-second tunnel. Verifies Windows Service creation and IP assignment.*

**File**: `test_tunnel_manual.py`
```powershell
python tests\test_tunnel_manual.py
```
*Full lifecycle test: Generates keys, creates config, starts service, checks status, stops service.*

See [Testing Guide](../docs/TESTING.md) for detailed instructions.

---

## Run All Tests

```powershell
python tests\run_all_tests.py
```

---

## Test Coverage Status

### Phase 1: In-Memory Cryptography [COMPLETE]
- [x] Async key generation
- [x] Zero-disk-key verification

### Phase 2: Database & Policy [COMPLETE]
- [x] SQLite Async I/O
- [x] Schema validation

### Phase 3: WireGuard Driver [COMPLETE]
- [x] Config generation
- [x] Service management (Start/Stop)
- [x] Persistent state handling

### Phase 4: API Endpoints [COMPLETE]
- [x] JWT Authentication
- [x] Device Enrollment
- [x] Network Status

### Phase 5: CLI [COMPLETE]
- [x] Argument parsing
- [x] API communication
- [x] Output formatting (Rich)
