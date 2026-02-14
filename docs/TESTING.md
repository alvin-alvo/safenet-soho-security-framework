# SafeNet Quick Test Scripts

Quick reference for Phase 3 tunnel testing with admin privileges.

## Quick Start

### Engine Validation Test (Recommended - 30 second verification)

```powershell
python tests\test_engine.py
```

This creates a real tunnel for 30 seconds so you can verify with `ipconfig`!

### Manual Tunnel Test (Quick test)

```powershell
python tests\test_tunnel_manual.py
```

This will:
1. Generate fresh WireGuard keys
2. Create tunnel configuration
3. Start the tunnel (installs Windows service)
4. Check status (should show RUNNING)
5. Stop the tunnel (removes Windows service)
6. Verify cleanup

**Expected Result**: All steps show `[OK]`

---

## Windows Service State Codes

When checking tunnel status, you'll see state codes:

| Code | State | Meaning |
|------|-------|---------|
| 1 | STOPPED | Service is stopped |
| 2 | START_PENDING | Service is starting |
| 3 | STOP_PENDING | Service is stopping |
| 4 | RUNNING | Service is running |

**Normal test flow:**
- After start: State 2 (START_PENDING) or 4 (RUNNING) [COMPLETE]
- After stop: State 1 (STOPPED) or 3 (STOP_PENDING) [COMPLETE]

---

## Troubleshooting

### "wireguard.exe not found"
- Install WireGuard: https://www.wireguard.com/install/
- Add to PATH: `C:\Program Files\WireGuard`

### "Access Denied"
- Run PowerShell as Administrator
- Right-click → "Run as Administrator"

### Tunnel stuck in STOP_PENDING
- Wait a few seconds, Windows is cleaning up
- Check with: `sc query WireGuardTunnel$safenet`

---

## Automated Tests

For non-admin testing (skips actual tunnel operations):

```powershell
python tests\test_phase3.py
```

This tests:
- Config generation
- Path resolution
- Security constraints
- (Skips tunnel start/stop if not admin)

---

**Phase 3 is production-ready!** [COMPLETE]
