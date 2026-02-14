# SafeNet Core Module

This directory contains the foundational business logic and "drivers" for the framework. It is independent of the API or CLI interfaces.

## Modules

### Cryptography & State
-   **`keygen.py`**: Handles Curve25519 key generation (using `wg` or internal libraries). Enforces Zero-Disk-Key generation for clients.
-   **`state.py`**: Manages ephemeral in-memory state (e.g., the server's current running status, temporary keys).

### Database & Models
-   **`db.py`**: Asynchronous SQLite interface (`aiosqlite`). Handles all persistent storage operations.
-   **`schemas.py`**: Pydantic models for type safety and validation across the application.

### Hardware Interface (The "Engine")
-   **`engine.py`**: The "Driver" for WireGuard on Windows.
    *   Wraps `wg.exe` commands.
    *   Parses command output.
    *   Manages the Windows Service (`WireGuardTunnel$safenet`).
    *   **Requires Administrator Privileges**.

### Policy
-   **`policy.py`**: (Phase 2) Parsers for the YAML-based access control policy engine.
