# SafeNet Utility Scripts

This directory contains standalone scripts for debugging, testing specific components, and manual verification.

## Scripts

### Troubleshooting & Debugging

-   **`check_wg_status.py`**
    *   **Purpose**: Runs `wg show` safely via Python `asyncio`.
    *   **Use**: diagnostic tool to check if the WireGuard interface is up and responding.

-   **`debug_keys.py`**
    *   **Purpose**: Tests WireGuard key generation and derivation logic.
    *   **Use**: Verifies that the server can correctly parse keys from `safenet.conf`.

-   **`debug_wireguard.py`**
    *   **Purpose**: Full system diagnostic for the WireGuard installation.
    *   **Use**: Checks admin privileges, `ProgramData` config existence, and firewall rules.

### Feature Testing

-   **`test_qr_image.py`**
    *   **Purpose**: Tests the `qrcode` and `pillow` library integration.
    *   **Use**: Generates a test QR code image (`test_qr.png`) to verify dependencies.

-   **`test_status_fix.py`**
    *   **Purpose**: Tests the tunnel status logic in isolation.
    *   **Use**: Verifies the `get_tunnel_status()` function from `core.engine` without running the full API.

## Usage

Run these scripts from the **project root** to ensure imports work correctly:

```powershell
python scripts\debug_wireguard.py
python scripts\check_wg_status.py
```
