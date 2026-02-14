# SafeNet Architecture

## 1. System Topology: Hub-and-Spoke
SafeNet implements a **Hub-and-Spoke** VPN topology using WireGuard.
- **Hub**: The Windows API Server (hosting the `safenet-vpn` interface).
- **Spokes**: Authenticated devices (clients/peers).

### Key Features
- **Zero-Trust**: No device can connect without explicit enrollment and a valid keypair.
- **Dynamic Routing**: Internal IP addresses (e.g., `10.0.0.x/32`) are assigned dynamically but persist in the database.
- **Split Tunneling**: Only internal subnet traffic is routed through the VPN by default (configurable).

---

## 2. Cryptography & Key Management

### Zero-Disk-Key Server Policy
To enhance security, the server's private key is treated uniquely:
1. **Generation**: Generated in-memory using `wg genkey`.
2. **Persistence**: Stored in `data/safenet.conf` (protected by OS file permissions).
3. **Usage**: Loaded into memory ONLY during tunnel startup.
4. **Destruction**: Cleared from memory immediately upon tunnel stop.

### Client Key Provisioning
- **Client Keys**: Generated server-side during `enroll`.
- **Private Key**: Delivered to the client ONCE via API response (and QR code). **Never stored in the database.**
- **Public Key**: Stored in `safenet.db` for peer authentication.

---

## 3. Database Schema (SQLite)

The system uses `aiosqlite` for non-blocking database operations.

### Tables

#### `devices`
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER PK | Auto-incrementing ID |
| `name` | TEXT | Unique device name (e.g., `alice-laptop`) |
| `public_key` | TEXT | WireGuard public key (Identity) |
| `ip_address` | TEXT | Assigned internal IP (e.g., `10.0.0.2`) |
| `created_at` | DATETIME | Timestamp of enrollment |

---

## 4. API & Process Model
- **FastAPI**: Handles HTTP requests, auth, and logic.
- **Uvicorn**: ASGI Server. **MUST run with `WindowsProactorEventLoopPolicy`** on Windows to support subprocesses.
- **WireGuard Service**: Managed via `wireguard.exe` subprocess calls (install/uninstall tunnel service).

### Windows Specifics
- **Privileges**: Running the API requires **Administrator** rights to manage network adapters.
- **Service Mode**: WireGuard runs as a Windows Service (`SafetNet Tunnel`) for persistence.
